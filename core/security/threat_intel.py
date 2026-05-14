"""
core/security/threat_intel.py
==============================
Threat-intelligence subsystem.

Self-healing has two halves:

  1. ACTIVE — watch your own audit logs, stop attacks in progress
     (see core/security/threat_monitor.py)

  2. PROACTIVE — watch the outside world, close holes before they're
     exploited locally (this module)

This module is the proactive half. It defines:

  Threat        — one piece of intelligence, e.g. "CVE-2025-1234 in
                  requests<2.32" or "ZEF block-rate dropped from 100%
                  to 92% on the periodic re-baseline".
  ThreatStore   — append-only SQLite table for ingested threats, with
                  the R-12 chained-HMAC tamper-evidence applied.
  IntelSource   — pluggable adapter contract; fetches a batch of
                  Threats from somewhere (OSV, ZEF self-test, etc.).
  Mitigator     — pluggable contract that responds to a Threat. The
                  default mitigators are CONSERVATIVE: tighten / log /
                  notify the operator. They never auto-apply code
                  patches or auto-add ZEF rules from external content
                  (poisoning vector — an attacker who can land a fake
                  threat would otherwise teach the filter to block
                  innocuous text or unblock real attacks).
  TriageEngine  — runs sources, dedupes against the store, dispatches
                  new threats to mitigators.

Operationally:

  $ python -m scripts.threat_scan
      → calls TriageEngine.scan_all() once. Cron-friendly.

  At process boot, core.bootstrap registers the default sources and
  mitigators but does NOT scan. Scanning happens on the schedule.
"""

from __future__ import annotations

import contextvars
import json
import logging
import sqlite3
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("super_tanks.threat_intel")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DB_PATH = _PROJECT_ROOT / "data" / "threat_intel.db"

SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"
_SEVERITIES = {SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL}


# ── Data model ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Threat:
    """One piece of threat intel.

    `fingerprint` is the dedup key. Two threats with the same
    `(source, fingerprint)` are considered the same finding — the
    store rejects the second insert. Use a stable identifier:
    "CVE-2025-1234", "zef-drift-block_rate-2026-05-14", etc.
    """
    source: str
    fingerprint: str
    severity: str
    summary: str
    details: Dict[str, Any] = field(default_factory=dict)
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self):
        if self.severity not in _SEVERITIES:
            # Frozen dataclass — bypass via object.__setattr__ would be
            # confusing. Just raise so misuse fails loudly at the source.
            raise ValueError(
                f"severity must be one of {sorted(_SEVERITIES)}, "
                f"got {self.severity!r}"
            )


# ── ThreatStore ────────────────────────────────────────────────────────────

_initialised: bool = False
_init_lock = threading.RLock()


def _ensure_db() -> None:
    global _initialised
    if _initialised:
        return
    with _init_lock:
        if _initialised:
            return
        _initialised = True
        try:
            _init_db()
        except Exception:
            _initialised = False
            raise


def _open() -> sqlite3.Connection:
    _ensure_db()
    from core.db.connection import open_db
    return open_db(str(DB_PATH), check_same_thread=False)


def _init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    from core.db.connection import open_db
    conn = open_db(str(DB_PATH), check_same_thread=False)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                discovered_at   TEXT    NOT NULL,
                source          TEXT    NOT NULL,
                fingerprint     TEXT    NOT NULL,
                severity        TEXT    NOT NULL,
                summary         TEXT    NOT NULL,
                details_json    TEXT    NOT NULL,
                hmac            TEXT    NOT NULL DEFAULT ''
            )
        """)
        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_threats_dedup
            ON threats (source, fingerprint)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_threats_severity_ts
            ON threats (severity, discovered_at DESC)
        """)
        conn.commit()
    finally:
        conn.close()


def _row_to_threat(row) -> Threat:
    return Threat(
        source=row["source"],
        fingerprint=row["fingerprint"],
        severity=row["severity"],
        summary=row["summary"],
        details=json.loads(row["details_json"] or "{}"),
        discovered_at=row["discovered_at"],
    )


def record_threat(threat: Threat) -> bool:
    """Append a threat to the store. Returns True if newly inserted,
    False if a row with the same (source, fingerprint) already exists.

    Uses the R-12 audit-chain machinery so the store inherits the same
    tamper-evidence guarantees as memory_audit and dispatch_audit.
    An attacker with FS-write to threat_intel.db cannot silently
    delete a stored threat without invalidating subsequent rows.
    """
    conn = None
    try:
        conn = _open()
        # Dedup BEFORE the chain insert so the chain stays gap-free.
        existing = conn.execute(
            "SELECT 1 FROM threats WHERE source=? AND fingerprint=? LIMIT 1",
            (threat.source, threat.fingerprint),
        ).fetchone()
        if existing:
            return False
        from core.security.audit_chain import append_chained
        row = {
            "discovered_at": threat.discovered_at,
            "source": threat.source,
            "fingerprint": threat.fingerprint,
            "severity": threat.severity,
            "summary": threat.summary,
            "details_json": json.dumps(threat.details, sort_keys=True,
                                       ensure_ascii=False),
        }
        append_chained(conn, "threats", row)
        return True
    except sqlite3.IntegrityError:
        # Race: another writer inserted the same fingerprint between our
        # SELECT and the append_chained INSERT. Treat as already-known.
        return False
    except Exception as exc:
        logger.error("[THREAT_INTEL] failed to record %s/%s: %s",
                     threat.source, threat.fingerprint, exc)
        return False
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def list_recent_threats(limit: int = 50,
                        min_severity: Optional[str] = None) -> List[Threat]:
    """Most recent threats first. Used by digest reports + tests."""
    conn = None
    try:
        conn = _open()
        conn.row_factory = sqlite3.Row
        if min_severity:
            order = [SEVERITY_LOW, SEVERITY_MEDIUM,
                     SEVERITY_HIGH, SEVERITY_CRITICAL]
            allowed = order[order.index(min_severity):]
            placeholders = ",".join("?" for _ in allowed)
            cur = conn.execute(
                f"SELECT * FROM threats WHERE severity IN ({placeholders}) "
                f"ORDER BY id DESC LIMIT ?",
                (*allowed, limit),
            )
        else:
            cur = conn.execute(
                "SELECT * FROM threats ORDER BY id DESC LIMIT ?", (limit,))
        return [_row_to_threat(r) for r in cur]
    except Exception as exc:
        logger.error("[THREAT_INTEL] list_recent_threats failed: %s", exc)
        return []
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def verify_threat_chain() -> Optional[int]:
    """Return None if chain is intact, else the id of the first
    tampered row. Called by the active threat_monitor as a periodic
    self-check."""
    conn = None
    try:
        conn = _open()
        from core.security.audit_chain import verify_chain
        return verify_chain(conn, "threats", [
            "discovered_at", "source", "fingerprint",
            "severity", "summary", "details_json",
        ])
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


# ── IntelSource / Mitigator contracts ──────────────────────────────────────

class IntelSource(ABC):
    """Pluggable adapter that fetches a batch of Threats from
    somewhere (OSV, GitHub Advisories, ZEF self-test, etc.)."""

    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def fetch(self) -> List[Threat]:
        """Return a list of Threats. Network failures should be
        caught and logged inside fetch(); raising leaks transient
        problems into the triage loop."""
        ...


# A Mitigator runs in response to a *new* threat. Returns a short
# string describing what it did, for inclusion in the digest. Returns
# None if it had nothing to do for this threat.
Mitigator = Callable[[Threat], Optional[str]]


# ── Registry ───────────────────────────────────────────────────────────────

_sources: List[IntelSource] = []
_mitigators: List[Mitigator] = []
_registry_lock = threading.RLock()


def register_source(source: IntelSource) -> None:
    with _registry_lock:
        # Replace by name if re-registered.
        _sources[:] = [s for s in _sources if s.name() != source.name()]
        _sources.append(source)


def register_mitigator(mitigator: Mitigator) -> None:
    with _registry_lock:
        if mitigator not in _mitigators:
            _mitigators.append(mitigator)


def registered_sources() -> List[IntelSource]:
    with _registry_lock:
        return list(_sources)


def registered_mitigators() -> List[Mitigator]:
    with _registry_lock:
        return list(_mitigators)


def _reset_registry_for_test() -> None:
    """Test helper. Production code never calls this."""
    with _registry_lock:
        _sources.clear()
        _mitigators.clear()


# ── TriageEngine ───────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    sources_run: int = 0
    threats_seen: int = 0
    new_threats: List[Threat] = field(default_factory=list)
    mitigation_log: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sources_run": self.sources_run,
            "threats_seen": self.threats_seen,
            "new_threats": [asdict(t) for t in self.new_threats],
            "mitigation_log": list(self.mitigation_log),
            "errors": list(self.errors),
        }


def scan_all() -> ScanResult:
    """Run every registered source, store new threats, dispatch them
    to every registered mitigator. Returns a digest-friendly summary.

    Idempotent re: dedup — re-running on the same data inserts no new
    rows and triggers no mitigations.
    """
    result = ScanResult()
    for source in registered_sources():
        result.sources_run += 1
        try:
            threats = source.fetch()
        except Exception as exc:
            msg = f"source {source.name()} failed: {exc}"
            logger.error("[THREAT_INTEL] %s", msg)
            result.errors.append(msg)
            continue
        for threat in threats:
            result.threats_seen += 1
            inserted = record_threat(threat)
            if not inserted:
                continue
            result.new_threats.append(threat)
            for mit in registered_mitigators():
                try:
                    note = mit(threat)
                    if note:
                        result.mitigation_log.append(
                            f"[{threat.severity}] {threat.source}/"
                            f"{threat.fingerprint}: {note}"
                        )
                except Exception as exc:
                    msg = (f"mitigator {getattr(mit, '__name__', mit)!r} "
                           f"raised on {threat.source}/{threat.fingerprint}: {exc}")
                    logger.error("[THREAT_INTEL] %s", msg)
                    result.errors.append(msg)
    return result
