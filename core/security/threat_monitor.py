"""
core/security/threat_monitor.py
=================================
Active threat monitor — the "stop attacks in progress" half of
self-healing.

Where threat_intel.py watches the outside world (CVEs, ZEF drift),
this module watches the inside: it scans the recent rows of
dispatch_audit, memory_audit, and the audit-chain integrity, and runs
a small catalogue of conservative responses.

Conservative: the monitor only TIGHTENS. It can drop trust score,
flip to LOCKDOWN, or enter SAFE_MODE — it never auto-loosens
permissions, auto-edits ZEF rules, or modifies code. New / unmatched
patterns are emitted as Threats and surfaced to the operator via the
threat_intel digest, not auto-handled.

Patterns implemented (all on the same 5-minute scan window):

  P1  identity_failure_burst
        ≥ THRESH_IDENTITY identity-verify denials in the window from
        the same agent_id  →  emit HIGH Threat, log
  P2  tripwire_burst
        ≥ THRESH_TRIPWIRE tripwire honeypot hits in the window from
        the same agent     →  flip to LOCKDOWN, emit CRITICAL Threat
  P3  zef_burst
        ≥ THRESH_ZEF "indirect_injection BLOCKED" gateway entries in
        the window         →  drop trust score for the offending
        agent by 5, emit HIGH Threat
  P4  dispatch_chain_tampered
        verify_dispatch_chain returns a row id (chain broken)
                            →  enter SAFE_MODE, emit CRITICAL Threat
  P5  memory_chain_tampered
        verify_audit_chain returns a row id (chain broken)
                            →  enter SAFE_MODE, emit CRITICAL Threat

Each call to scan_once() returns a digest of what it found and what
it did. The digest also goes into threat_intel as one Threat per
finding, so the cross-DB correlation_id machinery still works (and
the digest survives across restarts via the threat store).

Rate limiting: the dedup key inside the threat store
(source="threat_monitor", fingerprint=<pattern>+<window_bucket>)
prevents the same finding from triggering the same response twice in
the same minute-bucket.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("super_tanks.threat_monitor")

# Tunable thresholds. These are deliberately on the cautious side —
# tighter triggers mean more spurious LOCKDOWNs, looser means missed
# attacks. The values below are empirically defensible at v1; revisit
# after we have one week of production audit data.
WINDOW_MINUTES = 5
THRESH_IDENTITY = 10        # P1
THRESH_TRIPWIRE = 3         # P2
THRESH_ZEF = 5              # P3
TRUST_PENALTY_ZEF_BURST = 5.0


@dataclass
class MonitorReport:
    """What scan_once() found and did. Returned to the CLI for
    Telegram digest assembly."""
    window_minutes: int = WINDOW_MINUTES
    findings: List[str] = field(default_factory=list)
    actions_taken: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


# ── Helpers ────────────────────────────────────────────────────────────────

def _window_start_iso(now: Optional[datetime] = None,
                      minutes: int = WINDOW_MINUTES) -> str:
    now = now or datetime.now(timezone.utc)
    return (now - timedelta(minutes=minutes)).isoformat()


def _bucket(now: Optional[datetime] = None) -> str:
    """Coarse bucket for dedup — minute granularity within the day."""
    now = now or datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M")


def _emit_threat(*, fingerprint: str, severity: str, summary: str,
                 details: dict) -> None:
    """Insert a Threat for this pattern into the central store. The
    chain-HMAC, dedup, and digest plumbing is shared with the
    proactive intel sources."""
    from core.security.threat_intel import Threat, record_threat
    record_threat(Threat(
        source="threat_monitor",
        fingerprint=fingerprint,
        severity=severity,
        summary=summary,
        details=details,
    ))


# ── Pattern detectors ──────────────────────────────────────────────────────

def _detect_identity_burst(report: MonitorReport, now: datetime) -> None:
    """P1: identity verification failures piling up from the same
    agent. Caused by an attacker brute-forcing or replaying old
    tokens, or by a buggy client.

    We don't auto-blacklist (no in-process blacklist machinery yet);
    we emit a HIGH threat and log. If the operator's response is
    "yes, blacklist this agent" we add that wiring later."""
    try:
        from core.security.dispatch_audit import get_dispatch_history
    except Exception as exc:
        report.errors.append(f"P1: dispatch_audit unavailable ({exc})")
        return

    rows = get_dispatch_history(limit=500)
    cutoff = _window_start_iso(now)
    counts: Counter = Counter()
    for r in rows:
        if r.get("timestamp", "") < cutoff:
            continue
        if r.get("verdict") == "denied_identity":
            counts[r.get("agent_id", "<unknown>")] += 1

    for agent, n in counts.items():
        if n < THRESH_IDENTITY:
            continue
        finding = (f"P1 identity_failure_burst: agent={agent!r} "
                   f"failed identity verify {n}× in {WINDOW_MINUTES}min")
        report.findings.append(finding)
        _emit_threat(
            fingerprint=f"P1-identity-{agent}-{_bucket(now)}",
            severity="HIGH",
            summary=finding,
            details={"agent": agent, "count": n,
                     "window_minutes": WINDOW_MINUTES},
        )


def _detect_tripwire_burst(report: MonitorReport, now: datetime) -> None:
    """P2: multiple tripwire honeypot hits in a short window indicate
    an active probe of the memory store. This is a high-confidence
    signal — drop everything to LOCKDOWN."""
    try:
        from core.memory.audit_log import get_recent_access
    except Exception as exc:
        report.errors.append(f"P2: memory audit unavailable ({exc})")
        return

    rows = get_recent_access(limit=500)
    cutoff = _window_start_iso(now)
    counts: Counter = Counter()
    for r in rows:
        if r.get("timestamp", "") < cutoff:
            continue
        op = (r.get("operation") or "").lower()
        if "tripwire" in op:
            counts[r.get("agent_id", "<unknown>")] += 1

    if not counts:
        return
    total = sum(counts.values())
    if total < THRESH_TRIPWIRE:
        return

    finding = (f"P2 tripwire_burst: {total} tripwire hits in "
               f"{WINDOW_MINUTES}min from {dict(counts)}")
    report.findings.append(finding)
    _emit_threat(
        fingerprint=f"P2-tripwire-{_bucket(now)}",
        severity="CRITICAL",
        summary=finding,
        details={"counts": dict(counts), "total": total,
                 "window_minutes": WINDOW_MINUTES},
    )

    # Response: LOCKDOWN.
    try:
        from core.security.super_tanks_mode import set_mode, TankMode, get_mode
        if get_mode() != TankMode.LOCKDOWN:
            set_mode(TankMode.LOCKDOWN)
            report.actions_taken.append(
                "P2: flipped to LOCKDOWN due to tripwire burst")
    except Exception as exc:
        report.errors.append(f"P2: failed to LOCKDOWN ({exc})")


def _detect_zef_burst(report: MonitorReport, now: datetime) -> None:
    """P3: gateway recorded multiple indirect-injection blocks in a
    short window. The originating agent is currently consuming
    attacker-controlled content; drop its trust to slow it down."""
    try:
        from core.security.dispatch_audit import get_dispatch_history
    except Exception as exc:
        report.errors.append(f"P3: dispatch_audit unavailable ({exc})")
        return

    rows = get_dispatch_history(limit=500)
    cutoff = _window_start_iso(now)
    counts: Counter = Counter()
    for r in rows:
        if r.get("timestamp", "") < cutoff:
            continue
        err = r.get("error") or ""
        if "prompt-injection" in err or "indirect_injection" in err:
            counts[r.get("agent_id", "<unknown>")] += 1

    for agent, n in counts.items():
        if n < THRESH_ZEF:
            continue
        finding = (f"P3 zef_burst: agent={agent!r} hit indirect-injection "
                   f"refusal {n}× in {WINDOW_MINUTES}min")
        report.findings.append(finding)
        _emit_threat(
            fingerprint=f"P3-zef-{agent}-{_bucket(now)}",
            severity="HIGH",
            summary=finding,
            details={"agent": agent, "count": n,
                     "window_minutes": WINDOW_MINUTES},
        )
        # Response: trust drop. Goes through the _TrustAuthority gate
        # because this monitor is a legitimate internal subsystem.
        try:
            from core.security import trust_score
            with trust_score._TrustAuthority():
                trust_score.set_score(
                    agent,
                    max(0.0, trust_score.get_score(agent)["score"]
                        - TRUST_PENALTY_ZEF_BURST),
                    reason=f"threat_monitor P3 zef_burst (n={n})",
                )
            report.actions_taken.append(
                f"P3: trust dropped for {agent!r} by "
                f"{TRUST_PENALTY_ZEF_BURST}")
        except Exception as exc:
            report.errors.append(f"P3: trust drop failed for {agent}: {exc}")


def _detect_chain_tampering(report: MonitorReport, now: datetime) -> None:
    """P4 + P5: walk the audit-chain HMACs. A mismatch means an
    attacker (or a bug) has modified rows post-write. Both are SAFE
    MODE-level events.

    SAFE_MODE is sticky — once entered, only the operator can clear
    it. That's intentional: silent re-entry from "everything looks
    fine now" is exactly the failure mode this is meant to prevent."""
    pairs = [
        ("dispatch_log", "P4 dispatch_chain_tampered",
         "core.security.dispatch_audit:verify_dispatch_chain"),
        ("memory_access_log", "P5 memory_chain_tampered",
         "core.memory.audit_log:verify_audit_chain"),
    ]
    for table, label, dotted in pairs:
        try:
            mod_path, fn_name = dotted.split(":")
            import importlib
            verify = getattr(importlib.import_module(mod_path), fn_name)
            tampered_id = verify()
        except Exception as exc:
            report.errors.append(f"{label}: verify call failed ({exc})")
            continue
        if tampered_id is None:
            continue
        finding = (f"{label}: HMAC chain broken at id={tampered_id} in "
                   f"table {table!r} — possible filesystem tamper")
        report.findings.append(finding)
        _emit_threat(
            fingerprint=f"{label.split()[0]}-{table}-{tampered_id}",
            severity="CRITICAL",
            summary=finding,
            details={"table": table, "tampered_row_id": tampered_id},
        )
        # Response: SAFE_MODE.
        try:
            from core.soul_guard import enter_safe_mode
            enter_safe_mode(finding)
            report.actions_taken.append(f"{label}: SAFE_MODE entered")
        except Exception as exc:
            report.errors.append(f"{label}: SAFE_MODE entry failed ({exc})")


# ── Public entry point ────────────────────────────────────────────────────

def scan_once(now: Optional[datetime] = None) -> MonitorReport:
    """Run one full pass of the active threat monitor.

    Safe to call from cron, from a periodic background thread, or
    directly from a test. All state mutations are routed through the
    proper subsystems (set_mode, trust_score, soul_guard) so audit
    rows are written normally.
    """
    now = now or datetime.now(timezone.utc)
    report = MonitorReport()
    for fn in (_detect_identity_burst,
               _detect_tripwire_burst,
               _detect_zef_burst,
               _detect_chain_tampering):
        try:
            fn(report, now)
        except Exception as exc:
            logger.exception("[THREAT_MONITOR] %s failed: %s",
                             fn.__name__, exc)
            report.errors.append(f"{fn.__name__} crashed: {exc}")
    return report
