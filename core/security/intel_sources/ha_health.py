"""
core/security/intel_sources/ha_health.py
==========================================
Home Assistant health intel source — Aeris's self-healing eyes.

Aeris is the family-facing agent. When the smart house misbehaves
(lights don't respond, scenes don't fire, approvals pile up), the
operator notices because the LIGHTS DON'T TURN ON. By the time
William opens Telegram to ask "what happened to the smart house" the
queue is already cold and the cause is hidden.

This source emits structured Threats so Aeris's triage layer can:
  - auto-act on the things that have safe templates (clear stale
    pending approvals, dedupe lockout warnings)
  - escalate the ones that need the operator (missing HA token,
    AUTH failure on the HA REST endpoint)

Detectors:
  H1 ha_pending_stale       N+ home_assistant calls have been
                            sitting in approval_requests PENDING
                            for > T minutes (default 15). Almost
                            always means William didn't see / didn't
                            answer the GO-Gate Telegram. Aeris can
                            safely expire them so the queue doesn't
                            bloat.
  H2 ha_credentials_missing No HOMEASSISTANT_TOKEN / *_URL in env.
                            Aeris CANNOT auto-fix this — only the
                            operator can mint a new HA long-lived
                            token. Severity CRITICAL, escalate.
  H3 ha_denied_burst        N+ DENIED home_assistant ops in the
                            memory audit in the last hour. Either
                            the allowlist excludes Aeris, or the
                            system is in LOCKDOWN and the user
                            doesn't know.

Fingerprints include a UTC-day bucket so the same finding doesn't
re-emit every cron tick, but a fresh occurrence the next day does.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

from core.security.threat_intel import (
    IntelSource, Threat,
    SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL,
)

logger = logging.getLogger("super_tanks.threat_intel.ha_health")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
APPROVAL_DB = _PROJECT_ROOT / "data" / "approval_requests.db"
AUDIT_DB = _PROJECT_ROOT / "data" / "memory_audit.db"

# Tunables. Conservative on purpose — Aeris should err on the side of
# "ask William" if a finding is ambiguous.
STALE_PENDING_MINUTES = 15
STALE_PENDING_THRESHOLD = 1     # any single stale HA call is a finding
DENIED_BURST_THRESHOLD = 5      # ≥ 5 DENIED HA ops/hour to surface

HA_TOKEN_VARS = (
    "HOMEASSISTANT_TOKEN", "HASS_TOKEN", "HA_TOKEN",
    "AERIS_HA_TOKEN", "AERIS_HOMEASSISTANT_TOKEN", "ZEPH_HA_TOKEN",
)
HA_URL_VARS = (
    "HOMEASSISTANT_URL", "HASS_URL", "HA_URL",
    "AERIS_HA_URL", "AERIS_HOMEASSISTANT_URL", "ZEPH_HA_URL",
)


def _utc_day_bucket() -> str:
    return datetime.now(timezone.utc).date().isoformat()


class HAHealthSource(IntelSource):
    def name(self) -> str:
        return "ha_health"

    def fetch(self) -> List[Threat]:
        threats: List[Threat] = []
        bucket = _utc_day_bucket()
        try:
            threats.extend(self._check_pending_stale(bucket))
        except Exception as exc:
            logger.error("[HA_HEALTH] pending-stale check failed: %s", exc)
        try:
            threats.extend(self._check_credentials(bucket))
        except Exception as exc:
            logger.error("[HA_HEALTH] credentials check failed: %s", exc)
        try:
            threats.extend(self._check_denied_burst(bucket))
        except Exception as exc:
            logger.error("[HA_HEALTH] denied-burst check failed: %s", exc)
        return threats

    # ── H1 ──────────────────────────────────────────────────────────────
    def _check_pending_stale(self, bucket: str) -> List[Threat]:
        if not APPROVAL_DB.exists():
            return []
        cutoff = (datetime.now(timezone.utc)
                  - timedelta(minutes=STALE_PENDING_MINUTES)).timestamp()
        try:
            conn = sqlite3.connect(str(APPROVAL_DB))
            try:
                rows = conn.execute(
                    "SELECT request_id, created_at FROM approval_requests "
                    "WHERE status='pending' "
                    "  AND created_at < ? "
                    "  AND LOWER(tool_name) LIKE '%home_assistant%' "
                    "ORDER BY created_at ASC",
                    (cutoff,),
                ).fetchall()
            finally:
                conn.close()
        except sqlite3.Error as exc:
            logger.error("[HA_HEALTH] approval DB read failed: %s", exc)
            return []
        if len(rows) < STALE_PENDING_THRESHOLD:
            return []
        oldest_age_min = (datetime.now(timezone.utc).timestamp()
                          - rows[0][1]) / 60.0
        return [Threat(
            source="ha_health",
            fingerprint=f"H1-pending-stale-{bucket}",
            severity=SEVERITY_HIGH,
            summary=(f"{len(rows)} home_assistant call(s) stuck in GO-Gate "
                     f"PENDING > {STALE_PENDING_MINUTES}min "
                     f"(oldest {oldest_age_min:.0f}min)"),
            details={
                "kind": "ha_pending_stale",
                "count": len(rows),
                "oldest_age_minutes": round(oldest_age_min, 1),
                "request_ids": [r[0] for r in rows],
            },
        )]

    # ── H2 ──────────────────────────────────────────────────────────────
    def _check_credentials(self, bucket: str) -> List[Threat]:
        token_present = any(os.environ.get(v) for v in HA_TOKEN_VARS)
        url_present = any(os.environ.get(v) for v in HA_URL_VARS)
        missing = []
        if not token_present:
            missing.append("HA token")
        if not url_present:
            missing.append("HA URL")
        if not missing:
            return []
        return [Threat(
            source="ha_health",
            fingerprint=f"H2-credentials-{bucket}",
            severity=SEVERITY_CRITICAL,
            summary=(f"Home Assistant cannot reach the API — missing env: "
                     f"{', '.join(missing)}. Aeris cannot fix this; "
                     f"operator must mint a token."),
            details={
                "kind": "ha_credentials_missing",
                "missing": missing,
                "token_vars_checked": list(HA_TOKEN_VARS),
                "url_vars_checked": list(HA_URL_VARS),
            },
        )]

    # ── H3 ──────────────────────────────────────────────────────────────
    def _check_denied_burst(self, bucket: str) -> List[Threat]:
        if not AUDIT_DB.exists():
            return []
        cutoff = (datetime.now(timezone.utc)
                  - timedelta(hours=1)).isoformat()
        try:
            conn = sqlite3.connect(str(AUDIT_DB))
            try:
                row = conn.execute(
                    "SELECT COUNT(*) FROM memory_access_log "
                    "WHERE timestamp >= ? "
                    "  AND accessible = 0 "
                    "  AND (LOWER(operation) LIKE '%home_assistant%' "
                    "       OR LOWER(path) LIKE '%home_assistant%') ",
                    (cutoff,),
                ).fetchone()
                count = (row or [0])[0]
            finally:
                conn.close()
        except sqlite3.Error as exc:
            logger.error("[HA_HEALTH] audit DB read failed: %s", exc)
            return []
        if count < DENIED_BURST_THRESHOLD:
            return []
        return [Threat(
            source="ha_health",
            fingerprint=f"H3-denied-burst-{bucket}",
            severity=SEVERITY_MEDIUM,
            summary=(f"{count} home_assistant ops were DENIED in the last "
                     f"hour. Likely cause: LOCKDOWN mode, allowlist drop, "
                     f"or SAFE_MODE."),
            details={
                "kind": "ha_denied_burst",
                "count": count,
                "window_hours": 1,
            },
        )]
