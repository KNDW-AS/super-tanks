"""
core/security/aeris_response_templates.py
==========================================
Aeris's pre-approved response templates.

Mirrors zeph_response_templates.py but for the FAMILY-FACING domain:
Home Assistant, daily life, smart home automation. Templates here are
the ones Aeris is authorised to fire without William's say-so.

Same contract: each template is a (applies_to, execute) pair vetted
in code review. Templates may NOT:
  - delete/rename HA entities (could break automations)
  - mint or rotate HA tokens (requires William)
  - restart HA itself (operational risk)
  - issue any HA write outside the approval queue (bypass)

Templates MAY:
  - mark expired approval rows as expired (the API already supports this)
  - emit informational notifications
  - request the operator re-check a setting

Adding a template is a PR to this file — the runtime cannot extend
the registry dynamically. This is the operator control point.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, List

from core.security.threat_intel import Threat
from core.security.zeph_response_templates import ResponseTemplate

logger = logging.getLogger("super_tanks.aeris_templates")


# ── clear_stale_ha_approvals ──────────────────────────────────────────────

def _applies_clear_stale_ha_approvals(threat: Threat) -> bool:
    if threat.source != "ha_health":
        return False
    return threat.details.get("kind") == "ha_pending_stale"


def _t_clear_stale_ha_approvals(threat: Threat) -> str:
    """Expire stale PENDING home_assistant approval rows.

    Uses ApprovalStore.expire_old_requests which only flips rows
    whose expires_at has already passed. That means Aeris is doing
    nothing William didn't already opt into when the original GO-Gate
    request was created with its TTL — Aeris just makes sure the
    queue doesn't bloat indefinitely waiting for cron to notice.

    Why safe: the rows must already be past their TTL; the operation
    is the same one a /cleanup_approvals admin command would run; and
    no HA service is actually called.
    """
    try:
        from core.ask_admin import ApprovalStore
    except Exception as exc:
        raise RuntimeError(f"ApprovalStore unavailable: {exc}")
    store = ApprovalStore()
    expired_count = store.expire_old_requests()
    if expired_count == 0:
        # Nothing was actually past its TTL. The HA pending-stale
        # detector fires on age-since-created > STALE_PENDING_MINUTES,
        # which can be smaller than the per-request TTL. In that case
        # Aeris has correctly flagged a slow queue but has nothing to
        # auto-clean — promote to PROPOSE so the operator decides.
        return ""
    return (f"expired {expired_count} timed-out approval request(s); "
            "live HA writes were not touched")


# ── acknowledge_ha_credentials_missing ────────────────────────────────────

def _applies_ack_ha_creds(threat: Threat) -> bool:
    return (threat.source == "ha_health"
            and threat.details.get("kind") == "ha_credentials_missing")


def _t_ack_ha_creds(threat: Threat) -> str:
    """No auto-fix. Logs the finding and returns empty so the engine
    falls through to ESCALATE_NOW (the threat is CRITICAL severity
    anyway, but this makes the rationale explicit).

    Why no auto-fix: minting a Long-Lived Access Token in Home
    Assistant requires a human at the HA UI. Anything Aeris could
    "auto-do" here would either be useless (write a placeholder to
    env) or wrong (drop the requirement entirely)."""
    logger.warning(
        "[AERIS_RESP] HA credentials missing — Aeris cannot self-heal: "
        "%s", threat.details.get("missing"),
    )
    return ""  # declines → engine PROPOSES, severity forces ESCALATE_NOW


# ── Registry ───────────────────────────────────────────────────────────────

_TEMPLATES: List[ResponseTemplate] = [
    ResponseTemplate(
        name="clear_stale_ha_approvals",
        description=("Expire utgåtte home_assistant-godkjenningar i "
                     "ApprovalStore-køen"),
        applies_to=_applies_clear_stale_ha_approvals,
        execute=_t_clear_stale_ha_approvals,
    ),
    ResponseTemplate(
        name="acknowledge_ha_credentials_missing",
        description=("Logg manglande HA-credentials; ingen auto-fix "
                     "mogleg — operatør må gjere det"),
        applies_to=_applies_ack_ha_creds,
        execute=_t_ack_ha_creds,
    ),
]


def all_templates() -> List[ResponseTemplate]:
    return list(_TEMPLATES)


def find_template_for(threat: Threat):
    for tpl in _TEMPLATES:
        try:
            if tpl.applies_to(threat):
                return tpl
        except Exception as exc:
            logger.warning("[AERIS_RESP] template %s applies_to raised: %s",
                           tpl.name, exc)
            continue
    return None
