"""
core/security/zeph_response_templates.py
==========================================
Pre-approved Zeph response templates.

Zeph is the technical agent. When the threat scanner finds something,
Zeph triages it. For routine cases, Zeph applies a PRE-APPROVED
template — a deterministic action that William has signed off on
ahead of time. Anything outside the template registry escalates to
William.

Why templates and not "let Zeph decide"?

  Even a well-aligned LLM-Zeph could be tricked by attacker-controlled
  threat content into "deciding" that a real CVE is a false alarm or
  that a tripwire hit is benign. By restricting auto-action to a
  fixed registry, we bound Zeph's authority. The LLM half (when it
  exists) chooses WHICH template applies — but cannot invent new
  responses.

Template contract:

    name             — unique slug; audit trail uses this
    description      — short Norwegian description for digests
    applies_to(t)    — predicate. True if this template can handle
                       Threat `t`.
    execute(t)       — perform the action. Returns a short note
                       describing what was done. May raise; the
                       triage engine catches and escalates.

Templates may NOT:
  - modify code
  - upgrade dependencies
  - bypass identity / role / audit checks
  - delete data

Templates MAY:
  - log / acknowledge
  - record a trust event (via _TrustAuthority)
  - re-baseline ZEF (it's reversible)
  - notify William (informational, not "for approval")

Adding a template is a code change with a PR — that's the operator
control point. The runtime cannot add templates dynamically.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, List

from core.security.threat_intel import Threat

logger = logging.getLogger("super_tanks.zeph_templates")


@dataclass
class ResponseTemplate:
    name: str
    description: str
    applies_to: Callable[[Threat], bool]
    execute: Callable[[Threat], str]


# ── Concrete templates ─────────────────────────────────────────────────────

def _t_acknowledge_low(threat: Threat) -> str:
    """Lowest-risk template: log and move on. Used for LOW severity
    intel that Zeph has already seen handled by the auto-tighten path
    (P3) or that's purely informational."""
    logger.info("[ZEPH_RESP] acknowledged %s/%s", threat.source,
                threat.fingerprint)
    return f"acknowledged ({threat.severity})"


def _applies_low(threat: Threat) -> bool:
    return threat.severity == "LOW"


def _t_rebaseline_minor_zef_drift(threat: Threat) -> str:
    """ZEF block_rate or warn_rate slipped MEDIUM (small margin).
    Re-baseline against the current upstream tier so the gate doesn't
    block AUTONOMOUS forever on a tiny shift. CRITICAL drifts do NOT
    take this path — they escalate to William.
    """
    fingerprint = threat.fingerprint
    metric = threat.details.get("metric", "")
    # Only act on block_rate / warn_rate slippage. FPR slippage means
    # the filter is mis-blocking real users — that's not "drift", that's
    # a regression that needs human review.
    if metric not in ("block_rate", "warn_rate"):
        return ""
    try:
        from core.security.super_tanks_mode import (
            mark_zef_baselined, _MODEL_TIER_FINGERPRINT,
        )
    except Exception as exc:
        raise RuntimeError(f"super_tanks_mode unavailable: {exc}")
    if not _MODEL_TIER_FINGERPRINT:
        return ""  # no tier set → cannot rebaseline meaningfully
    mark_zef_baselined(_MODEL_TIER_FINGERPRINT)
    return (f"re-baselined ZEF against tier "
            f"{_MODEL_TIER_FINGERPRINT!r} after MEDIUM {metric} drift")


def _applies_minor_zef_drift(threat: Threat) -> bool:
    return (threat.source == "zef_drift"
            and threat.severity == "MEDIUM"
            and threat.details.get("metric") in ("block_rate", "warn_rate"))


def _t_mark_dependency_not_imported(threat: Threat) -> str:
    """OSV CVE in a package that is not actually imported by the
    running process. The vuln is in the dep tree but unreachable —
    still worth recording, but Zeph can confidently downgrade urgency.
    """
    if threat.source != "osv":
        return ""
    package = threat.details.get("package")
    if not package:
        return ""
    import sys
    if package.replace("-", "_") in sys.modules or package in sys.modules:
        return ""  # actually imported → escalate
    return (f"package {package!r} not imported in this process — "
            f"CVE present in dep tree but unreachable")


def _applies_unimported_dep(threat: Threat) -> bool:
    return threat.source == "osv"


# ── Registry ───────────────────────────────────────────────────────────────

_TEMPLATES: List[ResponseTemplate] = [
    ResponseTemplate(
        name="acknowledge_low",
        description="Logg og deduper LOW-severity funn",
        applies_to=_applies_low,
        execute=_t_acknowledge_low,
    ),
    ResponseTemplate(
        name="rebaseline_minor_zef_drift",
        description=("Re-baseline ZEF mot gjeldande tier ved MEDIUM "
                     "block_rate/warn_rate-drift"),
        applies_to=_applies_minor_zef_drift,
        execute=_t_rebaseline_minor_zef_drift,
    ),
    ResponseTemplate(
        name="mark_dependency_not_imported",
        description=("Markér OSV-CVE som ikkje-applikabel om pakka ikkje "
                     "vert importert"),
        applies_to=_applies_unimported_dep,
        execute=_t_mark_dependency_not_imported,
    ),
]


def all_templates() -> List[ResponseTemplate]:
    return list(_TEMPLATES)


def find_template_for(threat: Threat) -> ResponseTemplate | None:
    """Return the first registered template that applies to `threat`,
    or None if none matches. Order matters — earlier templates win
    on overlap, so put the most specific first."""
    for tpl in _TEMPLATES:
        try:
            if tpl.applies_to(threat):
                # Probe: a template's applies_to may say yes but its
                # execute may bail with empty string (e.g. dep IS
                # imported, so can't downgrade). Treat empty as "this
                # template declines" and try the next.
                # We'll let the triage engine do the actual probe.
                return tpl
        except Exception as exc:
            logger.warning("[ZEPH_RESP] template %s applies_to raised: %s",
                           tpl.name, exc)
            continue
    return None
