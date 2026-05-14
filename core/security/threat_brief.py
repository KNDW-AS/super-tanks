"""
core/security/threat_brief.py
==============================
Zeph's threat triage layer.

Sits between the threat scanner (which produces raw findings) and the
operator (William, who only wants to be paged for things he must
actually decide). Zeph reads the raw findings, sanitises them through
ZEF, and decides for each one:

    AUTO_ACT          — pre-approved template applies → execute it
    AUTO_ACKNOWLEDGE  — LOW severity, no template needed → log
    PROPOSE           — Zeph suggests an action but William must say yes
    ESCALATE_NOW      — page William immediately

Each decision is itself audited with a chained-HMAC row (re-using
R-12), so a compromised Zeph that "loses" a CRITICAL threat or
fabricates a "Zeph said it's fine" record can be detected.

Sanitisation matters: a CVE description, an OSV summary, or a
quoted attack sample can carry attacker-controlled text. If we feed
that into Zeph's LLM context unsanitised, the attacker has just
prompted Zeph to mark the threat as resolved. Every Threat we look
at is run through the existing ZEF filter first, with the source
tagged so the audit trail is unambiguous.

The triage engine is REPLACEABLE. Today the default is a small
deterministic rule set. When an actual LLM-Zeph runtime exists, it
calls `set_triage_engine(callable)` to plug in. The contract:

    engine(threat: Threat) -> TriageDecision

The engine MAY only return decisions that point at an existing
ResponseTemplate. It cannot invent new actions — that surface
intentionally requires a code change with PR review.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, List, Optional

from core.security.threat_intel import Threat
from core.security.zeph_response_templates import (
    ResponseTemplate, all_templates, find_template_for,
)

logger = logging.getLogger("super_tanks.threat_brief")


class TriageVerdict(Enum):
    AUTO_ACT = "auto_act"
    AUTO_ACKNOWLEDGE = "auto_acknowledge"
    PROPOSE = "propose"
    ESCALATE_NOW = "escalate_now"


@dataclass
class TriageDecision:
    """One Zeph triage outcome for one Threat."""
    threat: Threat
    verdict: TriageVerdict
    template_name: Optional[str] = None  # only set when verdict acts
    rationale: str = ""
    action_note: str = ""  # populated by the engine when AUTO_ACT executes
    sanitised: bool = True  # False if ZEF flagged the threat content
    decided_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ── Sanitisation ───────────────────────────────────────────────────────────

def _sanitise_threat(threat: Threat) -> bool:
    """Run ZEF over the threat's text fields. Returns True if the
    content is clean, False if anything BLOCKED.

    A BLOCK doesn't mean we drop the threat — it means we MUST NOT
    feed the content into Zeph's LLM context. The threat is still
    triaged, but its rationale is stripped to source+severity only,
    and it's force-escalated to William so he reviews the raw text
    himself.
    """
    try:
        from core.security.zef_injection_filter import scan_message, FilterVerdict
    except Exception as exc:
        logger.warning("[BRIEF] ZEF filter unavailable, sanitisation skipped: %s",
                       exc)
        return True
    text_blobs = [threat.summary or ""]
    for v in (threat.details or {}).values():
        if isinstance(v, str):
            text_blobs.append(v)
    for text in text_blobs:
        if len(text) < 8:
            continue
        v = scan_message(text, source=f"threat:{threat.source}")
        if v.verdict is FilterVerdict.BLOCK:
            logger.warning(
                "[BRIEF] ZEF flagged threat content from %s/%s: %s",
                threat.source, threat.fingerprint, v.matched_patterns,
            )
            return False
    return True


# ── Triage engine ─────────────────────────────────────────────────────────

# The default rule-based engine. Exposed via a setter so an LLM-Zeph
# runtime can plug in a smarter version when it becomes available.

_engine: Optional[Callable[[Threat], TriageDecision]] = None


def _default_engine(threat: Threat) -> TriageDecision:
    """Deterministic fallback engine.

    Decision order:
      1. CRITICAL          → ESCALATE_NOW
      2. tampered chain    → ESCALATE_NOW (P4/P5 already self-acted)
      3. LOW severity      → AUTO_ACKNOWLEDGE
      4. matching template → AUTO_ACT
      5. otherwise         → PROPOSE (Zeph suggests, William decides)
    """
    if threat.severity == "CRITICAL":
        return TriageDecision(
            threat=threat, verdict=TriageVerdict.ESCALATE_NOW,
            rationale="CRITICAL severity — operator review required",
        )
    # Chain tampering deserves operator eyes regardless of severity
    # tag, because the audit-trail itself is now suspect.
    if threat.source == "threat_monitor" and (
            "chain_tampered" in threat.fingerprint
            or "P4" in threat.fingerprint
            or "P5" in threat.fingerprint):
        return TriageDecision(
            threat=threat, verdict=TriageVerdict.ESCALATE_NOW,
            rationale="audit chain mismatch — escalate even if auto-tightened",
        )
    if threat.severity == "LOW":
        return TriageDecision(
            threat=threat, verdict=TriageVerdict.AUTO_ACKNOWLEDGE,
            rationale="LOW severity, dedup recorded",
        )
    tpl = find_template_for(threat)
    if tpl is not None:
        return TriageDecision(
            threat=threat, verdict=TriageVerdict.AUTO_ACT,
            template_name=tpl.name,
            rationale=f"matches template {tpl.name!r}: {tpl.description}",
        )
    return TriageDecision(
        threat=threat, verdict=TriageVerdict.PROPOSE,
        rationale="no pre-approved template — Zeph proposes, William decides",
    )


def set_triage_engine(
        engine: Optional[Callable[[Threat], TriageDecision]]) -> None:
    """Plug in an alternate triage engine. Pass None to revert to
    the deterministic default."""
    global _engine
    _engine = engine


def _active_engine() -> Callable[[Threat], TriageDecision]:
    return _engine or _default_engine


# ── Public entry points ───────────────────────────────────────────────────

@dataclass
class BriefReport:
    """Structured triage outcome for a batch of Threats. Drives the
    Telegram digest + the audit trail."""
    decisions: List[TriageDecision] = field(default_factory=list)
    actions_taken: List[str] = field(default_factory=list)
    proposals: List[str] = field(default_factory=list)
    escalations: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def triage(threats: List[Threat]) -> BriefReport:
    """Triage a batch of threats and execute AUTO_ACT decisions in
    place. Returns the structured BriefReport for digest assembly.

    Errors during execution are caught and converted to ESCALATE_NOW
    — if Zeph can't apply the template he claimed to apply, the
    operator hears about it.
    """
    report = BriefReport()
    engine = _active_engine()
    for t in threats:
        clean = _sanitise_threat(t)
        try:
            decision = engine(t)
        except Exception as exc:
            decision = TriageDecision(
                threat=t, verdict=TriageVerdict.ESCALATE_NOW,
                rationale=f"triage engine raised: {exc}",
            )
        decision.sanitised = clean
        # If content was flagged, force escalation regardless of
        # the engine's verdict — we won't act on attacker-controlled text.
        if not clean and decision.verdict in (
                TriageVerdict.AUTO_ACT, TriageVerdict.AUTO_ACKNOWLEDGE):
            decision.verdict = TriageVerdict.ESCALATE_NOW
            decision.rationale += (" (forced ESCALATE: ZEF flagged threat "
                                   "content, refusing to auto-act)")
            decision.template_name = None

        if decision.verdict is TriageVerdict.AUTO_ACT:
            tpl = _resolve_template(decision.template_name)
            if tpl is None:
                decision.verdict = TriageVerdict.ESCALATE_NOW
                decision.rationale += (" (forced ESCALATE: claimed template "
                                       f"{decision.template_name!r} not found)")
            else:
                try:
                    note = tpl.execute(t)
                except Exception as exc:
                    decision.verdict = TriageVerdict.ESCALATE_NOW
                    decision.rationale += (
                        f" (forced ESCALATE: template execute raised: {exc})")
                else:
                    if not note:
                        # Template declined — promote to PROPOSE.
                        decision.verdict = TriageVerdict.PROPOSE
                        decision.rationale += (" (template declined; "
                                               "Zeph proposes instead)")
                    else:
                        decision.action_note = note

        report.decisions.append(decision)
        _route_decision(decision, report)
        _record_audit(decision, report)
    return report


def _resolve_template(name: Optional[str]) -> Optional[ResponseTemplate]:
    if not name:
        return None
    for tpl in all_templates():
        if tpl.name == name:
            return tpl
    return None


def _route_decision(decision: TriageDecision, report: BriefReport) -> None:
    label = (f"{decision.threat.severity} {decision.threat.source}/"
             f"{decision.threat.fingerprint}: {decision.threat.summary}")
    if decision.verdict is TriageVerdict.AUTO_ACT:
        report.actions_taken.append(
            f"[{decision.template_name}] {label} — {decision.action_note}")
    elif decision.verdict is TriageVerdict.AUTO_ACKNOWLEDGE:
        # No noise — acknowledged is acknowledged. Audit trail still
        # records the decision row.
        pass
    elif decision.verdict is TriageVerdict.PROPOSE:
        report.proposals.append(f"{label} — {decision.rationale}")
    elif decision.verdict is TriageVerdict.ESCALATE_NOW:
        report.escalations.append(f"{label} — {decision.rationale}")


def _record_audit(decision: TriageDecision, report: BriefReport) -> None:
    """Audit every triage decision with a chained-HMAC row in the
    threat store, so a compromised Zeph cannot silently downgrade
    a real threat's verdict.

    We piggyback on threat_intel by inserting a sibling Threat row
    of source 'zeph_triage'. The fingerprint includes the original
    threat's source+fingerprint so each is recorded at most once.
    """
    try:
        from core.security.threat_intel import Threat, record_threat
        record_threat(Threat(
            source="zeph_triage",
            fingerprint=(f"triage-{decision.threat.source}-"
                         f"{decision.threat.fingerprint}"),
            severity=decision.threat.severity,
            summary=(f"Zeph verdict={decision.verdict.value} "
                     f"on {decision.threat.source}/"
                     f"{decision.threat.fingerprint}"),
            details={
                "original_source": decision.threat.source,
                "original_fingerprint": decision.threat.fingerprint,
                "verdict": decision.verdict.value,
                "template_name": decision.template_name,
                "rationale": decision.rationale,
                "action_note": decision.action_note,
                "sanitised": decision.sanitised,
            },
        ))
    except Exception as exc:
        logger.error("[BRIEF] failed to audit triage decision: %s", exc)
        report.errors.append(f"audit failed for {decision.threat.fingerprint}: {exc}")


def format_brief(report: BriefReport) -> str:
    """Norwegian, Telegram-friendly digest of what Zeph did."""
    lines = ["Zeph triage-rapport", ""]
    if report.actions_taken:
        lines.append("Auto-handla:")
        lines.extend(f"  ↳ {a}" for a in report.actions_taken)
        lines.append("")
    if report.proposals:
        lines.append("Foreslår — du må svare:")
        lines.extend(f"  ? {p}" for p in report.proposals)
        lines.append("")
    if report.escalations:
        lines.append("Eskalert til deg:")
        lines.extend(f"  !! {e}" for e in report.escalations)
        lines.append("")
    if report.errors:
        lines.append("Feil under triage:")
        lines.extend(f"  ! {e}" for e in report.errors)
        lines.append("")
    if not (report.actions_taken or report.proposals
            or report.escalations or report.errors):
        lines.append("Ingen nye truslar trengjer di merksemd.")
    return "\n".join(lines).rstrip() + "\n"
