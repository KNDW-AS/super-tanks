"""
core/security/cody_response_templates.py
==========================================
Cody's pre-approved response templates.

Mirrors `aeris_response_templates.py` and `zeph_response_templates.py`
for Cody's domain: code quality. Templates here are the actions Cody
can take in response to a threat or finding WITHOUT operator
approval.

Per the invariants in `cody_directives.py`:
  - Cody NEVER modifies code, applies diffs, or merges PRs.
  - Cody MAY write proposals to data/proposed_fixes/ (read-only from
    the live codebase's perspective; consumed by GO-Gate + human).
  - Cody MAY summarise, annotate, and route — never execute.

The registry is intentionally short. Code-quality findings come in
many flavours, but auto-acting on most of them risks poisoning the
codebase the same way auto-adding ZEF rules from external content
risks poisoning the filter. The conservative default is PROPOSE,
which is what the triage engine does when no template matches.
"""

from __future__ import annotations

import logging
from typing import List

from core.security.threat_intel import Threat
from core.security.zeph_response_templates import ResponseTemplate

logger = logging.getLogger("super_tanks.cody_templates")


# ── annotate_proposed_dep_upgrade ─────────────────────────────────────────

def _applies_annotate_proposed_dep(threat: Threat) -> bool:
    """Triggers when Zeph has already written a dep-upgrade proposal
    for a CVE in an imported package. Cody's job here is to summarise
    the diff for the human reviewer's Telegram so the operator can
    decide without opening a terminal."""
    return (threat.source == "zeph_triage"
            and threat.details.get("template_name") == "propose_dep_upgrade"
            and threat.details.get("verdict") == "auto_act")


def _t_annotate_proposed_dep(threat: Threat) -> str:
    """Read the underlying proposal (referenced via
    threat.details.action_note which embeds the proposal id), pull
    the structured FixProposal from disk, and produce a human-
    readable summary.

    Returns empty if the action_note doesn't contain a proposal id
    Cody can parse — engine falls through to PROPOSE, which is
    correct: the operator gets the raw threat.summary instead of a
    polished Cody review.
    """
    import re
    note = threat.details.get("action_note") or ""
    m = re.search(r"proposal\s+([0-9a-f-]{36})", note)
    if not m:
        return ""
    proposal_id = m.group(1)
    try:
        from core.security import fix_proposals
    except Exception as exc:
        raise RuntimeError(f"fix_proposals unavailable: {exc}")
    proposal = fix_proposals.load(proposal_id)
    if proposal is None:
        return ""
    diff_lines = (proposal.requirements_diff or "").splitlines()
    diff_changed = sum(1 for ln in diff_lines
                       if ln.startswith(("+", "-"))
                       and not ln.startswith(("+++", "---")))
    return (f"Cody-reviewed {proposal_id}: "
            f"{proposal.package} {proposal.current_version}→"
            f"{proposal.target_version}; "
            f"{diff_changed} line(s) of requirements.txt change. "
            f"Operator: python -m scripts.apply_proposed_fix --apply "
            f"{proposal_id}")


# ── Registry ───────────────────────────────────────────────────────────────

_TEMPLATES: List[ResponseTemplate] = [
    ResponseTemplate(
        name="annotate_proposed_dep_upgrade",
        description=("Skriv ein menneskeleg samandrag av Zeph sin "
                     "dep-upgrade-proposal slik at operatør kan "
                     "avgjere på Telegram utan terminal"),
        applies_to=_applies_annotate_proposed_dep,
        execute=_t_annotate_proposed_dep,
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
            logger.warning("[CODY_RESP] template %s applies_to raised: %s",
                           tpl.name, exc)
            continue
    return None
