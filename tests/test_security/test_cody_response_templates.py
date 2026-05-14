"""Tests for core/security/cody_response_templates.py."""

import pytest

from core.security.threat_intel import Threat
from core.security import cody_response_templates as crt


def _t(severity="MEDIUM", source="zeph_triage", fingerprint="x",
       summary="s", details=None):
    return Threat(source=source, fingerprint=fingerprint,
                  severity=severity, summary=summary,
                  details=details or {})


# ── annotate_proposed_dep_upgrade ─────────────────────────────────────────

class TestAnnotateProposedDep:
    @pytest.fixture
    def proposal_env(self, tmp_path, monkeypatch):
        from core.security import fix_proposals
        proposals_dir = tmp_path / "proposed_fixes"
        requirements = tmp_path / "requirements.txt"
        requirements.write_text("requests==2.30.0\n")
        monkeypatch.setattr(fix_proposals, "PROPOSALS_DIR", proposals_dir)
        monkeypatch.setattr(fix_proposals, "REQUIREMENTS_FILE", requirements)
        proposal = fix_proposals.propose_dep_upgrade(
            threat_source="osv", threat_fingerprint="CVE-1",
            package="requests", target_version="2.32.5", reason="x",
        )
        return proposal

    def test_applies_only_to_zeph_dep_upgrade_audit_rows(self):
        tpl = _by_name("annotate_proposed_dep_upgrade")
        good = _t(source="zeph_triage",
                  details={"template_name": "propose_dep_upgrade",
                           "verdict": "auto_act",
                           "action_note": "proposal abc"})
        assert tpl.applies_to(good)
        # Wrong source.
        bad_src = _t(source="osv",
                     details={"template_name": "propose_dep_upgrade",
                              "verdict": "auto_act"})
        assert not tpl.applies_to(bad_src)
        # Wrong template name.
        bad_tpl = _t(source="zeph_triage",
                     details={"template_name": "acknowledge_low",
                              "verdict": "auto_act"})
        assert not tpl.applies_to(bad_tpl)
        # Wrong verdict.
        bad_v = _t(source="zeph_triage",
                   details={"template_name": "propose_dep_upgrade",
                            "verdict": "escalate_now"})
        assert not tpl.applies_to(bad_v)

    def test_execute_pulls_diff_and_summarises(self, proposal_env):
        tpl = _by_name("annotate_proposed_dep_upgrade")
        threat = _t(
            source="zeph_triage",
            details={
                "template_name": "propose_dep_upgrade",
                "verdict": "auto_act",
                "action_note": f"proposal {proposal_env.id} written: "
                               "requests 2.30.0→2.32.5",
            },
        )
        note = tpl.execute(threat)
        assert "Cody-reviewed" in note
        assert "requests" in note
        assert "2.30.0" in note
        assert "2.32.5" in note
        assert "apply_proposed_fix" in note

    def test_execute_returns_empty_when_proposal_id_missing(self):
        tpl = _by_name("annotate_proposed_dep_upgrade")
        threat = _t(
            source="zeph_triage",
            details={"template_name": "propose_dep_upgrade",
                     "verdict": "auto_act",
                     "action_note": "no id here"},
        )
        assert tpl.execute(threat) == ""

    def test_execute_returns_empty_when_proposal_not_on_disk(self,
                                                              tmp_path,
                                                              monkeypatch):
        from core.security import fix_proposals
        monkeypatch.setattr(fix_proposals, "PROPOSALS_DIR",
                            tmp_path / "missing")
        tpl = _by_name("annotate_proposed_dep_upgrade")
        threat = _t(
            source="zeph_triage",
            details={"template_name": "propose_dep_upgrade",
                     "verdict": "auto_act",
                     "action_note": "proposal "
                                    "11111111-2222-3333-4444-555555555555"},
        )
        assert tpl.execute(threat) == ""


def _by_name(name):
    for tpl in crt.all_templates():
        if tpl.name == name:
            return tpl
    raise AssertionError(f"template {name!r} not registered")
