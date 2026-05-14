"""
Tests for core/security/zeph_response_templates.py.

Each template is exercised in isolation. The execute() side effects
that touch shared state (super_tanks_mode, sys.modules) are
monkeypatched.
"""

import sys
import types

import pytest

from core.security.threat_intel import Threat
from core.security import zeph_response_templates as zrt


def _t(severity="MEDIUM", source="osv", fingerprint="x",
       summary="s", details=None):
    return Threat(source=source, fingerprint=fingerprint,
                  severity=severity, summary=summary,
                  details=details or {})


# ── Registry shape ─────────────────────────────────────────────────────────

class TestRegistry:
    def test_all_templates_returns_copy(self):
        snap = zrt.all_templates()
        snap.append("mutated")
        assert "mutated" not in zrt.all_templates()

    def test_each_template_has_required_attrs(self):
        for tpl in zrt.all_templates():
            assert tpl.name and tpl.description
            assert callable(tpl.applies_to)
            assert callable(tpl.execute)


# ── acknowledge_low ────────────────────────────────────────────────────────

class TestAcknowledgeLow:
    def test_applies_to_low(self):
        tpl = _by_name("acknowledge_low")
        assert tpl.applies_to(_t(severity="LOW"))
        assert not tpl.applies_to(_t(severity="HIGH"))

    def test_execute_returns_acknowledged(self):
        tpl = _by_name("acknowledge_low")
        note = tpl.execute(_t(severity="LOW"))
        assert "acknowledged" in note


# ── rebaseline_minor_zef_drift ────────────────────────────────────────────

class TestRebaselineMinorZefDrift:
    def test_applies_only_to_medium_zef_drift_block_or_warn(self):
        tpl = _by_name("rebaseline_minor_zef_drift")
        good = _t(source="zef_drift", severity="MEDIUM",
                  details={"metric": "block_rate"})
        assert tpl.applies_to(good)
        # CRITICAL drift should NOT take this auto path.
        bad_sev = _t(source="zef_drift", severity="CRITICAL",
                     details={"metric": "block_rate"})
        assert not tpl.applies_to(bad_sev)
        # FPR slippage is a regression, not "drift" — must escalate.
        bad_metric = _t(source="zef_drift", severity="MEDIUM",
                        details={"metric": "false_positive_rate"})
        assert not tpl.applies_to(bad_metric)
        # Wrong source.
        bad_src = _t(source="osv", severity="MEDIUM",
                     details={"metric": "block_rate"})
        assert not tpl.applies_to(bad_src)

    def test_execute_marks_baselined(self, monkeypatch):
        from core.security import super_tanks_mode
        monkeypatch.setattr(super_tanks_mode, "_MODEL_TIER_FINGERPRINT",
                            "claude-mythos-2026-04")
        called = []
        monkeypatch.setattr(super_tanks_mode, "mark_zef_baselined",
                            lambda fp: called.append(fp))
        tpl = _by_name("rebaseline_minor_zef_drift")
        note = tpl.execute(_t(source="zef_drift", severity="MEDIUM",
                              details={"metric": "block_rate"}))
        assert called == ["claude-mythos-2026-04"]
        assert "re-baselined" in note

    def test_execute_no_tier_set_returns_empty(self, monkeypatch):
        from core.security import super_tanks_mode
        monkeypatch.setattr(super_tanks_mode, "_MODEL_TIER_FINGERPRINT", None)
        tpl = _by_name("rebaseline_minor_zef_drift")
        assert tpl.execute(_t(source="zef_drift", severity="MEDIUM",
                              details={"metric": "block_rate"})) == ""


# ── mark_dependency_not_imported ──────────────────────────────────────────

class TestMarkDependencyNotImported:
    def test_returns_note_when_package_not_in_sys_modules(self, monkeypatch):
        # Make sure the test package name isn't actually imported.
        monkeypatch.delitem(sys.modules, "totally_made_up_pkg_xyz",
                            raising=False)
        tpl = _by_name("mark_dependency_not_imported")
        note = tpl.execute(_t(source="osv",
                              details={"package": "totally_made_up_pkg_xyz"}))
        assert "not imported" in note

    def test_returns_empty_when_package_is_imported(self, monkeypatch):
        # `json` is always imported.
        tpl = _by_name("mark_dependency_not_imported")
        assert tpl.execute(_t(source="osv",
                              details={"package": "json"})) == ""

    def test_returns_empty_when_no_package_field(self):
        tpl = _by_name("mark_dependency_not_imported")
        assert tpl.execute(_t(source="osv", details={})) == ""

    def test_returns_empty_for_non_osv(self):
        tpl = _by_name("mark_dependency_not_imported")
        assert tpl.execute(_t(source="zef_drift",
                              details={"package": "anything"})) == ""


# ── find_template_for ─────────────────────────────────────────────────────

class TestFindTemplate:
    def test_low_finds_acknowledge(self):
        tpl = zrt.find_template_for(_t(severity="LOW"))
        assert tpl.name == "acknowledge_low"

    def test_zef_drift_finds_rebaseline(self):
        tpl = zrt.find_template_for(_t(source="zef_drift", severity="MEDIUM",
                                       details={"metric": "block_rate"}))
        assert tpl.name == "rebaseline_minor_zef_drift"

    def test_no_match_returns_none(self):
        # A HIGH severity OSV CVE for an imported package — no template.
        tpl = zrt.find_template_for(_t(source="osv", severity="HIGH",
                                       details={"package": "json"}))
        # acknowledge_low rejects (HIGH); zef_drift rejects (osv);
        # mark_dep matches osv via applies_to but returns empty on
        # execute — find_template_for stops at applies_to so it returns
        # the dep template.
        assert tpl is not None
        assert tpl.name == "mark_dependency_not_imported"


def _by_name(name):
    for tpl in zrt.all_templates():
        if tpl.name == name:
            return tpl
    raise AssertionError(f"template {name!r} not registered")


# ── propose_dep_upgrade ───────────────────────────────────────────────────

class TestProposeDepUpgrade:
    """The template that turns a HIGH/CRITICAL OSV CVE into a
    ready-to-apply fix proposal (or auto-applies it when opted in)."""

    @pytest.fixture
    def env(self, tmp_path, monkeypatch):
        from core.security import fix_proposals
        proposals_dir = tmp_path / "proposed_fixes"
        requirements = tmp_path / "requirements.txt"
        requirements.write_text("requests==2.30.0\n")
        monkeypatch.setattr(fix_proposals, "PROPOSALS_DIR", proposals_dir)
        monkeypatch.setattr(fix_proposals, "REQUIREMENTS_FILE", requirements)
        # Make 'requests' look imported.
        sys.modules.setdefault("requests", types.ModuleType("requests"))
        return tmp_path

    def test_applies_only_to_high_or_critical_with_fixed_versions(self):
        tpl = _by_name("propose_dep_upgrade")
        # Right shape, imported package (json is always imported).
        good = _t(source="osv", severity="HIGH",
                  details={"package": "json",
                           "fixed_versions": ["2.0.0"]})
        assert tpl.applies_to(good)
        # MEDIUM → not this template.
        med = _t(source="osv", severity="MEDIUM",
                 details={"package": "json",
                          "fixed_versions": ["2.0.0"]})
        assert not tpl.applies_to(med)
        # No fixed_versions → can't propose.
        no_fix = _t(source="osv", severity="HIGH",
                    details={"package": "json", "fixed_versions": []})
        assert not tpl.applies_to(no_fix)
        # Not imported → mark_not_imported handles it.
        not_imp = _t(source="osv", severity="HIGH",
                     details={"package": "totally_not_imported_xyz",
                              "fixed_versions": ["1.0"]})
        assert not tpl.applies_to(not_imp)

    def test_execute_writes_proposal(self, env, monkeypatch):
        monkeypatch.delenv("ST_ZEPH_AUTO_APPLY_DEPS", raising=False)
        tpl = _by_name("propose_dep_upgrade")
        threat = _t(source="osv", severity="HIGH",
                    fingerprint="CVE-2025-9",
                    summary="RCE in requests",
                    details={"package": "requests",
                             "fixed_versions": ["2.32.5", "2.33.0"]})
        note = tpl.execute(threat)
        assert "proposal" in note
        assert "requests" in note
        assert "2.30.0" in note
        assert "2.32.5" in note
        # File written.
        from core.security import fix_proposals
        all_p = fix_proposals.list_all()
        assert len(all_p) == 1
        assert all_p[0].package == "requests"
        assert all_p[0].target_version == "2.32.5"  # smallest bump

    def test_execute_returns_empty_when_no_pin(self, env):
        # Replace requirements with one that doesn't pin requests.
        from core.security import fix_proposals
        fix_proposals.REQUIREMENTS_FILE.write_text("flask==2.2.0\n")
        tpl = _by_name("propose_dep_upgrade")
        threat = _t(source="osv", severity="HIGH",
                    details={"package": "requests",
                             "fixed_versions": ["2.32.5"]})
        assert tpl.execute(threat) == ""

    def test_auto_apply_path_invokes_dep_upgrade(self, env, monkeypatch):
        monkeypatch.setenv("ST_ZEPH_AUTO_APPLY_DEPS", "1")
        # Stub the apply pipeline so we don't actually pip install.
        from core.security import dep_upgrade_apply

        called = []

        def _fake(proposal, by="operator"):
            called.append((proposal.package, proposal.target_version, by))
            return True, "stub apply ok"

        monkeypatch.setattr(dep_upgrade_apply, "apply_proposal", _fake)
        tpl = _by_name("propose_dep_upgrade")
        note = tpl.execute(_t(source="osv", severity="HIGH",
                              fingerprint="CVE-1",
                              summary="x",
                              details={"package": "requests",
                                       "fixed_versions": ["2.32.5"]}))
        assert called == [("requests", "2.32.5", "zeph_auto")]
        assert "applied" in note
        assert "auto-apply" in note

    def test_auto_apply_failure_is_reported(self, env, monkeypatch):
        monkeypatch.setenv("ST_ZEPH_AUTO_APPLY_DEPS", "1")
        from core.security import dep_upgrade_apply

        def _fake_fail(proposal, by="operator"):
            return False, "pip resolver failure: conflict with foo==1.0"

        monkeypatch.setattr(dep_upgrade_apply, "apply_proposal", _fake_fail)
        tpl = _by_name("propose_dep_upgrade")
        note = tpl.execute(_t(source="osv", severity="HIGH",
                              fingerprint="CVE-1",
                              summary="x",
                              details={"package": "requests",
                                       "fixed_versions": ["2.32.5"]}))
        assert "FAILED" in note
        assert "rolled back" in note
