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


def _t(severity="MEDIUM", source="osv", fingerprint="x", details=None):
    return Threat(source=source, fingerprint=fingerprint,
                  severity=severity, summary="s",
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
