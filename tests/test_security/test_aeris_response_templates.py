"""
Tests for core/security/aeris_response_templates.py.
"""

import sys
import time
import types

import pytest

from core.security.threat_intel import Threat
from core.security import aeris_response_templates as art


def _t(severity="HIGH", source="ha_health", fingerprint="x",
       summary="s", details=None):
    return Threat(source=source, fingerprint=fingerprint,
                  severity=severity, summary=summary,
                  details=details or {})


# ── Registry shape ─────────────────────────────────────────────────────────

class TestRegistry:
    def test_all_templates_returns_copy(self):
        snap = art.all_templates()
        snap.append("mutated")
        assert "mutated" not in art.all_templates()

    def test_each_template_has_required_attrs(self):
        for tpl in art.all_templates():
            assert tpl.name and tpl.description
            assert callable(tpl.applies_to)
            assert callable(tpl.execute)


# ── clear_stale_ha_approvals ──────────────────────────────────────────────

class TestClearStaleHaApprovals:
    def test_applies_only_to_ha_pending_stale(self):
        tpl = _by_name("clear_stale_ha_approvals")
        good = _t(details={"kind": "ha_pending_stale"})
        assert tpl.applies_to(good)
        bad = _t(details={"kind": "ha_credentials_missing"})
        assert not tpl.applies_to(bad)
        bad_src = _t(source="osv", details={"kind": "ha_pending_stale"})
        assert not tpl.applies_to(bad_src)

    def test_execute_calls_expire_old_requests(self, monkeypatch):
        called = []
        fake_store_mod = types.ModuleType("core.ask_admin")

        class _Store:
            def expire_old_requests(self):
                called.append("expire")
                return 3
        fake_store_mod.ApprovalStore = _Store
        monkeypatch.setitem(sys.modules, "core.ask_admin", fake_store_mod)
        tpl = _by_name("clear_stale_ha_approvals")
        note = tpl.execute(_t(details={"kind": "ha_pending_stale"}))
        assert called == ["expire"]
        assert "3" in note
        assert "expired" in note

    def test_execute_returns_empty_when_nothing_to_expire(self, monkeypatch):
        # ApprovalStore.expire_old_requests only flips rows past their
        # TTL. If the HA pending-stale finding fired on age but no row
        # is past TTL yet, execute returns "" so the engine promotes
        # to PROPOSE.
        fake_store_mod = types.ModuleType("core.ask_admin")

        class _Store:
            def expire_old_requests(self):
                return 0
        fake_store_mod.ApprovalStore = _Store
        monkeypatch.setitem(sys.modules, "core.ask_admin", fake_store_mod)
        tpl = _by_name("clear_stale_ha_approvals")
        assert tpl.execute(_t(details={"kind": "ha_pending_stale"})) == ""


# ── acknowledge_ha_credentials_missing ────────────────────────────────────

class TestAckHaCreds:
    def test_applies_only_to_credentials_missing(self):
        tpl = _by_name("acknowledge_ha_credentials_missing")
        good = _t(severity="CRITICAL",
                  details={"kind": "ha_credentials_missing",
                           "missing": ["HA token"]})
        assert tpl.applies_to(good)
        bad = _t(details={"kind": "ha_pending_stale"})
        assert not tpl.applies_to(bad)

    def test_execute_returns_empty_so_engine_escalates(self):
        # Returning "" makes the engine fall through to PROPOSE;
        # combined with CRITICAL severity that resolves to ESCALATE_NOW.
        # Aeris cannot mint a HA token, so escalation is correct.
        tpl = _by_name("acknowledge_ha_credentials_missing")
        out = tpl.execute(_t(severity="CRITICAL",
                             details={"kind": "ha_credentials_missing",
                                      "missing": ["HA token"]}))
        assert out == ""


# ── find_template_for ─────────────────────────────────────────────────────

class TestFindTemplate:
    def test_pending_stale_routes_to_clear(self):
        tpl = art.find_template_for(
            _t(details={"kind": "ha_pending_stale"}))
        assert tpl.name == "clear_stale_ha_approvals"

    def test_creds_missing_routes_to_ack(self):
        tpl = art.find_template_for(
            _t(details={"kind": "ha_credentials_missing",
                        "missing": ["HA URL"]}))
        assert tpl.name == "acknowledge_ha_credentials_missing"

    def test_unrelated_threat_returns_none(self):
        assert art.find_template_for(
            _t(source="osv", details={"package": "x"})) is None


def _by_name(name):
    for tpl in art.all_templates():
        if tpl.name == name:
            return tpl
    raise AssertionError(f"template {name!r} not registered")
