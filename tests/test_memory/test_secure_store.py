"""
Tests for core/memory/secure_store.py.

SecureMemoryStore is the enforcement layer that HierarchicalMemoryStore
lacks. These tests verify that every operation honours tripwire
detection, RBAC, and audit logging — and that nothing slips through.
"""

import sys
import types

import pytest

from core.memory.hierarchical_store import HierarchicalMemoryStore


@pytest.fixture
def secure(tmp_path, monkeypatch):
    """SecureMemoryStore against a tmp HierarchicalMemoryStore with all
    collaborators stubbed to capture calls."""
    from core.memory import secure_store, hierarchical_store

    # Redirect the underlying store to a tmp dir.
    monkeypatch.setattr(hierarchical_store, "STORE_ROOT", tmp_path / "hm")

    audit_calls = []
    alarm_calls = []

    fake_audit = types.ModuleType("core.memory.audit_log")
    fake_audit.log_access = lambda **kw: audit_calls.append(kw)
    monkeypatch.setitem(sys.modules, "core.memory.audit_log", fake_audit)

    fake_ac = types.ModuleType("core.memory.access_control")
    # By default everything is allowed; individual tests override.
    fake_ac.is_path_accessible = lambda path, agent, mode: True
    fake_ac.trigger_tripwire_alarm = lambda path, agent: \
        alarm_calls.append((path, agent))
    monkeypatch.setitem(sys.modules, "core.memory.access_control", fake_ac)

    raw = HierarchicalMemoryStore(store_root=tmp_path / "hm")
    store = secure_store.SecureMemoryStore(raw_store=raw)
    return types.SimpleNamespace(
        store=store, raw=raw, audit_calls=audit_calls,
        alarm_calls=alarm_calls, fake_ac=fake_ac,
    )


# ── Tripwire enforcement ──────────────────────────────────────────────

class TestTripwireEnforcement:
    def test_read_tripwire_blocked_and_alarmed(self, secure):
        result = secure.store.read("/william/secrets", "aeris")
        assert result is None
        assert secure.alarm_calls == [("/william/secrets", "aeris")]
        assert any(a["operation"] == "READ_TRIPWIRE_BLOCKED"
                   for a in secure.audit_calls)

    def test_store_tripwire_blocked_and_alarmed(self, secure):
        result = secure.store.store(
            "/william/secrets", "zeph",
            l0_abstract="x", l1_overview="y", l2_full="z")
        assert result is None
        assert secure.alarm_calls == [("/william/secrets", "zeph")]

    def test_delete_tripwire_blocked_and_alarmed(self, secure):
        result = secure.store.delete("/system/admin_keys", "zeph")
        assert result is False
        assert secure.alarm_calls == [("/system/admin_keys", "zeph")]


# ── RBAC enforcement ──────────────────────────────────────────────────

class TestRbacEnforcement:
    def test_read_denied_by_access_control(self, secure):
        secure.fake_ac.is_path_accessible = lambda p, a, m: False
        # Seed a path the underlying store would otherwise return.
        secure.raw.store("/family/finance/budget", "abs", "ov", {"x": 1})
        assert secure.store.read("/family/finance/budget", "aeris") is None
        assert any(a["operation"] == "READ_DENIED"
                   for a in secure.audit_calls)

    def test_store_denied(self, secure):
        secure.fake_ac.is_path_accessible = lambda p, a, m: False
        result = secure.store.store(
            "/family/finance/budget", "aeris",
            l0_abstract="x", l1_overview="y", l2_full="z")
        assert result is None
        # And the raw store really wasn't written to.
        assert secure.raw.read("/family/finance/budget") is None

    def test_delete_denied(self, secure):
        secure.raw.store("/family/preferences/x", "abs", "ov", "z")
        secure.fake_ac.is_path_accessible = lambda p, a, m: False
        assert secure.store.delete("/family/preferences/x", "aeris") is False
        # Underlying file still present.
        assert secure.raw.read("/family/preferences/x") is not None


# ── Audit logging ─────────────────────────────────────────────────────

class TestAuditLogging:
    def test_read_logs_on_success(self, secure):
        secure.raw.store("/family/preferences/x", "abs", "ov", "z")
        secure.store.read("/family/preferences/x", "aeris")
        ops = [a["operation"] for a in secure.audit_calls]
        assert "READ" in ops

    def test_write_logs_on_success(self, secure):
        secure.store.store("/family/preferences/x", "aeris",
                           l0_abstract="abs", l1_overview="ov", l2_full="z")
        ops = [a["operation"] for a in secure.audit_calls]
        assert "WRITE" in ops

    def test_delete_logs_on_success(self, secure):
        secure.raw.store("/family/preferences/x", "abs", "ov", "z")
        secure.store.delete("/family/preferences/x", "aeris")
        ops = [a["operation"] for a in secure.audit_calls]
        assert "DELETE" in ops

    def test_list_logs(self, secure):
        secure.store.list_dir("/family/preferences", "aeris")
        ops = [a["operation"] for a in secure.audit_calls]
        assert "LIST" in ops

    def test_search_logs(self, secure):
        secure.store.search("preferences", "aeris")
        ops = [a["operation"] for a in secure.audit_calls]
        assert "SEARCH" in ops

    def test_audit_failure_does_not_raise(self, secure, monkeypatch):
        # If the audit subsystem is down, the operation still completes
        # but the failure is loud, not silent.
        sys.modules["core.memory.audit_log"].log_access = \
            lambda **kw: (_ for _ in ()).throw(RuntimeError("audit down"))
        # Must not raise.
        secure.store.read("/family/preferences/x", "aeris")


# ── list_dir / search filtering ──────────────────────────────────────

class TestListAndSearchFiltering:
    def test_list_dir_filters_tripwires_silently(self, secure):
        secure.raw.store("/system/admin_keys", "real", "real", "x")
        secure.raw.store("/family/preferences/light", "ok", "ok", "x")
        items = secure.store.list_dir("/", "aeris")
        paths = [i["path"] for i in items]
        assert "/system/admin_keys" not in paths
        assert "/family/preferences/light" in paths
        # No alarm fires for a silent filter — alarm is only for direct
        # read attempts.
        assert secure.alarm_calls == []

    def test_list_dir_filters_inaccessible_paths(self, secure):
        secure.fake_ac.is_path_accessible = lambda p, a, m: p.startswith("/family/preferences/")
        secure.raw.store("/family/preferences/light", "ok", "ok", "x")
        secure.raw.store("/family/finance/budget", "denied", "denied", "x")
        items = secure.store.list_dir("/", "aeris")
        paths = [i["path"] for i in items]
        assert "/family/preferences/light" in paths
        assert "/family/finance/budget" not in paths

    def test_search_filters_tripwires(self, secure):
        secure.raw.store("/william/secrets", "secret password", "ov", "x")
        secure.raw.store("/family/preferences/auth", "password pref", "ov", "x")
        hits = secure.store.search("password", "aeris")
        paths = [h["path"] for h in hits]
        assert "/william/secrets" not in paths
        assert "/family/preferences/auth" in paths


# ── Module-level singleton ────────────────────────────────────────────

class TestSingleton:
    def test_get_secure_store_returns_same_instance(self, monkeypatch):
        from core.memory import secure_store
        monkeypatch.setattr(secure_store, "_default_secure_store", None)
        a = secure_store.get_secure_store()
        b = secure_store.get_secure_store()
        assert a is b
