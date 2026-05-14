"""
Tests for core/bootstrap.py.

Each test redirects every module the bootstrap touches and verifies the
step is invoked. Hard-fail vs soft-fail semantics are pinned: a DIQ
integrity violation aborts; a soul tampering enters SAFE_MODE without
aborting; a missing tools/ registry is logged but does not fail boot.
"""

import sys
import types

import pytest


@pytest.fixture
def boot_env(monkeypatch):
    """Patch every collaborator the bootstrap touches with capturing fakes."""
    from core import bootstrap

    monkeypatch.setattr(bootstrap, "_boot_result", None)

    calls = {
        "verify_diq": 0,
        "check_souls": 0,
        "load_mode": 0,
        "ensure_admin": 0,
        "ensure_tripwires": 0,
        "register_tools": 0,
    }
    state = {
        "diq_raises": False,
        "souls_ok": True,
        "souls_reason": "",
        "tools_import_error": False,
    }

    # ── diq_integrity ──
    fake_diq = types.ModuleType("core.diq.diq_integrity")

    def _verify():
        calls["verify_diq"] += 1
        if state["diq_raises"]:
            raise RuntimeError("DIQ tampered")
    fake_diq.verify_diq_integrity = _verify
    monkeypatch.setitem(sys.modules, "core.diq.diq_integrity", fake_diq)

    # ── soul_guard ──
    fake_soul = types.ModuleType("core.soul_guard")

    def _check_souls():
        calls["check_souls"] += 1
        return state["souls_ok"], state["souls_reason"]

    fake_soul.check_soul_integrity = _check_souls
    fake_soul.is_safe_mode = lambda: not state["souls_ok"]
    fake_soul.get_safe_mode_reason = lambda: state["souls_reason"]
    monkeypatch.setitem(sys.modules, "core.soul_guard", fake_soul)

    # ── super_tanks_mode ──
    fake_mode = types.ModuleType("core.security.super_tanks_mode")
    fake_mode.load_mode_from_state = lambda: calls.update(load_mode=calls["load_mode"] + 1)
    tier_state = {
        "set_upstream_tier_count": 0,
        "load_zef_baseline_count": 0,
        "tier_set_to": None,
        "baseline_loaded_returns": None,
    }

    def _set_tier(fp):
        tier_state["set_upstream_tier_count"] += 1
        tier_state["tier_set_to"] = fp
    fake_mode.set_current_model_tier = _set_tier

    def _load_baseline():
        tier_state["load_zef_baseline_count"] += 1
        return tier_state["baseline_loaded_returns"]
    fake_mode.load_zef_baseline = _load_baseline
    monkeypatch.setitem(sys.modules, "core.security.super_tanks_mode", fake_mode)

    # ── user_manager ──
    fake_um = types.ModuleType("core.security.user_manager")
    fake_um.ensure_admin_exists = lambda: calls.update(ensure_admin=calls["ensure_admin"] + 1)
    monkeypatch.setitem(sys.modules, "core.security.user_manager", fake_um)

    # ── tripwires + hierarchical_store ──
    fake_hs = types.ModuleType("core.memory.hierarchical_store")
    fake_hs.HierarchicalMemoryStore = lambda: object()
    monkeypatch.setitem(sys.modules, "core.memory.hierarchical_store", fake_hs)

    fake_tw = types.ModuleType("core.memory.tripwires")

    def _ensure_tw(store):
        calls["ensure_tripwires"] += 1
        return 0
    fake_tw.ensure_tripwires_exist = _ensure_tw
    monkeypatch.setitem(sys.modules, "core.memory.tripwires", fake_tw)

    # ── threat_scan (stubs the threat-intel registration step) ──
    fake_ts_script = types.ModuleType("scripts.threat_scan")
    calls["threat_intel_register"] = 0

    def _fake_sources():
        calls["threat_intel_register"] += 1
    fake_ts_script._build_default_sources = _fake_sources
    fake_ts_script._build_default_mitigators = lambda: None
    monkeypatch.setitem(sys.modules, "scripts.threat_scan", fake_ts_script)

    # ── diq_registry ──
    fake_reg = types.ModuleType("core.diq.diq_registry")

    def _reg_boot():
        calls["register_tools"] += 1
        if state["tools_import_error"]:
            raise ImportError("tools/ not present")
    fake_reg.bootstrap = _reg_boot
    monkeypatch.setitem(sys.modules, "core.diq.diq_registry", fake_reg)

    return types.SimpleNamespace(boot_mod=bootstrap, calls=calls,
                                  state=state, tier_state=tier_state)


# ── Happy path ────────────────────────────────────────────────────────

class TestHappyPath:
    def test_all_steps_run_in_order(self, boot_env):
        result = boot_env.boot_mod.boot()
        assert result.success is True
        assert result.safe_mode is False
        # Every step ran exactly once.
        for step, count in boot_env.calls.items():
            assert count == 1, f"step {step} ran {count} times"

    def test_steps_completed_recorded(self, boot_env):
        result = boot_env.boot_mod.boot()
        assert "verify_diq_integrity" in result.steps_completed
        assert "check_soul_integrity" in result.steps_completed
        assert "ensure_tripwires_exist" in result.steps_completed


# ── Hard-fail: DIQ tampering ──────────────────────────────────────────

class TestDiqTamperingAborts:
    def test_diq_raises_aborts_boot(self, boot_env):
        boot_env.state["diq_raises"] = True
        with pytest.raises(RuntimeError, match="DIQ"):
            boot_env.boot_mod.boot()
        # No later step ran.
        assert boot_env.calls["check_souls"] == 0
        assert boot_env.calls["ensure_admin"] == 0


# ── Soft-fail: soul tampering → safe mode ─────────────────────────────

class TestSoulTamperingSafeMode:
    def test_soul_mismatch_enters_safe_mode_without_abort(self, boot_env):
        boot_env.state["souls_ok"] = False
        boot_env.state["souls_reason"] = "aeris_soul.py hash mismatch"
        result = boot_env.boot_mod.boot()
        assert result.success is True
        assert result.safe_mode is True
        assert "aeris_soul.py" in result.safe_mode_reason
        # Later steps still ran — system stays partially up.
        assert boot_env.calls["ensure_admin"] == 1


# ── Soft-fail: missing tools/ registry ────────────────────────────────

class TestMissingToolsRegistry:
    def test_import_error_logged_not_raised(self, boot_env):
        boot_env.state["tools_import_error"] = True
        result = boot_env.boot_mod.boot()
        assert result.success is True
        assert any("registry" in e for e in result.errors)


# ── Tier-rebaseline gate wiring ───────────────────────────────────────

class TestUpstreamTierStep:
    def test_env_var_arms_the_gate(self, boot_env, monkeypatch):
        monkeypatch.setenv("ST_UPSTREAM_MODEL", "claude-mythos-2026-04")
        boot_env.boot_mod.boot()
        assert boot_env.tier_state["set_upstream_tier_count"] == 1
        assert boot_env.tier_state["tier_set_to"] == "claude-mythos-2026-04"
        assert "load_upstream_tier" in boot_env.boot_mod.get_boot_result().steps_completed

    def test_no_env_var_leaves_gate_dormant(self, boot_env, monkeypatch):
        monkeypatch.delenv("ST_UPSTREAM_MODEL", raising=False)
        boot_env.boot_mod.boot()
        assert boot_env.tier_state["set_upstream_tier_count"] == 0
        # Step still records completion — load_zef_baseline ran too.
        assert boot_env.tier_state["load_zef_baseline_count"] == 1
        assert "load_upstream_tier" in boot_env.boot_mod.get_boot_result().steps_completed

    def test_persisted_baseline_is_loaded(self, boot_env, monkeypatch):
        monkeypatch.setenv("ST_UPSTREAM_MODEL", "claude-mythos-2026-04")
        boot_env.tier_state["baseline_loaded_returns"] = "claude-mythos-2026-04"
        boot_env.boot_mod.boot()
        assert boot_env.tier_state["load_zef_baseline_count"] == 1


# ── Threat-intel registration ─────────────────────────────────────────

class TestThreatIntelStep:
    def test_intel_sources_registered_at_boot(self, boot_env):
        boot_env.boot_mod.boot()
        assert boot_env.calls["threat_intel_register"] == 1
        assert "register_threat_intel" in boot_env.boot_mod.get_boot_result().steps_completed


# ── Idempotency ───────────────────────────────────────────────────────

class TestIdempotency:
    def test_second_call_returns_cached_result(self, boot_env):
        first = boot_env.boot_mod.boot()
        second = boot_env.boot_mod.boot()
        assert first is second
        # Steps ran exactly once total.
        assert boot_env.calls["verify_diq"] == 1

    def test_force_reruns_steps(self, boot_env):
        boot_env.boot_mod.boot()
        boot_env.boot_mod.boot(force=True)
        assert boot_env.calls["verify_diq"] == 2

    def test_is_booted_reflects_state(self, boot_env):
        assert boot_env.boot_mod.is_booted() is False
        boot_env.boot_mod.boot()
        assert boot_env.boot_mod.is_booted() is True

    def test_get_boot_result_returns_last(self, boot_env):
        result = boot_env.boot_mod.boot()
        assert boot_env.boot_mod.get_boot_result() is result
