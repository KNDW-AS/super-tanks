"""
Tests for core/security/super_tanks_mode.py.

The module holds global mode state, so the `stm` fixture resets all
module-level globals between tests, redirects STATE_FILE to a tmp path,
and stubs the lazy-imported collaborators (trust_score, audit_store,
night_queue, requests).
"""

import json
import sys
import time
import types
from datetime import datetime

import pytest


@pytest.fixture
def stm(tmp_path, monkeypatch):
    from core.security import super_tanks_mode as m

    # Reset all module globals to defaults.
    monkeypatch.setattr(m, "_current_mode", m.TankMode.LOCKDOWN)
    monkeypatch.setattr(m, "_autonomous_started_at", 0)
    monkeypatch.setattr(m, "_autonomous_timeout_at", 0)
    monkeypatch.setattr(m, "_timeout_hours", 8)
    monkeypatch.setattr(m, "_night_mode_active", False)
    monkeypatch.setattr(m, "_last_interaction", time.time())
    monkeypatch.setattr(m, "_MODEL_TIER_FINGERPRINT", None)
    monkeypatch.setattr(m, "_LAST_BASELINED_TIER", None)

    state_file = tmp_path / "super_tanks_state.json"
    monkeypatch.setattr(m, "STATE_FILE", state_file)
    # Redirect ZEF baseline persistence so mark_zef_baselined doesn't
    # write into the real config dir during tests.
    baseline_file = tmp_path / "zef_baseline.json"
    monkeypatch.setattr(m, "ZEF_BASELINE_FILE", baseline_file)

    # Capture Telegram posts.
    posts = []
    fake_requests = types.SimpleNamespace(
        post=lambda *a, **kw: posts.append((a, kw)))
    monkeypatch.setitem(sys.modules, "requests", fake_requests)
    monkeypatch.setenv("AERIS_GOGATE_TELEGRAM_TOKEN", "fake")
    monkeypatch.setenv("AERIS_ADMIN_CHAT_ID", "1")

    # Stub memory audit log (lazy-imported in set_mode). Previously
    # set_mode imported core.audit_store, a module that doesn't exist —
    # the import error was silently swallowed and mode changes ran
    # un-audited. The real implementation now routes through the
    # existing memory audit log.
    audit_calls = []
    fake_audit = types.ModuleType("core.memory.audit_log")
    fake_audit.log_access = lambda **kw: audit_calls.append(kw)
    monkeypatch.setitem(sys.modules, "core.memory.audit_log", fake_audit)

    # Stub night_queue.
    queue_calls = []
    fake_nq = types.ModuleType("core.security.night_queue")
    fake_nq.queue_action = lambda agent, tool, params, reason="": (
        queue_calls.append((agent, tool, params, reason)) or
        {"queued_at": "now", "queue_id": len(queue_calls)})
    fake_nq.build_morning_report = lambda: ""
    monkeypatch.setitem(sys.modules, "core.security.night_queue", fake_nq)

    # Stub trust_score (used in get_effective_gogate_roles).
    fake_ts = types.ModuleType("core.security.trust_score")
    trust_state = {"level": "standard"}
    fake_ts.get_score = lambda agent_id: {"level": trust_state["level"],
                                          "score": 60.0, "agent_id": agent_id}
    monkeypatch.setitem(sys.modules, "core.security.trust_score", fake_ts)

    return types.SimpleNamespace(
        m=m, state_file=state_file, posts=posts,
        audit_calls=audit_calls, queue_calls=queue_calls,
        trust_state=trust_state,
    )


# ── Mode getters ───────────────────────────────────────────────────────────

class TestModeGetters:
    def test_default_is_lockdown(self, stm):
        assert stm.m.get_mode() == stm.m.TankMode.LOCKDOWN

    def test_get_mode_config_returns_lockdown_config(self, stm):
        cfg = stm.m.get_mode_config()
        assert cfg["gogate_required_roles"] == ["WRITE", "EXEC", "ADMIN"]
        assert cfg["zef_llm_classifier"] is True

    def test_get_config_value(self, stm):
        assert stm.m.get_config_value("zef_llm_classifier") is True
        assert stm.m.get_config_value("nonexistent") is None


# ── set_mode ───────────────────────────────────────────────────────────────

class TestSetMode:
    def test_switching_to_autonomous_sets_timeout(self, stm):
        cfg = stm.m.set_mode(stm.m.TankMode.AUTONOMOUS, timeout_hours=8)
        assert stm.m.get_mode() == stm.m.TankMode.AUTONOMOUS
        assert cfg["gogate_required_roles"] == ["ADMIN"]
        info = stm.m.get_timeout_info()
        assert info["active"] is True
        assert info["remaining_seconds"] == pytest.approx(8 * 3600, abs=5)

    def test_switching_to_lockdown_clears_timeout(self, stm):
        stm.m.set_mode(stm.m.TankMode.AUTONOMOUS, timeout_hours=8)
        stm.m.set_mode(stm.m.TankMode.LOCKDOWN)
        assert stm.m.get_timeout_info() == {"active": False}

    def test_persists_state_to_disk(self, stm):
        stm.m.set_mode(stm.m.TankMode.AUTONOMOUS, timeout_hours=4)
        assert stm.state_file.exists()
        state = json.loads(stm.state_file.read_text())
        assert state["mode"] == "autonomous"
        assert state["timeout_hours"] == 4
        assert state["changed_from"] == "lockdown"

    def test_audit_log_called(self, stm):
        stm.m.set_mode(stm.m.TankMode.AUTONOMOUS, timeout_hours=8)
        assert len(stm.audit_calls) == 1
        entry = stm.audit_calls[0]
        assert entry["operation"] == "MODE_CHANGE"
        assert "lockdown->autonomous" in entry["path"]
        assert entry["mode"] == "autonomous"

    def test_telegram_notification_sent(self, stm):
        stm.m.set_mode(stm.m.TankMode.AUTONOMOUS, timeout_hours=8)
        assert len(stm.posts) == 1
        text = stm.posts[0][1]["json"]["text"]
        assert "AUTONOMOUS aktivert" in text


# ── Timeout behaviour ──────────────────────────────────────────────────────

class TestTimeout:
    def test_check_timeout_noop_when_in_lockdown(self, stm):
        assert stm.m.check_timeout() is False

    def test_check_timeout_returns_false_before_expiry(self, stm):
        stm.m.set_mode(stm.m.TankMode.AUTONOMOUS, timeout_hours=8)
        assert stm.m.check_timeout() is False

    def test_check_timeout_switches_to_lockdown_after_expiry(self, stm, monkeypatch):
        stm.m.set_mode(stm.m.TankMode.AUTONOMOUS, timeout_hours=8)
        # Force the timeout into the past.
        monkeypatch.setattr(stm.m, "_autonomous_timeout_at", time.time() - 1)
        assert stm.m.check_timeout() is True
        assert stm.m.get_mode() == stm.m.TankMode.LOCKDOWN

    def test_extend_autonomous_pushes_timeout(self, stm):
        stm.m.set_mode(stm.m.TankMode.AUTONOMOUS, timeout_hours=4)
        before = stm.m.get_timeout_info()["timeout_at"]
        info = stm.m.extend_autonomous(extra_hours=2)
        assert info["timeout_at"] == pytest.approx(before + 2 * 3600, abs=5)
        assert info["timeout_hours"] == 6

    def test_extend_in_lockdown_returns_error(self, stm):
        result = stm.m.extend_autonomous(extra_hours=2)
        assert "error" in result


# ── Trust-aware GO-Gate roles ──────────────────────────────────────────────

class TestEffectiveGogateRoles:
    def test_lockdown_returns_full_role_list(self, stm):
        roles = stm.m.get_effective_gogate_roles("aeris")
        assert set(roles) == {"WRITE", "EXEC", "ADMIN"}

    def test_autonomous_returns_admin_only_for_standard_trust(self, stm):
        stm.m.set_mode(stm.m.TankMode.AUTONOMOUS, timeout_hours=8)
        roles = stm.m.get_effective_gogate_roles("aeris")
        assert roles == ["ADMIN"]

    def test_probation_always_requires_full_approval(self, stm):
        stm.trust_state["level"] = "probation"
        stm.m.set_mode(stm.m.TankMode.AUTONOMOUS, timeout_hours=8)
        roles = stm.m.get_effective_gogate_roles("aeris")
        assert set(roles) == {"WRITE", "EXEC", "ADMIN"}

    def test_junior_in_autonomous_requires_full_approval(self, stm):
        stm.trust_state["level"] = "junior"
        stm.m.set_mode(stm.m.TankMode.AUTONOMOUS, timeout_hours=8)
        roles = stm.m.get_effective_gogate_roles("aeris")
        assert set(roles) == {"WRITE", "EXEC", "ADMIN"}

    def test_junior_in_lockdown_uses_base_roles(self, stm):
        stm.trust_state["level"] = "junior"
        roles = stm.m.get_effective_gogate_roles("aeris")
        # Already WRITE/EXEC/ADMIN from lockdown base — junior doesn't reduce.
        assert set(roles) == {"WRITE", "EXEC", "ADMIN"}

    def test_requires_approval_uses_effective_roles(self, stm):
        stm.m.set_mode(stm.m.TankMode.AUTONOMOUS, timeout_hours=8)
        assert stm.m.requires_approval("ADMIN", "aeris") is True
        assert stm.m.requires_approval("WRITE", "aeris") is False
        assert stm.m.requires_approval("READ", "aeris") is False


# ── Night mode ─────────────────────────────────────────────────────────────

class TestNightMode:
    def test_night_mode_off_in_lockdown(self, stm, monkeypatch):
        # check_night_mode requires AUTONOMOUS to ever activate.
        monkeypatch.setattr(stm.m, "_night_mode_active", True)
        stm.m.check_night_mode()
        assert stm.m.is_night_mode() is False

    def test_activates_at_night_after_inactivity(self, stm, monkeypatch):
        stm.m.set_mode(stm.m.TankMode.AUTONOMOUS, timeout_hours=8)

        class FakeDT:
            @staticmethod
            def now(tz=None):
                return datetime(2024, 1, 1, 23, 30)

            @staticmethod
            def fromtimestamp(ts):
                return datetime.fromtimestamp(ts)

            fromisoformat = staticmethod(datetime.fromisoformat)
            timezone = datetime.now().tzinfo

        monkeypatch.setattr(stm.m, "datetime", FakeDT)
        monkeypatch.setattr(stm.m, "_last_interaction", time.time() - 3 * 3600)
        stm.m.check_night_mode()
        assert stm.m.is_night_mode() is True

    def test_does_not_activate_during_day(self, stm, monkeypatch):
        stm.m.set_mode(stm.m.TankMode.AUTONOMOUS, timeout_hours=8)

        class FakeDT:
            @staticmethod
            def now(tz=None):
                return datetime(2024, 1, 1, 12, 0)
            fromtimestamp = staticmethod(datetime.fromtimestamp)

        monkeypatch.setattr(stm.m, "datetime", FakeDT)
        monkeypatch.setattr(stm.m, "_last_interaction", time.time() - 10 * 3600)
        stm.m.check_night_mode()
        assert stm.m.is_night_mode() is False

    def test_does_not_activate_with_recent_interaction(self, stm, monkeypatch):
        stm.m.set_mode(stm.m.TankMode.AUTONOMOUS, timeout_hours=8)

        class FakeDT:
            @staticmethod
            def now(tz=None):
                return datetime(2024, 1, 1, 23, 30)
            fromtimestamp = staticmethod(datetime.fromtimestamp)

        monkeypatch.setattr(stm.m, "datetime", FakeDT)
        stm.m.record_interaction()
        stm.m.check_night_mode()
        assert stm.m.is_night_mode() is False


# ── check_night_tool ───────────────────────────────────────────────────────

class TestCheckNightTool:
    def test_passes_through_when_not_in_night(self, stm):
        assert stm.m.check_night_tool("aeris", "anything") == {"allowed": True}

    def test_aeris_allowed_tools_pass(self, stm, monkeypatch):
        monkeypatch.setattr(stm.m, "_night_mode_active", True)
        for tool in ("ha_search", "weather_met", "calculator"):
            assert stm.m.check_night_tool("aeris", tool)["allowed"] is True

    def test_aeris_other_tools_blocked(self, stm, monkeypatch):
        monkeypatch.setattr(stm.m, "_night_mode_active", True)
        result = stm.m.check_night_tool("aeris", "image_generate")
        assert result["allowed"] is False
        assert result["blocked"] is True

    def test_zeph_allowed_tools_pass(self, stm, monkeypatch):
        monkeypatch.setattr(stm.m, "_night_mode_active", True)
        assert stm.m.check_night_tool("zeph", "ha_search")["allowed"] is True

    def test_zeph_queued_tools_go_to_queue(self, stm, monkeypatch):
        monkeypatch.setattr(stm.m, "_night_mode_active", True)
        result = stm.m.check_night_tool("zeph", "home_assistant",
                                        params={"entity": "light.x"})
        assert result["allowed"] is False
        assert result["queued"] is True
        assert len(stm.queue_calls) == 1
        agent, tool, params, _reason = stm.queue_calls[0]
        assert agent == "zeph"
        assert tool == "home_assistant"
        assert params == {"entity": "light.x"}

    def test_zeph_blocked_tools_hard_deny(self, stm, monkeypatch):
        monkeypatch.setattr(stm.m, "_night_mode_active", True)
        result = stm.m.check_night_tool("zeph", "shell_exec")
        assert result["allowed"] is False
        assert result["blocked"] is True
        assert stm.queue_calls == []

    def test_zeph_unknown_tools_default_to_queue(self, stm, monkeypatch):
        monkeypatch.setattr(stm.m, "_night_mode_active", True)
        result = stm.m.check_night_tool("zeph", "wholly_new_tool")
        assert result["queued"] is True
        assert len(stm.queue_calls) == 1


# ── load_mode_from_state ───────────────────────────────────────────────────

class TestLoadModeFromState:
    def test_no_state_file_defaults_to_lockdown(self, stm):
        stm.m.load_mode_from_state()
        assert stm.m.get_mode() == stm.m.TankMode.LOCKDOWN

    def test_restores_autonomous_mode(self, stm):
        state = {
            "mode": "autonomous",
            "autonomous_started_at": time.time(),
            "autonomous_timeout_at": time.time() + 3600,
            "timeout_hours": 8,
        }
        stm.state_file.write_text(json.dumps(state))
        stm.m.load_mode_from_state()
        assert stm.m.get_mode() == stm.m.TankMode.AUTONOMOUS

    def test_expired_autonomous_state_resolves_to_lockdown(self, stm):
        state = {
            "mode": "autonomous",
            "autonomous_started_at": time.time() - 7200,
            "autonomous_timeout_at": time.time() - 60,  # already expired
            "timeout_hours": 1,
        }
        stm.state_file.write_text(json.dumps(state))
        stm.m.load_mode_from_state()
        assert stm.m.get_mode() == stm.m.TankMode.LOCKDOWN

    def test_corrupt_state_defaults_to_lockdown(self, stm):
        stm.state_file.write_text("{ not json")
        stm.m.load_mode_from_state()
        assert stm.m.get_mode() == stm.m.TankMode.LOCKDOWN


# ── get_effective_mode ─────────────────────────────────────────────────────

class TestGetEffectiveMode:
    def test_lockdown_summary(self, stm):
        info = stm.m.get_effective_mode()
        assert info["mode"] == "lockdown"
        assert info["display"] == "LOCKDOWN"
        assert info["night_mode"] is False

    def test_autonomous_summary_with_timeout(self, stm):
        stm.m.set_mode(stm.m.TankMode.AUTONOMOUS, timeout_hours=8)
        info = stm.m.get_effective_mode()
        assert info["mode"] == "autonomous"
        assert info["display"] == "AUTONOMOUS"
        assert info["timeout"]["active"] is True

    def test_autonomous_with_night_shows_moon(self, stm, monkeypatch):
        stm.m.set_mode(stm.m.TankMode.AUTONOMOUS, timeout_hours=8)
        monkeypatch.setattr(stm.m, "_night_mode_active", True)
        info = stm.m.get_effective_mode()
        assert info["night_mode"] is True
        assert "🌙" in info["display"]


# ── Tier-rebaseline gate ───────────────────────────────────────────────────

class TestTierRebaseline:
    """Force ZEF re-baseline before AUTONOMOUS on a new upstream model.

    A new Claude / Gemini tier may have different refusal training. Our
    ZEF false-positive / true-positive measurements were taken against
    the previous tier. Until those are re-measured against the new
    tier, AUTONOMOUS would grant wider autonomy to a model whose
    safety surface is unmeasured.
    """

    def test_no_tier_set_means_no_rebaseline(self, stm):
        # Legacy / pre-Mythos: tier tracking unused → never blocks.
        assert stm.m.needs_rebaseline() is False
        stm.m.set_mode(stm.m.TankMode.AUTONOMOUS, timeout_hours=8)
        assert stm.m.get_mode() == stm.m.TankMode.AUTONOMOUS

    def test_baseline_matches_current_tier(self, stm):
        stm.m.set_current_model_tier("claude-mythos-2026-04")
        stm.m.mark_zef_baselined("claude-mythos-2026-04")
        assert stm.m.needs_rebaseline() is False

    def test_baseline_mismatched_tier_needs_rebaseline(self, stm):
        stm.m.set_current_model_tier("claude-mythos-2026-04")
        stm.m.mark_zef_baselined("claude-sonnet-4-6")
        assert stm.m.needs_rebaseline() is True

    def test_tier_set_without_baseline_needs_rebaseline(self, stm):
        # New tier observed but no baseline ever recorded.
        stm.m.set_current_model_tier("claude-mythos-2026-04")
        assert stm.m.needs_rebaseline() is True

    def test_set_mode_autonomous_refused_when_stale(self, stm):
        stm.m.set_current_model_tier("claude-mythos-2026-04")
        stm.m.mark_zef_baselined("claude-sonnet-4-6")
        with pytest.raises(stm.m.StaleBaselineError):
            stm.m.set_mode(stm.m.TankMode.AUTONOMOUS, timeout_hours=8)
        # Mode must NOT have flipped; still LOCKDOWN.
        assert stm.m.get_mode() == stm.m.TankMode.LOCKDOWN

    def test_set_mode_lockdown_never_blocked_by_stale_baseline(self, stm):
        # Going TO lockdown is always safe — only AUTONOMOUS is gated.
        stm.m.set_current_model_tier("claude-mythos-2026-04")
        stm.m.mark_zef_baselined("claude-sonnet-4-6")
        # Pretend we were already AUTONOMOUS somehow (e.g. legacy state).
        # set_mode(LOCKDOWN) must never raise.
        stm.m.set_mode(stm.m.TankMode.LOCKDOWN)
        assert stm.m.get_mode() == stm.m.TankMode.LOCKDOWN

    def test_remediation_flow_unblocks_autonomous(self, stm):
        stm.m.set_current_model_tier("claude-mythos-2026-04")
        stm.m.mark_zef_baselined("claude-sonnet-4-6")
        # Operator runs the corpus and signs off on the new tier.
        stm.m.mark_zef_baselined("claude-mythos-2026-04")
        # Now AUTONOMOUS is allowed.
        stm.m.set_mode(stm.m.TankMode.AUTONOMOUS, timeout_hours=8)
        assert stm.m.get_mode() == stm.m.TankMode.AUTONOMOUS

    def test_mark_zef_baselined_persists_to_disk(self, stm):
        stm.m.mark_zef_baselined("claude-mythos-2026-04")
        assert stm.m.ZEF_BASELINE_FILE.exists()
        data = json.loads(stm.m.ZEF_BASELINE_FILE.read_text())
        assert data["fingerprint"] == "claude-mythos-2026-04"
        assert "baselined_at" in data

    def test_load_zef_baseline_round_trip(self, stm, monkeypatch):
        # Persist via the API.
        stm.m.mark_zef_baselined("claude-mythos-2026-04")
        # Wipe in-memory state, simulate restart.
        monkeypatch.setattr(stm.m, "_LAST_BASELINED_TIER", None)
        # Load picks the fingerprint back up.
        loaded = stm.m.load_zef_baseline()
        assert loaded == "claude-mythos-2026-04"
        # And the in-memory global is restored.
        stm.m.set_current_model_tier("claude-mythos-2026-04")
        assert stm.m.needs_rebaseline() is False

    def test_load_zef_baseline_missing_file_is_none(self, stm):
        assert stm.m.load_zef_baseline() is None

    def test_load_zef_baseline_corrupt_file_does_not_crash(self, stm):
        stm.m.ZEF_BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
        stm.m.ZEF_BASELINE_FILE.write_text("{ not json")
        assert stm.m.load_zef_baseline() is None
