"""
Tests for core/memory/access_control.py.

Covers the path-prefix RBAC classifier, the mode-aware access decision,
and the tripwire alarm pipeline (forced lockdown + Telegram + audit log
+ trust-score event). All collaborators imported lazily inside the
module (super_tanks_mode, trust_score, audit_log, requests) are
replaced with controllable fakes via sys.modules so the tests run
hermetically.
"""

import sys
import types

import pytest


# ── Fake collaborators ─────────────────────────────────────────────────────

class _FakeModeEnum:
    class _Member:
        def __init__(self, value):
            self.value = value

        def __repr__(self):
            return f"FakeMode.{self.value.upper()}"

    LOCKDOWN = _Member("lockdown")
    AUTONOMOUS = _Member("autonomous")


@pytest.fixture
def env(monkeypatch):
    """Replace inline-imported collaborators with capturing fakes.

    Returns a (access_control, calls, state) triple where:
      * access_control is the module under test
      * calls is a dict of side-effect captures
      * state["mode"] holds the current fake mode for get_mode()
    """
    calls = {
        "set_mode": [],
        "trust_events": [],
        "audit": [],
        "telegram_posts": [],
    }
    state = {"mode": _FakeModeEnum.AUTONOMOUS}

    # ── Fake super_tanks_mode ──
    fake_stm = types.ModuleType("core.security.super_tanks_mode")
    fake_stm.TankMode = _FakeModeEnum
    fake_stm.get_mode = lambda: state["mode"]

    def _set_mode(m):
        calls["set_mode"].append(m)
        state["mode"] = m

    fake_stm.set_mode = _set_mode
    monkeypatch.setitem(sys.modules, "core.security.super_tanks_mode", fake_stm)

    # ── Fake trust_score.record_event ──
    fake_ts = types.ModuleType("core.security.trust_score")
    fake_ts.record_event = lambda agent, event, details="": (
        calls["trust_events"].append((agent, event, details))
    )
    monkeypatch.setitem(sys.modules, "core.security.trust_score", fake_ts)

    # ── Fake audit_log.log_access ──
    fake_audit = types.ModuleType("core.memory.audit_log")
    fake_audit.log_access = lambda **kw: calls["audit"].append(kw)
    monkeypatch.setitem(sys.modules, "core.memory.audit_log", fake_audit)

    # ── Fake requests.post ──
    fake_requests = types.ModuleType("requests")
    fake_requests.post = lambda *a, **kw: calls["telegram_posts"].append((a, kw))
    monkeypatch.setitem(sys.modules, "requests", fake_requests)

    # Telegram env vars set by default; individual tests override.
    monkeypatch.setenv("AERIS_GOGATE_TELEGRAM_TOKEN", "fake-token")
    monkeypatch.setenv("AERIS_ADMIN_CHAT_ID", "42")

    from core.memory import access_control
    return access_control, calls, state


# ── Path classification ────────────────────────────────────────────────────

class TestGetPathClassification:
    @pytest.mark.parametrize("path,expected", [
        # Tripwires
        ("/system/passwords_backup", "tripwire"),
        ("/system/admin_keys", "tripwire"),
        ("/system/ssh_private_key", "tripwire"),
        ("/family/finance/bank_login", "tripwire"),
        ("/william/secrets", "tripwire"),
        # Agent-private
        ("/aeris/learned", "agent_private:aeris"),
        ("/aeris/personality", "agent_private:aeris"),
        ("/zeph/learned", "agent_private:zeph"),
        ("/zeph/security_log", "agent_private:zeph"),
        ("/zeph/successful_patterns", "agent_private:zeph"),
        # Sensitive
        ("/family/finance", "sensitive"),
        ("/family/health", "sensitive"),
        ("/system/config", "sensitive"),
        ("/william/work", "sensitive"),
        # Public
        ("/family/preferences", "public"),
        ("/family/routines", "public"),
        ("/system/home_assistant", "public"),
        ("/system/logs", "public"),
        ("/william/interests", "public"),
    ])
    def test_exact_prefix_classification(self, env, path, expected):
        ac, _, _ = env
        assert ac.get_path_classification(path) == expected

    def test_unknown_path_returns_unknown(self, env):
        ac, _, _ = env
        assert ac.get_path_classification("/random/path") == "unknown"
        assert ac.get_path_classification("/totally/made/up") == "unknown"

    def test_subpath_inherits_classification(self, env):
        ac, _, _ = env
        assert ac.get_path_classification("/family/finance/credit_cards") == "sensitive"
        assert ac.get_path_classification("/family/health/medications") == "sensitive"
        assert ac.get_path_classification("/aeris/learned/topic_x") == "agent_private:aeris"
        assert ac.get_path_classification("/family/preferences/dinner") == "public"

    def test_most_specific_prefix_wins(self, env):
        ac, _, _ = env
        # /family/finance is sensitive, but /family/finance/bank_login is
        # a tripwire — the longer prefix must win.
        assert ac.get_path_classification("/family/finance/bank_login") == "tripwire"
        # And subpaths of the tripwire stay tripwire.
        assert ac.get_path_classification("/family/finance/bank_login/foo") == "tripwire"

    def test_path_normalization(self, env):
        ac, _, _ = env
        # Leading/trailing slashes and missing leading slash all normalise.
        assert ac.get_path_classification("family/finance") == "sensitive"
        assert ac.get_path_classification("/family/finance/") == "sensitive"
        assert ac.get_path_classification("family/finance/") == "sensitive"

    def test_prefix_match_without_path_boundary_overclassifies(self, env):
        # FINDING: classification uses raw startswith with no trailing
        # separator check, so "/family/finance_other" is classified as
        # sensitive even though it's a semantically distinct path. This
        # is fail-closed (over-restrictive, never under-restrictive), so
        # it's safe in this direction. Documented so the next refactor
        # is intentional about it.
        ac, _, _ = env
        assert ac.get_path_classification("/family/finance_other") == "sensitive"


# ── is_path_accessible — public paths ──────────────────────────────────────

class TestIsPathAccessiblePublic:
    @pytest.mark.parametrize("mode", ["lockdown", "autonomous"])
    def test_public_always_allowed(self, env, mode):
        ac, _, _ = env
        assert ac.is_path_accessible("/family/preferences", "aeris", mode=mode) is True
        assert ac.is_path_accessible("/system/logs", "zeph", mode=mode) is True


# ── is_path_accessible — agent-private paths ───────────────────────────────

class TestIsPathAccessibleAgentPrivate:
    def test_owner_allowed(self, env):
        ac, _, _ = env
        assert ac.is_path_accessible("/aeris/learned", "aeris", mode="autonomous") is True
        assert ac.is_path_accessible("/zeph/learned", "zeph", mode="autonomous") is True

    def test_non_owner_denied(self, env):
        ac, _, _ = env
        assert ac.is_path_accessible("/aeris/learned", "zeph", mode="autonomous") is False
        assert ac.is_path_accessible("/zeph/learned", "aeris", mode="autonomous") is False

    def test_unrelated_agent_denied(self, env):
        ac, _, _ = env
        assert ac.is_path_accessible("/aeris/learned", "intruder", mode="autonomous") is False

    def test_owner_allowed_in_either_mode(self, env):
        ac, _, _ = env
        assert ac.is_path_accessible("/aeris/learned", "aeris", mode="lockdown") is True
        assert ac.is_path_accessible("/aeris/learned", "aeris", mode="autonomous") is True


# ── is_path_accessible — sensitive paths ───────────────────────────────────

class TestIsPathAccessibleSensitive:
    def test_blocked_in_autonomous_mode(self, env):
        ac, _, _ = env
        assert ac.is_path_accessible("/family/finance", "aeris", mode="autonomous") is False
        assert ac.is_path_accessible("/family/health", "zeph", mode="autonomous") is False

    def test_allowed_in_lockdown_mode(self, env):
        ac, _, _ = env
        assert ac.is_path_accessible("/family/finance", "aeris", mode="lockdown") is True
        assert ac.is_path_accessible("/system/config", "zeph", mode="lockdown") is True

    def test_mode_case_insensitive(self, env):
        ac, _, _ = env
        assert ac.is_path_accessible("/family/finance", "aeris", mode="LOCKDOWN") is True
        assert ac.is_path_accessible("/family/finance", "aeris", mode="Lockdown") is True


# ── is_path_accessible — tripwire paths ────────────────────────────────────

class TestIsPathAccessibleTripwire:
    def test_always_blocked(self, env):
        ac, _, _ = env
        for mode in ("lockdown", "autonomous"):
            assert ac.is_path_accessible("/william/secrets", "aeris", mode=mode) is False
            assert ac.is_path_accessible("/system/admin_keys", "aeris", mode=mode) is False

    def test_owner_of_subtree_still_blocked(self, env):
        ac, _, _ = env
        # Even if a tripwire happens to sit under an agent's "own" tree,
        # access is blocked. (None of the current tripwires do, but the
        # contract should be agent-agnostic.)
        assert ac.is_path_accessible("/family/finance/bank_login", "aeris",
                                     mode="lockdown") is False

    def test_triggers_alarm_and_trust_event(self, env):
        ac, calls, state = env
        state["mode"] = _FakeModeEnum.AUTONOMOUS
        ac.is_path_accessible("/william/secrets", "aeris", mode="autonomous")
        # Forced into lockdown
        assert state["mode"] is _FakeModeEnum.LOCKDOWN
        assert calls["set_mode"] == [_FakeModeEnum.LOCKDOWN]
        # Trust event recorded
        assert len(calls["trust_events"]) == 1
        agent, event, details = calls["trust_events"][0]
        assert agent == "aeris"
        assert event == "tripwire_access"
        assert "/william/secrets" in details
        # Audit log entry written
        assert len(calls["audit"]) == 1
        assert calls["audit"][0]["operation"] == "TRIPWIRE_ACCESS"
        assert calls["audit"][0]["agent_id"] == "aeris"
        # Telegram alert sent
        assert len(calls["telegram_posts"]) == 1

    def test_already_locked_does_not_set_mode_again(self, env):
        ac, calls, state = env
        state["mode"] = _FakeModeEnum.LOCKDOWN
        ac.is_path_accessible("/william/secrets", "aeris", mode="lockdown")
        # Audit + trust + telegram still fire, but set_mode is skipped.
        assert calls["set_mode"] == []
        assert len(calls["audit"]) == 1
        assert len(calls["trust_events"]) == 1


# ── is_path_accessible — unknown classifications ───────────────────────────

class TestIsPathAccessibleUnknown:
    def test_unknown_path_denied(self, env):
        ac, _, _ = env
        assert ac.is_path_accessible("/random/path", "aeris", mode="lockdown") is False
        assert ac.is_path_accessible("/random/path", "aeris", mode="autonomous") is False


# ── Mode auto-detection ────────────────────────────────────────────────────

class TestModeAutoDetection:
    def test_mode_read_from_super_tanks_when_unset(self, env):
        ac, _, state = env
        state["mode"] = _FakeModeEnum.LOCKDOWN
        # mode=None → falls back to get_mode() → LOCKDOWN → sensitive allowed
        assert ac.is_path_accessible("/family/finance", "aeris", mode=None) is True

    def test_mode_detection_failure_denies_sensitive(self, monkeypatch):
        # When super_tanks_mode is unavailable we don't know if a human
        # is supervising. The fallback must deny sensitive access, not
        # grant it. (Old behaviour: fallback was "lockdown", which
        # _allows_ sensitive — a fail-OPEN gap dressed up as fail-closed.)
        broken = types.ModuleType("core.security.super_tanks_mode")

        def _boom():
            raise RuntimeError("subsystem offline")

        broken.get_mode = _boom
        monkeypatch.setitem(sys.modules, "core.security.super_tanks_mode", broken)

        for mod_name in ("core.security.trust_score", "core.memory.audit_log"):
            stub = types.ModuleType(mod_name)
            if mod_name.endswith("trust_score"):
                stub.record_event = lambda *a, **kw: None
            else:
                stub.log_access = lambda **kw: None
            monkeypatch.setitem(sys.modules, mod_name, stub)
        monkeypatch.setitem(sys.modules, "requests",
                            types.SimpleNamespace(post=lambda *a, **kw: None))

        from core.memory import access_control
        assert access_control.is_path_accessible(
            "/family/finance", "aeris", mode=None) is False


# ── trigger_tripwire_alarm directly ────────────────────────────────────────

class TestTriggerTripwireAlarm:
    def test_sends_telegram_when_token_present(self, env):
        ac, calls, _ = env
        ac.trigger_tripwire_alarm("/william/secrets", "aeris")
        assert len(calls["telegram_posts"]) == 1
        args, kwargs = calls["telegram_posts"][0]
        assert "sendMessage" in args[0]
        assert kwargs["json"]["chat_id"] == 42
        text = kwargs["json"]["text"]
        assert "TRIPWIRE" in text
        assert "/william/secrets" in text
        assert "aeris" in text

    def test_skips_telegram_when_token_missing(self, env, monkeypatch):
        ac, calls, _ = env
        monkeypatch.delenv("AERIS_GOGATE_TELEGRAM_TOKEN", raising=False)
        ac.trigger_tripwire_alarm("/william/secrets", "aeris")
        assert calls["telegram_posts"] == []
        # But audit and set_mode still happen.
        assert len(calls["audit"]) == 1
        assert calls["set_mode"] == [_FakeModeEnum.LOCKDOWN]

    def test_writes_audit_entry(self, env):
        ac, calls, _ = env
        ac.trigger_tripwire_alarm("/system/admin_keys", "zeph")
        assert len(calls["audit"]) == 1
        entry = calls["audit"][0]
        assert entry["operation"] == "TRIPWIRE_ACCESS"
        assert entry["agent_id"] == "zeph"
        assert entry["path"] == "/system/admin_keys"
        assert entry["accessible"] is False

    def test_never_raises_when_all_subsystems_fail(self, monkeypatch):
        # Every collaborator throws — function must still return cleanly.
        for mod_name, attr, value in [
            ("core.security.super_tanks_mode", "get_mode",
             lambda: (_ for _ in ()).throw(RuntimeError("mode down"))),
            ("core.security.super_tanks_mode", "set_mode",
             lambda m: (_ for _ in ()).throw(RuntimeError("mode down"))),
            ("core.memory.audit_log", "log_access",
             lambda **kw: (_ for _ in ()).throw(RuntimeError("audit down"))),
        ]:
            stub = sys.modules.get(mod_name) or types.ModuleType(mod_name)
            setattr(stub, attr, value)
            monkeypatch.setitem(sys.modules, mod_name, stub)

        # Make TankMode accessible on the broken super_tanks_mode stub.
        stm = sys.modules["core.security.super_tanks_mode"]
        stm.TankMode = _FakeModeEnum

        # requests.post raises
        def _boom(*a, **kw):
            raise RuntimeError("network down")
        monkeypatch.setitem(sys.modules, "requests",
                            types.SimpleNamespace(post=_boom))
        monkeypatch.setenv("AERIS_GOGATE_TELEGRAM_TOKEN", "fake")

        from core.memory import access_control
        # Must not raise.
        access_control.trigger_tripwire_alarm("/william/secrets", "aeris")
