"""
Tests for core/security/threat_monitor.py.

Each pattern (P1..P5) is exercised in isolation with a stubbed audit
log + stubbed downstream subsystems (set_mode, trust_score,
soul_guard, threat_intel store).
"""

import sys
import types
from datetime import datetime, timedelta, timezone

import pytest


@pytest.fixture
def tm_env(monkeypatch, tmp_path):
    """Stub every module the threat monitor pulls in lazily."""
    # Fresh threat-intel DB so the monitor's _emit_threat doesn't write
    # to the real one.
    from core.security import threat_intel
    monkeypatch.setattr(threat_intel, "DB_PATH",
                        tmp_path / "threat_intel.db")
    monkeypatch.setattr(threat_intel, "_initialised", False)
    from core.security import agent_identity
    monkeypatch.setattr(agent_identity, "_KEY", b"test-tm-key")

    # Capture downstream subsystem calls.
    state = {
        "dispatch_rows": [],
        "memory_rows": [],
        "set_mode_calls": [],
        "trust_set_calls": [],
        "trust_authority_opens": 0,
        "current_mode": "autonomous",
        "safe_mode_entries": [],
        "dispatch_chain_tampered_id": None,
        "memory_chain_tampered_id": None,
    }

    # ── dispatch_audit ──
    fake_da = types.ModuleType("core.security.dispatch_audit")
    fake_da.get_dispatch_history = lambda limit=100: list(state["dispatch_rows"])
    fake_da.verify_dispatch_chain = lambda: state["dispatch_chain_tampered_id"]
    monkeypatch.setitem(sys.modules,
                        "core.security.dispatch_audit", fake_da)

    # ── memory audit ──
    fake_ma = types.ModuleType("core.memory.audit_log")
    fake_ma.get_recent_access = lambda limit=100: list(state["memory_rows"])
    fake_ma.verify_audit_chain = lambda: state["memory_chain_tampered_id"]
    monkeypatch.setitem(sys.modules, "core.memory.audit_log", fake_ma)

    # ── super_tanks_mode ──
    class FakeMode:
        LOCKDOWN = "lockdown"
        AUTONOMOUS = "autonomous"

    fake_stm = types.ModuleType("core.security.super_tanks_mode")
    fake_stm.TankMode = FakeMode
    fake_stm.get_mode = lambda: state["current_mode"]

    def _set_mode(new):
        state["set_mode_calls"].append(new)
        state["current_mode"] = new
    fake_stm.set_mode = _set_mode
    monkeypatch.setitem(sys.modules,
                        "core.security.super_tanks_mode", fake_stm)

    # ── trust_score ──
    fake_ts = types.ModuleType("core.security.trust_score")

    class _Authority:
        def __enter__(self):
            state["trust_authority_opens"] += 1
            return self

        def __exit__(self, *exc):
            return False
    fake_ts._TrustAuthority = _Authority
    fake_ts.get_score = lambda agent: {"score": 50.0, "level": "standard"}

    def _set_score(agent, score, reason=""):
        state["trust_set_calls"].append((agent, score, reason))
    fake_ts.set_score = _set_score
    monkeypatch.setitem(sys.modules, "core.security.trust_score", fake_ts)

    # ── soul_guard ──
    fake_sg = types.ModuleType("core.soul_guard")
    fake_sg.enter_safe_mode = lambda reason: state["safe_mode_entries"].append(reason)
    monkeypatch.setitem(sys.modules, "core.soul_guard", fake_sg)

    return state


def _now():
    return datetime(2026, 5, 14, 12, 0, 0, tzinfo=timezone.utc)


def _ts(offset_min: float) -> str:
    return (_now() + timedelta(minutes=offset_min)).isoformat()


# ── P1 identity_failure_burst ──────────────────────────────────────────────

class TestIdentityBurst:
    def test_below_threshold_no_finding(self, tm_env):
        tm_env["dispatch_rows"] = [
            {"timestamp": _ts(-1), "agent_id": "x", "verdict": "denied_identity"}
            for _ in range(5)  # < THRESH_IDENTITY (10)
        ]
        from core.security import threat_monitor
        r = threat_monitor.scan_once(now=_now())
        assert r.findings == []

    def test_above_threshold_emits_finding(self, tm_env):
        tm_env["dispatch_rows"] = [
            {"timestamp": _ts(-1), "agent_id": "attacker",
             "verdict": "denied_identity"} for _ in range(12)
        ]
        from core.security import threat_monitor
        r = threat_monitor.scan_once(now=_now())
        assert any("P1" in f and "attacker" in f for f in r.findings)

    def test_outside_window_excluded(self, tm_env):
        # All denials are 30 minutes old → outside the 5-min window.
        tm_env["dispatch_rows"] = [
            {"timestamp": _ts(-30), "agent_id": "attacker",
             "verdict": "denied_identity"} for _ in range(20)
        ]
        from core.security import threat_monitor
        r = threat_monitor.scan_once(now=_now())
        assert r.findings == []


# ── P2 tripwire_burst ──────────────────────────────────────────────────────

class TestTripwireBurst:
    def test_below_threshold_no_action(self, tm_env):
        tm_env["memory_rows"] = [
            {"timestamp": _ts(-1), "agent_id": "z",
             "operation": "tripwire_access"}
            for _ in range(2)  # < THRESH_TRIPWIRE (3)
        ]
        from core.security import threat_monitor
        threat_monitor.scan_once(now=_now())
        assert tm_env["set_mode_calls"] == []

    def test_above_threshold_flips_to_lockdown(self, tm_env):
        tm_env["memory_rows"] = [
            {"timestamp": _ts(-1), "agent_id": "zeph",
             "operation": "search_tripwire_hit"} for _ in range(4)
        ]
        from core.security import threat_monitor
        r = threat_monitor.scan_once(now=_now())
        assert any("P2" in f for f in r.findings)
        assert tm_env["set_mode_calls"] == ["lockdown"]
        assert any("LOCKDOWN" in a for a in r.actions_taken)

    def test_already_lockdown_no_double_flip(self, tm_env):
        tm_env["current_mode"] = "lockdown"
        tm_env["memory_rows"] = [
            {"timestamp": _ts(-1), "agent_id": "zeph",
             "operation": "search_tripwire_hit"} for _ in range(4)
        ]
        from core.security import threat_monitor
        threat_monitor.scan_once(now=_now())
        assert tm_env["set_mode_calls"] == []


# ── P3 zef_burst ───────────────────────────────────────────────────────────

class TestZefBurst:
    def test_above_threshold_drops_trust(self, tm_env):
        tm_env["dispatch_rows"] = [
            {"timestamp": _ts(-1), "agent_id": "aeris",
             "verdict": "allowed",
             "error": "Tool output contained likely prompt-injection content "
                      "and was redacted before reaching the agent."}
            for _ in range(6)
        ]
        from core.security import threat_monitor
        r = threat_monitor.scan_once(now=_now())
        assert any("P3" in f for f in r.findings)
        assert tm_env["trust_authority_opens"] >= 1
        assert len(tm_env["trust_set_calls"]) == 1
        agent, score, reason = tm_env["trust_set_calls"][0]
        assert agent == "aeris"
        assert score == 45.0  # 50 - 5

    def test_below_threshold_no_drop(self, tm_env):
        tm_env["dispatch_rows"] = [
            {"timestamp": _ts(-1), "agent_id": "aeris",
             "verdict": "allowed", "error": "indirect_injection"}
            for _ in range(3)
        ]
        from core.security import threat_monitor
        threat_monitor.scan_once(now=_now())
        assert tm_env["trust_set_calls"] == []


# ── P4 / P5 chain tampering ───────────────────────────────────────────────

class TestChainTamper:
    def test_dispatch_chain_break_enters_safe_mode(self, tm_env):
        tm_env["dispatch_chain_tampered_id"] = 42
        from core.security import threat_monitor
        r = threat_monitor.scan_once(now=_now())
        assert any("P4" in f and "42" in f for f in r.findings)
        assert any("dispatch_log" in s for s in tm_env["safe_mode_entries"])

    def test_memory_chain_break_enters_safe_mode(self, tm_env):
        tm_env["memory_chain_tampered_id"] = 7
        from core.security import threat_monitor
        r = threat_monitor.scan_once(now=_now())
        assert any("P5" in f and "7" in f for f in r.findings)
        assert any("memory_access_log" in s
                   for s in tm_env["safe_mode_entries"])

    def test_clean_chains_no_safe_mode(self, tm_env):
        from core.security import threat_monitor
        threat_monitor.scan_once(now=_now())
        assert tm_env["safe_mode_entries"] == []


# ── End-to-end: clean run produces empty report ───────────────────────────

def test_clean_state_produces_empty_report(tm_env):
    from core.security import threat_monitor
    r = threat_monitor.scan_once(now=_now())
    assert r.findings == []
    assert r.actions_taken == []
    assert r.errors == []
