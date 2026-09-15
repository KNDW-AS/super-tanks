"""
Council ↔ Layer 11/12 wiring tests.

Every voice gets a prompt stripped for its own trust tier, every call is
audited (metadata only), a sensitive question (``max_tier``) blocks lower-trust
voices unless GO-Gate approves, and a fallback voice is only used when the tier
gate allows it.
"""

from unittest.mock import patch

import pytest

from core.council import council as c
from core.security import provider_failover as pf
from core.security import provider_trust as pt


@pytest.fixture(autouse=True)
def _defaults():
    pt.load_provider_config("/nonexistent/providers.yaml")
    pf.load_failover_config("/nonexistent/providers.yaml")
    c._recent_audit.clear()
    c.set_audit_sink(None)
    yield
    pt.load_provider_config()
    pf.load_failover_config()
    c.set_audit_sink(None)


SECRET_Q = "password=hunter2 mail jane@example.com — what do you think?"


def _recorder(store: dict, name: str, reply: str = "ok"):
    def speak(prompt, system):
        store[name] = (prompt, system)
        return reply
    return speak


def test_each_voice_gets_prompt_stripped_for_its_own_tier():
    seen: dict = {}
    council = c.Council([
        c.Voice("Local", "ollama", _recorder(seen, "Local")),
        c.Voice("Claude", "anthropic", _recorder(seen, "Claude")),
        c.Voice("Gemini", "google", _recorder(seen, "Gemini")),
    ])
    verdict = council.ask(SECRET_Q, system_prompt="token: abc123")
    assert verdict.quorum == 3
    assert seen["Local"] == (SECRET_Q, "token: abc123")                     # tier 1: untouched
    assert "hunter2" not in seen["Claude"][0] and "jane@example.com" in seen["Claude"][0]  # tier 2
    assert "abc123" not in seen["Claude"][1]
    assert "jane@example.com" not in seen["Gemini"][0]                      # tier 3: PII gone
    assert {r.voice: r.tier for r in verdict.replies} == {"Local": 1, "Claude": 2, "Gemini": 3}


def test_every_call_is_audited_with_metadata_only():
    sink_rows = []
    c.set_audit_sink(sink_rows.append)
    council = c.Council([c.Voice("Claude", "anthropic", lambda p, s: "ok")], agent="test-agent")
    council.ask(SECRET_Q)
    assert len(sink_rows) == 1
    row = sink_rows[0]
    assert row["agent"] == "test-agent" and row["provider"] == "anthropic"
    assert row["tier"] == 2 and row["strip_level"] == "secrets"
    assert "hunter2" not in str(row) and "question" not in row
    assert c.recent_audit()[-1]["voice"] == "Claude"


def test_audit_sink_failure_does_not_block_the_call():
    def boom(_):
        raise RuntimeError("ledger down")
    c.set_audit_sink(boom)
    verdict = c.Council([c.Voice("Claude", "anthropic", lambda p, s: "ok")]).ask("q")
    assert verdict.quorum == 1


def test_max_tier_blocks_lower_trust_voice_without_approval():
    calls = []
    council = c.Council([
        c.Voice("Claude", "anthropic", lambda p, s: calls.append("claude") or "ok"),
        c.Voice("Deep", "deepseek", lambda p, s: calls.append("deepseek") or "ok"),
    ])
    with patch.object(pf, "_request_go_gate_approval", return_value=False) as gate:
        verdict = council.ask("sensitive", max_tier=pt.TIER_2_TRUSTED)
    gate.assert_called_once()
    assert calls == ["claude"]
    blocked = next(r for r in verdict.replies if r.voice == "Deep")
    assert blocked.error == "tier_blocked" and blocked.text == ""
    assert verdict.quorum == 1


def test_max_tier_allows_lower_trust_voice_after_approval():
    council = c.Council([c.Voice("Deep", "deepseek", lambda p, s: "ok")])
    with patch.object(pf, "_request_go_gate_approval", return_value=True):
        verdict = council.ask("sensitive", max_tier=pt.TIER_2_TRUSTED)
    assert verdict.quorum == 1


def test_fallback_to_higher_tier_is_automatic():
    def fail(p, s):
        raise RuntimeError("503")
    fb = c.Voice("Local", "ollama", lambda p, s: "local ok")
    council = c.Council([c.Voice("Gemini", "google", fail, fallback=fb)])
    with patch.object(pf, "_request_go_gate_approval") as gate:
        verdict = council.ask("q")
    gate.assert_not_called()
    assert verdict.quorum == 1 and verdict.replies[0].voice == "Local"


def test_fallback_to_lower_tier_is_gated_and_queued_when_denied():
    def fail(p, s):
        raise RuntimeError("503")
    fb = c.Voice("Deep", "deepseek", lambda p, s: "should not run")
    council = c.Council([c.Voice("Claude", "anthropic", fail, fallback=fb)])
    with patch.object(pf, "_request_go_gate_approval", return_value=False) as gate:
        verdict = council.ask("q")
    gate.assert_called_once()
    r = verdict.replies[0]
    assert r.error and "queued" in r.error and r.voice == "Claude"
    assert verdict.quorum == 0


def test_voice_without_fallback_reports_error():
    def fail(p, s):
        raise RuntimeError("boom")
    verdict = c.Council([c.Voice("Claude", "anthropic", fail)]).ask("q")
    assert verdict.replies[0].error == "boom"
