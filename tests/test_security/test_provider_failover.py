"""
Tests for core/security/provider_failover.py (Layer 12 — Provider Failover GO-Gate).

Covers: same/upgrade auto-approval, downgrade → GO-Gate, denial/timeout → queued,
approval via the shared ApprovalStore (approved / denied / expired / timeout /
store unavailable — all fail-closed), fallback chains and config loading.
"""

import textwrap
from unittest.mock import MagicMock, patch

import pytest

from core.security import provider_failover as pf
from core.security import provider_trust as pt


@pytest.fixture(autouse=True)
def _defaults():
    pt.load_provider_config("/nonexistent/providers.yaml")
    pf.load_failover_config("/nonexistent/providers.yaml")
    yield
    pt.load_provider_config()
    pf.load_failover_config()


# ── decisions ───────────────────────────────────────────────────────────────

def test_same_tier_auto_approved():
    with patch.object(pf, "_request_go_gate_approval") as gate:
        r = pf.check_failover("aeris", "anthropic", "openai")
    assert r.approved and r.provider == "openai" and not r.queued
    gate.assert_not_called()


def test_upgrade_auto_approved():
    with patch.object(pf, "_request_go_gate_approval") as gate:
        assert pf.check_failover("aeris", "google", "ollama").approved
    gate.assert_not_called()


def test_downgrade_denied_is_queued():
    with patch.object(pf, "_request_go_gate_approval", return_value=False) as gate:
        r = pf.check_failover("aeris", "anthropic", "openrouter")
    gate.assert_called_once()
    assert not r.approved and r.queued and r.provider is None


def test_downgrade_approved():
    with patch.object(pf, "_request_go_gate_approval", return_value=True):
        r = pf.check_failover("zeph", "anthropic", "google")
    assert r.approved and r.provider == "google"


def test_request_tier_approval_only_gates_lower_tiers():
    with patch.object(pf, "_request_go_gate_approval", return_value=False) as gate:
        assert pf.request_tier_approval("council", "anthropic", pt.TIER_2_TRUSTED) is True
        gate.assert_not_called()
        assert pf.request_tier_approval("council", "deepseek", pt.TIER_2_TRUSTED) is False
        gate.assert_called_once()


# ── chains ──────────────────────────────────────────────────────────────────

def test_no_chain_means_queued():
    r = pf.on_provider_error("aeris", "anthropic", "rate limit")
    assert not r.approved and r.queued


def test_chain_walks_and_gates(tmp_path):
    cfg = tmp_path / "providers.yaml"
    cfg.write_text(textwrap.dedent("""
        fallback_chains:
          default: ["anthropic", "google", "ollama"]
        downgrade_approval_timeout_s: 7
    """), encoding="utf-8")
    pf.load_failover_config(str(cfg))
    assert pf.get_approval_timeout_s() == 7
    assert pf.get_fallback_chain("anybody") == ["anthropic", "google", "ollama"]
    with patch.object(pf, "_request_go_gate_approval", return_value=False):
        r = pf.on_provider_error("aeris", "anthropic", "down")
    # anthropic(2) → google(3) is a downgrade and was denied; ollama(1) is an upgrade → allowed
    assert r.approved and r.provider == "ollama"


# ── GO-Gate via ApprovalStore ───────────────────────────────────────────────

def _store(final):
    from core.ask_admin import ApprovalStatus
    store = MagicMock()
    store.find_pending_duplicate.return_value = None
    req = MagicMock(); req.request_id = "req-1"
    store.create_request.return_value = req
    cur = MagicMock(); cur.status = getattr(ApprovalStatus, final)
    store.get_request.return_value = cur
    return store


def test_go_gate_approved():
    with patch("core.ask_admin.get_approval_store", return_value=_store("APPROVED")):
        assert pf._request_go_gate_approval("aeris", "why", {"a": 1}, timeout_s=5, sleep=lambda s: None) is True


@pytest.mark.parametrize("final", ["DENIED", "EXPIRED"])
def test_go_gate_denied_or_expired_is_fail_closed(final):
    with patch("core.ask_admin.get_approval_store", return_value=_store(final)):
        assert pf._request_go_gate_approval("aeris", "why", {"a": 1}, timeout_s=5, sleep=lambda s: None) is False


def test_go_gate_timeout_is_fail_closed():
    with patch("core.ask_admin.get_approval_store", return_value=_store("PENDING")):
        assert pf._request_go_gate_approval("aeris", "why", {"a": 1}, timeout_s=0, sleep=lambda s: None) is False


def test_go_gate_reuses_pending_duplicate():
    store = _store("APPROVED")
    pending = MagicMock(); pending.request_id = "dup-9"
    store.find_pending_duplicate.return_value = pending
    with patch("core.ask_admin.get_approval_store", return_value=store):
        assert pf._request_go_gate_approval("aeris", "why", {"a": 1}, timeout_s=5, sleep=lambda s: None) is True
    store.create_request.assert_not_called()


def test_go_gate_store_error_is_fail_closed():
    with patch("core.ask_admin.get_approval_store", side_effect=RuntimeError("no db")):
        assert pf._request_go_gate_approval("aeris", "why", {"a": 1}, timeout_s=1, sleep=lambda s: None) is False


def test_go_gate_request_carries_tool_name_and_args():
    store = _store("APPROVED")
    with patch("core.ask_admin.get_approval_store", return_value=store):
        pf._request_go_gate_approval("zeph", "why", {"from": "anthropic", "to": "deepseek"}, timeout_s=5, sleep=lambda s: None)
    kw = store.create_request.call_args.kwargs
    assert kw["tool_name"] == pf.TOOL_NAME == "provider_downgrade"
    assert kw["user_id"] == "zeph" and kw["args"]["to"] == "deepseek"
