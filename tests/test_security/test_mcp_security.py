"""Layer 9 — core/security/mcp_security.py."""

import sqlite3

import pytest

from core.security import mcp_security as ms
from core.security.mcp_security import MCPDecision, MCPServer, TrustLevel


@pytest.fixture
def mgr(tmp_path, monkeypatch):
    monkeypatch.setattr(ms, "MCP_SERVERS", {})
    monkeypatch.setattr(ms, "DB_PATH", tmp_path / "mcp.db")
    return ms.get_manager()


def test_unknown_server_denied(mgr):
    assert mgr.get_trust("nope") is TrustLevel.UNKNOWN
    assert mgr.evaluate("nope", "t")[0] is MCPDecision.DENY


@pytest.mark.parametrize("level,decision", [
    (TrustLevel.VERIFIED, MCPDecision.ALLOW),
    (TrustLevel.PROVISIONAL, MCPDecision.GO_GATE),
    (TrustLevel.QUARANTINED, MCPDecision.DENY),
])
def test_registry_levels(mgr, level, decision):
    ms.register_server(MCPServer(name="s", url="stdio:s", auth_method="stdio",
                                 trust_level=level))
    assert mgr.evaluate("s", "t")[0] is decision


def test_quarantine_overrides_registry_and_persists(mgr, tmp_path):
    ms.register_server(MCPServer(name="s", url="stdio:s", auth_method="stdio",
                                 trust_level=TrustLevel.VERIFIED))
    mgr.quarantine("s", "exfil seen")
    fresh = ms.MCPSecurityManager(db_path=tmp_path / "mcp.db")
    assert fresh.evaluate("s", "t")[0] is MCPDecision.DENY
    fresh.unquarantine("s", "patched")
    assert fresh.get_trust("s") is TrustLevel.PROVISIONAL
    fresh.verify("s", "reviewed")
    assert fresh.evaluate("s", "t")[0] is MCPDecision.ALLOW


def test_quarantine_hook(mgr, monkeypatch):
    seen = []
    monkeypatch.setattr(ms, "alert_hook", lambda e, s, d: seen.append((e, s, d["reason"])))
    mgr.quarantine("s", "why")
    assert seen == [("quarantine", "s", "why")]


def test_log_and_inventory(mgr):
    ms.register_server(MCPServer(name="s", url="stdio:s", auth_method="stdio",
                                 trust_level=TrustLevel.VERIFIED))
    mgr.quarantine("other", "bad")
    mgr.log_invocation("s", "t", "agent", MCPDecision.ALLOW, "verified")
    inv = mgr.get_inventory()
    assert inv["total_servers"] == 2
    assert inv["by_trust_level"]["verified"] == 1
    assert inv["by_trust_level"]["quarantined"] == 1


def test_db_error_fails_closed(mgr, monkeypatch):
    def broken(*_a, **_k):
        raise sqlite3.OperationalError("locked")
    monkeypatch.setattr(ms, "open_db", broken)
    with pytest.raises(sqlite3.OperationalError):
        mgr.evaluate("s", "t")
