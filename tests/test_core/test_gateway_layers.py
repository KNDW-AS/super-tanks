"""Gateway integration tests for layers 7-10.

Order under test: allowlist → allowed_agents (L10) → tool zone / GO-Gate
(L8) → MCP trust (L9) → circuit breaker (L7) → execute. Every layer's
state is isolated in tmp_path; nothing touches data/.
"""

import asyncio

import pytest

import core.ask_admin as ask_admin
from core import gateway
from core.diq.diq_tools import DIQTool, ToolResponse
from core.security import (
    agent_identity, circuit_breaker, mcp_security, tool_allowlists, tool_zones,
)
from core.security.mcp_security import MCPServer, TrustLevel
from core.security.tool_zones import Zone, ZoneAction


class _Tool(DIQTool):
    def __init__(self, name, agents=None, server=None, result="ok"):
        self._n, self._agents, self._server, self._result = name, agents, server, result
        self.calls = []

    def name(self):
        return self._n

    def description(self):
        return "fake"

    def parameters_schema(self):
        return {}

    def required_role(self):
        return "READ"

    def allowed_agents(self):
        return [] if self._agents is None else self._agents

    def mcp_server(self):
        return self._server

    async def _execute_impl(self, request):
        self.calls.append(request)
        return ToolResponse(success=True, result=self._result)


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    from core.security import dispatch_audit
    monkeypatch.setattr(agent_identity, "_KEY", b"test-key-for-layer-suite")
    monkeypatch.setattr(dispatch_audit, "DB_PATH", tmp_path / "dispatch.db")
    monkeypatch.setattr(dispatch_audit, "_initialised", False)
    monkeypatch.setattr(circuit_breaker, "DB_PATH", tmp_path / "cb.db")
    circuit_breaker.reset_breakers()
    monkeypatch.setattr(mcp_security, "DB_PATH", tmp_path / "mcp.db")
    monkeypatch.setattr(mcp_security, "MCP_SERVERS", {})
    store = ask_admin.ApprovalStore(db_path=str(tmp_path / "approvals.db"))
    monkeypatch.setattr(ask_admin, "_approval_store", store)
    monkeypatch.setattr(tool_zones, "TOOL_ZONES", {
        "read_tool": Zone.FILESYSTEM_RO,
        "write_tool": Zone.FILESYSTEM_RW,
        "denied_tool": Zone.EXEC,
    })
    monkeypatch.setattr(tool_zones, "ZONE_ACTIONS", {
        **tool_zones.ZONE_ACTIONS, Zone.EXEC: ZoneAction.DENY})
    monkeypatch.setattr(tool_allowlists, "is_tool_allowed", lambda a, t: True)
    tools = {}
    monkeypatch.setattr(gateway, "get_tool", tools.get)
    yield {"tools": tools, "store": store, "audit": dispatch_audit}
    circuit_breaker.reset_breakers()


def _call(tool_name, agent="aeris", params=None):
    return asyncio.run(gateway.dispatch_tool(
        tool_name, params or {}, agent, "READ",
        identity_token=agent_identity.issue_identity(agent)))


def _verdicts(audit, agent="aeris"):
    return [r["verdict"] for r in reversed(audit.get_dispatch_history(agent_id=agent))]


# ── Layer 10: allowed_agents ────────────────────────────────────────────────

class TestAllowedAgents:
    def test_empty_means_all(self, env):
        env["tools"]["read_tool"] = t = _Tool("read_tool")
        assert _call("read_tool").success is True
        assert len(t.calls) == 1

    def test_listed_agent_passes(self, env):
        env["tools"]["read_tool"] = _Tool("read_tool", agents=["aeris"])
        assert _call("read_tool").success is True

    def test_unlisted_agent_denied_and_short_circuits(self, env, monkeypatch):
        env["tools"]["read_tool"] = t = _Tool("read_tool", agents=["zeph"])
        later = []
        monkeypatch.setattr(gateway, "_check_tool_zone",
                            lambda *a: later.append(1))
        resp = _call("read_tool")
        assert resp.success is False and "not available" in resp.error
        assert t.calls == [] and later == []
        assert _verdicts(env["audit"]) == ["denied_agent"]

    @pytest.mark.parametrize("agent", ["system", "internal", "test"])
    def test_applies_to_reserved_agents(self, env, agent):
        env["tools"]["read_tool"] = _Tool("read_tool", agents=["zeph"])
        assert _call("read_tool", agent=agent).success is False
        assert _verdicts(env["audit"], agent) == ["denied_agent"]

    def test_malformed_return_fails_closed(self, env):
        env["tools"]["read_tool"] = t = _Tool("read_tool", agents="aeris")
        resp = _call("read_tool")
        assert resp.success is False and t.calls == []
        assert _verdicts(env["audit"]) == ["denied_subsystem"]


# ── Layer 8: zones + GO-Gate ────────────────────────────────────────────────

class TestZones:
    def test_deny_zone(self, env):
        env["tools"]["denied_tool"] = t = _Tool("denied_tool")
        resp = _call("denied_tool")
        assert resp.success is False and t.calls == []
        assert _verdicts(env["audit"]) == ["denied_zone"]

    def test_gated_zone_pauses_with_request_id(self, env):
        env["tools"]["write_tool"] = t = _Tool("write_tool")
        resp = _call("write_tool", params={"path": "x"})
        assert resp.success is False and t.calls == []
        req_id = resp.metadata["approval_request_id"]
        assert env["store"].get_request(req_id).tool_name == "write_tool"
        assert _verdicts(env["audit"]) == ["pending_approval"]
        # Retrying before a decision reuses the same request.
        assert _call("write_tool", params={"path": "x"}).metadata[
            "approval_request_id"] == req_id

    def test_approved_call_executes(self, env):
        env["tools"]["write_tool"] = t = _Tool("write_tool")
        req_id = _call("write_tool", params={"p": 1}).metadata["approval_request_id"]
        assert env["store"].approve_request(req_id, admin_id="human")
        resp = _call("write_tool", params={"p": 1})
        assert resp.success is True and len(t.calls) == 1
        assert _verdicts(env["audit"]) == ["pending_approval", "allowed"]

    def test_approval_is_bound_to_args(self, env):
        env["tools"]["write_tool"] = t = _Tool("write_tool")
        req_id = _call("write_tool", params={"p": 1}).metadata["approval_request_id"]
        env["store"].approve_request(req_id, admin_id="human")
        resp = _call("write_tool", params={"p": 2})
        assert resp.success is False and t.calls == []

    def test_denied_call_stays_denied(self, env):
        env["tools"]["write_tool"] = t = _Tool("write_tool")
        req_id = _call("write_tool").metadata["approval_request_id"]
        assert env["store"].deny_request(req_id, admin_id="human")
        resp = _call("write_tool")
        assert resp.success is False and t.calls == []
        assert resp.metadata["approval_request_id"] == req_id
        assert _verdicts(env["audit"]) == ["pending_approval", "denied_zone"]

    def test_timeout_never_executes(self, env, monkeypatch):
        env["tools"]["write_tool"] = t = _Tool("write_tool")
        monkeypatch.setattr(ask_admin, "DEFAULT_APPROVAL_TTL_SECONDS", 0)
        monkeypatch.setattr(ask_admin.gate_tool_call, "__defaults__", (0,))
        req_id = _call("write_tool").metadata["approval_request_id"]
        # Approving after expiry fails; the call is still not executed
        # and a retry opens a fresh request.
        assert env["store"].approve_request(req_id, admin_id="human") is False
        resp = _call("write_tool")
        assert resp.success is False and t.calls == []
        assert resp.metadata["approval_request_id"] != req_id

    def test_unknown_tool_is_gated(self, env):
        env["tools"]["brand_new"] = t = _Tool("brand_new")
        resp = _call("brand_new")
        assert resp.success is False and t.calls == []
        assert _verdicts(env["audit"]) == ["pending_approval"]

    def test_store_unavailable_fails_closed(self, env, monkeypatch):
        env["tools"]["write_tool"] = t = _Tool("write_tool")
        monkeypatch.setattr(env["store"], "create_request", lambda **k: None)
        resp = _call("write_tool")
        assert resp.success is False and t.calls == []
        assert _verdicts(env["audit"]) == ["denied_subsystem"]

    def test_zone_exception_fails_closed(self, env, monkeypatch):
        env["tools"]["read_tool"] = t = _Tool("read_tool")

        def boom(_name):
            raise RuntimeError("zone map corrupt")
        monkeypatch.setattr(tool_zones, "zone_action", boom)
        resp = _call("read_tool")
        assert resp.success is False and t.calls == []
        assert "tool_zone unavailable" in resp.error
        assert _verdicts(env["audit"]) == ["denied_subsystem"]


# ── Layer 9: MCP trust ──────────────────────────────────────────────────────

def _server(level):
    mcp_security.register_server(MCPServer(
        name="srv", url="stdio:srv", auth_method="stdio", trust_level=level))


class TestMCP:
    def test_non_mcp_tool_skips_manager(self, env, monkeypatch):
        env["tools"]["read_tool"] = _Tool("read_tool")
        monkeypatch.setattr(mcp_security, "get_manager",
                            lambda: pytest.fail("manager consulted"))
        assert _call("read_tool").success is True

    def test_verified_server_allowed(self, env):
        _server(TrustLevel.VERIFIED)
        env["tools"]["read_tool"] = t = _Tool("read_tool", server="srv")
        assert _call("read_tool").success is True and len(t.calls) == 1

    def test_quarantined_server_denied(self, env):
        _server(TrustLevel.VERIFIED)
        mcp_security.get_manager().quarantine("srv", "suspicious")
        env["tools"]["read_tool"] = t = _Tool("read_tool", server="srv")
        resp = _call("read_tool")
        assert resp.success is False and "quarantined" in resp.error
        assert t.calls == []
        assert _verdicts(env["audit"]) == ["denied_mcp"]

    def test_unknown_server_denied(self, env):
        env["tools"]["read_tool"] = t = _Tool("read_tool", server="ghost")
        assert _call("read_tool").success is False and t.calls == []
        assert _verdicts(env["audit"]) == ["denied_mcp"]

    def test_provisional_server_goes_through_go_gate(self, env):
        _server(TrustLevel.PROVISIONAL)
        env["tools"]["read_tool"] = t = _Tool("read_tool", server="srv")
        req_id = _call("read_tool").metadata["approval_request_id"]
        env["store"].approve_request(req_id, admin_id="human")
        assert _call("read_tool").success is True and len(t.calls) == 1

    def test_provisional_denied_by_human(self, env):
        _server(TrustLevel.PROVISIONAL)
        env["tools"]["read_tool"] = t = _Tool("read_tool", server="srv")
        req_id = _call("read_tool").metadata["approval_request_id"]
        env["store"].deny_request(req_id, admin_id="human")
        assert _call("read_tool").success is False and t.calls == []
        assert _verdicts(env["audit"])[-1] == "denied_mcp"

    def test_mcp_db_error_fails_closed(self, env, monkeypatch):
        _server(TrustLevel.VERIFIED)
        env["tools"]["read_tool"] = t = _Tool("read_tool", server="srv")

        def boom(*_a, **_k):
            raise RuntimeError("db gone")
        monkeypatch.setattr(mcp_security, "open_db", boom)
        assert _call("read_tool").success is False and t.calls == []
        assert _verdicts(env["audit"]) == ["denied_subsystem"]


# ── Layer 7: circuit breaker ────────────────────────────────────────────────

class TestCircuitBreaker:
    def test_trips_then_resets(self, env, monkeypatch):
        monkeypatch.setattr(circuit_breaker.CircuitBreaker, "DEFAULT_MAX_ACTIONS", 2)
        circuit_breaker.reset_breakers()
        env["tools"]["read_tool"] = t = _Tool("read_tool")
        assert _call("read_tool").success is True
        assert _call("read_tool").success is True
        resp = _call("read_tool")
        assert resp.success is False and len(t.calls) == 2
        assert resp.metadata["locked_until"]
        assert _verdicts(env["audit"])[-1] == "denied_circuit_breaker"
        # Other agents are unaffected.
        assert _call("read_tool", agent="zeph").success is True
        circuit_breaker.get_breaker("aeris").reset("test")
        assert _call("read_tool").success is True

    def test_applies_to_test_agent(self, env, monkeypatch):
        monkeypatch.setattr(circuit_breaker.CircuitBreaker, "DEFAULT_MAX_ACTIONS", 1)
        circuit_breaker.reset_breakers()
        env["tools"]["read_tool"] = _Tool("read_tool")
        assert _call("read_tool", agent="test").success is True
        assert _call("read_tool", agent="test").success is False

    def test_pending_calls_do_not_consume_budget(self, env, monkeypatch):
        monkeypatch.setattr(circuit_breaker.CircuitBreaker, "DEFAULT_MAX_ACTIONS", 1)
        circuit_breaker.reset_breakers()
        env["tools"]["write_tool"] = _Tool("write_tool")
        env["tools"]["read_tool"] = _Tool("read_tool")
        for _ in range(3):
            _call("write_tool")
        assert _call("read_tool").success is True

    def test_breaker_db_error_fails_closed(self, env, monkeypatch):
        env["tools"]["read_tool"] = t = _Tool("read_tool")

        def boom(*_a, **_k):
            raise RuntimeError("db gone")
        monkeypatch.setattr(circuit_breaker, "open_db", boom)
        circuit_breaker.reset_breakers()
        assert _call("read_tool").success is False and t.calls == []
        assert _verdicts(env["audit"]) == ["denied_subsystem"]


# ── Ordering, immutability, output scan ─────────────────────────────────────

class TestPipeline:
    def test_order(self, env, monkeypatch):
        env["tools"]["read_tool"] = _Tool("read_tool")
        seen = []
        for name in ("_check_allowed_agents", "_check_tool_zone",
                     "_check_mcp_trust", "_check_circuit_breaker"):
            monkeypatch.setattr(gateway, name,
                                (lambda n: lambda *a: seen.append(n))(name))
        assert _call("read_tool").success is True
        assert seen == ["_check_allowed_agents", "_check_tool_zone",
                        "_check_mcp_trust", "_check_circuit_breaker"]

    def test_allowlist_denial_runs_before_new_layers(self, env, monkeypatch):
        env["tools"]["read_tool"] = _Tool("read_tool", agents=["zeph"])
        monkeypatch.setattr(tool_allowlists, "is_tool_allowed", lambda a, t: False)
        _call("read_tool")
        assert _verdicts(env["audit"]) == ["denied_allowlist"]

    def test_request_reaches_tool_unchanged(self, env):
        env["tools"]["read_tool"] = t = _Tool("read_tool")
        params = {"q": "x", "n": [1, 2]}
        _call("read_tool", params=params)
        req = t.calls[0]
        assert req.parameters == {"q": "x", "n": [1, 2]}
        assert req.agent_id == "aeris" and req.tool_name == "read_tool"

    def test_output_scan_failure_withholds_output(self, env, monkeypatch):
        import core.security.zef_injection_filter as zef
        env["tools"]["read_tool"] = _Tool("read_tool", result="perfectly normal text")

        def boom(*_a, **_k):
            raise RuntimeError("filter broken")
        monkeypatch.setattr(zef, "scan_message", boom)
        resp = _call("read_tool")
        assert resp.success is False and resp.result is None
        assert resp.metadata["output_scan_failed"] is True
