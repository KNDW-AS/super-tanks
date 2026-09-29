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
        # Budget 2: a write (weight 1.5) passes the pre-check, pauses in
        # GO-Gate and records nothing, so two reads still fit afterwards.
        monkeypatch.setattr(circuit_breaker.CircuitBreaker, "DEFAULT_MAX_ACTIONS", 2)
        circuit_breaker.reset_breakers()
        env["tools"]["write_tool"] = _Tool("write_tool")
        env["tools"]["read_tool"] = _Tool("read_tool")
        for i in range(3):
            assert _call("write_tool", params={"i": i}).metadata["approval_request_id"]
        assert _call("read_tool").success is True
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
        order = ["_check_allowed_agents", "_precheck_circuit_breaker",
                 "_check_tool_zone", "_check_mcp_trust", "_record_circuit_breaker"]
        for name in order:
            monkeypatch.setattr(gateway, name,
                                (lambda n: lambda *a: seen.append(n))(name))
        assert _call("read_tool").success is True
        assert seen == order

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


# ── Review fixes: exceptions audited, breaker before GO-Gate, weights ───────

class _Raising(_Tool):
    def __init__(self, name, where):
        super().__init__(name)
        self._where = where

    def validate_access(self, request):
        if self._where == "role":
            raise RuntimeError("role boom")
        return super().validate_access(request)

    async def _execute_impl(self, request):
        if self._where == "execute":
            raise RuntimeError("exec boom")
        if self._where == "bad_return":
            return "not a ToolResponse"
        return await super()._execute_impl(request)


class TestExceptionsAreAudited:
    def test_execute_raises(self, env):
        env["tools"]["read_tool"] = _Raising("read_tool", "execute")
        resp = _call("read_tool")
        assert resp.success is False and "exec boom" in resp.error
        assert _verdicts(env["audit"]) == ["tool_error"]

    def test_execute_returns_wrong_type(self, env):
        env["tools"]["read_tool"] = _Raising("read_tool", "bad_return")
        resp = _call("read_tool")
        assert resp.success is False
        assert _verdicts(env["audit"]) == ["tool_error"]

    def test_validate_access_raises(self, env):
        env["tools"]["read_tool"] = t = _Raising("read_tool", "role")
        resp = _call("read_tool")
        assert resp.success is False and t.calls == []
        assert "Role check unavailable" in resp.error
        assert _verdicts(env["audit"]) == ["denied_subsystem"]

    def test_scan_returns_garbage(self, env, monkeypatch):
        import core.security.zef_injection_filter as zef
        env["tools"]["read_tool"] = _Tool("read_tool", result="perfectly normal text")
        monkeypatch.setattr(zef, "scan_message", lambda *a, **k: None)
        resp = _call("read_tool")
        assert resp.success is False and resp.metadata["output_scan_failed"] is True
        assert _verdicts(env["audit"]) == ["allowed"]

    def test_scan_returns_unknown_verdict(self, env, monkeypatch):
        import types
        import core.security.zef_injection_filter as zef
        env["tools"]["read_tool"] = _Tool("read_tool", result="perfectly normal text")
        monkeypatch.setattr(zef, "scan_message", lambda *a, **k: types.SimpleNamespace(
            verdict="PASS-ish", matched_patterns=[]))
        resp = _call("read_tool")
        assert resp.success is False and resp.metadata["output_scan_failed"] is True

    def test_result_whose_str_raises_is_withheld(self, env):
        class Evil:
            def __str__(self):
                raise RuntimeError("no str for you")
        env["tools"]["read_tool"] = t = _Tool("read_tool", result=Evil())
        resp = _call("read_tool")
        assert len(t.calls) == 1
        assert resp.success is False and resp.metadata["output_scan_failed"] is True
        rows = env["audit"].get_dispatch_history(agent_id="aeris")
        assert [r["verdict"] for r in rows] == ["allowed"]
        assert rows[0]["result_success"] == 0

    def test_none_agent_id_still_audited(self, env):
        resp = asyncio.run(gateway.dispatch_tool(
            "read_tool", {}, None, "READ", identity_token="x"))
        assert resp.success is False
        assert _verdicts(env["audit"], "<none>") == ["denied_identity"]

    def test_unexpected_error_is_caught_and_audited(self, env, monkeypatch):
        def boom(*_a, **_k):
            raise RuntimeError("request build failed")
        monkeypatch.setattr(gateway, "ToolRequest", boom)
        env["tools"]["read_tool"] = _Tool("read_tool")
        resp = _call("read_tool")
        assert resp.success is False and "request build failed" in resp.error
        assert _verdicts(env["audit"]) == ["denied_subsystem"]


class TestBreakerBeforeGoGate:
    def test_locked_agent_creates_zero_approval_requests(self, env, monkeypatch):
        monkeypatch.setattr(circuit_breaker.CircuitBreaker, "DEFAULT_MAX_ACTIONS", 1)
        circuit_breaker.reset_breakers()
        env["tools"]["read_tool"] = _Tool("read_tool")
        env["tools"]["write_tool"] = w = _Tool("write_tool")
        assert _call("read_tool").success is True
        assert _call("read_tool").success is False      # trips the lockout
        for i in range(25):
            resp = _call("write_tool", params={"i": i})
            assert resp.success is False
        assert env["store"].list_pending() == []
        assert w.calls == []
        assert set(_verdicts(env["audit"])[2:]) == {"denied_circuit_breaker"}

    def test_approved_call_still_counts_once(self, env, monkeypatch):
        env["tools"]["write_tool"] = _Tool("write_tool")
        rid = _call("write_tool").metadata["approval_request_id"]
        env["store"].approve_request(rid, "human")
        assert _call("write_tool").success is True
        load = circuit_breaker.get_breaker("aeris").get_status()["load_in_window"]
        assert load == tool_zones.risk_weight("write_tool")


class TestBreakerWeight:
    def test_breaker_receives_zone_risk_weight(self, env, monkeypatch):
        seen = []
        real = circuit_breaker.CircuitBreaker.check_and_record

        def spy(self, tool_name, weight=1.0):
            seen.append((tool_name, weight))
            return real(self, tool_name, weight)
        monkeypatch.setattr(circuit_breaker.CircuitBreaker, "check_and_record", spy)
        monkeypatch.setitem(tool_zones.TOOL_ZONES, "exec_tool", Zone.EXEC)
        monkeypatch.setitem(tool_zones.ZONE_ACTIONS, Zone.EXEC, ZoneAction.ALLOW)
        env["tools"]["exec_tool"] = _Tool("exec_tool")
        env["tools"]["read_tool"] = _Tool("read_tool")
        _call("exec_tool")
        _call("read_tool")
        assert seen == [("exec_tool", 3.0), ("read_tool", 1.0)]


class TestEventLoopNotBlocked:
    def test_slow_layer_runs_off_loop(self, env, monkeypatch):
        import time as _time
        env["tools"]["read_tool"] = _Tool("read_tool")
        real = gateway._check_tool_zone
        state = {"n": 0, "stop": False, "during": None}

        def slow(*a):
            before = state["n"]
            _time.sleep(0.3)
            state["during"] = state["n"] - before
            return real(*a)
        monkeypatch.setattr(gateway, "_check_tool_zone", slow)

        async def run():
            async def ticker():
                while not state["stop"]:
                    state["n"] += 1
                    await asyncio.sleep(0.01)
            t = asyncio.create_task(ticker())
            resp = await gateway.dispatch_tool(
                "read_tool", {}, "aeris", "READ",
                identity_token=agent_identity.issue_identity("aeris"))
            state["stop"] = True
            await t
            return resp

        assert asyncio.run(run()).success is True
        # The loop kept ticking while the layer slept in its worker thread;
        # on the event loop this would be 0.
        assert state["during"] >= 5


# ── Single-use approvals ────────────────────────────────────────────────────

class TestSingleUseApprovals:
    def test_approved_call_runs_once(self, env):
        env["tools"]["write_tool"] = t = _Tool("write_tool")
        rid = _call("write_tool", params={"p": 1}).metadata["approval_request_id"]
        env["store"].approve_request(rid, "human")
        assert _call("write_tool", params={"p": 1}).success is True
        again = _call("write_tool", params={"p": 1})
        assert again.success is False and len(t.calls) == 1
        assert again.metadata["approval_request_id"] != rid      # a fresh request
        assert _verdicts(env["audit"]) == ["pending_approval", "allowed", "pending_approval"]
        assert env["store"].get_request(rid).consumed_at is not None

    def test_concurrent_reissues_execute_once(self, env):
        env["tools"]["write_tool"] = t = _Tool("write_tool")
        rid = _call("write_tool", params={"p": 2}).metadata["approval_request_id"]
        env["store"].approve_request(rid, "human")

        async def both():
            tok = agent_identity.issue_identity("aeris")
            return await asyncio.gather(*[
                gateway.dispatch_tool("write_tool", {"p": 2}, "aeris", "READ",
                                      identity_token=tok) for _ in range(5)])
        results = asyncio.run(both())
        assert sum(r.success for r in results) == 1
        assert len(t.calls) == 1

    def test_ten_threads_reissue_execute_once(self, env):
        import threading
        env["tools"]["write_tool"] = t = _Tool("write_tool")
        rid = _call("write_tool", params={"p": 10}).metadata["approval_request_id"]
        env["store"].approve_request(rid, "human")
        results = []
        barrier = threading.Barrier(10)

        def worker():
            barrier.wait()
            results.append(_call("write_tool", params={"p": 10}))
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        assert len(results) == 10
        assert sum(r.success for r in results) == 1
        assert len(t.calls) == 1

    def test_lost_race_is_denied_with_gate_verdict(self, env, monkeypatch):
        env["tools"]["write_tool"] = t = _Tool("write_tool")
        rid = _call("write_tool", params={"p": 3}).metadata["approval_request_id"]
        env["store"].approve_request(rid, "human")
        monkeypatch.setattr(env["store"], "consume_approval", lambda *_a, **_k: False)
        resp = _call("write_tool", params={"p": 3})
        assert resp.success is False and t.calls == []
        assert "already used" in resp.error
        assert _verdicts(env["audit"])[-1] == "denied_zone"

    def test_one_approval_covers_zone_and_mcp_then_consumed_once(self, env):
        import sqlite3
        _server(TrustLevel.PROVISIONAL)
        env["tools"]["write_tool"] = t = _Tool("write_tool", server="srv")
        rid = _call("write_tool").metadata["approval_request_id"]
        env["store"].approve_request(rid, "human")
        assert _call("write_tool").success is True
        assert len(t.calls) == 1
        conn = sqlite3.connect(env["store"].db_path)
        events = [e for (e,) in conn.execute(
            "SELECT event FROM approval_events WHERE request_id=?", (rid,))]
        conn.close()
        assert events.count("consumed") == 1
        assert _call("write_tool").success is False   # consumed → asks again

    def test_deny_stays_sticky_after_single_use(self, env):
        env["tools"]["write_tool"] = t = _Tool("write_tool")
        rid = _call("write_tool", params={"p": 4}).metadata["approval_request_id"]
        env["store"].deny_request(rid, "human")
        for _ in range(3):
            assert _call("write_tool", params={"p": 4}).success is False
        assert t.calls == []
        assert set(_verdicts(env["audit"])[1:]) == {"denied_zone"}
