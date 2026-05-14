"""
Tests for core/gateway.py.

The gateway is async and pulls tools from the DIQ registry. Tests
install fake tools, exercise the role / allowlist enforcement, and
verify the bypass for system/internal/test callers.
"""

import asyncio

import pytest

from core.diq.diq_tools import DIQTool, ToolRequest, ToolResponse
from core import gateway


class _Tool(DIQTool):
    def __init__(self, name="fake", required_role="READ",
                 result="ok", success=True):
        self._n = name
        self._r = required_role
        self._result = result
        self._success = success
        self.calls = []

    def name(self):
        return self._n

    def description(self):
        return "fake"

    def parameters_schema(self):
        return {}

    def required_role(self):
        return self._r

    async def execute(self, request):
        self.calls.append(request)
        return ToolResponse(success=self._success, result=self._result)


@pytest.fixture
def fake_registry(monkeypatch):
    tools = {}

    def fake_get_tool(name):
        return tools.get(name)

    monkeypatch.setattr(gateway, "get_tool", fake_get_tool)
    return tools


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) \
        if False else asyncio.run(coro)


# ── Unknown tool → None (fall back to plugin run_fn) ───────────────────────

class TestUnknownTool:
    def test_returns_none(self, fake_registry):
        result = asyncio.run(gateway.dispatch_tool("nope", {}, "aeris", "READ"))
        assert result is None


# ── Role enforcement ───────────────────────────────────────────────────────

class TestRoleEnforcement:
    def test_grants_when_role_sufficient(self, fake_registry, monkeypatch):
        # Bypass allowlist by using "system" agent.
        fake_registry["t"] = _Tool(name="t", required_role="READ",
                                   result="data")
        resp = asyncio.run(gateway.dispatch_tool("t", {}, "system", "READ"))
        assert resp.success is True
        assert resp.result == "data"

    def test_denies_when_role_insufficient(self, fake_registry):
        fake_registry["t"] = _Tool(name="t", required_role="ADMIN")
        resp = asyncio.run(gateway.dispatch_tool("t", {}, "system", "READ"))
        assert resp.success is False
        assert "Access denied" in resp.error
        assert "ADMIN" in resp.error

    def test_tool_not_executed_on_denial(self, fake_registry):
        tool = _Tool(name="t", required_role="ADMIN")
        fake_registry["t"] = tool
        asyncio.run(gateway.dispatch_tool("t", {}, "system", "READ"))
        assert tool.calls == []


# ── Allowlist enforcement ──────────────────────────────────────────────────

class TestAllowlistEnforcement:
    def test_named_agent_blocked_when_not_in_allowlist(self, fake_registry,
                                                       monkeypatch):
        # Provide a tool that role check passes, then deny via allowlist.
        fake_registry["forbidden_tool"] = _Tool(name="forbidden_tool",
                                                required_role="READ")

        from core.security import tool_allowlists
        monkeypatch.setattr(tool_allowlists, "is_tool_allowed",
                            lambda agent, tool: False)
        resp = asyncio.run(gateway.dispatch_tool(
            "forbidden_tool", {}, "aeris", "READ"))
        assert resp.success is False
        assert "not in allowlist" in resp.error

    def test_named_agent_passes_when_in_allowlist(self, fake_registry,
                                                  monkeypatch):
        fake_registry["allowed_tool"] = _Tool(name="allowed_tool",
                                              required_role="READ",
                                              result="data")

        from core.security import tool_allowlists
        monkeypatch.setattr(tool_allowlists, "is_tool_allowed",
                            lambda agent, tool: True)
        resp = asyncio.run(gateway.dispatch_tool(
            "allowed_tool", {}, "aeris", "READ"))
        assert resp.success is True
        assert resp.result == "data"

    @pytest.mark.parametrize("agent", ["system", "internal", "test"])
    def test_internal_agents_bypass_allowlist(self, fake_registry,
                                              monkeypatch, agent):
        fake_registry["any_tool"] = _Tool(name="any_tool",
                                          required_role="READ",
                                          result="ok")

        from core.security import tool_allowlists
        calls = []
        monkeypatch.setattr(tool_allowlists, "is_tool_allowed",
                            lambda a, t: calls.append((a, t)) or False)
        resp = asyncio.run(gateway.dispatch_tool(
            "any_tool", {}, agent, "READ"))
        # Allowlist must not be consulted for internal agents.
        assert calls == []
        assert resp.success is True

    def test_allowlist_exception_fails_closed(
            self, fake_registry, monkeypatch):
        # If the allowlist module itself raises, the gateway MUST deny
        # the call. A subsystem failure must not become a free pass.
        fake_registry["t"] = _Tool(name="t", required_role="READ",
                                   result="ok")

        from core.security import tool_allowlists

        def boom(agent, tool):
            raise RuntimeError("allowlist offline")

        monkeypatch.setattr(tool_allowlists, "is_tool_allowed", boom)
        resp = asyncio.run(gateway.dispatch_tool("t", {}, "aeris", "READ"))
        assert resp.success is False
        assert "Allowlist unavailable" in resp.error


# ── Request shape passed through ───────────────────────────────────────────

class TestRequestPassthrough:
    def test_request_built_with_caller_args(self, fake_registry):
        tool = _Tool(name="t", required_role="READ")
        fake_registry["t"] = tool
        asyncio.run(gateway.dispatch_tool(
            "t", {"a": 1}, "system", "EXEC", conversation_id="conv-xyz"))
        assert len(tool.calls) == 1
        req: ToolRequest = tool.calls[0]
        assert req.tool_name == "t"
        assert req.parameters == {"a": 1}
        assert req.agent_id == "system"
        assert req.agent_role == "EXEC"
        assert req.conversation_id == "conv-xyz"
