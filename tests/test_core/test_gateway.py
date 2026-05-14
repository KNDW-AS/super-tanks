"""
Tests for core/gateway.py.

The gateway is async and pulls tools from the DIQ registry. Tests
install fake tools, exercise role + allowlist enforcement, and verify
that identity_token verification gates every dispatch.
"""

import asyncio

import pytest

from core.diq.diq_tools import DIQTool, ToolRequest, ToolResponse
from core import gateway
from core.security import agent_identity


@pytest.fixture
def identity(monkeypatch):
    """Set a deterministic HMAC key for the test."""
    monkeypatch.setattr(agent_identity, "_KEY", b"test-key-for-gateway-suite")
    return agent_identity


def _token(identity_mod, agent_id):
    return identity_mod.issue_identity(agent_id)


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

    async def _execute_impl(self, request):
        self.calls.append(request)
        return ToolResponse(success=self._success, result=self._result)


@pytest.fixture
def fake_registry(monkeypatch):
    tools = {}

    def fake_get_tool(name):
        return tools.get(name)

    monkeypatch.setattr(gateway, "get_tool", fake_get_tool)
    return tools


# ── Identity verification (the gate before everything else) ────────────────

class TestIdentityVerification:
    def test_missing_token_denies(self, fake_registry, identity):
        fake_registry["t"] = _Tool(name="t", required_role="READ")
        resp = asyncio.run(gateway.dispatch_tool(
            "t", {}, "aeris", "READ", identity_token=None))
        assert resp.success is False
        assert "Identity" in resp.error

    def test_wrong_token_denies(self, fake_registry, identity):
        fake_registry["t"] = _Tool(name="t", required_role="READ")
        # Token for zeph won't verify as aeris.
        resp = asyncio.run(gateway.dispatch_tool(
            "t", {}, "aeris", "READ",
            identity_token=_token(identity, "zeph")))
        assert resp.success is False
        assert "Identity" in resp.error

    def test_valid_token_grants(self, fake_registry, identity):
        fake_registry["t"] = _Tool(name="t", required_role="READ",
                                   result="data")
        # The fake-registry tool requires READ; aeris's allowlist would
        # block an unknown tool, so stub it allowed.
        from core.security import tool_allowlists
        import unittest.mock as _m
        with _m.patch.object(tool_allowlists, "is_tool_allowed",
                             return_value=True):
            resp = asyncio.run(gateway.dispatch_tool(
                "t", {}, "aeris", "READ",
                identity_token=_token(identity, "aeris")))
        assert resp.success is True
        assert resp.result == "data"

    def test_unauthenticated_does_not_leak_tool_existence(
            self, fake_registry, identity):
        # The identity check runs BEFORE get_tool, so an attacker can't
        # probe the registry by sending dispatches with no token.
        fake_registry["sensitive_tool"] = _Tool(name="sensitive_tool",
                                                required_role="READ")
        resp = asyncio.run(gateway.dispatch_tool(
            "sensitive_tool", {}, "attacker", "READ", identity_token=""))
        assert resp.success is False
        # Error message must NOT reveal whether the tool exists.
        assert "Identity" in resp.error
        assert "sensitive_tool" not in resp.error


# ── Unknown tool → None (fall back to plugin run_fn) ───────────────────────

class TestUnknownTool:
    def test_returns_none_after_auth(self, fake_registry, identity):
        # With a valid token, an unknown tool returns None so the caller
        # falls back to the plugin run_fn.
        result = asyncio.run(gateway.dispatch_tool(
            "nope", {}, "system", "READ",
            identity_token=_token(identity, "system")))
        assert result is None


# ── Role enforcement ───────────────────────────────────────────────────────

class TestRoleEnforcement:
    def test_grants_when_role_sufficient(self, fake_registry, identity):
        fake_registry["t"] = _Tool(name="t", required_role="READ",
                                   result="data")
        resp = asyncio.run(gateway.dispatch_tool(
            "t", {}, "system", "READ",
            identity_token=_token(identity, "system")))
        assert resp.success is True
        assert resp.result == "data"

    def test_denies_when_role_insufficient(self, fake_registry, identity):
        fake_registry["t"] = _Tool(name="t", required_role="ADMIN")
        resp = asyncio.run(gateway.dispatch_tool(
            "t", {}, "system", "READ",
            identity_token=_token(identity, "system")))
        assert resp.success is False
        assert "Access denied" in resp.error
        assert "ADMIN" in resp.error

    def test_tool_not_executed_on_denial(self, fake_registry, identity):
        tool = _Tool(name="t", required_role="ADMIN")
        fake_registry["t"] = tool
        asyncio.run(gateway.dispatch_tool(
            "t", {}, "system", "READ",
            identity_token=_token(identity, "system")))
        assert tool.calls == []


# ── Allowlist enforcement ──────────────────────────────────────────────────

class TestAllowlistEnforcement:
    def test_named_agent_blocked_when_not_in_allowlist(
            self, fake_registry, monkeypatch, identity):
        fake_registry["forbidden_tool"] = _Tool(name="forbidden_tool",
                                                required_role="READ")

        from core.security import tool_allowlists
        monkeypatch.setattr(tool_allowlists, "is_tool_allowed",
                            lambda agent, tool: False)
        resp = asyncio.run(gateway.dispatch_tool(
            "forbidden_tool", {}, "aeris", "READ",
            identity_token=_token(identity, "aeris")))
        assert resp.success is False
        assert "not in allowlist" in resp.error

    def test_named_agent_passes_when_in_allowlist(
            self, fake_registry, monkeypatch, identity):
        fake_registry["allowed_tool"] = _Tool(name="allowed_tool",
                                              required_role="READ",
                                              result="data")

        from core.security import tool_allowlists
        monkeypatch.setattr(tool_allowlists, "is_tool_allowed",
                            lambda agent, tool: True)
        resp = asyncio.run(gateway.dispatch_tool(
            "allowed_tool", {}, "aeris", "READ",
            identity_token=_token(identity, "aeris")))
        assert resp.success is True

    @pytest.mark.parametrize("agent", ["system", "internal", "test"])
    def test_internal_agents_skip_allowlist_but_still_need_token(
            self, fake_registry, monkeypatch, identity, agent):
        fake_registry["any_tool"] = _Tool(name="any_tool",
                                          required_role="READ",
                                          result="ok")

        from core.security import tool_allowlists
        calls = []
        monkeypatch.setattr(tool_allowlists, "is_tool_allowed",
                            lambda a, t: calls.append((a, t)) or False)
        resp = asyncio.run(gateway.dispatch_tool(
            "any_tool", {}, agent, "READ",
            identity_token=_token(identity, agent)))
        # Allowlist must not be consulted for internal agents.
        assert calls == []
        assert resp.success is True

    @pytest.mark.parametrize("agent", ["system", "internal", "test"])
    def test_internal_agents_still_require_token(
            self, fake_registry, identity, agent):
        # Pretending to be "system" without a real token must fail.
        fake_registry["any_tool"] = _Tool(name="any_tool",
                                          required_role="READ")
        resp = asyncio.run(gateway.dispatch_tool(
            "any_tool", {}, agent, "READ", identity_token=None))
        assert resp.success is False
        assert "Identity" in resp.error

    def test_allowlist_exception_fails_closed(
            self, fake_registry, monkeypatch, identity):
        fake_registry["t"] = _Tool(name="t", required_role="READ",
                                   result="ok")

        from core.security import tool_allowlists

        def boom(agent, tool):
            raise RuntimeError("allowlist offline")

        monkeypatch.setattr(tool_allowlists, "is_tool_allowed", boom)
        resp = asyncio.run(gateway.dispatch_tool(
            "t", {}, "aeris", "READ",
            identity_token=_token(identity, "aeris")))
        assert resp.success is False
        assert "Allowlist unavailable" in resp.error


# ── Dispatch audit trail ───────────────────────────────────────────────────

class TestDispatchAudit:
    """The gateway writes one row per dispatch to dispatch_audit, with
    a fresh correlation_id, regardless of allow/deny outcome. The
    correlation_id is also visible to downstream collaborators via the
    ContextVar — that's what makes incident reconstruction possible."""

    @pytest.fixture
    def audit(self, tmp_path, monkeypatch):
        from core.security import dispatch_audit
        monkeypatch.setattr(dispatch_audit, "DB_PATH",
                            tmp_path / "dispatch.db")
        monkeypatch.setattr(dispatch_audit, "_initialised", False)
        return dispatch_audit

    def test_allowed_dispatch_recorded_with_corr_id(
            self, fake_registry, identity, audit):
        fake_registry["t"] = _Tool(name="t", required_role="READ",
                                   result="data")
        from core.security import tool_allowlists
        import unittest.mock as _m
        with _m.patch.object(tool_allowlists, "is_tool_allowed",
                             return_value=True):
            asyncio.run(gateway.dispatch_tool(
                "t", {}, "aeris", "READ",
                identity_token=_token(identity, "aeris")))
        rows = audit.get_dispatch_history(agent_id="aeris")
        assert len(rows) == 1
        assert rows[0]["verdict"] == "allowed"
        assert rows[0]["result_success"] == 1
        assert rows[0]["correlation_id"]  # non-empty

    def test_denied_identity_recorded(
            self, fake_registry, identity, audit):
        fake_registry["t"] = _Tool(name="t", required_role="READ")
        asyncio.run(gateway.dispatch_tool(
            "t", {}, "aeris", "READ", identity_token=None))
        rows = audit.get_dispatch_history(agent_id="aeris")
        assert len(rows) == 1
        assert rows[0]["verdict"] == "denied_identity"

    def test_denied_role_recorded(
            self, fake_registry, identity, audit):
        fake_registry["t"] = _Tool(name="t", required_role="ADMIN")
        asyncio.run(gateway.dispatch_tool(
            "t", {}, "system", "READ",
            identity_token=_token(identity, "system")))
        rows = audit.get_dispatch_history(agent_id="system")
        assert rows[0]["verdict"] == "denied_role"

    def test_denied_allowlist_recorded(
            self, fake_registry, monkeypatch, identity, audit):
        fake_registry["t"] = _Tool(name="t", required_role="READ")
        from core.security import tool_allowlists
        monkeypatch.setattr(tool_allowlists, "is_tool_allowed",
                            lambda a, t: False)
        asyncio.run(gateway.dispatch_tool(
            "t", {}, "aeris", "READ",
            identity_token=_token(identity, "aeris")))
        rows = audit.get_dispatch_history(agent_id="aeris")
        assert rows[0]["verdict"] == "denied_allowlist"

    def test_no_wrapper_recorded(self, fake_registry, identity, audit):
        # Unknown tool returns None, but still gets a row so the
        # incident timeline has no gaps.
        asyncio.run(gateway.dispatch_tool(
            "unknown_tool", {}, "system", "READ",
            identity_token=_token(identity, "system")))
        rows = audit.get_dispatch_history(agent_id="system")
        assert rows[0]["verdict"] == "no_wrapper"

    def test_correlation_id_is_unique_per_dispatch(
            self, fake_registry, identity, audit):
        fake_registry["t"] = _Tool(name="t", required_role="READ",
                                   result="ok")
        from core.security import tool_allowlists
        import unittest.mock as _m
        with _m.patch.object(tool_allowlists, "is_tool_allowed",
                             return_value=True):
            for _ in range(3):
                asyncio.run(gateway.dispatch_tool(
                    "t", {}, "aeris", "READ",
                    identity_token=_token(identity, "aeris")))
        rows = audit.get_dispatch_history(agent_id="aeris")
        corr_ids = {r["correlation_id"] for r in rows}
        assert len(corr_ids) == 3  # all distinct


# ── Request shape passed through ───────────────────────────────────────────

class TestRequestPassthrough:
    def test_request_built_with_caller_args(self, fake_registry, identity):
        tool = _Tool(name="t", required_role="READ")
        fake_registry["t"] = tool
        asyncio.run(gateway.dispatch_tool(
            "t", {"a": 1}, "system", "EXEC", conversation_id="conv-xyz",
            identity_token=_token(identity, "system")))
        assert len(tool.calls) == 1
        req: ToolRequest = tool.calls[0]
        assert req.tool_name == "t"
        assert req.parameters == {"a": 1}
        assert req.agent_id == "system"
        assert req.agent_role == "EXEC"
        assert req.conversation_id == "conv-xyz"
