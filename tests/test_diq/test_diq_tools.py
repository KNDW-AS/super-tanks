"""
Tests for core/diq/diq_tools.py.

The DIQTool ABC + ToolRequest/ToolResponse dataclasses define the
contract every tool implements. We verify immutability of the
request/response objects and the default validate_access role
hierarchy.
"""

import pytest

from core.diq.diq_tools import DIQTool, ToolRequest, ToolResponse


class _FakeTool(DIQTool):
    def __init__(self, required="READ"):
        self._req = required

    def name(self):
        return "fake"

    def description(self):
        return "fake tool"

    def parameters_schema(self):
        return {}

    def required_role(self):
        return self._req

    async def _execute_impl(self, request):
        return ToolResponse(success=True, result="ok")


# ── Gateway chokepoint enforcement ─────────────────────────────────────────

class TestGatewayChokepoint:
    def test_direct_execute_outside_gateway_refused(self):
        # Calling .execute() without gateway context returns a refusal,
        # not the actual tool result. The architectural review flagged
        # that any caller could bypass role + allowlist + audit by
        # holding a tool instance and calling execute() directly.
        import asyncio
        tool = _FakeTool()
        req = ToolRequest(tool_name="fake", agent_id="aeris",
                          agent_role="READ", parameters={})
        resp = asyncio.run(tool.execute(req))
        assert resp.success is False
        assert "bypass" in resp.error.lower()

    def test_execute_inside_gateway_context_succeeds(self):
        # When the gateway sets the ContextVar, execute() proceeds.
        import asyncio
        from core.diq.diq_tools import _gateway_active

        async def _under_gateway():
            token = _gateway_active.set(True)
            try:
                tool = _FakeTool()
                req = ToolRequest(tool_name="fake", agent_id="aeris",
                                  agent_role="READ", parameters={})
                return await tool.execute(req)
            finally:
                _gateway_active.reset(token)

        resp = asyncio.run(_under_gateway())
        assert resp.success is True
        assert resp.result == "ok"

    def test_subclass_overriding_execute_is_rejected(self):
        # __init_subclass__ refuses subclasses that try to override
        # the chokepoint. Hard fail at class definition, not silent
        # bypass at call time.
        with pytest.raises(TypeError, match="overrides execute"):
            class _Bad(DIQTool):
                def name(self): return "bad"
                def description(self): return ""
                def parameters_schema(self): return {}
                def required_role(self): return "READ"

                async def execute(self, request):  # banned
                    return ToolResponse(success=True, result="bypass")

                async def _execute_impl(self, request):
                    return ToolResponse(success=True, result="ok")


# ── Dataclass immutability ─────────────────────────────────────────────────

class TestToolRequestImmutable:
    def test_request_is_frozen(self):
        req = ToolRequest(tool_name="x", agent_id="aeris", agent_role="READ",
                          parameters={})
        with pytest.raises((AttributeError, Exception)):
            req.agent_id = "evil"  # type: ignore[misc]

    def test_response_is_frozen(self):
        resp = ToolResponse(success=True, result=None)
        with pytest.raises((AttributeError, Exception)):
            resp.success = False  # type: ignore[misc]


class TestToolRequestDefaults:
    def test_conversation_id_default(self):
        req = ToolRequest(tool_name="x", agent_id="a", agent_role="READ",
                          parameters={})
        assert req.conversation_id is None


# ── validate_access ────────────────────────────────────────────────────────

class TestValidateAccess:
    @pytest.mark.parametrize("agent_role,required,expected", [
        ("READ", "READ", True),
        ("CHAT", "READ", True),
        ("WRITE", "READ", True),
        ("EXEC", "WRITE", True),
        ("ADMIN", "ADMIN", True),
        ("READ", "WRITE", False),
        ("READ", "EXEC", False),
        ("WRITE", "EXEC", False),
        ("EXEC", "ADMIN", False),
    ])
    def test_role_hierarchy(self, agent_role, required, expected):
        tool = _FakeTool(required=required)
        req = ToolRequest(tool_name="fake", agent_id="x",
                          agent_role=agent_role, parameters={})
        assert tool.validate_access(req) is expected

    def test_unknown_agent_role_denied(self):
        tool = _FakeTool(required="READ")
        req = ToolRequest(tool_name="fake", agent_id="x",
                          agent_role="GHOST", parameters={})
        assert tool.validate_access(req) is False

    def test_unknown_required_role_denied(self):
        tool = _FakeTool(required="WIZARD")
        req = ToolRequest(tool_name="fake", agent_id="x",
                          agent_role="ADMIN", parameters={})
        # required_level becomes 999, so even ADMIN can't reach it.
        assert tool.validate_access(req) is False


# ── ToolResponse shape ─────────────────────────────────────────────────────

class TestToolResponse:
    def test_minimum_constructor(self):
        resp = ToolResponse(success=True, result={"k": 1})
        assert resp.success is True
        assert resp.result == {"k": 1}
        assert resp.error is None
        assert resp.metadata is None

    def test_error_response(self):
        resp = ToolResponse(success=False, result=None, error="boom")
        assert resp.success is False
        assert resp.error == "boom"
