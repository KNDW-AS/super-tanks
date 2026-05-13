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

    async def execute(self, request):
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
