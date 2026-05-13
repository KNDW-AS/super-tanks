"""
Tests for core/diq/diq_registry.py.

The registry holds the only mutable state in the DIQ package: module
globals for tools/skills/a2a/cloud/memory/ha. Each test resets these
via monkeypatch so registration doesn't leak across tests.
"""

import pytest

from core.diq import diq_registry as reg
from core.diq.diq_tools import DIQTool, ToolRequest, ToolResponse


class _Tool(DIQTool):
    def __init__(self, n="t"):
        self._n = n

    def name(self):
        return self._n

    def description(self):
        return "tool"

    def parameters_schema(self):
        return {}

    def required_role(self):
        return "READ"

    async def execute(self, request):
        return ToolResponse(success=True, result=None)


@pytest.fixture
def fresh_registry(monkeypatch):
    """Reset every registry slot before each test."""
    monkeypatch.setattr(reg, "_tool_registry", {})
    monkeypatch.setattr(reg, "_skill_registry", {})
    monkeypatch.setattr(reg, "_a2a_channel", None)
    monkeypatch.setattr(reg, "_cloud_cortex", None)
    monkeypatch.setattr(reg, "_memory", None)
    monkeypatch.setattr(reg, "_ha", None)
    return reg


# ── Tool registry ──────────────────────────────────────────────────────────

class TestToolRegistry:
    def test_register_and_get(self, fresh_registry):
        t = _Tool("alpha")
        fresh_registry.register_tool(t)
        assert fresh_registry.get_tool("alpha") is t

    def test_get_unknown_returns_none(self, fresh_registry):
        assert fresh_registry.get_tool("missing") is None

    def test_register_overwrites_existing(self, fresh_registry):
        first = _Tool("alpha")
        second = _Tool("alpha")
        fresh_registry.register_tool(first)
        fresh_registry.register_tool(second)
        assert fresh_registry.get_tool("alpha") is second

    def test_all_tools_returns_copy(self, fresh_registry):
        fresh_registry.register_tool(_Tool("a"))
        snap = fresh_registry.all_tools()
        snap["b"] = "mutated"
        # External mutation must not leak into the real registry.
        assert "b" not in fresh_registry.all_tools()


# ── Singleton slots (a2a / cloud / memory / ha) ───────────────────────────

class TestSingletonSlots:
    def test_a2a_default_none(self, fresh_registry):
        assert fresh_registry.get_a2a() is None

    def test_a2a_register_and_retrieve(self, fresh_registry):
        sentinel = object()
        fresh_registry.register_a2a(sentinel)
        assert fresh_registry.get_a2a() is sentinel

    def test_cloud_register_and_retrieve(self, fresh_registry):
        sentinel = object()
        fresh_registry.register_cloud(sentinel)
        assert fresh_registry.get_cloud() is sentinel

    def test_memory_register_and_retrieve(self, fresh_registry):
        sentinel = object()
        fresh_registry.register_memory(sentinel)
        assert fresh_registry.get_memory() is sentinel

    def test_ha_register_and_retrieve(self, fresh_registry):
        sentinel = object()
        fresh_registry.register_ha(sentinel)
        assert fresh_registry.get_ha() is sentinel


# ── Skill registry ─────────────────────────────────────────────────────────

class TestSkillRegistry:
    def test_register_and_get(self, fresh_registry):
        class _Skill:
            def skill_name(self):
                return "weather"

        s = _Skill()
        fresh_registry.register_skill(s)
        assert fresh_registry.get_skill("weather") is s

    def test_unknown_skill_returns_none(self, fresh_registry):
        assert fresh_registry.get_skill("absent") is None

    def test_all_skills_returns_copy(self, fresh_registry):
        class _Skill:
            def skill_name(self):
                return "x"

        fresh_registry.register_skill(_Skill())
        snap = fresh_registry.all_skills()
        snap["mutated"] = True
        assert "mutated" not in fresh_registry.all_skills()
