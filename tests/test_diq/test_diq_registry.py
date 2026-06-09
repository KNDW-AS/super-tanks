"""
Tests for core/diq/diq_registry.py.

The registry holds the only mutable state in the DIQ package: module
globals for tools/skills/a2a/cloud/memory/ha. Each test resets these
via monkeypatch so registration doesn't leak across tests.
"""

import pytest

from core.diq import diq_registry as reg
from core.diq.diq_tools import DIQTool, ToolResponse


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

    async def _execute_impl(self, request):
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
        # register_a2a wraps the channel in _VerifyingA2AChannel so
        # every receive() output runs through verify_or_drop. The
        # original channel is held inside the wrapper.
        from core.diq.diq_a2a import DIQA2AChannel

        class _StubChannel(DIQA2AChannel):
            async def send(self, message): return True
            async def receive(self, agent_id): return None
            async def receive_all(self, agent_id): return []
            async def broadcast(self, sender, payload): return True

        inner = _StubChannel()
        fresh_registry.register_a2a(inner)
        wrapped = fresh_registry.get_a2a()
        assert isinstance(wrapped, fresh_registry._VerifyingA2AChannel)
        assert wrapped._inner is inner

    def test_a2a_register_does_not_double_wrap(self, fresh_registry):
        from core.diq.diq_a2a import DIQA2AChannel

        class _StubChannel(DIQA2AChannel):
            async def send(self, message): return True
            async def receive(self, agent_id): return None
            async def receive_all(self, agent_id): return []
            async def broadcast(self, sender, payload): return True

        inner = _StubChannel()
        fresh_registry.register_a2a(inner)
        wrapped_once = fresh_registry.get_a2a()
        # Re-register the already-wrapped channel — must not nest.
        fresh_registry.register_a2a(wrapped_once)
        wrapped_twice = fresh_registry.get_a2a()
        assert wrapped_twice is wrapped_once
        assert wrapped_twice._inner is inner


# ── A2A wrapper end-to-end (R-06) ──────────────────────────────────────────

class TestA2AVerifyingWrapper:
    """The registration wrapper must drop unsigned/forged messages
    before the agent runtime ever sees them. This is the integration
    point — verify_or_drop's unit tests live in tests/test_a2a/, but
    here we prove the wiring inside the registry."""

    def test_receive_drops_unsigned_message(self, fresh_registry):
        import asyncio
        from core.diq.diq_a2a import A2AMessage, DIQA2AChannel

        unsigned = A2AMessage(sender="aeris", recipient="zeph",
                              message_type="request")

        class _StubChannel(DIQA2AChannel):
            async def send(self, message): return True
            async def receive(self, agent_id): return unsigned
            async def receive_all(self, agent_id): return [unsigned]
            async def broadcast(self, sender, payload): return True

        fresh_registry.register_a2a(_StubChannel())
        ch = fresh_registry.get_a2a()
        # Unsigned → wrapper substitutes None, agent never sees it.
        assert asyncio.run(ch.receive("zeph")) is None
        assert asyncio.run(ch.receive_all("zeph")) == []

    def test_receive_passes_through_valid_signed(self, fresh_registry, monkeypatch):
        import asyncio
        from core.security import agent_identity
        from core.diq.diq_a2a import A2AMessage, DIQA2AChannel

        monkeypatch.setattr(agent_identity, "_KEY", b"test-a2a-wrap-key")
        signed = agent_identity.sign_a2a_message(A2AMessage(
            sender="aeris", recipient="zeph", message_type="request",
            timestamp="2024-01-01T00:00:00+00:00", correlation_id="c-1",
        ))

        class _StubChannel(DIQA2AChannel):
            async def send(self, message): return True
            async def receive(self, agent_id): return signed
            async def receive_all(self, agent_id): return [signed]
            async def broadcast(self, sender, payload): return True

        fresh_registry.register_a2a(_StubChannel())
        ch = fresh_registry.get_a2a()
        assert asyncio.run(ch.receive("zeph")) is signed
        assert asyncio.run(ch.receive_all("zeph")) == [signed]

    def test_receive_filters_mixed_batch(self, fresh_registry, monkeypatch):
        import asyncio
        from dataclasses import replace
        from core.security import agent_identity
        from core.diq.diq_a2a import A2AMessage, DIQA2AChannel

        monkeypatch.setattr(agent_identity, "_KEY", b"test-a2a-mix-key")
        good = agent_identity.sign_a2a_message(A2AMessage(
            sender="aeris", recipient="zeph", message_type="request",
            timestamp="2024-01-01T00:00:00+00:00", correlation_id="c-good",
        ))
        forged = replace(good, sender="william")  # signature won't verify
        unsigned = A2AMessage(sender="zeph", recipient="aeris",
                              message_type="notify")

        class _StubChannel(DIQA2AChannel):
            async def send(self, message): return True
            async def receive(self, agent_id): return None
            async def receive_all(self, agent_id):
                return [good, forged, unsigned]
            async def broadcast(self, sender, payload): return True

        fresh_registry.register_a2a(_StubChannel())
        ch = fresh_registry.get_a2a()
        out = asyncio.run(ch.receive_all("zeph"))
        assert out == [good]

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
