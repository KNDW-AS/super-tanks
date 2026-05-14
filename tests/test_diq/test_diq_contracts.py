"""
Tests for the frozen DIQ contract dataclasses.

These contracts (diq_a2a, diq_cloud, diq_memory, diq_skills, diq_ha)
must stay frozen and provide stable APIs. We verify the dataclasses
are immutable, default factories work as advertised, and ABC subclasses
can be instantiated when all abstract methods are implemented.
"""

import pytest

from core.diq.diq_a2a import A2AMessage, DIQA2AChannel
from core.diq.diq_cloud import LLMRequest, LLMResponse, DIQCloudCortex
from core.diq.diq_memory import MemoryEntry, MemoryQuery, MemoryResult, DIQMemory
from core.diq.diq_skills import SkillRequest, SkillResponse, DIQSkill
from core.diq.diq_ha import HACommand, HAStateQuery, HAResponse, DIQHA


# ── Dataclass immutability ─────────────────────────────────────────────────

class TestDataclassFrozenness:
    @pytest.mark.parametrize("cls,kwargs", [
        (A2AMessage, {"sender": "aeris", "recipient": "zeph",
                      "message_type": "request"}),
        (LLMRequest, {"messages": [], "agent_id": "aeris"}),
        (LLMResponse, {"content": "x", "provider_used": "ollama",
                       "model_used": "llama"}),
        (MemoryEntry, {"agent_id": "aeris", "collection": "x",
                       "content": "y"}),
        (MemoryQuery, {"agent_id": "aeris", "collection": "x", "query": "y"}),
        (MemoryResult, {"entries": [], "collection": "x",
                        "query_hash": "h", "total_chars": 0}),
        (SkillRequest, {"skill_name": "x", "agent_id": "aeris",
                        "parameters": {}}),
        (SkillResponse, {"success": True, "result": None, "skill_name": "x"}),
        (HACommand, {"domain": "light", "service": "turn_on",
                     "entity_id": "light.x"}),
        (HAStateQuery, {"entity_id": "light.x"}),
        (HAResponse, {"success": True, "entity_id": "light.x"}),
    ])
    def test_cannot_mutate(self, cls, kwargs):
        obj = cls(**kwargs)
        with pytest.raises(Exception):
            # Any frozen-dataclass attribute assignment must raise.
            setattr(obj, list(kwargs.keys())[0], "changed")


# ── Default factories ──────────────────────────────────────────────────────

class TestDefaults:
    def test_a2a_message_payload_defaults_to_empty(self):
        m = A2AMessage(sender="a", recipient="z", message_type="r")
        assert m.payload == {}
        # Timestamp is auto-generated.
        assert m.timestamp

    def test_memory_entry_metadata_defaults_to_empty(self):
        e = MemoryEntry(agent_id="a", collection="c", content="x")
        assert e.metadata == {}

    def test_skill_response_side_effects_default_empty(self):
        r = SkillResponse(success=True, result=None, skill_name="x")
        assert r.side_effects == []

    def test_ha_command_parameters_default_empty(self):
        c = HACommand(domain="light", service="turn_on", entity_id="light.x")
        assert c.parameters == {}
        assert c.agent_id == "aeris"

    def test_ha_state_query_default_agent(self):
        q = HAStateQuery(entity_id="light.x")
        assert q.agent_id == "aeris"


# ── ABC subclass implementation ────────────────────────────────────────────

class _FakeA2A(DIQA2AChannel):
    async def send(self, message):
        return True

    async def receive(self, agent_id):
        return None

    async def receive_all(self, agent_id):
        return []

    async def broadcast(self, sender, payload):
        return True


class _FakeCortex(DIQCloudCortex):
    async def complete(self, request):
        return LLMResponse(content="", provider_used="x", model_used="y")

    def available_providers(self):
        return ["ollama"]

    def classify_complexity(self, message):
        return 0.5


class _FakeMemory(DIQMemory):
    async def write(self, entry):
        return True

    async def query(self, query):
        return MemoryResult(entries=[], collection=query.collection,
                            query_hash="h", total_chars=0)

    async def can_access(self, agent_id, collection, operation):
        return True


class _FakeSkill(DIQSkill):
    def skill_name(self):
        return "fake"

    def description(self):
        return "x"

    def allowed_agents(self):
        return ["aeris", "zeph"]

    async def run(self, request):
        return SkillResponse(success=True, result=None, skill_name="fake")


class _FakeHA(DIQHA):
    async def call_service(self, command):
        return HAResponse(success=True, entity_id=command.entity_id)

    async def get_state(self, query):
        return HAResponse(success=True, entity_id=query.entity_id, state="on")

    async def list_entities(self, domain=None):
        return []

    async def is_available(self, entity_id):
        return True


class TestAbcCompleteness:
    @pytest.mark.parametrize("cls", [
        _FakeA2A, _FakeCortex, _FakeMemory, _FakeSkill, _FakeHA,
    ])
    def test_can_instantiate_when_abstract_methods_implemented(self, cls):
        # If the ABC contract grows a new method, this will fail until
        # the fake is updated — a regression signal for the frozen API.
        cls()

    def test_partial_implementation_fails(self):
        class Incomplete(DIQA2AChannel):
            async def send(self, message):
                return True
            # receive / receive_all / broadcast missing.

        with pytest.raises(TypeError):
            Incomplete()
