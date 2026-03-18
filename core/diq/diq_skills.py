"""
DIQ Skills Contract — DO NOT MODIFY
Version: 1.0

Skills execution contract.
Skills live in skills/ — they implement this interface and register in diq_registry.py.
The gateway never imports skills directly — this file never changes.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class SkillRequest:
    """Immutable skill execution request."""
    skill_name: str
    agent_id: str           # "aeris" or "zeph"
    parameters: Dict[str, Any]
    caller_context: Optional[str] = None


@dataclass(frozen=True)
class SkillResponse:
    """Immutable skill execution response."""
    success: bool
    result: Any
    skill_name: str
    error: Optional[str] = None
    side_effects: List[str] = field(default_factory=list)  # human-readable log of what changed


class DIQSkill(ABC):
    """
    Base contract for ALL skills in AerisProject.

    Skills differ from tools:
    - Tools are exposed to the LLM via function calling
    - Skills are internal helpers (parsers, calculators, integrations)
      that tools and the gateway call directly

    To add a new skill:
      1. Create skills/<name>.py implementing DIQSkill
      2. Register in diq_registry.py
      3. DONE
    """

    @abstractmethod
    def skill_name(self) -> str:
        """Unique skill name."""
        ...

    @abstractmethod
    def description(self) -> str:
        """Human-readable description."""
        ...

    @abstractmethod
    def allowed_agents(self) -> List[str]:
        """Which agents may invoke this skill. [] means all."""
        ...

    @abstractmethod
    async def run(self, request: SkillRequest) -> SkillResponse:
        """Execute the skill."""
        ...
