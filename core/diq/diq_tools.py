"""
DIQ Tool Contract — DO NOT MODIFY
Version: 1.0

All tools must implement this interface to register with the gateway.
The gateway calls ONLY these methods. Tools implement them.
New tools plug in behind this contract — this file never changes.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional

_logger = logging.getLogger("diq.contract")


@dataclass(frozen=True)
class ToolRequest:
    """Immutable request object passed to every tool."""
    tool_name: str
    agent_id: str           # "aeris" or "zeph"
    agent_role: str         # READ, CHAT, WRITE, EXEC, ADMIN
    parameters: Dict[str, Any]
    conversation_id: Optional[str] = None


@dataclass(frozen=True)
class ToolResponse:
    """Immutable response object returned by every tool."""
    success: bool
    result: Any
    error: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class DIQTool(ABC):
    """
    Base contract for ALL tools in AerisProject.

    To add a new tool:
      1. Create your tool file in tools/
      2. Implement this interface
      3. Register it in diq_registry.py
      4. DONE — no other files need to change
    """

    @abstractmethod
    def name(self) -> str:
        """Unique tool name. Used for routing."""
        ...

    @abstractmethod
    def description(self) -> str:
        """Tool description for LLM function calling."""
        ...

    @abstractmethod
    def parameters_schema(self) -> Dict[str, Any]:
        """JSON Schema for tool parameters."""
        ...

    @abstractmethod
    def required_role(self) -> str:
        """Minimum agent role needed: READ, CHAT, WRITE, EXEC, ADMIN."""
        ...

    @abstractmethod
    async def execute(self, request: ToolRequest) -> ToolResponse:
        """Execute the tool. Receives ToolRequest, returns ToolResponse."""
        ...

    def validate_access(self, request: ToolRequest) -> bool:
        """
        Default access check against agent role hierarchy.
        Override for custom permission logic.
        """
        role_hierarchy = ["READ", "CHAT", "WRITE", "EXEC", "ADMIN"]
        agent_level = (
            role_hierarchy.index(request.agent_role)
            if request.agent_role in role_hierarchy
            else -1
        )
        required = self.required_role()
        if required not in role_hierarchy:
            # An unknown required_role makes the tool uncallable for
            # everyone — silently. Surface this loudly so the broken
            # contract is fixed instead of being mistaken for working.
            _logger.critical(
                "DIQ contract violation: %s.required_role() = %r is not in %s",
                type(self).__name__, required, role_hierarchy,
            )
            return False
        required_level = role_hierarchy.index(required)
        return agent_level >= required_level
