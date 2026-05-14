"""
DIQ Tool Contract — DO NOT MODIFY
Version: 1.1

All tools must implement this interface to register with the gateway.
The gateway calls ONLY these methods. Tools implement them.
New tools plug in behind this contract — this file never changes.

v1.1 (architectural review fix): execute() is now a final concrete
method on the base class that refuses dispatches not routed through
the gateway. Subclasses implement `_execute_impl()` instead. The
previous design left `execute()` abstract — any code holding a tool
instance could call `.execute(request)` directly and bypass the
gateway's role + allowlist + audit checks entirely.
"""

import contextvars
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional

_logger = logging.getLogger("diq.contract")

# Set by core.gateway.dispatch_tool around its `tool.execute(request)`
# call. Any execute() invocation outside this context is rejected.
_gateway_active: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "diq_gateway_active", default=False,
)


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
      2. Implement this interface (note: implement `_execute_impl`,
         NOT `execute` — overriding `execute` is rejected).
      3. Register it in diq_registry.py
      4. DONE — no other files need to change
    """

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        # Refuse subclasses that override execute(). The base class is
        # the gateway-enforced chokepoint; bypassing it via subclass
        # override is exactly the architectural hole this contract
        # exists to close.
        if "execute" in cls.__dict__:
            raise TypeError(
                f"DIQTool subclass {cls.__name__} overrides execute(). "
                f"Implement _execute_impl() instead. The gateway is the "
                f"only legitimate entry point — overriding execute() "
                f"would bypass role + allowlist + audit checks."
            )

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
    async def _execute_impl(self, request: ToolRequest) -> ToolResponse:
        """Subclass entry point. Called by execute() when gateway is active."""
        ...

    async def execute(self, request: ToolRequest) -> ToolResponse:
        """Final entry point. Refuses dispatches outside the gateway.

        core.gateway.dispatch_tool sets the `_gateway_active` ContextVar
        before calling this. Any other caller — a tool that imports
        another tool, a script that instantiates MemoryStore directly,
        a prompt-injected agent that constructs and calls a tool —
        gets a ToolResponse(success=False) back with a "bypass attempt"
        error, and the actual tool logic never runs.
        """
        if not _gateway_active.get():
            _logger.error(
                "DIQTool.%s.execute() called outside the gateway "
                "(agent_id=%r tool=%r). Refusing dispatch.",
                type(self).__name__, request.agent_id, request.tool_name,
            )
            return ToolResponse(
                success=False,
                result=None,
                error=(
                    "Gateway-bypass attempt: tools must be invoked via "
                    "core.gateway.dispatch_tool, not directly."
                ),
            )
        return await self._execute_impl(request)

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
