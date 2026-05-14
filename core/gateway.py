"""
core/gateway.py — DIQ-Aware Tool Routing Gateway
==================================================
Phase 2.3: Single dispatch point for all tool calls.

This module imports ONLY from core/diq/. It knows nothing about tools/approved/
or any specific implementation. The DIQ registry provides everything.

Usage (from tool_registry.py handler):
    from core.gateway import dispatch_tool
    result = await dispatch_tool(tool_name, params, agent_id, agent_role)

If no DIQ wrapper exists for the tool, returns None → caller falls back to run_fn.
"""

import logging
from typing import Any, Dict, Optional

from core.diq.diq_registry import get_tool
from core.diq.diq_tools import ToolRequest, ToolResponse

logger = logging.getLogger("gateway")


async def dispatch_tool(
    tool_name: str,
    params: Dict[str, Any],
    agent_id: str = "system",
    agent_role: str = "READ",
    conversation_id: Optional[str] = None,
) -> Optional[ToolResponse]:
    """
    Route a tool call through the DIQ registry.

    Returns:
        ToolResponse if a DIQ wrapper exists for tool_name.
        None if no DIQ wrapper exists (caller should fall back to direct run_fn).
    """
    tool = get_tool(tool_name)
    if tool is None:
        return None  # No DIQ wrapper — fall back to plugin run_fn

    request = ToolRequest(
        tool_name=tool_name,
        agent_id=agent_id,
        agent_role=agent_role,
        parameters=params,
        conversation_id=conversation_id,
    )

    # Role enforcement — DIQ contract check
    if not tool.validate_access(request):
        logger.warning(
            "[gateway] DENIED: agent=%s role=%s tried %s (requires %s)",
            agent_id, agent_role, tool_name, tool.required_role(),
        )
        return ToolResponse(
            success=False,
            result=None,
            error=f"Access denied: {tool_name} requires role {tool.required_role()}, agent {agent_id} has {agent_role}",
        )

    # Allowlist enforcement — defense-in-depth (agent must be explicitly listed)
    # Only enforced for named agents; "system" and internal callers bypass.
    if agent_id not in ("system", "internal", "test"):
        try:
            from core.security.tool_allowlists import is_tool_allowed
            if not is_tool_allowed(agent_id, tool_name):
                return ToolResponse(
                    success=False,
                    result=None,
                    error=f"Tool '{tool_name}' not in allowlist for agent '{agent_id}'",
                )
        except Exception as _al_err:
            # Fail closed: an allowlist subsystem failure must not be a
            # free pass. Better to deny a legitimate call than to grant
            # an unauthorised one.
            logger.error("[gateway] allowlist check failed for %s/%s: %s — DENYING",
                         agent_id, tool_name, _al_err)
            return ToolResponse(
                success=False,
                result=None,
                error=f"Allowlist unavailable, denying: {_al_err}",
            )

    logger.debug("[gateway] dispatch: agent=%s tool=%s", agent_id, tool_name)
    return await tool.execute(request)
