"""
core/gateway.py — DIQ-Aware Tool Routing Gateway
==================================================
Single dispatch point for all tool calls.

This module imports ONLY from core/diq/ and core/security/. It knows
nothing about tools/approved/ or any specific implementation. The DIQ
registry provides everything.

Usage (from tool_registry.py handler):
    from core.gateway import dispatch_tool
    from core.security.agent_identity import issue_identity

    token = issue_identity("aeris")  # issued at agent process spawn
    result = await dispatch_tool(
        tool_name, params, "aeris", "READ", identity_token=token,
    )

The identity_token is verified against an HMAC signature the agent
process cannot forge. Without it, the gateway refuses to dispatch
even for the privileged "system" / "internal" / "test" identifiers —
those still need a real token, issued by a trusted in-process caller.

If no DIQ wrapper exists for the tool, returns None → caller falls
back to run_fn.
"""

import logging
from typing import Any, Dict, Optional

from core.diq.diq_registry import get_tool
from core.diq.diq_tools import ToolRequest, ToolResponse

logger = logging.getLogger("gateway")


async def dispatch_tool(
    tool_name: str,
    params: Dict[str, Any],
    agent_id: str,
    agent_role: str = "READ",
    *,
    identity_token: Optional[str] = None,
    conversation_id: Optional[str] = None,
) -> Optional[ToolResponse]:
    """
    Route a tool call through the DIQ registry.

    Args:
        tool_name: Registered tool name.
        params: Tool parameters.
        agent_id: Claimed agent identity.
        agent_role: Minimum role the caller asserts.
        identity_token: HMAC signature of agent_id, produced by
            `core.security.agent_identity.issue_identity(agent_id)`.
            Required — no anonymous dispatch.
        conversation_id: Optional tracing context.

    Returns:
        ToolResponse if a DIQ wrapper exists for tool_name (success or
        failure). None if no wrapper exists — caller should fall back
        to the plugin run_fn.
    """
    # Identity verification BEFORE the DIQ lookup so we don't leak the
    # registered tool surface to unauthenticated callers.
    from core.security.agent_identity import verify_identity
    if not verify_identity(agent_id, identity_token):
        logger.warning(
            "[gateway] DENIED unauthenticated dispatch: agent=%r tool=%r",
            agent_id, tool_name,
        )
        return ToolResponse(
            success=False,
            result=None,
            error="Identity verification failed",
        )

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

    # Allowlist enforcement — defense-in-depth. Named agents must be in
    # the explicit allowlist. The synthetic "system" / "internal" / "test"
    # identifiers still need a valid identity_token (verified above), so
    # they're no longer free passes, but they don't have entries in the
    # per-agent allowlist either.
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
            # free pass.
            logger.error("[gateway] allowlist check failed for %s/%s: %s — DENYING",
                         agent_id, tool_name, _al_err)
            return ToolResponse(
                success=False,
                result=None,
                error=f"Allowlist unavailable, denying: {_al_err}",
            )

    logger.debug("[gateway] dispatch: agent=%s tool=%s", agent_id, tool_name)
    return await tool.execute(request)
