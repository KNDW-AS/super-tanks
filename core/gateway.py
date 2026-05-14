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

Every dispatch — allowed or denied — is recorded in
`core.security.dispatch_audit` with a per-call correlation_id. The
correlation_id is also published via a ContextVar so downstream
audit/event writers (memory_audit.log_access, trust_score.record_event,
ApprovalStore) can attach the same ID to their rows. `grep <id>`
across the four DBs reconstructs the full incident timeline.

If no DIQ wrapper exists for the tool, returns None → caller falls
back to run_fn.
"""

import logging
from typing import Any, Dict, Optional

from core.diq.diq_registry import get_tool
from core.diq.diq_tools import ToolRequest, ToolResponse, _gateway_active
from core.security.dispatch_audit import (
    current_correlation_id,
    new_correlation_id,
    record_dispatch,
)

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

    Side effects:
        Writes one row to `data/dispatch_audit.db` per call (allowed
        or denied), tagged with a fresh correlation_id. Sets the
        `current_correlation_id` ContextVar for the duration of the
        dispatch so downstream writers can reference it.
    """
    corr_id = new_correlation_id()
    corr_token = current_correlation_id.set(corr_id)
    try:
        return await _dispatch_inner(
            tool_name=tool_name,
            params=params,
            agent_id=agent_id,
            agent_role=agent_role,
            identity_token=identity_token,
            conversation_id=conversation_id,
            corr_id=corr_id,
        )
    finally:
        current_correlation_id.reset(corr_token)


async def _dispatch_inner(
    *,
    tool_name: str,
    params: Dict[str, Any],
    agent_id: str,
    agent_role: str,
    identity_token: Optional[str],
    conversation_id: Optional[str],
    corr_id: str,
) -> Optional[ToolResponse]:
    """Actual dispatch logic, factored so the correlation_id wrap stays small."""
    # Identity verification BEFORE the DIQ lookup so we don't leak the
    # registered tool surface to unauthenticated callers.
    from core.security.agent_identity import verify_identity
    if not verify_identity(agent_id, identity_token):
        logger.warning(
            "[gateway] DENIED unauthenticated dispatch: agent=%r tool=%r corr=%s",
            agent_id, tool_name, corr_id,
        )
        resp = ToolResponse(
            success=False,
            result=None,
            error="Identity verification failed",
        )
        record_dispatch(
            correlation_id=corr_id, agent_id=agent_id, tool_name=tool_name,
            agent_role=agent_role, verdict="denied_identity",
            result_success=False, error=resp.error,
        )
        return resp

    tool = get_tool(tool_name)
    if tool is None:
        # Tool not registered. Not strictly an audit event — the caller
        # falls back to a non-DIQ run_fn. But we record it as an
        # "allowed" no-op so the dispatch history is complete.
        record_dispatch(
            correlation_id=corr_id, agent_id=agent_id, tool_name=tool_name,
            agent_role=agent_role, verdict="no_wrapper",
            result_success=None, error=None,
        )
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
            "[gateway] DENIED: agent=%s role=%s tried %s (requires %s) corr=%s",
            agent_id, agent_role, tool_name, tool.required_role(), corr_id,
        )
        resp = ToolResponse(
            success=False,
            result=None,
            error=f"Access denied: {tool_name} requires role {tool.required_role()}, agent {agent_id} has {agent_role}",
        )
        record_dispatch(
            correlation_id=corr_id, agent_id=agent_id, tool_name=tool_name,
            agent_role=agent_role, verdict="denied_role",
            result_success=False, error=resp.error,
        )
        return resp

    # Allowlist enforcement — defense-in-depth.
    if agent_id not in ("system", "internal", "test"):
        try:
            from core.security.tool_allowlists import is_tool_allowed
            if not is_tool_allowed(agent_id, tool_name):
                resp = ToolResponse(
                    success=False,
                    result=None,
                    error=f"Tool '{tool_name}' not in allowlist for agent '{agent_id}'",
                )
                record_dispatch(
                    correlation_id=corr_id, agent_id=agent_id,
                    tool_name=tool_name, agent_role=agent_role,
                    verdict="denied_allowlist",
                    result_success=False, error=resp.error,
                )
                return resp
        except Exception as _al_err:
            # Fail closed: an allowlist subsystem failure must not be a
            # free pass.
            logger.error("[gateway] allowlist check failed for %s/%s: %s corr=%s — DENYING",
                         agent_id, tool_name, _al_err, corr_id)
            resp = ToolResponse(
                success=False,
                result=None,
                error=f"Allowlist unavailable, denying: {_al_err}",
            )
            record_dispatch(
                correlation_id=corr_id, agent_id=agent_id,
                tool_name=tool_name, agent_role=agent_role,
                verdict="denied_subsystem",
                result_success=False, error=resp.error,
            )
            return resp

    logger.debug("[gateway] dispatch: agent=%s tool=%s corr=%s",
                 agent_id, tool_name, corr_id)
    # Mark this dispatch as gateway-originated so DIQTool.execute()
    # accepts it. The ContextVar is per-task, so concurrent dispatches
    # don't pollute each other.
    token = _gateway_active.set(True)
    try:
        resp = await tool.execute(request)
    finally:
        _gateway_active.reset(token)
    record_dispatch(
        correlation_id=corr_id, agent_id=agent_id, tool_name=tool_name,
        agent_role=agent_role, verdict="allowed",
        result_success=resp.success if resp else None,
        error=resp.error if resp else None,
    )
    return resp
