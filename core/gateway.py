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
correlation_id is also published via a ContextVar for the duration of
the dispatch. Today the only other writer that reads it is
`core.memory.audit_log.log_access`, so memory rows written during a
tool call carry the same id; trust events and approval requests do not
(yet) record it.

If no DIQ wrapper exists for the tool, returns None → caller falls
back to run_fn.

Check order (see docs/RUNTIME_PIPELINE.md): identity → registry lookup
→ role → allowlist → allowed_agents (L10) → circuit-breaker pre-check
(L7) → tool zone / GO-Gate (L8) → MCP server trust (L9) → circuit-breaker
record (L7) → execute → output injection scan. Every check fails closed;
agent_role is asserted by the caller, not verified.
"""

import asyncio
import logging
from typing import Any, Dict, Optional

from core.diq.diq_registry import get_tool
from core.diq.diq_tools import (
    ToolRequest,
    ToolResponse,
    mark_gateway_active,
    reset_gateway_active,
)
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
    except Exception as err:
        # Last-resort net: nothing inside the pipeline may escape as an
        # exception without an audit row.
        logger.exception("[gateway] unexpected error corr=%s — DENYING", corr_id)
        error = f"Gateway error, denying: {type(err).__name__}: {err}"
        await asyncio.to_thread(
            record_dispatch, correlation_id=corr_id, agent_id=str(agent_id),
            tool_name=str(tool_name), agent_role=str(agent_role),
            verdict="denied_subsystem", result_success=False, error=error)
        return ToolResponse(success=False, result=None, error=error)
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
    """Actual dispatch logic, factored so the correlation_id wrap stays small.

    SQLite work (audit rows, layer 7-9 state, GO-Gate store) runs in a
    worker thread via asyncio.to_thread so a contended database cannot
    block the event loop for the 15 s busy timeout.
    """
    async def audit(verdict: str, result_success: Optional[bool], error: Optional[str]) -> None:
        await asyncio.to_thread(
            record_dispatch,
            correlation_id=corr_id, agent_id=agent_id, tool_name=tool_name,
            agent_role=agent_role, verdict=verdict,
            result_success=result_success, error=error,
        )

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
        await audit("denied_identity", False, resp.error)
        return resp

    tool = get_tool(tool_name)
    if tool is None:
        # Tool not registered. Not strictly an audit event — the caller
        # falls back to a non-DIQ run_fn. But we record it as an
        # "allowed" no-op so the dispatch history is complete.
        await audit("no_wrapper", None, None)
        return None  # No DIQ wrapper — fall back to plugin run_fn

    request = ToolRequest(
        tool_name=tool_name,
        agent_id=agent_id,
        agent_role=agent_role,
        parameters=params,
        conversation_id=conversation_id,
    )

    # Role enforcement — DIQ contract check. agent_role is asserted by
    # the caller; it is bound only by the identity token and allowlist.
    try:
        role_ok = tool.validate_access(request)
    except Exception as role_err:
        logger.error("[gateway] role check raised for %s/%s: %s corr=%s — DENYING",
                     agent_id, tool_name, role_err, corr_id)
        resp = ToolResponse(success=False, result=None,
                            error=f"Role check unavailable, denying: {role_err}")
        await audit("denied_subsystem", False, resp.error)
        return resp
    if not role_ok:
        logger.warning(
            "[gateway] DENIED: agent=%s role=%s tried %s (requires %s) corr=%s",
            agent_id, agent_role, tool_name, tool.required_role(), corr_id,
        )
        resp = ToolResponse(
            success=False,
            result=None,
            error=f"Access denied: {tool_name} requires role {tool.required_role()}, agent {agent_id} has {agent_role}",
        )
        await audit("denied_role", False, resp.error)
        return resp

    # Allowlist enforcement — defense-in-depth.
    # The reserved agent ids system/internal skip ONLY this check: they
    # are in-process callers with no entry in AGENT_ALLOWLISTS (which is
    # keyed by LLM agent). They still need a valid identity token and
    # still pass role, layers 7-10 and the output scan below.
    if agent_id not in _ALLOWLIST_EXEMPT:
        try:
            from core.security.tool_allowlists import is_tool_allowed
            if not is_tool_allowed(agent_id, tool_name):
                resp = ToolResponse(
                    success=False,
                    result=None,
                    error=f"Tool '{tool_name}' not in allowlist for agent '{agent_id}'",
                )
                await audit("denied_allowlist", False, resp.error)
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
            await audit("denied_subsystem", False, resp.error)
            return resp

    # Layer 10 → layer 7 pre-check (read-only) → 8 → 9 → layer 7 record.
    # The breaker pre-check runs before GO-Gate so a locked-out agent
    # cannot open approval requests; usage is recorded only in the last
    # step, right before execute, so paused or denied calls cost nothing.
    # Each step returns a denial ToolResponse (already audited) or None.
    # Any exception inside a step is a deny (fail closed).
    for layer_name, layer in (
        ("allowed_agents", _check_allowed_agents),
        ("circuit_breaker", _precheck_circuit_breaker),
        ("tool_zone", _check_tool_zone),
        ("mcp_trust", _check_mcp_trust),
        ("circuit_breaker", _record_circuit_breaker),
    ):
        try:
            denial = await asyncio.to_thread(layer, tool, request, corr_id)
        except Exception as layer_err:
            logger.error("[gateway] %s check failed for %s/%s: %s corr=%s — DENYING",
                         layer_name, agent_id, tool_name, layer_err, corr_id)
            denial = await asyncio.to_thread(
                _deny, request, corr_id, "denied_subsystem",
                f"{layer_name} unavailable, denying: {layer_err}")
        if denial is not None:
            return denial

    logger.debug("[gateway] dispatch: agent=%s tool=%s corr=%s",
                 agent_id, tool_name, corr_id)
    # Mark this dispatch as gateway-originated so DIQTool.execute()
    # accepts it. The ContextVar is per-task, so concurrent dispatches
    # don't pollute each other.
    token = mark_gateway_active()
    try:
        resp = await tool.execute(request)
    except Exception as exec_err:
        logger.error("[gateway] tool %s raised: %s corr=%s", tool_name, exec_err, corr_id)
        resp = ToolResponse(success=False, result=None,
                            error=f"Tool raised {type(exec_err).__name__}: {exec_err}")
        await audit("tool_error", False, resp.error)
        return resp
    finally:
        reset_gateway_active(token)
    if not isinstance(resp, ToolResponse):
        resp = ToolResponse(success=False, result=None,
                            error=f"Tool returned {type(resp).__name__}, not ToolResponse")
        await audit("tool_error", False, resp.error)
        return resp

    # R-02: indirect prompt-injection scan on tool output. Web/file/
    # memory content can carry attacker instructions that ride back
    # into the LLM via the agent's next turn. We refuse to forward
    # content that scans as a high-confidence injection.
    resp = _scan_response_for_injection(resp, tool_name, corr_id)

    await audit("allowed", resp.success, resp.error)
    return resp


_ALLOWLIST_EXEMPT = ("system", "internal")


def _deny(request: ToolRequest, corr_id: str, verdict: str, error: str,
          metadata: Optional[Dict[str, Any]] = None) -> ToolResponse:
    """Build a denial, write its audit row, return it."""
    logger.warning("[gateway] %s: agent=%s tool=%s corr=%s — %s",
                   verdict.upper(), request.agent_id, request.tool_name, corr_id, error)
    record_dispatch(
        correlation_id=corr_id, agent_id=request.agent_id,
        tool_name=request.tool_name, agent_role=request.agent_role,
        verdict=verdict, result_success=False, error=error,
    )
    return ToolResponse(success=False, result=None, error=error, metadata=metadata)


def _go_gate(request: ToolRequest, corr_id: str, reason: str,
             deny_verdict: str) -> Optional[ToolResponse]:
    """Route a call through GO-Gate (core.ask_admin). None = approved."""
    from core.ask_admin import gate_tool_call
    outcome, req_id, status = gate_tool_call(
        request.tool_name, request.agent_id, dict(request.parameters), reason)
    if outcome == "approved":
        logger.info("[gateway] GO-Gate approved %s for %s (req=%s) corr=%s",
                    request.tool_name, request.agent_id, req_id, corr_id)
        return None
    if outcome == "pending":
        return _deny(
            request, corr_id, "pending_approval",
            f"Paused for human approval ({reason}); request {req_id}",
            metadata={"approval_request_id": req_id, "go_gate_status": status},
        )
    if outcome == "denied":
        return _deny(request, corr_id, deny_verdict,
                     f"Denied by human approver (request {req_id})",
                     metadata={"approval_request_id": req_id})
    return _deny(request, corr_id, "denied_subsystem",
                 f"GO-Gate approval store unavailable ({status}), denying")


def _check_allowed_agents(tool, request: ToolRequest, corr_id: str) -> Optional[ToolResponse]:
    """Layer 10 — per-tool agent scope. [] means all agents."""
    allowed = tool.allowed_agents()
    if not isinstance(allowed, (list, tuple, set, frozenset)) or not all(
            isinstance(a, str) for a in allowed):
        raise TypeError(f"allowed_agents() must return a list of str, got {allowed!r}")
    if allowed and request.agent_id not in allowed:
        return _deny(request, corr_id, "denied_agent",
                     f"Tool '{request.tool_name}' is not available to agent '{request.agent_id}'")
    return None


def _check_tool_zone(tool, request: ToolRequest, corr_id: str) -> Optional[ToolResponse]:
    """Layer 8 — zone policy: allow / GO-Gate / deny."""
    from core.security.tool_zones import ZoneAction, get_zone, zone_action
    zone = get_zone(request.tool_name)
    action = zone_action(request.tool_name)
    if action is ZoneAction.ALLOW:
        return None
    if action is ZoneAction.DENY:
        return _deny(request, corr_id, "denied_zone",
                     f"Tool '{request.tool_name}' is in zone '{zone.value}', which is denied")
    if action is ZoneAction.GO_GATE:
        return _go_gate(request, corr_id, f"zone '{zone.value}' requires approval",
                        "denied_zone")
    raise ValueError(f"unknown zone action {action!r}")


def _check_mcp_trust(tool, request: ToolRequest, corr_id: str) -> Optional[ToolResponse]:
    """Layer 9 — MCP server trust, only for tools that declare a server."""
    server = tool.mcp_server()
    if server is None:
        return None
    if not isinstance(server, str) or not server:
        raise TypeError(f"mcp_server() must return a non-empty str or None, got {server!r}")
    from core.security.mcp_security import MCPDecision, get_manager
    manager = get_manager()
    decision, reason = manager.evaluate(server, request.tool_name)
    manager.log_invocation(server, request.tool_name, request.agent_id, decision, reason)
    if decision is MCPDecision.ALLOW:
        return None
    if decision is MCPDecision.GO_GATE:
        return _go_gate(request, corr_id, f"MCP server '{server}': {reason}", "denied_mcp")
    return _deny(request, corr_id, "denied_mcp", f"MCP server '{server}' blocked: {reason}")


def _precheck_circuit_breaker(tool, request: ToolRequest, corr_id: str) -> Optional[ToolResponse]:
    """Layer 7 pre-check (before GO-Gate): deny if the agent is locked
    out or this call would exceed its budget. Records no usage."""
    from core.security.circuit_breaker import CircuitBreakerError, get_breaker
    from core.security.tool_zones import risk_weight
    try:
        get_breaker(request.agent_id).check(
            request.tool_name, weight=risk_weight(request.tool_name))
    except CircuitBreakerError as cb_err:
        return _deny(request, corr_id, "denied_circuit_breaker", str(cb_err),
                     metadata={"locked_until": cb_err.locked_until})
    return None


def _record_circuit_breaker(tool, request: ToolRequest, corr_id: str) -> Optional[ToolResponse]:
    """Layer 7, last step before execute: atomic check-and-record. Trips
    the lockout if this call would exceed the budget."""
    from core.security.circuit_breaker import CircuitBreakerError, get_breaker
    from core.security.tool_zones import risk_weight
    try:
        get_breaker(request.agent_id).check_and_record(
            request.tool_name, weight=risk_weight(request.tool_name))
    except CircuitBreakerError as cb_err:
        return _deny(request, corr_id, "denied_circuit_breaker", str(cb_err),
                     metadata={"locked_until": cb_err.locked_until})
    return None


def _extract_text(value) -> str:
    """Flatten any tool result into a single string for scanning."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return ""
    if isinstance(value, dict):
        return " ".join(_extract_text(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return " ".join(_extract_text(v) for v in value)
    return str(value)


def _scan_response_for_injection(
    resp: Optional[ToolResponse],
    tool_name: str,
    corr_id: str,
) -> Optional[ToolResponse]:
    """If the tool returned content that scans as injection, replace
    the result with a refusal. Successful responses only — failures
    don't carry attacker payload to filter.
    """
    if resp is None or not resp.success or resp.result is None:
        return resp
    try:
        # Flattening is inside the try: a result whose __str__ raises is
        # withheld like any other unscannable output.
        text = _extract_text(resp.result)
        if not text or len(text) < 8:
            return resp
        from core.security.zef_injection_filter import scan_message, FilterVerdict
        verdict = scan_message(text, source=f"tool_output:{tool_name}")
        kind, patterns = verdict.verdict, list(verdict.matched_patterns)
        if not isinstance(kind, FilterVerdict):
            raise TypeError(f"scan_message returned verdict {kind!r}")
    except Exception as scan_err:
        # Fail closed: output we could not scan is not forwarded.
        logger.error("[gateway] output scan unavailable for %s: %s corr=%s — withholding",
                     tool_name, scan_err, corr_id)
        return ToolResponse(
            success=False,
            result=None,
            error="Tool output could not be scanned for prompt injection and was withheld.",
            metadata={"output_scan_failed": True},
        )
    if kind is FilterVerdict.BLOCK:
        logger.warning(
            "[gateway] indirect-injection BLOCKED in %s output corr=%s patterns=%s",
            tool_name, corr_id, patterns,
        )
        return ToolResponse(
            success=False,
            result=None,
            error=(
                "Tool output contained likely prompt-injection content "
                "and was redacted before reaching the agent."
            ),
            metadata={
                "indirect_injection": True,
                "matched_patterns": patterns,
                "original_length": len(text),
            },
        )
    if kind is FilterVerdict.WARN:
        # Not definitive enough to drop (dropping a low-confidence hit
        # would cost utility), but this content came from an external
        # tool and tripped a suspicious pattern. Tag it with provenance
        # so the agent loop treats it as untrusted *data*, never as
        # instructions. This closes the WARN-level half of R-02 — the
        # BLOCK branch above only caught high-confidence payloads.
        logger.info(
            "[gateway] tool output from %s flagged untrusted (WARN) corr=%s patterns=%s",
            tool_name, corr_id, patterns,
        )
        merged = dict(resp.metadata or {})
        merged.update({
            "untrusted_content": True,
            "provenance": "external_tool_output",
            "provenance_warnings": patterns,
        })
        return ToolResponse(
            success=resp.success,
            result=resp.result,
            error=resp.error,
            metadata=merged,
        )
    return resp
