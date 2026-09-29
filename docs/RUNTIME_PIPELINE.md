# Runtime pipeline — what happens on a tool call

This document describes what `core.gateway.dispatch_tool` actually does,
in the order it does it, as of v3.3.0. It is written for people who want
to measure or attack the system (for example with AgentDojo), so it
lists the fail-open points as well as the fail-closed ones. If this
document and the code disagree, the code wins — please open an issue.

Source: `core/gateway.py` (`dispatch_tool` → `_dispatch_inner`).
Tests that pin this behaviour: `tests/test_core/test_gateway.py`,
`tests/test_core/test_gateway_layers.py`.

## Dispatch order

```
dispatch_tool(tool_name, params, agent_id, agent_role, identity_token=...)
 │  new correlation_id (ContextVar, joins all audit stores)
 ▼
[1] identity        verify_identity(agent_id, token)        ── fail → denied_identity
 ▼
[2] registry        get_tool(tool_name)                      ── None → no_wrapper, return None
 ▼
[3] role (L3)       tool.validate_access(request)            ── fail → denied_role
 ▼
[4] allowlist (L4)  is_tool_allowed(agent_id, tool_name)     ── fail → denied_allowlist
 │                  (skipped for agent_id system/internal/test)
 ▼
[5] allowed_agents  tool.allowed_agents()  [] = all          ── fail → denied_agent
 │  (L10)
 ▼
[6] tool zone (L8)  zone_action(tool_name)
 │                    ALLOW   → continue
 │                    DENY    → denied_zone
 │                    GO_GATE → gate_tool_call(...)  (L5)
 │                                approved    → continue
 │                                pending     → pending_approval (+ request id)
 │                                human-denied→ denied_zone
 │                                store down  → denied_subsystem
 ▼
[7] MCP trust (L9)  only if tool.mcp_server() is not None
 │                    verified    → continue
 │                    provisional → GO-Gate as in [6]; human-denied → denied_mcp
 │                    quarantined / unknown → denied_mcp
 ▼
[8] circuit breaker get_breaker(agent_id).check_and_record(tool, weight)
 │  (L7)                                                     ── over budget → denied_circuit_breaker
 ▼
[9] execute         tool.execute(request)  (refuses outside the gateway ContextVar)
 ▼
[10] output scan    ZEF on the tool result (L1)
 │                    BLOCK → result replaced by an error (indirect_injection)
 │                    WARN  → result kept, metadata untrusted_content=True
 │                    scan raised → result withheld (output_scan_failed)
 ▼
record_dispatch(verdict="allowed", result_success=...) → return ToolResponse
```

Any exception raised inside checks [5]–[8] is caught by the gateway and
turned into `denied_subsystem` with the layer name in the error. An
exception in [4] is also `denied_subsystem`. Every denial returns
immediately; later checks and the tool do not run. The `ToolRequest` is
frozen and no check modifies it.

## Outcome per check

All denials return `ToolResponse(success=False, result=None, error=...)`
and write one row to `dispatch_log` with the verdict below.

| # | Check | Verdict | `metadata` | Tool executed |
|---|---|---|---|---|
| 1 | identity | `denied_identity` | – | no |
| 2 | registry | `no_wrapper` (returns `None`, not a ToolResponse) | – | no — caller may fall back |
| 3 | role | `denied_role` | – | no |
| 4 | allowlist | `denied_allowlist` / `denied_subsystem` | – | no |
| 5 | allowed_agents | `denied_agent` | – | no |
| 6 | zone DENY | `denied_zone` | – | no |
| 6 | zone GO-Gate, no decision yet | `pending_approval` | `approval_request_id`, `go_gate_status` | no |
| 6 | zone GO-Gate, human denied | `denied_zone` | `approval_request_id` | no |
| 7 | MCP quarantined / unknown | `denied_mcp` | – | no |
| 7 | MCP provisional, pending | `pending_approval` | `approval_request_id`, `go_gate_status` | no |
| 7 | MCP provisional, human denied | `denied_mcp` | `approval_request_id` | no |
| 8 | circuit breaker | `denied_circuit_breaker` | `locked_until` (epoch) | no |
| 5–8 | layer raised / store unavailable | `denied_subsystem` | – | no |
| 10 | output BLOCK | `allowed` (`result_success=0`) | `indirect_injection`, `matched_patterns` | yes, output dropped |
| 10 | output WARN | `allowed` | `untrusted_content`, `provenance`, `provenance_warnings` | yes |
| 10 | output scan failed | `allowed` (`result_success=0`) | `output_scan_failed` | yes, output withheld |

## Fail-open / fail-closed

| Component | On internal error | Notes |
|---|---|---|
| identity | closed | any exception in verification → False |
| allowlist | closed | `denied_subsystem` |
| allowed_agents | closed | a non-list return value is treated as an error |
| tool zone | closed | unknown tool → `UNCATEGORIZED` → GO-Gate |
| GO-Gate store | closed | failed persist → `denied_subsystem` |
| MCP trust | closed | DB error → `denied_subsystem`; unknown server → deny |
| circuit breaker | closed | DB error → `denied_subsystem` (the private predecessor failed open) |
| output scan | closed | import or scan error → output withheld. Regex/normalisation filter only — the Ollama LLM classifier is not used on tool output (it is used on some input channels, where it fails open; see SECURITY.md) |
| **audit write** (`record_dispatch`) | **open** | a failed audit write is logged at ERROR and the dispatch result is still returned. The chain verifier (threat monitor) detects gaps/tampering afterwards, not at dispatch time. |
| **identity key** | **open-ish** | if neither `SUPER_TANKS_IDENTITY_KEY` nor `data/.identity_key` is available and the key file cannot be written, a per-process random key is used; tokens then only work in that process. |
| unregistered tool | n/a | `None` is returned; whatever the caller does next is outside the gateway. |

Callers exempt from a check: `system`, `internal` and `test` skip only
the per-agent allowlist [4]. They still need a valid token and pass
every other check, including [5]–[10].

## State and where it lives

| Store | Default path | Override (tests / harness) |
|---|---|---|
| dispatch audit | `<repo>/data/dispatch_audit.db` | `dispatch_audit.DB_PATH` (+ reset `_initialised`) |
| circuit breaker | `<repo>/data/circuit_breaker.db` | `circuit_breaker.DB_PATH`, then `circuit_breaker.reset_breakers()` |
| MCP trust | `<repo>/data/mcp_security.db` | `mcp_security.DB_PATH` |
| GO-Gate approvals | `data/approval_requests.db` **relative to the current working directory** | `core.ask_admin._approval_store = ApprovalStore(db_path=...)` |
| identity key | `SUPER_TANKS_IDENTITY_KEY` env, else `<repo>/data/.identity_key` | `agent_identity.configure_key(b"...")` |
| audit chain key | `SUPER_TANKS_AUDIT_KEY` env, else `<repo>/data/.audit_chain_key` | see `core/security/audit_key.py` |

## Defaults you will probably want to change

- **Zones** (`core/security/tool_zones.py`): the map covers this
  repository's tool names. Your own tools are `UNCATEGORIZED` until you
  map them, which means every call pauses for GO-Gate. Map them at
  startup:

  ```python
  from core.security.tool_zones import Zone, ZoneAction, set_tool_zone, set_zone_action
  set_tool_zone("get_balance", Zone.FILESYSTEM_RO)       # ALLOW
  set_tool_zone("send_money", Zone.NETWORK_WRITE)        # GO_GATE
  set_zone_action(Zone.EXEC, ZoneAction.DENY)            # tighten a whole zone
  ```

  Default actions: `filesystem_ro`, `network_read`, `smarthouse`,
  `agent_comms` → ALLOW; `filesystem_rw`, `network_write`, `exec`,
  `admin`, `uncategorized` → GO_GATE. No zone is DENY by default.
- **Circuit breaker**: 30 weighted units per 60 s per agent, 300 s
  lockout. Weights: 1.0 for read/device/comms zones, 1.5 `filesystem_rw`,
  2.0 `network_write`, 3.0 `exec`/`admin`, 5.0 `uncategorized`. Only
  calls that reach check [8] count (paused and denied calls do not).
  A benchmark run will trip this; raise it explicitly:

  ```python
  from core.security import circuit_breaker as cb
  cb.CircuitBreaker.DEFAULT_MAX_ACTIONS = 10_000
  cb.reset_breakers()
  ```
- **GO-Gate reuse window**: an approval covers the identical call (same
  tool, agent and SHA-256 of `json.dumps(params, sort_keys=True)`) for
  one hour; a human deny blocks the identical call for one hour. A
  different argument is a different call. Pending requests expire after
  300 s; an expired request cannot be approved, and the next identical
  call opens a new one. `params` must be JSON-serialisable for gated
  tools, otherwise the call is `denied_subsystem`.

## Public integration APIs

### `dispatch_tool`

```python
async def dispatch_tool(
    tool_name: str,
    params: Dict[str, Any],
    agent_id: str,
    agent_role: str = "READ",          # READ < CHAT < WRITE < EXEC < ADMIN
    *,
    identity_token: Optional[str] = None,   # required; no anonymous dispatch
    conversation_id: Optional[str] = None,
) -> Optional[ToolResponse]
```

`ToolResponse(success: bool, result: Any, error: Optional[str], metadata: Optional[dict])`
is frozen. `None` means "no DIQ tool with that name".

### Registering a tool

```python
from core.diq.diq_tools import DIQTool, ToolRequest, ToolResponse
from core.diq.diq_registry import register_tool

class SendMoney(DIQTool):
    def name(self): return "send_money"
    def description(self): return "Transfer money"
    def parameters_schema(self): return {"type": "object", "properties": {"to": {"type": "string"}}}
    def required_role(self): return "WRITE"
    def allowed_agents(self): return ["banking_agent"]   # optional; [] (default) = all
    def mcp_server(self): return None                    # optional; set if MCP-backed
    async def _execute_impl(self, request: ToolRequest) -> ToolResponse:
        return ToolResponse(success=True, result=f"sent to {request.parameters['to']}")

register_tool(SendMoney())
```

Implement `_execute_impl`, never `execute` (overriding `execute` raises
`TypeError` at class definition). The agent must also be in
`core.security.tool_allowlists.AGENT_ALLOWLISTS` (unknown agents are
denied) unless it uses one of the exempt ids.

`DIQTool` is a frozen contract. After upgrading run
`python -m supertanks seal` so `core.bootstrap.boot()` accepts the new
checksum.

### Identity

```python
from core.security.agent_identity import issue_identity, configure_key
configure_key(b"experiment-key")          # tests / harness; production: env var or key file
token = issue_identity("banking_agent")   # pass as identity_token=
```

### GO-Gate in tests (from `scripts/demo_go_gate.py`)

```python
import tempfile, pathlib
import core.ask_admin as ask_admin
from core.ask_admin import ApprovalStore

ask_admin._approval_store = ApprovalStore(
    db_path=str(pathlib.Path(tempfile.mkdtemp()) / "approvals.db"))

resp = await dispatch_tool("send_money", {"to": "x"}, "banking_agent", "WRITE", identity_token=token)
req_id = resp.metadata["approval_request_id"]          # verdict pending_approval
ask_admin.get_approval_store().approve_request(req_id, admin_id="human")   # or deny_request
resp = await dispatch_tool("send_money", {"to": "x"}, "banking_agent", "WRITE", identity_token=token)
```

There is no blocking wait inside the gateway: a paused call returns
immediately and the caller retries after the decision. In the private
deployment the decision comes from a Telegram bot; in an experiment your
harness plays the human (approve all, deny all, or a policy).

### Provider trust (L11) and failover (L12)

These act on LLM calls, not tool calls, and are not part of
`dispatch_tool`.

```python
from core.security.provider_trust import get_tier, strip_context_for_tier
tier = get_tier("some-provider")            # unknown → 4 (OPEN)
safe_prompt = strip_context_for_tier(prompt, tier)

from core.security.provider_failover import check_failover, on_provider_error
r = check_failover("agent", "local-model", "cloud-model")   # lower tier → GO-Gate
if not r.approved and r.queued: ...                          # do not send
```

Tiers and fallback chains come from `config/providers.yaml`. The
failover GO-Gate *does* block and poll the `ApprovalStore` until
approved, denied or timed out (`downgrade_approval_timeout_s`).

### Wrapping AgentDojo's tool execution (sketch)

AgentDojo runs tools through a `ToolsExecutor` pipeline element that
calls `FunctionsRuntime.run_function(env, name, args)`. To put Super
Tanks in that path, route each call through `dispatch_tool` with a
DIQ adapter whose `_execute_impl` calls the real function. Check the
names below against your installed AgentDojo version; the Super Tanks
side is exact.

```python
import asyncio, contextvars
from core.gateway import dispatch_tool
from core.diq.diq_tools import DIQTool, ToolResponse
from core.diq.diq_registry import register_tool
from core.security.agent_identity import issue_identity
from core.security.tool_allowlists import AGENT_ALLOWLISTS

_episode = contextvars.ContextVar("episode")      # (runtime, env) for the current task

class AgentDojoTool(DIQTool):
    def __init__(self, fn_name, role="READ"):
        self._n, self._role = fn_name, role
    def name(self): return self._n
    def description(self): return self._n
    def parameters_schema(self): return {}
    def required_role(self): return self._role
    async def _execute_impl(self, request):
        runtime, env = _episode.get()
        result, error = runtime.run_function(env, request.tool_name, dict(request.parameters))
        return ToolResponse(success=error is None, result=result, error=error)

AGENT = "agentdojo"
def setup(function_names):
    for fn in function_names:
        register_tool(AgentDojoTool(fn))
        # map each fn with set_tool_zone(...) — this mapping IS your policy
    AGENT_ALLOWLISTS[AGENT] = list(function_names)
    return issue_identity(AGENT)

def guarded_run_function(runtime, env, name, args, token):
    """Call this where ToolsExecutor would call runtime.run_function."""
    ctx = _episode.set((runtime, env))
    try:
        resp = asyncio.run(dispatch_tool(name, args, AGENT, "READ", identity_token=token))
    finally:
        _episode.reset(ctx)
    if resp is None:
        return "", f"unknown tool {name}"
    if not resp.success:
        return "", resp.error        # shown to the model as a tool error
    return resp.result, None
```

Things to decide and report in any evaluation:

- the zone map for the suite's tools and how GO-Gate is resolved
  (auto-approve measures the other layers only; auto-deny measures
  utility loss);
- the circuit-breaker budget (raise it, or it will trip);
- whether you count `untrusted_content` WARN tags as a defence (the
  gateway only tags them; acting on the tag is the agent loop's job,
  which is not in this repository);
- `asyncio.run` cannot be called from a running event loop — inside
  async code, `await dispatch_tool(...)` directly.
