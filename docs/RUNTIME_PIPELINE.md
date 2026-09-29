# Runtime pipeline — what happens on a tool call

This document describes what `core.gateway.dispatch_tool` does, in the
order it does it, as of v3.3.0. It is written for people who want to
measure or attack the system (for example with AgentDojo), so it lists
the fail-open points as well as the fail-closed ones. If this document
and the code disagree, the code wins — please open an issue.

Source: `core/gateway.py` (`dispatch_tool` → `_dispatch_inner`).
Tests that pin this behaviour: `tests/test_core/test_gateway.py`,
`tests/test_core/test_gateway_layers.py`. Every `python` block below is
executed by `tests/test_docs/test_runtime_pipeline_snippets.py` (the
AgentDojo block only when `agentdojo` is installed).

## Dispatch order

```text
dispatch_tool(tool_name, params, agent_id, agent_role, identity_token=...)
 │  new correlation_id (ContextVar, joins all audit stores)
 ▼
[1] identity         verify_identity(agent_id, token)           fail → denied_identity
 ▼
[2] registry         get_tool(tool_name)                        None → no_wrapper, return None
 ▼
[3] role (L3)        tool.validate_access(request)              fail → denied_role
 │                   (agent_role is asserted by the caller)      raised → denied_subsystem
 ▼
[4] allowlist (L4)   is_tool_allowed(agent_id, tool_name)       fail → denied_allowlist
 │                   (skipped for agent_id "system"/"internal")
 ▼
[5] allowed_agents   tool.allowed_agents()   [] = all           fail → denied_agent
 │  (L10)
 ▼
[6] breaker (L7)     get_breaker(agent).check(tool, weight)     locked / over budget
 │   pre-check       records no usage                            → denied_circuit_breaker
 ▼
[7] tool zone (L8)   zone_action(tool_name)
 │                     ALLOW   → continue
 │                     DENY    → denied_zone
 │                     GO_GATE → gate_tool_call(...)  (L5)
 │                                 approved      → continue
 │                                 pending       → pending_approval (+ request id)
 │                                 human-denied  → denied_zone
 │                                 store down    → denied_subsystem
 ▼
[8] MCP trust (L9)   only if tool.mcp_server() is not None
 │                     verified    → continue
 │                     provisional → GO-Gate as in [7]; human-denied → denied_mcp
 │                     quarantined / unknown → denied_mcp
 ▼
[9] breaker (L7)     check_and_record(tool, weight)             over budget → denied_circuit_breaker
 │   record          (atomic; only calls that reach here count)
 ▼
[10] execute         tool.execute(request)                      raised / wrong type → tool_error
 ▼
[11] output scan     ZEF regex filter on the result (L1)
 │                     BLOCK → result replaced by an error (indirect_injection)
 │                     WARN  → result kept, metadata untrusted_content=True
 │                     scan raised / bad verdict → result withheld (output_scan_failed)
 ▼
record_dispatch(verdict="allowed", result_success=...) → return ToolResponse
```

- Steps [5]–[9] run in a worker thread (`asyncio.to_thread`), as do
  all audit writes, so a busy SQLite database does not block the event
  loop. The tool itself ([10]) runs on the event loop: a tool that
  blocks, blocks the loop.
- Any exception inside [5]–[9] becomes `denied_subsystem` with the
  step name in the error. Any exception anywhere else in the pipeline
  is caught by `dispatch_tool` and also recorded as `denied_subsystem`.
  No exception escapes `dispatch_tool`.
- Every denial returns immediately; later steps and the tool do not
  run. `ToolRequest` is frozen and no step modifies it.

## Outcome per step

All denials return `ToolResponse(success=False, result=None, error=...)`
and write one row to `dispatch_log` with the verdict below.

| Step | Case | Verdict | `metadata` | Tool executed |
|---|---|---|---|---|
| 1 | bad / missing token | `denied_identity` | – | no |
| 2 | tool not registered | `no_wrapper` (returns `None`) | – | no — caller may fall back |
| 3 | role too low | `denied_role` | – | no |
| 3 | `validate_access` raised | `denied_subsystem` | – | no |
| 4 | not on allowlist / allowlist raised | `denied_allowlist` / `denied_subsystem` | – | no |
| 5 | agent not in `allowed_agents()` | `denied_agent` | – | no |
| 6, 9 | locked out or over budget | `denied_circuit_breaker` | `locked_until` (epoch) | no |
| 7 | zone DENY | `denied_zone` | – | no |
| 7, 8 | GO-Gate, no decision yet | `pending_approval` | `approval_request_id`, `go_gate_status` | no |
| 7 | GO-Gate, human denied | `denied_zone` | `approval_request_id` | no |
| 8 | MCP quarantined / unknown | `denied_mcp` | – | no |
| 8 | MCP provisional, human denied | `denied_mcp` | `approval_request_id` | no |
| 5–9 | step raised / store unavailable | `denied_subsystem` | – | no |
| 10 | tool raised or returned a non-`ToolResponse` | `tool_error` | – | started, failed |
| 11 | output BLOCK | `allowed` (`result_success=0`) | `indirect_injection`, `matched_patterns` | yes, output dropped |
| 11 | output WARN | `allowed` | `untrusted_content`, `provenance`, `provenance_warnings` | yes |
| 11 | output scan failed | `allowed` (`result_success=0`) | `output_scan_failed` | yes, output withheld |

## Fail-open / fail-closed

| Component | On internal error | Notes |
|---|---|---|
| identity | closed | any exception in verification → False |
| role check | closed | `denied_subsystem` |
| allowlist | closed | `denied_subsystem` |
| allowed_agents | closed | a non-list return value is treated as an error |
| circuit breaker | closed | DB error → `denied_subsystem` |
| tool zone | closed | unknown tool → `UNCATEGORIZED` → GO-Gate |
| GO-Gate store | closed | failed persist → `denied_subsystem` |
| MCP trust | closed | DB error → `denied_subsystem`; unknown server → deny |
| tool execution | closed | exception → `tool_error` |
| output scan | closed | import error, exception or unexpected verdict → output withheld. Regex/normalisation filter only; the Ollama LLM classifier is not used on tool output (it is used on some input channels, where it fails open — see SECURITY.md) |
| **audit write** (`record_dispatch`) | **open** | a failed audit write is logged at ERROR and the dispatch result is still returned. The chain verifier (threat monitor) detects missing or altered rows afterwards, not at dispatch time. |
| **identity key** | **open-ish** | if neither `SUPER_TANKS_IDENTITY_KEY` nor `data/.identity_key` is available and the key file cannot be written, a per-process random key is used; tokens then only work in that process. |
| unregistered tool | n/a | `None` is returned; whatever the caller does next is outside the gateway. |

## Things the gateway does not do

- **It does not verify `agent_role`.** The role is asserted by the
  caller and bound only by the identity token (who is calling) and the
  allowlist (which tools that agent may call). An agent with a valid
  token can claim `ADMIN` for any tool on its allowlist.
- **Exempt callers.** `system` and `internal` skip only the allowlist
  [4]; they still need a valid token and pass every other step. No other
  id is exempt (`test` was exempt before v3.3.0).
- **It does not resume paused calls.** After a human approves, the
  caller must re-issue the identical call (same tool, agent and
  arguments). The approval covers that call for 1 hour; a human deny
  blocks it for 1 hour. A different argument is a different call and
  asks again. Pending requests expire after 300 s; an expired request
  cannot be approved, and the next identical call opens a new one.
- **One approval, both gates.** If a tool is in a GO-Gate zone *and*
  backed by a provisional MCP server, one approval covers both, because
  both gates use the same key (tool + agent + argument hash).
- **It does not consult the mode controller or the trust score**
  (`super_tanks_mode.py`, `trust_score.py`). Those are used by memory
  access control, code quarantine and the agent loop (not in this
  repository).
- **The chokepoint guards `execute()` only.** In-process code can call
  a tool's `_execute_impl()` directly, or set the gateway ContextVar
  with `mark_gateway_active()`. The guard stops accidental and
  prompt-constructed bypasses, not deliberately written code in the
  same process.
- **Skills are not dispatched here.** `DIQSkill.allowed_agents()` has
  the same "[] = all" rule as `DIQTool.allowed_agents()`, but skills do
  not pass through the gateway and this repository has no skill
  dispatch path, so it is not enforced.
- `params` must be JSON-serialisable for gated tools (the approval key
  is a hash of `json.dumps(params, sort_keys=True)`); otherwise the call
  is `denied_subsystem`.

## State and where it lives

| Store | Default path | Override |
|---|---|---|
| dispatch audit | `<repo>/data/dispatch_audit.db` | `dispatch_audit.DB_PATH` (+ reset `_initialised`) |
| circuit breaker | `<repo>/data/circuit_breaker.db` | `circuit_breaker.DB_PATH`, then `circuit_breaker.reset_breakers()` |
| MCP trust | `<repo>/data/mcp_security.db` | `mcp_security.DB_PATH` |
| GO-Gate approvals | `<repo>/data/approval_requests.db` | `SUPER_TANKS_APPROVAL_DB` env, or `core.ask_admin._approval_store = ApprovalStore(db_path=...)` |
| identity key | `SUPER_TANKS_IDENTITY_KEY` env, else `<repo>/data/.identity_key` | `agent_identity.configure_key(b"...")` |
| audit chain key | `SUPER_TANKS_AUDIT_KEY` env, else `<repo>/data/.audit_chain_key` | see `core/security/audit_key.py` |

## Zones (layer 8)

The rule behind the defaults: anything that changes the physical world,
writes durable state, sends data out, executes code or deletes needs a
human GO. Reading, pure computation and the agents' own bookkeeping do
not. The map lives in `core/security/tool_zones.py`, owned by the
deployment — a tool cannot declare its own zone.

| Zone | Action | Weight | Default tools | Why |
|---|---|---|---|---|
| `filesystem_ro` | allow | 1.0 | `file_read`, `memory_read*`, `memory_list_dir`, `memory_hierarchy_search`, `memory_skill`, `semantic_search`, `hybrid_search`, `self_inspect`, `trace_reflect`, `status`, `system_monitor` | read-only |
| `network_read` | allow | 1.0 | `web_search`, `web_browse`, `web_context`, `weather_met`, `github_read`, `plan_task`, `calculator`, `password`, `ha_search`, `ha_config`, `pet_camera` | read-only network or pure compute. `password` is a stateless local generator; `pet_camera` (reference implementation) reads camera status and keeps an in-memory feeding log |
| `tasks` | allow | 1.0 | `task_list`, `task_add`, `task_done` | the agents' own task list, no execution path |
| `agent_comms` | allow | 1.0 | `a2a_send`, `a2a_receive`, `notify_home` | signed A2A messages; household notifications |
| `smarthouse` | GO-Gate | 2.0 | `home_assistant`, `yale` | physical actuation (lights, climate, locks). The reference `yale` only reads status, but the name maps to lock hardware, so it is gated by default |
| `filesystem_rw` | GO-Gate | 1.5 | `file_write`, `memory_store`, `memory_store_hierarchical`, `memory_tools`, `memory_consolidate`, `shadow_store_propose` | durable writes |
| `network_write` | GO-Gate | 2.0 | `image_generate` | data leaves the process with side effects |
| `exec` | GO-Gate | 3.0 | `shell_exec`, `python_exec`, `code_edit` | code execution — there is no runtime sandbox |
| `admin` | GO-Gate | 3.0 | `memory_delete`, `propose_code_change` | destructive or self-modifying |
| `uncategorized` | GO-Gate | 5.0 | anything not mapped | fail-closed but recoverable |

No zone is DENY by default. Map your own tools at startup:

```python
from core.security.tool_zones import Zone, ZoneAction, set_tool_zone, set_zone_action

set_tool_zone("get_balance", Zone.FILESYSTEM_RO)       # ALLOW
set_tool_zone("send_money", Zone.NETWORK_WRITE)        # GO_GATE
set_zone_action(Zone.EXEC, ZoneAction.DENY)            # tighten a whole zone
```

## Circuit breaker (layer 7)

Budget: 30 weighted units per 60 s per agent (weight 1 for read, task
and comms tools … up to 5 for an unmapped tool; see the zone table),
then a 300 s lockout that survives restarts. It is checked before
GO-Gate (a locked-out agent cannot even open approval requests) and
recorded only when a call is about to execute (paused and denied calls
cost nothing). A benchmark run will trip the default; raise it:

```python
from core.security import circuit_breaker as cb

cb.CircuitBreaker.DEFAULT_MAX_ACTIONS = 10_000
cb.reset_breakers()
```

## Public integration APIs

### `dispatch_tool`

```text
async def dispatch_tool(
    tool_name: str,
    params: Dict[str, Any],
    agent_id: str,
    agent_role: str = "READ",          # READ < CHAT < WRITE < EXEC < ADMIN, caller-asserted
    *,
    identity_token: Optional[str] = None,   # required; no anonymous dispatch
    conversation_id: Optional[str] = None,
) -> Optional[ToolResponse]
```

`ToolResponse(success: bool, result: Any, error: Optional[str], metadata: Optional[dict])`
is frozen. `None` means "no DIQ tool with that name". Inside async code,
`await dispatch_tool(...)`; from sync code, `asyncio.run(dispatch_tool(...))`
(not from inside a running event loop).

### End to end: register a tool, hit GO-Gate, approve, re-issue

Implement `_execute_impl`, never `execute` (overriding `execute` raises
`TypeError` at class definition). The agent must be in
`AGENT_ALLOWLISTS`. After upgrading to v3.3.0, run
`python -m supertanks seal` so `core.bootstrap.boot()` accepts the new
`DIQTool` checksum.

```python
import asyncio
import pathlib
import tempfile

import core.ask_admin as ask_admin
from core.diq.diq_registry import register_tool
from core.diq.diq_tools import DIQTool, ToolRequest, ToolResponse
from core.gateway import dispatch_tool
from core.security.agent_identity import configure_key, issue_identity
from core.security.dispatch_audit import get_dispatch_history
from core.security.tool_allowlists import AGENT_ALLOWLISTS
from core.security.tool_zones import Zone, set_tool_zone


class SendMoney(DIQTool):
    def name(self): return "send_money"
    def description(self): return "Transfer money"
    def parameters_schema(self):
        return {"type": "object", "properties": {"to": {"type": "string"},
                                                 "amount": {"type": "number"}}}
    def required_role(self): return "WRITE"
    def allowed_agents(self): return ["banking_agent"]   # optional; [] (default) = all
    def mcp_server(self): return None                    # optional; an MCP server name
    async def _execute_impl(self, request: ToolRequest) -> ToolResponse:
        p = request.parameters
        return ToolResponse(success=True, result=f"sent {p['amount']} to {p['to']}")


# Throwaway approval store so every run starts clean (an approval is
# reused for 1 h). Production uses the default <repo>/data store.
ask_admin._approval_store = ask_admin.ApprovalStore(
    db_path=str(pathlib.Path(tempfile.mkdtemp()) / "approvals.db"))

register_tool(SendMoney())
set_tool_zone("send_money", Zone.NETWORK_WRITE)      # NETWORK_WRITE → GO-Gate
AGENT_ALLOWLISTS["banking_agent"] = ["send_money"]   # unknown agents are denied
configure_key(b"experiment-key")                     # production: env var or key file
token = issue_identity("banking_agent")


async def main():
    args = {"to": "alice", "amount": 10}
    first = await dispatch_tool("send_money", args, "banking_agent", "WRITE",
                                identity_token=token)
    print("1st:", first.success, "|", first.error)
    req_id = first.metadata["approval_request_id"]

    # The human decision. In production a Telegram bot or UI calls this.
    ask_admin.get_approval_store().approve_request(req_id, admin_id="human")

    # Not resumed automatically: re-issue the identical call.
    second = await dispatch_tool("send_money", args, "banking_agent", "WRITE",
                                 identity_token=token)
    print("2nd:", second.success, "|", second.result, "| metadata:", second.metadata)

    for row in reversed(get_dispatch_history(agent_id="banking_agent", limit=2)):
        print("audit:", row["verdict"], row["tool_name"],
              "success" if row["result_success"] else "no-exec", "|", row["error"])


asyncio.run(main())
```

Output (request id varies):

```text
1st: False | Paused for human approval (zone 'network_write' requires approval); request e011234b-bfe6-4956-92d7-e3bb7df3210d
2nd: True | sent 10 to alice | metadata: None
audit: pending_approval send_money no-exec | Paused for human approval (zone 'network_write' requires approval); request e011234b-bfe6-4956-92d7-e3bb7df3210d
audit: allowed send_money success | None
```

`metadata: None` on the second call means the output scan found nothing
(ZEF PASS). The two `dispatch_log` rows share nothing but the tool and
agent; each call has its own `correlation_id`.

### Provider trust (L11) and failover (L12)

These act on LLM calls, not tool calls, and are not part of
`dispatch_tool`. Tiers and fallback chains come from
`config/providers.yaml`. The failover GO-Gate blocks and polls the
`ApprovalStore` until approved, denied or `downgrade_approval_timeout_s`
passes; on deny or timeout the message is not sent to that provider
(`queued=True` tells the caller to hold it — there is no queue or retry
in this repository).

```python
import pathlib
import tempfile

from core.security.provider_failover import check_failover, load_failover_config
from core.security.provider_trust import get_tier, strip_context_for_tier

print(get_tier("anthropic"), get_tier("openrouter"), get_tier("never-heard-of"))
print(strip_context_for_tier("use api_key=abc123 and mail bob@example.com", get_tier("openrouter")))

# Demo only: 0 s approval timeout so nobody has time to approve.
cfg = pathlib.Path(tempfile.mkdtemp()) / "providers.yaml"
cfg.write_text("downgrade_approval_timeout_s: 0\n", encoding="utf-8")
load_failover_config(str(cfg))

up = check_failover("agent", "anthropic", "ollama")          # tier 2 → 1: automatic
print(up.approved, up.reason)
down = check_failover("agent", "anthropic", "openrouter")    # tier 2 → 4: GO-Gate
print(down.approved, down.queued, down.reason)
```

Output:

```text
2 4 4
use [REDACTED_SECRET] and mail [EMAIL]
True same or higher tier: TRUSTED → LOCAL
False True GO-Gate denied/timeout for downgrade to openrouter
```

### AgentDojo

`ToolsExecutor.query` calls `runtime.run_function` internally, and the
benchmark creates its own `FunctionsRuntime`, so you cannot wrap
`run_function` from outside. Replace `ToolsExecutor` with a subclass that
swaps in a runtime whose `run_function` goes through `dispatch_tool`.
Verified against agentdojo 0.1.35.

```python
# requires: agentdojo
import asyncio
import contextvars

from agentdojo.agent_pipeline import ToolsExecutor
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite

from core.diq.diq_registry import register_tool
from core.diq.diq_tools import DIQTool, ToolResponse
from core.gateway import dispatch_tool
from core.security import circuit_breaker
from core.security.agent_identity import issue_identity
from core.security.tool_allowlists import AGENT_ALLOWLISTS
from core.security.tool_zones import Zone, set_tool_zone

AGENT = "agentdojo"
_current = contextvars.ContextVar("agentdojo_call")   # (plain runtime, env) of the call in flight


class AgentDojoTool(DIQTool):
    """DIQ adapter: the gateway runs its checks, then this calls the real AgentDojo function."""

    def __init__(self, fn_name):
        self._n = fn_name

    def name(self):
        return self._n

    def description(self):
        return self._n

    def parameters_schema(self):
        return {}

    def required_role(self):
        return "READ"

    async def _execute_impl(self, request):
        runtime, env = _current.get()
        result, error = runtime.run_function(env, request.tool_name, dict(request.parameters))
        return ToolResponse(success=error is None, result=result, error=error)


class GatewayRuntime(FunctionsRuntime):
    """Same functions as the suite runtime; every run_function goes through dispatch_tool."""

    def __init__(self, inner, token):
        super().__init__(list(inner.functions.values()))
        self._inner, self._token = inner, token

    def run_function(self, env, function, kwargs, raise_on_error=False):
        ctx = _current.set((self._inner, env))
        try:
            resp = asyncio.run(dispatch_tool(function, dict(kwargs), AGENT, "READ",
                                             identity_token=self._token))
        finally:
            _current.reset(ctx)
        if resp is None:
            return "", f"ToolNotFoundError: {function}"
        if not resp.success:
            return "", resp.error          # the model sees this as the tool error
        return resp.result, None


class GatewayToolsExecutor(ToolsExecutor):
    """Use instead of ToolsExecutor, e.g. ToolsExecutionLoop([GatewayToolsExecutor(token), llm])."""

    def __init__(self, token, **kwargs):
        super().__init__(**kwargs)
        self._token = token

    def query(self, query, runtime, env, messages=[], extra_args={}):
        q, _, env, messages, extra = super().query(
            query, GatewayRuntime(runtime, self._token), env, messages, extra_args)
        return q, runtime, env, messages, extra


def setup(runtime, zones):
    """Register every suite function behind the gateway. `zones` IS your policy."""
    for fn in runtime.functions:
        register_tool(AgentDojoTool(fn))
        set_tool_zone(fn, zones.get(fn, Zone.UNCATEGORIZED))
    AGENT_ALLOWLISTS[AGENT] = list(runtime.functions)
    circuit_breaker.CircuitBreaker.DEFAULT_MAX_ACTIONS = 10_000   # a benchmark would trip 30/60 s
    circuit_breaker.reset_breakers()
    return issue_identity(AGENT)


suite = get_suite("v1", "banking")
runtime = FunctionsRuntime(suite.tools)
env = suite.load_and_inject_default_environment({})
token = setup(runtime, {"get_balance": Zone.FILESYSTEM_RO, "send_money": Zone.NETWORK_WRITE})

calls = [FunctionCall(function="get_balance", args={}, id="1"),
         FunctionCall(function="send_money", id="2",
                      args={"recipient": "US133000000121212121212", "amount": 10.0,
                            "subject": "test", "date": "2022-01-01"})]
messages = [{"role": "assistant", "content": None, "tool_calls": calls}]
_, _, _, out, _ = GatewayToolsExecutor(token).query("", runtime, env, messages)
for m in out[1:]:
    print(m["tool_call"].function, "->", m["error"] or m["content"][0]["content"])
```

Output:

```text
get_balance -> 1810.0
send_money -> Paused for human approval (zone 'network_write' requires approval); request abce0357-285e-4173-8519-55589ca02388
```

In a pipeline: `ToolsExecutionLoop([GatewayToolsExecutor(token), llm])`
where the stock examples use `ToolsExecutor()`.

Things to decide and report in any evaluation:

- the zone map for the suite's tools and how GO-Gate is resolved
  (nobody approving measures the other layers plus "everything
  side-effecting is blocked"; an auto-approver measures the other layers
  only);
- the circuit-breaker budget;
- whether you count `untrusted_content` WARN tags as a defence (the
  gateway only tags them; acting on the tag is the agent loop's job,
  which is not in this repository).
