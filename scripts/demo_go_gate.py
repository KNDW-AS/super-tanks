"""
demo_go_gate.py — runnable GO-Gate walkthrough through the real gateway.

Every tool call goes through `core.gateway.dispatch_tool` — identity,
allowlist, zone, GO-Gate, circuit breaker, output scan and audit — exactly
as an agent's would. The only shortcut is the human: the demo approves or
denies in the approval store instead of via a chat bot. All state lives in
a throwaway temp directory; nothing here touches data/.

Run:  python3 scripts/demo_go_gate.py      (or: python -m supertanks demo)
      DEMO_FAST=1 skips the pauses.
"""

import asyncio
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_TMP = Path(tempfile.mkdtemp(prefix="gogate_demo_"))
os.environ["SUPER_TANKS_APPROVAL_DB"] = str(_TMP / "approvals.db")
os.environ.setdefault("SUPER_TANKS_IDENTITY_KEY", "demo-identity-key")
os.environ.setdefault("SUPER_TANKS_AUDIT_KEY", "demo-audit-key")

import logging  # noqa: E402

logging.disable(logging.WARNING)   # the demo prints its own narration

import core.ask_admin as ask_admin  # noqa: E402
from core.diq.diq_registry import register_tool  # noqa: E402
from core.diq.diq_tools import DIQTool, ToolResponse  # noqa: E402
from core.gateway import dispatch_tool  # noqa: E402
from core.security import circuit_breaker, dispatch_audit, mcp_security  # noqa: E402
from core.security.agent_identity import issue_identity  # noqa: E402
from core.security.tool_allowlists import AGENT_ALLOWLISTS  # noqa: E402
from core.security.tool_zones import Zone, set_tool_zone  # noqa: E402

dispatch_audit.DB_PATH = _TMP / "dispatch.db"
dispatch_audit._initialised = False
circuit_breaker.DB_PATH = _TMP / "cb.db"
mcp_security.DB_PATH = _TMP / "mcp.db"

FAST = bool(os.environ.get("DEMO_FAST"))
CYAN, GREEN, RED, DIM, BOLD, RESET = "\033[36m", "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"


def say(line: str = "", delay: float = 0.9) -> None:
    print(line, flush=True)
    if not FAST:
        time.sleep(delay)


def human(cmd: str) -> None:
    print(f"{BOLD}[human]{RESET} {cmd}", flush=True)
    if not FAST:
        time.sleep(0.8)


class DemoTool(DIQTool):
    def __init__(self, name: str):
        self._n = name

    def name(self): return self._n
    def description(self): return self._n
    def parameters_schema(self): return {}
    def required_role(self): return "WRITE"

    async def _execute_impl(self, request):
        return ToolResponse(success=True, result=f"{self._n} done: {request.parameters}")


AGENT = "demo_agent"
for tool, zone in (("send_email", Zone.NETWORK_WRITE), ("delete_files", Zone.ADMIN)):
    register_tool(DemoTool(tool))
    set_tool_zone(tool, zone)
AGENT_ALLOWLISTS[AGENT] = ["send_email", "delete_files"]
TOKEN = issue_identity(AGENT)


def call(tool: str, params: dict):
    return asyncio.run(dispatch_tool(tool, params, AGENT, "WRITE", identity_token=TOKEN))


def show(resp) -> str:
    if resp.success:
        return f"{GREEN}EXECUTED{RESET} → {resp.result}"
    req = (resp.metadata or {}).get("approval_request_id")
    tag = f" [request {req[:8]}]" if req and "Paused" in (resp.error or "") else ""
    return f"{RED}BLOCKED{RESET} — {resp.error.split(';')[0]}{tag}"


store = ask_admin.get_approval_store()
say(f"{BOLD}── Super Tanks · GO-Gate through dispatch_tool ──{RESET}", 1.2)
say(f"{DIM}   zones: send_email = network_write, delete_files = admin → both need a human GO{RESET}", 1.2)
say()

email = {"to": "supplier@example.com", "subject": "PO-4711"}
say(f"[agent] {CYAN}{AGENT}{RESET} calls send_email({email})")
r = call("send_email", email)
say(f"[gate ] {show(r)}", 1.2)
req_id = r.metadata["approval_request_id"]
human(f"/approve {req_id[:8]}")
store.approve_request(req_id, admin_id="human")
say("[agent] re-issues the identical call (paused calls are not resumed)")
say(f"[gate ] {show(call('send_email', email))}", 1.2)
say("[agent] tries the same call once more")
say(f"[gate ] {show(call('send_email', email))}  {DIM}(approvals are single-use){RESET}", 1.4)
say()

wipe = {"path": "/backups"}
say(f"[agent] {CYAN}{AGENT}{RESET} calls delete_files({wipe})")
r = call("delete_files", wipe)
say(f"[gate ] {show(r)}")
human(f"/deny {r.metadata['approval_request_id'][:8]}")
store.deny_request(r.metadata["approval_request_id"], admin_id="human")
say("[agent] re-issues it")
say(f"[gate ] {show(call('delete_files', wipe))}  {DIM}(a deny sticks for 1 h){RESET}", 1.4)
say()

say(f"{DIM}Audit trail (dispatch_log):{RESET}", 0.3)
for row in reversed(dispatch_audit.get_dispatch_history(agent_id=AGENT)):
    say(f"{DIM}  {row['verdict']:<18} {row['tool_name']}{RESET}", 0.1)
say(f"{DIM}No answer within the TTL (300 s)? The request expires and the call stays blocked.{RESET}", 0.5)
