"""
demo_go_gate.py — runnable GO-Gate walkthrough against a throwaway database.

Shows the real approval flow (core/ask_admin.py): an agent's tool call is
paused fail-closed, a human approves or denies, and the gate returns a
signed-off receipt or keeps the call blocked. Nothing here touches data/.

Run:  python3 scripts/demo_go_gate.py
"""

import sys
import time
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import core.ask_admin as ask_admin
from core.ask_admin import ApprovalStore, check_tool_permission, get_approval_receipt

# Isolated store — the demo never touches the production database.
ask_admin._approval_store = ApprovalStore(
    db_path=str(Path(tempfile.mkdtemp(prefix="gogate_demo_")) / "demo.db")
)

POLICY = {
    "tools": {
        "send_email":   {"permission": "ask_admin", "description": "Send e-mail on the user's behalf"},
        "delete_files": {"permission": "ask_admin", "description": "Delete files from disk"},
    }
}

CYAN, GREEN, RED, DIM, BOLD, RESET = "\033[36m", "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"


def say(line: str = "", delay: float = 0.9) -> None:
    print(line, flush=True)
    time.sleep(delay)


def human(cmd: str) -> None:
    print(f"{BOLD}[human]{RESET} ", end="", flush=True)
    for ch in cmd:
        print(ch, end="", flush=True)
        time.sleep(0.04)
    print(flush=True)
    time.sleep(0.7)


say(f"{BOLD}── Super Tanks · GO-Gate: human approval for agent tool calls ──{RESET}", 1.2)
say(f"{DIM}   policy: send_email + delete_files require ask_admin (fail-closed){RESET}", 1.4)
say()

# 1) Agent proposes a tool call → gate pauses it
say(f"[agent] {CYAN}cody{RESET} calls send_email(to='supplier@example.com', subject='PO-4711')", 1.0)
ok, req_id, status = check_tool_permission(
    "send_email", "cody", {"to": "supplier@example.com", "subject": "PO-4711"}, POLICY
)
say(f"[gate ] {status} — request {BOLD}{req_id[:8]}{RESET}  (TTL 300s)")
say(f"[gate ] tool call is {RED}BLOCKED{RESET} until a human decides", 1.3)
say()

# 2) Human approves → receipt, call proceeds
human(f"/approve {req_id[:8]}")
ask_admin.get_approval_store().approve_request(req_id, admin_id="william")
receipt = get_approval_receipt(req_id)
say(f"[gate ] {GREEN}APPROVED{RESET} by {receipt['approved_by']} · receipt {receipt['request_id'][:8]} logged")
say(f"[agent] send_email executed {GREEN}✓{RESET}", 1.6)
say()

# 3) Second call → human denies → never executed
say(f"[agent] {CYAN}cody{RESET} calls delete_files(path='/backups')", 1.0)
ok, req_id, status = check_tool_permission("delete_files", "cody", {"path": "/backups"}, POLICY)
say(f"[gate ] {status} — request {BOLD}{req_id[:8]}{RESET}")
human(f"/deny {req_id[:8]}")
ask_admin.get_approval_store().deny_request(req_id, admin_id="william")
say(f"[gate ] {RED}DENIED{RESET} by william — the call never executed · audit trail kept", 1.6)
say()
say(f"{DIM}No answer within the TTL? The request expires and the call stays blocked.{RESET}", 2.2)
