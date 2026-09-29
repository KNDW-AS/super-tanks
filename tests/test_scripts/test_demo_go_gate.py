"""The GO-Gate demo must run end to end through dispatch_tool."""

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_demo_runs_through_gateway():
    env = {**os.environ, "DEMO_FAST": "1", "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    env.pop("SUPER_TANKS_APPROVAL_DB", None)
    proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "demo_go_gate.py")],
                          cwd=str(ROOT), capture_output=True, text=True,
                          encoding="utf-8", env=env, timeout=60)
    assert proc.returncode == 0, proc.stderr[-2000:]
    out = re.sub(r"\x1b\[[0-9;]*m", "", proc.stdout)
    assert out.count("EXECUTED") == 1
    verdicts = re.findall(r"^\s+(\w+)\s+(send_email|delete_files)$", out, flags=re.M)
    assert verdicts == [("pending_approval", "send_email"), ("allowed", "send_email"),
                        ("pending_approval", "send_email"), ("pending_approval", "delete_files"),
                        ("denied_zone", "delete_files")]
