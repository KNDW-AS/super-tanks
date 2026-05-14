#!/usr/bin/env python3
"""
scripts/diagnose_smarthome.py
=============================
Read-only health check for "Aeris can't control the smart house".

Run on the Z620 (where the real deployment lives) and paste the output back.
Walks the most common failure modes for the Home Assistant write path:

  1. Environment   — HA token + URL set? REST /api/ reachable?
  2. Mode state    — LOCKDOWN means HA writes need GO-Gate
  3. Pending GO-Gate — queued home_assistant approvals = smoking gun
  4. Trust scores  — probation forces all writes through GO-Gate
  5. Allowlist     — home_assistant in core/security/tool_allowlists.py?
  6. Recent audit  — DENIED home_assistant entries in memory_audit.db
  7. Soul guard    — SOUL_SAFE_MODE blocks every write; check hashes
  8. Recent logs   — journalctl tail for the aeris/zeph/super-tanks units

Read-only. Never mutates DBs, never calls HA services, never touches state.

Usage:
    python scripts/diagnose_smarthome.py
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional

# Allow running from repo root or scripts/.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

DATA_DIR = PROJECT_ROOT / "data"

OK = "✅"      # green check
WARN = "⚠️"  # warning sign
FAIL = "\U0001f534"   # red circle
INFO = "ℹ️"  # information

# Where super_tanks_mode.py persists state. The module currently writes
# to config/super_tanks_state.json, but older builds wrote to data/. Try
# both so the diagnostic is robust across deployments.
STATE_FILE_CANDIDATES = [
    PROJECT_ROOT / "config" / "super_tanks_state.json",
    PROJECT_ROOT / "data" / "super_tanks_state.json",
]

APPROVAL_DB = DATA_DIR / "approval_requests.db"
TRUST_DB = DATA_DIR / "trust_score.db"
AUDIT_DB = DATA_DIR / "memory_audit.db"
INTEGRITY_FILE = PROJECT_ROOT / "core" / "soul_integrity.json"

# Env var names to try, in priority order. First non-empty wins.
HA_TOKEN_VARS = [
    "HOMEASSISTANT_TOKEN",
    "HASS_TOKEN",
    "HA_TOKEN",
    "AERIS_HA_TOKEN",
    "AERIS_HOMEASSISTANT_TOKEN",
    "ZEPH_HA_TOKEN",
]
HA_URL_VARS = [
    "HOMEASSISTANT_URL",
    "HASS_URL",
    "HA_URL",
    "AERIS_HA_URL",
    "AERIS_HOMEASSISTANT_URL",
    "ZEPH_HA_URL",
]

# Service unit names to try, in priority order.
SYSTEMD_UNITS = [
    "aeris-gateway",
    "aeris",
    "zeph",
    "super-tanks",
    "supertanks",
]


def _line(emoji: str, label: str, msg: str) -> None:
    print(f"  {emoji}  {label:<22s} {msg}")


def _hint(msg: str) -> None:
    print(f"      → {msg}")


def _section(num: int, title: str) -> None:
    print()
    print(f"[{num}] {title}")
    print("    " + "-" * (len(title) + 2))


def _short(value: str, n: int = 10) -> str:
    if not value:
        return "<empty>"
    if len(value) <= n:
        return value
    return f"{value[:n]}…"


# ── 1. Environment ─────────────────────────────────────────────────────────

def _pick_env(names: Iterable[str]) -> tuple[Optional[str], Optional[str]]:
    """Return (var_name, value) of first non-empty env var, or (None, None)."""
    for n in names:
        v = os.environ.get(n)
        if v:
            return n, v
    return None, None


def check_environment() -> dict:
    _section(1, "Environment / HA REST connectivity")
    token_name, token_val = _pick_env(HA_TOKEN_VARS)
    url_name, url_val = _pick_env(HA_URL_VARS)

    result: dict = {
        "token_var": token_name, "url_var": url_name,
        "url": url_val, "ping_status": None, "ping_error": None,
    }

    if token_name:
        _line(OK, "HA token", f"{token_name}={_short(token_val, 6)} (len={len(token_val)})")
    else:
        _line(FAIL, "HA token", f"none of {', '.join(HA_TOKEN_VARS)} are set")
        _hint("Aeris will silently fall back / fail. Export the token in the systemd unit.")

    if url_name:
        _line(OK, "HA URL", f"{url_name}={url_val}")
    else:
        _line(FAIL, "HA URL", f"none of {', '.join(HA_URL_VARS)} are set")
        _hint("Default is usually http://localhost:8123 — set it explicitly.")

    if not (token_name and url_name):
        _line(WARN, "REST ping", "skipped (missing token or URL)")
        return result

    try:
        import requests  # local import — only needed for this check
    except ImportError:
        _line(WARN, "REST ping", "requests not importable in this venv")
        result["ping_error"] = "requests-import-failed"
        return result

    base = url_val.rstrip("/")
    api = f"{base}/api/"
    headers = {"Authorization": f"Bearer {token_val}", "Content-Type": "application/json"}
    try:
        r = requests.get(api, headers=headers, timeout=5)
        result["ping_status"] = r.status_code
        if r.status_code == 200:
            _line(OK, "REST /api/", f"200 OK ({api})")
        elif r.status_code == 401:
            _line(FAIL, "REST /api/", "401 Unauthorized — token rejected by HA")
            _hint("Generate a fresh long-lived access token in HA → Profile → Security.")
        elif r.status_code == 404:
            _line(WARN, "REST /api/", "404 — wrong base URL? (try with/without trailing /api)")
        else:
            _line(WARN, "REST /api/", f"HTTP {r.status_code}")
    except requests.exceptions.ConnectTimeout:
        _line(FAIL, "REST /api/", f"connect timeout to {api}")
        _hint("HA process down? Wrong host? Firewall? Check `systemctl status home-assistant`.")
        result["ping_error"] = "connect-timeout"
    except requests.exceptions.ConnectionError as e:
        _line(FAIL, "REST /api/", f"connection refused / DNS: {e.__class__.__name__}")
        _hint(f"HA not reachable at {api}. Verify URL and network.")
        result["ping_error"] = "connection-error"
    except Exception as e:
        _line(FAIL, "REST /api/", f"{e.__class__.__name__}: {e}")
        result["ping_error"] = str(e)

    return result


# ── 2. Mode state ──────────────────────────────────────────────────────────

def check_mode() -> dict:
    _section(2, "Super Tanks mode (LOCKDOWN vs AUTONOMOUS)")
    state_file = next((p for p in STATE_FILE_CANDIDATES if p.exists()), None)
    result: dict = {"state_file": str(state_file) if state_file else None, "mode": None}

    if not state_file:
        _line(WARN, "state file", "not found in config/ or data/ — defaulting to LOCKDOWN at startup")
        _hint("Default LOCKDOWN means home_assistant calls require GO-Gate approval.")
        return result

    try:
        state = json.loads(state_file.read_text())
    except Exception as e:
        _line(FAIL, "state file", f"unreadable: {e}")
        return result

    mode = state.get("mode", "?")
    result["mode"] = mode
    changed_at = state.get("changed_at", "?")
    timeout_at = state.get("autonomous_timeout_at", 0)

    if mode == "lockdown":
        _line(WARN, "mode", "LOCKDOWN")
        _hint("In LOCKDOWN every WRITE/EXEC tool needs GO-Gate. home_assistant is WRITE.")
        _hint("If William wants Aeris to control HA without prompting: set AUTONOMOUS.")
    elif mode == "autonomous":
        _line(OK, "mode", f"AUTONOMOUS (since {changed_at})")
        if timeout_at and time.time() >= float(timeout_at):
            _line(FAIL, "timeout", "AUTONOMOUS expired — effective mode reverts to LOCKDOWN at next check")
            _hint("Re-arm AUTONOMOUS via the cockpit/PIN flow.")
        elif timeout_at:
            remaining = float(timeout_at) - time.time()
            h = int(remaining // 3600)
            m = int((remaining % 3600) // 60)
            _line(OK, "timeout", f"{h}h {m}m remaining")
    else:
        _line(WARN, "mode", f"unknown value: {mode!r}")

    return result


# ── 3. Pending GO-Gate ─────────────────────────────────────────────────────

def _open_ro(db: Path) -> Optional[sqlite3.Connection]:
    """Open SQLite read-only via URI so we can never mutate the DB."""
    if not db.exists():
        return None
    try:
        # mode=ro + immutable=0 prevents any writes including journal rotation.
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception:
        return None


def check_pending_gogate() -> dict:
    _section(3, "Pending GO-Gate approvals (the usual smoking gun)")
    result: dict = {"db": str(APPROVAL_DB), "pending_total": 0, "pending_ha": 0, "samples": []}

    conn = _open_ro(APPROVAL_DB)
    if conn is None:
        _line(WARN, "approval DB", f"{APPROVAL_DB} not found")
        _hint("Either ask_admin/ApprovalStore never ran, or DB lives elsewhere.")
        return result

    try:
        now = time.time()
        rows = conn.execute(
            "SELECT request_id, tool_name, user_id, reason, status, "
            "       created_at, expires_at "
            "FROM approval_requests "
            "WHERE status='pending' "
            "ORDER BY created_at DESC"
        ).fetchall()
    except sqlite3.OperationalError as e:
        _line(FAIL, "approval DB", f"query failed: {e}")
        conn.close()
        return result

    total = len(rows)
    ha_rows = [r for r in rows if "home_assistant" in (r["tool_name"] or "").lower()
               or "ha_" in (r["tool_name"] or "").lower()]
    result["pending_total"] = total
    result["pending_ha"] = len(ha_rows)

    if total == 0:
        _line(OK, "pending total", "0 (queue is clear)")
    else:
        _line(WARN, "pending total", f"{total} pending approvals across all tools")

    if ha_rows:
        _line(FAIL, "pending HA calls",
              f"{len(ha_rows)} home_assistant requests awaiting GO-Gate")
        _hint("THIS IS LIKELY THE PROBLEM. Aeris fired the call, GO-Gate held it,")
        _hint("nobody pressed APPROVE in Telegram. Resolve via cockpit /approvals.")
        for r in ha_rows[:5]:
            try:
                age = int(now - float(r["created_at"]))
                ttl = int(float(r["expires_at"]) - now)
            except Exception:
                age, ttl = -1, -1
            sample = {
                "request_id": r["request_id"][:12], "tool_name": r["tool_name"],
                "user_id": r["user_id"], "age_s": age, "ttl_s": ttl,
                "reason": (r["reason"] or "")[:60],
            }
            result["samples"].append(sample)
            tag = "EXPIRED" if ttl < 0 else f"ttl={ttl}s"
            _hint(f"{r['request_id'][:12]}  {r['tool_name']}  user={r['user_id']}  "
                  f"age={age}s  {tag}")
    else:
        _line(OK, "pending HA calls", "0 home_assistant requests waiting")

    conn.close()
    return result


# ── 4. Trust scores ────────────────────────────────────────────────────────

def check_trust() -> dict:
    _section(4, "Trust scores (probation forces GO-Gate on every write)")
    result: dict = {"db": str(TRUST_DB), "agents": {}}

    conn = _open_ro(TRUST_DB)
    if conn is None:
        _line(WARN, "trust DB", f"{TRUST_DB} not found")
        _hint("Defaults: aeris=70 (standard), zeph=55 (standard) per trust_score.py.")
        return result

    try:
        rows = conn.execute(
            "SELECT agent_id, score, level, updated_at FROM trust_scores"
        ).fetchall()
    except sqlite3.OperationalError as e:
        _line(FAIL, "trust DB", f"query failed: {e}")
        conn.close()
        return result

    by_agent = {r["agent_id"]: r for r in rows}
    for agent in ("aeris", "zeph"):
        r = by_agent.get(agent)
        if not r:
            _line(INFO, agent, "no row yet (uses default at first lookup)")
            continue
        score = r["score"]
        level = r["level"]
        result["agents"][agent] = {"score": score, "level": level,
                                    "updated_at": r["updated_at"]}
        if level == "probation":
            _line(FAIL, agent, f"score={score:.1f} level=PROBATION")
            _hint(f"All writes by {agent} require GO-Gate (WRITE+EXEC+ADMIN roles forced).")
            _hint(f"Inspect with: sqlite3 {TRUST_DB} 'SELECT * FROM trust_events "
                  f"WHERE agent_id=\"{agent}\" ORDER BY id DESC LIMIT 10'")
        elif level == "junior":
            _line(WARN, agent, f"score={score:.1f} level=junior")
            _hint(f"In AUTONOMOUS mode, {agent} writes still need GO-Gate.")
        else:
            _line(OK, agent, f"score={score:.1f} level={level}")

    conn.close()
    return result


# ── 5. Allowlist ───────────────────────────────────────────────────────────

def check_allowlist() -> dict:
    _section(5, "Tool allowlist (defense-in-depth)")
    result: dict = {"aeris": False, "zeph": False, "import_error": None}

    try:
        from core.security.tool_allowlists import AGENT_ALLOWLISTS, is_tool_allowed
    except Exception as e:
        _line(FAIL, "import", f"{e.__class__.__name__}: {e}")
        result["import_error"] = str(e)
        _hint("If the allowlist module won't import, the gateway likely fail-closes.")
        return result

    for agent in ("aeris", "zeph"):
        ok = is_tool_allowed(agent, "home_assistant")
        result[agent] = ok
        if ok:
            _line(OK, f"{agent} → home_assistant", "ALLOWED")
        else:
            _line(FAIL, f"{agent} → home_assistant", "NOT IN ALLOWLIST")
            _hint(f"Add 'home_assistant' to AGENT_ALLOWLISTS[{agent!r}] in tool_allowlists.py.")
            tools = AGENT_ALLOWLISTS.get(agent, [])
            _hint(f"Currently {len(tools)} tools allowed for {agent}.")

    return result


# ── 6. Recent audit ────────────────────────────────────────────────────────

def check_audit() -> dict:
    _section(6, "Recent memory_audit.db entries (home_assistant / DENIED)")
    result: dict = {"db": str(AUDIT_DB), "ha_recent": 0, "denied_recent": 0,
                    "entries": []}

    conn = _open_ro(AUDIT_DB)
    if conn is None:
        _line(WARN, "audit DB", f"{AUDIT_DB} not found")
        return result

    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        # Anything mentioning home_assistant in operation OR path within 24h.
        rows = conn.execute(
            "SELECT timestamp, agent_id, operation, path, mode, accessible, trajectory "
            "FROM memory_access_log "
            "WHERE timestamp >= ? "
            "  AND (LOWER(operation) LIKE '%home_assistant%' "
            "       OR LOWER(path) LIKE '%home_assistant%' "
            "       OR LOWER(operation) LIKE '%ha_%' "
            "       OR LOWER(trajectory) LIKE '%home_assistant%') "
            "ORDER BY id DESC LIMIT 25",
            (cutoff,),
        ).fetchall()
    except sqlite3.OperationalError as e:
        _line(FAIL, "audit DB", f"query failed: {e}")
        conn.close()
        return result

    result["ha_recent"] = len(rows)
    denied = [r for r in rows if int(r["accessible"]) == 0]
    result["denied_recent"] = len(denied)

    if not rows:
        _line(WARN, "HA in audit log", "0 entries in last 24h")
        _hint("Either Aeris hasn't tried HA recently, or the gateway isn't auditing it.")
        _hint("Confirm gateway calls core.memory.audit_log.log_access for HA dispatches.")
    else:
        _line(OK, "HA in audit log", f"{len(rows)} entries in last 24h")
        if denied:
            _line(FAIL, "denied HA ops", f"{len(denied)} DENIED in last 24h (accessible=0)")
            for r in denied[:5]:
                snippet = (
                    f"{r['timestamp']}  {r['agent_id']}  {r['operation']}  "
                    f"path={r['path'][:40]!r}  mode={r['mode']}  "
                    f"trajectory={(r['trajectory'] or '')[:60]!r}"
                )
                result["entries"].append(snippet)
                _hint(snippet)
        else:
            _line(OK, "denied HA ops", "0 (all permitted)")
            # Show the most recent permitted ones for context.
            for r in rows[:3]:
                snippet = (f"{r['timestamp']}  {r['agent_id']}  {r['operation']}  "
                           f"path={r['path'][:40]!r}  mode={r['mode']}")
                result["entries"].append(snippet)
                _hint(snippet)

    conn.close()
    return result


# ── 7. Soul guard ──────────────────────────────────────────────────────────

def check_soul() -> dict:
    _section(7, "Soul guard (SOUL_SAFE_MODE blocks every write)")
    result: dict = {"safe_mode": None, "manifest": str(INTEGRITY_FILE),
                    "violations": []}

    # We try to import soul_guard and call check_soul_integrity. That
    # function only sets a module-level flag; it never writes to disk.
    try:
        from core import soul_guard  # type: ignore
    except Exception as e:
        _line(WARN, "import", f"core.soul_guard not importable: {e}")
        result["safe_mode"] = "unknown"
        _hint("Without soul_guard the gateway may refuse to start. Check imports.")
        return result

    # Read current SOUL_SAFE_MODE flag. In a fresh process this is False
    # until check_soul_integrity() is called. Calling it here is safe
    # (read-only file hashing, no DB writes).
    try:
        ok, reason = soul_guard.check_soul_integrity()
    except Exception as e:
        _line(FAIL, "integrity check", f"raised: {e}")
        result["safe_mode"] = "raised"
        return result

    safe_mode = bool(getattr(soul_guard, "SOUL_SAFE_MODE", False))
    result["safe_mode"] = safe_mode

    if not INTEGRITY_FILE.exists():
        _line(FAIL, "manifest", f"{INTEGRITY_FILE} missing")
        _hint("soul_guard treats a missing manifest as tampering → SAFE_MODE → no writes.")
        return result

    try:
        manifest = json.loads(INTEGRITY_FILE.read_text())
    except Exception as e:
        _line(FAIL, "manifest", f"unreadable: {e}")
        return result

    souls = manifest.get("souls", {})
    for name, entry in souls.items():
        soul_path = PROJECT_ROOT / entry.get("file", "")
        expected = entry.get("sha256", "")
        if not soul_path.exists():
            _line(FAIL, name, f"file missing: {soul_path}")
            result["violations"].append(name)
            continue
        h = hashlib.sha256()
        with open(soul_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        actual = h.hexdigest()
        if actual == expected:
            _line(OK, name, f"hash OK ({_short(actual, 12)})")
        else:
            _line(FAIL, name, f"HASH MISMATCH expected={_short(expected, 12)} actual={_short(actual, 12)}")
            result["violations"].append(name)
            _hint(f"Re-seal with the soul-sealing tool, or restore {soul_path} from git.")

    if safe_mode:
        _line(FAIL, "SOUL_SAFE_MODE", f"TRUE — {reason}")
        _hint("All writes (incl. home_assistant) are blocked until /approve_soul_start.")
    else:
        _line(OK, "SOUL_SAFE_MODE", "False (writes allowed by soul guard)")

    return result


# ── 8. Recent logs ─────────────────────────────────────────────────────────

def check_logs() -> dict:
    _section(8, "Recent journal (last 30 min, ERROR or home_assistant)")
    result: dict = {"unit": None, "lines": []}

    if shutil.which("journalctl") is None:
        _line(WARN, "journalctl", "not on PATH (not on a systemd host?)")
        _hint("On the Z620 try: sudo journalctl -u aeris-gateway --since '30 min ago' | grep -iE 'error|home_assistant'")
        return result

    chosen_unit = None
    chosen_output = ""

    for unit in SYSTEMD_UNITS:
        try:
            # --no-pager + short-iso for grep-friendly output. -u with a
            # unit that doesn't exist returns 0 lines, not an error.
            proc = subprocess.run(
                ["journalctl", "-u", unit, "--since", "30 min ago",
                 "--no-pager", "-o", "short-iso"],
                capture_output=True, text=True, timeout=20,
            )
        except subprocess.TimeoutExpired:
            _line(WARN, f"unit {unit}", "journalctl timed out")
            continue
        except Exception as e:
            _line(WARN, f"unit {unit}", f"{e.__class__.__name__}: {e}")
            continue

        out = proc.stdout or ""
        # Skip units that don't exist (journalctl prints "No entries" or empty).
        if not out.strip() or "No entries" in out:
            continue
        chosen_unit = unit
        chosen_output = out
        break

    if not chosen_unit:
        _line(WARN, "service unit", f"no logs in last 30 min for {SYSTEMD_UNITS}")
        _hint("Try `systemctl list-units 'aeris*' 'zeph*' 'super*'` to find the real unit name.")
        return result

    result["unit"] = chosen_unit
    _line(OK, "service unit", chosen_unit)

    needles = ("error", "exception", "denied", "home_assistant",
               "go_gate", "gogate", "lockdown", "soul_safe", "allowlist")
    matched = [
        ln for ln in chosen_output.splitlines()
        if any(n in ln.lower() for n in needles)
    ]

    if not matched:
        _line(OK, "matches", f"0 lines hit {needles[:4]}… in last 30 min")
        _hint("No relevant errors logged. Either it's not erroring, or wrong unit chosen.")
        return result

    _line(WARN, "matches", f"{len(matched)} relevant lines in last 30 min")
    tail = matched[-15:]  # last 15 to keep paste-back small
    result["lines"] = tail
    for ln in tail:
        # journalctl lines can be long; truncate hard at 200 chars.
        _hint(ln[:200])

    return result


# ── Summary ─────────────────────────────────────────────────────────────────

def summarise(env, mode, pending, trust, allow, audit, soul, logs) -> None:
    print()
    print("=" * 72)
    print("  SUMMARY — paste this whole output back to William / Claude.")
    print("=" * 72)

    suspects: list[str] = []

    # Likeliest causes first.
    if soul.get("safe_mode") is True:
        suspects.append("SOUL_SAFE_MODE is TRUE → every write is blocked.")
    if pending.get("pending_ha", 0) > 0:
        suspects.append(
            f"{pending['pending_ha']} home_assistant call(s) stuck in GO-Gate "
            "queue — approve in Telegram / cockpit."
        )
    if env.get("ping_status") == 401:
        suspects.append("HA REST returned 401 → long-lived token expired or wrong.")
    if env.get("ping_status") not in (200, None):
        suspects.append(f"HA REST ping returned {env.get('ping_status')}.")
    if env.get("ping_error"):
        suspects.append(f"HA REST ping error: {env['ping_error']}.")
    if not env.get("token_var"):
        suspects.append("No HA token env var set in the systemd unit.")
    if not env.get("url_var"):
        suspects.append("No HA URL env var set in the systemd unit.")
    if mode.get("mode") == "lockdown":
        suspects.append(
            "Mode is LOCKDOWN → home_assistant calls require GO-Gate. "
            "Switch to AUTONOMOUS if William wants seamless control."
        )
    for agent, info in (trust.get("agents") or {}).items():
        if info.get("level") == "probation":
            suspects.append(f"{agent} is on PROBATION → every write needs GO-Gate.")
    if allow.get("aeris") is False:
        suspects.append("home_assistant is NOT in Aeris's allowlist (defense-in-depth deny).")
    if allow.get("zeph") is False:
        suspects.append("home_assistant is NOT in Zeph's allowlist.")
    if audit.get("denied_recent", 0) > 0:
        suspects.append(
            f"{audit['denied_recent']} DENIED home_assistant ops in audit log "
            "(last 24h) — see entries above for the deny reason."
        )
    if soul.get("violations"):
        suspects.append(
            f"Soul hash mismatch on: {', '.join(soul['violations'])} → SAFE_MODE."
        )

    if not suspects:
        print()
        print("  No obvious failure mode found by this check.")
        print("  If Aeris is still failing, look for application-level bugs:")
        print("    - skills/homeassistant.py error handling")
        print("    - HA entity_id typos (Aeris asking for entities that don't exist)")
        print("    - rate limiting / circuit breakers on the gateway")
        return

    print()
    print("  Most likely cause(s), in priority order:")
    for i, s in enumerate(suspects, 1):
        print(f"    {i}. {s}")


def main() -> int:
    print("=" * 72)
    print("  Super Tanks — smart-home diagnostic")
    print(f"  host : {os.uname().nodename}")
    print(f"  user : {os.environ.get('USER', '?')}")
    print(f"  cwd  : {os.getcwd()}")
    print(f"  root : {PROJECT_ROOT}")
    print(f"  time : {datetime.now(timezone.utc).isoformat()}")
    print("=" * 72)

    env = check_environment()
    mode = check_mode()
    pending = check_pending_gogate()
    trust = check_trust()
    allow = check_allowlist()
    audit = check_audit()
    soul = check_soul()
    logs = check_logs()

    summarise(env, mode, pending, trust, allow, audit, soul, logs)
    print()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
