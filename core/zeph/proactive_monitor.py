"""
core/zeph/proactive_monitor.py
===============================
Zeph's proactive monitoring system.
Runs scheduled health, security and deep-analysis checks.

Three schedules:
  - daily_health  (22:00)      : system health checks
  - weekly_security (Mon 10:00): security posture review
  - monthly_deep  (1st 10:00)  : trend analysis and self-reflection

All checks are READ-ONLY — never modify system state.
"""

import hashlib
import json
import logging
import sqlite3
import subprocess
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("zeph.proactive_monitor")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = REPO_ROOT / "data"
SCHEDULE_FILE = DATA_DIR / "monitor_schedule.json"

# ── Schedule definitions ─────────────────────────────────────────────────────

SCHEDULES: Dict[str, Dict[str, Any]] = {
    "daily_health": {
        "hour": 22,
        "minute": 0,
        "weekday": None,       # every day
        "monthday": None,
        "tasks": [
            "disk_usage",
            "memory_usage",
            "failed_services",
            "log_errors",
            "diq_integrity",
            "soul_integrity",
            "trust_scores",
            "gogate_pending",
        ],
    },
    "weekly_security": {
        "hour": 10,
        "minute": 0,
        "weekday": 0,          # Monday (datetime.weekday())
        "monthday": None,
        "tasks": [
            "outdated_packages",
            "tripwire_status",
            "failed_logins",
            "zef_block_count",
            "quarantine_review",
            "shadow_backlog",
        ],
    },
    "monthly_deep": {
        "hour": 10,
        "minute": 0,
        "weekday": None,
        "monthday": 1,         # 1st of month
        "tasks": [
            "trust_trend_analysis",
            "tool_usage_stats",
            "self_reflection",
        ],
    },
}


# ── Schedule state persistence ───────────────────────────────────────────────

def _load_schedule_state() -> Dict[str, str]:
    """Load last_run timestamps from data/monitor_schedule.json."""
    try:
        if SCHEDULE_FILE.exists():
            return json.loads(SCHEDULE_FILE.read_text())
    except Exception as exc:
        logger.warning("Could not load schedule state: %s", exc)
    return {}


def _save_schedule_state(state: Dict[str, str]) -> None:
    """Persist last_run timestamps."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        SCHEDULE_FILE.write_text(json.dumps(state, indent=2))
    except Exception as exc:
        logger.warning("Could not save schedule state: %s", exc)


def mark_completed(task_name: str) -> None:
    """Record that *task_name* has been run at current UTC time."""
    state = _load_schedule_state()
    state[task_name] = datetime.now(timezone.utc).isoformat()
    _save_schedule_state(state)
    logger.info("Marked '%s' as completed", task_name)


# ── Schedule evaluation ──────────────────────────────────────────────────────

def check_schedule() -> List[str]:
    """Return list of task names that are due now.

    A schedule is due when:
      - The current time matches the schedule's hour (and optionally weekday/monthday).
      - The task has not been run since the last matching window.
    """
    now = datetime.now(timezone.utc)
    state = _load_schedule_state()
    due: List[str] = []

    for schedule_name, spec in SCHEDULES.items():
        # Check time-of-day match (within the same hour)
        if now.hour != spec["hour"]:
            continue

        # Weekday constraint
        if spec.get("weekday") is not None and now.weekday() != spec["weekday"]:
            continue

        # Monthday constraint
        if spec.get("monthday") is not None and now.day != spec["monthday"]:
            continue

        # Check if already run in this window
        last_run_str = state.get(schedule_name)
        if last_run_str:
            try:
                last_run = datetime.fromisoformat(last_run_str)
                # Already run within the last 23 hours — skip
                if (now - last_run) < timedelta(hours=23):
                    continue
            except (ValueError, TypeError):
                pass  # corrupt timestamp — re-run

        due.append(schedule_name)

    return due


# ── Individual check implementations (READ-ONLY) ────────────────────────────

def _check_disk_usage() -> Dict[str, Any]:
    """Check root filesystem disk usage via psutil."""
    try:
        import psutil
        usage = psutil.disk_usage("/")
        pct = usage.percent
        level = "critical" if pct > 90 else ("warning" if pct > 80 else "ok")
        return {
            "status": level,
            "percent": pct,
            "total_gb": round(usage.total / (1024 ** 3), 1),
            "free_gb": round(usage.free / (1024 ** 3), 1),
        }
    except Exception as exc:
        logger.warning("disk_usage check failed: %s", exc)
        return {"status": "error", "error": str(exc)}


def _check_memory_usage() -> Dict[str, Any]:
    """Check system memory via psutil."""
    try:
        import psutil
        mem = psutil.virtual_memory()
        pct = mem.percent
        level = "critical" if pct > 90 else ("warning" if pct > 80 else "ok")
        return {
            "status": level,
            "percent": pct,
            "total_gb": round(mem.total / (1024 ** 3), 1),
            "available_gb": round(mem.available / (1024 ** 3), 1),
        }
    except Exception as exc:
        logger.warning("memory_usage check failed: %s", exc)
        return {"status": "error", "error": str(exc)}


def _check_failed_services() -> Dict[str, Any]:
    """List systemd failed units."""
    try:
        result = subprocess.run(
            ["systemctl", "--failed", "--no-pager"],
            capture_output=True, text=True, timeout=15,
        )
        output = result.stdout.strip()
        # Count lines that look like failed units (contain "failed" or "●")
        failed_lines = [
            line for line in output.splitlines()
            if "failed" in line.lower() or line.strip().startswith("●")
        ]
        return {
            "status": "warning" if failed_lines else "ok",
            "count": len(failed_lines),
            "units": failed_lines[:20],
            "raw_snippet": output[:1000],
        }
    except Exception as exc:
        logger.warning("failed_services check failed: %s", exc)
        return {"status": "error", "error": str(exc)}


def _check_log_errors() -> Dict[str, Any]:
    """Count ERROR lines in journalctl for the last 24 hours."""
    try:
        result = subprocess.run(
            ["journalctl", "--since", "24 hours ago", "--no-pager", "-p", "err"],
            capture_output=True, text=True, timeout=30,
        )
        lines = [l for l in result.stdout.strip().splitlines() if l.strip()]
        count = len(lines)
        level = "critical" if count > 100 else ("warning" if count > 20 else "ok")
        return {
            "status": level,
            "error_count_24h": count,
            "sample": lines[:10],
        }
    except Exception as exc:
        logger.warning("log_errors check failed: %s", exc)
        return {"status": "error", "error": str(exc)}


def _check_diq_integrity() -> Dict[str, Any]:
    """Verify DIQ contract checksums (mirrors diq_integrity.verify_diq_integrity)."""
    try:
        from core.diq.diq_integrity import verify_diq_integrity
        # verify_diq_integrity raises RuntimeError on tampering
        verify_diq_integrity()
        return {"status": "ok", "message": "All DIQ contracts verified"}
    except RuntimeError as exc:
        logger.warning("DIQ integrity violation: %s", exc)
        return {"status": "critical", "message": str(exc)}
    except Exception as exc:
        logger.warning("diq_integrity check failed: %s", exc)
        return {"status": "error", "error": str(exc)}


def _check_soul_integrity() -> Dict[str, Any]:
    """Verify SHA256 of aeris_soul.py and zeph_soul.py against sealed manifest."""
    try:
        integrity_file = REPO_ROOT / "core" / "soul_integrity.json"
        if not integrity_file.exists():
            return {"status": "warning", "message": "soul_integrity.json not found"}

        manifest = json.loads(integrity_file.read_text())
        results = {}
        all_ok = True

        for name, entry in manifest.get("souls", {}).items():
            soul_path = REPO_ROOT / entry["file"]
            expected_hash = entry["sha256"]

            if not soul_path.exists():
                results[name] = "MISSING"
                all_ok = False
                continue

            h = hashlib.sha256()
            with open(soul_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            actual_hash = h.hexdigest()

            if actual_hash == expected_hash:
                results[name] = "verified"
            else:
                results[name] = f"MISMATCH (expected {expected_hash[:16]}...)"
                all_ok = False

        return {
            "status": "ok" if all_ok else "critical",
            "souls": results,
        }
    except Exception as exc:
        logger.warning("soul_integrity check failed: %s", exc)
        return {"status": "error", "error": str(exc)}


def _check_trust_scores() -> Dict[str, Any]:
    """Read current trust scores for all agents."""
    try:
        from core.security.trust_score import get_score
        aeris = get_score("aeris")
        zeph = get_score("zeph")
        scores = {"aeris": aeris, "zeph": zeph}

        # Flag if any agent is on probation
        any_probation = any(
            s.get("level") == "probation" for s in [aeris, zeph]
        )
        return {
            "status": "warning" if any_probation else "ok",
            "scores": scores,
        }
    except Exception as exc:
        logger.warning("trust_scores check failed: %s", exc)
        return {"status": "error", "error": str(exc)}


def _check_gogate_pending() -> Dict[str, Any]:
    """Count pending GO-Gate approval requests."""
    try:
        from core.db.connection import open_db
        db_path = DATA_DIR / "go_gate.db"
        if not db_path.exists():
            return {"status": "ok", "pending": 0, "message": "go_gate.db not found"}

        conn = open_db(str(db_path))
        try:
            row = conn.execute(
                "SELECT COUNT(*) FROM approval_requests WHERE status='pending'"
            ).fetchone()
            count = row[0] if row else 0
        except sqlite3.OperationalError:
            # Table may not exist yet
            count = 0
        finally:
            conn.close()

        return {
            "status": "warning" if count > 5 else "ok",
            "pending": count,
        }
    except Exception as exc:
        logger.warning("gogate_pending check failed: %s", exc)
        return {"status": "error", "error": str(exc)}


# ── Weekly security checks ───────────────────────────────────────────────────

def _check_outdated_packages() -> Dict[str, Any]:
    """List pip packages with available updates."""
    try:
        result = subprocess.run(
            ["pip", "list", "--outdated", "--format=json"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0 and result.stdout.strip():
            packages = json.loads(result.stdout)
        else:
            packages = []
        return {
            "status": "warning" if len(packages) > 10 else "ok",
            "outdated_count": len(packages),
            "packages": packages[:20],
        }
    except Exception as exc:
        logger.warning("outdated_packages check failed: %s", exc)
        return {"status": "error", "error": str(exc)}


def _check_tripwire_status() -> Dict[str, Any]:
    """Check if frozen file manifests are intact (verify_frozen.py logic)."""
    try:
        manifest_path = REPO_ROOT / "core_locked" / "FROZEN_MANIFEST.json"
        if not manifest_path.exists():
            return {"status": "warning", "message": "FROZEN_MANIFEST.json not found"}

        manifest = json.loads(manifest_path.read_text())
        violations = []

        for file_info in manifest.get("frozen_files", []):
            filepath = REPO_ROOT / file_info["path"]
            expected_hash = file_info["sha256"]

            if not filepath.exists():
                violations.append(f"MISSING: {file_info['path']}")
                continue

            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    h.update(chunk)
            actual_hash = h.hexdigest()

            if actual_hash != expected_hash:
                violations.append(f"TAMPERED: {file_info['path']}")

        return {
            "status": "critical" if violations else "ok",
            "violations": violations,
            "checked": len(manifest.get("frozen_files", [])),
        }
    except Exception as exc:
        logger.warning("tripwire_status check failed: %s", exc)
        return {"status": "error", "error": str(exc)}


def _check_failed_logins() -> Dict[str, Any]:
    """Count failed SSH/login attempts from auth log or journalctl."""
    try:
        result = subprocess.run(
            ["journalctl", "--since", "7 days ago", "--no-pager",
             "-u", "ssh", "--grep", "Failed password"],
            capture_output=True, text=True, timeout=30,
        )
        lines = [l for l in result.stdout.strip().splitlines() if l.strip()]
        count = len(lines)
        return {
            "status": "warning" if count > 20 else "ok",
            "failed_login_count_7d": count,
            "sample": lines[:5],
        }
    except Exception as exc:
        logger.warning("failed_logins check failed: %s", exc)
        return {"status": "error", "error": str(exc)}


def _check_zef_block_count() -> Dict[str, Any]:
    """Count ZEF (Zeph Execution Firewall) blocked actions from audit log."""
    try:
        from core.db.connection import open_db
        db_path = DATA_DIR / "zeph_audit.db"
        if not db_path.exists():
            return {"status": "ok", "blocked": 0, "message": "zeph_audit.db not found"}

        conn = open_db(str(db_path))
        try:
            since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
            row = conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE outcome='blocked' AND timestamp >= ?",
                (since,),
            ).fetchone()
            count = row[0] if row else 0
        except sqlite3.OperationalError:
            count = 0
        finally:
            conn.close()

        return {
            "status": "warning" if count > 10 else "ok",
            "blocked_7d": count,
        }
    except Exception as exc:
        logger.warning("zef_block_count check failed: %s", exc)
        return {"status": "error", "error": str(exc)}


def _check_quarantine_review() -> Dict[str, Any]:
    """Count files in the quarantine directory awaiting review."""
    try:
        quarantine_dir = REPO_ROOT / "quarantine"
        if not quarantine_dir.exists():
            return {"status": "ok", "count": 0}

        files = list(quarantine_dir.iterdir())
        count = len(files)
        return {
            "status": "warning" if count > 0 else "ok",
            "count": count,
            "files": [f.name for f in files[:20]],
        }
    except Exception as exc:
        logger.warning("quarantine_review check failed: %s", exc)
        return {"status": "error", "error": str(exc)}


def _check_shadow_backlog() -> Dict[str, Any]:
    """Count pending shadow proposals in shadow_proposals.db."""
    try:
        from core.db.connection import open_db
        db_path = DATA_DIR / "shadow_proposals.db"
        if not db_path.exists():
            return {"status": "ok", "pending": 0, "message": "shadow_proposals.db not found"}

        conn = open_db(str(db_path))
        try:
            row = conn.execute(
                "SELECT COUNT(*) FROM proposals WHERE status='pending'"
            ).fetchone()
            count = row[0] if row else 0
        except sqlite3.OperationalError:
            count = 0
        finally:
            conn.close()

        return {
            "status": "warning" if count > 10 else "ok",
            "pending": count,
        }
    except Exception as exc:
        logger.warning("shadow_backlog check failed: %s", exc)
        return {"status": "error", "error": str(exc)}


# ── Monthly deep checks ─────────────────────────────────────────────────────

def _check_trust_trend_analysis() -> Dict[str, Any]:
    """Analyze 30-day trust score trend per agent."""
    try:
        from core.security.trust_score import get_event_history, get_score
        result = {}
        for agent_id in ("aeris", "zeph"):
            events = get_event_history(agent_id, limit=200)
            current = get_score(agent_id)

            if not events:
                result[agent_id] = {"trend": "no_data", "current": current}
                continue

            # Find events from 30 days ago
            cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
            recent = [e for e in events if e.get("timestamp", "") >= cutoff]

            if len(recent) < 2:
                result[agent_id] = {"trend": "insufficient_data", "current": current}
                continue

            # Compare oldest and newest score in the window
            oldest_score = recent[-1].get("after", current["score"])
            newest_score = recent[0].get("after", current["score"])
            delta = newest_score - oldest_score

            if delta > 2:
                trend = "up"
            elif delta < -2:
                trend = "down"
            else:
                trend = "stable"

            result[agent_id] = {
                "trend": trend,
                "delta": round(delta, 1),
                "events_30d": len(recent),
                "current": current,
            }

        return {"status": "ok", "trends": result}
    except Exception as exc:
        logger.warning("trust_trend_analysis check failed: %s", exc)
        return {"status": "error", "error": str(exc)}


def _check_tool_usage_stats() -> Dict[str, Any]:
    """Read tool trace data to find most/least used tools."""
    try:
        from core.db.connection import open_db
        db_path = REPO_ROOT / "aeris_kernel.db"
        if not db_path.exists():
            return {"status": "ok", "message": "aeris_kernel.db not found"}

        conn = open_db(str(db_path))
        try:
            since = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
            rows = conn.execute(
                "SELECT tool_name, COUNT(*) as cnt, "
                "AVG(duration_ms) as avg_ms, "
                "SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) as errors "
                "FROM tool_traces WHERE timestamp >= ? "
                "GROUP BY tool_name ORDER BY cnt DESC",
                (since,),
            ).fetchall()
        except sqlite3.OperationalError:
            rows = []
        finally:
            conn.close()

        if not rows:
            return {"status": "ok", "message": "No tool traces found in last 30 days"}

        tools = [
            {
                "tool": r[0],
                "calls": r[1],
                "avg_ms": round(r[2]) if r[2] else 0,
                "errors": r[3],
            }
            for r in rows
        ]

        return {
            "status": "ok",
            "total_tools": len(tools),
            "most_used": tools[:5],
            "least_used": tools[-5:] if len(tools) > 5 else [],
        }
    except Exception as exc:
        logger.warning("tool_usage_stats check failed: %s", exc)
        return {"status": "error", "error": str(exc)}


def _check_self_reflection() -> Dict[str, Any]:
    """Trigger monthly self-diagnostic via self_diagnostic module."""
    try:
        from core.zeph.self_diagnostic import run_monthly_diagnostic
        return run_monthly_diagnostic()
    except Exception as exc:
        logger.warning("self_reflection check failed: %s", exc)
        return {"status": "error", "error": str(exc)}


# ── Check dispatcher ─────────────────────────────────────────────────────────

_CHECK_REGISTRY: Dict[str, Any] = {
    # Daily health
    "disk_usage": _check_disk_usage,
    "memory_usage": _check_memory_usage,
    "failed_services": _check_failed_services,
    "log_errors": _check_log_errors,
    "diq_integrity": _check_diq_integrity,
    "soul_integrity": _check_soul_integrity,
    "trust_scores": _check_trust_scores,
    "gogate_pending": _check_gogate_pending,
    # Weekly security
    "outdated_packages": _check_outdated_packages,
    "tripwire_status": _check_tripwire_status,
    "failed_logins": _check_failed_logins,
    "zef_block_count": _check_zef_block_count,
    "quarantine_review": _check_quarantine_review,
    "shadow_backlog": _check_shadow_backlog,
    # Monthly deep
    "trust_trend_analysis": _check_trust_trend_analysis,
    "tool_usage_stats": _check_tool_usage_stats,
    "self_reflection": _check_self_reflection,
}


def run_checks(task_name: str) -> Dict[str, Any]:
    """Run all checks for a named schedule and return aggregated results.

    Returns:
        dict with keys: summary, overview, full, critical_count, warning_count
    """
    spec = SCHEDULES.get(task_name)
    if not spec:
        logger.warning("Unknown schedule: %s", task_name)
        return {
            "summary": f"Unknown schedule: {task_name}",
            "overview": "",
            "full": {},
            "critical_count": 0,
            "warning_count": 0,
        }

    results: Dict[str, Any] = {}
    critical_count = 0
    warning_count = 0
    overview_lines: List[str] = []

    for check_name in spec["tasks"]:
        func = _CHECK_REGISTRY.get(check_name)
        if not func:
            logger.warning("No implementation for check: %s", check_name)
            results[check_name] = {"status": "error", "error": "not implemented"}
            continue

        logger.info("Running check: %s", check_name)
        try:
            result = func()
        except Exception as exc:
            logger.warning("Check '%s' raised exception: %s", check_name, exc)
            result = {"status": "error", "error": str(exc)}

        results[check_name] = result

        status = result.get("status", "unknown")
        if status == "critical":
            critical_count += 1
            overview_lines.append(f"  CRITICAL  {check_name}")
        elif status == "warning":
            warning_count += 1
            overview_lines.append(f"  WARNING   {check_name}")
        else:
            overview_lines.append(f"  {status.upper():9s} {check_name}")

    # Build summary
    total = len(spec["tasks"])
    ok_count = total - critical_count - warning_count
    summary = (
        f"[{task_name}] {total} checks: "
        f"{ok_count} ok, {warning_count} warnings, {critical_count} critical"
    )

    logger.info(summary)

    # Mark schedule as completed
    mark_completed(task_name)

    return {
        "summary": summary,
        "overview": "\n".join(overview_lines),
        "full": results,
        "critical_count": critical_count,
        "warning_count": warning_count,
    }
