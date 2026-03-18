"""
core/zeph/self_diagnostic.py
=============================
Monthly self-diagnostic that analyzes Zeph's operational performance.

Produces a structured report covering:
  - Trust score trends (30-day window)
  - Tool usage patterns (most/least used, error rates)
  - Error rate analysis from audit log
  - Competence gap identification (registered tools vs actual usage)

Output is formatted as a report suitable for storing in /zeph/diagnostics/.
All operations are READ-ONLY.
"""

import json
import logging
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("zeph.self_diagnostic")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = REPO_ROOT / "data"


# ── Trust trend analysis ─────────────────────────────────────────────────────

def analyze_trust_trend() -> Dict[str, Any]:
    """Read trust events and calculate 30-day trend (up/down/stable) per agent.

    Returns:
        dict with per-agent trend data including direction, delta, event counts.
    """
    try:
        from core.security.trust_score import get_event_history, get_score

        cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        trends = {}

        for agent_id in ("aeris", "zeph"):
            current = get_score(agent_id)
            events = get_event_history(agent_id, limit=500)

            # Filter to last 30 days
            recent = [e for e in events if e.get("timestamp", "") >= cutoff]

            if len(recent) < 2:
                trends[agent_id] = {
                    "direction": "insufficient_data",
                    "current_score": current.get("score"),
                    "current_level": current.get("level"),
                    "events_30d": len(recent),
                }
                continue

            oldest_score = recent[-1].get("after", current["score"])
            newest_score = recent[0].get("after", current["score"])
            delta = newest_score - oldest_score

            # Categorize event types
            positive_count = sum(
                1 for e in recent if e.get("change", 0) > 0
            )
            negative_count = sum(
                1 for e in recent if e.get("change", 0) < 0
            )

            if delta > 2:
                direction = "up"
            elif delta < -2:
                direction = "down"
            else:
                direction = "stable"

            trends[agent_id] = {
                "direction": direction,
                "delta": round(delta, 2),
                "current_score": current.get("score"),
                "current_level": current.get("level"),
                "events_30d": len(recent),
                "positive_events": positive_count,
                "negative_events": negative_count,
            }

        return {"status": "ok", "trends": trends}

    except Exception as exc:
        logger.warning("analyze_trust_trend failed: %s", exc)
        return {"status": "error", "error": str(exc)}


# ── Tool usage analysis ──────────────────────────────────────────────────────

def analyze_tool_usage() -> Dict[str, Any]:
    """Read trace data to find most/least used tools over the last 30 days.

    Returns:
        dict with tool usage stats, rankings, and totals.
    """
    try:
        from core.db.connection import open_db

        db_path = REPO_ROOT / "aeris_kernel.db"
        if not db_path.exists():
            return {"status": "ok", "message": "aeris_kernel.db not found — no trace data"}

        conn = open_db(str(db_path))
        try:
            since = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()

            # Overall stats
            rows = conn.execute(
                "SELECT tool_name, COUNT(*) as cnt, "
                "AVG(duration_ms) as avg_ms, "
                "SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) as errors, "
                "SUM(CASE WHEN status='success' THEN 1 ELSE 0 END) as successes "
                "FROM tool_traces WHERE timestamp >= ? "
                "GROUP BY tool_name ORDER BY cnt DESC",
                (since,),
            ).fetchall()

            # Per-caller breakdown
            caller_rows = conn.execute(
                "SELECT caller, COUNT(*) as cnt "
                "FROM tool_traces WHERE timestamp >= ? "
                "GROUP BY caller ORDER BY cnt DESC",
                (since,),
            ).fetchall()
        except sqlite3.OperationalError as exc:
            logger.warning("tool_traces table query failed: %s", exc)
            return {"status": "ok", "message": f"Query error: {exc}"}
        finally:
            conn.close()

        if not rows:
            return {"status": "ok", "message": "No tool traces in last 30 days"}

        tools = []
        total_calls = 0
        total_errors = 0
        for r in rows:
            tool_info = {
                "tool": r[0],
                "calls": r[1],
                "avg_duration_ms": round(r[2]) if r[2] else 0,
                "errors": r[3],
                "successes": r[4],
                "error_rate": round(r[3] / r[1] * 100, 1) if r[1] > 0 else 0,
            }
            tools.append(tool_info)
            total_calls += r[1]
            total_errors += r[3]

        callers = [{"caller": c[0], "calls": c[1]} for c in caller_rows]

        return {
            "status": "ok",
            "total_calls": total_calls,
            "total_errors": total_errors,
            "overall_error_rate": round(total_errors / total_calls * 100, 1) if total_calls > 0 else 0,
            "unique_tools_used": len(tools),
            "most_used": tools[:5],
            "least_used": list(reversed(tools[-5:])) if len(tools) > 5 else [],
            "by_caller": callers[:10],
        }

    except Exception as exc:
        logger.warning("analyze_tool_usage failed: %s", exc)
        return {"status": "error", "error": str(exc)}


# ── Error rate analysis ──────────────────────────────────────────────────────

def analyze_error_rate() -> Dict[str, Any]:
    """Count failed tool calls and audit failures from the audit log.

    Returns:
        dict with error counts, failure categories, and trends.
    """
    try:
        from core.db.connection import open_db

        db_path = DATA_DIR / "zeph_audit.db"
        if not db_path.exists():
            return {"status": "ok", "message": "zeph_audit.db not found"}

        conn = open_db(str(db_path))
        try:
            since = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()

            # Total vs failed
            total_row = conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ?",
                (since,),
            ).fetchone()
            total = total_row[0] if total_row else 0

            failed_row = conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE outcome='failure' AND timestamp >= ?",
                (since,),
            ).fetchone()
            failed = failed_row[0] if failed_row else 0

            blocked_row = conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE outcome='blocked' AND timestamp >= ?",
                (since,),
            ).fetchone()
            blocked = blocked_row[0] if blocked_row else 0

            # Top failure actions
            fail_actions = conn.execute(
                "SELECT action, COUNT(*) as cnt FROM audit_log "
                "WHERE outcome='failure' AND timestamp >= ? "
                "GROUP BY action ORDER BY cnt DESC LIMIT 10",
                (since,),
            ).fetchall()
        except sqlite3.OperationalError as exc:
            logger.warning("audit_log query failed: %s", exc)
            return {"status": "ok", "message": f"Query error: {exc}"}
        finally:
            conn.close()

        error_rate = round(failed / total * 100, 1) if total > 0 else 0

        return {
            "status": "warning" if error_rate > 10 else "ok",
            "total_actions_30d": total,
            "failed": failed,
            "blocked": blocked,
            "error_rate_pct": error_rate,
            "top_failure_actions": [
                {"action": r[0], "count": r[1]} for r in fail_actions
            ],
        }

    except Exception as exc:
        logger.warning("analyze_error_rate failed: %s", exc)
        return {"status": "error", "error": str(exc)}


# ── Competence gap identification ────────────────────────────────────────────

def identify_competence_gaps() -> Dict[str, Any]:
    """Compare registered tool list vs actual usage to find unused capabilities.

    Returns:
        dict with lists of unused tools, heavily-used tools, and gaps.
    """
    try:
        from core.db.connection import open_db

        # Get registered tools from settings.yaml
        registered_tools: List[str] = []
        settings_path = REPO_ROOT / "config" / "settings.yaml"
        if settings_path.exists():
            try:
                import yaml
                settings = yaml.safe_load(settings_path.read_text())
                tools_section = settings.get("tools", {})
                if isinstance(tools_section, dict):
                    registered_tools = list(tools_section.keys())
            except Exception as exc:
                logger.warning("Could not parse settings.yaml for tools: %s", exc)

        # Get actually used tools from trace DB
        used_tools: Dict[str, int] = {}
        db_path = REPO_ROOT / "aeris_kernel.db"
        if db_path.exists():
            conn = open_db(str(db_path))
            try:
                since = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
                rows = conn.execute(
                    "SELECT tool_name, COUNT(*) FROM tool_traces "
                    "WHERE timestamp >= ? GROUP BY tool_name",
                    (since,),
                ).fetchall()
                used_tools = {r[0]: r[1] for r in rows}
            except sqlite3.OperationalError:
                pass
            finally:
                conn.close()

        # Identify gaps
        never_used = [t for t in registered_tools if t not in used_tools]
        only_traced = [t for t in used_tools if t not in registered_tools]

        return {
            "status": "ok",
            "registered_count": len(registered_tools),
            "used_count": len(used_tools),
            "never_used_30d": never_used[:30],
            "unregistered_but_used": only_traced[:20],
            "coverage_pct": round(
                len(used_tools) / len(registered_tools) * 100, 1
            ) if registered_tools else 0,
        }

    except Exception as exc:
        logger.warning("identify_competence_gaps failed: %s", exc)
        return {"status": "error", "error": str(exc)}


# ── Report builder ───────────────────────────────────────────────────────────

def _format_report(
    trust: Dict[str, Any],
    tools: Dict[str, Any],
    errors: Dict[str, Any],
    gaps: Dict[str, Any],
) -> str:
    """Format diagnostic results into a human-readable text report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "=" * 60,
        f"  ZEPH MONTHLY SELF-DIAGNOSTIC",
        f"  Generated: {now}",
        "=" * 60,
        "",
        "--- TRUST SCORE TRENDS (30 days) ---",
    ]

    trends = trust.get("trends", {})
    for agent_id, data in trends.items():
        direction = data.get("direction", "unknown")
        delta = data.get("delta", 0)
        score = data.get("current_score", "?")
        level = data.get("current_level", "?")
        lines.append(
            f"  {agent_id}: {direction} (delta={delta:+.1f}), "
            f"score={score}, level={level}, "
            f"events={data.get('events_30d', 0)}"
        )

    lines.append("")
    lines.append("--- TOOL USAGE (30 days) ---")
    lines.append(f"  Total calls: {tools.get('total_calls', 0)}")
    lines.append(f"  Unique tools: {tools.get('unique_tools_used', 0)}")
    lines.append(f"  Overall error rate: {tools.get('overall_error_rate', 0)}%")

    most = tools.get("most_used", [])
    if most:
        lines.append("  Most used:")
        for t in most:
            lines.append(f"    {t['tool']}: {t['calls']} calls ({t['error_rate']}% errors)")

    least = tools.get("least_used", [])
    if least:
        lines.append("  Least used:")
        for t in least:
            lines.append(f"    {t['tool']}: {t['calls']} calls")

    lines.append("")
    lines.append("--- ERROR ANALYSIS (30 days) ---")
    lines.append(f"  Total actions: {errors.get('total_actions_30d', 0)}")
    lines.append(f"  Failed: {errors.get('failed', 0)}")
    lines.append(f"  Blocked: {errors.get('blocked', 0)}")
    lines.append(f"  Error rate: {errors.get('error_rate_pct', 0)}%")

    top_fails = errors.get("top_failure_actions", [])
    if top_fails:
        lines.append("  Top failure actions:")
        for f in top_fails:
            lines.append(f"    {f['action']}: {f['count']} failures")

    lines.append("")
    lines.append("--- COMPETENCE GAPS ---")
    lines.append(f"  Registered tools: {gaps.get('registered_count', 0)}")
    lines.append(f"  Used (30d): {gaps.get('used_count', 0)}")
    lines.append(f"  Coverage: {gaps.get('coverage_pct', 0)}%")

    never_used = gaps.get("never_used_30d", [])
    if never_used:
        lines.append(f"  Never used ({len(never_used)}):")
        for t in never_used[:15]:
            lines.append(f"    - {t}")
        if len(never_used) > 15:
            lines.append(f"    ... and {len(never_used) - 15} more")

    unregistered = gaps.get("unregistered_but_used", [])
    if unregistered:
        lines.append(f"  Used but unregistered ({len(unregistered)}):")
        for t in unregistered[:10]:
            lines.append(f"    - {t}")

    lines.append("")
    lines.append("=" * 60)
    lines.append("  END OF DIAGNOSTIC REPORT")
    lines.append("=" * 60)

    return "\n".join(lines)


# ── Main entry point ─────────────────────────────────────────────────────────

def run_monthly_diagnostic() -> Dict[str, Any]:
    """Run the full monthly self-diagnostic and return structured results.

    Returns:
        dict with keys: summary, overview, full, status
        The 'full' field contains the complete text report.
    """
    logger.info("Starting monthly self-diagnostic")

    trust = analyze_trust_trend()
    tools = analyze_tool_usage()
    errors = analyze_error_rate()
    gaps = identify_competence_gaps()

    report_text = _format_report(trust, tools, errors, gaps)

    # Determine overall status
    statuses = [trust.get("status"), tools.get("status"),
                errors.get("status"), gaps.get("status")]
    if "critical" in statuses:
        overall = "critical"
    elif "warning" in statuses:
        overall = "warning"
    elif "error" in statuses:
        overall = "error"
    else:
        overall = "ok"

    # Build overview lines
    overview_parts = []
    for agent_id, data in trust.get("trends", {}).items():
        overview_parts.append(
            f"Trust {agent_id}: {data.get('direction', '?')} ({data.get('delta', 0):+.1f})"
        )
    overview_parts.append(
        f"Tool calls: {tools.get('total_calls', 0)}, "
        f"error rate: {tools.get('overall_error_rate', 0)}%"
    )
    overview_parts.append(
        f"Audit: {errors.get('total_actions_30d', 0)} actions, "
        f"{errors.get('failed', 0)} failed, {errors.get('blocked', 0)} blocked"
    )
    overview_parts.append(
        f"Tool coverage: {gaps.get('coverage_pct', 0)}%"
    )

    summary = f"Monthly diagnostic: {overall.upper()} — {', '.join(overview_parts[:2])}"

    # Try to save report to diagnostics directory
    try:
        diag_dir = REPO_ROOT / "zeph" / "diagnostics"
        diag_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_path = diag_dir / f"diagnostic_{timestamp}.txt"
        report_path.write_text(report_text)
        logger.info("Diagnostic report saved to %s", report_path)
    except Exception as exc:
        logger.warning("Could not save diagnostic report: %s", exc)

    logger.info("Monthly self-diagnostic complete: %s", overall)

    return {
        "status": overall,
        "summary": summary,
        "overview": "\n".join(overview_parts),
        "full": report_text,
        "sections": {
            "trust_trend": trust,
            "tool_usage": tools,
            "error_rate": errors,
            "competence_gaps": gaps,
        },
    }
