#!/usr/bin/env python3
"""
scripts/independent_review.py
==============================
Independent performance review — NOT an agent. Runs as cron or manually.

Reads directly from SQLite databases. Generates a JSON report per agent.

Databases analyzed:
  - data/trust_score.db        (trust_events)
  - data/approval_requests.db  (approval_requests)
  - data/token_budget.db       (token_usage)
  - data/memory_audit.db       (memory_access_log)
  - data/shadow_proposals.db   (shadow_proposals)

Score calculation (0-100):
  Baseline 70
  Trust improving  +10,  declining -10
  GO-Gate approval rate >= 95%  +10,  < 80%  -15
  Tripwire activation  -50
  Each ZEF block  -2

Output: data/performance_reviews/review_YYYY-MM-DD.json

Usage:
  python scripts/independent_review.py
  python scripts/independent_review.py --days 7
"""

import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Allow running from repo root or from scripts/
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.db.connection import open_db

DATA_DIR = PROJECT_ROOT / "data"
OUTPUT_DIR = DATA_DIR / "performance_reviews"

AGENTS = ["aeris", "zeph"]

# Database paths
TRUST_DB = DATA_DIR / "trust_score.db"
APPROVAL_DB = DATA_DIR / "approval_requests.db"
TOKEN_DB = DATA_DIR / "token_budget.db"
MEMORY_AUDIT_DB = DATA_DIR / "memory_audit.db"
SHADOW_DB = DATA_DIR / "shadow_proposals.db"


def _safe_open(db_path: Path):
    """Open a database connection, returning None if the file does not exist."""
    if not db_path.exists():
        return None
    try:
        return open_db(str(db_path))
    except Exception:
        return None


def _safe_query(conn, sql: str, params: tuple = ()) -> list:
    """Execute a query and return rows, or [] on any error."""
    if conn is None:
        return []
    try:
        return conn.execute(sql, params).fetchall()
    except Exception:
        return []


def _safe_close(conn):
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass


# ── Trust score trend ────────────────────────────────────────────────────────

def analyze_trust(agent_id: str, since: str) -> dict:
    """Analyze trust score trend from trust_events table."""
    conn = _safe_open(TRUST_DB)
    if conn is None:
        return {"status": "db_missing", "trend": "unknown", "events": 0}

    try:
        rows = _safe_query(
            conn,
            "SELECT score_before, score_after, event_type, timestamp "
            "FROM trust_events WHERE agent_id = ? AND timestamp >= ? "
            "ORDER BY id ASC",
            (agent_id, since),
        )
        if not rows:
            return {"status": "no_data", "trend": "stable", "events": 0}

        first_score = rows[0][0]
        last_score = rows[-1][1]
        delta = last_score - first_score

        if delta > 2:
            trend = "improving"
        elif delta < -2:
            trend = "declining"
        else:
            trend = "stable"

        return {
            "status": "ok",
            "trend": trend,
            "score_start": first_score,
            "score_end": last_score,
            "delta": round(delta, 2),
            "events": len(rows),
        }
    finally:
        _safe_close(conn)


# ── GO-Gate approval / denial ratio ─────────────────────────────────────────

def analyze_gogate(agent_id: str, since: str) -> dict:
    """Analyze GO-Gate approval vs denial ratio from approval_requests.db."""
    conn = _safe_open(APPROVAL_DB)
    if conn is None:
        return {"status": "db_missing", "approval_rate": None}

    try:
        # approval_requests uses user_id as the agent or requester
        rows = _safe_query(
            conn,
            "SELECT status FROM approval_requests "
            "WHERE user_id = ? AND created_at >= ?",
            (agent_id, since),
        )
        if not rows:
            # Also try without user_id filter (some systems use tool_name for tracking)
            rows = _safe_query(
                conn,
                "SELECT status FROM approval_requests WHERE created_at >= ?",
                (since,),
            )

        if not rows:
            return {"status": "no_data", "approval_rate": None, "total": 0}

        total = len(rows)
        approved = sum(1 for r in rows if r[0] == "approved")
        denied = sum(1 for r in rows if r[0] == "denied")
        expired = sum(1 for r in rows if r[0] == "expired")
        pending = sum(1 for r in rows if r[0] == "pending")

        rate = (approved / total * 100) if total > 0 else 0.0

        return {
            "status": "ok",
            "total": total,
            "approved": approved,
            "denied": denied,
            "expired": expired,
            "pending": pending,
            "approval_rate": round(rate, 1),
        }
    finally:
        _safe_close(conn)


# ── Token usage ──────────────────────────────────────────────────────────────

def analyze_tokens(agent_id: str, since_date: str) -> dict:
    """Analyze token usage from token_usage table."""
    conn = _safe_open(TOKEN_DB)
    if conn is None:
        return {"status": "db_missing", "total_tokens": 0}

    try:
        rows = _safe_query(
            conn,
            "SELECT SUM(tokens_used), COUNT(*), date FROM token_usage "
            "WHERE agent_id = ? AND date >= ? GROUP BY date ORDER BY date",
            (agent_id, since_date),
        )
        if not rows:
            return {"status": "no_data", "total_tokens": 0, "days": 0}

        total_tokens = sum(r[0] or 0 for r in rows)
        daily_breakdown = [
            {"date": r[2], "tokens": r[0] or 0, "requests": r[1]}
            for r in rows
        ]
        avg_daily = total_tokens / len(rows) if rows else 0

        return {
            "status": "ok",
            "total_tokens": total_tokens,
            "days": len(rows),
            "avg_daily": round(avg_daily),
            "daily_breakdown": daily_breakdown,
        }
    finally:
        _safe_close(conn)


# ── Memory access patterns ───────────────────────────────────────────────────

def analyze_memory_access(agent_id: str, since: str) -> dict:
    """Analyze memory access patterns from memory_access_log."""
    conn = _safe_open(MEMORY_AUDIT_DB)
    if conn is None:
        return {"status": "db_missing", "total_accesses": 0, "tripwire_count": 0}

    try:
        # Total accesses by operation type
        op_rows = _safe_query(
            conn,
            "SELECT operation, COUNT(*) FROM memory_access_log "
            "WHERE agent_id = ? AND timestamp >= ? GROUP BY operation",
            (agent_id, since),
        )
        operations = {r[0]: r[1] for r in op_rows}
        total = sum(operations.values())

        # Denied accesses
        denied_rows = _safe_query(
            conn,
            "SELECT COUNT(*) FROM memory_access_log "
            "WHERE agent_id = ? AND timestamp >= ? AND accessible = 0",
            (agent_id, since),
        )
        denied = denied_rows[0][0] if denied_rows else 0

        # Tripwire activations (operation contains 'tripwire', case-insensitive)
        tripwire_rows = _safe_query(
            conn,
            "SELECT COUNT(*) FROM memory_access_log "
            "WHERE agent_id = ? AND timestamp >= ? "
            "AND LOWER(operation) LIKE '%tripwire%'",
            (agent_id, since),
        )
        tripwire_count = tripwire_rows[0][0] if tripwire_rows else 0

        return {
            "status": "ok",
            "total_accesses": total,
            "operations": operations,
            "denied_accesses": denied,
            "tripwire_count": tripwire_count,
        }
    finally:
        _safe_close(conn)


# ── Shadow memory merge/reject ───────────────────────────────────────────────

def analyze_shadow(agent_id: str, since: str) -> dict:
    """Analyze shadow proposal merge/reject from shadow_proposals."""
    conn = _safe_open(SHADOW_DB)
    if conn is None:
        return {"status": "db_missing", "total_proposals": 0}

    try:
        rows = _safe_query(
            conn,
            "SELECT status, COUNT(*) FROM shadow_proposals "
            "WHERE agent_id = ? AND created_at >= ? GROUP BY status",
            (agent_id, since),
        )
        if not rows:
            return {"status": "no_data", "total_proposals": 0}

        statuses = {r[0]: r[1] for r in rows}
        total = sum(statuses.values())
        approved = statuses.get("approved", 0)
        rejected = statuses.get("rejected", 0)
        pending = statuses.get("pending", 0)
        expired = statuses.get("expired", 0)
        auto_rejected = statuses.get("auto_rejected", 0)

        merge_rate = (approved / total * 100) if total > 0 else 0.0

        return {
            "status": "ok",
            "total_proposals": total,
            "approved": approved,
            "rejected": rejected,
            "auto_rejected": auto_rejected,
            "pending": pending,
            "expired": expired,
            "merge_rate": round(merge_rate, 1),
        }
    finally:
        _safe_close(conn)


# ── ZEF block count ──────────────────────────────────────────────────────────

def count_zef_blocks(agent_id: str, since: str) -> int:
    """Count ZEF block events from trust_events."""
    conn = _safe_open(TRUST_DB)
    if conn is None:
        return 0
    try:
        rows = _safe_query(
            conn,
            "SELECT COUNT(*) FROM trust_events "
            "WHERE agent_id = ? AND event_type = 'zef_blocked' AND timestamp >= ?",
            (agent_id, since),
        )
        return rows[0][0] if rows else 0
    finally:
        _safe_close(conn)


# ── Overall score calculation ────────────────────────────────────────────────

def calculate_score(trust: dict, gogate: dict, memory: dict, zef_blocks: int) -> dict:
    """
    Calculate overall performance score (0-100).

    Baseline: 70
    Trust improving:          +10
    Trust declining:          -10
    GO-Gate approval >= 95%:  +10
    GO-Gate approval < 80%:   -15
    Tripwire activation:      -50
    Each ZEF block:           -2
    """
    score = 70
    breakdown = []

    # Trust trend
    trend = trust.get("trend", "stable")
    if trend == "improving":
        score += 10
        breakdown.append(("trust_improving", +10))
    elif trend == "declining":
        score -= 10
        breakdown.append(("trust_declining", -10))

    # GO-Gate approval rate
    approval_rate = gogate.get("approval_rate")
    if approval_rate is not None:
        if approval_rate >= 95:
            score += 10
            breakdown.append(("gogate_high_approval", +10))
        elif approval_rate < 80:
            score -= 15
            breakdown.append(("gogate_low_approval", -15))

    # Tripwire activations
    tripwire_count = memory.get("tripwire_count", 0)
    if tripwire_count > 0:
        score -= 50
        breakdown.append(("tripwire_activation", -50))

    # ZEF blocks
    if zef_blocks > 0:
        penalty = zef_blocks * -2
        score += penalty
        breakdown.append(("zef_blocks", penalty))

    # Clamp to 0-100
    score = max(0, min(100, score))

    return {
        "score": score,
        "breakdown": breakdown,
    }


# ── Full review for one agent ────────────────────────────────────────────────

def review_agent(agent_id: str, days: int = 7) -> dict:
    """Generate a full performance review for one agent."""
    now = datetime.now(timezone.utc)
    since_iso = (now - timedelta(days=days)).isoformat()
    since_date = (now - timedelta(days=days)).strftime("%Y-%m-%d")

    trust = analyze_trust(agent_id, since_iso)
    gogate = analyze_gogate(agent_id, since_iso)
    tokens = analyze_tokens(agent_id, since_date)
    memory = analyze_memory_access(agent_id, since_iso)
    shadow = analyze_shadow(agent_id, since_iso)
    zef_blocks = count_zef_blocks(agent_id, since_iso)

    scoring = calculate_score(trust, gogate, memory, zef_blocks)

    return {
        "agent_id": agent_id,
        "period_days": days,
        "since": since_iso,
        "trust": trust,
        "gogate": gogate,
        "tokens": tokens,
        "memory_access": memory,
        "shadow_proposals": shadow,
        "zef_blocks": zef_blocks,
        "overall": scoring,
    }


# ── Main ─────────────────────────────────────────────────────────────────────

def run_review(days: int = 7) -> dict:
    """Run full review for all agents and save to JSON."""
    now = datetime.now(timezone.utc)
    report = {
        "generated_at": now.isoformat(),
        "period_days": days,
        "agents": {},
    }

    for agent_id in AGENTS:
        report["agents"][agent_id] = review_agent(agent_id, days)

    # Save report
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"review_{now.strftime('%Y-%m-%d')}.json"
    output_path = OUTPUT_DIR / filename

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    report["saved_to"] = str(output_path)
    return report


def print_summary(report: dict):
    """Print a human-readable summary to stdout."""
    print("=" * 70)
    print(f"  INDEPENDENT PERFORMANCE REVIEW — {report['generated_at'][:10]}")
    print(f"  Period: {report['period_days']} days")
    print("=" * 70)

    for agent_id, data in report["agents"].items():
        overall = data["overall"]
        score = overall["score"]
        trust = data["trust"]
        gogate = data["gogate"]
        tokens = data["tokens"]
        memory = data["memory_access"]
        shadow = data["shadow_proposals"]

        print()
        print(f"  Agent: {agent_id.upper()}")
        print(f"  Overall score: {score}/100")
        print()

        # Breakdown
        if overall["breakdown"]:
            print("    Score breakdown:")
            print(f"      Baseline:                  70")
            for name, delta in overall["breakdown"]:
                sign = "+" if delta > 0 else ""
                print(f"      {name:<28s} {sign}{delta}")
            print(f"      {'─' * 36}")
            print(f"      {'TOTAL':<28s} {score}")
        else:
            print("    Score: baseline 70 (no modifiers)")

        print()

        # Trust
        trend = trust.get("trend", "unknown")
        events = trust.get("events", 0)
        delta = trust.get("delta", 0)
        print(f"    Trust: {trend} (delta={delta:+.1f}, {events} events)")

        # GO-Gate
        rate = gogate.get("approval_rate")
        total = gogate.get("total", 0)
        if rate is not None:
            print(f"    GO-Gate: {rate:.1f}% approval ({gogate.get('approved', 0)}/{total})")
        else:
            print(f"    GO-Gate: no data")

        # Tokens
        total_tokens = tokens.get("total_tokens", 0)
        avg = tokens.get("avg_daily", 0)
        print(f"    Tokens: {total_tokens:,} total, {avg:,}/day avg")

        # Memory access
        total_access = memory.get("total_accesses", 0)
        tripwire = memory.get("tripwire_count", 0)
        denied = memory.get("denied_accesses", 0)
        print(f"    Memory: {total_access} accesses, {denied} denied, {tripwire} tripwires")

        # Shadow
        proposals = shadow.get("total_proposals", 0)
        merge_rate = shadow.get("merge_rate", 0)
        print(f"    Shadow: {proposals} proposals, {merge_rate:.1f}% merge rate")

        # ZEF
        zef = data.get("zef_blocks", 0)
        print(f"    ZEF blocks: {zef}")

        print("    " + "-" * 40)

    saved = report.get("saved_to", "N/A")
    print()
    print(f"  Report saved to: {saved}")
    print("=" * 70)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Independent agent performance review")
    parser.add_argument("--days", type=int, default=7, help="Review period in days (default: 7)")
    args = parser.parse_args()

    report = run_review(days=args.days)
    print_summary(report)
