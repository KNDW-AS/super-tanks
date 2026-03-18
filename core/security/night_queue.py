"""
core/security/night_queue.py
==============================
Night Action Queue — queues Zeph's non-critical actions for morning review.

During night mode (23:00-06:00), certain operations are not blocked but
deferred. They accumulate in a queue and are presented as a "Morning Report"
at 06:00 via cockpit and Telegram.

Queue entries persist in SQLite so they survive restarts.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any

from core.db.connection import open_db

logger = logging.getLogger("super_tanks.night_queue")

QUEUE_DB = Path(__file__).resolve().parent.parent.parent / "data" / "night_queue.db"


def _get_conn():
    QUEUE_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = open_db(str(QUEUE_DB), timeout=15, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def _init_db():
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS night_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            params TEXT NOT NULL,
            reason TEXT,
            queued_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            executed_at TEXT,
            result TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_nq_status ON night_queue(status)")
    conn.commit()
    conn.close()


_init_db()


def queue_action(agent_id: str, tool_name: str, params: Dict[str, Any], reason: str = "") -> Dict:
    """Queue an action for morning execution."""
    now = datetime.now(timezone.utc).isoformat()
    conn = _get_conn()
    try:
        conn.execute(
            "INSERT INTO night_queue (agent_id, tool_name, params, reason, queued_at) VALUES (?, ?, ?, ?, ?)",
            (agent_id, tool_name, json.dumps(params, ensure_ascii=False), reason, now),
        )
        conn.commit()
        qid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    finally:
        conn.close()

    logger.info("[NIGHT_QUEUE] Queued %s/%s (id=%d): %s", agent_id, tool_name, qid, reason[:60])
    return {"queued": True, "queue_id": qid, "tool": tool_name, "message": f"Køa til morgon-rapport (id {qid})"}


def get_pending() -> List[Dict]:
    """Get all pending queued actions."""
    conn = _get_conn()
    try:
        rows = conn.execute(
            "SELECT id, agent_id, tool_name, params, reason, queued_at "
            "FROM night_queue WHERE status='pending' ORDER BY queued_at"
        ).fetchall()
    finally:
        conn.close()
    return [
        {"id": r[0], "agent_id": r[1], "tool_name": r[2],
         "params": json.loads(r[3]), "reason": r[4], "queued_at": r[5]}
        for r in rows
    ]


def mark_executed(queue_id: int, result: str = ""):
    """Mark a queued action as executed."""
    now = datetime.now(timezone.utc).isoformat()
    conn = _get_conn()
    try:
        conn.execute(
            "UPDATE night_queue SET status='executed', executed_at=?, result=? WHERE id=?",
            (now, result[:500], queue_id),
        )
        conn.commit()
    finally:
        conn.close()


def mark_dismissed(queue_id: int):
    """Dismiss a queued action without executing."""
    conn = _get_conn()
    try:
        conn.execute("UPDATE night_queue SET status='dismissed' WHERE id=?", (queue_id,))
        conn.commit()
    finally:
        conn.close()


def clear_old(days: int = 7):
    """Remove old executed/dismissed entries."""
    conn = _get_conn()
    try:
        conn.execute(
            "DELETE FROM night_queue WHERE status IN ('executed','dismissed') "
            "AND datetime(queued_at) < datetime('now', ?)",
            (f"-{days} days",),
        )
        conn.commit()
    finally:
        conn.close()


def build_morning_report() -> str:
    """Build a formatted morning report from pending queue items."""
    items = get_pending()
    if not items:
        return ""

    lines = [f"Morgon-rapport: {len(items)} utsette handlingar frå i natt\n"]
    for i, item in enumerate(items, 1):
        ts = item["queued_at"][:16].replace("T", " ") if item["queued_at"] else ""
        params_preview = json.dumps(item["params"], ensure_ascii=False)[:100]
        lines.append(
            f"{i}. [{item['tool_name']}] {item.get('reason', '') or params_preview}\n"
            f"   Agent: {item['agent_id']} | Tid: {ts} | ID: {item['id']}"
        )

    lines.append(f"\nGodkjenn alle: /approve-morning\nAvvis alle: /dismiss-morning")
    return "\n".join(lines)
