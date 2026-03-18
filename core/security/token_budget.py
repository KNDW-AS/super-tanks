"""
core/security/token_budget.py
===============================
Per-agent daily and per-task token limits.

Micro: Per-task limit (prevents infinite loops)
Macro: Per-day rolling limit (protects costs)

80% daily → Telegram warning. 100% daily → agent frozen.
"""

import logging
from datetime import datetime, date, timezone
from pathlib import Path
from core.db.connection import open_db

logger = logging.getLogger("super_tanks.budget")
BUDGET_DB = Path(__file__).resolve().parent.parent.parent / "data" / "token_budget.db"

BUDGET_CONFIG = {
    "aeris": {"daily_limit": 100_000, "per_task_limit": 5_000, "soft_cutoff_pct": 0.80},
    "zeph": {"daily_limit": 200_000, "per_task_limit": 10_000, "soft_cutoff_pct": 0.80},
}


def _get_conn():
    BUDGET_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = open_db(str(BUDGET_DB), timeout=15, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def _init_db():
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS token_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            task_id TEXT,
            tokens_used INTEGER NOT NULL,
            provider TEXT,
            timestamp TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tu_date_agent ON token_usage(date, agent_id)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS budget_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT
        )
    """)
    conn.commit()
    conn.close()

_init_db()


def record_usage(agent_id: str, tokens: int, task_id: str = "", provider: str = ""):
    now = datetime.now(timezone.utc).isoformat()
    conn = _get_conn()
    try:
        conn.execute(
            "INSERT INTO token_usage (date, agent_id, task_id, tokens_used, provider, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (date.today().isoformat(), agent_id, task_id, tokens, provider, now))
        conn.commit()
    finally:
        conn.close()


def get_daily_usage(agent_id: str) -> int:
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT COALESCE(SUM(tokens_used), 0) FROM token_usage WHERE agent_id=? AND date=?",
            (agent_id, date.today().isoformat())).fetchone()
        return row[0] if row else 0
    finally:
        conn.close()


def check_budget(agent_id: str, task_id: str = "") -> dict:
    config = BUDGET_CONFIG.get(agent_id, BUDGET_CONFIG["aeris"])
    daily_usage = get_daily_usage(agent_id)
    daily_limit = config["daily_limit"]
    daily_pct = daily_usage / daily_limit if daily_limit > 0 else 0

    if task_id:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT COALESCE(SUM(tokens_used), 0) FROM token_usage WHERE agent_id=? AND task_id=? AND date=?",
                (agent_id, task_id, date.today().isoformat())).fetchone()
            task_usage = row[0] if row else 0
        finally:
            conn.close()
        if task_usage >= config["per_task_limit"]:
            _log_event(agent_id, "task_limit_hit", f"Task {task_id}: {task_usage}")
            return {"allowed": False, "reason": f"Per-task limit exceeded ({task_usage}/{config['per_task_limit']})", "daily_pct": daily_pct, "alert": "task_limit"}

    if daily_usage >= daily_limit:
        _log_event(agent_id, "daily_hard_cutoff", f"{daily_usage}/{daily_limit}")
        return {"allowed": False, "reason": f"Daily budget exhausted ({daily_usage}/{daily_limit})", "daily_pct": 1.0, "alert": "hard_cutoff"}

    alert = None
    if daily_pct >= config["soft_cutoff_pct"]:
        alert = "soft_warning"

    return {"allowed": True, "reason": "Within budget", "daily_pct": daily_pct, "daily_used": daily_usage, "daily_limit": daily_limit, "alert": alert}


def get_budget_status() -> dict:
    result = {}
    for agent_id, config in BUDGET_CONFIG.items():
        usage = get_daily_usage(agent_id)
        limit = config["daily_limit"]
        result[agent_id] = {"used": usage, "limit": limit, "pct": usage / limit if limit else 0, "remaining": max(0, limit - usage)}
    return result


def _log_event(agent_id: str, event_type: str, details: str):
    conn = _get_conn()
    try:
        conn.execute("INSERT INTO budget_events (timestamp, agent_id, event_type, details) VALUES (?, ?, ?, ?)",
                     (datetime.now(timezone.utc).isoformat(), agent_id, event_type, details))
        conn.commit()
    finally:
        conn.close()
