"""
core/security/trust_score.py
==============================
Agent Trust Score — behavioral reputation that changes over time.

Levels:
  probation (0-25):  READ+CHAT only, all writes require GO-Gate
  junior    (25-50): READ+CHAT, WRITE requires GO-Gate
  standard  (50-75): Normal operations
  senior    (75-90): Extended autonomy
  principal (90-100): Full autonomous (ADMIN still requires approval)

Score changes:
  Positive: successful tasks, correct tool usage, incident-free days
  Negative: tripwire access (-100, instant probation), quarantine fails, denials
  Decay: -0.5 per day (trust must be maintained through good behavior)
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from core.db.connection import open_db

logger = logging.getLogger("super_tanks.trust")

TRUST_DB = Path(__file__).resolve().parent.parent.parent / "data" / "trust_score.db"

TRUST_LEVELS = {
    "probation":  (0, 25),
    "junior":     (25, 50),
    "standard":   (50, 75),
    "senior":     (75, 90),
    "principal":  (90, 100),
}

TRUST_EVENTS = {
    # Positive
    "successful_task": 1.0,
    "accurate_memory_write": 0.5,
    "correct_tool_usage": 0.2,
    "safe_chat_response": 0.5,
    "day_without_incident": 2.0,
    # Negative
    "tripwire_access": -100.0,
    "quarantine_fail": -50.0,
    "gogate_denied": -5.0,
    "zef_blocked": -10.0,
    "repeated_errors": -3.0,
    "timeout_exceeded": -1.0,
    # Decay
    "daily_decay": -0.5,
    # Manual
    "manual_adjust": 0.0,  # Delta set at call time
}

DEFAULT_SCORES = {
    "aeris": 70.0,   # Starts as standard (50-75)
    "zeph": 55.0,    # Starts as standard (50-75)
}


def _get_conn():
    TRUST_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = open_db(str(TRUST_DB), timeout=15, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def _init_db():
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS trust_scores (
            agent_id TEXT PRIMARY KEY,
            score REAL NOT NULL,
            level TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS trust_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            score_change REAL NOT NULL,
            score_before REAL NOT NULL,
            score_after REAL NOT NULL,
            details TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_te_agent ON trust_events(agent_id, timestamp DESC)")
    conn.commit()
    conn.close()


_init_db()


def _score_to_level(score: float) -> str:
    for level, (low, high) in TRUST_LEVELS.items():
        if low <= score < high:
            return level
    return "principal" if score >= 90 else "probation"


def _save_score(agent_id: str, score: float, level: str):
    now = datetime.now(timezone.utc).isoformat()
    conn = _get_conn()
    try:
        conn.execute(
            "INSERT INTO trust_scores (agent_id, score, level, updated_at) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(agent_id) DO UPDATE SET score=?, level=?, updated_at=?",
            (agent_id, score, level, now, score, level, now),
        )
        conn.commit()
    finally:
        conn.close()


def get_score(agent_id: str) -> Dict:
    """Get current trust score and level."""
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT score, level, updated_at FROM trust_scores WHERE agent_id=?",
            (agent_id,),
        ).fetchone()
    finally:
        conn.close()

    if not row:
        score = DEFAULT_SCORES.get(agent_id, 50.0)
        level = _score_to_level(score)
        _save_score(agent_id, score, level)
        return {"agent_id": agent_id, "score": score, "level": level}

    return {"agent_id": agent_id, "score": row[0], "level": row[1], "updated_at": row[2]}


def record_event(agent_id: str, event_type: str, details: str = "") -> Dict:
    """Record a trust event and update the score."""
    if event_type == "manual_adjust":
        # For manual adjustments, the caller sets the delta via details
        change = 0.0
    elif event_type not in TRUST_EVENTS:
        logger.warning("[TRUST] Unknown event: %s", event_type)
        return {"error": f"Unknown event: {event_type}"}
    else:
        change = TRUST_EVENTS[event_type]

    current = get_score(agent_id)
    score_before = current["score"]
    score_after = max(0.0, min(100.0, score_before + change))
    new_level = _score_to_level(score_after)
    old_level = current["level"]

    _save_score(agent_id, score_after, new_level)

    now = datetime.now(timezone.utc).isoformat()
    conn = _get_conn()
    try:
        conn.execute(
            "INSERT INTO trust_events "
            "(timestamp, agent_id, event_type, score_change, score_before, score_after, details) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (now, agent_id, event_type, change, score_before, score_after, details),
        )
        conn.commit()
    finally:
        conn.close()

    if new_level != old_level:
        logger.warning(
            "TRUST LEVEL CHANGE: %s %s -> %s (%.1f -> %.1f, event=%s)",
            agent_id, old_level, new_level, score_before, score_after, event_type,
        )
        _notify_level_change(agent_id, old_level, new_level, score_after, event_type)

    return {
        "agent_id": agent_id,
        "event": event_type,
        "change": change,
        "score_before": score_before,
        "score_after": score_after,
        "level": new_level,
    }


def set_score(agent_id: str, new_score: float, reason: str = "Manual adjustment"):
    """Direct score set (admin only)."""
    new_score = max(0.0, min(100.0, new_score))
    current = get_score(agent_id)
    old_score = current["score"]
    new_level = _score_to_level(new_score)
    _save_score(agent_id, new_score, new_level)

    now = datetime.now(timezone.utc).isoformat()
    conn = _get_conn()
    try:
        conn.execute(
            "INSERT INTO trust_events "
            "(timestamp, agent_id, event_type, score_change, score_before, score_after, details) "
            "VALUES (?, ?, 'manual_adjust', ?, ?, ?, ?)",
            (now, agent_id, new_score - old_score, old_score, new_score, reason),
        )
        conn.commit()
    finally:
        conn.close()

    logger.info("[TRUST] Manual set: %s %.1f -> %.1f (%s)", agent_id, old_score, new_score, reason)


def get_event_history(agent_id: str, limit: int = 50) -> List[Dict]:
    conn = _get_conn()
    try:
        rows = conn.execute(
            "SELECT timestamp, event_type, score_change, score_before, score_after, details "
            "FROM trust_events WHERE agent_id=? ORDER BY id DESC LIMIT ?",
            (agent_id, limit),
        ).fetchall()
    finally:
        conn.close()
    return [
        {"timestamp": r[0], "event": r[1], "change": r[2],
         "before": r[3], "after": r[4], "details": r[5]}
        for r in rows
    ]


def apply_daily_decay():
    """Run once per day. Reduces all agent scores by 0.5."""
    for agent_id in DEFAULT_SCORES:
        record_event(agent_id, "daily_decay", "Automatic daily decay")


def _notify_level_change(agent_id: str, old_level: str, new_level: str, score: float, event: str):
    """Telegram alert on trust level change."""
    try:
        import os
        import requests as _req
        token = os.environ.get("AERIS_GOGATE_TELEGRAM_TOKEN")
        chat_id = os.environ.get("AERIS_ADMIN_CHAT_ID", os.getenv("AERIS_ADMIN_CHAT_ID", "0"))
        if not token:
            return
        direction = "opp" if TRUST_LEVELS.get(new_level, (0,0))[0] > TRUST_LEVELS.get(old_level, (0,0))[0] else "ned"
        _req.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": int(chat_id), "text":
                f"TRUST LEVEL ENDRA\n\n"
                f"Agent: {agent_id}\n"
                f"Retning: {direction}\n"
                f"{old_level} -> {new_level}\n"
                f"Score: {score:.1f}/100\n"
                f"Hendelse: {event}"},
            timeout=8,
        )
    except Exception:
        pass
