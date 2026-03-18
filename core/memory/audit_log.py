"""
core/memory/audit_log.py
=========================
Super Tanks v3.0 — SQLite Audit Trail for Hierarchical Memory Operations.

Every memory read, write, delete, and access-control decision is logged
to an append-only SQLite table using WAL mode for concurrent safety.

DB path: data/memory_audit.db
"""

import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("super_tanks.memory.audit")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DB_PATH = _PROJECT_ROOT / "data" / "memory_audit.db"

# Lazy singleton connection
_conn: Optional[sqlite3.Connection] = None


def _get_connection() -> sqlite3.Connection:
    """
    Return a shared SQLite connection with WAL mode and busy timeout.

    Uses open_db() from core.db.connection for consistent settings.
    Creates the audit table if it does not exist.
    """
    global _conn
    if _conn is not None:
        return _conn

    from core.db.connection import open_db

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    _conn = open_db(str(DB_PATH), check_same_thread=False)

    _conn.execute("""
        CREATE TABLE IF NOT EXISTS memory_access_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    NOT NULL,
            agent_id        TEXT    NOT NULL,
            operation       TEXT    NOT NULL,
            path            TEXT    NOT NULL,
            detail_level    INTEGER NOT NULL DEFAULT 2,
            mode            TEXT    NOT NULL DEFAULT 'lockdown',
            accessible      INTEGER NOT NULL DEFAULT 1,
            conversation_id TEXT    NOT NULL DEFAULT '',
            trajectory      TEXT    NOT NULL DEFAULT ''
        )
    """)

    # Index for common query patterns
    _conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_mal_timestamp
        ON memory_access_log (timestamp DESC)
    """)
    _conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_mal_agent_path
        ON memory_access_log (agent_id, path)
    """)
    _conn.commit()

    logger.info("Memory audit log initialized at %s", DB_PATH)
    return _conn


def log_access(
    agent_id: str,
    operation: str,
    path: str,
    detail_level: int = 2,
    mode: str = "lockdown",
    accessible: bool = True,
    conversation_id: str = "",
    trajectory: str = "",
) -> None:
    """
    Record a memory access event.

    Args:
        agent_id: Identifier of the agent performing the operation.
        operation: Type of operation ("READ", "WRITE", "DELETE",
                   "LIST", "SEARCH", "TRIPWIRE_ACCESS", etc.).
        path: Logical memory path that was accessed.
        detail_level: Level of detail requested (0, 1, 2, or -1 for
                      special events like tripwires).
        mode: Current Super Tanks mode ("lockdown" or "autonomous").
        accessible: Whether the access was permitted.
        conversation_id: Optional conversation/session ID for tracing.
        trajectory: Optional free-text description of the access context.
    """
    now = datetime.now(timezone.utc).isoformat()
    try:
        conn = _get_connection()
        conn.execute(
            """
            INSERT INTO memory_access_log
                (timestamp, agent_id, operation, path, detail_level,
                 mode, accessible, conversation_id, trajectory)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now,
                agent_id,
                operation,
                path,
                detail_level,
                mode,
                1 if accessible else 0,
                conversation_id,
                trajectory,
            ),
        )
        conn.commit()
    except sqlite3.Error as exc:
        logger.error("Failed to write audit log entry: %s", exc)


def get_recent_access(limit: int = 100) -> List[Dict]:
    """
    Retrieve the most recent memory access log entries.

    Args:
        limit: Maximum number of entries to return (default 100).

    Returns:
        List of dicts with columns as keys, ordered by timestamp descending.
    """
    try:
        conn = _get_connection()
        cursor = conn.execute(
            """
            SELECT id, timestamp, agent_id, operation, path,
                   detail_level, mode, accessible, conversation_id, trajectory
            FROM memory_access_log
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    except sqlite3.Error as exc:
        logger.error("Failed to query audit log: %s", exc)
        return []
