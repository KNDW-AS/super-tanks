"""
core/memory/audit_log.py
=========================
Super Tanks v3.0 — SQLite Audit Trail for Hierarchical Memory Operations.

Every memory read, write, delete, and access-control decision is logged
to an append-only SQLite table using WAL mode for concurrent safety.

DB path: data/memory_audit.db

Thread safety: every write opens a fresh sqlite3 connection. The
previous implementation kept a module-level singleton with
check_same_thread=False and no lock; concurrent calls from the gateway
+ tripwire alarm + SecureMemoryStore could interleave cursor state on
one connection. WAL mode lets multiple writers serialize at the DB
file level instead.
"""

import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("super_tanks.memory.audit")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DB_PATH = _PROJECT_ROOT / "data" / "memory_audit.db"

# A one-shot init lock prevents two threads from both running CREATE
# TABLE on first call.
_init_lock = threading.Lock()
_initialised: bool = False


def _ensure_schema() -> None:
    """Create the table + indexes on the first call (idempotent)."""
    global _initialised
    if _initialised:
        return
    with _init_lock:
        if _initialised:  # racing thread won
            return

        from core.db.connection import open_db

        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = open_db(str(DB_PATH), check_same_thread=False)
        try:
            conn.execute("""
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
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_mal_timestamp
                ON memory_access_log (timestamp DESC)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_mal_agent_path
                ON memory_access_log (agent_id, path)
            """)
            conn.commit()
        finally:
            conn.close()
        _initialised = True
        logger.info("Memory audit log initialized at %s", DB_PATH)


def _open() -> sqlite3.Connection:
    """Open a fresh connection for one operation. Caller must close()."""
    _ensure_schema()
    from core.db.connection import open_db
    return open_db(str(DB_PATH), check_same_thread=False)


# Backwards-compat alias for tests that monkeypatched _get_connection.
def _get_connection() -> sqlite3.Connection:
    return _open()


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
    """Record a memory access event.

    Each call opens, writes, and closes its own connection — concurrent
    writers serialize via SQLite's busy_timeout (15s) rather than
    interleaving on a shared cursor.
    """
    now = datetime.now(timezone.utc).isoformat()
    conn = None
    try:
        conn = _open()
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
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def get_recent_access(limit: int = 100) -> List[Dict]:
    """Retrieve the most recent memory access log entries."""
    conn = None
    try:
        conn = _open()
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
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
