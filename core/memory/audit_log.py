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
    """Create the table + indexes on the first call (idempotent).

    Schema includes an `hmac` column for tamper-evident chaining
    (R-12). Each row's hmac is HMAC(key, prev_row_hmac || row_bytes);
    rewriting history requires the runtime HMAC key.
    """
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
                    trajectory      TEXT    NOT NULL DEFAULT '',
                    correlation_id  TEXT    NOT NULL DEFAULT '',
                    hmac            TEXT    NOT NULL DEFAULT ''
                )
            """)
            # Migration for existing DBs that pre-date the chain columns.
            for col, ddl in (
                ("correlation_id", "ALTER TABLE memory_access_log "
                                   "ADD COLUMN correlation_id TEXT NOT NULL DEFAULT ''"),
                ("hmac", "ALTER TABLE memory_access_log "
                         "ADD COLUMN hmac TEXT NOT NULL DEFAULT ''"),
            ):
                try:
                    conn.execute(f"SELECT {col} FROM memory_access_log LIMIT 0")
                except sqlite3.OperationalError:
                    conn.execute(ddl)
                    logger.info("[AUDIT_LOG] Migrated: added %s column", col)

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
    # Read the gateway's correlation_id (None outside a dispatch).
    try:
        from core.security.dispatch_audit import current_correlation_id
        corr = current_correlation_id.get() or ""
    except Exception:
        corr = ""

    row = {
        "timestamp": now,
        "agent_id": agent_id,
        "operation": operation,
        "path": path,
        "detail_level": detail_level,
        "mode": mode,
        "accessible": 1 if accessible else 0,
        "conversation_id": conversation_id,
        "trajectory": trajectory,
        "correlation_id": corr,
    }

    conn = None
    try:
        conn = _open()
        from core.security.audit_chain import append_chained
        append_chained(conn, "memory_access_log", row)
    except sqlite3.Error as exc:
        logger.error("Failed to write audit log entry: %s", exc)
    except Exception as exc:
        # HMAC chain failure (e.g. key file unreachable) — log loudly,
        # but don't crash the operation. The proactive monitor will
        # spot the bad chain.
        logger.error("Audit log chain write failed: %s", exc)
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


# Public re-export for the proactive monitor.
def verify_audit_chain() -> Optional[int]:
    """Return None if the chain is clean, else the id of the first
    tampered row."""
    conn = None
    try:
        conn = _open()
        from core.security.audit_chain import verify_chain
        return verify_chain(
            conn, "memory_access_log",
            ["timestamp", "agent_id", "operation", "path", "detail_level",
             "mode", "accessible", "conversation_id", "trajectory",
             "correlation_id"],
        )
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
