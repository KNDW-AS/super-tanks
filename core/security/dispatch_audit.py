"""
core/security/dispatch_audit.py
================================
Gateway-level dispatch audit log + cross-DB correlation ID.

Closes the AISI/RSP review finding that `core.gateway.dispatch_tool`
only `logger.debug`s. Memory ops were the only thing with a SQLite
trail; tool dispatches left no record tying agent + tool + args +
verdict to the same incident.

This module:

  1. Generates a `correlation_id` (UUID) for every dispatch.
  2. Records the dispatch in `data/dispatch_audit.db` (WAL, indexed)
     with: timestamp, correlation_id, agent_id, tool_name,
     agent_role, verdict (allowed / denied_role / denied_allowlist /
     denied_identity / denied_subsystem), result_success, error.
  3. Exposes a ContextVar `current_correlation_id` so downstream
     callers (memory_audit.log_access, trust_score.record_event,
     approval store) can read it and include it in their own rows.

The correlation_id is the join key for incident reconstruction.
`grep <id>` across memory_audit.db, trust_score.db,
approval_requests.db, and this DB returns the full story of one
agent action — what, who, when, did-it-work, what side effects.

Append-only by convention. The follow-up to make the rows
tamper-evident (chained HMAC) is tracked as R-12 in the risk
register.
"""

import contextvars
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("super_tanks.dispatch_audit")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DB_PATH = _PROJECT_ROOT / "data" / "dispatch_audit.db"

# Correlation ID for the current dispatch. Set by the gateway just
# before invoking the tool; read by any downstream audit/event writer
# that wants to tie its row back to this dispatch.
current_correlation_id: contextvars.ContextVar[Optional[str]] = (
    contextvars.ContextVar("dispatch_correlation_id", default=None)
)


_initialised: bool = False
_init_lock = threading.RLock()


def _ensure_db() -> None:
    """One-shot schema bootstrap (idempotent)."""
    global _initialised
    if _initialised:
        return
    with _init_lock:
        if _initialised:
            return
        _initialised = True
        try:
            _init_db()
        except Exception:
            _initialised = False
            raise


def _open() -> sqlite3.Connection:
    """Open a fresh connection. Caller closes."""
    _ensure_db()
    from core.db.connection import open_db
    return open_db(str(DB_PATH), check_same_thread=False)


def _init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    from core.db.connection import open_db
    conn = open_db(str(DB_PATH), check_same_thread=False)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dispatch_log (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT    NOT NULL,
                correlation_id  TEXT    NOT NULL,
                agent_id        TEXT    NOT NULL,
                tool_name       TEXT    NOT NULL,
                agent_role      TEXT    NOT NULL,
                verdict         TEXT    NOT NULL,
                result_success  INTEGER,
                error           TEXT,
                hmac            TEXT    NOT NULL DEFAULT ''
            )
        """)
        # Migration for existing DBs.
        try:
            conn.execute("SELECT hmac FROM dispatch_log LIMIT 0")
        except sqlite3.OperationalError:
            conn.execute("ALTER TABLE dispatch_log ADD COLUMN hmac TEXT NOT NULL DEFAULT ''")
            logger.info("[DISPATCH_AUDIT] Migrated: added hmac column")
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_dispatch_corr
            ON dispatch_log (correlation_id)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_dispatch_agent_ts
            ON dispatch_log (agent_id, timestamp DESC)
        """)
        conn.commit()
    finally:
        conn.close()


def new_correlation_id() -> str:
    """Generate a fresh correlation_id for a new dispatch."""
    return str(uuid.uuid4())


def record_dispatch(
    correlation_id: str,
    agent_id: str,
    tool_name: str,
    agent_role: str,
    verdict: str,
    result_success: Optional[bool] = None,
    error: Optional[str] = None,
) -> None:
    """Append one dispatch row.

    verdict is one of:
      "allowed"           — passed every gate, tool was invoked
      "denied_identity"   — HMAC token verification failed
      "denied_role"       — DIQ role check failed
      "denied_allowlist"  — per-agent allowlist rejected the call
      "denied_subsystem"  — allowlist or another subsystem raised;
                            fail-closed deny
    """
    now = datetime.now(timezone.utc).isoformat()
    row = {
        "timestamp": now,
        "correlation_id": correlation_id,
        "agent_id": agent_id,
        "tool_name": tool_name,
        "agent_role": agent_role,
        "verdict": verdict,
        "result_success": (None if result_success is None
                           else (1 if result_success else 0)),
        "error": error,
    }
    conn = None
    try:
        conn = _open()
        from core.security.audit_chain import append_chained
        append_chained(conn, "dispatch_log", row)
    except sqlite3.Error as exc:
        logger.error("[DISPATCH_AUDIT] Failed to record dispatch %s: %s",
                     correlation_id, exc)
    except Exception as exc:
        logger.error("[DISPATCH_AUDIT] Chain write failed for %s: %s",
                     correlation_id, exc)
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def verify_dispatch_chain() -> Optional[int]:
    """Returns None if dispatch_log chain is intact, else the id of
    the first tampered row."""
    conn = None
    try:
        conn = _open()
        from core.security.audit_chain import verify_chain
        return verify_chain(
            conn, "dispatch_log",
            ["timestamp", "correlation_id", "agent_id", "tool_name",
             "agent_role", "verdict", "result_success", "error"],
        )
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def get_dispatch_history(
    correlation_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    limit: int = 100,
) -> List[Dict]:
    """Read recent dispatch rows. Either filter to one correlation_id
    (full incident reconstruction) or one agent (per-agent timeline)
    or neither (system-wide tail)."""
    conn = None
    try:
        conn = _open()
        if correlation_id:
            cursor = conn.execute(
                "SELECT id, timestamp, correlation_id, agent_id, tool_name, "
                "agent_role, verdict, result_success, error "
                "FROM dispatch_log WHERE correlation_id=? "
                "ORDER BY id ASC LIMIT ?",
                (correlation_id, limit),
            )
        elif agent_id:
            cursor = conn.execute(
                "SELECT id, timestamp, correlation_id, agent_id, tool_name, "
                "agent_role, verdict, result_success, error "
                "FROM dispatch_log WHERE agent_id=? "
                "ORDER BY id DESC LIMIT ?",
                (agent_id, limit),
            )
        else:
            cursor = conn.execute(
                "SELECT id, timestamp, correlation_id, agent_id, tool_name, "
                "agent_role, verdict, result_success, error "
                "FROM dispatch_log ORDER BY id DESC LIMIT ?",
                (limit,),
            )
        columns = [d[0] for d in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    except sqlite3.Error as exc:
        logger.error("[DISPATCH_AUDIT] Query failed: %s", exc)
        return []
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
