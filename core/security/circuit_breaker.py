"""
core/security/circuit_breaker.py — Layer 7: per-agent circuit breaker.

OWASP Agentic Top 10 (2026): ASI08 Cascading Failures, ASI02 Tool Misuse
(partial).

The gateway checks the breaker twice: `check()` before GO-Gate (records
nothing, so a locked-out agent cannot even open approval requests) and
`check_and_record()` as the last step before execute. Only calls that
execute are recorded, each with its zone's risk weight (see
`core.security.tool_zones.risk_weight`). When the weighted sum inside the
sliding window reaches `max_actions`, the agent is locked out for
`lockout_seconds`. State lives in SQLite (`data/circuit_breaker.db` by
default) so a process restart cannot clear an active lockout.

Fail policy: FAIL-CLOSED. Any internal error (DB unavailable, corrupt
schema, ...) propagates to the caller; `core.gateway` turns it into a
deny (`denied_subsystem`). An agent that cannot be rate-limited is not
allowed to act.

Tuning: defaults are class attributes. A benchmark harness that needs a
higher ceiling sets them before the first dispatch and calls
`reset_breakers()` to drop cached instances:

    from core.security import circuit_breaker as cb
    cb.CircuitBreaker.DEFAULT_MAX_ACTIONS = 500
    cb.reset_breakers()

Manual reset of a tripped agent: `get_breaker(agent).reset(reason)` —
only after the root cause is understood.
"""
from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Callable, Dict, Optional

from core.db.connection import open_db

logger = logging.getLogger("super_tanks.circuit_breaker")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DB_PATH = _PROJECT_ROOT / "data" / "circuit_breaker.db"

# Optional alert hook: called as hook(event, agent, details) on
# "lockout" and "reset". Exceptions raised by the hook are logged and
# never affect the breaker decision.
alert_hook: Optional[Callable[[str, str, dict], None]] = None


class CircuitBreakerError(Exception):
    """Raised when the breaker blocks an action."""

    def __init__(self, message: str, locked_until: Optional[float] = None):
        super().__init__(message)
        self.locked_until = locked_until


_schema_lock = threading.Lock()
_schema_ready: set = set()


def _init_schema(db_path: Path) -> None:
    """Create tables once per DB path per process. Serialised by a lock:
    concurrent first-time `PRAGMA journal_mode=WAL` on a fresh file can
    fail with "database is locked" instead of waiting."""
    key = str(Path(db_path).resolve())
    with _schema_lock:
        if key in _schema_ready:
            return
        _create_schema(Path(db_path))
        _schema_ready.add(key)


def _create_schema(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = open_db(str(db_path))
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS circuit_breaker_state (
                agent          TEXT PRIMARY KEY,
                locked_until   REAL,
                last_action_ts REAL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS circuit_breaker_actions (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                agent     TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                weight    REAL NOT NULL DEFAULT 1.0,
                ts        REAL NOT NULL
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_cb_actions_agent_ts "
            "ON circuit_breaker_actions(agent, ts)"
        )
        conn.commit()
    finally:
        conn.close()


def _alert(event: str, agent: str, details: dict) -> None:
    hook = alert_hook
    if hook is None:
        return
    try:
        hook(event, agent, details)
    except Exception:
        logger.exception("circuit_breaker alert hook failed (%s/%s)", event, agent)


class CircuitBreaker:
    # 30 weighted units per 60 s: a call costs its zone's risk weight
    # (1.0 for read-only zones ... 5.0 for an unmapped tool).
    DEFAULT_MAX_ACTIONS = 30
    DEFAULT_WINDOW_SECONDS = 60
    DEFAULT_LOCKOUT_SECONDS = 300

    def __init__(
        self,
        agent: str,
        max_actions: Optional[float] = None,
        window_seconds: Optional[int] = None,
        lockout_seconds: Optional[int] = None,
        db_path: Optional[Path] = None,
    ):
        self.agent = agent
        self.max_actions = self.DEFAULT_MAX_ACTIONS if max_actions is None else max_actions
        self.window = self.DEFAULT_WINDOW_SECONDS if window_seconds is None else window_seconds
        self.lockout_seconds = (self.DEFAULT_LOCKOUT_SECONDS
                                if lockout_seconds is None else lockout_seconds)
        self.db_path = Path(db_path) if db_path is not None else DB_PATH
        _init_schema(self.db_path)

    def check(self, tool_name: str, weight: float = 1.0) -> None:
        """Same decision as check_and_record() but records no usage.

        The gateway calls this before GO-Gate (so a locked-out agent
        cannot open approval requests) and check_and_record() only when
        the call is about to execute (so paused or denied calls cost no
        budget). An over-budget check still trips the lockout.
        """
        self._decide(tool_name, weight, record=False)

    def check_and_record(self, tool_name: str, weight: float = 1.0) -> bool:
        """Allow-and-record, or raise CircuitBreakerError.

        Atomic (BEGIN IMMEDIATE): two concurrent callers cannot both
        pass the threshold check. Internal errors propagate (fail closed).
        """
        self._decide(tool_name, weight, record=True)
        return True

    def _decide(self, tool_name: str, weight: float, record: bool) -> None:
        now = time.time()
        conn = open_db(str(self.db_path), isolation_level=None)
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT locked_until FROM circuit_breaker_state WHERE agent = ?",
                (self.agent,),
            ).fetchone()
            if row and row[0] and now < row[0]:
                conn.execute("COMMIT")
                raise CircuitBreakerError(
                    f"Circuit breaker open for agent '{self.agent}' until "
                    f"{time.ctime(row[0])} (tool={tool_name})",
                    locked_until=row[0],
                )

            conn.execute(
                "DELETE FROM circuit_breaker_actions WHERE agent = ? AND ts < ?",
                (self.agent, now - self.window),
            )
            total = conn.execute(
                "SELECT COALESCE(SUM(weight), 0) FROM circuit_breaker_actions "
                "WHERE agent = ? AND ts >= ?",
                (self.agent, now - self.window),
            ).fetchone()[0]

            if total + weight > self.max_actions:
                locked_until = now + self.lockout_seconds
                conn.execute(
                    "INSERT OR REPLACE INTO circuit_breaker_state "
                    "(agent, locked_until, last_action_ts) VALUES (?, ?, ?)",
                    (self.agent, locked_until, now),
                )
                conn.execute("COMMIT")
                logger.warning(
                    "circuit breaker TRIPPED agent=%s load=%.1f+%.1f max=%s window=%ss",
                    self.agent, total, weight, self.max_actions, self.window,
                )
                _alert("lockout", self.agent, {
                    "load": total, "weight": weight, "tool": tool_name,
                    "max_actions": self.max_actions, "window_seconds": self.window,
                    "locked_until": locked_until,
                })
                raise CircuitBreakerError(
                    f"Circuit breaker tripped for agent '{self.agent}': weighted "
                    f"load {total + weight:.1f} in {self.window}s exceeds "
                    f"{self.max_actions}. Locked until {time.ctime(locked_until)}.",
                    locked_until=locked_until,
                )

            if record:
                conn.execute(
                    "INSERT INTO circuit_breaker_actions (agent, tool_name, weight, ts) "
                    "VALUES (?, ?, ?, ?)",
                    (self.agent, tool_name, float(weight), now),
                )
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    logger.debug("rollback failed", exc_info=True)
            raise
        finally:
            conn.close()

    def get_status(self) -> dict:
        """Snapshot for monitoring. Raises on DB error."""
        now = time.time()
        conn = open_db(str(self.db_path))
        try:
            row = conn.execute(
                "SELECT locked_until FROM circuit_breaker_state WHERE agent = ?",
                (self.agent,),
            ).fetchone()
            load = conn.execute(
                "SELECT COALESCE(SUM(weight), 0) FROM circuit_breaker_actions "
                "WHERE agent = ? AND ts >= ?",
                (self.agent, now - self.window),
            ).fetchone()[0]
        finally:
            conn.close()
        locked_until = row[0] if row and row[0] else None
        return {
            "agent": self.agent,
            "is_locked": locked_until is not None and now < locked_until,
            "locked_until_epoch": locked_until,
            "load_in_window": load,
            "max_actions": self.max_actions,
            "window_seconds": self.window,
            "headroom": max(0.0, self.max_actions - load),
        }

    def reset(self, reason: str) -> None:
        """Clear lockout and history for this agent."""
        conn = open_db(str(self.db_path))
        try:
            conn.execute("DELETE FROM circuit_breaker_state WHERE agent = ?", (self.agent,))
            conn.execute("DELETE FROM circuit_breaker_actions WHERE agent = ?", (self.agent,))
            conn.commit()
        finally:
            conn.close()
        logger.warning("circuit breaker RESET agent=%s reason=%s", self.agent, reason)
        _alert("reset", self.agent, {"reason": reason})


_breakers: Dict[str, CircuitBreaker] = {}
_lock = threading.Lock()


def get_breaker(agent: str) -> CircuitBreaker:
    """One CircuitBreaker per agent, bound to the DB_PATH at creation."""
    with _lock:
        br = _breakers.get(agent)
        if br is None or br.db_path != DB_PATH:
            br = CircuitBreaker(agent=agent)
            _breakers[agent] = br
        return br


def reset_breakers() -> None:
    """Drop cached instances (after changing defaults or DB_PATH).
    Persisted lockouts are NOT cleared — use CircuitBreaker.reset()."""
    with _lock:
        _breakers.clear()
