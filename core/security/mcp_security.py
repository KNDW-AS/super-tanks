"""
core/security/mcp_security.py — Layer 9: MCP server trust.

OWASP Agentic Top 10 (2026): ASI04 Supply Chain Vulnerabilities;
Agentic Skills Top 10: AST01/AST02 (partial), AST08, AST10.

A tool that is backed by an MCP server declares it by overriding
`DIQTool.mcp_server()` to return the server name. For such tools the
gateway asks this manager for a decision before execution:

  VERIFIED     → allow
  PROVISIONAL  → GO-Gate (human approval per call, via core.ask_admin)
  QUARANTINED  → deny
  UNKNOWN      → deny (server not registered — fail-closed)

Trust is persisted in SQLite (`data/mcp_security.db` by default).
Persisted state overrides the in-code registry, so a quarantine survives
restarts and re-registration. Every decision is logged to
`mcp_invocation_log`.

Fail policy: FAIL-CLOSED. DB errors propagate; the gateway denies.

What this layer does NOT do: it does not scan, sign-check or sandbox
the MCP server itself. It is a trust gate on dispatch, nothing more.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from core.db.connection import open_db

logger = logging.getLogger("super_tanks.mcp_security")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DB_PATH = _PROJECT_ROOT / "data" / "mcp_security.db"

# Optional alert hook: hook(event, server_name, details). Exceptions are
# logged and ignored.
alert_hook: Optional[Callable[[str, str, dict], None]] = None


class TrustLevel(str, Enum):
    VERIFIED = "verified"
    PROVISIONAL = "provisional"
    QUARANTINED = "quarantined"
    UNKNOWN = "unknown"


class MCPDecision(str, Enum):
    ALLOW = "allow"
    GO_GATE = "go_gate"
    DENY = "deny"


@dataclass
class MCPServer:
    name: str
    url: str
    auth_method: str  # "none" | "bearer" | "oauth" | "mtls" | "stdio"
    trust_level: TrustLevel = TrustLevel.UNKNOWN
    capabilities: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["trust_level"] = self.trust_level.value
        return d


# In-code registry. Empty in the open-source edition — register your
# servers at startup with register_server(). Persisted trust (set_trust,
# quarantine, verify) always wins over the value given here.
MCP_SERVERS: Dict[str, MCPServer] = {}


def register_server(server: MCPServer) -> None:
    MCP_SERVERS[server.name] = server


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
            CREATE TABLE IF NOT EXISTS mcp_server_state (
                name        TEXT PRIMARY KEY,
                trust_level TEXT NOT NULL,
                notes       TEXT,
                updated_ts  REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mcp_invocation_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                server_name TEXT NOT NULL,
                tool_name   TEXT NOT NULL,
                caller      TEXT,
                ts          REAL NOT NULL,
                decision    TEXT NOT NULL,
                reason      TEXT
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_mcp_inv_server_ts "
            "ON mcp_invocation_log(server_name, ts)"
        )
        conn.commit()
    finally:
        conn.close()


class MCPSecurityManager:
    """Use get_manager() in production; construct directly in tests."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path is not None else DB_PATH
        _init_schema(self.db_path)

    def get_trust(self, server_name: str) -> TrustLevel:
        """Persisted trust, else registry, else UNKNOWN. Raises on DB error."""
        conn = open_db(str(self.db_path))
        try:
            row = conn.execute(
                "SELECT trust_level FROM mcp_server_state WHERE name = ?",
                (server_name,),
            ).fetchone()
        finally:
            conn.close()
        if row:
            return TrustLevel(row[0])
        server = MCP_SERVERS.get(server_name)
        return server.trust_level if server else TrustLevel.UNKNOWN

    def evaluate(self, server_name: str, tool_name: str) -> Tuple[MCPDecision, str]:
        trust = self.get_trust(server_name)
        if trust is TrustLevel.VERIFIED:
            return MCPDecision.ALLOW, "verified"
        if trust is TrustLevel.PROVISIONAL:
            return MCPDecision.GO_GATE, "provisional server — human approval required"
        if trust is TrustLevel.QUARANTINED:
            return MCPDecision.DENY, "server quarantined"
        return MCPDecision.DENY, "unknown server (fail-closed)"

    def set_trust(self, server_name: str, trust_level: TrustLevel, reason: str = "") -> None:
        conn = open_db(str(self.db_path))
        try:
            conn.execute(
                """
                INSERT INTO mcp_server_state (name, trust_level, notes, updated_ts)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    trust_level = excluded.trust_level,
                    notes       = excluded.notes,
                    updated_ts  = excluded.updated_ts
                """,
                (server_name, TrustLevel(trust_level).value, reason, time.time()),
            )
            conn.commit()
        finally:
            conn.close()
        logger.info("mcp trust: %s -> %s (%s)", server_name, TrustLevel(trust_level).value, reason)

    def quarantine(self, server_name: str, reason: str) -> None:
        self.set_trust(server_name, TrustLevel.QUARANTINED, reason)
        hook = alert_hook
        if hook is not None:
            try:
                hook("quarantine", server_name, {"reason": reason})
            except Exception:
                logger.exception("mcp alert hook failed")

    def unquarantine(self, server_name: str, reason: str) -> None:
        """Back to PROVISIONAL — never straight to VERIFIED."""
        self.set_trust(server_name, TrustLevel.PROVISIONAL, reason)

    def verify(self, server_name: str, reason: str) -> None:
        """Mark VERIFIED — only after human review."""
        self.set_trust(server_name, TrustLevel.VERIFIED, reason)

    def log_invocation(self, server_name: str, tool_name: str, caller: str,
                       decision: MCPDecision, reason: str = "") -> None:
        conn = open_db(str(self.db_path))
        try:
            conn.execute(
                "INSERT INTO mcp_invocation_log "
                "(server_name, tool_name, caller, ts, decision, reason) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (server_name, tool_name, caller, time.time(),
                 MCPDecision(decision).value, reason),
            )
            conn.commit()
        finally:
            conn.close()

    def get_inventory(self) -> dict:
        inventory = {name: s.to_dict() for name, s in MCP_SERVERS.items()}
        conn = open_db(str(self.db_path))
        try:
            rows = conn.execute(
                "SELECT name, trust_level, notes, updated_ts FROM mcp_server_state"
            ).fetchall()
        finally:
            conn.close()
        for name, trust, notes, updated in rows:
            entry = inventory.setdefault(
                name, {"name": name, "url": "", "auth_method": "", "capabilities": []})
            entry.update({"trust_level": trust, "notes": notes or "", "updated_ts": updated})
        counts = {t.value: 0 for t in TrustLevel}
        for entry in inventory.values():
            counts[entry.get("trust_level", "unknown")] = (
                counts.get(entry.get("trust_level", "unknown"), 0) + 1)
        return {"total_servers": len(inventory), "by_trust_level": counts,
                "servers": inventory}


_manager: Optional[MCPSecurityManager] = None
_lock = threading.Lock()


def get_manager() -> MCPSecurityManager:
    """Singleton bound to the current DB_PATH."""
    global _manager
    with _lock:
        if _manager is None or _manager.db_path != DB_PATH:
            _manager = MCPSecurityManager()
        return _manager
