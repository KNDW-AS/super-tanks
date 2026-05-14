"""
core/security/audit_chain.py
=============================
Hash-chained tamper-evidence for SQLite append-only audit tables.

Closes R-12 in docs/RISK_REGISTER.md: "an attacker with FS write to
data/memory_audit.db can rewrite history undetected."

Each row in a chained table carries an `hmac` column whose value is

    HMAC(key, previous_row_hmac || row_canonical_bytes)

where:
- key       : the runtime HMAC key from core.security.agent_identity
              (same key the gateway uses for identity tokens — never
              leaves the process).
- prev_hmac : the hmac of the immediately preceding row (empty bytes
              for the first row).
- row_canonical_bytes : sorted-keys JSON of the row's other fields.

To rewrite history an attacker must (a) recompute the chain from the
forged row forward AND (b) hold the runtime HMAC key. The key file is
mode-0600 and never serialised through SQLite. The chain is therefore
trustworthy even on a writable filesystem, so long as the key file is
intact.

`verify_chain` walks a table and returns the row id of the first
mismatch (or None for a clean table). Forensic tools / proactive
monitor call this to detect tampering.

Two callers today:
- core/memory/audit_log.py (memory_access_log)
- core/security/dispatch_audit.py (dispatch_log)
"""

import hashlib
import hmac
import json
import logging
import sqlite3
from typing import Any, Dict, Optional

logger = logging.getLogger("super_tanks.audit_chain")


def _key() -> bytes:
    """Resolve the runtime HMAC key. Lazy import avoids a cycle on
    cold start (agent_identity imports nothing from this module)."""
    from core.security.agent_identity import _load_key
    return _load_key()


def canonical_bytes(row: Dict[str, Any]) -> bytes:
    """Stable byte serialisation of a row for HMAC input.

    `id`, `hmac`, and `prev_hmac` are excluded — they're either
    auto-assigned or part of the chain machinery itself, not data.
    """
    body = {k: v for k, v in row.items()
            if k not in ("id", "hmac", "prev_hmac")}
    return json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")


def compute_hmac(prev_hmac: Optional[str], row: Dict[str, Any]) -> str:
    """Return the hmac for one row given the predecessor's hmac."""
    prev = prev_hmac.encode("utf-8") if prev_hmac else b""
    return hmac.new(_key(), prev + canonical_bytes(row),
                    hashlib.sha256).hexdigest()


def append_chained(
    conn: sqlite3.Connection,
    table: str,
    row: Dict[str, Any],
) -> str:
    """Insert one row with a correctly-chained hmac.

    Caller is responsible for opening the connection and committing.
    Inside this function we BEGIN IMMEDIATE to serialise the
    read-prev-then-compute-then-insert sequence; concurrent writers
    will queue rather than race the chain.

    Returns the new row's hmac so the caller can assert / log it.
    """
    conn.execute("BEGIN IMMEDIATE")
    prev = conn.execute(
        f"SELECT hmac FROM {table} ORDER BY id DESC LIMIT 1"
    ).fetchone()
    prev_hmac = prev[0] if prev else None

    row_with_chain = dict(row)
    row_with_chain["hmac"] = compute_hmac(prev_hmac, row)

    cols = ", ".join(row_with_chain.keys())
    placeholders = ", ".join("?" for _ in row_with_chain)
    conn.execute(
        f"INSERT INTO {table} ({cols}) VALUES ({placeholders})",
        tuple(row_with_chain.values()),
    )
    conn.commit()
    return row_with_chain["hmac"]


def verify_chain(
    conn: sqlite3.Connection,
    table: str,
    columns: list,
) -> Optional[int]:
    """Walk every row in `table` (id ASC) and recompute the hmac chain.

    `columns` is the list of column names to include in the canonical
    serialisation, in the order they appear. Returns the id of the
    first row whose stored hmac doesn't match the recomputed value, or
    None if the entire chain is intact.
    """
    cursor = conn.execute(
        f"SELECT id, {', '.join(columns)}, hmac FROM {table} ORDER BY id ASC"
    )
    prev_hmac: Optional[str] = None
    for row in cursor:
        row_id = row[0]
        stored_hmac = row[-1]
        row_dict = dict(zip(columns, row[1:-1]))
        expected = compute_hmac(prev_hmac, row_dict)
        if not hmac.compare_digest(expected, stored_hmac or ""):
            logger.critical(
                "[AUDIT_CHAIN] tamper detected in %s at row id=%s",
                table, row_id,
            )
            return row_id
        prev_hmac = stored_hmac
    return None
