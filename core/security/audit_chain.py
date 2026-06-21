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

Tail-truncation defence (checkpoints)
-------------------------------------
A per-row chain detects MODIFICATION of any existing row, but not
TAIL TRUNCATION: an attacker who simply deletes the last N rows
leaves a shorter — yet still internally valid — chain. Nothing in
the chain itself records how long it should be.

`write_checkpoint` closes that gap by recording a signed attestation
of the current chain head into a sidecar `<table>_checkpoint` table:

    HMAC(key, table_name || max_row_id || head_hmac || count)

`verify_checkpoint` re-derives that attestation from the live table
and compares against the last stored checkpoint. If the row count or
head no longer matches (or has shrunk below) the attested value, the
tail has been truncated even though every surviving row still chains
cleanly. The checkpoint is signed with the same runtime HMAC key, so
an attacker who lacks the key cannot forge a fresh checkpoint over the
truncated table.

Two callers today:
- core/memory/audit_log.py (memory_access_log)
- core/security/dispatch_audit.py (dispatch_log)
"""

import hashlib
import hmac
import json
import logging
import sqlite3
from typing import Any, Dict, NamedTuple, Optional

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


# ── Checkpoints: tail-truncation defence ─────────────────────────────────

def _checkpoint_table(table: str) -> str:
    """Name of the sidecar checkpoint table for `table`."""
    return f"{table}_checkpoint"


class ChainHead(NamedTuple):
    """A snapshot of a chain's tail: highest row id, that row's hmac,
    and the total row count. `head_hmac` is empty for an empty table."""
    max_row_id: int
    head_hmac: str
    count: int


def _read_head(conn: sqlite3.Connection, table: str) -> ChainHead:
    """Read the live chain head (max id, its hmac, row count)."""
    row = conn.execute(
        f"SELECT id, hmac FROM {table} ORDER BY id DESC LIMIT 1"
    ).fetchone()
    count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    if row is None:
        return ChainHead(max_row_id=0, head_hmac="", count=0)
    return ChainHead(max_row_id=row[0], head_hmac=row[1] or "", count=count)


def _attest(table: str, head: ChainHead) -> str:
    """Sign a chain head into a checkpoint attestation hmac.

    The signed message binds the table name, the highest row id, the
    head row's hmac, and the count together. Same runtime key as the
    row chain; never serialised.
    """
    message = "\x00".join((
        table,
        str(head.max_row_id),
        head.head_hmac,
        str(head.count),
    )).encode("utf-8")
    return hmac.new(_key(), message, hashlib.sha256).hexdigest()


def _ensure_checkpoint_table(conn: sqlite3.Connection, table: str) -> None:
    """Create the sidecar checkpoint table if absent (idempotent)."""
    ckpt = _checkpoint_table(table)
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS {ckpt} (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT    NOT NULL,
            max_row_id  INTEGER NOT NULL,
            head_hmac   TEXT    NOT NULL DEFAULT '',
            count       INTEGER NOT NULL,
            hmac        TEXT    NOT NULL
        )
    """)


def write_checkpoint(
    conn: sqlite3.Connection,
    table: str,
) -> Optional[ChainHead]:
    """Record a signed attestation of `table`'s current chain head.

    Appends one row to the `<table>_checkpoint` sidecar table holding
    the head (max id, head hmac, count) plus an attestation hmac over
    all of them. Later truncation of the main table's tail can then be
    detected by `verify_checkpoint` even though the surviving rows
    still chain cleanly.

    Caller owns the connection; we BEGIN IMMEDIATE so the head read and
    checkpoint insert can't race a concurrent append. Crash-never:
    logs and returns None on failure rather than propagating.

    Returns the attested ChainHead, or None if the write failed.
    """
    from datetime import datetime, timezone
    try:
        conn.execute("BEGIN IMMEDIATE")
        _ensure_checkpoint_table(conn, table)
        head = _read_head(conn, table)
        attestation = _attest(table, head)
        conn.execute(
            f"INSERT INTO {_checkpoint_table(table)} "
            "(ts, max_row_id, head_hmac, count, hmac) "
            "VALUES (?, ?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(),
             head.max_row_id, head.head_hmac, head.count, attestation),
        )
        conn.commit()
        return head
    except Exception as exc:  # noqa: BLE001 — crash-never by contract
        logger.error("[AUDIT_CHAIN] checkpoint write failed for %s: %s",
                     table, exc)
        try:
            conn.rollback()
        except Exception:
            logger.debug("Suppressed rollback exception", exc_info=True)
        return None


def latest_checkpoint(
    conn: sqlite3.Connection,
    table: str,
) -> Optional[ChainHead]:
    """Return the most recent *valid* checkpoint for `table`, or None.

    "Valid" means its stored attestation hmac re-derives correctly
    under the runtime key — a checkpoint row whose hmac doesn't verify
    is treated as forged/corrupt and skipped (we walk newest-first
    until we find a genuine one).
    """
    try:
        ckpt = _checkpoint_table(table)
        try:
            cursor = conn.execute(
                f"SELECT max_row_id, head_hmac, count, hmac FROM {ckpt} "
                "ORDER BY id DESC"
            )
        except sqlite3.OperationalError:
            return None  # no checkpoint table yet
        for max_row_id, head_hmac, count, stored in cursor:
            head = ChainHead(max_row_id=max_row_id,
                             head_hmac=head_hmac or "", count=count)
            expected = _attest(table, head)
            if hmac.compare_digest(expected, stored or ""):
                return head
        return None
    except Exception as exc:  # noqa: BLE001 — crash-never by contract
        logger.error("[AUDIT_CHAIN] checkpoint read failed for %s: %s",
                     table, exc)
        return None


class CheckpointResult(NamedTuple):
    """Outcome of `verify_checkpoint`.

    - ok            : True iff no tampering detected.
    - tampered_row  : id of the first modified row (per-row check), or
                      None.
    - truncated     : True iff the live tail is shorter than / no
                      longer matches the attested checkpoint.
    """
    ok: bool
    tampered_row: Optional[int]
    truncated: bool


def verify_checkpoint(
    conn: sqlite3.Connection,
    table: str,
    columns: list,
) -> CheckpointResult:
    """Full tamper check: per-row modification AND tail truncation.

    Runs `verify_chain` first (catches in-place edits / forged rows).
    Then, if a valid checkpoint exists, compares the live chain head
    against the attestation: a live count below the attested count, or
    a head id/hmac that no longer matches the attested head, means the
    tail was truncated even though survivors chain cleanly.

    With no checkpoint on record, only the per-row result is reported
    (`truncated=False`) — there is nothing to truncate against.

    Crash-never: on unexpected error returns a non-ok result rather
    than raising.
    """
    try:
        tampered_row = verify_chain(conn, table, columns)

        attested = latest_checkpoint(conn, table)
        truncated = False
        if attested is not None:
            live = _read_head(conn, table)
            # Truncation = the live chain is shorter than, or its head
            # has diverged from, what we attested. A clean append-only
            # growth keeps count >= attested.count AND, at the attested
            # length, the same head — but here we only hold the head, so
            # a strictly smaller count, or an equal count with a
            # different head/id, is the truncation/rewrite signal.
            if live.count < attested.count:
                truncated = True
            elif (live.count == attested.count and
                  (live.max_row_id != attested.max_row_id or
                   not hmac.compare_digest(live.head_hmac,
                                           attested.head_hmac))):
                truncated = True
            if truncated:
                logger.critical(
                    "[AUDIT_CHAIN] tail truncation detected in %s "
                    "(attested count=%s head id=%s; live count=%s head id=%s)",
                    table, attested.count, attested.max_row_id,
                    live.count, live.max_row_id,
                )

        return CheckpointResult(
            ok=(tampered_row is None and not truncated),
            tampered_row=tampered_row,
            truncated=truncated,
        )
    except Exception as exc:  # noqa: BLE001 — crash-never by contract
        logger.error("[AUDIT_CHAIN] verify_checkpoint failed for %s: %s",
                     table, exc)
        return CheckpointResult(ok=False, tampered_row=None, truncated=False)
