#!/usr/bin/env python3
"""
scripts/rotate_audit_chain_key.py
==================================
One-time migration: re-chain existing audit tables under the dedicated
audit-chain key.

Before this release the audit chains (dispatch_log, memory_access_log,
threats) were HMAC'd with the *identity* key. The keys are now
separated (STA-01 Threat 06) — new rows chain under
`data/.audit_chain_key`, so pre-upgrade rows would fail verification
and trip the threat monitor into SAFE_MODE.

Run this ONCE after upgrading, while the system is stopped:

    python scripts/rotate_audit_chain_key.py

For each chained table it:
  1. Verifies the existing chain under the OLD (identity) key and
     reports the result — the chain is only evidence up to this point
     if that verification passes. Rows written before chaining existed
     (hmac='') are reported too.
  2. Recomputes every row's hmac under the NEW audit key, making the
     full history verifiable going forward.

Also chains any legacy rows in trust_events / approval_events that
pre-date those tables' chaining.
"""

import sqlite3
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

DATA = REPO_ROOT / "data"

# (db_path, table) for every chained table in the system.
TABLES = [
    (DATA / "dispatch_audit.db", "dispatch_log"),
    (DATA / "memory_audit.db", "memory_access_log"),
    (DATA / "threat_intel.db", "threats"),
    (DATA / "trust_score.db", "trust_events"),
    (DATA / "approval_requests.db", "approval_events"),
]


def _columns(conn: sqlite3.Connection, table: str) -> list:
    """All data columns (everything except id and hmac)."""
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return [r[1] for r in rows if r[1] not in ("id", "hmac")]


def _verify_with_key(conn, table, columns, key: bytes):
    """Walk the chain under an explicit key. Returns (first_bad_id, empty_count)."""
    import hashlib
    import hmac as hmac_mod

    from core.security.audit_chain import canonical_bytes

    prev = None
    first_bad = None
    empty = 0
    for row in conn.execute(
        f"SELECT id, {', '.join(columns)}, hmac FROM {table} ORDER BY id ASC"
    ):
        stored = row[-1]
        if not stored:
            empty += 1
        row_dict = dict(zip(columns, row[1:-1]))
        prev_bytes = prev.encode("utf-8") if prev else b""
        expected = hmac_mod.new(key, prev_bytes + canonical_bytes(row_dict),
                                hashlib.sha256).hexdigest()
        if first_bad is None and not hmac_mod.compare_digest(expected, stored or ""):
            first_bad = row[0]
        prev = stored
    return first_bad, empty


def _rechain(conn, table, columns) -> int:
    """Recompute every hmac under the current (new) audit key."""
    from core.security.audit_chain import compute_hmac

    rows = conn.execute(
        f"SELECT id, {', '.join(columns)} FROM {table} ORDER BY id ASC"
    ).fetchall()
    conn.execute("BEGIN IMMEDIATE")
    prev = None
    for row in rows:
        row_dict = dict(zip(columns, row[1:]))
        new_hmac = compute_hmac(prev, row_dict)
        conn.execute(f"UPDATE {table} SET hmac=? WHERE id=?", (new_hmac, row[0]))
        prev = new_hmac
    conn.commit()
    return len(rows)


def main() -> int:
    from core.security.agent_identity import _load_key as load_identity_key
    from core.security.audit_chain import verify_chain

    old_key = load_identity_key()
    exit_code = 0

    for db_path, table in TABLES:
        if not db_path.exists():
            print(f"— {table}: {db_path} not found, skipping")
            continue
        conn = sqlite3.connect(str(db_path))
        try:
            try:
                columns = _columns(conn, table)
            except sqlite3.OperationalError:
                print(f"— {table}: table missing in {db_path.name}, skipping")
                continue
            if not columns:
                print(f"— {table}: no such table in {db_path.name}, skipping")
                continue

            first_bad, empty = _verify_with_key(conn, table, columns, old_key)
            if first_bad is not None:
                print(f"⚠ {table}: pre-rotation chain NOT clean under old key "
                      f"(first mismatch id={first_bad}, {empty} unchained rows). "
                      f"History before rotation cannot be vouched for.")
            else:
                print(f"✓ {table}: pre-rotation chain clean under old key")

            n = _rechain(conn, table, columns)

            still_bad = verify_chain(conn, table, columns)
            if still_bad is None:
                print(f"✓ {table}: {n} rows re-chained under new audit key")
            else:
                print(f"✗ {table}: re-chain FAILED verification at id={still_bad}")
                exit_code = 1
        finally:
            conn.close()

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
