"""
Tests for scripts/rotate_audit_chain_key.py.

The upgrade path from identity-keyed chains to the dedicated audit
key: after rotation, every chained table must verify under the NEW
audit key, including rows originally chained under the identity key
and legacy rows that were never chained at all.
"""

import hashlib
import hmac as hmac_mod
import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest

_SCRIPT = (Path(__file__).resolve().parent.parent.parent
           / "scripts" / "rotate_audit_chain_key.py")


@pytest.fixture
def rotate(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("rotate_key_test", str(_SCRIPT))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _old_key_chain_insert(conn, table, rows, key):
    """Simulate the pre-upgrade chain: HMAC under the identity key."""
    prev = None
    for row in rows:
        body = json.dumps(row, sort_keys=True, ensure_ascii=False).encode()
        prev_bytes = prev.encode() if prev else b""
        h = hmac_mod.new(key, prev_bytes + body, hashlib.sha256).hexdigest()
        cols = ", ".join(list(row) + ["hmac"])
        ph = ", ".join("?" for _ in range(len(row) + 1))
        conn.execute(f"INSERT INTO {table} ({cols}) VALUES ({ph})",
                     tuple(row.values()) + (h,))
        prev = h
    conn.commit()


class TestRechain:
    def test_identity_keyed_chain_verifies_after_rotation(
            self, rotate, tmp_path, monkeypatch):
        from core.security import agent_identity, audit_chain, audit_key
        monkeypatch.setattr(agent_identity, "_KEY", b"old-identity-key")
        monkeypatch.setattr(audit_key, "_KEY", b"new-audit-key")

        db = tmp_path / "dispatch_audit.db"
        conn = sqlite3.connect(str(db))
        conn.execute("""
            CREATE TABLE dispatch_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, agent_id TEXT, verdict TEXT,
                hmac TEXT NOT NULL DEFAULT ''
            )
        """)
        _old_key_chain_insert(conn, "dispatch_log", [
            {"timestamp": "t0", "agent_id": "aeris", "verdict": "allowed"},
            {"timestamp": "t1", "agent_id": "zeph", "verdict": "denied_role"},
        ], b"old-identity-key")

        columns = rotate._columns(conn, "dispatch_log")
        # Sanity: old chain is clean under old key, broken under new.
        first_bad, empty = rotate._verify_with_key(
            conn, "dispatch_log", columns, b"old-identity-key")
        assert first_bad is None and empty == 0
        assert audit_chain.verify_chain(conn, "dispatch_log", columns) == 1

        rotate._rechain(conn, "dispatch_log", columns)
        assert audit_chain.verify_chain(conn, "dispatch_log", columns) is None
        conn.close()

    def test_unchained_legacy_rows_get_chained(self, rotate, tmp_path,
                                               monkeypatch):
        from core.security import audit_chain, audit_key
        monkeypatch.setattr(audit_key, "_KEY", b"new-audit-key")

        db = tmp_path / "trust_score.db"
        conn = sqlite3.connect(str(db))
        conn.execute("""
            CREATE TABLE trust_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, agent_id TEXT, event_type TEXT,
                hmac TEXT NOT NULL DEFAULT ''
            )
        """)
        conn.execute("INSERT INTO trust_events (timestamp, agent_id, event_type) "
                     "VALUES ('t0', 'aeris', 'successful_task')")
        conn.commit()

        columns = rotate._columns(conn, "trust_events")
        rotate._rechain(conn, "trust_events", columns)
        assert audit_chain.verify_chain(conn, "trust_events", columns) is None
        conn.close()

    def test_columns_excludes_id_and_hmac(self, rotate, tmp_path):
        db = tmp_path / "x.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, a TEXT, "
                     "b REAL, hmac TEXT)")
        assert rotate._columns(conn, "t") == ["a", "b"]
        conn.close()
