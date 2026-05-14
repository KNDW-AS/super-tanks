"""
Tests for core/security/audit_chain.py.

Verifies the chain construction, deterministic hmac computation, and
end-to-end tamper detection on both dispatch_log and memory_access_log.
"""

import sqlite3

import pytest


@pytest.fixture
def chain_env(tmp_path, monkeypatch):
    """Return audit_chain plus a tmp DB with a tiny chain table."""
    from core.security import agent_identity, audit_chain

    monkeypatch.setattr(agent_identity, "_KEY", b"test-key-for-chain")
    db = tmp_path / "chain.db"
    conn = sqlite3.connect(str(db))
    conn.execute("""
        CREATE TABLE log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, agent TEXT, op TEXT,
            hmac TEXT NOT NULL DEFAULT ''
        )
    """)
    conn.commit()
    return audit_chain, conn, db


# ── canonical_bytes / compute_hmac ────────────────────────────────────────

class TestCanonical:
    def test_dict_order_does_not_change_canonical(self, chain_env):
        ac, _, _ = chain_env
        a = ac.canonical_bytes({"a": 1, "b": 2})
        b = ac.canonical_bytes({"b": 2, "a": 1})
        assert a == b

    def test_id_and_hmac_excluded(self, chain_env):
        ac, _, _ = chain_env
        with_meta = ac.canonical_bytes({"id": 99, "hmac": "x", "ts": "now"})
        without = ac.canonical_bytes({"ts": "now"})
        assert with_meta == without

    def test_compute_hmac_is_deterministic(self, chain_env):
        ac, _, _ = chain_env
        h1 = ac.compute_hmac(None, {"ts": "2024", "agent": "aeris"})
        h2 = ac.compute_hmac(None, {"ts": "2024", "agent": "aeris"})
        assert h1 == h2

    def test_chain_links_change_with_prev(self, chain_env):
        ac, _, _ = chain_env
        h_first = ac.compute_hmac(None, {"x": 1})
        h_second = ac.compute_hmac(h_first, {"x": 2})
        h_alt = ac.compute_hmac("different-prev", {"x": 2})
        # Same row content but different predecessor → different hmac.
        assert h_second != h_alt


# ── append_chained / verify_chain ─────────────────────────────────────────

class TestChainEnd2End:
    def test_clean_chain_verifies(self, chain_env):
        ac, conn, _ = chain_env
        for i in range(5):
            ac.append_chained(conn, "log",
                              {"ts": f"t{i}", "agent": "aeris", "op": "READ"})
        assert ac.verify_chain(conn, "log", ["ts", "agent", "op"]) is None

    def test_tampered_row_detected(self, chain_env):
        ac, conn, _ = chain_env
        for i in range(3):
            ac.append_chained(conn, "log",
                              {"ts": f"t{i}", "agent": "aeris", "op": "READ"})
        # Tamper with row 2's `op` column directly.
        conn.execute("UPDATE log SET op='DELETE' WHERE id=2")
        conn.commit()
        first_bad = ac.verify_chain(conn, "log", ["ts", "agent", "op"])
        assert first_bad == 2

    def test_inserted_forged_row_breaks_chain(self, chain_env):
        ac, conn, _ = chain_env
        for i in range(3):
            ac.append_chained(conn, "log",
                              {"ts": f"t{i}", "agent": "aeris", "op": "READ"})
        # Insert a row with a forged hmac (attacker has access to the
        # DB but not the HMAC key).
        conn.execute(
            "INSERT INTO log (ts, agent, op, hmac) "
            "VALUES (?, ?, ?, ?)",
            ("forged-ts", "william", "ADMIN", "deadbeef" * 8))
        conn.commit()
        # The forged row's hmac doesn't match what the chain expects.
        first_bad = ac.verify_chain(conn, "log", ["ts", "agent", "op"])
        assert first_bad == 4  # the forged row

    def test_first_row_uses_empty_prev(self, chain_env):
        ac, conn, _ = chain_env
        h = ac.append_chained(conn, "log",
                              {"ts": "t0", "agent": "x", "op": "Y"})
        # Reproduce the same hmac with prev=None to confirm the
        # "first row" semantic.
        expected = ac.compute_hmac(None,
                                   {"ts": "t0", "agent": "x", "op": "Y"})
        assert h == expected


# ── Real audit_log integration ────────────────────────────────────────────

class TestAuditLogIntegration:
    def test_round_trip_with_chain(self, tmp_path, monkeypatch):
        from core.memory import audit_log
        from core.security import agent_identity
        monkeypatch.setattr(agent_identity, "_KEY", b"test-audit-key")
        monkeypatch.setattr(audit_log, "DB_PATH", tmp_path / "audit.db")
        monkeypatch.setattr(audit_log, "_initialised", False)

        for i in range(4):
            audit_log.log_access(
                agent_id="aeris", operation="READ",
                path=f"/family/preferences/{i}",
            )
        assert audit_log.verify_audit_chain() is None

    def test_tampered_audit_row_detected(self, tmp_path, monkeypatch):
        from core.memory import audit_log
        from core.security import agent_identity
        monkeypatch.setattr(agent_identity, "_KEY", b"test-audit-key-2")
        monkeypatch.setattr(audit_log, "DB_PATH", tmp_path / "audit.db")
        monkeypatch.setattr(audit_log, "_initialised", False)

        audit_log.log_access(agent_id="aeris", operation="WRITE",
                             path="/family/preferences/lighting",
                             accessible=False)
        audit_log.log_access(agent_id="aeris", operation="READ",
                             path="/family/preferences/lighting")
        # Attacker rewrites the WRITE row's `accessible` field to hide
        # the denial.
        conn = sqlite3.connect(str(audit_log.DB_PATH))
        try:
            conn.execute("UPDATE memory_access_log SET accessible=1 WHERE id=1")
            conn.commit()
        finally:
            conn.close()
        # Verify catches it.
        assert audit_log.verify_audit_chain() == 1


class TestDispatchAuditIntegration:
    def test_round_trip_with_chain(self, tmp_path, monkeypatch):
        from core.security import dispatch_audit, agent_identity
        monkeypatch.setattr(agent_identity, "_KEY", b"test-dispatch-key")
        monkeypatch.setattr(dispatch_audit, "DB_PATH", tmp_path / "dispatch.db")
        monkeypatch.setattr(dispatch_audit, "_initialised", False)

        for i in range(3):
            dispatch_audit.record_dispatch(
                correlation_id=f"corr-{i}", agent_id="aeris",
                tool_name="ha_search", agent_role="READ",
                verdict="allowed", result_success=True,
            )
        assert dispatch_audit.verify_dispatch_chain() is None

    def test_tampered_dispatch_row_detected(self, tmp_path, monkeypatch):
        from core.security import dispatch_audit, agent_identity
        monkeypatch.setattr(agent_identity, "_KEY", b"test-dispatch-key-2")
        monkeypatch.setattr(dispatch_audit, "DB_PATH", tmp_path / "dispatch.db")
        monkeypatch.setattr(dispatch_audit, "_initialised", False)

        dispatch_audit.record_dispatch(
            correlation_id="x", agent_id="aeris", tool_name="shell_exec",
            agent_role="EXEC", verdict="denied_role",
            result_success=False, error="denied",
        )
        dispatch_audit.record_dispatch(
            correlation_id="y", agent_id="aeris", tool_name="ha_search",
            agent_role="READ", verdict="allowed", result_success=True,
        )
        # Attacker promotes the denied row to "allowed".
        conn = sqlite3.connect(str(dispatch_audit.DB_PATH))
        try:
            conn.execute("UPDATE dispatch_log SET verdict='allowed' WHERE id=1")
            conn.commit()
        finally:
            conn.close()
        assert dispatch_audit.verify_dispatch_chain() == 1
