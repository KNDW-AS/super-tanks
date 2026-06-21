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


# ── Checkpoints: tail-truncation defence ──────────────────────────────────

class TestCheckpoint:
    def _seed(self, ac, conn, n):
        for i in range(n):
            ac.append_chained(conn, "log",
                              {"ts": f"t{i}", "agent": "aeris", "op": "READ"})

    def test_checkpoint_roundtrip(self, chain_env):
        ac, conn, _ = chain_env
        self._seed(ac, conn, 5)
        head = ac.write_checkpoint(conn, "log")
        assert head is not None
        assert head.count == 5
        assert head.max_row_id == 5
        assert head.head_hmac  # non-empty
        # latest_checkpoint re-derives the same head from the sidecar.
        restored = ac.latest_checkpoint(conn, "log")
        assert restored == head

    def test_empty_table_checkpoint(self, chain_env):
        ac, conn, _ = chain_env
        head = ac.write_checkpoint(conn, "log")
        assert head is not None
        assert head == ac.ChainHead(max_row_id=0, head_hmac="", count=0)
        # verify against the empty attestation: clean.
        res = ac.verify_checkpoint(conn, "log", ["ts", "agent", "op"])
        assert res.ok is True
        assert res.truncated is False

    def test_clean_chain_with_checkpoint_passes(self, chain_env):
        ac, conn, _ = chain_env
        self._seed(ac, conn, 4)
        ac.write_checkpoint(conn, "log")
        res = ac.verify_checkpoint(conn, "log", ["ts", "agent", "op"])
        assert res == ac.CheckpointResult(ok=True, tampered_row=None,
                                          truncated=False)

    def test_continued_appends_after_checkpoint_pass(self, chain_env):
        ac, conn, _ = chain_env
        self._seed(ac, conn, 3)
        ac.write_checkpoint(conn, "log")
        # Legitimate growth beyond the checkpoint must not look like
        # tampering or truncation.
        self._seed(ac, conn, 2)
        res = ac.verify_checkpoint(conn, "log", ["ts", "agent", "op"])
        assert res.ok is True
        assert res.truncated is False
        assert res.tampered_row is None

    def test_modified_row_detected_via_checkpoint(self, chain_env):
        ac, conn, _ = chain_env
        self._seed(ac, conn, 3)
        ac.write_checkpoint(conn, "log")
        conn.execute("UPDATE log SET op='DELETE' WHERE id=2")
        conn.commit()
        res = ac.verify_checkpoint(conn, "log", ["ts", "agent", "op"])
        assert res.ok is False
        assert res.tampered_row == 2

    def test_tail_truncation_detected_via_checkpoint(self, chain_env):
        ac, conn, _ = chain_env
        self._seed(ac, conn, 5)
        ac.write_checkpoint(conn, "log")
        # Attacker deletes the last two rows. The surviving 3-row chain
        # still verifies per-row (verify_chain returns None)...
        conn.execute("DELETE FROM log WHERE id > 3")
        conn.commit()
        assert ac.verify_chain(conn, "log", ["ts", "agent", "op"]) is None
        # ...but the checkpoint catches the missing tail.
        res = ac.verify_checkpoint(conn, "log", ["ts", "agent", "op"])
        assert res.ok is False
        assert res.truncated is True
        assert res.tampered_row is None

    def test_head_rewrite_at_same_count_detected(self, chain_env):
        ac, conn, _ = chain_env
        self._seed(ac, conn, 3)
        ac.write_checkpoint(conn, "log")
        # Delete the real head and insert a forged replacement so the
        # count is unchanged but the head id/hmac differs.
        conn.execute("DELETE FROM log WHERE id=3")
        conn.execute(
            "INSERT INTO log (ts, agent, op, hmac) VALUES (?, ?, ?, ?)",
            ("forged", "william", "ADMIN", "deadbeef" * 8))
        conn.commit()
        res = ac.verify_checkpoint(conn, "log", ["ts", "agent", "op"])
        assert res.ok is False
        assert res.truncated is True

    def test_no_checkpoint_means_no_truncation_signal(self, chain_env):
        ac, conn, _ = chain_env
        self._seed(ac, conn, 3)
        # No checkpoint written: verify_checkpoint reports per-row only.
        res = ac.verify_checkpoint(conn, "log", ["ts", "agent", "op"])
        assert res.ok is True
        assert res.truncated is False
        assert res.tampered_row is None

    def test_forged_checkpoint_ignored(self, chain_env):
        ac, conn, _ = chain_env
        self._seed(ac, conn, 3)
        ac.write_checkpoint(conn, "log")
        # Attacker truncates the tail, then forges a fresh checkpoint
        # row over the shorter table — but without the key the
        # attestation hmac is wrong, so it's skipped and the genuine
        # earlier checkpoint still wins.
        conn.execute("DELETE FROM log WHERE id > 1")
        conn.execute(
            f"INSERT INTO log_checkpoint "
            "(ts, max_row_id, head_hmac, count, hmac) "
            "VALUES (?, ?, ?, ?, ?)",
            ("forged-ts", 1, "whatever", 1, "deadbeef" * 8))
        conn.commit()
        # latest_checkpoint skips the forged row, returns the real one.
        good = ac.latest_checkpoint(conn, "log")
        assert good is not None
        assert good.count == 3
        res = ac.verify_checkpoint(conn, "log", ["ts", "agent", "op"])
        assert res.ok is False
        assert res.truncated is True

    def test_latest_checkpoint_picks_newest(self, chain_env):
        ac, conn, _ = chain_env
        self._seed(ac, conn, 2)
        ac.write_checkpoint(conn, "log")
        self._seed(ac, conn, 3)
        second = ac.write_checkpoint(conn, "log")
        assert ac.latest_checkpoint(conn, "log") == second
        assert second.count == 5


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
