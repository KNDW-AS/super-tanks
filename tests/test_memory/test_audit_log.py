"""
Tests for core/memory/audit_log.py.

The module opens a fresh sqlite3 connection per write to avoid the
cross-thread cursor interleaving the previous singleton suffered. The
fixture redirects DB_PATH to a tmp file and resets the one-shot
init flag so each test starts with a clean schema.
"""

import threading

import pytest


@pytest.fixture
def audit(tmp_path, monkeypatch):
    from core.memory import audit_log

    monkeypatch.setattr(audit_log, "DB_PATH", tmp_path / "memory_audit.db")
    monkeypatch.setattr(audit_log, "_initialised", False)
    return audit_log


# ── log_access / get_recent_access ─────────────────────────────────────────

class TestLogAccess:
    def test_single_entry_round_trip(self, audit):
        audit.log_access(
            agent_id="aeris", operation="READ", path="/family/preferences",
            detail_level=2, mode="autonomous", accessible=True,
            conversation_id="conv-1", trajectory="lookup",
        )
        rows = audit.get_recent_access()
        assert len(rows) == 1
        r = rows[0]
        assert r["agent_id"] == "aeris"
        assert r["operation"] == "READ"
        assert r["path"] == "/family/preferences"
        assert r["accessible"] == 1
        assert r["mode"] == "autonomous"
        assert r["conversation_id"] == "conv-1"

    def test_denied_access_stored_as_zero(self, audit):
        audit.log_access(agent_id="aeris", operation="READ", path="/x",
                         accessible=False)
        assert audit.get_recent_access()[0]["accessible"] == 0

    def test_defaults_applied(self, audit):
        audit.log_access(agent_id="aeris", operation="READ", path="/x")
        r = audit.get_recent_access()[0]
        assert r["detail_level"] == 2
        assert r["mode"] == "lockdown"
        assert r["accessible"] == 1
        assert r["conversation_id"] == ""
        assert r["trajectory"] == ""

    def test_entries_ordered_newest_first(self, audit):
        for i in range(5):
            audit.log_access(agent_id="aeris", operation="READ",
                             path=f"/p/{i}", trajectory=str(i))
        rows = audit.get_recent_access()
        trajs = [r["trajectory"] for r in rows]
        assert trajs == ["4", "3", "2", "1", "0"]

    def test_limit_respected(self, audit):
        for _ in range(50):
            audit.log_access(agent_id="aeris", operation="READ", path="/x")
        assert len(audit.get_recent_access(limit=10)) == 10

    def test_tripwire_event_stored_with_negative_detail(self, audit):
        # access_control writes detail_level=-1 for tripwires.
        audit.log_access(agent_id="zeph", operation="TRIPWIRE_ACCESS",
                         path="/william/secrets", detail_level=-1,
                         accessible=False)
        r = audit.get_recent_access()[0]
        assert r["detail_level"] == -1
        assert r["operation"] == "TRIPWIRE_ACCESS"
        assert r["accessible"] == 0

    def test_empty_log_returns_empty_list(self, audit):
        assert audit.get_recent_access() == []


# ── Connection lifecycle ──────────────────────────────────────────────────

class TestConnectionLifecycle:
    def test_each_call_opens_fresh_connection(self, audit):
        # New behaviour: per-call connections, not a shared singleton.
        c1 = audit._open()
        c2 = audit._open()
        try:
            assert c1 is not c2
        finally:
            c1.close()
            c2.close()

    def test_table_created_on_first_use(self, audit):
        conn = audit._open()
        try:
            row = conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name='memory_access_log'"
            ).fetchone()
            assert row is not None
        finally:
            conn.close()

    def test_concurrent_writes_do_not_corrupt_each_other(self, audit):
        # 30 threads each log one row. With the old shared-cursor
        # singleton these would interleave; now WAL serializes them at
        # the file level and every row lands.
        N = 30

        def writer(i):
            audit.log_access(agent_id="aeris", operation="WRITE",
                             path=f"/p/{i}", trajectory=str(i))

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(N)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        rows = audit.get_recent_access(limit=100)
        assert len(rows) == N
        # Every trajectory id from 0..N-1 is present.
        observed = {int(r["trajectory"]) for r in rows}
        assert observed == set(range(N))
