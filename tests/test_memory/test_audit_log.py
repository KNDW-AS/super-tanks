"""
Tests for core/memory/audit_log.py.

The module caches a singleton connection in module-level `_conn`. The
fixture resets that singleton, redirects DB_PATH to a tmp file, and
runs each test against a clean append-only log.
"""

import pytest


@pytest.fixture
def audit(tmp_path, monkeypatch):
    from core.memory import audit_log

    # Reset singleton and redirect DB.
    monkeypatch.setattr(audit_log, "_conn", None)
    monkeypatch.setattr(audit_log, "DB_PATH", tmp_path / "memory_audit.db")
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


# ── Singleton connection ───────────────────────────────────────────────────

class TestSingletonConnection:
    def test_get_connection_caches(self, audit):
        c1 = audit._get_connection()
        c2 = audit._get_connection()
        assert c1 is c2

    def test_table_created_on_first_call(self, audit):
        conn = audit._get_connection()
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='memory_access_log'"
        ).fetchone()
        assert row is not None
