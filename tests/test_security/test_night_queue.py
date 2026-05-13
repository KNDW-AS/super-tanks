"""
Tests for core/security/night_queue.py.

Verifies SQLite-backed queueing of deferred night-time actions:
insertion, status transitions (pending → executed/dismissed), pruning
of old entries, and morning-report formatting.
"""

from datetime import datetime, timedelta, timezone

import pytest


# ── queue_action / get_pending ─────────────────────────────────────────────

class TestQueueAction:
    def test_inserts_pending_entry(self, night_queue_db):
        result = night_queue_db.queue_action(
            "zeph", "home_assistant", {"entity": "light.x"},
            reason="night defer")
        assert result["queued"] is True
        assert isinstance(result["queue_id"], int)
        assert result["tool"] == "home_assistant"

        pending = night_queue_db.get_pending()
        assert len(pending) == 1
        entry = pending[0]
        assert entry["agent_id"] == "zeph"
        assert entry["tool_name"] == "home_assistant"
        assert entry["params"] == {"entity": "light.x"}
        assert entry["reason"] == "night defer"

    def test_multiple_entries_ordered_by_queued_at(self, night_queue_db):
        for i in range(3):
            night_queue_db.queue_action("zeph", f"tool_{i}", {"i": i})
        ids = [e["id"] for e in night_queue_db.get_pending()]
        assert ids == sorted(ids)

    def test_params_are_json_round_tripped(self, night_queue_db):
        payload = {"nested": {"a": [1, 2, {"æ": "ø"}]}}
        night_queue_db.queue_action("zeph", "x", payload)
        entry = night_queue_db.get_pending()[0]
        assert entry["params"] == payload


# ── mark_executed / mark_dismissed ─────────────────────────────────────────

class TestStatusTransitions:
    def test_executed_removes_from_pending(self, night_queue_db):
        r = night_queue_db.queue_action("zeph", "x", {})
        night_queue_db.mark_executed(r["queue_id"], result="ok")
        assert night_queue_db.get_pending() == []

    def test_dismissed_removes_from_pending(self, night_queue_db):
        r = night_queue_db.queue_action("zeph", "x", {})
        night_queue_db.mark_dismissed(r["queue_id"])
        assert night_queue_db.get_pending() == []

    def test_executed_status_persisted(self, night_queue_db):
        r = night_queue_db.queue_action("zeph", "x", {})
        night_queue_db.mark_executed(r["queue_id"], result="fine")
        conn = night_queue_db._get_conn()
        try:
            row = conn.execute(
                "SELECT status, result FROM night_queue WHERE id=?",
                (r["queue_id"],)).fetchone()
        finally:
            conn.close()
        assert row[0] == "executed"
        assert row[1] == "fine"

    def test_long_result_is_truncated(self, night_queue_db):
        r = night_queue_db.queue_action("zeph", "x", {})
        night_queue_db.mark_executed(r["queue_id"], result="A" * 800)
        conn = night_queue_db._get_conn()
        try:
            row = conn.execute(
                "SELECT result FROM night_queue WHERE id=?",
                (r["queue_id"],)).fetchone()
        finally:
            conn.close()
        assert len(row[0]) == 500


# ── clear_old ──────────────────────────────────────────────────────────────

class TestClearOld:
    def test_only_old_executed_entries_pruned(self, night_queue_db):
        # Insert: one old-executed, one recent-executed, one pending.
        conn = night_queue_db._get_conn()
        old_ts = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        recent_ts = datetime.now(timezone.utc).isoformat()
        try:
            conn.execute(
                "INSERT INTO night_queue "
                "(agent_id, tool_name, params, queued_at, status) "
                "VALUES (?, ?, ?, ?, ?)",
                ("zeph", "old_t", "{}", old_ts, "executed"))
            conn.execute(
                "INSERT INTO night_queue "
                "(agent_id, tool_name, params, queued_at, status) "
                "VALUES (?, ?, ?, ?, ?)",
                ("zeph", "recent_t", "{}", recent_ts, "executed"))
            conn.execute(
                "INSERT INTO night_queue "
                "(agent_id, tool_name, params, queued_at, status) "
                "VALUES (?, ?, ?, ?, ?)",
                ("zeph", "pending_t", "{}", old_ts, "pending"))
            conn.commit()
        finally:
            conn.close()

        night_queue_db.clear_old(days=7)

        conn = night_queue_db._get_conn()
        try:
            tools = [r[0] for r in conn.execute(
                "SELECT tool_name FROM night_queue").fetchall()]
        finally:
            conn.close()
        # Old executed pruned; recent executed and old pending retained.
        assert "old_t" not in tools
        assert "recent_t" in tools
        assert "pending_t" in tools


# ── build_morning_report ───────────────────────────────────────────────────

class TestMorningReport:
    def test_empty_when_no_pending(self, night_queue_db):
        assert night_queue_db.build_morning_report() == ""

    def test_includes_each_pending_item(self, night_queue_db):
        night_queue_db.queue_action("zeph", "home_assistant", {"entity": "light.x"},
                                    reason="defer")
        night_queue_db.queue_action("zeph", "task_add", {"title": "X"})
        report = night_queue_db.build_morning_report()
        assert "2 utsette" in report
        assert "home_assistant" in report
        assert "task_add" in report

    def test_includes_approval_commands(self, night_queue_db):
        night_queue_db.queue_action("zeph", "x", {})
        report = night_queue_db.build_morning_report()
        assert "/approve-morning" in report
        assert "/dismiss-morning" in report
