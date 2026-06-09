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

    def test_pending_ordered_by_queued_at_not_id(self, night_queue_db):
        # The earlier version inserted three rows and asserted IDs were
        # in sorted order — trivially true because both id and timestamp
        # are monotonic on insertion. If somebody swapped the ORDER BY
        # to `id` the test would still pass. Backdate one of the rows
        # to verify ORDER BY queued_at actually applies.
        night_queue_db.queue_action("zeph", "tool_a", {"i": 0})
        second = night_queue_db.queue_action("zeph", "tool_b", {"i": 1})
        # Backdate the second-inserted row so its queued_at is the
        # oldest. ORDER BY queued_at must then put it first.
        conn = night_queue_db._get_conn()
        try:
            conn.execute(
                "UPDATE night_queue SET queued_at='2000-01-01T00:00:00' "
                "WHERE id=?",
                (second["queue_id"],))
            conn.commit()
        finally:
            conn.close()
        pending = night_queue_db.get_pending()
        # Backdated row should come first.
        assert pending[0]["tool_name"] == "tool_b"
        assert pending[1]["tool_name"] == "tool_a"

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


# ── _ensure_db lazy bootstrap ──────────────────────────────────────────────

class TestEnsureDb:
    def test_skips_when_already_initialised(self, night_queue_db, monkeypatch):
        # Fast-path: the unlocked `if _initialised: return` at the top of
        # _ensure_db must early-exit without taking the lock or calling
        # _init_db. After night_queue_db fixture runs, _initialised=True.
        called = []
        monkeypatch.setattr(night_queue_db, "_init_db",
                            lambda: called.append(1))
        night_queue_db._ensure_db()
        assert called == []

    def test_double_checked_lock_skips_when_winner_already_inited(
            self, night_queue_db, monkeypatch):
        # The second `if _initialised: return` inside the lock (line 47)
        # handles the case where another thread set the flag while we
        # waited for the lock. Simulate by entering _ensure_db with
        # _initialised=False, but flipping it to True while the lock is
        # contended.
        monkeypatch.setattr(night_queue_db, "_initialised", False)
        called = []
        monkeypatch.setattr(night_queue_db, "_init_db",
                            lambda: called.append(1))

        original_lock = night_queue_db._init_lock

        class FlippingLock:
            def __enter__(self_inner):
                # Pretend a competing thread won the race: flip the flag
                # before _ensure_db re-checks it inside the critical
                # section. The inner `if _initialised: return` (line 47)
                # must trigger.
                monkeypatch.setattr(night_queue_db, "_initialised", True)
                return original_lock.__enter__()

            def __exit__(self_inner, *a):
                return original_lock.__exit__(*a)

        monkeypatch.setattr(night_queue_db, "_init_lock", FlippingLock())
        night_queue_db._ensure_db()
        # _init_db must not have been invoked — line 47 short-circuited.
        assert called == []

    def test_init_failure_resets_flag_and_reraises(
            self, night_queue_db, monkeypatch):
        # When _init_db raises, _ensure_db must reset _initialised to
        # False (so the next caller retries) and propagate the error.
        monkeypatch.setattr(night_queue_db, "_initialised", False)

        def boom():
            raise RuntimeError("schema bootstrap failed")

        monkeypatch.setattr(night_queue_db, "_init_db", boom)

        with pytest.raises(RuntimeError, match="schema bootstrap failed"):
            night_queue_db._ensure_db()

        # Critical: flag must be cleared so a retry can succeed.
        assert night_queue_db._initialised is False
