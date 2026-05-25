"""
Tests for core/security/token_budget.py.

Covers per-task and per-day budget enforcement, soft warning threshold,
hard cutoff, unknown-agent fallback to Aeris config, status summary,
and event logging.
"""

import pytest

from core.security import token_budget


# ── record_usage / get_daily_usage ─────────────────────────────────────────

class TestRecordUsage:
    def test_single_entry_summed(self, budget_db):
        budget_db.record_usage("aeris", 500, task_id="t1", provider="openai")
        assert budget_db.get_daily_usage("aeris") == 500

    def test_multiple_entries_summed(self, budget_db):
        budget_db.record_usage("aeris", 500)
        budget_db.record_usage("aeris", 700)
        budget_db.record_usage("aeris", 100)
        assert budget_db.get_daily_usage("aeris") == 1300

    def test_per_agent_isolation(self, budget_db):
        budget_db.record_usage("aeris", 500)
        budget_db.record_usage("zeph", 1000)
        assert budget_db.get_daily_usage("aeris") == 500
        assert budget_db.get_daily_usage("zeph") == 1000

    def test_unknown_agent_returns_zero(self, budget_db):
        assert budget_db.get_daily_usage("ghost") == 0


# ── check_budget ───────────────────────────────────────────────────────────

class TestCheckBudget:
    def test_clean_state_allows_with_no_alert(self, budget_db):
        result = budget_db.check_budget("aeris")
        assert result["allowed"] is True
        assert result["alert"] is None
        assert result["daily_pct"] == 0.0

    def test_soft_warning_at_80_percent(self, budget_db):
        # Aeris daily_limit = 100_000, soft = 0.80
        budget_db.record_usage("aeris", 80_000)
        result = budget_db.check_budget("aeris")
        assert result["allowed"] is True
        assert result["alert"] == "soft_warning"
        assert result["daily_pct"] == pytest.approx(0.8)

    def test_no_warning_below_80_percent(self, budget_db):
        budget_db.record_usage("aeris", 79_999)
        result = budget_db.check_budget("aeris")
        assert result["alert"] is None

    def test_hard_cutoff_at_100_percent(self, budget_db):
        budget_db.record_usage("aeris", 100_000)
        result = budget_db.check_budget("aeris")
        assert result["allowed"] is False
        assert result["alert"] == "hard_cutoff"
        assert result["daily_pct"] == 1.0

    def test_hard_cutoff_beyond_limit(self, budget_db):
        budget_db.record_usage("aeris", 200_000)
        result = budget_db.check_budget("aeris")
        assert result["allowed"] is False
        assert result["alert"] == "hard_cutoff"

    def test_per_task_limit_enforced(self, budget_db):
        # Aeris per_task_limit = 5_000
        budget_db.record_usage("aeris", 5_000, task_id="task-A")
        result = budget_db.check_budget("aeris", task_id="task-A")
        assert result["allowed"] is False
        assert result["alert"] == "task_limit"

    def test_per_task_limit_isolates_tasks(self, budget_db):
        budget_db.record_usage("aeris", 5_000, task_id="task-A")
        # A different task is fine.
        result = budget_db.check_budget("aeris", task_id="task-B")
        assert result["allowed"] is True

    def test_unknown_agent_uses_aeris_config(self, budget_db):
        result = budget_db.check_budget("ghost")
        assert result["daily_limit"] == 100_000

    def test_zeph_has_higher_limit(self, budget_db):
        budget_db.record_usage("zeph", 100_000)
        result = budget_db.check_budget("zeph")
        assert result["allowed"] is True  # Zeph limit is 200k
        assert result["daily_pct"] == pytest.approx(0.5)


# ── get_budget_status ──────────────────────────────────────────────────────

class TestGetBudgetStatus:
    def test_empty_status(self, budget_db):
        s = budget_db.get_budget_status()
        assert s["aeris"]["used"] == 0
        assert s["aeris"]["remaining"] == 100_000
        assert s["zeph"]["used"] == 0
        assert s["zeph"]["remaining"] == 200_000

    def test_status_after_usage(self, budget_db):
        budget_db.record_usage("aeris", 25_000)
        s = budget_db.get_budget_status()
        assert s["aeris"]["used"] == 25_000
        assert s["aeris"]["pct"] == pytest.approx(0.25)
        assert s["aeris"]["remaining"] == 75_000

    def test_remaining_never_negative(self, budget_db):
        budget_db.record_usage("aeris", 250_000)  # over limit
        s = budget_db.get_budget_status()
        assert s["aeris"]["remaining"] == 0


# ── _log_event ─────────────────────────────────────────────────────────────

class TestEventLogging:
    def test_task_limit_logs_event(self, budget_db):
        budget_db.record_usage("aeris", 5_000, task_id="t")
        budget_db.check_budget("aeris", task_id="t")
        # Direct DB inspection — module doesn't expose a public reader.
        conn = budget_db._get_conn()
        try:
            rows = conn.execute(
                "SELECT event_type FROM budget_events WHERE agent_id=?",
                ("aeris",)).fetchall()
        finally:
            conn.close()
        assert any(r[0] == "task_limit_hit" for r in rows)

    def test_hard_cutoff_logs_event(self, budget_db):
        budget_db.record_usage("aeris", 150_000)
        budget_db.check_budget("aeris")
        conn = budget_db._get_conn()
        try:
            rows = conn.execute(
                "SELECT event_type FROM budget_events WHERE agent_id=?",
                ("aeris",)).fetchall()
        finally:
            conn.close()
        assert any(r[0] == "daily_hard_cutoff" for r in rows)

    def test_soft_warning_does_not_log_event(self, budget_db):
        # Only hard cutoff / task limit log events — soft warnings stay
        # in-memory only. This documents the current behaviour.
        budget_db.record_usage("aeris", 85_000)
        budget_db.check_budget("aeris")
        conn = budget_db._get_conn()
        try:
            rows = conn.execute(
                "SELECT COUNT(*) FROM budget_events WHERE agent_id=?",
                ("aeris",)).fetchone()
        finally:
            conn.close()
        assert rows[0] == 0


# ── _ensure_db (lazy schema bootstrap) ─────────────────────────────────────

class TestEnsureDb:
    """Cover the double-checked-locking and exception-rollback paths in
    `_ensure_db`. The fixture is *not* used here: we control the
    `_initialised` flag directly to exercise the locked branches."""

    def test_fast_path_returns_when_already_initialised(self, monkeypatch):
        # Outer check on line 43 short-circuits — no lock acquired, no
        # _init_db call.
        monkeypatch.setattr(token_budget, "_initialised", True)
        called = []
        monkeypatch.setattr(token_budget, "_init_db",
                            lambda: called.append(1))
        token_budget._ensure_db()
        assert called == []

    def test_double_checked_lock_second_check_returns(self, monkeypatch):
        # Simulate the race: outer check sees False, but by the time we
        # acquire the lock another thread has flipped the flag. The
        # inner check on line 46-47 must short-circuit and skip
        # _init_db. We synthesise the race by wrapping the lock's
        # __enter__ to set _initialised=True before the body runs.
        monkeypatch.setattr(token_budget, "_initialised", False)
        called = []
        monkeypatch.setattr(token_budget, "_init_db",
                            lambda: called.append(1))

        real_lock = token_budget._init_lock

        class RacingLock:
            def __enter__(self_inner):
                # Another "thread" finished bootstrap first.
                token_budget._initialised = True
                return real_lock.__enter__()

            def __exit__(self_inner, *exc):
                return real_lock.__exit__(*exc)

        monkeypatch.setattr(token_budget, "_init_lock", RacingLock())
        token_budget._ensure_db()
        # Inner guard tripped → _init_db was NOT invoked.
        assert called == []
        assert token_budget._initialised is True

    def test_init_failure_resets_flag_and_reraises(self, monkeypatch):
        # If _init_db blows up (e.g. disk full, permission denied) the
        # bootstrap must roll the flag back so a later call retries
        # instead of silently leaving an unmigrated DB.
        monkeypatch.setattr(token_budget, "_initialised", False)

        def boom():
            raise RuntimeError("simulated sqlite failure")

        monkeypatch.setattr(token_budget, "_init_db", boom)

        with pytest.raises(RuntimeError, match="simulated sqlite failure"):
            token_budget._ensure_db()
        # The except branch on lines 51-53 must have reset the flag.
        assert token_budget._initialised is False
