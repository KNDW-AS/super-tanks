"""
Tests for core/security/token_budget.py.

Covers per-task and per-day budget enforcement, soft warning threshold,
hard cutoff, unknown-agent fallback to Aeris config, status summary,
and event logging.
"""

import pytest


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
