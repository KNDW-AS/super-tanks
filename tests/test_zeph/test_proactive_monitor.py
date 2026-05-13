"""
Tests for core/zeph/proactive_monitor.py.

Covers schedule-state persistence, due-detection logic, the check
dispatcher, and run_checks aggregation. Individual subprocess-based
checks are out of scope (they shell out to systemctl/journalctl/pip)
but the dispatcher and aggregator are exercised against a stubbed
check registry.
"""

from datetime import datetime, timedelta, timezone

import pytest

from core.zeph import proactive_monitor as pm


@pytest.fixture
def monitor(tmp_path, monkeypatch):
    monkeypatch.setattr(pm, "DATA_DIR", tmp_path)
    monkeypatch.setattr(pm, "SCHEDULE_FILE", tmp_path / "monitor_schedule.json")
    return pm


# ── Schedule state persistence ─────────────────────────────────────────────

class TestScheduleState:
    def test_empty_when_no_file(self, monitor):
        assert monitor._load_schedule_state() == {}

    def test_mark_completed_persists(self, monitor):
        monitor.mark_completed("daily_health")
        state = monitor._load_schedule_state()
        assert "daily_health" in state
        # Round-trips through ISO 8601.
        datetime.fromisoformat(state["daily_health"])

    def test_corrupt_state_is_tolerated(self, monitor):
        monitor.SCHEDULE_FILE.write_text("{ not json")
        assert monitor._load_schedule_state() == {}


# ── check_schedule ─────────────────────────────────────────────────────────

class _FakeDT:
    """datetime stand-in for monkeypatching pm.datetime.

    Returns a configurable "now" while keeping helpers like
    fromisoformat available so the module's own date parsing still works.
    """

    fixed = datetime(2024, 1, 1, 22, 0, tzinfo=timezone.utc)

    @classmethod
    def now(cls, tz=None):
        return cls.fixed

    fromisoformat = staticmethod(datetime.fromisoformat)


class TestCheckSchedule:
    def test_daily_health_due_at_hour_22(self, monitor, monkeypatch):
        # Monday 2024-01-01 22:00 UTC.
        _FakeDT.fixed = datetime(2024, 1, 1, 22, 0, tzinfo=timezone.utc)
        monkeypatch.setattr(monitor, "datetime", _FakeDT)
        due = monitor.check_schedule()
        assert "daily_health" in due

    def test_weekly_security_due_monday_10(self, monitor, monkeypatch):
        # Monday 2024-01-01 10:00 UTC.
        _FakeDT.fixed = datetime(2024, 1, 1, 10, 0, tzinfo=timezone.utc)
        monkeypatch.setattr(monitor, "datetime", _FakeDT)
        due = monitor.check_schedule()
        assert "weekly_security" in due

    def test_weekly_security_not_due_on_other_days(self, monitor, monkeypatch):
        # Tuesday 2024-01-02 10:00.
        _FakeDT.fixed = datetime(2024, 1, 2, 10, 0, tzinfo=timezone.utc)
        monkeypatch.setattr(monitor, "datetime", _FakeDT)
        due = monitor.check_schedule()
        assert "weekly_security" not in due

    def test_monthly_deep_due_first_of_month(self, monitor, monkeypatch):
        _FakeDT.fixed = datetime(2024, 6, 1, 10, 0, tzinfo=timezone.utc)
        monkeypatch.setattr(monitor, "datetime", _FakeDT)
        due = monitor.check_schedule()
        assert "monthly_deep" in due

    def test_monthly_deep_not_due_other_days(self, monitor, monkeypatch):
        _FakeDT.fixed = datetime(2024, 6, 2, 10, 0, tzinfo=timezone.utc)
        monkeypatch.setattr(monitor, "datetime", _FakeDT)
        due = monitor.check_schedule()
        assert "monthly_deep" not in due

    def test_already_run_within_23_hours_skipped(self, monitor, monkeypatch):
        _FakeDT.fixed = datetime(2024, 1, 1, 22, 0, tzinfo=timezone.utc)
        monkeypatch.setattr(monitor, "datetime", _FakeDT)
        # Mark as completed an hour ago.
        recent = (_FakeDT.fixed - timedelta(hours=1)).isoformat()
        monitor._save_schedule_state({"daily_health": recent})
        due = monitor.check_schedule()
        assert "daily_health" not in due

    def test_run_more_than_23_hours_ago_re_eligible(self, monitor, monkeypatch):
        _FakeDT.fixed = datetime(2024, 1, 2, 22, 0, tzinfo=timezone.utc)
        monkeypatch.setattr(monitor, "datetime", _FakeDT)
        long_ago = (_FakeDT.fixed - timedelta(hours=25)).isoformat()
        monitor._save_schedule_state({"daily_health": long_ago})
        due = monitor.check_schedule()
        assert "daily_health" in due


# ── run_checks dispatcher ──────────────────────────────────────────────────

class TestRunChecks:
    def test_unknown_schedule_returns_warning(self, monitor):
        result = monitor.run_checks("ghost_schedule")
        assert "Unknown schedule" in result["summary"]
        assert result["critical_count"] == 0

    def test_aggregates_statuses(self, monitor, monkeypatch):
        # Override two checks: one critical, one warning, one ok.
        monkeypatch.setitem(
            monitor._CHECK_REGISTRY, "disk_usage",
            lambda: {"status": "critical", "percent": 99})
        monkeypatch.setitem(
            monitor._CHECK_REGISTRY, "memory_usage",
            lambda: {"status": "warning", "percent": 85})
        monkeypatch.setitem(
            monitor._CHECK_REGISTRY, "failed_services",
            lambda: {"status": "ok"})

        # Trim the schedule down to a small known set to keep test focused.
        small_schedule = dict(monitor.SCHEDULES)
        small_schedule["daily_health"] = {
            **small_schedule["daily_health"],
            "tasks": ["disk_usage", "memory_usage", "failed_services"],
        }
        monkeypatch.setattr(monitor, "SCHEDULES", small_schedule)

        result = monitor.run_checks("daily_health")
        assert result["critical_count"] == 1
        assert result["warning_count"] == 1
        assert "1 ok" in result["summary"]
        assert result["full"]["disk_usage"]["status"] == "critical"

    def test_exception_in_check_recorded_as_error(self, monitor, monkeypatch):
        def boom():
            raise RuntimeError("subsystem offline")

        monkeypatch.setitem(monitor._CHECK_REGISTRY, "disk_usage", boom)
        monkeypatch.setattr(monitor, "SCHEDULES", {
            "daily_health": {**monitor.SCHEDULES["daily_health"],
                              "tasks": ["disk_usage"]},
        })
        result = monitor.run_checks("daily_health")
        assert result["full"]["disk_usage"]["status"] == "error"
        assert "subsystem offline" in result["full"]["disk_usage"]["error"]

    def test_missing_check_recorded_as_error(self, monitor, monkeypatch):
        # Use a task name with no registry entry.
        monkeypatch.setattr(monitor, "SCHEDULES", {
            "daily_health": {**monitor.SCHEDULES["daily_health"],
                              "tasks": ["wholly_new_check"]},
        })
        result = monitor.run_checks("daily_health")
        assert result["full"]["wholly_new_check"]["status"] == "error"
        assert "not implemented" in result["full"]["wholly_new_check"]["error"]

    def test_mark_completed_called(self, monitor, monkeypatch):
        monkeypatch.setattr(monitor, "SCHEDULES", {
            "daily_health": {**monitor.SCHEDULES["daily_health"], "tasks": []},
        })
        monitor.run_checks("daily_health")
        state = monitor._load_schedule_state()
        assert "daily_health" in state
