"""
Tests for core/zeph/self_diagnostic.py.

The diagnostic pulls from trust_score, an aeris_kernel.db trace store,
the zeph audit log, and settings.yaml. These DBs aren't present in test
fixtures, so most analysers return a graceful "ok" status with a
message. We verify the graceful-degradation paths, the trust trend
math, and the report formatter.
"""

import sys
import types
from datetime import datetime, timedelta, timezone

import pytest

from core.zeph import self_diagnostic as sd


@pytest.fixture
def diag(tmp_path, monkeypatch):
    monkeypatch.setattr(sd, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(sd, "DATA_DIR", tmp_path / "data")
    return sd


# ── analyze_trust_trend ────────────────────────────────────────────────────

class TestAnalyzeTrustTrend:
    def test_insufficient_data_returns_no_trend(self, diag, monkeypatch):
        fake_ts = types.ModuleType("core.security.trust_score")
        fake_ts.get_score = lambda agent: {"score": 70, "level": "standard",
                                            "agent_id": agent}
        fake_ts.get_event_history = lambda agent, limit=200: []
        monkeypatch.setitem(sys.modules, "core.security.trust_score", fake_ts)

        result = diag.analyze_trust_trend()
        assert result["status"] == "ok"
        for agent in ("aeris", "zeph"):
            assert result["trends"][agent]["direction"] == "insufficient_data"

    def test_up_trend_detected(self, diag, monkeypatch):
        now = datetime.now(timezone.utc)
        events = [
            {"timestamp": (now - timedelta(days=5)).isoformat(),
             "after": 78, "change": 1.0},
            {"timestamp": (now - timedelta(days=20)).isoformat(),
             "after": 70, "change": 1.0},
        ]
        fake_ts = types.ModuleType("core.security.trust_score")
        fake_ts.get_score = lambda agent: {"score": 78, "level": "standard",
                                            "agent_id": agent}
        fake_ts.get_event_history = lambda agent, limit=500: events
        monkeypatch.setitem(sys.modules, "core.security.trust_score", fake_ts)

        result = diag.analyze_trust_trend()
        assert result["trends"]["aeris"]["direction"] == "up"
        assert result["trends"]["aeris"]["delta"] == 8.0

    def test_down_trend_detected(self, diag, monkeypatch):
        now = datetime.now(timezone.utc)
        events = [
            {"timestamp": (now - timedelta(days=2)).isoformat(),
             "after": 50, "change": -2.0},
            {"timestamp": (now - timedelta(days=25)).isoformat(),
             "after": 70, "change": -2.0},
        ]
        fake_ts = types.ModuleType("core.security.trust_score")
        fake_ts.get_score = lambda agent: {"score": 50, "level": "standard",
                                            "agent_id": agent}
        fake_ts.get_event_history = lambda agent, limit=500: events
        monkeypatch.setitem(sys.modules, "core.security.trust_score", fake_ts)

        result = diag.analyze_trust_trend()
        assert result["trends"]["zeph"]["direction"] == "down"
        assert result["trends"]["zeph"]["delta"] == -20.0

    def test_stable_trend_when_small_delta(self, diag, monkeypatch):
        now = datetime.now(timezone.utc)
        events = [
            {"timestamp": (now - timedelta(days=2)).isoformat(),
             "after": 70, "change": 1.0},
            {"timestamp": (now - timedelta(days=25)).isoformat(),
             "after": 69, "change": 1.0},
        ]
        fake_ts = types.ModuleType("core.security.trust_score")
        fake_ts.get_score = lambda agent: {"score": 70, "level": "standard",
                                            "agent_id": agent}
        fake_ts.get_event_history = lambda agent, limit=500: events
        monkeypatch.setitem(sys.modules, "core.security.trust_score", fake_ts)

        result = diag.analyze_trust_trend()
        assert result["trends"]["aeris"]["direction"] == "stable"


# ── analyze_tool_usage / analyze_error_rate / identify_competence_gaps ─────
# (These shell out to DBs that don't exist in the test environment;
# we just verify the graceful-degradation contract.)

class TestGracefulDegradation:
    def test_tool_usage_with_no_db(self, diag):
        # REPO_ROOT is tmp_path → no aeris_kernel.db.
        result = diag.analyze_tool_usage()
        assert result["status"] == "ok"

    def test_error_rate_with_no_db(self, diag):
        result = diag.analyze_error_rate()
        assert result["status"] == "ok"

    def test_competence_gaps_with_no_settings(self, diag):
        result = diag.identify_competence_gaps()
        assert result["status"] == "ok"
        assert result["registered_count"] == 0


# ── _format_report ─────────────────────────────────────────────────────────

class TestFormatReport:
    def test_report_has_required_sections(self, diag):
        trust = {"status": "ok", "trends": {
            "aeris": {"direction": "up", "delta": 1.5,
                      "current_score": 71, "current_level": "standard",
                      "events_30d": 10},
            "zeph": {"direction": "stable", "delta": 0.0,
                     "current_score": 55, "current_level": "standard",
                     "events_30d": 5},
        }}
        tools = {"status": "ok", "total_calls": 100,
                 "unique_tools_used": 8, "overall_error_rate": 2.0,
                 "most_used": [{"tool": "ha_search", "calls": 50,
                                "error_rate": 0.0}],
                 "least_used": []}
        errors = {"status": "ok", "total_actions_30d": 100, "failed": 2,
                  "blocked": 1, "error_rate_pct": 2.0,
                  "top_failure_actions": [{"action": "x", "count": 2}]}
        gaps = {"status": "ok", "registered_count": 10,
                "used_count": 8, "coverage_pct": 80.0,
                "never_used_30d": ["foo", "bar"],
                "unregistered_but_used": []}
        report = diag._format_report(trust, tools, errors, gaps)
        assert "ZEPH MONTHLY SELF-DIAGNOSTIC" in report
        assert "TRUST SCORE TRENDS" in report
        assert "TOOL USAGE" in report
        assert "ERROR ANALYSIS" in report
        assert "COMPETENCE GAPS" in report
        assert "aeris: up" in report
        assert "ha_search" in report


# ── run_monthly_diagnostic ─────────────────────────────────────────────────

class TestRunMonthlyDiagnostic:
    def test_overall_ok_when_no_data(self, diag, monkeypatch):
        # Stub trust_score so analyze_trust_trend has data to return.
        fake_ts = types.ModuleType("core.security.trust_score")
        fake_ts.get_score = lambda agent: {"score": 70, "level": "standard",
                                            "agent_id": agent}
        fake_ts.get_event_history = lambda agent, limit=500: []
        monkeypatch.setitem(sys.modules, "core.security.trust_score", fake_ts)

        result = diag.run_monthly_diagnostic()
        assert result["status"] == "ok"
        assert "ZEPH MONTHLY SELF-DIAGNOSTIC" in result["full"]
        # All four analyser sections must be present.
        assert set(result["sections"].keys()) == {
            "trust_trend", "tool_usage", "error_rate", "competence_gaps"}
