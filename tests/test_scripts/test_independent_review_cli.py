"""
CLI surface tests for scripts/independent_review.py.

Covers print_summary formatting against synthetic report data and the
__main__ entry point via the argparse path.
"""

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent.parent / "scripts" / "independent_review.py"


@pytest.fixture
def review(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("ir_cli_test", str(_SCRIPT))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "DATA_DIR", tmp_path)
    monkeypatch.setattr(mod, "OUTPUT_DIR", tmp_path / "performance_reviews")
    monkeypatch.setattr(mod, "TRUST_DB", tmp_path / "trust.db")
    monkeypatch.setattr(mod, "APPROVAL_DB", tmp_path / "approval.db")
    monkeypatch.setattr(mod, "TOKEN_DB", tmp_path / "tokens.db")
    monkeypatch.setattr(mod, "MEMORY_AUDIT_DB", tmp_path / "audit.db")
    monkeypatch.setattr(mod, "SHADOW_DB", tmp_path / "shadow.db")
    return mod, tmp_path


SAMPLE_REPORT = {
    "generated_at": "2024-01-15T10:00:00+00:00",
    "period_days": 7,
    "agents": {
        "aeris": {
            "agent_id": "aeris", "period_days": 7,
            "since": "2024-01-08T10:00:00+00:00",
            "trust": {"status": "ok", "trend": "improving",
                      "delta": 5.5, "events": 12},
            "gogate": {"status": "ok", "approval_rate": 96.0,
                       "approved": 24, "total": 25,
                       "denied": 1, "expired": 0, "pending": 0},
            "tokens": {"status": "ok", "total_tokens": 50_000,
                       "avg_daily": 7142, "days": 7,
                       "daily_breakdown": []},
            "memory_access": {"status": "ok", "total_accesses": 100,
                              "denied_accesses": 2, "tripwire_count": 0,
                              "operations": {"READ": 100}},
            "shadow_proposals": {"status": "ok", "total_proposals": 5,
                                  "approved": 4, "rejected": 1,
                                  "auto_rejected": 0, "pending": 0,
                                  "expired": 0, "merge_rate": 80.0},
            "zef_blocks": 0,
            "overall": {"score": 90, "breakdown": [
                ("trust_improving", 10), ("gogate_high_approval", 10)]},
        },
        "zeph": {
            "agent_id": "zeph", "period_days": 7,
            "since": "2024-01-08T10:00:00+00:00",
            "trust": {"status": "ok", "trend": "stable",
                      "delta": 0.0, "events": 8},
            "gogate": {"status": "no_data", "approval_rate": None, "total": 0},
            "tokens": {"status": "ok", "total_tokens": 12_000,
                       "avg_daily": 1714, "days": 7,
                       "daily_breakdown": []},
            "memory_access": {"status": "ok", "total_accesses": 50,
                              "denied_accesses": 0, "tripwire_count": 0,
                              "operations": {}},
            "shadow_proposals": {"status": "no_data", "total_proposals": 0},
            "zef_blocks": 0,
            "overall": {"score": 70, "breakdown": []},
        },
    },
    "saved_to": "/tmp/x.json",
}


class TestPrintSummary:
    def test_includes_both_agents(self, review, capsys):
        mod, _ = review
        mod.print_summary(SAMPLE_REPORT)
        out = capsys.readouterr().out
        assert "AERIS" in out
        assert "ZEPH" in out

    def test_shows_overall_score(self, review, capsys):
        mod, _ = review
        mod.print_summary(SAMPLE_REPORT)
        out = capsys.readouterr().out
        assert "90/100" in out
        assert "70/100" in out

    def test_shows_score_breakdown_when_present(self, review, capsys):
        mod, _ = review
        mod.print_summary(SAMPLE_REPORT)
        out = capsys.readouterr().out
        assert "trust_improving" in out
        assert "+10" in out

    def test_handles_no_gogate_data(self, review, capsys):
        mod, _ = review
        mod.print_summary(SAMPLE_REPORT)
        out = capsys.readouterr().out
        assert "no data" in out  # zeph branch has no GO-Gate data

    def test_handles_baseline_only_score(self, review, capsys):
        mod, _ = review
        # Zeph has empty breakdown → "baseline 70" path.
        mod.print_summary(SAMPLE_REPORT)
        out = capsys.readouterr().out
        assert "baseline 70" in out

    def test_includes_saved_path(self, review, capsys):
        mod, _ = review
        mod.print_summary(SAMPLE_REPORT)
        assert "/tmp/x.json" in capsys.readouterr().out


# ── Top-level _safe_close behaviour ────────────────────────────────────────

class TestSafeClose:
    def test_handles_none(self, review):
        mod, _ = review
        mod._safe_close(None)  # must not raise

    def test_handles_close_exception(self, review):
        mod, _ = review

        class Boomer:
            def close(self):
                raise RuntimeError("can't close")
        mod._safe_close(Boomer())  # must not raise


class TestSafeQuery:
    def test_none_conn_returns_empty(self, review):
        mod, _ = review
        assert mod._safe_query(None, "SELECT 1") == []

    def test_query_error_returns_empty(self, review):
        mod, _ = review

        class Boomer:
            def execute(self, *a, **kw):
                raise RuntimeError("no such table")
        assert mod._safe_query(Boomer(), "SELECT 1") == []


class TestSafeOpen:
    def test_missing_file_returns_none(self, review, tmp_path):
        mod, _ = review
        assert mod._safe_open(tmp_path / "no_such.db") is None
