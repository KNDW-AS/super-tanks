"""
Tests for scripts/independent_review.py.

Focus on the score calculation algorithm and the per-DB analyser
functions with manually seeded SQLite databases pointed at by
monkeypatching the script's *_DB module constants.
"""

import importlib.util
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent.parent / "scripts" / "independent_review.py"


@pytest.fixture
def review(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("independent_review_test",
                                                  str(_SCRIPT))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    # Redirect every DB constant to a per-test tmp file.
    monkeypatch.setattr(mod, "DATA_DIR", tmp_path)
    monkeypatch.setattr(mod, "OUTPUT_DIR", tmp_path / "performance_reviews")
    monkeypatch.setattr(mod, "TRUST_DB", tmp_path / "trust.db")
    monkeypatch.setattr(mod, "APPROVAL_DB", tmp_path / "approval.db")
    monkeypatch.setattr(mod, "TOKEN_DB", tmp_path / "tokens.db")
    monkeypatch.setattr(mod, "MEMORY_AUDIT_DB", tmp_path / "audit.db")
    monkeypatch.setattr(mod, "SHADOW_DB", tmp_path / "shadow.db")
    return mod, tmp_path


def _make_trust_db(path: Path):
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE trust_events (
            id INTEGER PRIMARY KEY,
            agent_id TEXT, event_type TEXT, score_change REAL,
            score_before REAL, score_after REAL, details TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    return conn


def _make_approval_db(path: Path):
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE approval_requests (
            request_id TEXT PRIMARY KEY,
            tool_name TEXT, user_id TEXT, reason TEXT,
            args_hash TEXT, args_len INTEGER, status TEXT,
            created_at REAL, expires_at REAL, resolved_at REAL,
            resolved_by TEXT, raw_params TEXT
        )
    """)
    conn.commit()
    return conn


def _make_token_db(path: Path):
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE token_usage (
            id INTEGER PRIMARY KEY,
            date TEXT, agent_id TEXT, task_id TEXT,
            tokens_used INTEGER, provider TEXT, timestamp TEXT
        )
    """)
    conn.commit()
    return conn


def _make_audit_db(path: Path):
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE memory_access_log (
            id INTEGER PRIMARY KEY,
            timestamp TEXT, agent_id TEXT, operation TEXT,
            path TEXT, detail_level INTEGER, mode TEXT,
            accessible INTEGER, conversation_id TEXT, trajectory TEXT
        )
    """)
    conn.commit()
    return conn


def _make_shadow_db(path: Path):
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE shadow_proposals (
            id INTEGER PRIMARY KEY,
            branch_id TEXT, agent_id TEXT, operation TEXT,
            path TEXT, status TEXT, created_at TEXT
        )
    """)
    conn.commit()
    return conn


# ── calculate_score ────────────────────────────────────────────────────────

class TestCalculateScore:
    def test_baseline_70(self, review):
        mod, _ = review
        s = mod.calculate_score({"trend": "stable"}, {"approval_rate": None},
                                {"tripwire_count": 0}, 0)
        assert s["score"] == 70
        assert s["breakdown"] == []

    def test_trust_improving_adds_10(self, review):
        mod, _ = review
        s = mod.calculate_score({"trend": "improving"},
                                {"approval_rate": None},
                                {"tripwire_count": 0}, 0)
        assert s["score"] == 80

    def test_trust_declining_subtracts_10(self, review):
        mod, _ = review
        s = mod.calculate_score({"trend": "declining"},
                                {"approval_rate": None},
                                {"tripwire_count": 0}, 0)
        assert s["score"] == 60

    def test_high_approval_adds_10(self, review):
        mod, _ = review
        s = mod.calculate_score({"trend": "stable"},
                                {"approval_rate": 96.0},
                                {"tripwire_count": 0}, 0)
        assert s["score"] == 80

    def test_low_approval_subtracts_15(self, review):
        mod, _ = review
        s = mod.calculate_score({"trend": "stable"},
                                {"approval_rate": 70.0},
                                {"tripwire_count": 0}, 0)
        assert s["score"] == 55

    def test_tripwire_subtracts_50(self, review):
        mod, _ = review
        s = mod.calculate_score({"trend": "stable"},
                                {"approval_rate": None},
                                {"tripwire_count": 1}, 0)
        assert s["score"] == 20

    def test_zef_blocks_penalty(self, review):
        mod, _ = review
        s = mod.calculate_score({"trend": "stable"},
                                {"approval_rate": None},
                                {"tripwire_count": 0}, 5)
        # baseline 70 - 5*2 = 60.
        assert s["score"] == 60

    def test_score_clamped_at_zero(self, review):
        mod, _ = review
        s = mod.calculate_score({"trend": "declining"},
                                {"approval_rate": 50.0},
                                {"tripwire_count": 1}, 10)
        assert s["score"] == 0

    def test_score_clamped_at_100(self, review):
        mod, _ = review
        s = mod.calculate_score({"trend": "improving"},
                                {"approval_rate": 99.0},
                                {"tripwire_count": 0}, 0)
        # 70 + 10 + 10 = 90 → still in range.
        assert s["score"] == 90


# ── analyze_trust ──────────────────────────────────────────────────────────

class TestAnalyzeTrust:
    def test_missing_db_returns_status(self, review):
        mod, _ = review
        result = mod.analyze_trust("aeris", "2020-01-01")
        assert result["status"] == "db_missing"

    def test_no_data_returns_stable(self, review):
        mod, tmp = review
        conn = _make_trust_db(tmp / "trust.db")
        conn.close()
        result = mod.analyze_trust("aeris", "2020-01-01")
        assert result["status"] == "no_data"
        assert result["trend"] == "stable"

    def test_improving_trend(self, review):
        mod, tmp = review
        conn = _make_trust_db(tmp / "trust.db")
        conn.execute(
            "INSERT INTO trust_events (agent_id, event_type, score_change, "
            "score_before, score_after, timestamp) VALUES (?,?,?,?,?,?)",
            ("aeris", "successful_task", 1, 70, 71, "2024-01-01T00:00:00"))
        conn.execute(
            "INSERT INTO trust_events (agent_id, event_type, score_change, "
            "score_before, score_after, timestamp) VALUES (?,?,?,?,?,?)",
            ("aeris", "successful_task", 1, 75, 80, "2024-01-05T00:00:00"))
        conn.commit()
        conn.close()
        result = mod.analyze_trust("aeris", "2024-01-01T00:00:00")
        assert result["trend"] == "improving"
        assert result["delta"] == 10.0


# ── analyze_gogate ─────────────────────────────────────────────────────────

class TestAnalyzeGogate:
    def test_approval_rate_calculation(self, review):
        mod, tmp = review
        conn = _make_approval_db(tmp / "approval.db")
        for i, status in enumerate(("approved", "approved", "approved",
                                    "denied")):
            conn.execute(
                "INSERT INTO approval_requests (request_id, tool_name, "
                "user_id, args_hash, args_len, status, created_at, expires_at, "
                "raw_params) VALUES (?,?,?,?,?,?,?,?,?)",
                (f"r{i}", "t", "aeris", "h", 0, status,
                 "2024-01-01T00:00:00", "2024-01-01T01:00:00", "{}"))
        conn.commit()
        conn.close()
        result = mod.analyze_gogate("aeris", "2020-01-01")
        assert result["total"] == 4
        assert result["approved"] == 3
        assert result["denied"] == 1
        assert result["approval_rate"] == 75.0


# ── analyze_memory_access ──────────────────────────────────────────────────

class TestAnalyzeMemoryAccess:
    def test_tripwire_count(self, review):
        mod, tmp = review
        conn = _make_audit_db(tmp / "audit.db")
        for op in ("READ", "READ", "TRIPWIRE_ACCESS", "WRITE"):
            conn.execute(
                "INSERT INTO memory_access_log (timestamp, agent_id, "
                "operation, path, detail_level, mode, accessible) "
                "VALUES (?,?,?,?,?,?,?)",
                ("2024-01-05T00:00:00", "aeris", op, "/x", 2,
                 "autonomous", 0 if "TRIPWIRE" in op else 1))
        conn.commit()
        conn.close()
        result = mod.analyze_memory_access("aeris", "2020-01-01")
        assert result["total_accesses"] == 4
        assert result["tripwire_count"] == 1
        assert result["denied_accesses"] == 1


# ── analyze_shadow ─────────────────────────────────────────────────────────

class TestAnalyzeShadow:
    def test_merge_rate(self, review):
        mod, tmp = review
        conn = _make_shadow_db(tmp / "shadow.db")
        for i, status in enumerate(("approved", "approved", "rejected",
                                    "pending")):
            conn.execute(
                "INSERT INTO shadow_proposals (branch_id, agent_id, operation, "
                "path, status, created_at) VALUES (?,?,?,?,?,?)",
                (f"b{i}", "zeph", "create", "/x", status,
                 "2024-01-05T00:00:00"))
        conn.commit()
        conn.close()
        result = mod.analyze_shadow("zeph", "2020-01-01")
        assert result["total_proposals"] == 4
        assert result["merge_rate"] == 50.0


# ── analyze_tokens ─────────────────────────────────────────────────────────

class TestAnalyzeTokens:
    def test_sums_by_day(self, review):
        mod, tmp = review
        conn = _make_token_db(tmp / "tokens.db")
        for d, t in [("2024-01-01", 1000), ("2024-01-01", 500),
                     ("2024-01-02", 2000)]:
            conn.execute(
                "INSERT INTO token_usage (date, agent_id, task_id, "
                "tokens_used, provider, timestamp) VALUES (?,?,?,?,?,?)",
                (d, "aeris", "", t, "ollama",
                 d + "T12:00:00"))
        conn.commit()
        conn.close()
        result = mod.analyze_tokens("aeris", "2020-01-01")
        assert result["total_tokens"] == 3500
        assert result["days"] == 2
        assert result["avg_daily"] == 1750


# ── count_zef_blocks ───────────────────────────────────────────────────────

class TestCountZefBlocks:
    def test_counts_zef_blocked_events(self, review):
        mod, tmp = review
        conn = _make_trust_db(tmp / "trust.db")
        for et in ("zef_blocked", "zef_blocked", "successful_task"):
            conn.execute(
                "INSERT INTO trust_events (agent_id, event_type, "
                "score_change, score_before, score_after, timestamp) "
                "VALUES (?,?,?,?,?,?)",
                ("zeph", et, 0, 70, 70, "2024-01-01T00:00:00"))
        conn.commit()
        conn.close()
        assert mod.count_zef_blocks("zeph", "2020-01-01") == 2

    def test_missing_db_returns_zero(self, review):
        mod, _ = review
        assert mod.count_zef_blocks("zeph", "2020-01-01") == 0


# ── run_review end-to-end ──────────────────────────────────────────────────

class TestRunReview:
    def test_produces_report_for_both_agents(self, review):
        mod, tmp = review
        report = mod.run_review(days=7)
        assert "agents" in report
        assert set(report["agents"].keys()) == {"aeris", "zeph"}
        assert report["agents"]["aeris"]["overall"]["score"] == 70  # baseline

    def test_writes_json_to_output_dir(self, review):
        mod, tmp = review
        report = mod.run_review(days=7)
        saved = Path(report["saved_to"])
        assert saved.exists()
        data = json.loads(saved.read_text())
        assert data["period_days"] == 7
