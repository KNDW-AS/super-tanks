"""
Tests for core/security/intel_sources/ha_health.py.

Stubs out the two SQLite DBs (approval + audit) and the env vars so
each detector is exercised in isolation.
"""

import sqlite3
import time

import pytest

from core.security.intel_sources import ha_health


@pytest.fixture
def env(tmp_path, monkeypatch):
    approval_db = tmp_path / "approval_requests.db"
    audit_db = tmp_path / "memory_audit.db"
    monkeypatch.setattr(ha_health, "APPROVAL_DB", approval_db)
    monkeypatch.setattr(ha_health, "AUDIT_DB", audit_db)
    # Seed approval schema.
    conn = sqlite3.connect(str(approval_db))
    conn.execute("""
        CREATE TABLE approval_requests (
            request_id TEXT PRIMARY KEY,
            tool_name TEXT, user_id TEXT, reason TEXT,
            args_hash TEXT, args_len INTEGER, status TEXT,
            created_at REAL, expires_at REAL,
            resolved_at REAL, resolved_by TEXT, raw_params TEXT
        )""")
    conn.commit()
    conn.close()
    # Seed audit schema.
    conn = sqlite3.connect(str(audit_db))
    conn.execute("""
        CREATE TABLE memory_access_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, agent_id TEXT, operation TEXT, path TEXT,
            detail_level INTEGER, mode TEXT, accessible INTEGER,
            conversation_id TEXT, trajectory TEXT,
            correlation_id TEXT, hmac TEXT
        )""")
    conn.commit()
    conn.close()
    # Clear HA env vars so creds-missing is the default state.
    for v in ha_health.HA_TOKEN_VARS + ha_health.HA_URL_VARS:
        monkeypatch.delenv(v, raising=False)
    return tmp_path


def _insert_approval(env_dir, *, status="pending",
                     tool_name="home_assistant",
                     created_offset_min=0):
    conn = sqlite3.connect(str(env_dir / "approval_requests.db"))
    try:
        conn.execute(
            "INSERT INTO approval_requests "
            "(request_id, tool_name, user_id, reason, args_hash, "
            " args_len, status, created_at, expires_at) "
            "VALUES (?, ?, 'william', 'reason', 'h', 0, ?, ?, ?)",
            (f"req-{tool_name}-{created_offset_min}", tool_name, status,
             time.time() + (created_offset_min * 60),
             time.time() + (created_offset_min * 60) + 300),
        )
        conn.commit()
    finally:
        conn.close()


def _insert_audit(env_dir, *, accessible=0, operation="home_assistant",
                  timestamp_offset_hours=0):
    from datetime import datetime, timedelta, timezone
    ts = (datetime.now(timezone.utc) +
          timedelta(hours=timestamp_offset_hours)).isoformat()
    conn = sqlite3.connect(str(env_dir / "memory_audit.db"))
    try:
        conn.execute(
            "INSERT INTO memory_access_log "
            "(timestamp, agent_id, operation, path, detail_level, "
            " mode, accessible) "
            "VALUES (?, 'aeris', ?, '', 0, 'lockdown', ?)",
            (ts, operation, accessible),
        )
        conn.commit()
    finally:
        conn.close()


# ── H1 pending stale ───────────────────────────────────────────────────────

class TestPendingStale:
    def test_fresh_pending_no_finding(self, env):
        _insert_approval(env, created_offset_min=-2)  # 2min old
        threats = ha_health.HAHealthSource().fetch()
        assert not any(t.fingerprint.startswith("H1") for t in threats)

    def test_stale_pending_emits_high(self, env):
        _insert_approval(env, created_offset_min=-20)  # 20min old
        threats = ha_health.HAHealthSource().fetch()
        h1 = [t for t in threats if t.fingerprint.startswith("H1")]
        assert len(h1) == 1
        assert h1[0].severity == "HIGH"
        assert h1[0].details["kind"] == "ha_pending_stale"
        assert h1[0].details["count"] == 1

    def test_non_ha_tools_ignored(self, env):
        _insert_approval(env, tool_name="some_other_tool",
                         created_offset_min=-30)
        threats = ha_health.HAHealthSource().fetch()
        assert not any(t.fingerprint.startswith("H1") for t in threats)

    def test_resolved_not_counted(self, env):
        _insert_approval(env, status="approved", created_offset_min=-30)
        threats = ha_health.HAHealthSource().fetch()
        assert not any(t.fingerprint.startswith("H1") for t in threats)


# ── H2 credentials missing ────────────────────────────────────────────────

class TestCredentialsMissing:
    def test_no_env_emits_critical(self, env):
        threats = ha_health.HAHealthSource().fetch()
        h2 = [t for t in threats if t.fingerprint.startswith("H2")]
        assert len(h2) == 1
        assert h2[0].severity == "CRITICAL"
        assert "HA token" in h2[0].details["missing"]
        assert "HA URL" in h2[0].details["missing"]

    def test_partial_env_still_emits(self, env, monkeypatch):
        monkeypatch.setenv("HA_TOKEN", "abc")
        threats = ha_health.HAHealthSource().fetch()
        h2 = [t for t in threats if t.fingerprint.startswith("H2")]
        assert len(h2) == 1
        assert h2[0].details["missing"] == ["HA URL"]

    def test_full_env_emits_nothing(self, env, monkeypatch):
        monkeypatch.setenv("HA_TOKEN", "abc")
        monkeypatch.setenv("HA_URL", "http://hass.local:8123")
        threats = ha_health.HAHealthSource().fetch()
        assert not any(t.fingerprint.startswith("H2") for t in threats)


# ── H3 denied burst ────────────────────────────────────────────────────────

class TestDeniedBurst:
    def test_below_threshold_no_finding(self, env, monkeypatch):
        monkeypatch.setenv("HA_TOKEN", "x")
        monkeypatch.setenv("HA_URL", "http://hass")
        for _ in range(2):
            _insert_audit(env, accessible=0,
                          operation="home_assistant.turn_on")
        threats = ha_health.HAHealthSource().fetch()
        assert not any(t.fingerprint.startswith("H3") for t in threats)

    def test_above_threshold_emits_medium(self, env, monkeypatch):
        monkeypatch.setenv("HA_TOKEN", "x")
        monkeypatch.setenv("HA_URL", "http://hass")
        for _ in range(7):
            _insert_audit(env, accessible=0,
                          operation="home_assistant.turn_on")
        threats = ha_health.HAHealthSource().fetch()
        h3 = [t for t in threats if t.fingerprint.startswith("H3")]
        assert len(h3) == 1
        assert h3[0].severity == "MEDIUM"
        assert h3[0].details["count"] >= 5

    def test_old_entries_excluded(self, env, monkeypatch):
        monkeypatch.setenv("HA_TOKEN", "x")
        monkeypatch.setenv("HA_URL", "http://hass")
        # 2 hours ago — outside the 1-hour window.
        for _ in range(10):
            _insert_audit(env, accessible=0,
                          operation="home_assistant",
                          timestamp_offset_hours=-2)
        threats = ha_health.HAHealthSource().fetch()
        assert not any(t.fingerprint.startswith("H3") for t in threats)

    def test_successful_ops_excluded(self, env, monkeypatch):
        monkeypatch.setenv("HA_TOKEN", "x")
        monkeypatch.setenv("HA_URL", "http://hass")
        # accessible=1 means the op was allowed.
        for _ in range(10):
            _insert_audit(env, accessible=1, operation="home_assistant")
        threats = ha_health.HAHealthSource().fetch()
        assert not any(t.fingerprint.startswith("H3") for t in threats)


# ── Missing DBs degrade gracefully ────────────────────────────────────────

class TestGracefulDegradation:
    def test_no_approval_db_no_h1(self, tmp_path, monkeypatch):
        # Don't create the schema — just point at a nonexistent file.
        monkeypatch.setattr(ha_health, "APPROVAL_DB",
                            tmp_path / "missing.db")
        monkeypatch.setattr(ha_health, "AUDIT_DB",
                            tmp_path / "missing2.db")
        for v in ha_health.HA_TOKEN_VARS + ha_health.HA_URL_VARS:
            monkeypatch.delenv(v, raising=False)
        threats = ha_health.HAHealthSource().fetch()
        # Only H2 (creds missing) fires; H1 and H3 silently skip.
        assert all(not t.fingerprint.startswith("H1") for t in threats)
        assert all(not t.fingerprint.startswith("H3") for t in threats)
