"""
Tests for core/security/trust_score.py.

Covers level-band mapping, event-driven score changes (with [0, 100]
clamping), tripwire instant-demotion, daily decay, default scores for
unknown agents, event history ordering, and the Telegram notification
side-effect on level transitions.
"""

import pytest


# ── Level band mapping ─────────────────────────────────────────────────────

class TestScoreToLevel:
    @pytest.mark.parametrize("score,expected", [
        (0.0, "probation"),
        (24.99, "probation"),
        (25.0, "junior"),
        (49.99, "junior"),
        (50.0, "standard"),
        (74.99, "standard"),
        (75.0, "senior"),
        (89.99, "senior"),
        (90.0, "principal"),
        (100.0, "principal"),
    ])
    def test_band_boundaries(self, trust_db, score, expected):
        assert trust_db._score_to_level(score) == expected

    def test_above_100_falls_to_principal(self, trust_db):
        # Defensive: even if a caller bypasses clamping, the mapping is sane.
        assert trust_db._score_to_level(150.0) == "principal"

    def test_below_zero_falls_to_probation(self, trust_db):
        assert trust_db._score_to_level(-10.0) == "probation"


# ── Default scores for new agents ──────────────────────────────────────────

class TestDefaultScores:
    def test_aeris_default_is_70_standard(self, trust_db):
        result = trust_db.get_score("aeris")
        assert result["score"] == 70.0
        assert result["level"] == "standard"

    def test_zeph_default_is_55_standard(self, trust_db):
        result = trust_db.get_score("zeph")
        assert result["score"] == 55.0
        assert result["level"] == "standard"

    def test_unknown_agent_defaults_to_50(self, trust_db):
        result = trust_db.get_score("unknown_agent")
        assert result["score"] == 50.0
        assert result["level"] == "standard"

    def test_default_is_persisted_on_first_read(self, trust_db):
        # First get creates the row; second get reads it back.
        trust_db.get_score("aeris")
        second = trust_db.get_score("aeris")
        assert "updated_at" in second  # populated only on persisted reads


# ── record_event: score changes ────────────────────────────────────────────

class TestRecordEvent:
    def test_positive_event_increases_score(self, trust_db):
        before = trust_db.get_score("aeris")["score"]
        result = trust_db.record_event("aeris", "successful_task")
        assert result["score_after"] == before + 1.0
        assert result["change"] == 1.0

    def test_negative_event_decreases_score(self, trust_db):
        before = trust_db.get_score("aeris")["score"]
        result = trust_db.record_event("aeris", "gogate_denied")
        assert result["score_after"] == before - 5.0

    def test_score_clamped_at_100(self, trust_db):
        trust_db.set_score("aeris", 99.8, reason="setup")
        result = trust_db.record_event("aeris", "successful_task")  # +1.0
        assert result["score_after"] == 100.0

    def test_score_clamped_at_0(self, trust_db):
        trust_db.set_score("aeris", 1.0, reason="setup")
        result = trust_db.record_event("aeris", "quarantine_fail")  # -50.0
        assert result["score_after"] == 0.0

    def test_unknown_event_returns_error(self, trust_db):
        result = trust_db.record_event("aeris", "made_up_event")
        assert "error" in result

    def test_tripwire_drops_to_probation(self, trust_db):
        # aeris defaults to 70 (standard) → after -100 → 0 (probation)
        result = trust_db.record_event("aeris", "tripwire_access")
        assert result["score_after"] == 0.0
        assert result["level"] == "probation"

    def test_event_is_recorded_in_history(self, trust_db):
        trust_db.record_event("aeris", "successful_task", details="completed X")
        history = trust_db.get_event_history("aeris")
        assert len(history) == 1
        assert history[0]["event"] == "successful_task"
        assert history[0]["details"] == "completed X"
        assert history[0]["change"] == 1.0


# ── Manual adjust quirks ───────────────────────────────────────────────────

class TestManualAdjustViaRecordEvent:
    def test_positive_numeric_details_applies_delta(self, trust_db):
        before = trust_db.get_score("aeris")["score"]
        result = trust_db.record_event("aeris", "manual_adjust", details="+10")
        assert result["change"] == 10.0
        assert result["score_after"] == before + 10.0

    def test_negative_numeric_details_applies_delta(self, trust_db):
        before = trust_db.get_score("aeris")["score"]
        result = trust_db.record_event("aeris", "manual_adjust", details="-7.5")
        assert result["change"] == -7.5
        assert result["score_after"] == before - 7.5

    def test_empty_details_means_zero_delta(self, trust_db):
        before = trust_db.get_score("aeris")["score"]
        result = trust_db.record_event("aeris", "manual_adjust", details="")
        assert result["change"] == 0.0
        assert result["score_after"] == before

    def test_non_numeric_details_falls_back_to_zero(self, trust_db):
        before = trust_db.get_score("aeris")["score"]
        result = trust_db.record_event("aeris", "manual_adjust",
                                       details="not a number")
        assert result["change"] == 0.0
        assert result["score_after"] == before

    def test_manual_adjust_respects_clamp(self, trust_db):
        trust_db.set_score("aeris", 95.0, reason="setup")
        result = trust_db.record_event("aeris", "manual_adjust", details="+50")
        assert result["score_after"] == 100.0


# ── set_score: direct override ─────────────────────────────────────────────

class TestSetScore:
    def test_sets_arbitrary_value(self, trust_db):
        trust_db.set_score("aeris", 42.0, reason="test")
        assert trust_db.get_score("aeris")["score"] == 42.0

    def test_clamps_above_100(self, trust_db):
        trust_db.set_score("aeris", 250.0, reason="test")
        assert trust_db.get_score("aeris")["score"] == 100.0

    def test_clamps_below_0(self, trust_db):
        trust_db.set_score("aeris", -50.0, reason="test")
        assert trust_db.get_score("aeris")["score"] == 0.0

    def test_updates_level_to_match_score(self, trust_db):
        trust_db.set_score("aeris", 92.0, reason="promotion")
        assert trust_db.get_score("aeris")["level"] == "principal"
        trust_db.set_score("aeris", 10.0, reason="demotion")
        assert trust_db.get_score("aeris")["level"] == "probation"

    def test_records_event_with_correct_delta(self, trust_db):
        # default aeris = 70.0
        trust_db.set_score("aeris", 80.0, reason="manual bump")
        history = trust_db.get_event_history("aeris")
        # The set_score event row is the most recent.
        latest = history[0]
        assert latest["event"] == "manual_adjust"
        assert latest["change"] == pytest.approx(10.0)
        assert latest["details"] == "manual bump"


# ── Daily decay ────────────────────────────────────────────────────────────

class TestDailyDecay:
    def test_decay_applies_to_known_agents(self, trust_db):
        trust_db.get_score("aeris")  # 70.0
        trust_db.get_score("zeph")   # 55.0
        trust_db.apply_daily_decay()
        assert trust_db.get_score("aeris")["score"] == pytest.approx(69.5)
        assert trust_db.get_score("zeph")["score"] == pytest.approx(54.5)

    def test_decay_does_not_drop_below_zero(self, trust_db):
        trust_db.set_score("aeris", 0.0, reason="bottomed")
        trust_db.apply_daily_decay()
        assert trust_db.get_score("aeris")["score"] == 0.0

    def test_decay_does_not_apply_to_unknown_agents(self, trust_db):
        trust_db.get_score("ghost")  # creates at 50.0
        trust_db.apply_daily_decay()  # only iterates DEFAULT_SCORES
        assert trust_db.get_score("ghost")["score"] == 50.0

    def test_decay_logs_event(self, trust_db):
        trust_db.apply_daily_decay()
        history = trust_db.get_event_history("aeris")
        assert any(e["event"] == "daily_decay" for e in history)

    def test_decay_is_idempotent_within_a_day(self, trust_db):
        # Running daily_decay twice in the same UTC day must NOT double-debit.
        # Previously a DST transition or a retry-on-failure dropped scores
        # by 1.0 instead of 0.5.
        trust_db.apply_daily_decay()
        trust_db.apply_daily_decay()
        assert trust_db.get_score("aeris")["score"] == pytest.approx(69.5)
        # And only one decay event recorded.
        decay_events = [e for e in trust_db.get_event_history("aeris")
                        if e["event"] == "daily_decay"]
        assert len(decay_events) == 1


# ── Event history ──────────────────────────────────────────────────────────

class TestEventHistory:
    def test_returns_newest_first(self, trust_db):
        trust_db.record_event("aeris", "successful_task", details="first")
        trust_db.record_event("aeris", "gogate_denied", details="second")
        trust_db.record_event("aeris", "successful_task", details="third")
        history = trust_db.get_event_history("aeris")
        details = [e["details"] for e in history]
        assert details == ["third", "second", "first"]

    def test_respects_limit(self, trust_db):
        for _ in range(10):
            trust_db.record_event("aeris", "successful_task")
        assert len(trust_db.get_event_history("aeris", limit=3)) == 3

    def test_isolated_per_agent(self, trust_db):
        trust_db.record_event("aeris", "successful_task")
        trust_db.record_event("zeph", "gogate_denied")
        aeris_hist = trust_db.get_event_history("aeris")
        zeph_hist = trust_db.get_event_history("zeph")
        assert all(e["event"] == "successful_task" for e in aeris_hist)
        assert all(e["event"] == "gogate_denied" for e in zeph_hist)

    def test_empty_for_new_agent(self, trust_db):
        assert trust_db.get_event_history("nobody") == []


# ── Level-transition notification ──────────────────────────────────────────

class TestTrustAuthorityGate:
    """R-14: Only authorised subsystems may mutate trust. Tool-reachable
    code calling record_event/set_score directly is rejected."""

    def test_record_event_without_authority_raises(self, tmp_path, monkeypatch):
        # Reset the authority ContextVar to default-False (the trust_db
        # fixture flips it to True, so we use raw monkeypatch here).
        from core.security import trust_score
        monkeypatch.setattr(trust_score, "TRUST_DB", tmp_path / "trust.db")
        monkeypatch.setattr(trust_score, "_initialised", False)
        import contextvars
        monkeypatch.setattr(trust_score, "_trust_writes_authorised",
                            contextvars.ContextVar("trust_writes_authorised",
                                                    default=False))
        with pytest.raises(PermissionError, match="authorised context"):
            trust_score.record_event("aeris", "successful_task")

    def test_set_score_without_authority_raises(self, tmp_path, monkeypatch):
        from core.security import trust_score
        monkeypatch.setattr(trust_score, "TRUST_DB", tmp_path / "trust.db")
        monkeypatch.setattr(trust_score, "_initialised", False)
        import contextvars
        monkeypatch.setattr(trust_score, "_trust_writes_authorised",
                            contextvars.ContextVar("trust_writes_authorised",
                                                    default=False))
        with pytest.raises(PermissionError):
            trust_score.set_score("aeris", 100.0)

    def test_authority_context_manager_opens_window(self, tmp_path, monkeypatch):
        from core.security import trust_score
        monkeypatch.setattr(trust_score, "TRUST_DB", tmp_path / "trust.db")
        monkeypatch.setattr(trust_score, "_initialised", False)
        monkeypatch.setattr(trust_score, "_notify_level_change",
                            lambda *a, **kw: None)
        import contextvars
        monkeypatch.setattr(trust_score, "_trust_writes_authorised",
                            contextvars.ContextVar("trust_writes_authorised",
                                                    default=False))
        # Authorised: works.
        with trust_score._TrustAuthority():
            r = trust_score.record_event("aeris", "successful_task")
        assert r["change"] == 1.0
        # Outside: blocked again.
        with pytest.raises(PermissionError):
            trust_score.record_event("aeris", "successful_task")

    def test_apply_daily_decay_runs_under_default_no_authority(
            self, tmp_path, monkeypatch):
        """Regression: R-14 introduced a landmine where a scheduler
        firing apply_daily_decay() on production defaults would crash
        with PermissionError on the first record_event call. The
        function must open its own _TrustAuthority window."""
        from core.security import trust_score
        monkeypatch.setattr(trust_score, "TRUST_DB", tmp_path / "trust.db")
        monkeypatch.setattr(trust_score, "_initialised", False)
        monkeypatch.setattr(trust_score, "_notify_level_change",
                            lambda *a, **kw: None)
        import contextvars
        # Production default — authority is closed.
        monkeypatch.setattr(trust_score, "_trust_writes_authorised",
                            contextvars.ContextVar("trust_writes_authorised",
                                                    default=False))
        # Must not raise.
        trust_score.apply_daily_decay()
        # And must not have left the authority window leaked open.
        with pytest.raises(PermissionError):
            trust_score.record_event("aeris", "successful_task")


class TestLevelChangeNotification:
    def test_called_on_level_drop(self, trust_db):
        # trust_db fixture provides the authority context.
        calls = []
        trust_db._notify_level_change = lambda *a, **kw: calls.append(a)
        # aeris=70 standard → tripwire → 0 probation
        trust_db.record_event("aeris", "tripwire_access")
        assert len(calls) == 1
        agent, old, new, score, event = calls[0]
        assert agent == "aeris"
        assert old == "standard"
        assert new == "probation"
        assert event == "tripwire_access"

    def test_not_called_when_level_unchanged(self, trust_db):
        calls = []
        trust_db._notify_level_change = lambda *a, **kw: calls.append(a)
        # aeris=70 standard → +1 = 71, still standard
        trust_db.record_event("aeris", "successful_task")
        assert calls == []

    def test_called_on_level_rise(self, trust_db):
        # Seed agent at 89.9 (senior), then bump to push into principal.
        trust_db.set_score("aeris", 89.9, reason="setup")
        calls = []
        trust_db._notify_level_change = lambda *a, **kw: calls.append(a)
        trust_db.record_event("aeris", "successful_task")  # +1.0 → 90.9
        assert len(calls) == 1
        _, old, new, _, _ = calls[0]
        assert old == "senior"
        assert new == "principal"


# ── _notify_level_change network safety ────────────────────────────────────

class TestNotifyLevelChangeSafety:
    def test_handles_missing_token_silently(self, monkeypatch):
        from core.security import trust_score
        monkeypatch.delenv("AERIS_GOGATE_TELEGRAM_TOKEN", raising=False)
        # Must not raise.
        trust_score._notify_level_change("aeris", "senior", "principal",
                                         91.0, "successful_task")

    def test_swallows_network_errors(self, monkeypatch):
        from core.security import trust_score
        monkeypatch.setenv("AERIS_GOGATE_TELEGRAM_TOKEN", "fake")
        monkeypatch.setenv("AERIS_ADMIN_CHAT_ID", "123")

        import sys
        import types

        def boom(*a, **kw):
            raise RuntimeError("network down")

        fake_requests = types.SimpleNamespace(post=boom)
        monkeypatch.setitem(sys.modules, "requests", fake_requests)
        # Must not raise.
        trust_score._notify_level_change("aeris", "standard", "probation",
                                         0.0, "tripwire_access")


# ── HMAC-chained trust_events (STA-01 Threat 06) ───────────────────────────

class TestTrustEventChain:
    def test_clean_chain_verifies(self, trust_db):
        trust_db.record_event("aeris", "successful_task")
        trust_db.record_event("aeris", "zef_blocked")
        trust_db.record_event("zeph", "successful_task")
        assert trust_db.verify_trust_chain() is None

    def test_hmac_column_populated(self, trust_db):
        trust_db.record_event("aeris", "successful_task")
        conn = trust_db._get_conn()
        try:
            (h,) = conn.execute(
                "SELECT hmac FROM trust_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
        finally:
            conn.close()
        assert h and len(h) == 64  # sha256 hexdigest

    def test_tampered_event_detected(self, trust_db):
        trust_db.record_event("aeris", "successful_task")
        trust_db.record_event("aeris", "successful_task")
        # Attacker inflates a recorded score_after post-hoc.
        conn = trust_db._get_conn()
        try:
            conn.execute("UPDATE trust_events SET score_after=99.0 WHERE id=1")
            conn.commit()
        finally:
            conn.close()
        assert trust_db.verify_trust_chain() == 1

    def test_set_score_is_chained_too(self, trust_db):
        trust_db.set_score("aeris", 42.0, reason="test")
        assert trust_db.verify_trust_chain() is None
        conn = trust_db._get_conn()
        try:
            conn.execute("UPDATE trust_events SET details='benign' WHERE id=1")
            conn.commit()
        finally:
            conn.close()
        assert trust_db.verify_trust_chain() == 1
