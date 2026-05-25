"""
Tests for core/a2a/escalation_rules.py.

Pure regex-based routing layer. Tests cover both EN and NO triggers,
the tie-breaking default (aeris), and the human-readable reason
formatter.
"""

import pytest

from core.a2a import escalation_rules as er


# ── should_escalate_to_zeph ────────────────────────────────────────────────

class TestEscalateToZeph:
    @pytest.mark.parametrize("msg", [
        "Can you check the system logs?",
        "I'm seeing a Python traceback",
        "Run debug on the deploy pipeline",
        "There's a CVE in the firewall",
        "Possible prompt injection in input",
        # Norwegian
        "Det er feil i koden",
        "Sjekk sikkerheit på serveren",
        "Det skjer ein angrep mot databasen",
    ])
    def test_tech_messages_escalate(self, msg):
        assert er.should_escalate_to_zeph(msg) is True

    @pytest.mark.parametrize("msg", [
        "How are you today?",
        "Tell me a bedtime story",
        "What's the weather?",
        "Trist og lei meg",
    ])
    def test_non_tech_does_not_escalate(self, msg):
        assert er.should_escalate_to_zeph(msg) is False

    def test_word_boundary_enforced(self):
        # "coded" should not match "code" — \b prevents it.
        assert er.should_escalate_to_zeph("She coded a song") is False


# ── should_escalate_to_aeris ───────────────────────────────────────────────

class TestEscalateToAeris:
    @pytest.mark.parametrize("msg", [
        "I'm so sad today",
        "Tell me a bedtime story please",
        "Need some homework help with this",
        "Plan a birthday party",
        # Norwegian
        "Eg er litt trist",
        "Kan du fortelje ei godnathistorie?",
        "Familie-middag i kveld",
        "Hjelp med lekser",
    ])
    def test_emotional_or_family_messages_escalate(self, msg):
        assert er.should_escalate_to_aeris(msg) is True

    @pytest.mark.parametrize("msg", [
        "Server is overloaded",
        "Patch the CVE",
        "What's 2+2?",
    ])
    def test_tech_does_not_escalate(self, msg):
        assert er.should_escalate_to_aeris(msg) is False


# ── primary_responder ──────────────────────────────────────────────────────

class TestPrimaryResponder:
    def test_zeph_wins_when_more_tech_triggers(self):
        assert er.primary_responder(
            "Fix the server, debug the code, check the logs") == "zeph"

    def test_aeris_wins_when_more_family_triggers(self):
        # Three family keywords: bedtime, story, birthday.
        assert er.primary_responder(
            "Tell me a bedtime story for my birthday") == "aeris"

    def test_default_is_aeris_on_tie(self):
        # No triggers either way → default aeris.
        assert er.primary_responder("Hello there.") == "aeris"

    def test_default_is_aeris_on_zero_matches(self):
        assert er.primary_responder("") == "aeris"

    def test_cody_routing_on_code_review(self):
        assert er.primary_responder(
            "Please review this code and check for refactor opportunities"
        ) == "cody"

    def test_cody_wins_on_pure_code_quality(self):
        assert er.primary_responder(
            "We need a regression test and missing tests"
        ) == "cody"

    def test_norwegian_code_review_routes_to_cody(self):
        assert er.primary_responder(
            "Kan du gjere ein kodegjennomgang av denne"
        ) == "cody"


class TestEscalateToCody:
    @pytest.mark.parametrize("msg", [
        "Please refactor this function",
        "Run mypy on this",
        "We need a regression test for this bug",
        "Refaktor denne metoden",
        "Kvalitetssjekk koden",
    ])
    def test_code_quality_routes_to_cody(self, msg):
        assert er.should_escalate_to_cody(msg) is True

    @pytest.mark.parametrize("msg", [
        "Tell me a bedtime story",
        "What's the weather?",
    ])
    def test_non_code_does_not_route_to_cody(self, msg):
        assert er.should_escalate_to_cody(msg) is False


# ── get_escalation_reason ──────────────────────────────────────────────────

class TestEscalationReason:
    def test_aeris_to_zeph_includes_keywords(self):
        reason = er.get_escalation_reason(
            "There's a CVE in the deploy pipeline", from_agent="aeris")
        assert "Zeph" in reason
        assert "CVE" in reason or "deploy" in reason

    def test_zeph_to_aeris_includes_keywords(self):
        reason = er.get_escalation_reason(
            "Tell me a bedtime story", from_agent="zeph")
        assert "Aeris" in reason
        assert "bedtime" in reason or "story" in reason

    def test_empty_when_no_match(self):
        assert er.get_escalation_reason("just hello", "aeris") == ""

    def test_empty_when_wrong_direction(self):
        # Tech message but from_agent=zeph → no escalation (already there).
        assert er.get_escalation_reason("CVE patch needed", "zeph") == ""

    def test_unknown_agent_returns_empty(self):
        assert er.get_escalation_reason("anything", "wizard") == ""

    def test_keywords_truncated_to_five(self):
        msg = "tech security code system diagnostics error CVE hack"
        reason = er.get_escalation_reason(msg, from_agent="aeris")
        # Keyword list portion should hold <= 5 entries.
        between = reason.split("keywords: ")[1].split(")")[0]
        assert between.count(",") <= 4


# ── Shared responsibility list ─────────────────────────────────────────────

class TestVerifyOrDrop:
    """R-06: every A2A receive path MUST go through verify_or_drop.
    Unsigned or forged messages are dropped silently to the caller
    but logged."""

    def _signed_msg(self, monkeypatch, **fields):
        from core.security import agent_identity
        from core.diq.diq_a2a import A2AMessage
        monkeypatch.setattr(agent_identity, "_KEY", b"test-a2a-verify-key")
        base = dict(sender="aeris", recipient="zeph",
                    message_type="request", payload={"x": 1},
                    timestamp="2024-01-01T00:00:00+00:00",
                    correlation_id="c-1")
        base.update(fields)
        return agent_identity.sign_a2a_message(A2AMessage(**base))

    def test_valid_signed_message_returned(self, monkeypatch):
        signed = self._signed_msg(monkeypatch)
        assert er.verify_or_drop(signed) is signed

    def test_unsigned_message_dropped(self, monkeypatch):
        from core.diq.diq_a2a import A2AMessage
        msg = A2AMessage(sender="aeris", recipient="zeph",
                         message_type="request")
        assert er.verify_or_drop(msg) is None

    def test_forged_sender_dropped(self, monkeypatch):
        from core.security import agent_identity
        from dataclasses import replace
        signed = self._signed_msg(monkeypatch)
        forged = replace(signed, sender="william")  # claim admin
        assert er.verify_or_drop(forged) is None

    def test_none_input_returns_none(self):
        assert er.verify_or_drop(None) is None

    def test_verify_helper_import_failure_drops(self, monkeypatch, caplog):
        # Force the lazy `from core.security.agent_identity import
        # verify_a2a_message` to raise. Setting the module to None in
        # sys.modules makes the import statement raise ImportError.
        import sys
        from core.diq.diq_a2a import A2AMessage
        monkeypatch.setitem(sys.modules, "core.security.agent_identity", None)
        msg = A2AMessage(sender="aeris", recipient="zeph",
                         message_type="request")
        with caplog.at_level("ERROR", logger="super_tanks.a2a"):
            assert er.verify_or_drop(msg) is None
        assert any("verify_a2a_message unavailable" in r.message
                   for r in caplog.records)

    def test_module_import_tolerates_missing_diq_a2a(self, monkeypatch):
        # Lines 56-59: the top-level `from core.diq.diq_a2a import
        # A2AMessage` is wrapped in try/except so this module is
        # importable even when diq_a2a is not present. Reload with
        # diq_a2a poisoned and verify the import does not raise.
        import importlib
        import sys
        monkeypatch.setitem(sys.modules, "core.diq.diq_a2a", None)
        try:
            reloaded = importlib.reload(er)
            assert reloaded.should_escalate_to_zeph("debug the server") is True
        finally:
            # Restore real module so later tests see real A2AMessage.
            monkeypatch.undo()
            importlib.reload(er)


class TestSharedResponsibility:
    def test_shared_list_is_nonempty(self):
        assert len(er.SHARED_RESPONSIBILITY) > 0

    def test_includes_common_neutrals(self):
        assert "weather" in er.SHARED_RESPONSIBILITY
        assert "calendar" in er.SHARED_RESPONSIBILITY
