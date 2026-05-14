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

class TestSharedResponsibility:
    def test_shared_list_is_nonempty(self):
        assert len(er.SHARED_RESPONSIBILITY) > 0

    def test_includes_common_neutrals(self):
        assert "weather" in er.SHARED_RESPONSIBILITY
        assert "calendar" in er.SHARED_RESPONSIBILITY
