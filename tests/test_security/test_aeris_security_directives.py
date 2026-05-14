"""
Tests for core/security/aeris_security_directives.py.

The module exports a single string constant. These tests verify the
critical clauses are present so a careless edit can't silently strip
them. The directives are appended to Aeris's system prompt and are
the last line of defence against information-disclosure prompts.
"""

import pytest

from core.security.aeris_security_directives import AERIS_SECURITY_DIRECTIVES


class TestDirectivesContent:
    def test_is_non_empty_string(self):
        assert isinstance(AERIS_SECURITY_DIRECTIVES, str)
        assert len(AERIS_SECURITY_DIRECTIVES.strip()) > 100

    @pytest.mark.parametrize("forbidden_tool", [
        "propose_code_change",
        "file_write",
        "code_edit",
        "shell_exec",
        "python_exec",
    ])
    def test_forbidden_tools_listed(self, forbidden_tool):
        assert forbidden_tool in AERIS_SECURITY_DIRECTIVES

    @pytest.mark.parametrize("disclosure_term", [
        ".env",
        "secret",
        "token",
        "password",
        "soul",
        "credentials",
    ])
    def test_disclosure_terms_listed(self, disclosure_term):
        assert disclosure_term.lower() in AERIS_SECURITY_DIRECTIVES.lower()

    def test_has_capability_disclosure_rule(self):
        # The "do not enumerate tools" rule is in clause 3.
        assert "tool-namn" in AERIS_SECURITY_DIRECTIVES or \
               "verktøy" in AERIS_SECURITY_DIRECTIVES

    def test_has_no_self_modification_clause(self):
        assert "ALDRI" in AERIS_SECURITY_DIRECTIVES
        assert "kodeendringar" in AERIS_SECURITY_DIRECTIVES or \
               "kapabilitetar" in AERIS_SECURITY_DIRECTIVES

    def test_has_escalation_clause(self):
        # When Aeris finds a gap, she should escalate to William or Zeph.
        assert "William" in AERIS_SECURITY_DIRECTIVES
        assert "Zeph" in AERIS_SECURITY_DIRECTIVES
