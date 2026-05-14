"""
Tests for core/security/aeris_security_directives.py.

The module exports the directive text plus AERIS_FORBIDDEN_TOOLS, the
single source of truth for what Aeris must never invoke. These tests
verify the critical clauses are present, the forbidden-tool set has
the expected entries, and the directive stays in sync with the real
per-agent allowlist (otherwise the prompt and the enforcement layer
silently disagree).
"""

import pytest

from core.security.aeris_security_directives import (
    AERIS_SECURITY_DIRECTIVES,
    AERIS_FORBIDDEN_TOOLS,
)


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


# ── Single-source-of-truth: forbidden set + allowlist consistency ──────

class TestForbiddenToolsConsistency:
    def test_forbidden_set_includes_dangerous_tools(self):
        for t in ("propose_code_change", "file_write", "code_edit",
                  "shell_exec", "python_exec"):
            assert t in AERIS_FORBIDDEN_TOOLS

    def test_allowlist_disjoint_from_forbidden(self):
        # If anyone ever adds one of the forbidden tools to Aeris's
        # allowlist, the module-level import would raise; this test
        # makes the contract explicit.
        from core.security.tool_allowlists import AGENT_ALLOWLISTS
        aeris_allowed = set(AGENT_ALLOWLISTS.get("aeris", []))
        assert aeris_allowed.isdisjoint(AERIS_FORBIDDEN_TOOLS)

    def test_directive_text_lists_each_forbidden_tool(self):
        for t in AERIS_FORBIDDEN_TOOLS:
            assert t in AERIS_SECURITY_DIRECTIVES, \
                f"directive text doesn't mention forbidden tool {t!r}"
