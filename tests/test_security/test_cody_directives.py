"""Tests for core/security/cody_directives.py.

Pins the invariants that make Cody a SAFE third agent:
  - allowlist and forbidden sets don't overlap
  - allowlist matches the canonical tool_allowlists entry
  - forbidden tools never sneak into the live allowlist
  - trust level cap is junior or stricter
"""

import pytest

from core.security import cody_directives
from core.security import tool_allowlists


class TestInvariants:
    def test_allowed_and_forbidden_disjoint(self):
        # Direct assertion.
        cody_directives.assert_invariants()

    def test_no_dangerous_tools_in_allowlist(self):
        dangerous = {
            "shell_exec", "python_exec", "code_edit", "file_write",
            "memory_delete", "memory_store_hierarchical",
            "propose_code_change_apply",
        }
        for tool in dangerous:
            assert tool not in cody_directives.CODY_ALLOWED_TOOLS, (
                f"INVARIANT VIOLATION: Cody allowlist contains {tool!r}, "
                f"which would bypass shadow_store + human review.")
            assert tool in cody_directives.CODY_FORBIDDEN_TOOLS, (
                f"INVARIANT WEAKENED: {tool!r} should be explicitly "
                f"forbidden so a future maintainer sees it in the "
                f"directives file.")


class TestAllowlistAgreement:
    def test_cody_in_global_allowlist(self):
        assert "cody" in tool_allowlists.AGENT_ALLOWLISTS

    def test_global_and_directives_allowlists_match(self):
        """Both files list the same allowed tools — drift here is
        a bug because the global allowlist is what the gateway
        actually enforces."""
        global_set = set(tool_allowlists.AGENT_ALLOWLISTS["cody"])
        assert global_set == cody_directives.CODY_ALLOWED_TOOLS, (
            "tool_allowlists.AGENT_ALLOWLISTS['cody'] drifted from "
            "cody_directives.CODY_ALLOWED_TOOLS. The gateway only "
            "respects the former; the latter is the canonical "
            "definition. Bring them back in sync.")

    def test_forbidden_tools_never_appear_in_global_allowlist(self):
        global_set = set(tool_allowlists.AGENT_ALLOWLISTS["cody"])
        leaks = global_set & cody_directives.CODY_FORBIDDEN_TOOLS
        assert not leaks, (
            f"Forbidden Cody tools leaked into the global allowlist: "
            f"{leaks}. Either remove them or move them out of the "
            f"forbidden set with a justification.")


class TestTrustCap:
    def test_trust_level_is_junior_or_stricter(self):
        assert cody_directives.CODY_TRUST_LEVEL in ("junior", "probation")
