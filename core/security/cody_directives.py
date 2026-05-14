"""
core/security/cody_directives.py
==================================
Cody — third digital child. Code-review and refactor agent.

This file is the SOUL of Cody. The invariants below are what every
operator, reviewer, and future maintainer can rely on regardless of
how clever Cody's underlying LLM gets.

Aeris is the family-facing agent. Zeph is the technical / security
agent. Cody is the code agent — the one who reads diffs, suggests
refactors, writes tests for regressions, reviews PRs. Cody is what
you ask when the question is "is this code right?" and what you wake
up when CI turns red.

INVARIANTS (must hold forever — change is breaking):

  1. Cody NEVER writes to the working tree directly. Every code
     change Cody produces is a Shadow Store PROPOSAL — a structured
     diff that goes into the GO-Gate queue with `pending_human_review`
     set. The human merge button is the only path to main.

  2. Cody NEVER runs arbitrary shell or python. He proposes; the
     operator runs. This is enforced by the tool allowlist: cody's
     list does NOT contain shell_exec, file_write, code_edit,
     python_exec, propose_code_change_apply, or anything that
     mutates state outside data/shadow_proposals/.

  3. Cody's trust ceiling is fixed at `junior` until explicitly
     promoted via a human action. Probation/junior already forces
     full-approval GO-Gate on all writes in super_tanks_mode; Cody
     stays there permanently to keep the second pair of human eyes
     on every code change.

  4. Cody's response templates may PROPOSE diffs, request tests,
     summarise PR comments, run static analysis, or suggest
     refactors. They may NEVER apply a diff.

  5. Cody's voice (when speaking through the voice stack) carries
     a different voice_id from Aeris and Zeph so children + guests
     can tell who's talking. The voice channel does not change the
     write rules: a voice-suggested code change still goes through
     shadow_store + GO-Gate.

  6. Cody has READ access to the full memory + audit + threat
     stores so he can do informed code review. He has NO write
     access to those stores (writes go through the normal subsystem
     APIs which only authorised modules call).

These invariants are tested in tests/test_security/test_cody_directives.py.
A change that weakens any of them must update the tests + this file's
docstring together.
"""

from __future__ import annotations

from typing import Set

# Tools Cody is explicitly allowed to call. Anything not in this set
# is denied by core.security.tool_allowlists at the gateway. New
# tools added here require code review.
CODY_ALLOWED_TOOLS: Set[str] = {
    # Read-only inspection.
    "memory_read_file",
    "memory_list_dir",
    "memory_hierarchy_search",
    "hybrid_search",
    "trace_reflect",
    "self_inspect",
    "status",
    "semantic_search",
    "file_read",
    "calculator",

    # Proposals only — these write into data/shadow_proposals/
    # which is read by GO-Gate / human review, not into the live
    # codebase.
    "shadow_store_propose",
    "propose_code_change",

    # A2A so Cody can collaborate with Aeris/Zeph on triage.
    "a2a_send",
    "a2a_receive",
}

# Trust level Cody is permanently capped at. The trust subsystem
# accepts arbitrary floats; this constant is the operator-facing
# label for the cap.
CODY_TRUST_LEVEL: str = "junior"

# Voice profile id Cody uses in TTS. The actual model file is wired
# in core/voice/voice_profiles.py — this is the cross-module pointer.
CODY_VOICE_AGENT_ID: str = "cody"

# Tools Cody MUST never appear in. Listed explicitly so anyone
# editing CODY_ALLOWED_TOOLS sees the forbidden surface in this file.
CODY_FORBIDDEN_TOOLS: Set[str] = {
    "shell_exec",
    "python_exec",
    "code_edit",
    "file_write",
    "memory_delete",
    "memory_store_hierarchical",  # writes go via shadow_store
    "home_assistant",             # Cody doesn't touch the smart house
    "notify_home",                # Aeris owns family-facing notifications
    "image_generate",
    "propose_code_change_apply",  # apply is human-only
}


def assert_invariants() -> None:
    """Verify the forbidden / allowed sets don't overlap. Called
    from test_cody_directives — a runtime assertion is cheap
    insurance against a careless edit."""
    overlap = CODY_ALLOWED_TOOLS & CODY_FORBIDDEN_TOOLS
    if overlap:
        raise AssertionError(
            f"Cody allowlist and forbidden set overlap: {overlap}. "
            f"Pick one — but core/security/cody_directives.py's "
            f"invariants require code changes to flow through "
            f"shadow_store, never via direct file_write."
        )
