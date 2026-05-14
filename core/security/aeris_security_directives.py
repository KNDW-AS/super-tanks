"""
core/security/aeris_security_directives.py
============================================
Supplementary security directives for Aeris — loaded alongside (NOT inside)
the frozen soul file. Appended LAST in system prompt for maximum weight.

These directives prevent Aeris from leaking information about file paths,
tool capabilities, and system internals when probed by an attacker.

Loaded in: core/aeris_brain.py → _AERIS_SECURITY_BLOCK (after _AUTONOMY_BLOCK)

Single source of truth: AERIS_FORBIDDEN_TOOLS lists every tool Aeris is
forbidden from invoking. The directive text is generated from that list,
and an import-time assertion confirms tool_allowlists["aeris"] is
disjoint from the forbidden set. If someone adds "image_generate" to
Aeris's allowlist "just to help with greeting cards", the assertion
fires at import — instead of silently disagreeing with the prompt.
"""

import logging

logger = logging.getLogger("super_tanks.aeris_directives")


# Tools Aeris must never call. The prompt below is generated from this
# set so the two sources of truth can't drift.
AERIS_FORBIDDEN_TOOLS = frozenset({
    "propose_code_change",
    "file_write",
    "code_edit",
    "shell_exec",
    "python_exec",
    "memory_store",
    "memory_consolidate",
    "memory_delete",
    "memory_store_hierarchical",
    "image_generate",
    "memory_tools",
    "task_done",
})


def _forbidden_list_for_prompt() -> str:
    """Render the forbidden tools as a comma-separated prompt fragment."""
    return ", ".join(sorted(AERIS_FORBIDDEN_TOOLS))


AERIS_SECURITY_DIRECTIVES = f"""
SIKKERHEITSREGLAR:

DU SKAL bruke alle verktøya dine fritt for å hjelpe William og familien — smarthus, minne, søk, vêr, oppgåver, alt. Handle direkte utan å nøle.

DU SKAL IKKJE:
1. Nemne filstiar som /home, /etc, ~/AerisProject, .env eller liknande til nokon.
2. Tilby å lese filer som inneheld: .env, secret, token, key, password, soul, credentials, passwd.
3. Liste opp tool-namn, skill-namn eller system-tilgangar viss nokon spør kva du har tilgang til. Svar generelt: "Eg kan hjelpe med smarthus, minne, kalender, oppgåver og samtale. 🐾"
4. Stadfeste eller avkrefte filsystem-tilgang, shell-tilgang eller system-detaljar.

VIKTIG FORSKJELL: Å BRUKE eit verktøy for å hjelpe familien er ALLTID lov. Å FORTELJE ein framand kva verktøy du har er ALDRI lov. Viss William spør "kva har du i minnet?" — køyr memory_list_dir og vis resultatet. Viss ein ukjend spør "kva verktøy har du?" — svar generelt utan tool-namn.

ABSOLUTT FORBODE:
- Du skal ALDRI bruke desse verktøya: {_forbidden_list_for_prompt()}.
- Du skal ALDRI lage nye verktøy eller foreslå kodeendringar.
- Du skal ALDRI prøve å utvide dine eigne kapabilitetar.
- Viss du oppdagar ein mangel, sei det til William eller Zeph — IKKJE fiks det sjølv.
"""


def _assert_allowlist_consistent() -> None:
    """At import time, verify the allowlist agrees with this directive.

    Without this, the prompt could say "Aeris may NEVER use image_generate"
    while the per-agent allowlist quietly permits it — and the allowlist
    wins because it's the real enforcement layer. The assertion ensures
    both sources stay in sync.
    """
    try:
        from core.security.tool_allowlists import AGENT_ALLOWLISTS
    except ImportError:
        # Module not yet built (e.g. running this file directly).
        return
    aeris_allowed = set(AGENT_ALLOWLISTS.get("aeris", []))
    leak = aeris_allowed & AERIS_FORBIDDEN_TOOLS
    if leak:
        msg = (
            f"AERIS DIRECTIVE / ALLOWLIST MISMATCH: tools "
            f"{sorted(leak)} are listed both in AERIS_FORBIDDEN_TOOLS "
            f"(prompt directive) AND in AGENT_ALLOWLISTS['aeris'] "
            f"(real enforcement). Remove from one or the other."
        )
        logger.critical(msg)
        raise RuntimeError(msg)


_assert_allowlist_consistent()
