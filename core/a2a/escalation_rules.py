"""
core/a2a/escalation_rules.py
==============================
Escalation rules between Aeris and Zeph agents.

Determines when one agent should defer to the other based on message
content analysis. Supports both English and Norwegian keywords.

Aeris handles: emotions, family, creativity, daily life, cooking, celebrations.
Zeph handles:  tech, security, code, system diagnostics, error analysis.
Shared:        general questions, scheduling, reminders, weather.

Also exports `verify_or_drop` (R-06): every A2A receive path MUST run
incoming messages through this helper. An unsigned or tamper-detected
message is dropped — a compromised agent forging `sender="william"`
to escalate via A2A is the canonical privilege-escalation path on
this channel.
"""

import logging
import re
from typing import List, Optional, Tuple

_logger = logging.getLogger("super_tanks.a2a")


def verify_or_drop(message) -> Optional["A2AMessage"]:
    """Return `message` if its HMAC signature verifies; None otherwise.

    Production A2A receive code calls this BEFORE doing anything with
    the message. Dropping a forged message is silent on the caller's
    side (the agent sees no message), but loud in the logs so the
    operator can see the attempt.

    Type-imported lazily to avoid pulling diq_a2a at module load.
    """
    if message is None:
        return None
    try:
        from core.security.agent_identity import verify_a2a_message
    except Exception as exc:
        _logger.error("[A2A] verify_a2a_message unavailable, dropping: %s", exc)
        return None
    if verify_a2a_message(message):
        return message
    sender = getattr(message, "sender", "<unknown>")
    correlation = getattr(message, "correlation_id", "<no-corr>")
    _logger.warning(
        "[A2A] dropped message with bad/missing signature sender=%s corr=%s",
        sender, correlation,
    )
    return None


# A2AMessage type — re-exported for callers that only import this module.
try:
    from core.diq.diq_a2a import A2AMessage  # noqa: F401
except Exception:
    _logger.debug("A2AMessage re-export unavailable (diq_a2a not importable)", exc_info=True)

# ---------------------------------------------------------------------------
# Trigger patterns — each is a (compiled_regex, human_label) tuple
# ---------------------------------------------------------------------------

def _compile(patterns: List[str]) -> List[Tuple[re.Pattern, str]]:
    """Compile keyword patterns into case-insensitive regexes."""
    return [(re.compile(rf"\b{p}\b", re.IGNORECASE), p) for p in patterns]


# Keywords / patterns where Aeris should defer to Zeph
_AERIS_TO_ZEPH_RAW = [
    # English — tech / security / code
    "tech", "security", "code", "system", "diagnostics", "error",
    "CVE", "hack", "exec", "analyse", "analyze", "debug", "log",
    "crash", "exception", "traceback", "firewall", "sandbox",
    "injection", "exploit", "vulnerability", "docker", "container",
    "pipeline", "deploy", "git", "commit", "branch", "merge",
    "python", "javascript", "bash", "shell", "terminal", "ssh",
    "API", "endpoint", "server", "daemon", "service", "process",
    "CPU", "RAM", "disk", "memory leak", "OOM", "segfault",
    "certificate", "TLS", "SSL", "encryption", "token",
    "prompt injection", "jailbreak", "privilege escalation",
    # Norwegian
    "feil", "kode", "sikkerheit", "sikkerhet", "system",
    "diagnostikk", "teknisk", "teknologi", "server",
    "brannmur", "sårbarheit", "sårbarhet", "angrep",
    "skript", "program", "database", "nettverk",
    "logg", "oppdatering", "installasjon", "kompilering",
]

# Keywords / patterns that route to Cody — the code-review and
# refactor agent. Cody's beat is "is this code right?" — diffs, PR
# reviews, refactoring, missing tests, code quality. Some words
# overlap with Zeph's tech list (git, commit) but the intent differs:
# Zeph debugs running systems, Cody reviews proposed changes.
_TO_CODY_RAW = [
    # English — code quality / review / refactor
    "refactor", "refactoring", "review code", "code review",
    "lint", "mypy", "type check", "type checking", "type hints",
    "test coverage", "missing test", "missing tests",
    "regression test", "write a test", "write tests",
    "code style", "naming convention", "dry principle",
    "duplication", "duplicate code", "cyclomatic complexity",
    "code smell", "anti-pattern", "design pattern",
    "abstraction", "architecture review", "pull request review",
    "PR review", "PR feedback", "rebase", "squash",
    # Norwegian
    "refaktor", "refaktorer", "kode-review", "kode review",
    "kodegjennomgang", "kvalitetssjekk", "skrive ein test",
    "skriv ein test", "skrive testar", "skriv testar",
    "kode-stil", "kodestil", "namnekonvensjon",
    "duplikat", "duplisering",
]

# Keywords / patterns where Zeph should defer to Aeris
_ZEPH_TO_AERIS_RAW = [
    # English — emotions, family, creativity, daily life
    "emotions", "feelings", "sad", "happy", "angry", "worried",
    "family", "activities", "kids", "children", "creative",
    "cooking", "recipe", "bedtime", "story", "stories",
    "celebration", "birthday", "party", "holiday", "christmas",
    "drawing", "painting", "craft", "song", "poem", "lullaby",
    "homework help", "school", "parenting", "comfort",
    "morning routine", "evening routine", "chores",
    "play", "game", "fun", "adventure", "imagine",
    "love", "hug", "miss you", "proud of you",
    "dinner", "lunch", "breakfast", "snack", "meal plan",
    # Norwegian
    "føler", "følelser", "trist", "glad", "sint", "bekymra",
    "familie", "aktivitetar", "aktiviteter", "barn", "ungar",
    "kreativ", "kreativt", "matlaging", "oppskrift", "middag",
    "godnathistorie", "godnatthistorie", "bursdag", "feiring",
    "fest", "jul", "påske", "tegning", "sang", "dikt",
    "lekser", "skule", "skole", "leik", "lek",
    "kveldsstell", "morgonstell", "eventyrstund",
    "familiemiddag", "kos", "hygge", "stolt", "savner",
]

# Areas where both agents share responsibility
SHARED_RESPONSIBILITY = [
    "general questions",
    "scheduling",
    "reminders",
    "weather",
    "calendar",
    "timers",
    "simple lookups",
    "status checks",
    "greetings",
    "small talk",
]

# Compiled trigger lists
AERIS_TO_ZEPH_TRIGGERS = _compile(_AERIS_TO_ZEPH_RAW)
ZEPH_TO_AERIS_TRIGGERS = _compile(_ZEPH_TO_AERIS_RAW)
TO_CODY_TRIGGERS = _compile(_TO_CODY_RAW)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def should_escalate_to_zeph(message: str) -> bool:
    """
    Return True if the message contains patterns that indicate Zeph
    should handle it (tech, security, code, diagnostics, etc.).

    :param message: The user message text to evaluate.
    :returns: True if any Aeris→Zeph trigger pattern matches.
    :rtype: bool
    """
    return any(pat.search(message) for pat, _ in AERIS_TO_ZEPH_TRIGGERS)


def should_escalate_to_aeris(message: str) -> bool:
    """
    Return True if the message contains patterns that indicate Aeris
    should handle it (emotions, family, creativity, daily life, etc.).

    :param message: The user message text to evaluate.
    :returns: True if any Zeph→Aeris trigger pattern matches.
    :rtype: bool
    """
    return any(pat.search(message) for pat, _ in ZEPH_TO_AERIS_TRIGGERS)


def should_escalate_to_cody(message: str) -> bool:
    """
    Return True if the message contains patterns that indicate Cody
    should handle it (code review, refactor, missing tests, PR
    feedback, etc.).

    :param message: The user message text to evaluate.
    :returns: True if any to-Cody trigger pattern matches.
    :rtype: bool
    """
    return any(pat.search(message) for pat, _ in TO_CODY_TRIGGERS)


def primary_responder(message: str) -> str:
    """
    Determine which agent should be the primary responder for a message.

    Returns:
        "aeris", "zeph", or "cody"

    Logic:
        1. Count matching triggers for each agent.
        2. The agent with the most matches wins.
        3. Cody → Zeph → Aeris on ties (most-specific first); Aeris
           remains the default when no triggers fire, because she is
           the family-facing frontline agent.
    """
    zeph_score = sum(1 for pat, _ in AERIS_TO_ZEPH_TRIGGERS if pat.search(message))
    aeris_score = sum(1 for pat, _ in ZEPH_TO_AERIS_TRIGGERS if pat.search(message))
    cody_score = sum(1 for pat, _ in TO_CODY_TRIGGERS if pat.search(message))

    # Pick the strict maximum first. On any tie the most-specific
    # responder wins: Cody (code review) is more specialised than
    # Zeph (tech), which is more specialised than Aeris (general).
    best = max(cody_score, zeph_score, aeris_score)
    if best == 0:
        return "aeris"
    if cody_score == best:
        return "cody"
    if zeph_score == best:
        return "zeph"
    return "aeris"


def get_escalation_reason(message: str, from_agent: str) -> str:
    """
    Return a human-readable reason explaining why a message should be
    escalated from *from_agent* to the other agent.

    Args:
        message:    The user message text.
        from_agent: "aeris" or "zeph" — the agent currently handling it.

    Returns:
        A descriptive string, or an empty string if no escalation is needed.
    """
    if from_agent == "aeris":
        matched = [label for pat, label in AERIS_TO_ZEPH_TRIGGERS if pat.search(message)]
        if matched:
            kw = ", ".join(matched[:5])
            return (
                f"Aeris detected technical/security content (keywords: {kw}). "
                f"Escalating to Zeph for expert handling."
            )
    elif from_agent == "zeph":
        matched = [label for pat, label in ZEPH_TO_AERIS_TRIGGERS if pat.search(message)]
        if matched:
            kw = ", ".join(matched[:5])
            return (
                f"Zeph detected family/creative/emotional content (keywords: {kw}). "
                f"Deferring to Aeris who is better suited for this."
            )

    return ""
