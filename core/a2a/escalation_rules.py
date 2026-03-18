"""
core/a2a/escalation_rules.py
==============================
Escalation rules between Aeris and Zeph agents.

Determines when one agent should defer to the other based on message
content analysis. Supports both English and Norwegian keywords.

Aeris handles: emotions, family, creativity, daily life, cooking, celebrations.
Zeph handles:  tech, security, code, system diagnostics, error analysis.
Shared:        general questions, scheduling, reminders, weather.
"""

import re
from typing import List, Tuple

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


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def should_escalate_to_zeph(message: str) -> bool:
    """
    Return True if the message contains patterns that indicate Zeph
    should handle it (tech, security, code, diagnostics, etc.).
    """
    return any(pat.search(message) for pat, _ in AERIS_TO_ZEPH_TRIGGERS)


def should_escalate_to_aeris(message: str) -> bool:
    """
    Return True if the message contains patterns that indicate Aeris
    should handle it (emotions, family, creativity, daily life, etc.).
    """
    return any(pat.search(message) for pat, _ in ZEPH_TO_AERIS_TRIGGERS)


def primary_responder(message: str) -> str:
    """
    Determine which agent should be the primary responder for a message.

    Returns:
        "aeris" or "zeph"

    Logic:
        1. Count matching triggers for each agent.
        2. The agent with more matches wins.
        3. On a tie or zero matches, default to "aeris" (she is the
           family-facing frontline agent).
    """
    zeph_score = sum(1 for pat, _ in AERIS_TO_ZEPH_TRIGGERS if pat.search(message))
    aeris_score = sum(1 for pat, _ in ZEPH_TO_AERIS_TRIGGERS if pat.search(message))

    if zeph_score > aeris_score:
        return "zeph"
    # Aeris is the default — she handles general conversation and
    # anything that does not clearly belong to Zeph's domain.
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
