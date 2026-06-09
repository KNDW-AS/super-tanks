"""
core/voice/voice_security.py
==============================
Voice-input security gates.

Voice is THE attacker's loudest entry point. The same microphone that
hears William also hears:

  - household guests
  - small children imitating "Aeris, unlock the door"
  - TV ads ("Hey Aeris, buy the…")
  - audio deepfakes played from a phone
  - the neighbour shouting through a window

This module enforces two invariants before a transcript ever reaches
agent logic:

  1. ZEF SCAN — every voice transcript is run through the same
     prompt-injection filter as text input (`scan_message`). A
     transcript that lands as BLOCK is dropped and logged; the
     agent never sees it.

  2. CRITICAL-COMMAND ELEVATION — voice intents that would touch
     locks, alarms, the front door, super_tanks_mode, or any
     WRITE/EXEC tool are ALWAYS routed through GO-Gate. Trust
     score does NOT lower this bar. Voice is a low-confidence
     authentication channel by design — anyone in earshot is
     "authenticated as voice", and that's not enough for
     irreversible operations.

A transcript that passes both gates is wrapped in a `VoiceIntent`
that carries the scan verdict + correlation id forward. The agent
runtime receives the intent (not raw text) so the audit trail is
complete.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from core.diq.diq_voice import Transcript

logger = logging.getLogger("super_tanks.voice.security")


# Norwegian + English keywords that flip a voice intent into the
# "critical, force GO-Gate" lane. Patterns are intentionally broad —
# false positives just mean the operator approves with a tap; false
# negatives mean an unlocked door.
_CRITICAL_PATTERNS = [
    # English
    r"\bunlock\b", r"\block\b", r"\bdisarm\b", r"\barm\b",
    r"\bopen\s+(the\s+)?door\b", r"\bopen\s+(the\s+)?front\s+door\b",
    r"\bgarage\b", r"\bsafe\s+mode\b", r"\blockdown\b",
    r"\bautonomous\b", r"\bdelete\b", r"\bdrop\b", r"\bwipe\b",
    r"\btransfer\b.{0,40}\bmoney\b",
    r"\bbuy\b", r"\border\b",
    # Norwegian
    r"\blås(e|er)?\s+opp\b", r"\blås(e|er)?\b",
    r"\båpne\s+(døra|ytterdøra|døren)\b",
    r"\balarmen?\s+av\b", r"\balarm\s+(på|av)\b",
    r"\bavvepn\b", r"\bbevæpn\b",
    r"\bslett\b", r"\bsletta\b",
    r"\bkjøp\b", r"\bbestill\b",
    r"\boverfør\b.{0,40}\b(penger|kroner)\b",
]
_CRITICAL_RE = re.compile("|".join(_CRITICAL_PATTERNS), re.IGNORECASE)


@dataclass(frozen=True)
class VoiceIntent:
    """A vetted voice command ready for the agent runtime.

    The presence of this object is the contract that voice_security
    has already approved the transcript: ZEF scanned, critical-command
    elevation flagged, and a correlation id assigned. Agent runtime
    code may rely on these invariants.
    """
    transcript: Transcript
    correlation_id: str
    is_critical: bool
    routing_target: str  # "aeris" or "zeph" — pre-routed before agent runtime
    requires_go_gate: bool
    blocked: bool
    block_reason: str = ""
    accepted_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())


def is_critical_command(text: str) -> bool:
    """Does this transcript look like it wants to do something
    irreversible? Used by `vet_transcript`, exposed publicly for
    tests + the operator CLI."""
    return bool(_CRITICAL_RE.search(text or ""))


def vet_transcript(transcript: Transcript) -> VoiceIntent:
    """Run a transcript through both gates and return a structured
    intent. The intent is ALWAYS returned (never raises) so the
    voice pipeline can log + skip cleanly; check
    `intent.blocked` before acting.

    The routing target is decided HERE (not later) so a compromised
    agent runtime can't second-guess routing. Aeris is the default
    family-facing responder; clear technical/security cues route to
    Zeph via the same `escalation_rules.primary_responder` that
    governs text routing.
    """
    corr = str(uuid.uuid4())
    text = (transcript.text or "").strip()
    if not text:
        return VoiceIntent(
            transcript=transcript, correlation_id=corr,
            is_critical=False, routing_target="aeris",
            requires_go_gate=False, blocked=True,
            block_reason="empty transcript",
        )

    # Low confidence: refuse silently. The voice pipeline asks the
    # user to repeat instead of guessing.
    if transcript.confidence < 0.5:
        logger.info(
            "[VOICE] low-confidence transcript dropped: room=%s conf=%.2f",
            transcript.room_id, transcript.confidence,
        )
        return VoiceIntent(
            transcript=transcript, correlation_id=corr,
            is_critical=False, routing_target="aeris",
            requires_go_gate=False, blocked=True,
            block_reason=f"low confidence {transcript.confidence:.2f}",
        )

    # ZEF scan of the transcript text. Same filter as text input.
    try:
        from core.security.zef_injection_filter import scan_message, FilterVerdict
        result = scan_message(text, source=f"voice:{transcript.room_id}")
        if result.verdict is FilterVerdict.BLOCK:
            logger.warning(
                "[VOICE] transcript BLOCKED by ZEF in room=%s patterns=%s",
                transcript.room_id, result.matched_patterns,
            )
            return VoiceIntent(
                transcript=transcript, correlation_id=corr,
                is_critical=False, routing_target="aeris",
                requires_go_gate=False, blocked=True,
                block_reason=(f"ZEF blocked: "
                              f"{', '.join(result.matched_patterns)}"),
            )
    except Exception as exc:
        # Fail-CLOSED. If we can't scan, we don't pass the input —
        # otherwise an attacker who can disable ZEF gets a free
        # bypass on the voice channel.
        logger.error("[VOICE] ZEF scan failed; dropping transcript: %s", exc)
        return VoiceIntent(
            transcript=transcript, correlation_id=corr,
            is_critical=False, routing_target="aeris",
            requires_go_gate=False, blocked=True,
            block_reason=f"ZEF unavailable, failing closed: {exc}",
        )

    critical = is_critical_command(text)

    # Route Aeris-vs-Zeph using the SAME logic text input uses.
    try:
        from core.a2a.escalation_rules import primary_responder
        target = primary_responder(text)
    except Exception as exc:
        logger.warning("[VOICE] primary_responder failed, defaulting Aeris: %s",
                       exc)
        target = "aeris"

    return VoiceIntent(
        transcript=transcript, correlation_id=corr,
        is_critical=critical, routing_target=target,
        # Critical voice commands ALWAYS force GO-Gate, regardless of
        # the agent's role-permission. Voice is too easy to spoof to
        # honour any trust-derived shortcut here.
        requires_go_gate=critical,
        blocked=False,
    )
