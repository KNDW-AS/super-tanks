"""
core/voice/voice_pipeline.py
==============================
Voice I/O orchestration.

Ties together:

    DIQWakeWord  → DIQVoiceSTT  → voice_security.vet_transcript
                                     ↓
                          escalation_rules + GO-Gate
                                     ↓
                        (agent runtime hook: out of scope)
                                     ↓
              voice_profiles + room_router → DIQVoiceTTS

The pipeline is the orchestrator only. STT/TTS/wake-word
implementations live in `core.voice.backends.*` and are passed in
explicitly — no global state. Tests can wire stub backends and
exercise the whole flow deterministically.

handle_transcript() is the single public entry point. The voice
runtime (HA-Voice satellite, Wyoming receiver, whatever the operator
runs on Z620) calls it once per finalised transcript. handle_transcript
returns a VoiceResponse describing what was said in reply and which
speaker entity it was sent to — used for tests + the morning Telegram
digest, and as the audit record.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Awaitable, Callable, List, Optional

from core.diq.diq_voice import DIQVoiceTTS, Transcript, Utterance
from core.voice.room_router import speaker_for_room
from core.voice.voice_profiles import get_voice_profile
from core.voice.voice_security import VoiceIntent, vet_transcript

logger = logging.getLogger("super_tanks.voice.pipeline")


# Agent-runtime hook: a callable that takes (intent, agent_text_in) and
# returns the agent's spoken response. The voice pipeline doesn't know
# how Aeris/Zeph actually decide what to say — that's the agent runtime
# (the actual LLM client / brain) which lives outside this repo. We
# accept a callable here so the pipeline is unit-testable with a stub.
AgentHook = Callable[[VoiceIntent], Awaitable[str]]


@dataclass
class VoiceResponse:
    """What the pipeline did with one transcript."""
    intent: VoiceIntent
    response_text: str = ""
    spoken_on: Optional[str] = None   # speaker entity_id; None if not spoken
    blocked: bool = False
    block_reason: str = ""
    requires_go_gate: bool = False
    audit_notes: List[str] = field(default_factory=list)


# ── The pipeline ───────────────────────────────────────────────────────────

async def handle_transcript(
    transcript: Transcript,
    *,
    tts: DIQVoiceTTS,
    agent_hook: AgentHook,
) -> VoiceResponse:
    """Run one transcript end-to-end.

    `tts` is the active TTS backend (Piper, ElevenLabs, etc.).
    `agent_hook` is the runtime that turns a routed VoiceIntent into
    text to speak back. The pipeline never lets `agent_hook` raw-text
    out — every response goes through TTS with the right voice and
    the right speaker.
    """
    intent = vet_transcript(transcript)
    audit: List[str] = [
        f"corr={intent.correlation_id}",
        f"room={transcript.room_id}",
        f"conf={transcript.confidence:.2f}",
        f"target={intent.routing_target}",
        f"critical={intent.is_critical}",
    ]

    if intent.blocked:
        logger.info("[VOICE] transcript blocked: %s", intent.block_reason)
        return VoiceResponse(
            intent=intent, blocked=True,
            block_reason=intent.block_reason, audit_notes=audit,
        )

    # Critical commands NEVER bypass GO-Gate, regardless of trust. We
    # don't enqueue the approval here — the pipeline signals it on
    # the response, and the higher-level voice runtime is responsible
    # for routing the GO-Gate handshake to William's Telegram (or
    # another approval channel). Acting now without that handshake is
    # exactly the "TV played a command" bypass we're guarding against.
    if intent.requires_go_gate:
        audit.append("go_gate_required")
        ack = _gogate_acknowledgement(intent)
        spoken_on = await _speak_to_intent_room(
            ack, intent, tts=tts, agent_id=intent.routing_target,
            audit=audit,
        )
        return VoiceResponse(
            intent=intent, response_text=ack,
            spoken_on=spoken_on, requires_go_gate=True,
            audit_notes=audit,
        )

    # Hand off to the agent runtime to compose the reply text.
    try:
        response_text = await agent_hook(intent)
    except Exception as exc:
        logger.error("[VOICE] agent_hook raised: %s", exc)
        response_text = ("Beklagar, eg fekk ikkje svar denne gongen. "
                         "Eg har logga det.")
        audit.append(f"agent_hook_error={exc}")

    spoken_on = await _speak_to_intent_room(
        response_text, intent, tts=tts,
        agent_id=intent.routing_target, audit=audit,
    )
    return VoiceResponse(
        intent=intent, response_text=response_text,
        spoken_on=spoken_on, audit_notes=audit,
    )


def _gogate_acknowledgement(intent: VoiceIntent) -> str:
    """The single response Aeris/Zeph gives when a critical command
    has been intercepted into GO-Gate. The text is identical for
    both agents so an attacker can't infer trust by listening for
    a different phrase."""
    return ("Eg har sendt forespurnaden til godkjenning. "
            "Du må stadfeste det på Telegram før eg gjer noko.")


async def _speak_to_intent_room(
    text: str,
    intent: VoiceIntent,
    *,
    tts: DIQVoiceTTS,
    agent_id: str,
    audit: List[str],
) -> Optional[str]:
    """Pick the speaker + voice profile, send to TTS. Returns the
    speaker entity_id that played the audio, or None if no speaker
    was available (in which case the runtime falls back to Telegram).
    """
    speaker = speaker_for_room(intent.transcript.room_id)
    if speaker is None:
        audit.append("no_speaker_available")
        logger.warning("[VOICE] no speaker for room=%s",
                       intent.transcript.room_id)
        return None
    try:
        profile = get_voice_profile(agent_id)
    except KeyError as exc:
        audit.append(f"voice_profile_missing={exc}")
        logger.error("[VOICE] unknown agent for TTS: %s", exc)
        return None
    utterance = Utterance(
        text=text, voice_id=profile.voice_id,
        speaker_entity=speaker, agent_id=agent_id,
        correlation_id=intent.correlation_id,
    )
    try:
        ok = await tts.speak(utterance)
    except Exception as exc:
        audit.append(f"tts_raised={exc}")
        logger.error("[VOICE] TTS backend raised: %s", exc)
        return None
    if not ok:
        audit.append("tts_returned_false")
        return None
    audit.append(f"spoken_on={speaker} voice={profile.voice_id}")
    return speaker
