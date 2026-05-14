"""
DIQ Voice Contract — DO NOT MODIFY
Version: 1.0

Voice I/O contract for Aeris and Zeph.

All speech-to-text, text-to-speech, and wake-word events flow through
this interface. Implementations live in core/voice/backends/ —
Piper for local TTS, Whisper for local STT, Wyoming/HA-Voice for
satellites. This file is the stable surface the rest of Super Tanks
calls into.

Three abstractions:

  DIQVoiceSTT     — turn audio frames into transcripts
  DIQVoiceTTS     — turn agent responses into audio for a given voice
  DIQWakeWord     — detect "Aeris" / "Zeph" / other configured words

Plus three value types:

  Transcript      — what was said + where + when
  Utterance       — what to say + which voice + which speaker
  WakeEvent       — wake word detected + room + audio handle

NOTE: the voice surface is THE attacker's loudest entry point.
Anyone in earshot of a mic — household guest, neighbour, TV ad,
voice deepfake — can attempt to issue commands. Every transcript
that flows from STT INTO an agent MUST go through ZEF first
(core.voice.voice_security.scan_transcript) and every WRITE/EXEC
intent derived from voice MUST round-trip through GO-Gate, regardless
of trust score. Voice is a low-confidence input channel by design.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional


# ── Value types ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Transcript:
    """One STT result. `text` is the transcribed utterance.

    `room_id` identifies which mic/satellite captured it so the
    voice pipeline can route the agent's reply to the right
    speaker. `confidence` is 0..1 from the STT backend; below 0.5
    the pipeline asks the user to repeat instead of acting.

    `audio_ref` is an opaque handle the backend uses internally
    (e.g. a wave-file path or stream id). Callers should not
    interpret it — only pass it back to the same backend if needed.
    """
    text: str
    room_id: str
    confidence: float
    captured_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())
    audio_ref: Optional[str] = None
    speaker_hint: Optional[str] = None  # weak voice-bio guess, NOT auth


@dataclass(frozen=True)
class Utterance:
    """One TTS request from an agent. `voice_id` selects which
    persona speaks; see core.voice.voice_profiles for the canonical
    map (aeris→warm Norwegian female, zeph→calm Norwegian male)."""
    text: str
    voice_id: str
    speaker_entity: str       # HA media_player.* or similar
    agent_id: str
    correlation_id: Optional[str] = None


@dataclass(frozen=True)
class WakeEvent:
    """Wake-word detection from a satellite. Triggers an STT
    capture window on the same mic for the next N seconds."""
    wake_word: str            # "aeris" or "zeph"
    room_id: str
    detected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())
    audio_ref: Optional[str] = None


# ── Contracts ─────────────────────────────────────────────────────────────

class DIQVoiceSTT(ABC):
    """Speech-to-text backend contract."""

    @abstractmethod
    async def transcribe(self, audio_ref: str, *,
                         language: str = "no") -> Transcript:
        """Block until the audio has been fully transcribed.
        Backends MUST raise on hardware errors so the pipeline can
        log + skip instead of silently dropping the user's command.
        """
        ...

    @abstractmethod
    async def stream(self, audio_ref: str, *,
                     language: str = "no") -> AsyncIterator[Transcript]:
        """Yield partial transcripts as the user speaks. The final
        yielded transcript is the canonical one and is also what
        gets logged. Backends without streaming support may yield
        once with the final result."""
        ...


class DIQVoiceTTS(ABC):
    """Text-to-speech backend contract."""

    @abstractmethod
    async def speak(self, utterance: Utterance) -> bool:
        """Synthesise + play. Returns True on success. False means
        the audio was synthesised but playback failed (e.g. speaker
        offline); the caller decides whether to retry on another
        speaker."""
        ...

    @abstractmethod
    def list_voices(self) -> List[Dict[str, Any]]:
        """Voices available to the operator. Each entry: {voice_id,
        language, gender, description}. Used by the CLI to map
        Aeris/Zeph → backend voice ids."""
        ...


class DIQWakeWord(ABC):
    """Wake-word detection contract. Implementations run inside the
    Wyoming satellite or as a separate daemon."""

    @abstractmethod
    async def stream_events(self) -> AsyncIterator[WakeEvent]:
        """Yield WakeEvents as they happen. This is an infinite
        async iterator until the caller closes it."""
        ...

    @abstractmethod
    def configured_wake_words(self) -> List[str]:
        """List of wake words this detector is trained for. The
        pipeline uses this to refuse routing for unknown words."""
        ...
