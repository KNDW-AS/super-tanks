"""
core/voice/backends/whisper_stt.py
====================================
Whisper STT backend skeleton.

Wraps OpenAI's open-source Whisper (or, preferably, faster-whisper via
CTranslate2 for ~4x speedup on the same CPU) and adapts it to the
DIQVoiceSTT contract.

Like the Piper backend, this file is the ADAPTER — the actual model
files and Python bindings live on the deployment machine. The
operator picks one of:

    ST_WHISPER_MODEL          path to a faster-whisper model directory
                              (e.g. /opt/whisper/large-v3-int8)
    ST_WHISPER_DEVICE         "cpu" | "cuda" | "auto"  (default cpu)
    ST_WHISPER_LANG           default language hint, e.g. "no"

Without ST_WHISPER_MODEL, every transcribe() returns an empty
transcript with confidence 0 — the voice pipeline already drops
low-confidence transcripts so this fails closed (no silent acceptance
of garbage).
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import AsyncIterator

from core.diq.diq_voice import DIQVoiceSTT, Transcript

logger = logging.getLogger("super_tanks.voice.whisper")

ENV_WHISPER_MODEL = "ST_WHISPER_MODEL"
ENV_WHISPER_DEVICE = "ST_WHISPER_DEVICE"
ENV_WHISPER_LANG = "ST_WHISPER_LANG"


class WhisperSTTBackend(DIQVoiceSTT):
    def __init__(self,
                 model_path: str = "",
                 device: str = "",
                 default_language: str = ""):
        self.model_path = model_path or os.environ.get(ENV_WHISPER_MODEL, "")
        self.device = device or os.environ.get(ENV_WHISPER_DEVICE, "cpu")
        self.default_language = (default_language
                                 or os.environ.get(ENV_WHISPER_LANG, "no"))
        self._model = None  # lazy-loaded on first call

    def _ensure_model(self):
        if self._model is not None:
            return
        if not self.model_path:
            return
        try:
            # Production: from faster_whisper import WhisperModel
            from faster_whisper import WhisperModel  # type: ignore
            self._model = WhisperModel(self.model_path, device=self.device)
        except Exception as exc:
            logger.warning("[WHISPER] could not load model: %s", exc)
            self._model = None

    async def transcribe(self, audio_ref: str, *,
                         language: str = "no") -> Transcript:
        self._ensure_model()
        if self._model is None:
            logger.warning(
                "[WHISPER] not configured (set %s); skipping audio %s",
                ENV_WHISPER_MODEL, audio_ref,
            )
            return Transcript(text="", room_id="unknown", confidence=0.0,
                              audio_ref=audio_ref)
        loop = asyncio.get_running_loop()

        def _run():
            # faster-whisper returns (segments, info) where segments is
            # a generator; collecting it materialises the transcript.
            segments, info = self._model.transcribe(
                audio_ref, language=(language or self.default_language),
            )
            text_parts = []
            avg_logprob = []
            for seg in segments:
                text_parts.append(seg.text)
                if hasattr(seg, "avg_logprob"):
                    avg_logprob.append(seg.avg_logprob)
            confidence = (sum(_logprob_to_confidence(p) for p in avg_logprob)
                          / len(avg_logprob)) if avg_logprob else 0.5
            return " ".join(t.strip() for t in text_parts).strip(), confidence

        try:
            text, confidence = await loop.run_in_executor(None, _run)
        except Exception as exc:
            logger.error("[WHISPER] transcribe raised: %s", exc)
            return Transcript(text="", room_id="unknown", confidence=0.0,
                              audio_ref=audio_ref)
        return Transcript(text=text, room_id="unknown",
                          confidence=max(0.0, min(1.0, confidence)),
                          audio_ref=audio_ref)

    async def stream(self, audio_ref: str, *,
                     language: str = "no") -> AsyncIterator[Transcript]:
        # faster-whisper segments arrive as a generator; the simplest
        # bridge is to yield the final transcript once. Real streaming
        # needs a different model (Whisper-Streaming / RTPP). Operators
        # who want it can override this method.
        final = await self.transcribe(audio_ref, language=language)
        yield final


def _logprob_to_confidence(logprob: float) -> float:
    """Map Whisper's avg_logprob (typically -1.0..0.0) to a 0..1
    confidence. -0.2 ≈ very confident, -1.0 ≈ guessing."""
    import math
    return max(0.0, min(1.0, math.exp(logprob)))
