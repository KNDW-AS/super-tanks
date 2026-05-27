"""Council orchestration: broadcast a question to N voices, gather replies."""

from __future__ import annotations

import concurrent.futures
import dataclasses
import logging
import time
from typing import Callable, Iterable

logger = logging.getLogger("council")


@dataclasses.dataclass
class Voice:
    """A single council member.

    name: human-readable handle (e.g. "Claude-Opus", "Gemini-Pro", "Llama-Local")
    vendor: provider tag (e.g. "anthropic", "google", "ollama")
    speak: callable that takes (prompt, system_prompt) -> str
    role: optional persona ("strategist", "skeptic", "ethicist", ...)
    timeout_s: how long we wait for this voice before giving up
    """

    name: str
    vendor: str
    speak: Callable[[str, str], str]
    role: str = "generalist"
    timeout_s: int = 60


@dataclasses.dataclass
class Reply:
    """One voice's response to the question."""

    voice: str
    vendor: str
    role: str
    text: str
    elapsed_s: float
    error: str | None = None


@dataclasses.dataclass
class Verdict:
    """The council's collected answer."""

    question: str
    system_prompt: str
    replies: list[Reply]
    synthesis: str | None = None

    @property
    def quorum(self) -> int:
        return sum(1 for r in self.replies if r.error is None)

    @property
    def total(self) -> int:
        return len(self.replies)


class Council:
    """A council of voices. Ask a question, get every voice's view."""

    def __init__(self, voices: Iterable[Voice], default_system: str = ""):
        self.voices = list(voices)
        self.default_system = default_system
        if not self.voices:
            raise ValueError("Council needs at least one voice")

    def ask(
        self,
        question: str,
        system_prompt: str | None = None,
        synthesizer: Callable[[Verdict], str] | None = None,
    ) -> Verdict:
        """Broadcast the question to every voice in parallel. Optionally
        synthesise into one answer.
        """
        sys = system_prompt if system_prompt is not None else self.default_system
        replies: list[Reply] = []
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, len(self.voices))
        ) as pool:
            futures = {
                pool.submit(self._ask_one, v, question, sys): v for v in self.voices
            }
            for fut in concurrent.futures.as_completed(futures):
                replies.append(fut.result())
        replies.sort(key=lambda r: r.voice)

        verdict = Verdict(
            question=question, system_prompt=sys, replies=replies, synthesis=None
        )
        if synthesizer is not None:
            try:
                verdict.synthesis = synthesizer(verdict)
            except Exception:
                logger.exception("synthesizer raised; verdict left without synthesis")
        return verdict

    @staticmethod
    def _ask_one(voice: Voice, question: str, system_prompt: str) -> Reply:
        start = time.monotonic()
        try:
            text = voice.speak(question, system_prompt)
            return Reply(
                voice=voice.name,
                vendor=voice.vendor,
                role=voice.role,
                text=text.strip(),
                elapsed_s=time.monotonic() - start,
            )
        except Exception as exc:
            logger.warning("voice %s failed: %s", voice.name, exc)
            return Reply(
                voice=voice.name,
                vendor=voice.vendor,
                role=voice.role,
                text="",
                elapsed_s=time.monotonic() - start,
                error=str(exc),
            )
