"""Council orchestration: broadcast a question to N voices, gather replies.

Layer 11/12 integration (provider trust): every voice's prompt and system
prompt are stripped for the voice's trust tier before they leave the process,
each call is audited, and a question can carry ``max_tier`` — voices in a lower
trust tier than that are only asked after a GO-Gate approval. A voice may name a
``fallback`` voice; switching to it goes through the same tier gate.
"""

from __future__ import annotations

import concurrent.futures
import dataclasses
import logging
import time
from typing import Callable, Iterable, Optional

from core.security import provider_failover, provider_trust

logger = logging.getLogger("council")


@dataclasses.dataclass
class Voice:
    """A single council member.

    name: human-readable handle (e.g. "Claude-Opus", "Gemini-Pro", "Llama-Local")
    vendor: provider tag (e.g. "anthropic", "google", "ollama") — also the key
            into config/providers.yaml ``provider_tiers`` (Layer 11)
    speak: callable that takes (prompt, system_prompt) -> str
    role: optional persona ("strategist", "skeptic", "ethicist", ...)
    timeout_s: how long we wait for this voice before giving up
    fallback: optional voice to try if this one fails; a switch to a lower
              trust tier requires GO-Gate approval (Layer 12)
    """

    name: str
    vendor: str
    speak: Callable[[str, str], str]
    role: str = "generalist"
    timeout_s: int = 60
    fallback: Optional["Voice"] = None

    @property
    def tier(self) -> int:
        return provider_trust.get_tier(self.vendor)


@dataclasses.dataclass
class Reply:
    """One voice's response to the question."""

    voice: str
    vendor: str
    role: str
    text: str
    elapsed_s: float
    error: str | None = None
    tier: int | None = None


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


# ── Audit (Layer 11): provider → tier → strip level, per call ────────────────

_audit_sink: Optional[Callable[[dict], None]] = None
_recent_audit: list[dict] = []
_RECENT_MAX = 200


def set_audit_sink(sink: Optional[Callable[[dict], None]]) -> None:
    """Plug a ledger (e.g. a hash-chained audit table). Metadata only, never content."""
    global _audit_sink
    _audit_sink = sink


def recent_audit() -> list[dict]:
    return list(_recent_audit)


def _audit_provider_call(agent: str, voice: Voice, tier: int) -> None:
    """Fail-open: auditing must never block or abort a model call."""
    entry = {
        "agent": agent,
        "voice": voice.name,
        "provider": voice.vendor,
        "tier": tier,
        "tier_name": provider_trust.get_tier_name(tier),
        "strip_level": provider_trust.get_strip_level(tier),
        "ts": time.time(),
    }
    try:
        _recent_audit.append(entry)
        del _recent_audit[:-_RECENT_MAX]
        logger.info(
            "[PROVIDER_TRUST] %s → %s (%s) tier=%d strip=%s",
            agent, voice.name, voice.vendor, tier, entry["strip_level"],
        )
        if _audit_sink is not None:
            _audit_sink(dict(entry))
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("[PROVIDER_TRUST] audit sink failed (fail-open): %s", exc)


class Council:
    """A council of voices. Ask a question, get every voice's view."""

    def __init__(self, voices: Iterable[Voice], default_system: str = "", agent: str = "council"):
        self.voices = list(voices)
        self.default_system = default_system
        self.agent = agent
        if not self.voices:
            raise ValueError("Council needs at least one voice")

    def ask(
        self,
        question: str,
        system_prompt: str | None = None,
        synthesizer: Callable[[Verdict], str] | None = None,
        max_tier: int | None = None,
    ) -> Verdict:
        """Broadcast the question to every voice in parallel. Optionally
        synthesise into one answer.

        ``max_tier`` marks the question as sensitive: voices in a lower trust
        tier (higher number) are only asked after a GO-Gate approval; denied or
        timed-out approvals leave the voice out with ``error="tier_blocked"``.
        """
        sys = system_prompt if system_prompt is not None else self.default_system
        replies: list[Reply] = []
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, len(self.voices))
        ) as pool:
            futures = {
                pool.submit(self._ask_one, v, question, sys, max_tier): v for v in self.voices
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

    def _ask_one(
        self, voice: Voice, question: str, system_prompt: str, max_tier: int | None = None
    ) -> Reply:
        start = time.monotonic()
        tier = voice.tier

        # Layer 12: sensitive question → lower-trust voice needs a human GO
        if max_tier is not None and tier > max_tier:
            if not provider_failover.request_tier_approval(self.agent, voice.vendor, max_tier):
                logger.warning("voice %s blocked: TIER_%d > max TIER_%d", voice.name, tier, max_tier)
                return Reply(
                    voice=voice.name, vendor=voice.vendor, role=voice.role, text="",
                    elapsed_s=time.monotonic() - start, error="tier_blocked", tier=tier,
                )

        # Layer 11: strip for this voice's tier, then audit
        q = provider_trust.strip_context_for_tier(question, tier)
        s = provider_trust.strip_context_for_tier(system_prompt, tier)
        _audit_provider_call(self.agent, voice, tier)

        try:
            text = voice.speak(q, s)
            return Reply(
                voice=voice.name, vendor=voice.vendor, role=voice.role,
                text=text.strip(), elapsed_s=time.monotonic() - start, tier=tier,
            )
        except Exception as exc:
            logger.warning("voice %s failed: %s", voice.name, exc)
            if voice.fallback is not None:
                # Layer 12: no silent downgrade — the switch goes through the tier gate
                decision = provider_failover.check_failover(self.agent, voice.vendor, voice.fallback.vendor)
                if decision.approved:
                    reply = self._ask_one(voice.fallback, question, system_prompt, max_tier)
                    reply.elapsed_s = time.monotonic() - start
                    return reply
                return Reply(
                    voice=voice.name, vendor=voice.vendor, role=voice.role, text="",
                    elapsed_s=time.monotonic() - start,
                    error=f"{exc}; fallback to {voice.fallback.vendor} queued: {decision.reason}",
                    tier=tier,
                )
            return Reply(
                voice=voice.name, vendor=voice.vendor, role=voice.role, text="",
                elapsed_s=time.monotonic() - start, error=str(exc), tier=tier,
            )
