"""
core/security/provider_failover.py
====================================
Layer 12 — Provider Failover with GO-Gate. *No silent downgrade.*

Rule: when an agent moves from a provider in a higher trust tier to one in a
lower tier (see Layer 11, :mod:`core.security.provider_trust`), the switch is
not automatic. A GO-Gate approval request is created; until a human approves
it the message is *queued*, never sent to the less-trusted provider. Same or
higher tier switches are automatic.

Approval uses the existing :class:`core.ask_admin.ApprovalStore` — the same
store the GO-Gate daemon, the Telegram approve/deny buttons and
``scripts/demo_go_gate.py`` operate on — so no new approval channel is
introduced. Fail-closed: any error, timeout or missing store means *denied*.

Fallback chains and the approval timeout are configured in
``config/providers.yaml`` (``fallback_chains``, ``downgrade_approval_timeout_s``).
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from core.security.provider_trust import get_tier, get_tier_name, load_config_file

logger = logging.getLogger("supertanks.provider_failover")

DEFAULT_APPROVAL_TIMEOUT_S = 300
TOOL_NAME = "provider_downgrade"

_fallback_chains: Dict[str, List[str]] = {}
_approval_timeout_s: int = DEFAULT_APPROVAL_TIMEOUT_S


@dataclass
class FailoverResult:
    """Outcome of a failover decision."""
    approved: bool
    provider: Optional[str] = None
    queued: bool = False
    reason: str = ""


def _default_config_path() -> str:
    return os.path.join(os.path.dirname(__file__), "..", "..", "config", "providers.yaml")


def load_failover_config(config_path: Optional[str] = None) -> None:
    """Load ``fallback_chains`` and ``downgrade_approval_timeout_s``. Missing file = defaults."""
    global _fallback_chains, _approval_timeout_s
    _fallback_chains = {}
    _approval_timeout_s = DEFAULT_APPROVAL_TIMEOUT_S
    path = config_path or _default_config_path()
    try:
        cfg = load_config_file(path)
        if not isinstance(cfg, dict):
            raise ValueError("top level is not a mapping")
    except FileNotFoundError:
        return
    except Exception as exc:
        logger.warning("[FAILOVER] could not load %s: %s — using defaults", path, exc)
        return
    chains = cfg.get("fallback_chains") or {}
    for agent, chain in chains.items():
        if isinstance(chain, list):
            _fallback_chains[str(agent)] = [str(p) for p in chain]
    try:
        _approval_timeout_s = max(0, int(cfg.get("downgrade_approval_timeout_s", DEFAULT_APPROVAL_TIMEOUT_S)))
    except (TypeError, ValueError):
        pass


def get_fallback_chain(agent: str) -> List[str]:
    """Configured fallback chain for ``agent`` (falls back to ``default``)."""
    return list(_fallback_chains.get(agent) or _fallback_chains.get("default") or [])


def get_approval_timeout_s() -> int:
    return _approval_timeout_s


# ── Decision ─────────────────────────────────────────────────────────────────

def check_failover(agent: str, current_provider: str, fallback_provider: str) -> FailoverResult:
    """
    May ``agent`` move from ``current_provider`` to ``fallback_provider``?

    Same or higher tier → approved automatically.
    Lower tier → GO-Gate; denied/timeout → ``queued=True``.
    """
    current_tier = get_tier(current_provider)
    fallback_tier = get_tier(fallback_provider)

    if fallback_tier <= current_tier:
        logger.info(
            "[FAILOVER] %s: %s (TIER_%d) → %s (TIER_%d) — auto-approved (same/upgrade)",
            agent, current_provider, current_tier, fallback_provider, fallback_tier,
        )
        return FailoverResult(
            approved=True, provider=fallback_provider,
            reason=f"same or higher tier: {get_tier_name(current_tier)} → {get_tier_name(fallback_tier)}",
        )

    logger.warning(
        "[FAILOVER] %s: DOWNGRADE %s (TIER_%d) → %s (TIER_%d) — requesting GO-Gate",
        agent, current_provider, current_tier, fallback_provider, fallback_tier,
    )
    approved = _request_go_gate_approval(
        agent=agent,
        reason=(
            f"PROVIDER DOWNGRADE for {agent}: {current_provider} ({get_tier_name(current_tier)}) → "
            f"{fallback_provider} ({get_tier_name(fallback_tier)}). Content is stripped for the lower tier, "
            f"but context may still leak. Deny or ignore to keep the message queued."
        ),
        args={
            "agent": agent, "from": current_provider, "to": fallback_provider,
            "from_tier": current_tier, "to_tier": fallback_tier,
        },
    )
    if approved:
        return FailoverResult(
            approved=True, provider=fallback_provider,
            reason=f"GO-Gate approved downgrade: {get_tier_name(current_tier)} → {get_tier_name(fallback_tier)}",
        )
    logger.warning("[FAILOVER] %s: GO-Gate denied/timeout — queuing message", agent)
    return FailoverResult(
        approved=False, queued=True,
        reason=f"GO-Gate denied/timeout for downgrade to {fallback_provider}",
    )


def request_tier_approval(agent: str, provider: str, max_tier: int) -> bool:
    """
    May ``agent`` send this request to ``provider`` although its tier is lower
    (a higher number) than ``max_tier``? Used by the council when a question is
    marked as sensitive. GO-Gate; fail-closed.
    """
    tier = get_tier(provider)
    if tier <= max_tier:
        return True
    logger.warning(
        "[FAILOVER] %s: %s is TIER_%d, question allows max TIER_%d — requesting GO-Gate",
        agent, provider, tier, max_tier,
    )
    return _request_go_gate_approval(
        agent=agent,
        reason=(
            f"LOWER-TRUST PROVIDER for {agent}: {provider} is {get_tier_name(tier)}, the request allows "
            f"at most {get_tier_name(max_tier)}. Approve to send stripped content anyway."
        ),
        args={"agent": agent, "provider": provider, "tier": tier, "max_tier": max_tier},
    )


def on_provider_error(agent: str, current_provider: str, error: str) -> FailoverResult:
    """
    Called when a provider fails (rate limit, timeout, error). Walks the agent's
    fallback chain from ``current_provider`` and returns the first allowed
    provider, or ``queued=True`` when none is allowed.
    """
    chain = get_fallback_chain(agent)
    try:
        idx = chain.index(current_provider)
    except ValueError:
        idx = -1
    for next_provider in chain[idx + 1:]:
        result = check_failover(agent, current_provider, next_provider)
        if result.approved:
            return result
    logger.warning("[FAILOVER] %s: no allowed provider left after %s (%s) — queuing", agent, current_provider, error)
    return FailoverResult(approved=False, queued=True, reason="all providers exhausted")


# ── GO-Gate ──────────────────────────────────────────────────────────────────

def _request_go_gate_approval(
    agent: str,
    reason: str,
    args: Dict[str, object],
    timeout_s: Optional[int] = None,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """
    Create an approval request in the shared :class:`ApprovalStore` and wait for
    a human decision. Returns ``True`` only on an explicit APPROVED. Fail-closed
    on denial, timeout, expiry or any error.
    """
    if timeout_s is None:
        timeout_s = _approval_timeout_s
    try:
        from core.ask_admin import ApprovalStatus, get_approval_store
    except Exception as exc:
        logger.warning("[FAILOVER] approval store unavailable (%s) — denying", exc)
        return False

    try:
        store = get_approval_store()
        request = None
        try:
            request = store.find_pending_duplicate(tool_name=TOOL_NAME, user_id=agent, args=args)
        except Exception as exc:
            logger.warning("[FAILOVER] find_pending_duplicate failed: %s", exc)
        if request is None:
            request = store.create_request(
                tool_name=TOOL_NAME, user_id=agent, reason=reason, args=args,
                ttl_seconds=timeout_s + 60,
            )
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                current = store.get_request(request.request_id)
            except Exception as exc:
                logger.warning("[FAILOVER] poll error: %s", exc)
                current = None
            if current is not None:
                if current.status == ApprovalStatus.APPROVED:
                    return True
                if current.status in (ApprovalStatus.DENIED, ApprovalStatus.EXPIRED):
                    return False
            if time.monotonic() >= deadline:
                break
            sleep(1.0)
        logger.warning("[FAILOVER] GO-Gate timeout after %ds (request %s) — queuing", timeout_s, request.request_id)
        return False
    except Exception as exc:
        logger.error("[FAILOVER] GO-Gate request failed: %s — denying", exc)
        return False


# Load config on import
load_failover_config()
