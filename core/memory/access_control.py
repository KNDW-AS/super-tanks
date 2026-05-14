"""
core/memory/access_control.py
==============================
Super Tanks v3.0 — Mode-Aware RBAC for Hierarchical Memory Paths.

Classifies every memory path into one of:
  - "public"         : Always accessible to any agent in any mode.
  - "sensitive"       : Accessible only in LOCKDOWN mode (requires GO-Gate).
  - "agent_private:X" : Only accessible by agent X.
  - "tripwire"        : Honeypot. Any access triggers alarm + forced LOCKDOWN.

The most specific prefix match wins.
"""

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger("super_tanks.memory.access_control")

# ---------------------------------------------------------------------------
# Path classification table — most specific prefix wins
# ---------------------------------------------------------------------------
# Order: longest prefixes first so the matching loop can break early after
# sorting by specificity.

_PATH_CLASSIFICATIONS: list[Tuple[str, str]] = [
    # ── Tripwires (honeypots) — must be checked before broader prefixes ──
    ("/system/passwords_backup", "tripwire"),
    ("/system/admin_keys", "tripwire"),
    ("/system/ssh_private_key", "tripwire"),
    ("/family/finance/bank_login", "tripwire"),
    ("/william/secrets", "tripwire"),

    # ── Agent-private ──
    ("/aeris/learned", "agent_private:aeris"),
    ("/aeris/personality", "agent_private:aeris"),
    ("/zeph/learned", "agent_private:zeph"),
    ("/zeph/security_log", "agent_private:zeph"),
    ("/zeph/successful_patterns", "agent_private:zeph"),

    # ── Sensitive (lockdown-only access) ──
    ("/family/finance", "sensitive"),
    ("/family/health", "sensitive"),
    ("/system/config", "sensitive"),
    ("/william/work", "sensitive"),

    # ── Public (always accessible) ──
    ("/family/preferences", "public"),
    ("/family/routines", "public"),
    ("/system/home_assistant", "public"),
    ("/system/logs", "public"),
    ("/william/interests", "public"),
]

# Pre-sort by prefix length descending — longest match wins
_PATH_CLASSIFICATIONS.sort(key=lambda x: len(x[0]), reverse=True)


def get_path_classification(path: str) -> str:
    """
    Classify a memory path by its most specific prefix match.

    Args:
        path: Logical memory path (e.g. "/family/finance/bank_login").

    Returns:
        Classification string: "public", "sensitive", "agent_private:<id>",
        "tripwire", or "unknown" if no prefix matches.
    """
    normalized = "/" + path.strip("/")
    for prefix, classification in _PATH_CLASSIFICATIONS:
        # Require a path boundary so /family/finance does NOT match
        # /family/finance_other. Either an exact match or the prefix
        # followed by a "/".
        if normalized == prefix or normalized.startswith(prefix + "/"):
            return classification
    return "unknown"


def is_path_accessible(
    path: str,
    agent_id: str,
    mode: Optional[str] = None,
) -> bool:
    """
    Check whether an agent may access a memory path in the current mode.

    If mode is not passed, it is read from the live Super Tanks state.

    Side effect: accessing a tripwire path triggers an alarm (forced
    LOCKDOWN, Telegram alert, audit log entry).

    Args:
        path: Logical memory path.
        agent_id: Identifier of the requesting agent ("aeris", "zeph", etc.).
        mode: "lockdown" or "autonomous". If None, auto-detected.

    Returns:
        True if access is allowed, False otherwise.
    """
    classification = get_path_classification(path)

    # Resolve current mode if not provided
    if mode is None:
        try:
            from core.security.super_tanks_mode import get_mode
            mode = get_mode().value
        except Exception:
            # "lockdown" allows sensitive (assumes human is supervising),
            # "autonomous" denies sensitive. If we can't determine which
            # mode we're in we must assume nobody is watching.
            mode = "autonomous"

    # Always lowercase, even after .value, in case the enum value itself
    # was stored uppercase. Previously a value like "LOCKDOWN" would
    # compare unequal to the literal "lockdown" below and deny sensitive
    # paths inside lockdown mode.
    mode_lower = (mode.value if hasattr(mode, 'value') else str(mode)).lower()

    # ── Tripwire — always blocked, always triggers alarm ──
    if classification == "tripwire":
        logger.critical(
            "TRIPWIRE ACCESS by agent=%s path=%s mode=%s",
            agent_id, path, mode_lower,
        )
        trigger_tripwire_alarm(path, agent_id)
        # Instant probation via trust score. If the trust subsystem is
        # down we log loudly — silent swallow means a tripped honeypot
        # leaves the agent's score untouched.
        try:
            from core.security.trust_score import record_event
            record_event(agent_id, "tripwire_access", f"Accessed honeypot: {path}")
        except Exception as exc:
            logger.error(
                "[ACCESS_CONTROL] trust_score unavailable for tripwire event "
                "agent=%s path=%s: %s", agent_id, path, exc,
            )
        return False

    # ── Public — always allowed ──
    if classification == "public":
        return True

    # ── Agent-private — only the owning agent may access ──
    if classification.startswith("agent_private:"):
        owner = classification.split(":", 1)[1]
        if agent_id == owner:
            return True
        logger.warning(
            "Agent %s denied access to agent-private path %s (owner=%s)",
            agent_id, path, owner,
        )
        return False

    # ── Sensitive — allowed only in lockdown (human-supervised) ──
    if classification == "sensitive":
        if mode_lower == "lockdown":
            return True
        logger.warning(
            "Sensitive path %s blocked in AUTONOMOUS mode for agent %s",
            path, agent_id,
        )
        return False

    # ── Unknown — fail closed ──
    logger.warning(
        "Unknown classification for path %s — denying access for agent %s",
        path, agent_id,
    )
    return False


def trigger_tripwire_alarm(path: str, agent_id: str) -> None:
    """
    Handle a tripwire access event:
      1. Force system into LOCKDOWN mode.
      2. Send Telegram alert to William.
      3. Write to audit log.

    This function never raises — all errors are logged.
    """
    now = datetime.now(timezone.utc)
    now_str = now.strftime("%Y-%m-%d %H:%M:%S UTC")

    # 1. Force LOCKDOWN
    try:
        from core.security.super_tanks_mode import TankMode, set_mode, get_mode
        if get_mode() != TankMode.LOCKDOWN:
            set_mode(TankMode.LOCKDOWN)
            logger.critical(
                "FORCED LOCKDOWN due to tripwire access: agent=%s path=%s",
                agent_id, path,
            )
    except Exception as exc:
        logger.error("Failed to force LOCKDOWN on tripwire: %s", exc)

    # 2. Telegram alert (same pattern as zeph_quarantine.py)
    try:
        import requests as _req

        _token = os.environ.get("AERIS_GOGATE_TELEGRAM_TOKEN")
        _chat_id = os.environ.get("AERIS_ADMIN_CHAT_ID", os.getenv("AERIS_ADMIN_CHAT_ID", "0"))
        if not _token:
            logger.warning("No AERIS_GOGATE_TELEGRAM_TOKEN — tripwire Telegram alert skipped")
        else:
            text = (
                f"TRIPWIRE UTLOYST\n\n"
                f"Agent: {agent_id}\n"
                f"Sti: {path}\n"
                f"Tidspunkt: {now_str}\n\n"
                f"Systemet er TVINGA til LOCKDOWN.\n"
                f"Sjekk audit-loggen umiddelbart."
            )
            _req.post(
                f"https://api.telegram.org/bot{_token}/sendMessage",
                json={"chat_id": int(_chat_id), "text": text},
                timeout=8,
            )
            logger.info("Tripwire Telegram alert sent for agent=%s path=%s", agent_id, path)
    except Exception as exc:
        logger.error("Tripwire Telegram alert failed: %s", exc)

    # 3. Audit log entry
    try:
        from core.memory.audit_log import log_access
        log_access(
            agent_id=agent_id,
            operation="TRIPWIRE_ACCESS",
            path=path,
            detail_level=-1,
            mode="lockdown",
            accessible=False,
            conversation_id="",
            trajectory=f"TRIPWIRE alarm triggered at {now_str}",
        )
    except Exception as exc:
        logger.error("Tripwire audit log failed: %s", exc)
