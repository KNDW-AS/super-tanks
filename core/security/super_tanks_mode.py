"""
core/security/super_tanks_mode.py
==================================
Super Tanks Dual Mode Controller — LOCKDOWN / AUTONOMOUS toggle.

Features:
- Timed autonomy: AUTONOMOUS falls back to LOCKDOWN after timeout
- Night mode: reduced autonomy after 23:00 + 2h inactivity
- Trust-aware GO-Gate roles
- Persist/restore across restarts

INVARIANTS (never change regardless of mode):
- Soul file integrity, DIQ frozen contracts, ZEF regex, audit logging
"""

import json
import logging
import os
import threading
import time
from pathlib import Path
from enum import Enum
from datetime import datetime, timezone

logger = logging.getLogger("super_tanks.mode")

STATE_FILE = Path(__file__).resolve().parent.parent.parent / "config" / "super_tanks_state.json"


class TankMode(Enum):
    LOCKDOWN = "lockdown"
    AUTONOMOUS = "autonomous"


MODE_CONFIG = {
    TankMode.LOCKDOWN: {
        "zef_llm_classifier": True,
        "gogate_required_roles": ["WRITE", "EXEC", "ADMIN"],
        "quarantine_auto_approve": False,
        "description_no": "Full kontroll. Alt krev godkjenning.",
    },
    TankMode.AUTONOMOUS: {
        "zef_llm_classifier": False,
        "gogate_required_roles": ["ADMIN"],
        "quarantine_auto_approve": True,
        "description_no": "Zeph handlar sjølvstendig. Berre ADMIN krev godkjenning.",
    },
}

NIGHT_MODE_CONFIG = {
    "start_hour": 21,
    "end_hour": 6,
    "inactivity_hours": 2,
    "aeris_allowed": [
        "ha_search", "home_assistant", "notify_home",
        "memory_list_dir", "memory_read_file", "memory_hierarchy_search",
        "weather_met", "calculator", "status",
    ],
    # Zeph: Stille Observasjonsmodus
    "zeph_allowed": [
        # READ — alltid tillete
        "ha_search", "memory_list_dir", "memory_read_file", "memory_hierarchy_search",
        "trace_reflect", "self_inspect", "status", "system_monitor",
        "file_read", "semantic_search", "calculator",
        # Security alerts — alltid tillete
        "notify_home",  # For nødvarsel
        "a2a_send", "a2a_receive",
    ],
    "zeph_queued": [
        # Utsette til 06:00 (ikkje nekta, lagra i action_queue)
        "home_assistant", "memory_store_hierarchical",
        "task_add", "task_done", "image_generate",
    ],
    "zeph_blocked": [
        # Blokkert heilt om natta
        "shell_exec", "file_write", "code_edit", "python_exec",
        "propose_code_change", "memory_delete",
    ],
}

# ── State ──
# Module-level globals serialised by _state_lock. A request crossing a
# mode-switch boundary previously could see _current_mode=AUTONOMOUS
# alongside _autonomous_timeout_at=0 (mid-write) and apply the wrong
# RBAC. The lock makes "mode + timeout" reads/writes mutually
# exclusive. RLock so set_mode can call get_mode_config() without
# self-deadlocking.
_state_lock = threading.RLock()
_current_mode: TankMode = TankMode.LOCKDOWN
_autonomous_started_at: float = 0
_autonomous_timeout_at: float = 0
_timeout_hours: int = 8
_night_mode_active: bool = False
_last_interaction: float = time.time()


def get_mode() -> TankMode:
    with _state_lock:
        return _current_mode


def get_mode_config() -> dict:
    with _state_lock:
        return dict(MODE_CONFIG[_current_mode])


def get_config_value(key: str):
    with _state_lock:
        return MODE_CONFIG[_current_mode].get(key)


def get_effective_gogate_roles(agent_id: str) -> list:
    """GO-Gate roles considering mode + trust level."""
    with _state_lock:
        base_roles = MODE_CONFIG[_current_mode].get("gogate_required_roles", ["ADMIN"])
        current_mode_snapshot = _current_mode
    try:
        from core.security.trust_score import get_score
        trust = get_score(agent_id)
        level = trust["level"]
        if level == "probation":
            return ["WRITE", "EXEC", "ADMIN"]
        if level == "junior" and current_mode_snapshot == TankMode.AUTONOMOUS:
            return ["WRITE", "EXEC", "ADMIN"]
    except Exception:
        pass
    return base_roles


def requires_approval(tool_role: str, agent_id: str = "aeris") -> bool:
    """Check if role requires GO-Gate in current mode + trust."""
    return tool_role in get_effective_gogate_roles(agent_id)


# ── Mode switching ──

def set_mode(new_mode: TankMode, timeout_hours: int = 8) -> dict:
    global _current_mode, _autonomous_started_at, _autonomous_timeout_at, _timeout_hours, _night_mode_active

    with _state_lock:
        old_mode = _current_mode
        _current_mode = new_mode

        if new_mode == TankMode.AUTONOMOUS:
            _autonomous_started_at = time.time()
            _timeout_hours = timeout_hours
            _autonomous_timeout_at = _autonomous_started_at + (timeout_hours * 3600)
            _night_mode_active = False
            logger.warning(
                "AUTONOMOUS aktivert — timeout om %d timar (kl %s)",
                timeout_hours, _format_time(_autonomous_timeout_at),
            )
        else:
            _autonomous_started_at = 0
            _autonomous_timeout_at = 0
            _night_mode_active = False

        _persist_state(old_mode, new_mode)

    # Audit. Previously this imported core.audit_store, a module that
    # doesn't exist in this codebase, then swallowed the ImportError —
    # so every mode change (including tripwire-forced LOCKDOWN) ran
    # un-audited. Use the real memory audit log instead.
    try:
        from core.memory.audit_log import log_access
        log_access(
            agent_id="boss",
            operation="MODE_CHANGE",
            path=f"{old_mode.value}->{new_mode.value}",
            detail_level=-1,
            mode=new_mode.value,
            accessible=True,
            trajectory=f"timeout={timeout_hours}h",
        )
    except Exception as exc:
        logger.error("[MODE] Audit write failed for %s->%s: %s",
                     old_mode.value, new_mode.value, exc)

    _notify_mode_change(old_mode, new_mode)
    return get_mode_config()


def _persist_state(old_mode=None, new_mode=None):
    state = {
        "mode": _current_mode.value,
        "changed_at": datetime.now(timezone.utc).isoformat(),
        "changed_from": old_mode.value if old_mode else "",
        "autonomous_started_at": _autonomous_started_at,
        "autonomous_timeout_at": _autonomous_timeout_at,
        "timeout_hours": _timeout_hours,
    }
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(state, indent=2))
    except Exception as e:
        logger.error("Failed to persist state: %s", e)


# ── Timeout ──

def check_timeout() -> bool:
    """Check if AUTONOMOUS timed out. Call every 60s. Returns True if switched."""
    global _current_mode
    if _current_mode != TankMode.AUTONOMOUS or _autonomous_timeout_at == 0:
        return False
    if time.time() >= _autonomous_timeout_at:
        logger.warning("AUTONOMOUS timeout — tilbake til LOCKDOWN")
        set_mode(TankMode.LOCKDOWN)
        return True
    return False


def get_timeout_info() -> dict:
    if _current_mode != TankMode.AUTONOMOUS or _autonomous_timeout_at == 0:
        return {"active": False}
    remaining = max(0, _autonomous_timeout_at - time.time())
    h = int(remaining // 3600)
    m = int((remaining % 3600) // 60)
    return {
        "active": True,
        "started_at": _autonomous_started_at,
        "timeout_at": _autonomous_timeout_at,
        "remaining_seconds": remaining,
        "remaining_display": f"{h}t {m}min",
        "timeout_hours": _timeout_hours,
    }


def extend_autonomous(extra_hours: int = 8) -> dict:
    """Extend AUTONOMOUS timeout. PIN checked by caller."""
    global _autonomous_timeout_at, _timeout_hours
    if _current_mode != TankMode.AUTONOMOUS:
        return {"error": "Ikkje i AUTONOMOUS modus"}
    _autonomous_timeout_at += extra_hours * 3600
    _timeout_hours += extra_hours
    _persist_state()
    logger.info("AUTONOMOUS forlenga +%dh — ny timeout kl %s", extra_hours, _format_time(_autonomous_timeout_at))
    return get_timeout_info()


# ── Night mode ──

def record_interaction():
    """Call when William interacts (Telegram, cockpit, etc.)."""
    global _last_interaction
    _last_interaction = time.time()


def is_night_mode() -> bool:
    return _night_mode_active


def check_night_mode():
    """Check if night mode should activate/deactivate. Call every 60s."""
    global _night_mode_active
    if _current_mode != TankMode.AUTONOMOUS:
        _night_mode_active = False
        return

    hour = datetime.now().hour
    is_night_hours = hour >= NIGHT_MODE_CONFIG["start_hour"] or hour < NIGHT_MODE_CONFIG["end_hour"]
    inactive_hours = (time.time() - _last_interaction) / 3600
    should_be_night = is_night_hours and inactive_hours >= NIGHT_MODE_CONFIG["inactivity_hours"]

    if should_be_night and not _night_mode_active:
        _night_mode_active = True
        logger.info("Nattmodus aktivert")
        _send_telegram("Nattmodus aktivert\n\nAeris: smarthus-drift\nZeph: berre observasjon\n\nAvsluttast kl 06:00 eller ved interaksjon.")
    elif not should_be_night and _night_mode_active:
        _night_mode_active = False
        logger.info("Nattmodus avslutta")
        # Send morning report if there are queued actions
        try:
            from core.security.night_queue import build_morning_report
            report = build_morning_report()
            if report:
                _send_telegram(f"Morgon-rapport\n\n{report}")
                logger.info("Morning report sent with queued actions")
        except Exception as e:
            logger.warning("Morning report failed: %s", e)


def check_night_tool(agent_id: str, tool_name: str, params: dict = None) -> dict:
    """
    Check if tool is allowed during night mode.

    Returns:
        {"allowed": True} — proceed normally
        {"allowed": False, "queued": True, ...} — action queued for morning
        {"allowed": False, "blocked": True} — hard blocked
    """
    if not _night_mode_active:
        return {"allowed": True}

    if agent_id == "aeris":
        if tool_name in NIGHT_MODE_CONFIG["aeris_allowed"]:
            return {"allowed": True}
        return {"allowed": False, "blocked": True, "reason": "Aeris: ikkje tillete om natta"}

    if agent_id == "zeph":
        # Allowed — proceed
        if tool_name in NIGHT_MODE_CONFIG["zeph_allowed"]:
            return {"allowed": True}

        # Queued — defer to morning
        if tool_name in NIGHT_MODE_CONFIG["zeph_queued"]:
            from core.security.night_queue import queue_action
            result = queue_action(agent_id, tool_name, params or {},
                                  reason=f"Nattmodus: {tool_name} utsett til 06:00")
            return {"allowed": False, "queued": True, **result}

        # Blocked — hard deny
        if tool_name in NIGHT_MODE_CONFIG["zeph_blocked"]:
            return {"allowed": False, "blocked": True, "reason": f"Blokkert om natta: {tool_name}"}

        # Unknown tool — default queue
        from core.security.night_queue import queue_action
        result = queue_action(agent_id, tool_name, params or {},
                              reason=f"Ukjent tool om natta: {tool_name}")
        return {"allowed": False, "queued": True, **result}

    return {"allowed": True}


def is_tool_allowed_night(agent_id: str, tool_name: str) -> bool:
    """Simple bool check for backward compat. Use check_night_tool for full info."""
    return check_night_tool(agent_id, tool_name).get("allowed", True)


# ── Status ──

def get_effective_mode() -> dict:
    """Full status including timeout and night mode."""
    base = get_mode_config()
    timeout = get_timeout_info()
    return {
        "mode": _current_mode.value,
        "display": f"{'LOCKDOWN' if _current_mode == TankMode.LOCKDOWN else 'AUTONOMOUS'}{' 🌙' if _night_mode_active else ''}",
        "night_mode": _night_mode_active,
        "config": base,
        "timeout": timeout,
    }


# ── Startup ──

def load_mode_from_state():
    global _current_mode, _autonomous_started_at, _autonomous_timeout_at, _timeout_hours
    if STATE_FILE.exists():
        try:
            state = json.loads(STATE_FILE.read_text())
            _current_mode = TankMode(state.get("mode", "lockdown"))

            if _current_mode == TankMode.AUTONOMOUS:
                _autonomous_started_at = state.get("autonomous_started_at", 0)
                _autonomous_timeout_at = state.get("autonomous_timeout_at", 0)
                _timeout_hours = state.get("timeout_hours", 8)

                # Check if timeout passed during downtime
                if _autonomous_timeout_at > 0 and time.time() >= _autonomous_timeout_at:
                    logger.warning("AUTONOMOUS tima ut under nedetid — byter til LOCKDOWN")
                    _current_mode = TankMode.LOCKDOWN
                    _autonomous_started_at = 0
                    _autonomous_timeout_at = 0

            logger.info("Super Tanks mode loaded: %s", _current_mode.value)
        except Exception as e:
            logger.warning("Could not load state, defaulting to LOCKDOWN: %s", e)
            _current_mode = TankMode.LOCKDOWN
    else:
        _current_mode = TankMode.LOCKDOWN
        logger.info("Super Tanks mode: LOCKDOWN (default)")


# ── Helpers ──

def _format_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M")


def _send_telegram(text: str):
    try:
        import requests as _req
        token = os.environ.get("AERIS_GOGATE_TELEGRAM_TOKEN")
        chat_id = os.environ.get("AERIS_ADMIN_CHAT_ID", os.getenv("AERIS_ADMIN_CHAT_ID", "0"))
        if token:
            _req.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": int(chat_id), "text": text}, timeout=8,
            )
    except Exception:
        pass


def _notify_mode_change(old_mode: TankMode, new_mode: TankMode):
    timeout = get_timeout_info()
    if new_mode == TankMode.AUTONOMOUS and timeout.get("active"):
        text = (
            f"AUTONOMOUS aktivert\n\n"
            f"Timeout: {_timeout_hours}t (kl {_format_time(_autonomous_timeout_at)})\n"
            f"Byter automatisk til LOCKDOWN ved timeout."
        )
    elif new_mode == TankMode.LOCKDOWN:
        text = "LOCKDOWN aktivert\nAlt krev no godkjenning."
    else:
        text = f"Mode: {new_mode.value}"
    _send_telegram(text)
