"""
core/soul_guard.py - Soul Integrity Guard

Checks SHA256 hashes of aeris_soul.py and zeph_soul.py at startup.
On mismatch: does NOT crash — enters SAFE_MODE and notifies William via Telegram.

Safe Mode means:
  - System starts and responds to messages
  - No write operations, no tool execution, no external actions
  - All requests get a canned response explaining safe mode
  - William must send /approve_soul_start to resume normal operation
"""

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Tuple

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).parent.parent.resolve()
INTEGRITY_FILE = REPO_ROOT / "core" / "soul_integrity.json"

# Global safe-mode flag — read by main loop
SOUL_SAFE_MODE: bool = False
SOUL_SAFE_MODE_REASON: str = ""


def _hash_file(path: Path) -> str:
    """Compute SHA256 of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _send_telegram_alert(message: str) -> None:
    """
    Send Telegram alert to admin (William) about soul integrity violation.
    Best-effort — never raises, never blocks startup.
    """
    try:
        import requests
        token = os.environ.get("AERIS_TELEGRAM_TOKEN") or os.environ.get("ZEPH_TELEGRAM_TOKEN")
        admin_id = os.environ.get("ADMIN_USER_ID", os.getenv("AERIS_ADMIN_CHAT_ID", "0"))
        if not token:
            logger.warning("[SOUL_GUARD] No Telegram token available for alert")
            return
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": admin_id,
            "text": message,
            "parse_mode": "Markdown"
        }
        requests.post(url, json=payload, timeout=10)
        logger.info("[SOUL_GUARD] Telegram alert sent to admin")
    except Exception as e:
        logger.error(f"[SOUL_GUARD] Failed to send Telegram alert: {e}")


def check_soul_integrity() -> Tuple[bool, str]:
    """
    Verify soul file integrity against sealed hashes in soul_integrity.json.

    Returns:
        (ok: bool, reason: str)
        ok=True  → hashes match, normal startup
        ok=False → mismatch detected, enter SAFE_MODE
    """
    global SOUL_SAFE_MODE, SOUL_SAFE_MODE_REASON

    if not INTEGRITY_FILE.exists():
        # A missing manifest is indistinguishable from an attacker who
        # deleted it to silence the integrity check. Treat as tampering.
        msg = ("[SOUL_GUARD] soul_integrity.json missing — entering SAFE MODE. "
               "Run the soul-sealing tool to (re)generate the manifest.")
        logger.critical(msg)
        SOUL_SAFE_MODE = True
        SOUL_SAFE_MODE_REASON = msg
        return False, msg

    try:
        with open(INTEGRITY_FILE, "r") as f:
            manifest = json.load(f)
    except Exception as e:
        msg = f"[SOUL_GUARD] Cannot read soul_integrity.json: {e}"
        logger.error(msg)
        SOUL_SAFE_MODE = True
        SOUL_SAFE_MODE_REASON = msg
        return False, msg

    violations = []

    for name, entry in manifest.get("souls", {}).items():
        soul_path = REPO_ROOT / entry["file"]
        expected_hash = entry["sha256"]

        if not soul_path.exists():
            violations.append(f"  • {name}: FILE MISSING ({soul_path})")
            continue

        actual_hash = _hash_file(soul_path)
        if actual_hash != expected_hash:
            violations.append(
                f"  • {name}: HASH MISMATCH\n"
                f"    expected: {expected_hash}\n"
                f"    actual:   {actual_hash}"
            )
        else:
            logger.info(f"[SOUL_GUARD] {name}: ✅ integrity verified")

    if violations:
        reason = "Soul integrity violation(s) detected:\n" + "\n".join(violations)
        logger.critical(f"[SOUL_GUARD] {reason}")
        SOUL_SAFE_MODE = True
        SOUL_SAFE_MODE_REASON = reason

        alert = (
            "🚨 *SOUL INTEGRITY ALERT*\n\n"
            "One or more soul files have been modified since sealing.\n\n"
            f"```\n{reason}\n```\n\n"
            "System has entered *SAFE MODE*.\n"
            "No write operations or tool execution will proceed.\n\n"
            "To resume normal operation after reviewing:\n"
            "`/approve_soul_start`\n\n"
            "To restore from backup:\n"
            "`./restore_souls.sh`"
        )
        _send_telegram_alert(alert)

        print("\n" + "═" * 70)
        print("🚨  SOUL INTEGRITY VIOLATION — ENTERING SAFE MODE")
        print("═" * 70)
        print(reason)
        print("\nSystem is running in SAFE MODE.")
        print("William has been notified via Telegram.")
        print("Send /approve_soul_start to resume normal operation.")
        print("═" * 70 + "\n")

        return False, reason

    logger.info("[SOUL_GUARD] All soul files verified ✅")
    return True, "ok"


def is_safe_mode() -> bool:
    """Return True if system is in soul-integrity safe mode."""
    return SOUL_SAFE_MODE


def get_safe_mode_reason() -> str:
    """Return human-readable reason for safe mode."""
    return SOUL_SAFE_MODE_REASON


def safe_mode_response() -> str:
    """Canned response for all requests while in safe mode."""
    return (
        "⚠️ *System er i SAFE MODE*\n\n"
        "En eller flere soul-filer har blitt endret siden forseglingen. "
        "Jeg kan ikke utføre handlinger eller svare normalt før William "
        "har godkjent situasjonen.\n\n"
        "William er varslet via Telegram.\n"
        "Send `/approve_soul_start` for å gjenoppta normal drift."
    )
