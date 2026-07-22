"""
core/security/audit_key.py
===========================
Dedicated HMAC key for the audit-chain subsystem.

The audit chain previously signed rows with the *identity* key from
core.security.agent_identity. That coupled two unrelated guarantees:
stealing data/.identity_key let an attacker both forge agent identity
tokens AND rewrite chained audit history undetected (7ASecurity STA-01,
Threat 06). This module holds separate key material so one key
compromise no longer affects both authentication and evidence
integrity.

Key acquisition order (mirrors agent_identity):
  1. `SUPER_TANKS_AUDIT_KEY` env var (preferred — set by main_loop on
     boot from a secret store).
  2. `data/.audit_chain_key` file (created on first boot, mode 0600).
  3. In-memory random bytes for the session (development fallback).

Existing deployments whose chains were written under the identity key
must run `scripts/rotate_audit_chain_key.py` once after upgrading —
otherwise chain verification flags every pre-upgrade row as tampered.
"""

import logging
import os
import secrets
from pathlib import Path
from typing import Optional

logger = logging.getLogger("super_tanks.audit_key")

# Process-wide key. Loaded lazily on first use; do NOT export this
# variable — code that can read it can rewrite chain history.
_KEY: Optional[bytes] = None

_KEY_FILE_DEFAULT = (
    Path(__file__).resolve().parent.parent.parent / "data" / ".audit_chain_key"
)
_KEY_FILE_PATH: Path = _KEY_FILE_DEFAULT


def _load_key() -> bytes:
    """Load (or generate) the audit-chain HMAC key. Idempotent within
    a process."""
    global _KEY
    if _KEY is not None:
        return _KEY

    env_key = os.environ.get("SUPER_TANKS_AUDIT_KEY")
    if env_key:
        _KEY = env_key.encode("utf-8")
        logger.info("[AUDIT_KEY] HMAC key loaded from environment")
        return _KEY

    try:
        if _KEY_FILE_PATH.exists():
            _KEY = _KEY_FILE_PATH.read_bytes()
            logger.info("[AUDIT_KEY] HMAC key loaded from %s", _KEY_FILE_PATH)
            return _KEY
    except Exception as exc:
        logger.warning("[AUDIT_KEY] Could not read key file %s: %s",
                       _KEY_FILE_PATH, exc)

    # First boot: generate a key and persist it.
    _KEY = secrets.token_bytes(32)
    try:
        _KEY_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _KEY_FILE_PATH.write_bytes(_KEY)
        try:
            os.chmod(_KEY_FILE_PATH, 0o600)
        except OSError:
            # Filesystem may not support chmod (e.g. on Windows).
            pass
        logger.warning(
            "[AUDIT_KEY] Generated new audit-chain key at %s. Back this "
            "file up — losing it makes existing chains unverifiable.",
            _KEY_FILE_PATH,
        )
    except Exception as exc:
        logger.error(
            "[AUDIT_KEY] Could not persist key to %s: %s. Chains written "
            "in this process will not verify after restart.",
            _KEY_FILE_PATH, exc,
        )
    return _KEY


def configure_key(key: bytes) -> None:
    """Test/bootstrap hook: set the audit-chain key explicitly."""
    global _KEY
    _KEY = key


def configure_key_file(path: Path) -> None:
    """Redirect the key-file path (tests only)."""
    global _KEY_FILE_PATH, _KEY
    _KEY_FILE_PATH = path
    _KEY = None
