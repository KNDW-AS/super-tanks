"""
core/security/agent_identity.py
================================
HMAC-backed agent identity tokens.

The threat: previously, every dispatch entrypoint trusted the `agent_id`
string parameter without any verification. A prompt-injected Aeris that
could reach `dispatch_tool` could simply set `agent_id="system"` and
walk past the allowlist. `record_event("zeph", "successful_task")`
could be called by anything that imports `core.security.trust_score`
to inflate Zeph's trust score until GO-Gate dropped.

The fix: a process-local HMAC key signs an opaque token per identity.
Callers must present `(agent_id, identity_token)` together; the gateway
verifies the token and refuses the dispatch otherwise. The signing key
never leaves this module — agent-controlled code (LLM prompts,
quarantine proposals, tool implementations) cannot read it.

Key acquisition order:
  1. `SUPER_TANKS_IDENTITY_KEY` env var (preferred — set by main_loop on
     boot from a secret store).
  2. `data/.identity_key` file (created on first boot, mode 0600).
  3. In-memory random bytes for the session (development fallback).
"""

import hashlib
import hmac
import logging
import os
import secrets
from pathlib import Path
from typing import Optional

logger = logging.getLogger("super_tanks.identity")

# Process-wide key. Loaded lazily on first use; do NOT export this
# variable — callers should not be able to forge tokens by reading it.
_KEY: Optional[bytes] = None

_KEY_FILE_DEFAULT = (
    Path(__file__).resolve().parent.parent.parent / "data" / ".identity_key"
)
_KEY_FILE_PATH: Path = _KEY_FILE_DEFAULT


def _load_key() -> bytes:
    """Load (or generate) the HMAC key. Idempotent within a process."""
    global _KEY
    if _KEY is not None:
        return _KEY

    env_key = os.environ.get("SUPER_TANKS_IDENTITY_KEY")
    if env_key:
        _KEY = env_key.encode("utf-8")
        logger.info("[IDENTITY] HMAC key loaded from environment")
        return _KEY

    try:
        if _KEY_FILE_PATH.exists():
            _KEY = _KEY_FILE_PATH.read_bytes()
            logger.info("[IDENTITY] HMAC key loaded from %s", _KEY_FILE_PATH)
            return _KEY
    except Exception as exc:
        logger.warning("[IDENTITY] Could not read key file %s: %s",
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
            "[IDENTITY] Generated new HMAC key at %s. Back this file up — "
            "losing it invalidates every issued identity token.",
            _KEY_FILE_PATH,
        )
    except Exception as exc:
        logger.error(
            "[IDENTITY] Could not persist HMAC key to %s: %s. "
            "Tokens will only be valid for this process lifetime.",
            _KEY_FILE_PATH, exc,
        )
    return _KEY


def issue_identity(agent_id: str) -> str:
    """Sign `agent_id` with the runtime HMAC key. Returns an opaque token.

    The boot sequence (or any internal authority) calls this once per
    agent process. The resulting token is passed to `dispatch_tool` and
    every other security-checked entrypoint.
    """
    if not agent_id:
        raise ValueError("agent_id must be non-empty")
    sig = hmac.new(_load_key(), agent_id.encode("utf-8"),
                   hashlib.sha256).hexdigest()
    return sig


def verify_identity(agent_id: str, token: Optional[str]) -> bool:
    """Return True iff `token` is the valid signature for `agent_id`.

    Constant-time compare (hmac.compare_digest) — avoids leaking the
    signature byte-by-byte to a timing oracle.
    """
    if not agent_id or not token:
        return False
    try:
        expected = issue_identity(agent_id)
        return hmac.compare_digest(expected, token)
    except Exception:
        return False


def configure_key(key: bytes) -> None:
    """Test/bootstrap hook: set the HMAC key explicitly.

    Production code should use the env var or key file. This is for
    deterministic tests and explicit migration tooling.
    """
    global _KEY
    _KEY = key


def configure_key_file(path: Path) -> None:
    """Redirect the key-file path (tests only)."""
    global _KEY_FILE_PATH, _KEY
    _KEY_FILE_PATH = path
    _KEY = None


# ── A2A message signing ──────────────────────────────────────────────
#
# A2AMessage instances flow between agents over the A2A channel. Without
# a signature, the receiver has no way to verify that `sender` matches
# the agent that actually emitted the message — a prompt-injected agent
# could forge `sender="william"` and trigger downstream privilege.
#
# These helpers operate on the immutable A2AMessage dataclass: signing
# produces a new instance with the `signature` field populated, and
# verification reconstructs the canonical bytes to compare.

import dataclasses as _dataclasses  # noqa: E402  (kept here for locality)
import json as _json  # noqa: E402


def _a2a_canonical_bytes(message) -> bytes:
    """Serialise an A2AMessage to a stable byte string for signing.

    Excludes `signature` so the canonical form is identical before and
    after signing. `json.dumps` with `sort_keys=True` produces a stable
    ordering regardless of dict insertion order in `payload`.
    """
    body = {
        "sender": message.sender,
        "recipient": message.recipient,
        "message_type": message.message_type,
        "payload": message.payload,
        "timestamp": message.timestamp,
        "correlation_id": message.correlation_id,
    }
    return _json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")


def sign_a2a_message(message):
    """Return a new A2AMessage with `signature` populated."""
    sig = hmac.new(_load_key(), _a2a_canonical_bytes(message),
                   hashlib.sha256).hexdigest()
    return _dataclasses.replace(message, signature=sig)


def verify_a2a_message(message) -> bool:
    """True iff `message.signature` validates against the runtime key."""
    if not message.signature:
        return False
    expected = hmac.new(_load_key(), _a2a_canonical_bytes(message),
                        hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, message.signature)
