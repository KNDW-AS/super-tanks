"""
core/memory/tripwires.py
=========================
Super Tanks v3.0 — Honeypot Memory Files.

Creates and manages tripwire files in the hierarchical memory store.
These files look like legitimate sensitive data but contain a canary
marker at L2. Any access triggers a security alarm via access_control.

Tripwire paths:
  /system/passwords_backup
  /system/admin_keys
  /system/ssh_private_key
  /family/finance/bank_login
  /william/secrets
"""

import logging
from pathlib import Path
from typing import List

logger = logging.getLogger("super_tanks.memory.tripwires")

# Canary value stored as l2_full — proves the file is a trap
TRIPWIRE_CANARY = "TRIPWIRE_CANARY_DO_NOT_ACCESS"

# ---------------------------------------------------------------------------
# Tripwire definitions
# ---------------------------------------------------------------------------
# Each entry: (path, l0_abstract, l1_overview)
# l2_full is always TRIPWIRE_CANARY.

_TRIPWIRE_DEFINITIONS: list[tuple[str, str, str]] = [
    (
        "/system/passwords_backup",
        "Encrypted backup of all system service passwords.",
        "Contains encrypted copies of passwords for PostgreSQL, Redis, "
        "MQTT broker, and internal API tokens. Encrypted with AES-256-GCM "
        "using the master key stored in the hardware TPM. Last rotated "
        "2026-02-15. Format: JSON dict mapping service names to "
        "base64-encoded ciphertext blobs.",
    ),
    (
        "/system/admin_keys",
        "SSH and API admin keys for infrastructure management.",
        "Administrative key bundle for the Aeris Gateway infrastructure. "
        "Includes SSH private keys for Z620 and Legion, Tailscale auth keys, "
        "Home Assistant long-lived tokens, and Cloudflare API tokens. "
        "All keys are PEM-encoded and individually password-protected. "
        "Rotation schedule: quarterly. Last audit: 2026-01-30.",
    ),
    (
        "/system/ssh_private_key",
        "Primary SSH private key for remote server access.",
        "Ed25519 SSH private key used for automated deployments and "
        "backup synchronization between Z620 and Legion. Passphrase "
        "protected (PBKDF2, 600k iterations). Authorized on: Z620, "
        "Legion, NAS. Fingerprint: SHA256:xK9mR2... Last rotated: "
        "2026-03-01. Associated public key is in /system/config/ssh/.",
    ),
    (
        "/family/finance/bank_login",
        "Bank account credentials and two-factor recovery codes.",
        "Login credentials for family bank accounts at DNB and "
        "Sbanken. Includes account numbers, online banking passwords, "
        "BankID recovery codes, and credit card PINs. All values are "
        "AES-encrypted with per-field keys derived from the family "
        "master passphrase. Emergency contact: DNB +47 915 04800. "
        "Last verified: 2026-02-20.",
    ),
    (
        "/william/secrets",
        "William's personal secret notes and recovery phrases.",
        "Personal vault containing cryptocurrency wallet seed phrases, "
        "password manager master password hint, two-factor backup codes "
        "for GitHub/Google/Apple, and PGP private key passphrase. "
        "Stored with double encryption: outer layer AES-256, inner "
        "layer ChaCha20-Poly1305. Only accessible via physical "
        "presence verification.",
    ),
]

# Set of all tripwire paths for O(1) lookup
_TRIPWIRE_PATHS: set[str] = {defn[0] for defn in _TRIPWIRE_DEFINITIONS}


def is_tripwire(path: str) -> bool:
    """
    Check if a memory path is a known tripwire.

    Args:
        path: Logical memory path.

    Returns:
        True if the path is a registered honeypot tripwire.
    """
    normalized = "/" + path.strip("/")
    return normalized in _TRIPWIRE_PATHS


def get_tripwire_paths() -> List[str]:
    """Return all tripwire paths."""
    return sorted(_TRIPWIRE_PATHS)


def ensure_tripwires_exist(store) -> int:
    """
    Create all tripwire files in the hierarchical memory store if they
    do not already exist.

    Call this at system startup to guarantee honeypots are in place.

    Args:
        store: A HierarchicalMemoryStore instance.

    Returns:
        Number of tripwires created (0 if all already existed).
    """
    created = 0

    for tw_path, l0, l1 in _TRIPWIRE_DEFINITIONS:
        existing = store.read(tw_path, level=0)
        if existing is not None:
            logger.debug("Tripwire already exists: %s", tw_path)
            continue

        store.store(
            path=tw_path,
            l0_abstract=l0,
            l1_overview=l1,
            l2_full=TRIPWIRE_CANARY,
            source_agent="system",
            trust_level="tripwire",
            extra_metadata={"is_tripwire": True, "do_not_delete": True},
        )
        logger.info("Tripwire created: %s", tw_path)
        created += 1

    if created:
        logger.warning(
            "Tripwire deployment complete: %d/%d created",
            created, len(_TRIPWIRE_DEFINITIONS),
        )
    else:
        logger.info(
            "All %d tripwires already in place", len(_TRIPWIRE_DEFINITIONS)
        )

    return created
