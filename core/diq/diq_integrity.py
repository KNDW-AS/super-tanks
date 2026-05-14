"""
DIQ Integrity Guard
Version: 1.0

Verifies SHA256 checksums of all frozen DIQ contract files at gateway startup.
If any contract has been tampered with, startup halts immediately.

Same philosophy as soul_guard.py — frozen files prove their own integrity.
"""

import hashlib
import json
import logging
from pathlib import Path
from typing import Dict

logger = logging.getLogger("diq.integrity")

_DIQ_DIR = Path(__file__).parent
_CHECKSUMS_FILE = _DIQ_DIR / "DIQ_CHECKSUMS.json"

# Files that are frozen (chmod 444) and must match their stored checksums.
# diq_registry.py and diq_integrity.py are intentionally excluded —
# registry is mutable, integrity guard bootstraps itself.
FROZEN_FILES = [
    "diq_tools.py",
    "diq_a2a.py",
    "diq_cloud.py",
    "diq_memory.py",
    "diq_skills.py",
    "diq_ha.py",
]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def compute_checksums() -> Dict[str, str]:
    """Compute current SHA256 for all frozen files. Used to generate DIQ_CHECKSUMS.json."""
    return {name: _sha256(_DIQ_DIR / name) for name in FROZEN_FILES}


def write_checksums() -> None:
    """Write current checksums to DIQ_CHECKSUMS.json. Run once after contract validation."""
    checksums = compute_checksums()
    _CHECKSUMS_FILE.write_text(json.dumps(checksums, indent=2))
    logger.info("DIQ checksums written to %s", _CHECKSUMS_FILE)
    for name, digest in checksums.items():
        logger.info("  %s  %s", digest[:16], name)


def verify_diq_integrity() -> None:
    """
    Verify all frozen DIQ contract files against stored checksums.
    Called at gateway startup. Raises RuntimeError if any file has been tampered with.
    If DIQ_CHECKSUMS.json does not yet exist, logs a warning and continues
    (first-boot scenario — run write_checksums() to seal).
    """
    if not _CHECKSUMS_FILE.exists():
        # A missing manifest is indistinguishable from tampering — an
        # attacker who can rm DIQ_CHECKSUMS.json would otherwise defeat
        # the integrity check entirely. First-boot must run
        # diq_integrity.write_checksums() explicitly to seal.
        raise RuntimeError(
            "DIQ_CHECKSUMS.json not found — refusing to start. "
            "Run diq_integrity.write_checksums() once after validating "
            "the frozen contract files."
        )

    expected: Dict[str, str] = json.loads(_CHECKSUMS_FILE.read_text())
    failures = []

    for name in FROZEN_FILES:
        path = _DIQ_DIR / name
        if not path.exists():
            failures.append(f"MISSING: {name}")
            continue
        actual = _sha256(path)
        stored = expected.get(name)
        if stored is None:
            failures.append(f"NOT IN CHECKSUMS: {name}")
        elif actual != stored:
            failures.append(f"TAMPERED: {name} (expected {stored[:16]}… got {actual[:16]}…)")

    if failures:
        msg = "DIQ CONTRACT INTEGRITY VIOLATION:\n" + "\n".join(f"  {f}" for f in failures)
        logger.critical(msg)
        raise RuntimeError(msg)

    logger.info("✅ All %d DIQ contracts verified", len(FROZEN_FILES))
