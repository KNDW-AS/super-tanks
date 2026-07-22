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
import subprocess
from datetime import datetime, timezone
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


def _git_commit() -> str:
    """Best-effort short commit hash for seal provenance."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(_DIQ_DIR), capture_output=True, text=True, timeout=5,
        )
        return out.stdout.strip() if out.returncode == 0 else ""
    except Exception:
        return ""


def _parse_manifest(raw: dict) -> tuple:
    """Return (files: Dict[str, str], meta: dict).

    Supports both the sealed format {"meta": {...}, "files": {...}}
    and the legacy flat {name: hash} format (meta comes back empty —
    rollback protection inactive until re-sealed).
    """
    if "files" in raw and isinstance(raw["files"], dict):
        return raw["files"], raw.get("meta", {})
    return raw, {}


def write_checksums() -> None:
    """Write current checksums to DIQ_CHECKSUMS.json. Run once after contract validation.

    Re-sealing bumps `meta.generation` — the anti-rollback counter that
    verify_diq_integrity checks against the deployment's floor.
    """
    old_generation = 0
    if _CHECKSUMS_FILE.exists():
        try:
            _, old_meta = _parse_manifest(json.loads(_CHECKSUMS_FILE.read_text()))
            old_generation = int(old_meta.get("generation", 0))
        except Exception:
            logger.warning("Existing DIQ_CHECKSUMS.json unreadable — generation restarts at 1")

    manifest = {
        "meta": {
            "generation": old_generation + 1,
            "sealed_at": datetime.now(timezone.utc).isoformat(),
            "git_commit": _git_commit(),
        },
        "files": compute_checksums(),
    }
    _CHECKSUMS_FILE.write_text(json.dumps(manifest, indent=2))
    logger.info("DIQ checksums written to %s (generation %d)",
                _CHECKSUMS_FILE, manifest["meta"]["generation"])
    for name, digest in manifest["files"].items():
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

    expected, meta = _parse_manifest(json.loads(_CHECKSUMS_FILE.read_text()))
    failures = []

    # Anti-rollback (STA-01 Threat 05): a manifest that matches its
    # files can still be a restored stale seal with weaker contracts.
    generation = meta.get("generation")
    if isinstance(generation, int):
        from core.security.integrity_floor import check_and_update
        rollback = check_and_update("diq", generation)
        if rollback:
            failures.append(f"ROLLBACK: {rollback}")
    else:
        logger.warning(
            "DIQ_CHECKSUMS.json has no meta.generation — legacy manifest, "
            "rollback protection inactive. Re-seal with "
            "diq_integrity.write_checksums() to enable it."
        )

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
