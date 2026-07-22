"""
core/security/integrity_floor.py
=================================
Monotonic generation floor for integrity manifests (anti-rollback).

STA-01 Threat 05 scenario: "a backup, restore, or deployment sync
process rolls back code and manifests to an older but valid state with
weaker controls." A hash-only manifest cannot see this — the old
manifest matches the old files perfectly.

Defense: manifests carry a `meta.generation` counter that the sealing
tools bump on every re-seal. This module remembers the highest
generation ever seen (per manifest) in `data/.integrity_floor.json`.
A boot that presents an older generation than the floor is a rollback
and fails the integrity check.

Limits (documented, not hidden): the floor file lives in `data/` on
the same filesystem. An attacker with full host write access can reset
it — that attacker is out of scope (SECURITY.md threat class 3). The
control targets the realistic case: restore/sync jobs that roll back
the source tree (including manifests) without touching runtime state
in `data/`.
"""

import json
import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger("super_tanks.integrity_floor")

_FLOOR_FILE_DEFAULT = (
    Path(__file__).resolve().parent.parent.parent
    / "data" / ".integrity_floor.json"
)
FLOOR_FILE: Path = _FLOOR_FILE_DEFAULT


def _read_floors() -> dict:
    try:
        if FLOOR_FILE.exists():
            return json.loads(FLOOR_FILE.read_text())
    except Exception as exc:
        # Unreadable floor state is loud but non-fatal: failing closed
        # here would brick startup on a corrupt json, and an attacker
        # who can corrupt the file could zero it just as easily. The
        # hard stop is reserved for a *provable* rollback below.
        logger.error("[INTEGRITY_FLOOR] Cannot read %s: %s", FLOOR_FILE, exc)
    return {}


def _write_floors(floors: dict) -> None:
    try:
        FLOOR_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = FLOOR_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(floors, indent=2))
        os.replace(tmp, FLOOR_FILE)
        try:
            os.chmod(FLOOR_FILE, 0o600)
        except OSError:
            pass
    except Exception as exc:
        logger.error("[INTEGRITY_FLOOR] Cannot persist %s: %s", FLOOR_FILE, exc)


def check_and_update(manifest_name: str, generation: int) -> Optional[str]:
    """Compare `generation` against the stored floor for `manifest_name`.

    Returns None if the manifest is current (and advances the floor),
    or a human-readable error string if the manifest is OLDER than a
    generation this deployment has already seen — i.e. a rollback.
    """
    floors = _read_floors()
    floor = floors.get(manifest_name)

    if isinstance(floor, int) and generation < floor:
        return (
            f"{manifest_name} manifest generation {generation} is older "
            f"than the highest generation seen on this deployment "
            f"({floor}). This looks like a rollback to a stale but "
            f"previously-valid state (backup restore / deployment sync). "
            f"If intentional, re-seal the manifest to advance the "
            f"generation, or remove {FLOOR_FILE} after review."
        )

    if floor != generation:
        floors[manifest_name] = generation
        _write_floors(floors)
    return None
