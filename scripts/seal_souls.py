#!/usr/bin/env python3
"""
scripts/seal_souls.py
=====================
Seal (or re-seal) the soul integrity manifest `core/soul_integrity.json`.

This is the "soul-sealing tool" soul_guard.py refers to. Every seal
bumps `meta.generation` — the anti-rollback counter checked at boot
against `data/.integrity_floor.json` (STA-01 Threat 05: a backup
restore that rolls code + manifest back to an older valid state).

Usage:
    # First seal — list the soul files explicitly:
    python scripts/seal_souls.py core/aeris_soul.py core/zeph_soul.py

    # Re-seal the files already listed in the manifest (e.g. after an
    # approved soul change):
    python scripts/seal_souls.py
"""

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "core" / "soul_integrity.json"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _git_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=5,
        )
        return out.stdout.strip() if out.returncode == 0 else ""
    except Exception:
        return ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("soul_files", nargs="*",
                        help="Soul files to seal (repo-relative). "
                             "Omit to re-seal the current manifest's files.")
    args = parser.parse_args()

    old_generation = 0
    old_souls = {}
    if MANIFEST.exists():
        try:
            raw = json.loads(MANIFEST.read_text())
            old_souls = raw.get("souls", {})
            old_generation = int(raw.get("meta", {}).get("generation", 0))
        except Exception as exc:
            print(f"WARNING: existing manifest unreadable ({exc}) — "
                  f"generation restarts at 1", file=sys.stderr)

    if args.soul_files:
        files = [Path(f) for f in args.soul_files]
    elif old_souls:
        files = [REPO_ROOT / entry["file"] for entry in old_souls.values()]
    else:
        parser.error("no soul files given and no existing manifest to re-seal")

    souls = {}
    for path in files:
        path = path.resolve()
        if not path.exists():
            print(f"ERROR: {path} does not exist", file=sys.stderr)
            return 1
        rel = path.relative_to(REPO_ROOT)
        souls[path.stem] = {"file": str(rel), "sha256": _sha256(path)}

    manifest = {
        "meta": {
            "generation": old_generation + 1,
            "sealed_at": datetime.now(timezone.utc).isoformat(),
            "git_commit": _git_commit(),
        },
        "souls": souls,
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2))

    print(f"Sealed {len(souls)} soul file(s) → {MANIFEST}")
    print(f"  generation: {manifest['meta']['generation']}")
    for name, entry in souls.items():
        print(f"  {entry['sha256'][:16]}  {name} ({entry['file']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
