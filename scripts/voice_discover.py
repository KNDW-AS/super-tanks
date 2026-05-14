"""
scripts/voice_discover.py
===========================
Operator helper for setting up the voice stack on Z620.

Two modes:

    --check
        Inspect the local environment for required binaries / env
        vars / config files. Prints a readiness checklist plus any
        next steps. Read-only — never modifies anything.

    --scan-ha
        Query the configured Home Assistant for media_player entities
        and Wyoming-Voice satellites; print a starter
        config/voice_rooms.json the operator can edit.

This script is the bridge between "Claude built the code" and "the
voice stack actually works in the kitchen". Run it on Z620 after
deployment — it tells you exactly which env vars to set, which
binaries to install, and which HA entities to plug into the room
config.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("voice_discover")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
ROOM_CONFIG_FILE = _PROJECT_ROOT / "config" / "voice_rooms.json"


# ── readiness check ───────────────────────────────────────────────────────

def _check_binary(name: str, env_var: str) -> Tuple[bool, str]:
    explicit = os.environ.get(env_var)
    if explicit and Path(explicit).exists():
        return True, f"{name}: {explicit} ({env_var})"
    found = shutil.which(name)
    if found:
        return True, f"{name}: {found} (on PATH; set {env_var} to pin)"
    return False, f"{name}: NOT FOUND; install + set {env_var}"


def _check_dir(env_var: str, label: str) -> Tuple[bool, str]:
    val = os.environ.get(env_var)
    if val and Path(val).exists():
        return True, f"{label}: {val}"
    return False, f"{label}: {env_var} not set or path missing"


def _check_env(env_var: str, label: str) -> Tuple[bool, str]:
    val = os.environ.get(env_var)
    if val:
        return True, f"{label}: {env_var} set"
    return False, f"{label}: {env_var} not set"


def _check_room_config() -> Tuple[bool, str]:
    if not ROOM_CONFIG_FILE.exists():
        return False, (f"room map: {ROOM_CONFIG_FILE} missing — "
                       f"run with --scan-ha to generate a starter")
    try:
        data = json.loads(ROOM_CONFIG_FILE.read_text())
    except Exception as exc:
        return False, f"room map: {ROOM_CONFIG_FILE} corrupt ({exc})"
    rooms = data.get("rooms") or {}
    if not rooms:
        return False, f"room map: {ROOM_CONFIG_FILE} has no rooms"
    return True, (f"room map: {ROOM_CONFIG_FILE} OK "
                  f"({len(rooms)} rooms)")


def run_check() -> int:
    print("Voice-stack readiness check")
    print("=" * 60)
    checks = [
        _check_binary("piper", "ST_PIPER_BIN"),
        _check_dir("ST_PIPER_MODEL_DIR", "piper models"),
        _check_dir("ST_WHISPER_MODEL", "whisper model"),
        _check_env("HOMEASSISTANT_URL", "HA URL"),
        _check_env("HOMEASSISTANT_TOKEN", "HA token"),
        _check_room_config(),
    ]
    ready = all(ok for ok, _ in checks)
    for ok, msg in checks:
        marker = "OK " if ok else "MISS"
        print(f"  [{marker}] {msg}")
    print()
    if ready:
        print("All checks passed — start the voice runner.")
        return 0
    print("Next steps:")
    print("  1. Install missing binaries (Piper, faster-whisper)")
    print("  2. Set the env vars listed above")
    print("  3. Run --scan-ha to seed the room map from HA")
    return 1


# ── HA scan ───────────────────────────────────────────────────────────────

def _ha_get(url: str, token: str, path: str) -> Any:
    req = urllib.request.Request(
        f"{url.rstrip('/')}{path}",
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _room_hint(entity_id: str, friendly_name: str) -> str:
    """Best-effort room id from entity name. The operator is expected
    to edit the output, so guesses don't have to be perfect.

    Match against an ASCII-folded version of the name so 'kjøkken' and
    'kjokken' both land in the same room. The returned key is always
    ASCII so config/voice_rooms.json stays portable across editors."""
    folded = (f"{entity_id} {friendly_name}".lower()
              .replace("ø", "o").replace("å", "a").replace("æ", "ae"))
    for room in ("kjokken", "kitchen",
                 "stue", "livingroom", "living_room",
                 "bad", "bath", "soverom", "bedroom",
                 "kontor", "office", "gang", "hall",
                 "barnerom", "kids"):
        if room in folded:
            return room
    return "unassigned"


def run_scan_ha() -> int:
    url = os.environ.get("HOMEASSISTANT_URL")
    token = os.environ.get("HOMEASSISTANT_TOKEN")
    if not url or not token:
        print("HOMEASSISTANT_URL / HOMEASSISTANT_TOKEN not set; cannot scan.",
              file=sys.stderr)
        return 2
    try:
        states = _ha_get(url, token, "/api/states")
    except urllib.error.URLError as exc:
        print(f"HA unreachable: {exc}", file=sys.stderr)
        return 2

    media_players: List[Dict[str, Any]] = []
    assist_satellites: List[Dict[str, Any]] = []
    for s in states:
        entity_id = s.get("entity_id", "")
        if entity_id.startswith("media_player."):
            media_players.append(s)
        if (entity_id.startswith("assist_satellite.")
                or entity_id.startswith("wyoming.")):
            assist_satellites.append(s)

    # Group by hinted room.
    rooms: Dict[str, Dict[str, List[str]]] = {}
    for s in media_players:
        eid = s["entity_id"]
        fn = (s.get("attributes") or {}).get("friendly_name", "")
        room = _room_hint(eid, fn)
        rooms.setdefault(room, {"mics": [], "speakers": []})
        rooms[room]["speakers"].append(eid)
    for s in assist_satellites:
        eid = s["entity_id"]
        fn = (s.get("attributes") or {}).get("friendly_name", "")
        room = _room_hint(eid, fn)
        rooms.setdefault(room, {"mics": [], "speakers": []})
        rooms[room]["mics"].append(eid)

    out = {"rooms": {room: {"mics": rooms[room]["mics"],
                            "speakers": rooms[room]["speakers"]}
                     for room in sorted(rooms.keys())}}
    print(json.dumps(out, indent=2, ensure_ascii=False))
    print()
    print(f"# Found {len(media_players)} media_player(s), "
          f"{len(assist_satellites)} satellite(s).", file=sys.stderr)
    print(f"# Save to {ROOM_CONFIG_FILE} after reviewing.",
          file=sys.stderr)
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="voice_discover")
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true",
                   help="Print readiness checklist and exit.")
    g.add_argument("--scan-ha", action="store_true",
                   help="Query HA for media_players + satellites, "
                        "print starter voice_rooms.json.")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if args.check:
        return run_check()
    if args.scan_ha:
        return run_scan_ha()
    return 2


if __name__ == "__main__":
    sys.exit(main())
