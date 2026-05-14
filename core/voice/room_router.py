"""
core/voice/room_router.py
==========================
Mic-to-speaker routing.

When Aeris hears a command on the kitchen mic, she should reply on
the kitchen speaker — not blast a bedtime story through every Sonos
in the house. This module owns the room mapping.

Two layers:

  1. STATIC MAPPING from config/voice_rooms.json. A dict of
     {room_id: {"mics": [...], "speakers": [...]}}. Operators edit
     this by hand to match their HA setup.

  2. RUNTIME LOOKUP. The voice pipeline calls `speaker_for_room(
     room_id)` to find where to play the reply. If the configured
     primary speaker is offline (via HA availability), the router
     falls back to the next speaker in the list before finally
     escalating to "no speaker available — fall back to Telegram".

Multi-speaker rooms support a "broadcast" mode for whole-house
announcements (e.g. SAFE_MODE alerts) — see `speakers_for_broadcast`.

The room map is data, not code: changing it does not require a
deploy. The pipeline reloads on every lookup so a hot-swap of the
config file takes effect immediately.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("super_tanks.voice.room_router")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
ROOM_CONFIG_FILE = _PROJECT_ROOT / "config" / "voice_rooms.json"


@dataclass(frozen=True)
class Room:
    room_id: str
    mics: List[str] = field(default_factory=list)
    speakers: List[str] = field(default_factory=list)
    fallback_speaker: Optional[str] = None


# ── Config loading ────────────────────────────────────────────────────────

def _load_room_config() -> Dict[str, Room]:
    if not ROOM_CONFIG_FILE.exists():
        return {}
    try:
        data = json.loads(ROOM_CONFIG_FILE.read_text())
    except Exception as exc:
        logger.error("[ROOM_ROUTER] failed to parse %s: %s",
                     ROOM_CONFIG_FILE, exc)
        return {}
    rooms: Dict[str, Room] = {}
    for room_id, body in (data.get("rooms") or {}).items():
        rooms[room_id] = Room(
            room_id=room_id,
            mics=list(body.get("mics") or []),
            speakers=list(body.get("speakers") or []),
            fallback_speaker=body.get("fallback_speaker"),
        )
    return rooms


def _availability_provider_default(entity_id: str) -> bool:
    """Probe HA for whether a media_player entity is available.

    Returns True if HA isn't reachable from this process — we'd
    rather TRY the speaker and let HA report the failure than
    silently route somewhere else based on stale availability data.
    Real deployments inject a provider that hits HA proper.
    """
    return True


# ── Public API ───────────────────────────────────────────────────────────

def room_for_mic(mic_id: str) -> Optional[str]:
    """Reverse-lookup: which room owns this mic? Returns None if
    the mic isn't claimed by any room — in which case the pipeline
    treats the input as 'no location context' and uses the
    fallback speaker."""
    for room_id, room in _load_room_config().items():
        if mic_id in room.mics:
            return room_id
    return None


def speaker_for_room(
        room_id: str,
        *, availability_provider=_availability_provider_default,
) -> Optional[str]:
    """Pick the right speaker entity for a room. Tries the configured
    speakers in order; falls back to fallback_speaker; finally
    returns None if nothing's available."""
    rooms = _load_room_config()
    if room_id not in rooms:
        # Unknown room — try the fallback speaker if anyone has one.
        for r in rooms.values():
            if r.fallback_speaker and availability_provider(r.fallback_speaker):
                return r.fallback_speaker
        return None
    room = rooms[room_id]
    for speaker in room.speakers:
        try:
            if availability_provider(speaker):
                return speaker
        except Exception as exc:
            logger.warning("[ROOM_ROUTER] availability probe raised for %s: %s",
                           speaker, exc)
            continue
    if (room.fallback_speaker
            and availability_provider(room.fallback_speaker)):
        return room.fallback_speaker
    return None


def speakers_for_broadcast(
        *, availability_provider=_availability_provider_default,
) -> List[str]:
    """All available speakers, deduplicated, in stable order.

    Used by whole-house announcements (SAFE_MODE entered, fire
    alarm, etc.). Offline speakers are skipped silently — the
    broadcast continues on the ones that respond."""
    out: List[str] = []
    seen = set()
    for room in _load_room_config().values():
        for speaker in room.speakers:
            if speaker in seen:
                continue
            seen.add(speaker)
            try:
                if availability_provider(speaker):
                    out.append(speaker)
            except Exception:
                continue
    return out


def list_rooms() -> List[Room]:
    """All configured rooms — used by the discovery CLI."""
    return list(_load_room_config().values())
