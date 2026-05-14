"""Tests for core/voice/room_router.py."""

import json

import pytest

from core.voice import room_router


@pytest.fixture
def room_config(tmp_path, monkeypatch):
    path = tmp_path / "voice_rooms.json"
    path.write_text(json.dumps({
        "rooms": {
            "kitchen": {
                "mics": ["assist_satellite.kitchen_atom"],
                "speakers": ["media_player.kitchen_sonos",
                             "media_player.kitchen_atom"],
                "fallback_speaker": "media_player.living_room_sonos",
            },
            "bedroom": {
                "mics": ["assist_satellite.bedroom_satellite"],
                "speakers": ["media_player.bedroom_speaker"],
            },
        },
    }))
    monkeypatch.setattr(room_router, "ROOM_CONFIG_FILE", path)
    return path


class TestRoomForMic:
    def test_known_mic_returns_room(self, room_config):
        assert (room_router.room_for_mic("assist_satellite.kitchen_atom")
                == "kitchen")

    def test_unknown_mic_returns_none(self, room_config):
        assert room_router.room_for_mic("assist_satellite.unknown") is None

    def test_no_config_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(room_router, "ROOM_CONFIG_FILE",
                            tmp_path / "missing.json")
        assert room_router.room_for_mic("x") is None


class TestSpeakerForRoom:
    def test_picks_first_available_speaker(self, room_config):
        result = room_router.speaker_for_room("kitchen")
        assert result == "media_player.kitchen_sonos"

    def test_falls_back_to_second_when_first_offline(self, room_config):
        availability = {
            "media_player.kitchen_sonos": False,
            "media_player.kitchen_atom": True,
        }
        result = room_router.speaker_for_room(
            "kitchen",
            availability_provider=lambda e: availability.get(e, True),
        )
        assert result == "media_player.kitchen_atom"

    def test_falls_back_to_fallback_speaker(self, room_config):
        availability = {
            "media_player.kitchen_sonos": False,
            "media_player.kitchen_atom": False,
            "media_player.living_room_sonos": True,
        }
        result = room_router.speaker_for_room(
            "kitchen",
            availability_provider=lambda e: availability.get(e, False),
        )
        assert result == "media_player.living_room_sonos"

    def test_all_offline_returns_none(self, room_config):
        result = room_router.speaker_for_room(
            "kitchen", availability_provider=lambda e: False,
        )
        assert result is None

    def test_unknown_room_uses_any_fallback(self, room_config):
        result = room_router.speaker_for_room("garage")
        assert result == "media_player.living_room_sonos"


class TestBroadcast:
    def test_returns_every_speaker_deduped(self, room_config):
        out = room_router.speakers_for_broadcast()
        assert sorted(out) == [
            "media_player.bedroom_speaker",
            "media_player.kitchen_atom",
            "media_player.kitchen_sonos",
        ]

    def test_skips_offline_speakers(self, room_config):
        availability = {"media_player.kitchen_sonos": False}
        out = room_router.speakers_for_broadcast(
            availability_provider=lambda e: availability.get(e, True),
        )
        assert "media_player.kitchen_sonos" not in out
        assert "media_player.kitchen_atom" in out


class TestListRooms:
    def test_returns_all_rooms(self, room_config):
        rooms = room_router.list_rooms()
        names = {r.room_id for r in rooms}
        assert names == {"kitchen", "bedroom"}
