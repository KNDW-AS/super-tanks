"""Tests for scripts/voice_discover.py."""

import json
import sys
import types
import urllib.error

import pytest

from scripts import voice_discover


class TestCheck:
    def test_check_returns_nonzero_when_misconfigured(self, tmp_path,
                                                        monkeypatch, capsys):
        # Wipe all relevant env + the room config.
        for v in ("ST_PIPER_BIN", "ST_PIPER_MODEL_DIR",
                  "ST_WHISPER_MODEL",
                  "HOMEASSISTANT_URL", "HOMEASSISTANT_TOKEN"):
            monkeypatch.delenv(v, raising=False)
        monkeypatch.setattr(voice_discover, "ROOM_CONFIG_FILE",
                            tmp_path / "missing.json")
        rc = voice_discover.main(["--check"])
        assert rc == 1
        out = capsys.readouterr().out
        assert "MISS" in out

    def test_check_returns_zero_when_all_set(self, tmp_path, monkeypatch,
                                              capsys):
        # Fake piper bin (exists), model dir (exists), whisper model
        # (exists), HA env vars, room config.
        bin_path = tmp_path / "piper"
        bin_path.write_text("#!/bin/sh\nexit 0\n")
        bin_path.chmod(0o755)
        model_dir = tmp_path / "models"
        model_dir.mkdir()
        whisper_dir = tmp_path / "whisper"
        whisper_dir.mkdir()
        room_cfg = tmp_path / "rooms.json"
        room_cfg.write_text(json.dumps({"rooms": {"a": {}}}))
        monkeypatch.setenv("ST_PIPER_BIN", str(bin_path))
        monkeypatch.setenv("ST_PIPER_MODEL_DIR", str(model_dir))
        monkeypatch.setenv("ST_WHISPER_MODEL", str(whisper_dir))
        monkeypatch.setenv("HOMEASSISTANT_URL", "http://hass:8123")
        monkeypatch.setenv("HOMEASSISTANT_TOKEN", "abc")
        monkeypatch.setattr(voice_discover, "ROOM_CONFIG_FILE", room_cfg)
        rc = voice_discover.main(["--check"])
        assert rc == 0


class TestScanHA:
    def test_missing_creds_returns_2(self, monkeypatch, capsys):
        monkeypatch.delenv("HOMEASSISTANT_URL", raising=False)
        monkeypatch.delenv("HOMEASSISTANT_TOKEN", raising=False)
        rc = voice_discover.main(["--scan-ha"])
        assert rc == 2

    def test_scan_emits_starter_room_map(self, monkeypatch, capsys):
        monkeypatch.setenv("HOMEASSISTANT_URL", "http://hass:8123")
        monkeypatch.setenv("HOMEASSISTANT_TOKEN", "abc")

        fake_states = [
            {"entity_id": "media_player.kjokken_sonos",
             "attributes": {"friendly_name": "Kjøkken Sonos"}},
            {"entity_id": "media_player.stue_sonos",
             "attributes": {"friendly_name": "Stue Sonos"}},
            {"entity_id": "assist_satellite.kjokken_atom",
             "attributes": {"friendly_name": "Kjøkken Atom"}},
            {"entity_id": "light.bedroom",  # ignored
             "attributes": {}},
        ]
        monkeypatch.setattr(voice_discover, "_ha_get",
                            lambda url, token, path: fake_states)
        rc = voice_discover.main(["--scan-ha"])
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "rooms" in data
        assert "kjokken" in data["rooms"]
        assert ("assist_satellite.kjokken_atom"
                in data["rooms"]["kjokken"]["mics"])
        assert ("media_player.kjokken_sonos"
                in data["rooms"]["kjokken"]["speakers"])
        # Light entity not pulled in.
        for room in data["rooms"].values():
            assert "light.bedroom" not in room["mics"]
            assert "light.bedroom" not in room["speakers"]

    def test_scan_handles_ha_unreachable(self, monkeypatch, capsys):
        monkeypatch.setenv("HOMEASSISTANT_URL", "http://nowhere")
        monkeypatch.setenv("HOMEASSISTANT_TOKEN", "abc")

        def _boom(*a, **kw):
            raise urllib.error.URLError("connection refused")
        monkeypatch.setattr(voice_discover, "_ha_get", _boom)
        rc = voice_discover.main(["--scan-ha"])
        assert rc == 2
