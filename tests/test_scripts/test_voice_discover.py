"""Tests for scripts/voice_discover.py."""

import json
import types
import urllib.error
import urllib.request


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


class TestHelpers:
    def test_check_binary_falls_back_to_path(self, monkeypatch):
        """When env var unset, _check_binary should locate via PATH."""
        monkeypatch.delenv("ST_PIPER_BIN", raising=False)
        monkeypatch.setattr(voice_discover.shutil, "which",
                            lambda name: "/usr/bin/piper")
        ok, msg = voice_discover._check_binary("piper", "ST_PIPER_BIN")
        assert ok is True
        assert "/usr/bin/piper" in msg
        assert "PATH" in msg

    def test_check_binary_not_found(self, monkeypatch):
        """Both env var and PATH lookup miss → NOT FOUND."""
        monkeypatch.delenv("ST_PIPER_BIN", raising=False)
        monkeypatch.setattr(voice_discover.shutil, "which",
                            lambda name: None)
        ok, msg = voice_discover._check_binary("piper", "ST_PIPER_BIN")
        assert ok is False
        assert "NOT FOUND" in msg
        assert "ST_PIPER_BIN" in msg

    def test_check_env_set(self, monkeypatch):
        monkeypatch.setenv("SOME_VAR", "x")
        ok, msg = voice_discover._check_env("SOME_VAR", "thing")
        assert ok is True
        assert "set" in msg

    def test_check_env_unset(self, monkeypatch):
        monkeypatch.delenv("SOME_VAR", raising=False)
        ok, msg = voice_discover._check_env("SOME_VAR", "thing")
        assert ok is False
        assert "not set" in msg

    def test_room_config_corrupt_json(self, tmp_path, monkeypatch):
        bad = tmp_path / "rooms.json"
        bad.write_text("{not valid json")
        monkeypatch.setattr(voice_discover, "ROOM_CONFIG_FILE", bad)
        ok, msg = voice_discover._check_room_config()
        assert ok is False
        assert "corrupt" in msg

    def test_room_config_empty_rooms(self, tmp_path, monkeypatch):
        empty = tmp_path / "rooms.json"
        empty.write_text(json.dumps({"rooms": {}}))
        monkeypatch.setattr(voice_discover, "ROOM_CONFIG_FILE", empty)
        ok, msg = voice_discover._check_room_config()
        assert ok is False
        assert "no rooms" in msg

    def test_room_hint_unassigned_when_no_match(self):
        assert voice_discover._room_hint(
            "media_player.garage_amp", "Garage Amp") == "unassigned"


class TestHAGet:
    def test_ha_get_parses_json_response(self, monkeypatch):
        """_ha_get builds an authorised Request and decodes the JSON body."""
        captured: dict = {}

        class _FakeResp:
            def __init__(self, payload: bytes):
                self._payload = payload

            def read(self) -> bytes:
                return self._payload

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def _fake_urlopen(req, timeout=10):
            captured["url"] = req.full_url
            captured["auth"] = req.get_header("Authorization")
            captured["timeout"] = timeout
            return _FakeResp(json.dumps([{"entity_id": "x"}]).encode("utf-8"))

        monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
        out = voice_discover._ha_get("http://hass:8123/", "tok",
                                     "/api/states")
        assert out == [{"entity_id": "x"}]
        assert captured["url"] == "http://hass:8123/api/states"
        assert captured["auth"] == "Bearer tok"
        assert captured["timeout"] == 10


class TestMainDispatch:
    def test_main_returns_2_when_no_branch_taken(self, monkeypatch):
        """Belt-and-braces fallthrough when args namespace has neither flag.

        argparse normally enforces the mutually-exclusive required group,
        so we bypass it by stubbing parse_args to exercise line 208.
        """
        ns = types.SimpleNamespace(check=False, scan_ha=False)
        monkeypatch.setattr(
            voice_discover.argparse.ArgumentParser,
            "parse_args",
            lambda self, argv=None: ns,
        )
        assert voice_discover.main([]) == 2
