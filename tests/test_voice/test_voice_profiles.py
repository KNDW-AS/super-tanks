"""Tests for core/voice/voice_profiles.py."""

import pytest

from core.voice import voice_profiles


class TestVoiceProfiles:
    def test_aeris_default_profile(self, monkeypatch):
        monkeypatch.delenv("ST_VOICE_AERIS", raising=False)
        monkeypatch.delenv("ST_VOICE_LANG", raising=False)
        p = voice_profiles.get_voice_profile("aeris")
        assert p.agent_id == "aeris"
        assert "nb_NO" in p.language
        assert p.voice_id  # non-empty

    def test_zeph_default_profile(self, monkeypatch):
        monkeypatch.delenv("ST_VOICE_ZEPH", raising=False)
        monkeypatch.delenv("ST_VOICE_LANG", raising=False)
        p = voice_profiles.get_voice_profile("zeph")
        assert p.agent_id == "zeph"
        assert p.voice_id != voice_profiles.get_voice_profile("aeris").voice_id

    def test_unknown_agent_raises(self):
        with pytest.raises(KeyError):
            voice_profiles.get_voice_profile("nobody")

    def test_env_override_voice_id(self, monkeypatch):
        monkeypatch.setenv("ST_VOICE_AERIS", "custom-voice")
        p = voice_profiles.get_voice_profile("aeris")
        assert p.voice_id == "custom-voice"
        assert "operator override" in p.description

    def test_env_override_language(self, monkeypatch):
        monkeypatch.setenv("ST_VOICE_LANG", "en_US")
        p = voice_profiles.get_voice_profile("aeris")
        assert p.language == "en_US"

    def test_list_profiles_returns_all_three(self, monkeypatch):
        for v in ("ST_VOICE_AERIS", "ST_VOICE_ZEPH", "ST_VOICE_CODY"):
            monkeypatch.delenv(v, raising=False)
        out = voice_profiles.list_profiles()
        assert set(out.keys()) >= {"aeris", "zeph", "cody"}

    def test_cody_profile_distinct_from_aeris_and_zeph(self, monkeypatch):
        for v in ("ST_VOICE_AERIS", "ST_VOICE_ZEPH", "ST_VOICE_CODY",
                  "ST_VOICE_LANG"):
            monkeypatch.delenv(v, raising=False)
        a = voice_profiles.get_voice_profile("aeris")
        z = voice_profiles.get_voice_profile("zeph")
        c = voice_profiles.get_voice_profile("cody")
        # Three distinct voices.
        assert len({a.voice_id, z.voice_id, c.voice_id}) == 3

    def test_cody_env_override(self, monkeypatch):
        monkeypatch.setenv("ST_VOICE_CODY", "custom-cody-voice")
        assert (voice_profiles.get_voice_profile("cody").voice_id
                == "custom-cody-voice")
