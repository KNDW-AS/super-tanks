"""Tests for core/voice/backends/piper_tts.py — model + speaker resolution."""

import asyncio
import json
from pathlib import Path

import pytest

from core.diq.diq_voice import Utterance
from core.voice.backends.piper_tts import PiperTTSBackend


@pytest.fixture
def model_dir(tmp_path):
    """Synthesise a model_dir with a single-speaker and multi-speaker
    .onnx + .onnx.json pair. The .onnx files themselves are empty —
    `_resolve_model` only checks existence, not content."""
    (tmp_path / "no_NO-talesyntese-medium.onnx").write_bytes(b"")
    (tmp_path / "no_NO-talesyntese-medium.onnx.json").write_text(
        json.dumps({"num_speakers": 1}),
    )
    (tmp_path / "multi-3spk.onnx").write_bytes(b"")
    (tmp_path / "multi-3spk.onnx.json").write_text(
        json.dumps({"num_speakers": 3}),
    )
    return tmp_path


class TestResolveModel:
    def test_no_suffix_returns_speaker_zero(self, model_dir):
        backend = PiperTTSBackend(piper_bin="/bin/true",
                                  model_dir=str(model_dir))
        path, idx = backend._resolve_model("no_NO-talesyntese-medium")
        assert path.name == "no_NO-talesyntese-medium.onnx"
        assert idx == 0

    def test_hash_suffix_on_single_speaker_clamps_to_zero(
            self, model_dir, caplog):
        backend = PiperTTSBackend(piper_bin="/bin/true",
                                  model_dir=str(model_dir))
        with caplog.at_level("WARNING", logger="super_tanks.voice.piper"):
            path, idx = backend._resolve_model(
                "no_NO-talesyntese-medium#1",
            )
        assert path.name == "no_NO-talesyntese-medium.onnx"
        assert idx == 0
        # Operator visibility: a warning explaining the clamp.
        assert any("falling back to 0" in r.message for r in caplog.records)

    def test_hash_suffix_on_multi_speaker_passes_through(self, model_dir):
        backend = PiperTTSBackend(piper_bin="/bin/true",
                                  model_dir=str(model_dir))
        path, idx = backend._resolve_model("multi-3spk#2")
        assert path.name == "multi-3spk.onnx"
        assert idx == 2

    def test_hash_suffix_beyond_speaker_count_clamps(self, model_dir, caplog):
        backend = PiperTTSBackend(piper_bin="/bin/true",
                                  model_dir=str(model_dir))
        with caplog.at_level("WARNING", logger="super_tanks.voice.piper"):
            path, idx = backend._resolve_model("multi-3spk#9")
        assert idx == 0
        assert any("falling back to 0" in r.message for r in caplog.records)

    def test_invalid_idx_string_clamps_to_zero(self, model_dir, caplog):
        backend = PiperTTSBackend(piper_bin="/bin/true",
                                  model_dir=str(model_dir))
        with caplog.at_level("WARNING", logger="super_tanks.voice.piper"):
            path, idx = backend._resolve_model(
                "no_NO-talesyntese-medium#bogus",
            )
        assert idx == 0
        assert any("invalid speaker idx" in r.message for r in caplog.records)

    def test_missing_model_returns_none(self, model_dir):
        backend = PiperTTSBackend(piper_bin="/bin/true",
                                  model_dir=str(model_dir))
        assert backend._resolve_model("nope-not-here") is None

    def test_missing_config_defaults_num_speakers_to_one(self, tmp_path):
        # Model file present, config missing.
        (tmp_path / "lone.onnx").write_bytes(b"")
        backend = PiperTTSBackend(piper_bin="/bin/true",
                                  model_dir=str(tmp_path))
        # Without config we assume single-speaker and clamp.
        path, idx = backend._resolve_model("lone#1")
        assert idx == 0


class TestSynthesiseCmdline:
    """We can't actually call piper in CI — but we can inspect what
    cmdline `_synthesise` would build. Patch
    `asyncio.create_subprocess_exec` to capture the argv."""

    def test_no_speaker_flag_when_idx_zero(self, tmp_path, monkeypatch):
        (tmp_path / "lone.onnx").write_bytes(b"")
        backend = PiperTTSBackend(piper_bin="/bin/true",
                                  model_dir=str(tmp_path))
        captured = {}

        async def fake_exec(*args, **kwargs):
            captured["argv"] = list(args)

            class _Proc:
                returncode = 0

                async def communicate(self, _input):
                    return b"", b""

            return _Proc()

        monkeypatch.setattr(
            "asyncio.create_subprocess_exec", fake_exec,
        )
        asyncio.run(backend._synthesise(
            "hei", tmp_path / "lone.onnx", speaker_idx=0,
        ))
        assert "--speaker" not in captured["argv"]

    def test_speaker_flag_present_when_idx_nonzero(self, tmp_path, monkeypatch):
        (tmp_path / "multi.onnx").write_bytes(b"")
        backend = PiperTTSBackend(piper_bin="/bin/true",
                                  model_dir=str(tmp_path))
        captured = {}

        async def fake_exec(*args, **kwargs):
            captured["argv"] = list(args)

            class _Proc:
                returncode = 0

                async def communicate(self, _input):
                    return b"", b""

            return _Proc()

        monkeypatch.setattr(
            "asyncio.create_subprocess_exec", fake_exec,
        )
        asyncio.run(backend._synthesise(
            "hei", tmp_path / "multi.onnx", speaker_idx=2,
        ))
        argv = captured["argv"]
        assert "--speaker" in argv
        # Index immediately follows the --speaker flag.
        assert argv[argv.index("--speaker") + 1] == "2"


class TestLoadNumSpeakers:
    def test_reads_num_speakers_from_config(self, tmp_path):
        model = tmp_path / "x.onnx"
        model.write_bytes(b"")
        (tmp_path / "x.onnx.json").write_text(json.dumps({"num_speakers": 7}))
        assert PiperTTSBackend._load_num_speakers(model) == 7

    def test_missing_config_returns_one(self, tmp_path):
        model = tmp_path / "x.onnx"
        model.write_bytes(b"")
        assert PiperTTSBackend._load_num_speakers(model) == 1

    def test_corrupt_config_returns_one(self, tmp_path):
        model = tmp_path / "x.onnx"
        model.write_bytes(b"")
        (tmp_path / "x.onnx.json").write_text("{not json")
        assert PiperTTSBackend._load_num_speakers(model) == 1

    def test_zero_is_clamped_to_one(self, tmp_path):
        model = tmp_path / "x.onnx"
        model.write_bytes(b"")
        (tmp_path / "x.onnx.json").write_text(json.dumps({"num_speakers": 0}))
        # Floor at 1 so the speaker-idx clamp logic always has a sane
        # ceiling to compare against.
        assert PiperTTSBackend._load_num_speakers(model) == 1
