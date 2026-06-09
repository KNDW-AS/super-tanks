"""Tests for core/voice/backends/whisper_stt.py — init, fail-closed,
transcribe, stream, confidence mapping."""

import asyncio
import math

import pytest

from core.voice.backends.whisper_stt import (
    WhisperSTTBackend,
    _logprob_to_confidence,
)


class _FakeSegment:
    def __init__(self, text, avg_logprob=None):
        self.text = text
        if avg_logprob is not None:
            self.avg_logprob = avg_logprob


class _FakeModel:
    """Stand-in for faster_whisper.WhisperModel — captures the
    transcribe args and replays scripted segments."""

    def __init__(self, segments, info=None, raises=None):
        self._segments = segments
        self._info = info or object()
        self._raises = raises
        self.calls = []

    def transcribe(self, audio_ref, language=None):
        self.calls.append((audio_ref, language))
        if self._raises:
            raise self._raises
        return iter(self._segments), self._info


class TestInit:
    def test_args_take_precedence_over_env(self, monkeypatch):
        monkeypatch.setenv("ST_WHISPER_MODEL", "/env/model")
        monkeypatch.setenv("ST_WHISPER_DEVICE", "cuda")
        monkeypatch.setenv("ST_WHISPER_LANG", "en")
        backend = WhisperSTTBackend(
            model_path="/arg/model", device="cpu", default_language="no",
        )
        assert backend.model_path == "/arg/model"
        assert backend.device == "cpu"
        assert backend.default_language == "no"

    def test_env_fallback_when_args_empty(self, monkeypatch):
        monkeypatch.setenv("ST_WHISPER_MODEL", "/env/model")
        monkeypatch.setenv("ST_WHISPER_DEVICE", "cuda")
        monkeypatch.setenv("ST_WHISPER_LANG", "sv")
        backend = WhisperSTTBackend()
        assert backend.model_path == "/env/model"
        assert backend.device == "cuda"
        assert backend.default_language == "sv"

    def test_defaults_when_nothing_set(self, monkeypatch):
        for var in ("ST_WHISPER_MODEL", "ST_WHISPER_DEVICE", "ST_WHISPER_LANG"):
            monkeypatch.delenv(var, raising=False)
        backend = WhisperSTTBackend()
        assert backend.model_path == ""
        assert backend.device == "cpu"
        assert backend.default_language == "no"


class TestEnsureModel:
    def test_empty_model_path_leaves_model_none(self, monkeypatch):
        monkeypatch.delenv("ST_WHISPER_MODEL", raising=False)
        backend = WhisperSTTBackend()
        backend._ensure_model()
        assert backend._model is None

    def test_load_failure_logs_warning_and_keeps_none(self, monkeypatch, caplog):
        backend = WhisperSTTBackend(model_path="/no/such/path")

        def boom(*_a, **_kw):
            raise RuntimeError("cannot load")

        # Provide a fake faster_whisper module so the import succeeds
        # but the constructor blows up.
        import sys
        import types
        fake_mod = types.ModuleType("faster_whisper")
        fake_mod.WhisperModel = boom
        monkeypatch.setitem(sys.modules, "faster_whisper", fake_mod)

        with caplog.at_level("WARNING", logger="super_tanks.voice.whisper"):
            backend._ensure_model()
        assert backend._model is None
        assert any("could not load model" in r.message for r in caplog.records)

    def test_already_loaded_is_idempotent(self):
        backend = WhisperSTTBackend(model_path="/x")
        sentinel = object()
        backend._model = sentinel
        backend._ensure_model()
        assert backend._model is sentinel


class TestTranscribe:
    def test_fails_closed_when_unconfigured(self, monkeypatch, caplog):
        monkeypatch.delenv("ST_WHISPER_MODEL", raising=False)
        backend = WhisperSTTBackend()
        with caplog.at_level("WARNING", logger="super_tanks.voice.whisper"):
            result = asyncio.run(backend.transcribe("clip.wav"))
        assert result.text == ""
        assert result.confidence == 0.0
        assert result.audio_ref == "clip.wav"
        assert any("not configured" in r.message for r in caplog.records)

    def test_concatenates_segments_and_averages_confidence(self):
        backend = WhisperSTTBackend(model_path="/x")
        backend._model = _FakeModel([
            _FakeSegment("  hei ", avg_logprob=-0.2),
            _FakeSegment(" Aeris", avg_logprob=-0.4),
        ])
        result = asyncio.run(backend.transcribe("clip.wav", language="no"))
        assert result.text == "hei Aeris"
        expected = (math.exp(-0.2) + math.exp(-0.4)) / 2
        assert result.confidence == pytest.approx(expected)
        assert backend._model.calls == [("clip.wav", "no")]

    def test_segments_without_logprob_default_to_half(self):
        backend = WhisperSTTBackend(model_path="/x")
        backend._model = _FakeModel([_FakeSegment("ok")])
        result = asyncio.run(backend.transcribe("clip.wav"))
        # Default language falls back to backend.default_language.
        assert backend._model.calls[0][1] == "no"
        assert result.confidence == 0.5

    def test_language_arg_falls_back_to_default_when_empty(self):
        backend = WhisperSTTBackend(model_path="/x", default_language="sv")
        backend._model = _FakeModel([_FakeSegment("hej")])
        asyncio.run(backend.transcribe("clip.wav", language=""))
        assert backend._model.calls[0][1] == "sv"

    def test_exception_returns_empty_transcript(self, caplog):
        backend = WhisperSTTBackend(model_path="/x")
        backend._model = _FakeModel([], raises=RuntimeError("decoder OOM"))
        with caplog.at_level("ERROR", logger="super_tanks.voice.whisper"):
            result = asyncio.run(backend.transcribe("clip.wav"))
        assert result.text == ""
        assert result.confidence == 0.0
        assert any("transcribe raised" in r.message for r in caplog.records)


class TestStream:
    def test_yields_single_final_transcript(self):
        backend = WhisperSTTBackend(model_path="/x")
        backend._model = _FakeModel([_FakeSegment("hei", avg_logprob=-0.3)])

        async def collect():
            return [t async for t in backend.stream("clip.wav")]

        results = asyncio.run(collect())
        assert len(results) == 1
        assert results[0].text == "hei"


class TestLogprobToConfidence:
    @pytest.mark.parametrize("logprob,expected", [
        (0.0, 1.0),       # perfect
        (-0.2, math.exp(-0.2)),
        (-1.0, math.exp(-1.0)),
    ])
    def test_maps_to_unit_interval(self, logprob, expected):
        assert _logprob_to_confidence(logprob) == pytest.approx(expected)

    def test_positive_logprob_clamps_to_one(self):
        # Numerically impossible from Whisper but the clamp guards the contract.
        assert _logprob_to_confidence(0.5) == 1.0

    def test_very_negative_logprob_stays_in_range(self):
        result = _logprob_to_confidence(-50.0)
        assert 0.0 <= result <= 1.0
