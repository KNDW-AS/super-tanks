"""Tests for core/voice/voice_security.py.

Voice is the loudest attack surface (anyone in earshot is
"authenticated"). These tests pin the invariants:

  - ZEF scans every transcript; BLOCK drops it silently
  - low-confidence transcripts dropped
  - critical commands force GO-Gate regardless of trust
  - fail-CLOSED on ZEF unavailability
  - routing uses the SAME logic as text input (escalation_rules)
"""

import sys
import types

import pytest

from core.diq.diq_voice import Transcript
from core.voice import voice_security


def _t(text, confidence=0.95, room_id="kitchen"):
    return Transcript(text=text, room_id=room_id, confidence=confidence)


@pytest.fixture
def zef_pass(monkeypatch):
    """ZEF stub that always PASSes."""
    fake = types.ModuleType("core.security.zef_injection_filter")
    from enum import Enum

    class FV(Enum):
        PASS = "pass"
        WARN = "warn"
        BLOCK = "block"
    fake.FilterVerdict = FV

    class _R:
        verdict = FV.PASS
        matched_patterns = []
    fake.scan_message = lambda text, source="": _R()
    monkeypatch.setitem(sys.modules,
                        "core.security.zef_injection_filter", fake)
    return fake


@pytest.fixture
def zef_block(monkeypatch):
    fake = types.ModuleType("core.security.zef_injection_filter")
    from enum import Enum

    class FV(Enum):
        PASS = "pass"
        WARN = "warn"
        BLOCK = "block"
    fake.FilterVerdict = FV

    class _R:
        verdict = FV.BLOCK
        matched_patterns = ["instruction_override"]
    fake.scan_message = lambda text, source="": _R()
    monkeypatch.setitem(sys.modules,
                        "core.security.zef_injection_filter", fake)
    return fake


# ── Critical command detection ────────────────────────────────────────────

class TestCriticalDetection:
    @pytest.mark.parametrize("text", [
        "Aeris unlock the door",
        "lås opp ytterdøra",
        "låse opp",
        "open the garage",
        "switch to autonomous mode",
        "kjøp ein ny TV",
        "overfør penger til ola",
        "set safe mode",
    ])
    def test_critical_patterns(self, text):
        assert voice_security.is_critical_command(text)

    @pytest.mark.parametrize("text", [
        "Aeris, hvordan er været?",
        "fortelje ei godnathistorie",
        "kva er klokka",
        "skru på lyset i stua",  # "skru på" is not in critical patterns
    ])
    def test_non_critical(self, text):
        assert not voice_security.is_critical_command(text)


# ── vet_transcript ────────────────────────────────────────────────────────

class TestVetTranscript:
    def test_empty_transcript_blocked(self, zef_pass):
        intent = voice_security.vet_transcript(_t(""))
        assert intent.blocked
        assert "empty" in intent.block_reason

    def test_low_confidence_dropped(self, zef_pass):
        intent = voice_security.vet_transcript(_t("hello", confidence=0.3))
        assert intent.blocked
        assert "low confidence" in intent.block_reason

    def test_zef_block_drops_transcript(self, zef_block):
        intent = voice_security.vet_transcript(_t("hello world"))
        assert intent.blocked
        assert "ZEF blocked" in intent.block_reason

    def test_zef_unavailable_fails_closed(self, monkeypatch):
        # Make the ZEF import raise.
        import builtins
        real_import = builtins.__import__

        def _import(name, *args, **kwargs):
            if name == "core.security.zef_injection_filter":
                raise RuntimeError("ZEF down")
            return real_import(name, *args, **kwargs)
        monkeypatch.setattr(builtins, "__import__", _import)
        intent = voice_security.vet_transcript(_t("hello world"))
        assert intent.blocked
        assert "failing closed" in intent.block_reason

    def test_clean_transcript_not_blocked(self, zef_pass):
        intent = voice_security.vet_transcript(_t("hello"))
        assert not intent.blocked
        assert intent.correlation_id

    def test_critical_command_forces_go_gate(self, zef_pass):
        intent = voice_security.vet_transcript(_t("unlock the door"))
        assert not intent.blocked
        assert intent.is_critical
        assert intent.requires_go_gate is True

    def test_non_critical_does_not_force_go_gate(self, zef_pass):
        intent = voice_security.vet_transcript(_t("kva er klokka"))
        assert not intent.blocked
        assert intent.is_critical is False
        assert intent.requires_go_gate is False

    def test_routing_target_uses_escalation_rules(self, zef_pass, monkeypatch):
        # Patch primary_responder via the module the import resolves through.
        from core.a2a import escalation_rules
        monkeypatch.setattr(escalation_rules, "primary_responder",
                            lambda text: "zeph")
        intent = voice_security.vet_transcript(_t("sjekk loggane"))
        assert intent.routing_target == "zeph"

    def test_routing_default_aeris_on_error(self, zef_pass, monkeypatch):
        from core.a2a import escalation_rules

        def boom(text):
            raise RuntimeError("router down")
        monkeypatch.setattr(escalation_rules, "primary_responder", boom)
        intent = voice_security.vet_transcript(_t("hello"))
        assert intent.routing_target == "aeris"
