"""
Tests for core/security/intel_sources/zef_drift.py.

The source delegates measurement to scripts.zef_baseline._measure;
we patch that to feed deterministic numbers and assert the right
threats are emitted.
"""

import sys
import types

import pytest

from core.security.intel_sources.zef_drift import ZEFDriftSource


def _measurement(block_pass=True, fp_pass=True, warn_pass=True,
                 block_rate=1.0, fp_rate=0.0, warn_rate=1.0):
    return {
        "block_rate": block_rate, "block_rate_floor": 0.95,
        "block_rate_pass": block_pass,
        "block_count": (46 if block_pass else 40, 46),

        "false_positive_rate": fp_rate,
        "false_positive_ceiling": 0.10,
        "false_positive_pass": fp_pass,
        "false_positive_count": (0 if fp_pass else 5, 20),

        "warn_rate": warn_rate, "warn_rate_floor": 0.66,
        "warn_rate_pass": warn_pass,
        "warn_count": (3 if warn_pass else 1, 3),
    }


@pytest.fixture
def patched_measure(monkeypatch):
    """Replace scripts.zef_baseline._measure for the test."""
    fake_mod = types.ModuleType("scripts.zef_baseline")
    holder = {"value": _measurement()}
    fake_mod._measure = lambda: holder["value"]
    monkeypatch.setitem(sys.modules, "scripts.zef_baseline", fake_mod)
    return holder


# ── ZEFDriftSource.fetch ───────────────────────────────────────────────────

class TestFetch:
    def test_no_drift_emits_nothing(self, patched_measure):
        threats = ZEFDriftSource().fetch()
        assert threats == []

    def test_block_rate_drop_emits_high(self, patched_measure):
        patched_measure["value"] = _measurement(
            block_pass=False, block_rate=0.92)
        threats = ZEFDriftSource().fetch()
        assert len(threats) == 1
        t = threats[0]
        assert t.severity == "MEDIUM"  # 0.95 - 0.92 = 0.03 → margin floor
        assert "block_rate" in t.fingerprint
        assert "92.0%" in t.summary

    def test_large_block_rate_drop_emits_critical(self, patched_measure):
        patched_measure["value"] = _measurement(
            block_pass=False, block_rate=0.80)
        threats = ZEFDriftSource().fetch()
        assert threats[0].severity == "CRITICAL"

    def test_fpr_above_ceiling_emits_high(self, patched_measure):
        patched_measure["value"] = _measurement(
            fp_pass=False, fp_rate=0.20)
        threats = ZEFDriftSource().fetch()
        assert len(threats) == 1
        assert threats[0].severity == "HIGH"
        assert "false_positive_rate" in threats[0].fingerprint

    def test_warn_rate_drop_emits_medium(self, patched_measure):
        patched_measure["value"] = _measurement(
            warn_pass=False, warn_rate=0.30)
        threats = ZEFDriftSource().fetch()
        assert len(threats) == 1
        assert threats[0].severity == "MEDIUM"

    def test_multiple_failures_emit_multiple_threats(self, patched_measure):
        patched_measure["value"] = _measurement(
            block_pass=False, fp_pass=False, warn_pass=False,
            block_rate=0.85, fp_rate=0.20, warn_rate=0.30)
        threats = ZEFDriftSource().fetch()
        assert len(threats) == 3

    def test_measure_failure_returns_empty(self, monkeypatch):
        fake_mod = types.ModuleType("scripts.zef_baseline")
        def boom(): raise RuntimeError("filter import busted")
        fake_mod._measure = boom
        monkeypatch.setitem(sys.modules, "scripts.zef_baseline", fake_mod)
        assert ZEFDriftSource().fetch() == []
