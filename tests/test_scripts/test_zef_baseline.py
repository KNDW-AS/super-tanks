"""
Tests for scripts/zef_baseline.py.

The CLI is the operator's tool for marking the ZEF redteam corpus as
"passed against this upstream model tier." It must:

  - exit 0 + write the baseline when all floors are met
  - exit 1 + leave baseline untouched on any miss
  - skip writing under --report-only

We monkeypatch the corpus and the filter so the test runs in a few ms
and is independent of the live corpus contents.
"""

import json
import sys
import types

import pytest

from scripts import zef_baseline as cli


@pytest.fixture
def cli_env(tmp_path, monkeypatch):
    """Stub out the corpus + filter + baseline persistence."""
    # Mock corpus.
    fake_corpus = types.ModuleType("tests.security.redteam.corpus")
    fake_corpus.ATTACK_CASES = [
        ("attack-1", "BLOCK", "a1"),
        ("attack-2", "BLOCK", "a2"),
    ]
    fake_corpus.WARN_CASES = [("warn-1", "WARN", "w1")]
    fake_corpus.CLEAN_CASES = [
        ("clean-1", "PASS", "c1"),
        ("clean-2", "PASS", "c2"),
    ]
    monkeypatch.setitem(sys.modules, "tests.security.redteam.corpus", fake_corpus)

    # Mock the redteam test module for floor constants.
    fake_test = types.ModuleType("tests.security.redteam.test_zef_redteam")
    fake_test.MIN_BLOCK_RATE = 0.95
    fake_test.MAX_FALSE_POSITIVE_RATE = 0.10
    fake_test.MIN_WARN_RATE = 0.66
    monkeypatch.setitem(sys.modules,
                        "tests.security.redteam.test_zef_redteam", fake_test)

    # Verdict table — flip per-test by mutating `verdicts`.
    verdicts = {
        "attack-1": "BLOCK", "attack-2": "BLOCK",
        "clean-1": "PASS", "clean-2": "PASS",
        "warn-1": "WARN",
    }

    fake_filter = types.ModuleType("core.security.zef_injection_filter")

    class _Result:
        def __init__(self, v):
            self.verdict = types.SimpleNamespace(value=v.lower())
    fake_filter.scan_message = lambda text, source="": _Result(verdicts[text])
    monkeypatch.setitem(sys.modules,
                        "core.security.zef_injection_filter", fake_filter)

    # Stub mark_zef_baselined to capture calls + redirect persistence.
    baseline_calls = []
    fake_mode = types.ModuleType("core.security.super_tanks_mode")
    fake_mode.mark_zef_baselined = lambda fp: baseline_calls.append(fp)
    monkeypatch.setitem(sys.modules,
                        "core.security.super_tanks_mode", fake_mode)

    return types.SimpleNamespace(
        verdicts=verdicts, baseline_calls=baseline_calls, tmp=tmp_path,
    )


class TestMeasure:
    def test_all_pass(self, cli_env):
        m = cli._measure()
        assert m["block_rate"] == 1.0
        assert m["false_positive_rate"] == 0.0
        assert m["warn_rate"] == 1.0
        assert m["block_rate_pass"] and m["false_positive_pass"] and m["warn_rate_pass"]

    def test_block_rate_below_floor(self, cli_env):
        cli_env.verdicts["attack-1"] = "PASS"
        m = cli._measure()
        assert m["block_rate"] == 0.5
        assert m["block_rate_pass"] is False

    def test_false_positive_above_ceiling(self, cli_env):
        cli_env.verdicts["clean-1"] = "BLOCK"
        m = cli._measure()
        assert m["false_positive_rate"] == 0.5
        assert m["false_positive_pass"] is False

    def test_warn_rate_below_floor(self, cli_env):
        cli_env.verdicts["warn-1"] = "PASS"
        m = cli._measure()
        assert m["warn_rate"] == 0.0
        assert m["warn_rate_pass"] is False


class TestCli:
    def test_pass_writes_baseline(self, cli_env, capsys):
        rc = cli.main(["--tier", "claude-mythos-2026-04"])
        assert rc == 0
        assert cli_env.baseline_calls == ["claude-mythos-2026-04"]
        out = capsys.readouterr().out
        assert "BASELINED" in out
        assert "claude-mythos-2026-04" in out

    def test_block_rate_miss_blocks_baseline(self, cli_env, capsys):
        cli_env.verdicts["attack-1"] = "PASS"
        rc = cli.main(["--tier", "claude-mythos-2026-04"])
        assert rc == 1
        assert cli_env.baseline_calls == []
        out = capsys.readouterr().out
        assert "REJECTED" in out

    def test_report_only_does_not_write_even_on_pass(self, cli_env, capsys):
        rc = cli.main(["--tier", "claude-mythos-2026-04", "--report-only"])
        assert rc == 0
        assert cli_env.baseline_calls == []
        out = capsys.readouterr().out
        assert "REPORT-ONLY" in out
        assert "block_rate" in out

    def test_missing_tier_arg_exits_with_error(self, cli_env):
        with pytest.raises(SystemExit):
            cli.main([])
