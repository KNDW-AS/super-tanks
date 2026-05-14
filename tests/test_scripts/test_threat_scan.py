"""
Tests for scripts/threat_scan.py.

Stubs out threat_intel + threat_monitor and verifies the orchestrator
calls them correctly + emits a digest.
"""

import json
import sys
import types

import pytest

from scripts import threat_scan as cli


@pytest.fixture
def cli_env(monkeypatch):
    """Monkeypatch the real subsystem functions in place. (Replacing
    whole modules in sys.modules doesn't work here because
    `from core.security import threat_intel` resolves through the
    package attribute, not sys.modules.)"""
    intel_calls = []
    monitor_calls = []

    from core.security import threat_intel as real_intel

    monkeypatch.setattr(real_intel, "register_source",
                        lambda s: intel_calls.append(("source", s)))
    monkeypatch.setattr(real_intel, "register_mitigator",
                        lambda m: intel_calls.append(("mit", m)))

    class _Result:
        sources_run = 2
        threats_seen = 3
        new_threats: list = []
        mitigation_log = ["did stuff"]
        errors: list = []

        def to_dict(self):
            return {
                "sources_run": self.sources_run,
                "threats_seen": self.threats_seen,
                "new_threats": self.new_threats,
                "mitigation_log": self.mitigation_log,
                "errors": self.errors,
            }

    monkeypatch.setattr(real_intel, "scan_all",
                        lambda: (intel_calls.append(("scan_all", None))
                                 or _Result()))

    # Stub source classes (avoid real network in OSV).
    fake_osv = types.ModuleType("core.security.intel_sources.osv")
    fake_osv.OSVDepSource = lambda: object()
    monkeypatch.setitem(sys.modules,
                        "core.security.intel_sources.osv", fake_osv)
    fake_zd = types.ModuleType("core.security.intel_sources.zef_drift")
    fake_zd.ZEFDriftSource = lambda: object()
    monkeypatch.setitem(sys.modules,
                        "core.security.intel_sources.zef_drift", fake_zd)

    # Stub the active monitor.
    from core.security import threat_monitor as real_tm

    class _Report:
        window_minutes = 5
        findings = ["f1"]
        actions_taken = ["a1"]
        errors: list = []

    monkeypatch.setattr(real_tm, "scan_once",
                        lambda: (monitor_calls.append("scan_once")
                                 or _Report()))

    return types.SimpleNamespace(intel_calls=intel_calls,
                                 monitor_calls=monitor_calls)


class TestCli:
    def test_default_runs_both(self, cli_env, capsys):
        rc = cli.main([])
        assert rc == 0
        # Sources + mitigators registered.
        assert any(c[0] == "source" for c in cli_env.intel_calls)
        assert any(c[0] == "mit" for c in cli_env.intel_calls)
        assert any(c[0] == "scan_all" for c in cli_env.intel_calls)
        assert cli_env.monitor_calls == ["scan_once"]
        out = capsys.readouterr().out
        assert "External intel" in out
        assert "Active monitor" in out

    def test_skip_intel_runs_monitor_only(self, cli_env, capsys):
        rc = cli.main(["--skip-intel"])
        assert rc == 0
        assert not any(c[0] == "scan_all" for c in cli_env.intel_calls)
        assert cli_env.monitor_calls == ["scan_once"]
        out = capsys.readouterr().out
        assert "Active monitor" in out

    def test_skip_monitor_runs_intel_only(self, cli_env, capsys):
        rc = cli.main(["--skip-monitor"])
        assert rc == 0
        assert any(c[0] == "scan_all" for c in cli_env.intel_calls)
        assert cli_env.monitor_calls == []

    def test_json_emits_parseable_dict(self, cli_env, capsys):
        rc = cli.main(["--json"])
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "intel" in data and "monitor" in data
        assert data["monitor"]["findings"] == ["f1"]
