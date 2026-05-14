"""
Tests for scripts/apply_proposed_fix.py.
"""

import json

import pytest

from scripts import apply_proposed_fix as cli
from core.security import fix_proposals as fp


@pytest.fixture
def env(tmp_path, monkeypatch):
    proposals_dir = tmp_path / "proposed_fixes"
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.30.0\n")
    monkeypatch.setattr(fp, "PROPOSALS_DIR", proposals_dir)
    monkeypatch.setattr(fp, "REQUIREMENTS_FILE", requirements)
    return tmp_path


def _make_proposal():
    return fp.propose_dep_upgrade(
        threat_source="osv", threat_fingerprint="CVE-1",
        package="requests", target_version="2.32.5", reason="RCE in requests",
    )


class TestList:
    def test_empty(self, env, capsys):
        rc = cli.main(["--list"])
        assert rc == 0
        assert "No proposals" in capsys.readouterr().out

    def test_lists_proposal(self, env, capsys):
        p = _make_proposal()
        rc = cli.main(["--list"])
        assert rc == 0
        out = capsys.readouterr().out
        assert p.id in out
        assert "requests" in out
        assert "proposed" in out


class TestShow:
    def test_unknown_id_returns_2(self, env, capsys):
        rc = cli.main(["--show", "missing-id"])
        assert rc == 2

    def test_show_prints_diff_and_commands(self, env, capsys):
        p = _make_proposal()
        rc = cli.main(["--show", p.id])
        assert rc == 0
        out = capsys.readouterr().out
        assert "requests" in out
        assert "2.30.0" in out
        assert "2.32.5" in out
        assert "pip install" in out


class TestReject:
    def test_reject_marks_rejected(self, env, capsys):
        p = _make_proposal()
        rc = cli.main(["--reject", p.id, "--note", "wait for upstream"])
        assert rc == 0
        assert fp.load(p.id).status == fp.STATUS_REJECTED
        assert "wait for upstream" in fp.load(p.id).apply_log


class TestApply:
    def test_unknown_id(self, env, capsys):
        rc = cli.main(["--apply", "missing-id"])
        assert rc == 2

    def test_already_applied_refuses(self, env, capsys):
        p = _make_proposal()
        fp.mark_applied(p.id, by="op", log="x")
        rc = cli.main(["--apply", p.id])
        assert rc == 2

    def test_apply_invokes_pipeline_and_marks_applied(self, env, monkeypatch,
                                                       capsys):
        p = _make_proposal()
        # Stub the apply pipeline so we don't actually pip install.
        from core.security import dep_upgrade_apply
        called = []

        def _fake_apply(proposal, by="operator"):
            called.append((proposal.id, by))
            fp.mark_applied(proposal.id, by=by, log="stub success")
            return True, "stub success"

        monkeypatch.setattr(dep_upgrade_apply, "apply_proposal", _fake_apply)
        rc = cli.main(["--apply", p.id])
        assert rc == 0
        assert called == [(p.id, "operator")]
        assert "APPLIED" in capsys.readouterr().out

    def test_apply_failure_returns_1(self, env, monkeypatch, capsys):
        p = _make_proposal()
        from core.security import dep_upgrade_apply

        def _fake_apply(proposal, by="operator"):
            fp.mark_failed(proposal.id, by=by, error="boom")
            return False, "boom"

        monkeypatch.setattr(dep_upgrade_apply, "apply_proposal", _fake_apply)
        rc = cli.main(["--apply", p.id])
        assert rc == 1
        captured = capsys.readouterr()
        assert "FAILED" in captured.err or "FAILED" in captured.out
