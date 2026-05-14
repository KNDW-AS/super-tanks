"""
Tests for core/security/fix_proposals.py.

Isolates the proposals dir + a fake requirements.txt per test.
"""

import json

import pytest

from core.security import fix_proposals as fp


@pytest.fixture
def env(tmp_path, monkeypatch):
    proposals_dir = tmp_path / "proposed_fixes"
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "# header\n"
        "requests==2.30.0\n"
        "flask==2.2.0  # web app\n"
        "PyYAML==6.0.3\n"
    )
    monkeypatch.setattr(fp, "PROPOSALS_DIR", proposals_dir)
    monkeypatch.setattr(fp, "REQUIREMENTS_FILE", requirements)
    return tmp_path


# ── pin parsing ────────────────────────────────────────────────────────────

class TestPinParse:
    def test_finds_existing_pin(self, env):
        assert fp.find_pinned_version("requests") == "2.30.0"

    def test_case_insensitive(self, env):
        assert fp.find_pinned_version("REQUESTS") == "2.30.0"

    def test_underscore_dash_normalised(self, env, monkeypatch):
        path = env / "requirements.txt"
        path.write_text("python-telegram-bot==22.6\n")
        monkeypatch.setattr(fp, "REQUIREMENTS_FILE", path)
        assert fp.find_pinned_version("python_telegram_bot") == "22.6"

    def test_unpinned_returns_none(self, env):
        assert fp.find_pinned_version("nonexistent") is None


# ── diff ───────────────────────────────────────────────────────────────────

class TestDiff:
    def test_diff_includes_old_and_new_pin(self, env):
        diff = fp._build_requirements_diff("requests", "2.30.0", "2.32.5")
        assert "-requests==2.30.0" in diff
        assert "+requests==2.32.5" in diff

    def test_diff_does_not_touch_other_lines(self, env):
        diff = fp._build_requirements_diff("requests", "2.30.0", "2.32.5")
        assert "flask" not in diff or "+flask" not in diff


# ── propose_dep_upgrade ───────────────────────────────────────────────────

class TestPropose:
    def test_creates_proposal_for_pinned_pkg(self, env):
        p = fp.propose_dep_upgrade(
            threat_source="osv", threat_fingerprint="CVE-1",
            package="requests", target_version="2.32.5", reason="RCE",
        )
        assert p is not None
        assert p.package == "requests"
        assert p.current_version == "2.30.0"
        assert p.target_version == "2.32.5"
        assert "pip install" in p.apply_command
        assert "2.32.5" in p.apply_command
        assert "2.30.0" in p.rollback_command
        # Persisted to disk.
        path = fp.PROPOSALS_DIR / f"{p.id}.json"
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["package"] == "requests"

    def test_returns_none_for_unpinned(self, env):
        p = fp.propose_dep_upgrade(
            threat_source="osv", threat_fingerprint="CVE-1",
            package="missing-package", target_version="1.0", reason="x",
        )
        assert p is None

    def test_returns_none_when_already_at_target(self, env):
        p = fp.propose_dep_upgrade(
            threat_source="osv", threat_fingerprint="CVE-1",
            package="requests", target_version="2.30.0", reason="x",
        )
        assert p is None


# ── load / list / status transitions ──────────────────────────────────────

class TestStorage:
    def test_round_trip(self, env):
        p = fp.propose_dep_upgrade(
            threat_source="osv", threat_fingerprint="CVE-1",
            package="requests", target_version="2.32.5", reason="x",
        )
        loaded = fp.load(p.id)
        assert loaded.id == p.id
        assert loaded.package == "requests"

    def test_list_all_returns_every_proposal(self, env):
        a = fp.propose_dep_upgrade(
            threat_source="osv", threat_fingerprint="CVE-A",
            package="requests", target_version="2.32.5", reason="x")
        b = fp.propose_dep_upgrade(
            threat_source="osv", threat_fingerprint="CVE-B",
            package="flask", target_version="3.0.0", reason="y")
        ids = {p.id for p in fp.list_all()}
        assert ids == {a.id, b.id}

    def test_mark_applied_updates_status(self, env):
        p = fp.propose_dep_upgrade(
            threat_source="osv", threat_fingerprint="CVE-1",
            package="requests", target_version="2.32.5", reason="x")
        fp.mark_applied(p.id, by="operator", log="installed")
        loaded = fp.load(p.id)
        assert loaded.status == fp.STATUS_APPLIED
        assert loaded.applied_by == "operator"
        assert loaded.apply_log == "installed"

    def test_mark_rejected_updates_status(self, env):
        p = fp.propose_dep_upgrade(
            threat_source="osv", threat_fingerprint="CVE-1",
            package="requests", target_version="2.32.5", reason="x")
        fp.mark_rejected(p.id, by="operator", reason="not now")
        assert fp.load(p.id).status == fp.STATUS_REJECTED

    def test_mark_failed_updates_status(self, env):
        p = fp.propose_dep_upgrade(
            threat_source="osv", threat_fingerprint="CVE-1",
            package="requests", target_version="2.32.5", reason="x")
        fp.mark_failed(p.id, by="zeph_auto", error="pip exploded")
        assert fp.load(p.id).status == fp.STATUS_FAILED


# ── auto_apply_enabled ────────────────────────────────────────────────────

class TestAutoApplyFlag:
    def test_default_off(self, env, monkeypatch):
        monkeypatch.delenv("ST_ZEPH_AUTO_APPLY_DEPS", raising=False)
        assert fp.auto_apply_enabled() is False

    def test_one_enables(self, env, monkeypatch):
        monkeypatch.setenv("ST_ZEPH_AUTO_APPLY_DEPS", "1")
        assert fp.auto_apply_enabled() is True

    def test_zero_disables(self, env, monkeypatch):
        monkeypatch.setenv("ST_ZEPH_AUTO_APPLY_DEPS", "0")
        assert fp.auto_apply_enabled() is False


# ── write_requirements_with_pin ───────────────────────────────────────────

class TestWriteRequirements:
    def test_updates_only_target_pin(self, env):
        new = fp.write_requirements_with_pin("requests", "2.32.5")
        assert "requests==2.32.5" in new
        assert "flask==2.2.0" in new  # untouched
        assert "PyYAML==6.0.3" in new

    def test_preserves_unrelated_lines(self, env):
        fp.write_requirements_with_pin("flask", "3.0.0")
        text = (env / "requirements.txt").read_text()
        assert "# header" in text
