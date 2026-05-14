"""
Tests for the individual check implementations inside
core/zeph/proactive_monitor.py. The checks shell out to psutil,
subprocess, and various DBs/manifests — we stub them so each branch
(ok / warning / critical / error) is exercised.
"""

import sys
import types
from datetime import datetime, timezone

import pytest

from core.zeph import proactive_monitor as pm


# ── _check_disk_usage / _check_memory_usage ────────────────────────────────

class TestPsutilChecks:
    def _fake_psutil(self, monkeypatch, *, disk_pct=10.0, mem_pct=10.0):
        psutil_stub = types.SimpleNamespace(
            disk_usage=lambda path: types.SimpleNamespace(
                percent=disk_pct, total=100 * 1024**3, free=90 * 1024**3),
            virtual_memory=lambda: types.SimpleNamespace(
                percent=mem_pct, total=32 * 1024**3, available=24 * 1024**3),
        )
        monkeypatch.setitem(sys.modules, "psutil", psutil_stub)

    def test_disk_ok(self, monkeypatch):
        self._fake_psutil(monkeypatch, disk_pct=50)
        assert pm._check_disk_usage()["status"] == "ok"

    def test_disk_warning(self, monkeypatch):
        self._fake_psutil(monkeypatch, disk_pct=85)
        assert pm._check_disk_usage()["status"] == "warning"

    def test_disk_critical(self, monkeypatch):
        self._fake_psutil(monkeypatch, disk_pct=95)
        assert pm._check_disk_usage()["status"] == "critical"

    def test_memory_ok(self, monkeypatch):
        self._fake_psutil(monkeypatch, mem_pct=40)
        assert pm._check_memory_usage()["status"] == "ok"

    def test_memory_warning(self, monkeypatch):
        self._fake_psutil(monkeypatch, mem_pct=85)
        assert pm._check_memory_usage()["status"] == "warning"

    def test_memory_critical(self, monkeypatch):
        self._fake_psutil(monkeypatch, mem_pct=99)
        assert pm._check_memory_usage()["status"] == "critical"

    def test_disk_error_when_psutil_missing(self, monkeypatch):
        # Force the import inside _check_disk_usage to raise.
        monkeypatch.setitem(sys.modules, "psutil", None)
        assert pm._check_disk_usage()["status"] == "error"


# ── Subprocess-based checks ────────────────────────────────────────────────

class _FakeProc:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode


class TestSubprocessChecks:
    def test_failed_services_none(self, monkeypatch):
        monkeypatch.setattr(pm.subprocess, "run",
                            lambda *a, **kw: _FakeProc(stdout="0 loaded units listed."))
        result = pm._check_failed_services()
        assert result["status"] == "ok"
        assert result["count"] == 0

    def test_failed_services_some(self, monkeypatch):
        output = "● broken.service\nfailed broken.service"
        monkeypatch.setattr(pm.subprocess, "run",
                            lambda *a, **kw: _FakeProc(stdout=output))
        result = pm._check_failed_services()
        assert result["status"] == "warning"
        assert result["count"] >= 1

    def test_failed_services_subprocess_error(self, monkeypatch):
        def boom(*a, **kw):
            raise OSError("systemctl not found")
        monkeypatch.setattr(pm.subprocess, "run", boom)
        assert pm._check_failed_services()["status"] == "error"

    def test_log_errors_ok(self, monkeypatch):
        monkeypatch.setattr(pm.subprocess, "run",
                            lambda *a, **kw: _FakeProc(stdout="line1\nline2\n"))
        result = pm._check_log_errors()
        assert result["status"] == "ok"
        assert result["error_count_24h"] == 2

    def test_log_errors_warning(self, monkeypatch):
        output = "\n".join(f"err{i}" for i in range(25))
        monkeypatch.setattr(pm.subprocess, "run",
                            lambda *a, **kw: _FakeProc(stdout=output))
        assert pm._check_log_errors()["status"] == "warning"

    def test_log_errors_critical(self, monkeypatch):
        output = "\n".join(f"err{i}" for i in range(150))
        monkeypatch.setattr(pm.subprocess, "run",
                            lambda *a, **kw: _FakeProc(stdout=output))
        assert pm._check_log_errors()["status"] == "critical"

    def test_outdated_packages_none(self, monkeypatch):
        monkeypatch.setattr(pm.subprocess, "run",
                            lambda *a, **kw: _FakeProc(stdout="[]", returncode=0))
        result = pm._check_outdated_packages()
        assert result["outdated_count"] == 0

    def test_outdated_packages_warning(self, monkeypatch):
        import json as _json
        packages = [{"name": f"p{i}", "version": "1.0"} for i in range(15)]
        monkeypatch.setattr(
            pm.subprocess, "run",
            lambda *a, **kw: _FakeProc(stdout=_json.dumps(packages), returncode=0))
        assert pm._check_outdated_packages()["status"] == "warning"

    def test_failed_logins(self, monkeypatch):
        monkeypatch.setattr(pm.subprocess, "run",
                            lambda *a, **kw: _FakeProc(stdout="entry1\nentry2"))
        result = pm._check_failed_logins()
        assert result["failed_login_count_7d"] == 2

    def test_failed_logins_warning(self, monkeypatch):
        output = "\n".join(f"entry{i}" for i in range(25))
        monkeypatch.setattr(pm.subprocess, "run",
                            lambda *a, **kw: _FakeProc(stdout=output))
        assert pm._check_failed_logins()["status"] == "warning"


# ── DIQ / soul integrity ───────────────────────────────────────────────────

class TestIntegrityChecks:
    def test_diq_integrity_passes(self, monkeypatch):
        fake = types.ModuleType("core.diq.diq_integrity")
        fake.verify_diq_integrity = lambda: None
        monkeypatch.setitem(sys.modules, "core.diq.diq_integrity", fake)
        result = pm._check_diq_integrity()
        assert result["status"] == "ok"

    def test_diq_integrity_critical_on_runtime_error(self, monkeypatch):
        fake = types.ModuleType("core.diq.diq_integrity")
        def boom():
            raise RuntimeError("tampered")
        fake.verify_diq_integrity = boom
        monkeypatch.setitem(sys.modules, "core.diq.diq_integrity", fake)
        result = pm._check_diq_integrity()
        assert result["status"] == "critical"

    def test_soul_integrity_missing_manifest(self, monkeypatch, tmp_path):
        monkeypatch.setattr(pm, "REPO_ROOT", tmp_path)
        result = pm._check_soul_integrity()
        assert result["status"] == "warning"

    def test_soul_integrity_clean(self, monkeypatch, tmp_path):
        import hashlib, json
        core = tmp_path / "core"
        core.mkdir()
        soul = core / "aeris_soul.py"
        soul.write_bytes(b"clean soul")
        manifest = {"souls": {
            "aeris": {"file": "core/aeris_soul.py",
                      "sha256": hashlib.sha256(b"clean soul").hexdigest()}}}
        (core / "soul_integrity.json").write_text(json.dumps(manifest))
        monkeypatch.setattr(pm, "REPO_ROOT", tmp_path)
        result = pm._check_soul_integrity()
        assert result["status"] == "ok"

    def test_soul_integrity_critical_on_mismatch(self, monkeypatch, tmp_path):
        import hashlib, json
        core = tmp_path / "core"
        core.mkdir()
        soul = core / "aeris_soul.py"
        soul.write_bytes(b"tampered soul")
        manifest = {"souls": {
            "aeris": {"file": "core/aeris_soul.py",
                      "sha256": hashlib.sha256(b"original").hexdigest()}}}
        (core / "soul_integrity.json").write_text(json.dumps(manifest))
        monkeypatch.setattr(pm, "REPO_ROOT", tmp_path)
        result = pm._check_soul_integrity()
        assert result["status"] == "critical"


# ── DB-backed checks (missing DBs → ok with message) ──────────────────────

class TestDbChecks:
    def test_gogate_pending_no_db(self, monkeypatch, tmp_path):
        monkeypatch.setattr(pm, "DATA_DIR", tmp_path)
        assert pm._check_gogate_pending()["pending"] == 0

    def test_zef_block_count_no_db(self, monkeypatch, tmp_path):
        monkeypatch.setattr(pm, "DATA_DIR", tmp_path)
        assert pm._check_zef_block_count()["blocked"] == 0

    def test_shadow_backlog_no_db(self, monkeypatch, tmp_path):
        monkeypatch.setattr(pm, "DATA_DIR", tmp_path)
        assert pm._check_shadow_backlog()["pending"] == 0

    def test_quarantine_review_empty_dir(self, monkeypatch, tmp_path):
        monkeypatch.setattr(pm, "REPO_ROOT", tmp_path)
        result = pm._check_quarantine_review()
        # No quarantine dir at all → status ok, count 0.
        assert result["status"] == "ok"
        assert result["count"] == 0


# ── Trust scores ──────────────────────────────────────────────────────────

class TestTrustCheck:
    def test_probation_yields_warning(self, monkeypatch):
        fake = types.ModuleType("core.security.trust_score")
        fake.get_score = lambda a: {"score": 5, "level": "probation",
                                    "agent_id": a}
        monkeypatch.setitem(sys.modules, "core.security.trust_score", fake)
        result = pm._check_trust_scores()
        assert result["status"] == "warning"

    def test_standard_yields_ok(self, monkeypatch):
        fake = types.ModuleType("core.security.trust_score")
        fake.get_score = lambda a: {"score": 70, "level": "standard",
                                    "agent_id": a}
        monkeypatch.setitem(sys.modules, "core.security.trust_score", fake)
        assert pm._check_trust_scores()["status"] == "ok"


# ── Tripwire status ────────────────────────────────────────────────────────

class TestTripwireStatus:
    def test_missing_manifest_warning(self, monkeypatch, tmp_path):
        monkeypatch.setattr(pm, "REPO_ROOT", tmp_path)
        assert pm._check_tripwire_status()["status"] == "warning"

    def test_clean_manifest_ok(self, monkeypatch, tmp_path):
        import hashlib, json
        locked = tmp_path / "core_locked"
        locked.mkdir()
        target = tmp_path / "x.py"
        target.write_bytes(b"hello")
        manifest = {"frozen_files": [
            {"path": "x.py", "sha256": hashlib.sha256(b"hello").hexdigest()},
        ]}
        (locked / "FROZEN_MANIFEST.json").write_text(json.dumps(manifest))
        monkeypatch.setattr(pm, "REPO_ROOT", tmp_path)
        result = pm._check_tripwire_status()
        assert result["status"] == "ok"
        assert result["violations"] == []

    def test_tampered_yields_critical(self, monkeypatch, tmp_path):
        import hashlib, json
        locked = tmp_path / "core_locked"
        locked.mkdir()
        target = tmp_path / "x.py"
        target.write_bytes(b"TAMPERED")
        manifest = {"frozen_files": [
            {"path": "x.py", "sha256": hashlib.sha256(b"original").hexdigest()},
        ]}
        (locked / "FROZEN_MANIFEST.json").write_text(json.dumps(manifest))
        monkeypatch.setattr(pm, "REPO_ROOT", tmp_path)
        result = pm._check_tripwire_status()
        assert result["status"] == "critical"
        assert any("TAMPERED" in v for v in result["violations"])
