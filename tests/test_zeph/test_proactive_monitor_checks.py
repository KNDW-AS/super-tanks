"""
Tests for the individual check implementations inside
core/zeph/proactive_monitor.py. The checks shell out to psutil,
subprocess, and various DBs/manifests — we stub them so each branch
(ok / warning / critical / error) is exercised.
"""

import sys
import types


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

    def test_soul_integrity_delegates_to_soul_guard_ok(self, monkeypatch):
        # The check now routes through soul_guard so the SAFE_MODE flag
        # actually gets set on tampering — the previous standalone
        # implementation only reported, never enforced.
        fake_sg = types.ModuleType("core.soul_guard")
        fake_sg.check_soul_integrity = lambda: (True, "ok")
        fake_sg.is_safe_mode = lambda: False
        monkeypatch.setitem(sys.modules, "core.soul_guard", fake_sg)
        result = pm._check_soul_integrity()
        assert result["status"] == "ok"
        assert result["safe_mode"] is False

    def test_soul_integrity_tampering_sets_safe_mode(self, monkeypatch):
        fake_sg = types.ModuleType("core.soul_guard")
        fake_sg.check_soul_integrity = lambda: (False, "aeris hash mismatch")
        fake_sg.is_safe_mode = lambda: True
        monkeypatch.setitem(sys.modules, "core.soul_guard", fake_sg)
        result = pm._check_soul_integrity()
        assert result["status"] == "critical"
        assert result["safe_mode"] is True
        assert "aeris" in result["souls"].lower()


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
    def test_all_honeypots_present_and_canary_intact(self, monkeypatch, tmp_path):
        # Deploy real tripwires in a tmp store and verify the check
        # reports ok.
        from core.memory import hierarchical_store
        from core.memory.tripwires import ensure_tripwires_exist
        monkeypatch.setattr(hierarchical_store, "STORE_ROOT", tmp_path / "hm")
        ensure_tripwires_exist(hierarchical_store.HierarchicalMemoryStore())
        result = pm._check_tripwire_status()
        assert result["status"] == "ok"
        assert result["missing"] == []
        assert result["tampered"] == []
        assert result["checked"] >= 5

    def test_missing_honeypot_is_critical(self, monkeypatch, tmp_path):
        # No deployment → every honeypot is missing.
        from core.memory import hierarchical_store
        monkeypatch.setattr(hierarchical_store, "STORE_ROOT", tmp_path / "hm")
        result = pm._check_tripwire_status()
        assert result["status"] == "critical"
        assert len(result["missing"]) >= 5

    def test_modified_canary_is_critical(self, monkeypatch, tmp_path):
        # Deploy then tamper with one honeypot's l2_full content.
        from core.memory import hierarchical_store
        from core.memory.tripwires import (
            ensure_tripwires_exist, get_tripwire_paths,
        )
        monkeypatch.setattr(hierarchical_store, "STORE_ROOT", tmp_path / "hm")
        store = hierarchical_store.HierarchicalMemoryStore()
        ensure_tripwires_exist(store)
        target = get_tripwire_paths()[0]
        # Overwrite the canary with attacker-controlled content.
        store.store(target, "fake abs", "fake ov", "ATTACKER_CONTENT")
        result = pm._check_tripwire_status()
        assert result["status"] == "critical"
        assert target in result["tampered"]
