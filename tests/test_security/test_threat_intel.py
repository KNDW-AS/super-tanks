"""
Tests for core/security/threat_intel.py.

Covers:
  - Threat dataclass validation
  - ThreatStore: insert + dedup + chain integrity (re-uses R-12)
  - Registry: register_source / register_mitigator / reset
  - scan_all: source + mitigator dispatch, per-source error isolation
"""

import sqlite3

import pytest

from core.security import threat_intel as ti
from core.security.threat_intel import (
    Threat, IntelSource,
    register_source, register_mitigator, scan_all,
    record_threat, list_recent_threats, verify_threat_chain,
)


@pytest.fixture
def store(tmp_path, monkeypatch):
    """Isolated threat-intel DB + clean registry per test."""
    monkeypatch.setattr(ti, "DB_PATH", tmp_path / "threat_intel.db")
    monkeypatch.setattr(ti, "_initialised", False)
    # Set a deterministic HMAC key so the audit_chain machinery works.
    from core.security import agent_identity
    monkeypatch.setattr(agent_identity, "_KEY", b"test-threat-intel-key")
    ti._reset_registry_for_test()
    yield ti
    ti._reset_registry_for_test()


# ── Threat dataclass ───────────────────────────────────────────────────────

class TestThreat:
    def test_basic_fields(self):
        t = Threat(source="osv", fingerprint="CVE-2025-1",
                   severity="HIGH", summary="oops")
        assert t.source == "osv"
        assert t.severity == "HIGH"
        assert t.discovered_at  # auto-populated

    def test_invalid_severity_raises(self):
        with pytest.raises(ValueError):
            Threat(source="osv", fingerprint="x",
                   severity="EXTREME", summary="bad")

    def test_frozen_dataclass(self):
        t = Threat(source="s", fingerprint="f",
                   severity="LOW", summary="ok")
        with pytest.raises(Exception):
            t.severity = "HIGH"  # frozen


# ── Store: insert + dedup + chain ──────────────────────────────────────────

class TestThreatStore:
    def test_insert_returns_true_for_new(self, store):
        t = Threat(source="osv", fingerprint="CVE-1",
                   severity="HIGH", summary="x")
        assert record_threat(t) is True

    def test_dedup_returns_false_for_repeat(self, store):
        t = Threat(source="osv", fingerprint="CVE-1",
                   severity="HIGH", summary="x")
        assert record_threat(t) is True
        assert record_threat(t) is False

    def test_dedup_is_per_source_fingerprint(self, store):
        a = Threat(source="osv", fingerprint="CVE-1",
                   severity="HIGH", summary="a")
        b = Threat(source="zef_drift", fingerprint="CVE-1",
                   severity="HIGH", summary="b")
        assert record_threat(a) is True
        assert record_threat(b) is True  # different source

    def test_list_recent_returns_inserted(self, store):
        record_threat(Threat(source="s", fingerprint="f1",
                             severity="LOW", summary="one"))
        record_threat(Threat(source="s", fingerprint="f2",
                             severity="HIGH", summary="two"))
        rows = list_recent_threats(limit=10)
        assert {r.fingerprint for r in rows} == {"f1", "f2"}

    def test_list_recent_filters_by_severity(self, store):
        record_threat(Threat(source="s", fingerprint="f1",
                             severity="LOW", summary="one"))
        record_threat(Threat(source="s", fingerprint="f2",
                             severity="HIGH", summary="two"))
        rows = list_recent_threats(min_severity="HIGH")
        assert {r.fingerprint for r in rows} == {"f2"}

    def test_chain_intact_after_inserts(self, store):
        for i in range(5):
            record_threat(Threat(source="s", fingerprint=f"f{i}",
                                 severity="LOW", summary=str(i)))
        assert verify_threat_chain() is None

    def test_chain_detects_tamper(self, store):
        for i in range(3):
            record_threat(Threat(source="s", fingerprint=f"f{i}",
                                 severity="LOW", summary=str(i)))
        # Mutate row 2 directly through SQLite, bypassing the chain.
        conn = sqlite3.connect(str(ti.DB_PATH))
        try:
            conn.execute("UPDATE threats SET summary='tampered' WHERE id=2")
            conn.commit()
        finally:
            conn.close()
        assert verify_threat_chain() == 2


# ── Registry ───────────────────────────────────────────────────────────────

class _FakeSource(IntelSource):
    def __init__(self, name, threats):
        self._name = name
        self._threats = threats
        self.call_count = 0

    def name(self): return self._name
    def fetch(self):
        self.call_count += 1
        return list(self._threats)


class TestRegistry:
    def test_register_source_appends(self, store):
        s = _FakeSource("a", [])
        register_source(s)
        assert ti.registered_sources() == [s]

    def test_register_source_replaces_by_name(self, store):
        s1 = _FakeSource("dup", [])
        s2 = _FakeSource("dup", [])
        register_source(s1)
        register_source(s2)
        names = [x.name() for x in ti.registered_sources()]
        assert names == ["dup"]
        assert ti.registered_sources()[0] is s2

    def test_register_mitigator_dedupes(self, store):
        def m(threat): return None
        register_mitigator(m)
        register_mitigator(m)
        assert ti.registered_mitigators() == [m]


# ── scan_all ───────────────────────────────────────────────────────────────

class TestScanAll:
    def test_no_sources_returns_empty(self, store):
        r = scan_all()
        assert r.sources_run == 0
        assert r.new_threats == []

    def test_runs_source_and_inserts_new(self, store):
        s = _FakeSource("a", [
            Threat(source="a", fingerprint="f1",
                   severity="HIGH", summary="x"),
            Threat(source="a", fingerprint="f2",
                   severity="LOW", summary="y"),
        ])
        register_source(s)
        r = scan_all()
        assert r.sources_run == 1
        assert r.threats_seen == 2
        assert {t.fingerprint for t in r.new_threats} == {"f1", "f2"}

    def test_dedup_prevents_re_emission(self, store):
        s = _FakeSource("a", [
            Threat(source="a", fingerprint="f1",
                   severity="LOW", summary="x"),
        ])
        register_source(s)
        scan_all()  # first emits
        r2 = scan_all()  # second sees nothing new
        assert r2.threats_seen == 1
        assert r2.new_threats == []

    def test_mitigators_called_for_new_only(self, store):
        s = _FakeSource("a", [
            Threat(source="a", fingerprint="f1",
                   severity="HIGH", summary="x"),
        ])
        seen = []

        def mit(t):
            seen.append(t.fingerprint)
            return f"acknowledged {t.fingerprint}"

        register_source(s)
        register_mitigator(mit)
        scan_all()
        scan_all()  # second scan: dedup, mitigator NOT called again
        assert seen == ["f1"]

    def test_source_failure_isolated(self, store):
        class Bad(IntelSource):
            def name(self): return "bad"
            def fetch(self): raise RuntimeError("network down")

        good = _FakeSource("good", [
            Threat(source="good", fingerprint="g1",
                   severity="LOW", summary="ok"),
        ])
        register_source(Bad())
        register_source(good)
        r = scan_all()
        assert r.sources_run == 2
        assert any("bad" in e for e in r.errors)
        assert {t.fingerprint for t in r.new_threats} == {"g1"}

    def test_mitigator_failure_isolated(self, store):
        s = _FakeSource("a", [
            Threat(source="a", fingerprint="f1",
                   severity="HIGH", summary="x"),
        ])

        def boom(t): raise RuntimeError("mit broke")

        register_source(s)
        register_mitigator(boom)
        r = scan_all()
        # Threat still recorded; mitigator failure surfaced as error.
        assert {t.fingerprint for t in r.new_threats} == {"f1"}
        assert any("boom" in e for e in r.errors)
