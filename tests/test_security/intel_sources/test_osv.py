"""
Tests for core/security/intel_sources/osv.py.

Network is mocked at the _OSVHTTP boundary; no live calls.
"""


from core.security.intel_sources.osv import (
    OSVDepSource, _osv_severity_to_threat,
    SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL,
)


class _FakeHTTP:
    def __init__(self, batch_payload, vuln_details=None):
        self.batch_payload = batch_payload
        self.vuln_details = vuln_details or {}
        self.batch_calls = 0
        self.vuln_calls = []

    def post_batch(self, queries, timeout=None):
        self.batch_calls += 1
        self.captured_queries = queries
        return self.batch_payload

    def get_vuln(self, vuln_id, timeout=None):
        self.vuln_calls.append(vuln_id)
        return self.vuln_details.get(vuln_id)


def _packages():
    return [("requests", "2.30.0"), ("flask", "2.2.0")]


# ── Severity mapping ───────────────────────────────────────────────────────

class TestSeverityMap:
    def test_no_severity_defaults_medium(self):
        assert _osv_severity_to_threat(None) == SEVERITY_MEDIUM
        assert _osv_severity_to_threat([]) == SEVERITY_MEDIUM

    def test_critical_score(self):
        assert _osv_severity_to_threat([{"score": "9.5"}]) == SEVERITY_CRITICAL

    def test_high_score(self):
        assert _osv_severity_to_threat([{"score": "7.5"}]) == SEVERITY_HIGH

    def test_medium_score(self):
        assert _osv_severity_to_threat([{"score": "5.0"}]) == SEVERITY_MEDIUM

    def test_low_score(self):
        assert _osv_severity_to_threat([{"score": "2.0"}]) == SEVERITY_LOW


# ── fetch ──────────────────────────────────────────────────────────────────

class TestFetch:
    def test_no_packages_returns_empty(self):
        s = OSVDepSource(http=_FakeHTTP({"results": []}),
                         packages_provider=lambda: [])
        assert s.fetch() == []

    def test_no_vulns_returns_empty(self):
        http = _FakeHTTP({"results": [{"vulns": []}, {"vulns": []}]})
        s = OSVDepSource(http=http, packages_provider=_packages)
        assert s.fetch() == []
        assert http.batch_calls == 1

    def test_vuln_becomes_threat(self):
        http = _FakeHTTP(
            batch_payload={"results": [
                {"vulns": [{"id": "CVE-2025-1"}]},
                {"vulns": []},
            ]},
            vuln_details={
                "CVE-2025-1": {
                    "summary": "RCE in requests",
                    "severity": [{"score": "9.8"}],
                    "aliases": ["GHSA-xxx-yyyy-zzzz"],
                    "affected": [{
                        "package": {"name": "requests", "ecosystem": "PyPI"},
                        "ranges": [{"events": [
                            {"introduced": "0"},
                            {"fixed": "2.32.5"},
                        ]}],
                    }],
                },
            },
        )
        s = OSVDepSource(http=http, packages_provider=_packages)
        threats = s.fetch()
        assert len(threats) == 1
        t = threats[0]
        assert t.fingerprint == "CVE-2025-1"
        assert t.severity == SEVERITY_CRITICAL
        assert "RCE in requests" in t.summary
        assert t.details["package"] == "requests"
        assert t.details["version"] == "2.30.0"
        assert t.details["aliases"] == ["GHSA-xxx-yyyy-zzzz"]
        assert t.details["fixed_versions"] == ["2.32.5"]

    def test_no_affected_block_means_empty_fixed_versions(self):
        http = _FakeHTTP(
            batch_payload={"results": [
                {"vulns": [{"id": "CVE-2025-2"}]},
                {"vulns": []},
            ]},
            vuln_details={"CVE-2025-2": {"summary": "x"}},
        )
        s = OSVDepSource(http=http, packages_provider=_packages)
        threats = s.fetch()
        assert threats[0].details["fixed_versions"] == []

    def test_enrich_failure_still_emits_threat(self):
        class FlakyHTTP(_FakeHTTP):
            def get_vuln(self, vuln_id, timeout=None):
                raise RuntimeError("temporary fail")

        http = FlakyHTTP(batch_payload={"results": [
            {"vulns": [{"id": "CVE-2025-2"}]},
            {"vulns": []},
        ]})
        s = OSVDepSource(http=http, packages_provider=_packages)
        threats = s.fetch()
        assert len(threats) == 1
        # Without enrichment, severity defaults MEDIUM and summary is
        # synthesised from package name.
        assert threats[0].severity == "MEDIUM"
        assert "requests==2.30.0" in threats[0].summary

    def test_batch_failure_returns_empty(self):
        class DeadHTTP(_FakeHTTP):
            def post_batch(self, queries, timeout=None):
                raise RuntimeError("dns failure")

        s = OSVDepSource(http=DeadHTTP({}), packages_provider=_packages)
        assert s.fetch() == []

    def test_packages_provider_failure_returns_empty(self):
        def boom(): raise RuntimeError("metadata busted")
        s = OSVDepSource(http=_FakeHTTP({}), packages_provider=boom)
        assert s.fetch() == []

    def test_max_packages_caps_query(self):
        many = [(f"pkg{i}", "1.0") for i in range(500)]
        http = _FakeHTTP({"results": [{"vulns": []}] * 200})
        s = OSVDepSource(http=http, packages_provider=lambda: many,
                         max_packages=200)
        s.fetch()
        assert len(http.captured_queries) == 200
