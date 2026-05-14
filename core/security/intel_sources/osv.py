"""
core/security/intel_sources/osv.py
====================================
OSV.dev dependency-CVE source.

Queries https://api.osv.dev/v1/querybatch with the project's installed
PyPI packages and converts each returned advisory into a Threat. OSV
is Google's open vulnerability database — it aggregates CVE, GHSA,
PYSEC and friends, no auth required, JSON in/out, stable.

Network failures, malformed responses, and per-package errors are
caught inside fetch() so the triage loop never sees an exception. A
silent failure is logged loudly but does not block other intel
sources from running.

The fingerprint is the OSV advisory id (e.g. "GHSA-xxx-yyyy-zzzz" or
"CVE-2025-1234"), so re-running the scan is idempotent.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from core.security.threat_intel import (
    IntelSource, Threat,
    SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL,
)

logger = logging.getLogger("super_tanks.threat_intel.osv")

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
DEFAULT_TIMEOUT_SEC = 8


def _installed_pypi_packages() -> List[Tuple[str, str]]:
    """Return [(name, version)] for the current process's installed
    distributions. Best-effort — importlib.metadata is stdlib in 3.8+.
    """
    try:
        from importlib import metadata as _md
    except Exception:
        return []
    out: List[Tuple[str, str]] = []
    for dist in _md.distributions():
        name = dist.metadata.get("Name") if dist.metadata else None
        version = getattr(dist, "version", None)
        if name and version:
            out.append((str(name).strip().lower(), str(version)))
    # Dedup and sort for stability — the OSV API doesn't care, but
    # tests are easier with a deterministic ordering.
    return sorted(set(out))


def _osv_severity_to_threat(osv_sev: Optional[List[Dict[str, Any]]]) -> str:
    """Best-effort map from OSV severity records to our 4-level scale.

    OSV uses CVSS strings; we want one of LOW/MEDIUM/HIGH/CRITICAL.
    When OSV has no severity at all, default to MEDIUM — unknown is
    not LOW, because we don't want to silently downgrade an
    advisory we couldn't fully parse.
    """
    if not osv_sev:
        return SEVERITY_MEDIUM
    # Try to find a CVSS_V3 score.
    score: Optional[float] = None
    for entry in osv_sev:
        if not isinstance(entry, dict):
            continue
        s = entry.get("score")
        if not isinstance(s, str):
            continue
        # Score format: "CVSS:3.x/AV:.../I:H/A:H" or just "9.8"
        try:
            score = float(s)
            break
        except ValueError:
            # Pull the base score from a CVSS string.
            for chunk in s.split("/"):
                if chunk.startswith(("CVSS:", "AV:", "AC:", "PR:", "UI:",
                                     "S:", "C:", "I:", "A:")):
                    continue
                try:
                    score = float(chunk)
                    break
                except ValueError:
                    continue
        if score is not None:
            break
    if score is None:
        return SEVERITY_MEDIUM
    if score >= 9.0:
        return SEVERITY_CRITICAL
    if score >= 7.0:
        return SEVERITY_HIGH
    if score >= 4.0:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW


def _extract_fixed_versions(detail: Dict[str, Any], package: str) -> List[str]:
    """Pull `fixed` versions for `package` out of an OSV detail blob.

    OSV puts fixes inside `affected[*].ranges[*].events`, with each
    event being either {"introduced": "x"} or {"fixed": "x"}. Reading
    the structure correctly is what gives Zeph a deterministic upgrade
    target instead of a guess.
    """
    norm = package.replace("_", "-").lower()
    out: List[str] = []
    for aff in (detail.get("affected") or []):
        if not isinstance(aff, dict):
            continue
        pkg = (aff.get("package") or {}).get("name", "")
        if pkg.replace("_", "-").lower() != norm:
            continue
        for r in (aff.get("ranges") or []):
            for ev in (r.get("events") or []):
                fixed = ev.get("fixed") if isinstance(ev, dict) else None
                if fixed:
                    out.append(str(fixed))
    # Dedup, preserve order.
    seen, uniq = set(), []
    for v in out:
        if v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq


class _OSVHTTP:
    """Indirection point for the network call so tests can stub it
    without monkeypatching urllib globally."""

    def post_batch(self, queries: List[Dict[str, Any]],
                   timeout: float = DEFAULT_TIMEOUT_SEC) -> Dict[str, Any]:
        body = json.dumps({"queries": queries}).encode("utf-8")
        req = urllib.request.Request(
            OSV_BATCH_URL, data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read()
        return json.loads(payload.decode("utf-8"))

    def get_vuln(self, vuln_id: str,
                 timeout: float = DEFAULT_TIMEOUT_SEC) -> Optional[Dict[str, Any]]:
        url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = resp.read()
            return json.loads(payload.decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise


class OSVDepSource(IntelSource):
    """Default OSV source. Inject a fake `_http` in tests."""

    def __init__(self, http: Optional[_OSVHTTP] = None,
                 packages_provider=None,
                 max_packages: int = 200):
        self._http = http or _OSVHTTP()
        self._packages_provider = packages_provider or _installed_pypi_packages
        self._max_packages = max_packages

    def name(self) -> str:
        return "osv"

    def fetch(self) -> List[Threat]:
        try:
            packages = self._packages_provider()
        except Exception as exc:
            logger.error("[OSV] could not enumerate packages: %s", exc)
            return []
        if not packages:
            return []
        # Cap the batch — OSV accepts up to 1000 per call but our
        # process-installed list is usually < 200. Bigger than that
        # almost certainly means we're scanning the host's site-packages
        # too aggressively; truncate to avoid surprise costs.
        packages = packages[: self._max_packages]
        queries = [
            {"package": {"name": name, "ecosystem": "PyPI"},
             "version": version}
            for name, version in packages
        ]
        try:
            payload = self._http.post_batch(queries)
        except Exception as exc:
            logger.error("[OSV] batch query failed: %s", exc)
            return []

        threats: List[Threat] = []
        results = payload.get("results", [])
        for (name, version), result in zip(packages, results):
            vulns = (result or {}).get("vulns") or []
            for v in vulns:
                vuln_id = v.get("id")
                if not vuln_id:
                    continue
                # Try to enrich with severity / summary via the per-id
                # endpoint. If that fails we still produce a Threat
                # — losing severity is OK, dropping the threat is not.
                summary = ""
                severity = SEVERITY_MEDIUM
                aliases: List[str] = []
                fixed_versions: List[str] = []
                try:
                    detail = self._http.get_vuln(vuln_id)
                    if detail:
                        summary = (detail.get("summary")
                                   or detail.get("details", "")[:200]
                                   or "")
                        severity = _osv_severity_to_threat(detail.get("severity"))
                        aliases = list(detail.get("aliases") or [])
                        fixed_versions = _extract_fixed_versions(detail, name)
                except Exception as exc:
                    logger.warning("[OSV] enrich %s failed: %s", vuln_id, exc)

                threats.append(Threat(
                    source="osv",
                    fingerprint=vuln_id,
                    severity=severity,
                    summary=(summary or
                             f"{vuln_id}: vulnerability in {name}=={version}"),
                    details={
                        "package": name,
                        "version": version,
                        "vuln_id": vuln_id,
                        "aliases": aliases,
                        "fixed_versions": fixed_versions,
                    },
                ))
        return threats
