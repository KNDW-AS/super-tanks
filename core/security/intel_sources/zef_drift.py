"""
core/security/intel_sources/zef_drift.py
==========================================
ZEF self-test drift detector.

Periodically re-runs the ZEF redteam corpus against the live filter
and emits a Threat when the measured block_rate / FPR / warn_rate
drift below the published floors.

Why this matters: an upstream model swap, a regex edit, or a
dependency upgrade can silently change ZEF behaviour. The CI gate in
tests/security/redteam/ catches it at PR time, but it does NOT catch:

  - production-only configuration that disables a pattern
  - a runtime environment where a regex compiles differently
  - data-poisoning effects we'd see only after the fact

Running the same measurement on the live process fingerprints the
filter as it actually behaves NOW, and produces a Threat if it
regresses. The threat is severity-graded by how far below the floor
we are.

The fingerprint is `zef-drift-YYYYMMDD-{metric}` so a fresh slip
generates a fresh threat, but two consecutive scans on the same UTC
day for the same metric are deduped by the store.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List

from core.security.threat_intel import (
    IntelSource, Threat,
    SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL,
)

logger = logging.getLogger("super_tanks.threat_intel.zef_drift")


class ZEFDriftSource(IntelSource):
    def name(self) -> str:
        return "zef_drift"

    def fetch(self) -> List[Threat]:
        try:
            # Reuse the CLI's measurement — same code path as the
            # operator-facing baseline tool, so drift detected here is
            # what the operator would also see by hand.
            from scripts.zef_baseline import _measure
        except Exception as exc:
            logger.error("[ZEF_DRIFT] could not import _measure: %s", exc)
            return []
        try:
            m = _measure()
        except Exception as exc:
            logger.error("[ZEF_DRIFT] measurement failed: %s", exc)
            return []

        today = datetime.now(timezone.utc).date().isoformat()
        threats: List[Threat] = []

        if not m["block_rate_pass"]:
            margin = m["block_rate_floor"] - m["block_rate"]
            sev = (SEVERITY_CRITICAL if margin >= 0.10
                   else SEVERITY_HIGH if margin >= 0.03
                   else SEVERITY_MEDIUM)
            threats.append(Threat(
                source="zef_drift",
                fingerprint=f"zef-drift-{today}-block_rate",
                severity=sev,
                summary=(f"ZEF block_rate {m['block_rate']:.1%} below floor "
                         f"{m['block_rate_floor']:.0%} "
                         f"({m['block_count'][0]}/{m['block_count'][1]} blocked)"),
                details={"metric": "block_rate", **_metric_payload(m)},
            ))

        if not m["false_positive_pass"]:
            sev = SEVERITY_HIGH  # FPR regression is operator-blocking
            threats.append(Threat(
                source="zef_drift",
                fingerprint=f"zef-drift-{today}-false_positive_rate",
                severity=sev,
                summary=(f"ZEF false_positive_rate {m['false_positive_rate']:.1%} "
                         f"above ceiling {m['false_positive_ceiling']:.0%} "
                         f"({m['false_positive_count'][0]}/"
                         f"{m['false_positive_count'][1]} clean misclassified)"),
                details={"metric": "false_positive_rate",
                         **_metric_payload(m)},
            ))

        if not m["warn_rate_pass"]:
            threats.append(Threat(
                source="zef_drift",
                fingerprint=f"zef-drift-{today}-warn_rate",
                severity=SEVERITY_MEDIUM,
                summary=(f"ZEF warn_rate {m['warn_rate']:.1%} below floor "
                         f"{m['warn_rate_floor']:.0%} — low-confidence "
                         f"patterns going undetected"),
                details={"metric": "warn_rate", **_metric_payload(m)},
            ))

        return threats


def _metric_payload(m: dict) -> dict:
    """Strip non-JSON-friendly bits, keep the numbers operators want."""
    return {
        "block_rate": m["block_rate"],
        "block_rate_floor": m["block_rate_floor"],
        "false_positive_rate": m["false_positive_rate"],
        "false_positive_ceiling": m["false_positive_ceiling"],
        "warn_rate": m["warn_rate"],
        "warn_rate_floor": m["warn_rate_floor"],
    }
