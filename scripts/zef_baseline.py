"""
scripts/zef_baseline.py
========================
ZEF tier-baseline CLI.

Runs the redteam corpus against the current ZEF filter implementation
and, on pass, marks the supplied upstream-model fingerprint as
baselined. The persisted baseline is what `set_mode(AUTONOMOUS)` checks
against the live tier (set via ST_UPSTREAM_MODEL or by the LLM client).

Usage
-----
    python -m scripts.zef_baseline --tier claude-mythos-2026-04
    python -m scripts.zef_baseline --tier <name> --report-only

Exit codes
----------
    0   measurements meet floor → baseline written
    1   one or more measurements failed floor → baseline NOT written
    2   bad arguments

Operationally
-------------
Run this whenever the upstream LLM provider ships a new tier. The
output reports:

    block_rate            (must be ≥ MIN_BLOCK_RATE)
    false_positive_rate   (must be ≤ MAX_FALSE_POSITIVE_RATE)
    warn_rate             (must be ≥ MIN_WARN_RATE)

If any miss the floor, the new tier is NOT marked baselined and
AUTONOMOUS will refuse to engage on that tier until a future run
passes (presumably after tightening the filter).

The same constants live in tests/security/redteam/test_zef_redteam.py.
This script imports them directly so the floor cannot drift between
the gate-level CLI and the CI-level pytest assertions.
"""

from __future__ import annotations

import argparse
import logging
import sys

logger = logging.getLogger("zef_baseline")


def _measure() -> dict:
    """Run the corpus and return aggregate measurements."""
    from core.security.zef_injection_filter import scan_message
    from tests.security.redteam.corpus import (
        ATTACK_CASES, WARN_CASES, CLEAN_CASES,
    )
    from tests.security.redteam.test_zef_redteam import (
        MIN_BLOCK_RATE, MAX_FALSE_POSITIVE_RATE, MIN_WARN_RATE,
    )

    def verdict(text: str) -> str:
        return scan_message(text, source="telegram:user").verdict.value.upper()

    blocked = sum(1 for t, _, _ in ATTACK_CASES if verdict(t) == "BLOCK")
    block_rate = blocked / len(ATTACK_CASES) if ATTACK_CASES else 0.0

    expected_pass = [c for c in CLEAN_CASES if c[1] == "PASS"]
    mis_blocked = sum(1 for t, _, _ in expected_pass if verdict(t) == "BLOCK")
    fpr = mis_blocked / len(expected_pass) if expected_pass else 0.0

    warned = sum(1 for t, _, _ in WARN_CASES if verdict(t) in ("WARN", "BLOCK"))
    warn_rate = warned / len(WARN_CASES) if WARN_CASES else 0.0

    return {
        "block_rate": block_rate,
        "block_rate_floor": MIN_BLOCK_RATE,
        "block_rate_pass": block_rate >= MIN_BLOCK_RATE,
        "block_count": (blocked, len(ATTACK_CASES)),

        "false_positive_rate": fpr,
        "false_positive_ceiling": MAX_FALSE_POSITIVE_RATE,
        "false_positive_pass": fpr <= MAX_FALSE_POSITIVE_RATE,
        "false_positive_count": (mis_blocked, len(expected_pass)),

        "warn_rate": warn_rate,
        "warn_rate_floor": MIN_WARN_RATE,
        "warn_rate_pass": warn_rate >= MIN_WARN_RATE,
        "warn_count": (warned, len(WARN_CASES)),
    }


def _report(tier: str, m: dict, baselined: bool, all_pass: bool,
            report_only: bool) -> str:
    def line(label, value, target, op, ok):
        mark = "OK " if ok else "FAIL"
        return f"  [{mark}] {label:<22} {value:>6.1%}  (target {op} {target:.0%})"

    lines = [
        f"ZEF redteam baseline — tier {tier!r}",
        "",
        line("block_rate", m["block_rate"], m["block_rate_floor"], ">=",
             m["block_rate_pass"]),
        f"         {m['block_count'][0]}/{m['block_count'][1]} attacks blocked",
        line("false_positive_rate", m["false_positive_rate"],
             m["false_positive_ceiling"], "<=", m["false_positive_pass"]),
        f"         {m['false_positive_count'][0]}/{m['false_positive_count'][1]} clean misclassified",
        line("warn_rate", m["warn_rate"], m["warn_rate_floor"], ">=",
             m["warn_rate_pass"]),
        f"         {m['warn_count'][0]}/{m['warn_count'][1]} low-confidence cases surfaced",
        "",
    ]
    if baselined:
        lines.append(f"BASELINED: {tier!r} written to disk.")
        lines.append("AUTONOMOUS may now engage against this tier.")
    elif all_pass and report_only:
        lines.append("REPORT-ONLY: floors met, but baseline NOT written by request.")
        lines.append("Re-run without --report-only to mark this tier baselined.")
    else:
        lines.append("REJECTED: one or more floors missed; baseline NOT written.")
        lines.append("Tighten the filter, then re-run before unlocking AUTONOMOUS.")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="zef_baseline",
        description="Measure ZEF redteam corpus and (on pass) mark "
                    "the upstream model tier as baselined.",
    )
    parser.add_argument(
        "--tier", required=True,
        help="Upstream model fingerprint, e.g. 'claude-mythos-2026-04'.",
    )
    parser.add_argument(
        "--report-only", action="store_true",
        help="Print the measurements but do not write the baseline file. "
             "Use to audit the filter without affecting runtime gates.",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    m = _measure()
    all_pass = (m["block_rate_pass"]
                and m["false_positive_pass"]
                and m["warn_rate_pass"])

    baselined = False
    if all_pass and not args.report_only:
        from core.security.super_tanks_mode import mark_zef_baselined
        mark_zef_baselined(args.tier)
        baselined = True

    print(_report(args.tier, m, baselined, all_pass, args.report_only))
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
