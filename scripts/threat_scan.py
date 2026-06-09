"""
scripts/threat_scan.py
=======================
Self-healing scan orchestrator.

One pass:
  1. Run every registered threat-intel source (OSV CVE check,
     ZEF drift detector, etc.) — closes holes the OUTSIDE world
     has discovered before they bite us locally.
  2. Run the active threat monitor — flags attacks in progress
     against THIS deployment by scanning recent audit / dispatch
     logs and tightening defenses.
  3. Print a digest of new findings + actions for cron / log
     scrapers / Telegram.

Cron usage:
    */15 * * * * cd /opt/super-tanks && python -m scripts.threat_scan

Exit codes:
    0   scan completed (may have found and acted on threats)
    1   scan crashed unrecoverably (rare — almost everything is
        caught and reported as an error inside the digest)
"""

from __future__ import annotations

import argparse
import json
import logging
import sys


def _build_default_sources() -> None:
    """Register the production set of intel sources. Idempotent —
    register_source replaces by name, so calling this from both the
    bootstrap and the CLI is fine."""
    from core.security import threat_intel
    from core.security.intel_sources.osv import OSVDepSource
    from core.security.intel_sources.zef_drift import ZEFDriftSource
    from core.security.intel_sources.ha_health import HAHealthSource
    threat_intel.register_source(OSVDepSource())
    threat_intel.register_source(ZEFDriftSource())
    threat_intel.register_source(HAHealthSource())


def _build_default_mitigators() -> None:
    """Register conservative default mitigators. Right now the
    threat-intel side only logs and notifies — the active
    threat_monitor handles trust drops / LOCKDOWN / SAFE_MODE."""
    from core.security import threat_intel

    def _log_high_severity(threat) -> str:
        if threat.severity in ("HIGH", "CRITICAL"):
            logging.getLogger("threat_scan").warning(
                "[%s] %s: %s", threat.severity, threat.fingerprint,
                threat.summary,
            )
            return f"logged at {threat.severity}"
        return ""

    threat_intel.register_mitigator(_log_high_severity)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="threat_scan",
        description="Run one self-healing scan pass: external "
                    "threat intel + active local monitor.",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Print the digest as JSON (cron / log scrapers).",
    )
    parser.add_argument(
        "--skip-intel", action="store_true",
        help="Skip the external intel sources (offline / fast mode). "
             "Active monitor still runs.",
    )
    parser.add_argument(
        "--skip-monitor", action="store_true",
        help="Skip the active local monitor.",
    )
    parser.add_argument(
        "--zeph", action="store_true",
        help="Run Zeph triage on every new threat after the scan. Auto-acts "
             "on pre-approved templates, proposes the rest. Outputs a "
             "Norwegian brief in addition to the raw digest.",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    digest = {"intel": None, "monitor": None, "zeph": None}
    new_threats: list = []

    if not args.skip_intel:
        from core.security import threat_intel
        _build_default_sources()
        _build_default_mitigators()
        scan = threat_intel.scan_all()
        digest["intel"] = scan.to_dict()
        new_threats.extend(scan.new_threats)

    if not args.skip_monitor:
        from core.security import threat_monitor
        report = threat_monitor.scan_once()
        digest["monitor"] = {
            "window_minutes": report.window_minutes,
            "findings": report.findings,
            "actions_taken": report.actions_taken,
            "errors": report.errors,
        }
        # Hand the monitor's emitted Threats to the triage layer too;
        # otherwise --zeph would only see intel-side findings.
        new_threats.extend(report.emitted_threats)

    if args.zeph and new_threats:
        from core.security import threat_brief
        brief = threat_brief.triage(new_threats)
        digest["zeph"] = {
            "decisions": [{
                "verdict": d.verdict.value,
                "template": d.template_name,
                "rationale": d.rationale,
                "action_note": d.action_note,
                "sanitised": d.sanitised,
                "fingerprint": d.threat.fingerprint,
                "source": d.threat.source,
            } for d in brief.decisions],
            "actions_taken": brief.actions_taken,
            "proposals": brief.proposals,
            "escalations": brief.escalations,
            "errors": brief.errors,
        }

    if args.json:
        print(json.dumps(digest, indent=2, sort_keys=True))
    else:
        print(_format_digest(digest))
        if digest["zeph"] is not None:
            from core.security.threat_brief import (
                BriefReport, format_brief,
            )
            # Re-hydrate a BriefReport for the formatter.
            r = BriefReport(
                actions_taken=digest["zeph"]["actions_taken"],
                proposals=digest["zeph"]["proposals"],
                escalations=digest["zeph"]["escalations"],
                errors=digest["zeph"]["errors"],
            )
            print()
            print(format_brief(r))
    return 0


def _format_digest(digest: dict) -> str:
    lines = ["Self-healing scan digest", ""]
    intel = digest.get("intel")
    if intel:
        lines.append(f"External intel: {intel['sources_run']} sources, "
                     f"{intel['threats_seen']} threats seen, "
                     f"{len(intel['new_threats'])} new")
        for t in intel["new_threats"]:
            lines.append(f"  [{t['severity']}] {t['source']}/"
                         f"{t['fingerprint']}: {t['summary']}")
        for note in intel["mitigation_log"]:
            lines.append(f"  ↳ {note}")
        for err in intel["errors"]:
            lines.append(f"  ! {err}")
    monitor = digest.get("monitor")
    if monitor:
        lines.append("")
        lines.append(f"Active monitor (window {monitor['window_minutes']}min):")
        if not monitor["findings"]:
            lines.append("  no new findings")
        for f in monitor["findings"]:
            lines.append(f"  • {f}")
        for a in monitor["actions_taken"]:
            lines.append(f"  ↳ {a}")
        for err in monitor["errors"]:
            lines.append(f"  ! {err}")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
