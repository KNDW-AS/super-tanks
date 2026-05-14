"""
scripts/apply_proposed_fix.py
==============================
Operator CLI for Zeph's fix proposals.

Zeph writes ready-to-apply fix proposals to data/proposed_fixes/
whenever he can't or shouldn't auto-act (typically a CVE in a
package you actually use). This CLI is how you inspect and apply
them.

    python -m scripts.apply_proposed_fix --list
    python -m scripts.apply_proposed_fix --show <id>
    python -m scripts.apply_proposed_fix --apply <id>
    python -m scripts.apply_proposed_fix --reject <id> --note "reason"

`--apply` runs the full pipeline: dry-run resolvability, snapshot
requirements.txt, pip install, post-upgrade smoke verification,
rollback on any failure. The proposal's status is updated to
applied/failed for the audit trail.
"""

from __future__ import annotations

import argparse
import logging
import sys

logger = logging.getLogger("apply_proposed_fix")


def _print_list() -> int:
    from core.security import fix_proposals
    proposals = fix_proposals.list_all()
    if not proposals:
        print("No proposals on disk.")
        return 0
    for p in proposals:
        print(f"{p.id}  [{p.status:9}]  {p.kind:14}  "
              f"{p.package}=={p.current_version} → {p.target_version}  "
              f"(threat {p.threat_source}/{p.threat_fingerprint})")
    return 0


def _print_show(proposal_id: str) -> int:
    from core.security import fix_proposals
    p = fix_proposals.load(proposal_id)
    if p is None:
        print(f"No proposal with id {proposal_id!r}.", file=sys.stderr)
        return 2
    print(f"Proposal:        {p.id}")
    print(f"Proposed at:     {p.proposed_at}")
    print(f"Status:          {p.status}")
    print(f"Kind:            {p.kind}")
    print(f"Threat:          {p.threat_source}/{p.threat_fingerprint}")
    print(f"Package:         {p.package}")
    print(f"Current version: {p.current_version}")
    print(f"Target version:  {p.target_version}")
    print(f"Reason:          {p.reason}")
    print()
    print(f"Apply:           {p.apply_command}")
    print(f"Rollback:        {p.rollback_command}")
    print()
    print("requirements.txt diff:")
    print(p.requirements_diff or "  (empty)")
    if p.apply_log:
        print()
        print("Apply log:")
        print(p.apply_log)
    return 0


def _do_apply(proposal_id: str) -> int:
    from core.security import fix_proposals
    from core.security import dep_upgrade_apply
    p = fix_proposals.load(proposal_id)
    if p is None:
        print(f"No proposal with id {proposal_id!r}.", file=sys.stderr)
        return 2
    if p.status != fix_proposals.STATUS_PROPOSED:
        print(f"Proposal {proposal_id} already has status {p.status!r}. "
              f"Refusing to re-apply.", file=sys.stderr)
        return 2
    if p.kind != "dep_upgrade":
        print(f"Unsupported proposal kind {p.kind!r}.", file=sys.stderr)
        return 2
    ok, log = dep_upgrade_apply.apply_proposal(p, by="operator")
    print(log)
    if ok:
        print()
        print(f"APPLIED — {p.package} pinned to {p.target_version}.")
        return 0
    print()
    print(f"FAILED — proposal {proposal_id} rolled back. "
          f"See the log above and the proposal file for the audit trail.",
          file=sys.stderr)
    return 1


def _do_reject(proposal_id: str, note: str) -> int:
    from core.security import fix_proposals
    p = fix_proposals.mark_rejected(proposal_id, by="operator", reason=note)
    if p is None:
        print(f"No proposal with id {proposal_id!r}.", file=sys.stderr)
        return 2
    print(f"REJECTED — proposal {p.id} marked as rejected.")
    if note:
        print(f"Reason: {note}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="apply_proposed_fix",
        description="Inspect and apply Zeph's fix proposals.",
    )
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--list", action="store_true",
                   help="List every proposal on disk.")
    g.add_argument("--show", metavar="ID",
                   help="Print full detail for one proposal.")
    g.add_argument("--apply", metavar="ID",
                   help="Apply the proposal end-to-end (dry-run, install, "
                        "verify, rollback on failure).")
    g.add_argument("--reject", metavar="ID",
                   help="Mark the proposal as rejected.")
    parser.add_argument("--note", default="",
                        help="Free-text note (used by --reject).")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if args.list:
        return _print_list()
    if args.show:
        return _print_show(args.show)
    if args.apply:
        return _do_apply(args.apply)
    if args.reject:
        return _do_reject(args.reject, args.note)
    return 2


if __name__ == "__main__":
    sys.exit(main())
