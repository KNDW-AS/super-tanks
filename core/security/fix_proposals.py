"""
core/security/fix_proposals.py
================================
Fix proposals — Zeph's "ready-to-apply" patches for the operator.

When Zeph identifies a threat that he cannot or should not auto-act on
(typically a CVE in a dependency you actually use), he writes a
structured fix proposal to disk. The operator can:

  - inspect:  python -m scripts.apply_proposed_fix --list
              python -m scripts.apply_proposed_fix --show <id>
  - apply:    python -m scripts.apply_proposed_fix --apply <id>
  - reject:   python -m scripts.apply_proposed_fix --reject <id>

Or, with the env var ST_ZEPH_AUTO_APPLY_DEPS=1, Zeph applies the
proposal himself after running the post-upgrade verification step.

Why proposals instead of direct upgrades by default? pip install
modifies the live process environment, can hang, can pull in
incompatible transitive deps, or can introduce subtle behavioural
changes that fail open. The default keeps the human in the loop;
the opt-in trusts the operator's risk appetite.

A proposal contains everything needed to apply OR reject:

  id              uuid
  proposed_at     ISO-8601
  threat          source + fingerprint of the originating Threat
  kind            "dep_upgrade" today; future kinds OK (e.g. config_patch)
  package         name of the affected PyPI package
  current_version current pin in requirements.txt
  target_version  the version Zeph wants to bump to
  requirements_diff   unified diff of requirements.txt
  reason          short Norwegian explanation
  apply_command   the actual shell command that applies the change
  rollback_command counter-command to undo
  status          "proposed" | "applied" | "rejected" | "failed"
  applied_at, applied_by   audit trail when status flips

Proposals are stored in `data/proposed_fixes/<id>.json`. The directory
is per-deployment; back up alongside data/.
"""

from __future__ import annotations

import difflib
import json
import logging
import os
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("super_tanks.fix_proposals")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
PROPOSALS_DIR = _PROJECT_ROOT / "data" / "proposed_fixes"
REQUIREMENTS_FILE = _PROJECT_ROOT / "requirements.txt"

STATUS_PROPOSED = "proposed"
STATUS_APPLIED = "applied"
STATUS_REJECTED = "rejected"
STATUS_FAILED = "failed"


@dataclass
class FixProposal:
    id: str
    proposed_at: str
    threat_source: str
    threat_fingerprint: str
    kind: str
    package: str
    current_version: str
    target_version: str
    requirements_diff: str
    reason: str
    apply_command: str
    rollback_command: str
    status: str = STATUS_PROPOSED
    applied_at: Optional[str] = None
    applied_by: Optional[str] = None
    apply_log: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ── requirements.txt parsing ──────────────────────────────────────────────

_PIN_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.+\-]+)")


def _read_requirements() -> List[str]:
    if not REQUIREMENTS_FILE.exists():
        return []
    return REQUIREMENTS_FILE.read_text().splitlines(keepends=True)


def find_pinned_version(package: str) -> Optional[str]:
    """Return the currently pinned version for `package` in
    requirements.txt, or None if it's not pinned (or the file is
    missing). Comparison is case-insensitive on package name; PEP-503
    name normalisation is applied (- and _ treated equivalently).
    """
    norm_target = package.replace("_", "-").lower()
    for line in _read_requirements():
        m = _PIN_RE.match(line)
        if not m:
            continue
        if m.group(1).replace("_", "-").lower() == norm_target:
            return m.group(2)
    return None


def _build_requirements_diff(package: str, current: str, target: str) -> str:
    """Generate a unified diff that updates the pin for `package`."""
    old_lines = _read_requirements()
    new_lines: List[str] = []
    norm_target = package.replace("_", "-").lower()
    for line in old_lines:
        m = _PIN_RE.match(line)
        if m and m.group(1).replace("_", "-").lower() == norm_target:
            # Preserve trailing comments / whitespace.
            stripped_eol = "\n" if line.endswith("\n") else ""
            new_lines.append(f"{m.group(1)}=={target}{stripped_eol}")
        else:
            new_lines.append(line)
    diff = "".join(difflib.unified_diff(
        old_lines, new_lines,
        fromfile="requirements.txt (current)",
        tofile=f"requirements.txt (after upgrading {package} {current}→{target})",
        lineterm="",
    ))
    return diff


# ── Storage ───────────────────────────────────────────────────────────────

def _path_for(proposal_id: str) -> Path:
    return PROPOSALS_DIR / f"{proposal_id}.json"


def _ensure_dir() -> None:
    PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)


def save(proposal: FixProposal) -> Path:
    _ensure_dir()
    path = _path_for(proposal.id)
    path.write_text(json.dumps(proposal.to_dict(), indent=2,
                               ensure_ascii=False))
    return path


def load(proposal_id: str) -> Optional[FixProposal]:
    path = _path_for(proposal_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        return FixProposal(**data)
    except Exception as exc:
        logger.error("[FIX] failed to load proposal %s: %s",
                     proposal_id, exc)
        return None


def list_all() -> List[FixProposal]:
    if not PROPOSALS_DIR.exists():
        return []
    out: List[FixProposal] = []
    for path in sorted(PROPOSALS_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text())
            out.append(FixProposal(**data))
        except Exception as exc:
            logger.warning("[FIX] skipping malformed %s: %s", path.name, exc)
    return out


# ── Construction ──────────────────────────────────────────────────────────

def propose_dep_upgrade(
    *,
    threat_source: str,
    threat_fingerprint: str,
    package: str,
    target_version: str,
    reason: str,
) -> Optional[FixProposal]:
    """Materialise a fix proposal for a dependency upgrade. Returns
    None if the package is not currently pinned (we only manage
    pinned deps to avoid silently changing transitive resolution).
    """
    current = find_pinned_version(package)
    if current is None:
        logger.warning("[FIX] cannot propose upgrade for unpinned package %r",
                       package)
        return None
    if current == target_version:
        logger.info("[FIX] %r already at %s, no proposal needed",
                    package, target_version)
        return None
    diff = _build_requirements_diff(package, current, target_version)
    proposal = FixProposal(
        id=str(uuid.uuid4()),
        proposed_at=datetime.now(timezone.utc).isoformat(),
        threat_source=threat_source,
        threat_fingerprint=threat_fingerprint,
        kind="dep_upgrade",
        package=package,
        current_version=current,
        target_version=target_version,
        requirements_diff=diff,
        reason=reason,
        apply_command=f"pip install --upgrade {package}=={target_version}",
        rollback_command=f"pip install {package}=={current}",
    )
    save(proposal)
    logger.info("[FIX] proposed %s: %s %s→%s (id=%s)",
                proposal.kind, package, current, target_version, proposal.id)
    return proposal


# ── Apply / reject ───────────────────────────────────────────────────────

def auto_apply_enabled() -> bool:
    """True iff the operator has opted into Zeph applying dep
    upgrades autonomously. Default OFF."""
    return os.environ.get("ST_ZEPH_AUTO_APPLY_DEPS", "0") in ("1", "true", "yes")


def mark_applied(proposal_id: str, *, by: str, log: str = "") -> Optional[FixProposal]:
    p = load(proposal_id)
    if p is None:
        return None
    p.status = STATUS_APPLIED
    p.applied_at = datetime.now(timezone.utc).isoformat()
    p.applied_by = by
    p.apply_log = log
    save(p)
    return p


def mark_rejected(proposal_id: str, *, by: str,
                  reason: str = "") -> Optional[FixProposal]:
    p = load(proposal_id)
    if p is None:
        return None
    p.status = STATUS_REJECTED
    p.applied_at = datetime.now(timezone.utc).isoformat()
    p.applied_by = by
    p.apply_log = reason
    save(p)
    return p


def mark_failed(proposal_id: str, *, by: str,
                error: str) -> Optional[FixProposal]:
    p = load(proposal_id)
    if p is None:
        return None
    p.status = STATUS_FAILED
    p.applied_at = datetime.now(timezone.utc).isoformat()
    p.applied_by = by
    p.apply_log = error
    save(p)
    return p


def write_requirements_with_pin(package: str, target_version: str) -> str:
    """Update requirements.txt in place to set `package` to
    `target_version`. Returns the new file contents for caller
    inspection. Caller is responsible for backing up the file
    beforehand if rollback is desired."""
    new_lines: List[str] = []
    norm_target = package.replace("_", "-").lower()
    for line in _read_requirements():
        m = _PIN_RE.match(line)
        if m and m.group(1).replace("_", "-").lower() == norm_target:
            stripped_eol = "\n" if line.endswith("\n") else ""
            new_lines.append(f"{m.group(1)}=={target_version}{stripped_eol}")
        else:
            new_lines.append(line)
    new_text = "".join(new_lines)
    REQUIREMENTS_FILE.write_text(new_text)
    return new_text
