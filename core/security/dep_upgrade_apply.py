"""
core/security/dep_upgrade_apply.py
====================================
Apply a dependency-upgrade FixProposal end-to-end with rollback.

Pipeline:
  1. Snapshot requirements.txt to data/proposed_fixes/<id>.requirements.bak
  2. Run `pip install --dry-run` to check resolvability without
     touching the live env
  3. If dry-run passes: write the new pin to requirements.txt + run
     `pip install` for real
  4. Run a smoke verification (light pytest subset)
  5. On any failure: restore the backup + run rollback pip install,
     mark the proposal failed
  6. On success: mark the proposal applied

The whole thing is intentionally synchronous and audited via the
proposal status field. The caller (Zeph's auto-apply path or the
operator CLI) gets a (success, log) tuple back.

Side effects: this module IS allowed to invoke pip and write to
requirements.txt — that's the whole point. It is gated by:
  - The operator opting in via ST_ZEPH_AUTO_APPLY_DEPS (for Zeph
    auto-path), OR
  - The operator running scripts/apply_proposed_fix --apply explicitly.

Either way the action is recorded on the FixProposal and reachable
via list_all() for audit.
"""

from __future__ import annotations

import logging
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Tuple

from core.security.fix_proposals import (
    FixProposal, REQUIREMENTS_FILE,
    mark_applied, mark_failed, write_requirements_with_pin,
)

logger = logging.getLogger("super_tanks.dep_upgrade")

PIP_TIMEOUT_SEC = 180
VERIFY_TIMEOUT_SEC = 240


def _backup_path(proposal_id: str) -> Path:
    return REQUIREMENTS_FILE.parent / "data" / "proposed_fixes" / f"{proposal_id}.requirements.bak"


def _snapshot_requirements(proposal: FixProposal) -> Path:
    backup = _backup_path(proposal.id)
    backup.parent.mkdir(parents=True, exist_ok=True)
    if REQUIREMENTS_FILE.exists():
        shutil.copy2(REQUIREMENTS_FILE, backup)
    return backup


def _run(cmd: list, timeout: int) -> Tuple[int, str]:
    """Run a subprocess. Returns (returncode, combined_output)."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout}s running {shlex.join(cmd)}"
    except FileNotFoundError as exc:
        return 127, f"command not found: {exc}"
    except Exception as exc:
        return 1, f"subprocess failed: {exc}"


def _verify_after_install() -> Tuple[bool, str]:
    """Run a quick smoke check after the upgrade.

    We use the redteam corpus + the threat-intel core test as a
    cheap "does the security surface still work" gate. The full
    pytest suite is too slow to run in the apply path; the operator
    can re-run it themselves before pushing to prod.
    """
    cmd = [
        "python", "-m", "pytest", "-x", "-q", "--no-cov",
        "tests/security/redteam/",
        "tests/test_security/test_threat_intel.py",
    ]
    rc, out = _run(cmd, VERIFY_TIMEOUT_SEC)
    if rc == 0:
        return True, out[-2000:]
    return False, out[-2000:]


def apply_proposal(proposal: FixProposal, *,
                   by: str = "operator") -> Tuple[bool, str]:
    """End-to-end apply with rollback. Returns (success, log).

    The proposal's status field is updated regardless of outcome
    (applied/failed). Mutates requirements.txt and the pip env.
    """
    log_chunks: list = [f"[apply] proposal={proposal.id} pkg={proposal.package} "
                        f"{proposal.current_version}→{proposal.target_version}"]
    backup = _snapshot_requirements(proposal)
    log_chunks.append(f"[backup] requirements.txt → {backup}")

    # Step 1: dry-run resolvability check.
    dry = ["pip", "install", "--dry-run",
           f"{proposal.package}=={proposal.target_version}"]
    rc, out = _run(dry, PIP_TIMEOUT_SEC)
    log_chunks.append(f"[dry-run] rc={rc}\n{out[-1500:]}")
    if rc != 0:
        log = "\n".join(log_chunks)
        mark_failed(proposal.id, by=by, error=log)
        return False, log

    # Step 2: write requirements + real install.
    try:
        write_requirements_with_pin(proposal.package, proposal.target_version)
    except Exception as exc:
        log_chunks.append(f"[write-requirements] FAILED: {exc}")
        log = "\n".join(log_chunks)
        mark_failed(proposal.id, by=by, error=log)
        return False, log
    log_chunks.append(f"[write-requirements] pinned {proposal.package}=="
                      f"{proposal.target_version}")

    install = ["pip", "install",
               f"{proposal.package}=={proposal.target_version}"]
    rc, out = _run(install, PIP_TIMEOUT_SEC)
    log_chunks.append(f"[pip-install] rc={rc}\n{out[-1500:]}")
    if rc != 0:
        _rollback(proposal, backup, log_chunks)
        log = "\n".join(log_chunks)
        mark_failed(proposal.id, by=by, error=log)
        return False, log

    # Step 3: verify.
    ok, vout = _verify_after_install()
    log_chunks.append(f"[verify] ok={ok}\n{vout}")
    if not ok:
        _rollback(proposal, backup, log_chunks)
        log = "\n".join(log_chunks)
        mark_failed(proposal.id, by=by, error=log)
        return False, log

    log = "\n".join(log_chunks)
    mark_applied(proposal.id, by=by, log=log)
    return True, log


def _rollback(proposal: FixProposal, backup: Path, log_chunks: list) -> None:
    """Restore requirements.txt + reinstall the original version."""
    if backup.exists():
        try:
            shutil.copy2(backup, REQUIREMENTS_FILE)
            log_chunks.append("[rollback] requirements.txt restored")
        except Exception as exc:
            log_chunks.append(f"[rollback] requirements restore FAILED: {exc}")
    rb = ["pip", "install",
          f"{proposal.package}=={proposal.current_version}"]
    rc, out = _run(rb, PIP_TIMEOUT_SEC)
    log_chunks.append(f"[rollback-pip] rc={rc}\n{out[-1000:]}")
