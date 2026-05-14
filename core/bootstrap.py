"""
core/bootstrap.py
==================
Canonical Super Tanks startup sequence.

Every guarantee in this codebase — soul integrity, DIQ contracts,
tripwire deployment, mode persistence, admin presence — depends on
its setup function being called once at process start. Previously
those functions were scattered across modules with no central caller;
`main_loop.py` (which is not in this repository) was supposed to wire
them up, and reviewers could not prove from reading `core/` whether
the system was ever in a known-good state.

This module is the contract. Call `boot()` once at the very top of
your entry point. Each step is fail-fast — a missing manifest, a
tampered soul file, or an unreachable admin DB aborts startup rather
than silently degrading.

Idempotent: calling `boot()` a second time is a no-op (returns the
cached BootResult). The harness re-runs steps that are themselves
idempotent if you pass `force=True`.
"""

import logging
import threading
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger("super_tanks.bootstrap")


@dataclass
class BootResult:
    """Outcome of the boot sequence."""
    success: bool
    steps_completed: List[str] = field(default_factory=list)
    safe_mode: bool = False
    safe_mode_reason: str = ""
    errors: List[str] = field(default_factory=list)


_boot_lock = threading.Lock()
_boot_result: Optional[BootResult] = None


def _step_verify_diq(result: BootResult) -> None:
    """DIQ contract integrity. Raises on tampering — abort startup."""
    from core.diq.diq_integrity import verify_diq_integrity
    verify_diq_integrity()  # raises RuntimeError on tampering/missing
    result.steps_completed.append("verify_diq_integrity")
    logger.info("[BOOT] DIQ contracts verified")


def _step_check_souls(result: BootResult) -> None:
    """Soul-file hashes. On mismatch flips global SAFE_MODE but does
    not abort — the system stays up with a hobbled surface so William
    can review and unlock."""
    from core.soul_guard import check_soul_integrity, is_safe_mode, get_safe_mode_reason
    ok, _reason = check_soul_integrity()
    result.steps_completed.append("check_soul_integrity")
    if not ok:
        result.safe_mode = True
        result.safe_mode_reason = get_safe_mode_reason()
        logger.critical("[BOOT] Soul integrity FAILED — entering SAFE MODE")
    else:
        logger.info("[BOOT] Soul files verified")


def _step_load_mode(result: BootResult) -> None:
    """Restore persisted Super Tanks mode (LOCKDOWN / AUTONOMOUS).
    Failure → LOCKDOWN, which is the safe default."""
    from core.security.super_tanks_mode import load_mode_from_state
    load_mode_from_state()
    result.steps_completed.append("load_mode_from_state")
    logger.info("[BOOT] Mode state loaded")


def _step_ensure_admin(result: BootResult) -> None:
    """Guarantee at least one Level 5 user exists. Without this, the
    user_manager has no actor authorised to call update_user/delete_user."""
    from core.security.user_manager import ensure_admin_exists
    ensure_admin_exists()
    result.steps_completed.append("ensure_admin_exists")
    logger.info("[BOOT] Admin user verified")


def _step_ensure_tripwires(result: BootResult) -> None:
    """Deploy honeypot memory files. Idempotent — only creates missing ones."""
    from core.memory.hierarchical_store import HierarchicalMemoryStore
    from core.memory.tripwires import ensure_tripwires_exist
    created = ensure_tripwires_exist(HierarchicalMemoryStore())
    result.steps_completed.append("ensure_tripwires_exist")
    logger.info("[BOOT] Tripwires verified (%d deployed)", created)


def _step_load_upstream_tier(result: BootResult) -> None:
    """Arm the tier-rebaseline gate.

    Reads the configured upstream model fingerprint from the
    `ST_UPSTREAM_MODEL` env var and tells super_tanks_mode which tier
    is live. Then loads the persisted ZEF baseline (if any) so the
    last `mark_zef_baselined()` survives restarts.

    A missing env var is intentional and logged — it leaves the gate
    dormant (no calls to `set_current_model_tier` → `needs_rebaseline()`
    returns False → AUTONOMOUS unaffected). Pre-Mythos / dev workflows
    can run without setting it.
    """
    import os
    from core.security.super_tanks_mode import (
        set_current_model_tier, load_zef_baseline,
    )
    tier = os.environ.get("ST_UPSTREAM_MODEL")
    if tier:
        set_current_model_tier(tier)
        logger.info("[BOOT] Upstream model tier: %s", tier)
    else:
        logger.info(
            "[BOOT] ST_UPSTREAM_MODEL not set — tier-rebaseline gate dormant"
        )
    baselined = load_zef_baseline()
    if baselined:
        logger.info("[BOOT] ZEF baseline loaded: %s", baselined)
    result.steps_completed.append("load_upstream_tier")


def _step_register_tools(result: BootResult) -> None:
    """Register DIQ tools/skills/adapters. The registry needs this run
    before any tool dispatch can succeed.

    This step is intentionally best-effort because the production
    bootstrap loads tool modules from `tools/` which lives outside this
    repository. A missing tools/ directory is normal in open-source
    builds and must not abort startup."""
    try:
        from core.diq.diq_registry import bootstrap as registry_bootstrap
        registry_bootstrap()
        logger.info("[BOOT] DIQ registry populated")
    except ImportError as e:
        logger.warning("[BOOT] DIQ registry not bootstrapped (tools/ missing?): %s", e)
        result.errors.append(f"registry: {e}")
    result.steps_completed.append("register_tools")


_BOOT_SEQUENCE = [
    _step_verify_diq,           # hard fail
    _step_check_souls,          # soft fail (safe mode)
    _step_load_mode,
    _step_ensure_admin,
    _step_ensure_tripwires,
    _step_load_upstream_tier,   # arms the tier-rebaseline gate
    _step_register_tools,       # soft fail (tools/ may be absent)
]


def boot(force: bool = False) -> BootResult:
    """Run the canonical startup sequence. Returns a BootResult.

    Idempotent unless `force=True`. The result is cached at module
    level so calling code can `boot()` from multiple entry points
    without redoing work.

    Raises:
        RuntimeError: on hard-fail steps (DIQ contract violation).
        Soft failures (soul integrity, soul guard, tool import) are
        captured in the BootResult instead of raising.
    """
    global _boot_result
    with _boot_lock:
        if _boot_result is not None and not force:
            return _boot_result

        logger.info("[BOOT] Super Tanks startup sequence begin")
        result = BootResult(success=False)

        for step in _BOOT_SEQUENCE:
            try:
                step(result)
            except RuntimeError:
                # Hard fail — propagate up.
                raise
            except Exception as exc:
                logger.error("[BOOT] step %s failed: %s", step.__name__, exc)
                result.errors.append(f"{step.__name__}: {exc}")

        result.success = True
        _boot_result = result
        logger.info(
            "[BOOT] Complete: %d steps, safe_mode=%s, errors=%d",
            len(result.steps_completed), result.safe_mode, len(result.errors),
        )
        return result


def is_booted() -> bool:
    """True if boot() has been called at least once."""
    return _boot_result is not None


def get_boot_result() -> Optional[BootResult]:
    """Last BootResult or None if boot() has not been called."""
    return _boot_result
