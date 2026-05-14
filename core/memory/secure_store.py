"""
core/memory/secure_store.py
============================
Super Tanks — security-enforced wrapper around HierarchicalMemoryStore.

All memory operations executed through this class are gated by:
  1. Tripwire check (honeypot detection → alarm + deny)
  2. RBAC check (is_path_accessible)
  3. Audit log entry (every operation, allowed or not)

The plain `HierarchicalMemoryStore` is the raw data plane. It enforces
NOTHING — anyone calling `store.read("/system/admin_keys")` directly
walks past every layer of the security model. `SecureMemoryStore` is
the only class agent-facing tools should be allowed to import.

Methods mirror the underlying store but require `agent_id` (and
optionally `mode`) on every call. There is no anonymous read.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from core.memory.hierarchical_store import (
    HierarchicalMemoryStore,
    MemoryFile,
)

logger = logging.getLogger("super_tanks.memory.secure")


class AccessDenied(Exception):
    """Raised when an agent attempts an operation outside its permissions."""


class SecureMemoryStore:
    """RBAC + tripwire + audit-enforcing wrapper around HierarchicalMemoryStore.

    Construct with an existing `HierarchicalMemoryStore` instance, or
    let the constructor build one at the default location.
    """

    def __init__(self, raw_store: Optional[HierarchicalMemoryStore] = None):
        self._raw = raw_store or HierarchicalMemoryStore()

    # ── Internal helpers ──────────────────────────────────────────────

    def _audit(self, agent_id: str, op: str, path: str,
               accessible: bool, mode: str = "unknown") -> None:
        try:
            from core.memory.audit_log import log_access
            log_access(
                agent_id=agent_id,
                operation=op,
                path=path,
                detail_level=2,
                mode=mode,
                accessible=accessible,
            )
        except Exception as exc:
            # Audit must never crash the operation, but it must never be
            # silent either. A separate logger keeps the failure visible.
            logger.error(
                "[SECURE_STORE] audit_log unavailable for op=%s agent=%s path=%s: %s",
                op, agent_id, path, exc,
            )

    def _check_path(self, agent_id: str, path: str,
                    mode: Optional[str], op: str) -> bool:
        """Run tripwire + RBAC. Returns True iff the operation may proceed.

        A tripwire hit triggers the alarm pipeline (forced lockdown,
        Telegram, trust event) inside `is_path_accessible`. Returning
        False here ensures the underlying raw operation is not executed.
        """
        from core.memory.tripwires import is_tripwire
        from core.memory.access_control import is_path_accessible, trigger_tripwire_alarm

        if is_tripwire(path):
            logger.critical(
                "TRIPWIRE HIT via SecureMemoryStore op=%s agent=%s path=%s",
                op, agent_id, path,
            )
            trigger_tripwire_alarm(path, agent_id)
            self._audit(agent_id, f"{op}_TRIPWIRE_BLOCKED", path,
                        accessible=False, mode=str(mode or "unknown"))
            return False

        if not is_path_accessible(path, agent_id, mode):
            self._audit(agent_id, f"{op}_DENIED", path,
                        accessible=False, mode=str(mode or "unknown"))
            return False
        return True

    # ── Public operations ─────────────────────────────────────────────

    def read(self, path: str, agent_id: str, *,
             level: int = 2, mode: Optional[str] = None
             ) -> Optional[Union[str, dict, MemoryFile]]:
        """Read a memory entry. Returns None on tripwire / RBAC denial."""
        if not self._check_path(agent_id, path, mode, "READ"):
            return None
        result = self._raw.read(path, level=level)
        self._audit(agent_id, "READ", path, accessible=True,
                    mode=str(mode or "unknown"))
        return result

    def store(self, path: str, agent_id: str, *,
              l0_abstract: str, l1_overview: str,
              l2_full: Union[dict, list, str],
              mode: Optional[str] = None,
              trust_level: str = "normal",
              extra_metadata: Optional[Dict[str, Any]] = None,
              ) -> Optional[MemoryFile]:
        """Write or overwrite a memory entry. Returns None on denial."""
        if not self._check_path(agent_id, path, mode, "WRITE"):
            return None
        result = self._raw.store(
            path=path,
            l0_abstract=l0_abstract,
            l1_overview=l1_overview,
            l2_full=l2_full,
            source_agent=agent_id,
            trust_level=trust_level,
            extra_metadata=extra_metadata,
        )
        self._audit(agent_id, "WRITE", path, accessible=True,
                    mode=str(mode or "unknown"))
        return result

    def delete(self, path: str, agent_id: str, *,
               mode: Optional[str] = None) -> bool:
        """Delete a memory entry. Returns False on denial OR if missing."""
        if not self._check_path(agent_id, path, mode, "DELETE"):
            return False
        result = self._raw.delete(path)
        self._audit(agent_id, "DELETE", path, accessible=True,
                    mode=str(mode or "unknown"))
        return result

    def list_dir(self, path: str, agent_id: str, *,
                 mode: Optional[str] = None) -> List[Dict[str, str]]:
        """List entries under a directory, filtered by per-entry access.

        We do NOT gate on the directory path itself — the filter is the
        gate, applied per-item. That avoids the degenerate case where
        "/" classifies as "unknown" and denies enumeration of any
        accessible child. Tripwire paths are filtered out silently so
        an attacker can't list them; the alarm fires only when an agent
        actually attempts to read a tripwire.
        """
        from core.memory.tripwires import is_tripwire
        from core.memory.access_control import is_path_accessible

        all_items = self._raw.list_dir(path)
        visible: List[Dict[str, str]] = []
        for item in all_items:
            item_path = item.get("path", "")
            if is_tripwire(item_path):
                continue
            if not is_path_accessible(item_path, agent_id, mode):
                continue
            visible.append(item)

        self._audit(agent_id, "LIST", path or "/", accessible=True,
                    mode=str(mode or "unknown"))
        return visible

    def search(self, query: str, agent_id: str, *,
               mode: Optional[str] = None) -> List[Dict[str, str]]:
        """Substring search across visible memory.

        Like list_dir, tripwires are filtered out silently (the alarm
        fires when the agent actually tries to *read* one). Otherwise
        a search would let an agent enumerate honeypots without alarms.
        """
        from core.memory.tripwires import is_tripwire
        from core.memory.access_control import is_path_accessible

        all_hits = self._raw.search(query)
        visible: List[Dict[str, str]] = []
        for hit in all_hits:
            p = hit.get("path", "")
            if is_tripwire(p):
                continue
            if not is_path_accessible(p, agent_id, mode):
                continue
            visible.append(hit)

        self._audit(agent_id, "SEARCH", query[:100], accessible=True,
                    mode=str(mode or "unknown"))
        return visible


# Module-level singleton for the common case.
_default_secure_store: Optional[SecureMemoryStore] = None


def get_secure_store() -> SecureMemoryStore:
    """Return the process-wide SecureMemoryStore."""
    global _default_secure_store
    if _default_secure_store is None:
        _default_secure_store = SecureMemoryStore()
    return _default_secure_store
