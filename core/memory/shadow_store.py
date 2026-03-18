"""
core/memory/shadow_store.py
============================
Shadow Memory — git-inspired write governance for hierarchical memory.

All agent writes go through shadow proposals instead of writing directly.
William reviews and approves/rejects via cockpit or auto-approve rules.

Flow:
  Agent calls memory_store_hierarchical → creates shadow proposal
  → Auto-approve rules check (confidence, path sensitivity, TTL)
  → Pending proposals appear in cockpit "Shadow Review" tab
  → William approves → merged into main memory tree
  → Or auto-approved after 24h if rules match
  → Or expired after ttl_days (default 7)
"""

import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.db.connection import open_db

logger = logging.getLogger("super_tanks.memory.shadow")

SHADOW_DB = Path(__file__).resolve().parent.parent.parent / "data" / "shadow_proposals.db"

# Paths that always require manual review
SENSITIVE_PREFIXES = [
    "/william/age", "/family/health", "/family/finance",
    "/system/config", "/system/passwords", "/system/admin",
]


def _get_conn():
    SHADOW_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = open_db(str(SHADOW_DB), timeout=15, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def _init_db():
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS shadow_proposals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            branch_id TEXT NOT NULL UNIQUE,
            agent_id TEXT NOT NULL,
            operation TEXT NOT NULL,
            path TEXT NOT NULL,
            old_value TEXT,
            new_value TEXT NOT NULL,
            confidence REAL DEFAULT 0.8,
            status TEXT NOT NULL DEFAULT 'pending',
            auto_approve_at TEXT,
            created_at TEXT NOT NULL,
            reviewed_at TEXT,
            reviewed_by TEXT,
            ttl_days INTEGER DEFAULT 7,
            reason TEXT
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_shadow_status
        ON shadow_proposals(status, created_at)
    """)
    conn.close()


_init_db()


def propose(
    agent_id: str,
    path: str,
    l0_abstract: str,
    l1_overview: str,
    l2_full: Any,
    confidence: float = 0.8,
    operation: str = "create",
) -> Dict[str, Any]:
    """
    Create a shadow proposal for a memory write.

    Returns dict with branch_id, status, and auto_approve info.
    """
    branch_id = str(uuid.uuid4())[:12]
    now = datetime.now(timezone.utc).isoformat()

    new_value = json.dumps({
        "l0_abstract": l0_abstract,
        "l1_overview": l1_overview,
        "l2_full": l2_full,
    }, ensure_ascii=False)

    # Check existing value for diff
    old_value = None
    try:
        from core.memory.hierarchical_store import HierarchicalMemoryStore
        store = HierarchicalMemoryStore()
        existing = store.read(path, level=2)
        if existing is not None:
            operation = "update"
            if hasattr(existing, 'l2_full'):
                old_value = json.dumps({
                    "l0_abstract": existing.l0_abstract,
                    "l1_overview": existing.l1_overview,
                    "l2_full": existing.l2_full,
                }, ensure_ascii=False)
    except Exception:
        pass

    # Auto-approve rules
    status = "pending"
    auto_approve_at = None
    reason = None

    if confidence < 0.5:
        status = "auto_rejected"
        reason = "Confidence too low (<0.5)"
    elif _is_sensitive_path(path):
        status = "pending"
        reason = "Sensitive path — requires manual review"
    elif operation == "update":
        status = "pending"
        reason = "Correction of existing fact — requires manual review"
    elif operation == "create" and confidence >= 0.8:
        # Auto-approve new entries with high confidence after 24h
        auto_approve_at = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        status = "pending"
        reason = f"New entry, confidence {confidence:.1f} — auto-approve in 24h"

    conn = _get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("""
            INSERT INTO shadow_proposals
            (branch_id, agent_id, operation, path, old_value, new_value,
             confidence, status, auto_approve_at, created_at, ttl_days, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 7, ?)
        """, (branch_id, agent_id, operation, path, old_value, new_value,
              confidence, status, auto_approve_at, now, reason))
        conn.commit()
    finally:
        conn.close()

    # Audit log
    try:
        from core.memory.audit_log import log_access
        log_access(agent_id, "propose", path, detail_level=2,
                   mode="shadow", accessible=True)
    except Exception:
        pass

    logger.info(
        "[SHADOW] Proposal %s by %s: %s %s (confidence=%.1f, status=%s)",
        branch_id, agent_id, operation, path, confidence, status,
    )

    return {
        "branch_id": branch_id,
        "status": status,
        "operation": operation,
        "auto_approve_at": auto_approve_at,
        "reason": reason,
    }


def get_pending(limit: int = 50) -> List[Dict]:
    """Get all pending shadow proposals."""
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, branch_id, agent_id, operation, path, old_value, new_value,
                   confidence, status, auto_approve_at, created_at, reason
            FROM shadow_proposals
            WHERE status = 'pending'
            ORDER BY created_at DESC
            LIMIT ?
        """, (limit,))
        rows = cur.fetchall()
        return [{
            "id": r[0], "branch_id": r[1], "agent_id": r[2], "operation": r[3],
            "path": r[4], "old_value": r[5], "new_value": r[6],
            "confidence": r[7], "status": r[8], "auto_approve_at": r[9],
            "created_at": r[10], "reason": r[11],
        } for r in rows]
    finally:
        conn.close()


def approve(branch_id: str, reviewed_by: str = "william") -> Dict[str, Any]:
    """Approve a shadow proposal and merge into main memory."""
    conn = _get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.cursor()
        cur.execute(
            "SELECT path, new_value, status FROM shadow_proposals WHERE branch_id = ?",
            (branch_id,)
        )
        row = cur.fetchone()
        if not row:
            return {"success": False, "error": "Proposal not found"}
        if row[2] != "pending":
            return {"success": False, "error": f"Proposal is {row[2]}, not pending"}

        path, new_value_json = row[0], row[1]
        new_value = json.loads(new_value_json)

        # Merge into main memory
        from core.memory.hierarchical_store import HierarchicalMemoryStore
        store = HierarchicalMemoryStore()
        l0 = new_value.get("l0_abstract", "")
        l1 = new_value.get("l1_overview", "")
        store.store(
            path=path,
            l0_abstract=l0,
            l1_overview=l1,
            l2_full=new_value.get("l2_full", ""),
            source_agent=reviewed_by,
        )

        # Generate embedding for hybrid search (L0+L1 only, not L2)
        try:
            from core.memory.hybrid_search import store_embedding
            store_embedding(path, l0, l1)
        except Exception as _emb_err:
            logger.warning("[SHADOW] Embedding generation failed for %s: %s", path, _emb_err)

        now = datetime.now(timezone.utc).isoformat()
        conn.execute("""
            UPDATE shadow_proposals SET status='approved', reviewed_at=?, reviewed_by=?
            WHERE branch_id=?
        """, (now, reviewed_by, branch_id))
        conn.commit()

        logger.info("[SHADOW] Approved %s → merged %s", branch_id, path)
        return {"success": True, "path": path, "branch_id": branch_id}
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        return {"success": False, "error": str(e)}
    finally:
        conn.close()


def reject(branch_id: str, reviewed_by: str = "william", reason: str = "") -> Dict[str, Any]:
    """Reject a shadow proposal."""
    conn = _get_conn()
    try:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("""
            UPDATE shadow_proposals SET status='rejected', reviewed_at=?, reviewed_by=?, reason=?
            WHERE branch_id=? AND status='pending'
        """, (now, reviewed_by, reason or "Manually rejected", branch_id))
        affected = conn.execute("SELECT changes()").fetchone()[0]
        conn.commit()

        if affected == 0:
            return {"success": False, "error": "Proposal not found or not pending"}

        logger.info("[SHADOW] Rejected %s", branch_id)
        return {"success": True, "branch_id": branch_id}
    finally:
        conn.close()


def process_auto_approvals() -> int:
    """Auto-approve proposals past their auto_approve_at time. Run periodically."""
    now = datetime.now(timezone.utc).isoformat()
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT branch_id FROM shadow_proposals
            WHERE status='pending' AND auto_approve_at IS NOT NULL AND auto_approve_at < ?
        """, (now,))
        rows = cur.fetchall()
        count = 0
        for (bid,) in rows:
            result = approve(bid, reviewed_by="auto")
            if result.get("success"):
                count += 1
        return count
    finally:
        conn.close()


def expire_old_proposals() -> int:
    """Expire proposals older than their TTL."""
    conn = _get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        now = datetime.now(timezone.utc)
        conn.execute("""
            UPDATE shadow_proposals SET status='expired'
            WHERE status='pending'
            AND datetime(created_at, '+' || ttl_days || ' days') < ?
        """, (now.isoformat(),))
        affected = conn.execute("SELECT changes()").fetchone()[0]
        conn.commit()
        if affected:
            logger.info("[SHADOW] Expired %d proposals", affected)
        return affected
    finally:
        conn.close()


def _is_sensitive_path(path: str) -> bool:
    normalized = "/" + path.strip("/")
    return any(normalized.startswith(p) for p in SENSITIVE_PREFIXES)
