"""
core/ask_admin.py - Approval Request System for Tool Access Gatekeeping

R5.1 ask_admin: Interactive gatekeeping via Telegram
- TTL: 300 seconds (5 min)
- Fail-closed: BLOCK on timeout
- Deduplication: tool_name + args_hash + user_id
- Replay-proof: request_id single-use
"""

import uuid
import hashlib
import json
import time
import logging
from enum import Enum
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from core.db.connection import open_db

logger = logging.getLogger(__name__)


class ApprovalStatus(Enum):
    """Approval request states"""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


@dataclass
class ApprovalRequest:
    """Approval request for tool access"""
    request_id: str
    tool_name: str
    user_id: str
    reason: str
    args_hash: str
    args_len: int
    status: ApprovalStatus
    created_at: float
    expires_at: float
    resolved_at: Optional[float] = None
    resolved_by: Optional[str] = None
    raw_params: Optional[str] = None  # JSON-serialized raw tool parameters
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for storage"""
        data = asdict(self)
        data['status'] = self.status.value
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ApprovalRequest':
        """Create from dict"""
        data['status'] = ApprovalStatus(data['status'])
        return cls(**data)
    
    def is_expired(self) -> bool:
        """Check if request has expired"""
        return time.time() > self.expires_at
    
    def time_remaining(self) -> int:
        """Get seconds remaining until expiry"""
        remaining = int(self.expires_at - time.time())
        return max(0, remaining)


class ApprovalStore:
    """SQLite-backed store for approval requests"""
    
    def __init__(self, db_path: str = "data/approval_requests.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _get_conn(self):
        """Return a WAL-mode connection with busy timeout. ZEF v1.
        isolation_level=None disables Python's implicit transaction management
        so we can use BEGIN IMMEDIATE explicitly without conflicts.
        """
        import sqlite3
        conn = open_db(str(self.db_path), timeout=15, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=15000")
        return conn

    def _init_db(self):
        """Initialize database schema"""
        import sqlite3

        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS approval_requests (
                    request_id TEXT PRIMARY KEY,
                    tool_name TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    reason TEXT,
                    args_hash TEXT NOT NULL,
                    args_len INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    resolved_at REAL,
                    resolved_by TEXT,
                    raw_params TEXT DEFAULT '{}'
                )
            """)

            # Migration: add raw_params column if missing (existing DBs)
            try:
                conn.execute("SELECT raw_params FROM approval_requests LIMIT 0")
            except Exception:
                conn.execute("ALTER TABLE approval_requests ADD COLUMN raw_params TEXT DEFAULT '{}'")
                logger.info("[ASK_ADMIN] Migrated: added raw_params column")
            
            # Index for fast lookups
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_status_expires 
                ON approval_requests(status, expires_at)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_tool_user_hash 
                ON approval_requests(tool_name, user_id, args_hash, status)
            """)
    
    def create_request(
        self,
        tool_name: str,
        user_id: str,
        reason: str,
        args: Dict[str, Any],
        ttl_seconds: int = 300
    ) -> Optional[ApprovalRequest]:
        """Create new approval request. Returns None if persistence fails.

        The args_hash is the full 256-bit SHA-256 hex. The previous
        truncation to 64 bits (16 hex chars) made deliberate collisions
        cheap (≈ 2^32 hashes ≈ minutes on commodity hardware) — an
        attacker could craft args that collide with a previously-approved
        request and ride the 1h replay window.
        """
        args_str = json.dumps(args, sort_keys=True)
        args_hash = hashlib.sha256(args_str.encode()).hexdigest()
        args_len = len(args_str)

        # Store raw params for display in approval notification.
        # Truncate to 4000 chars max to prevent DB bloat.
        raw_params = json.dumps(args, indent=2, ensure_ascii=False)
        if len(raw_params) > 4000:
            raw_params = raw_params[:4000] + "\n... (truncated)"

        request = ApprovalRequest(
            # Full UUID (128 bits) — the previous 8-char truncation (32 bits)
            # collides at ~65k requests, and INSERT OR REPLACE would silently
            # overwrite the older row.
            request_id=str(uuid.uuid4()),
            tool_name=tool_name,
            user_id=user_id,
            reason=reason,
            args_hash=args_hash,
            args_len=args_len,
            status=ApprovalStatus.PENDING,
            created_at=time.time(),
            expires_at=time.time() + ttl_seconds,
            raw_params=raw_params,
        )

        if not self._save_request(request):
            logger.error(
                f"[ASK_ADMIN] Could not persist request {request.request_id} "
                f"for {tool_name} — caller must deny the operation"
            )
            return None
        logger.info(f"[ASK_ADMIN] Created request {request.request_id} for {tool_name}")
        return request
    
    def _save_request(self, request: ApprovalRequest) -> bool:
        """Persist the request. Returns True on success, False on SQLITE_BUSY.

        Previously this swallowed SQLITE_BUSY silently — callers
        constructed an ApprovalRequest object that never landed in the
        DB, dedup broke, and the daemon polling the DB never saw the
        request. Now the failure is surfaced so create_request can
        propagate it as a DENY to the caller.
        """
        import sqlite3

        conn = self._get_conn()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("""
                INSERT OR REPLACE INTO approval_requests
                (request_id, tool_name, user_id, reason, args_hash, args_len,
                 status, created_at, expires_at, resolved_at, resolved_by,
                 raw_params)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                request.request_id, request.tool_name, request.user_id,
                request.reason, request.args_hash, request.args_len,
                request.status.value, request.created_at, request.expires_at,
                request.resolved_at, request.resolved_by,
                request.raw_params or '{}',
            ))
            conn.commit()
            return True
        except sqlite3.OperationalError as e:
            logger.error(f"[ZEF v1] _save_request SQLITE_BUSY for {request.request_id}: {e} — DENY")
            try:
                conn.rollback()
            except Exception:
                pass
            return False
        finally:
            conn.close()
    
    def get_request(self, request_id: str) -> Optional[ApprovalRequest]:
        """Get request by ID"""
        import sqlite3
        
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM approval_requests WHERE request_id = ?",
                (request_id,)
            ).fetchone()
            
            if row:
                return self._row_to_request(row)
        return None
    
    def find_pending_duplicate(
        self,
        tool_name: str,
        user_id: str,
        args: Dict[str, Any]
    ) -> Optional[ApprovalRequest]:
        """Find existing pending request for same tool/args/user"""
        import sqlite3
        
        # Hash args same way as create
        args_str = json.dumps(args, sort_keys=True)
        args_hash = hashlib.sha256(args_str.encode()).hexdigest()
        
        with self._get_conn() as conn:
            row = conn.execute("""
                SELECT * FROM approval_requests 
                WHERE tool_name = ? AND user_id = ? AND args_hash = ? 
                AND status = ? AND expires_at > ?
                ORDER BY created_at DESC LIMIT 1
            """, (tool_name, user_id, args_hash, 
                  ApprovalStatus.PENDING.value, time.time())).fetchone()
            
            if row:
                return self._row_to_request(row)
        return None
    
    def find_approved_request(
        self,
        tool_name: str,
        user_id: str,
        args: Dict[str, Any],
        max_age_seconds: int = 3600  # 1 hour default
    ) -> Optional[ApprovalRequest]:
        """
        Find recently approved request for same tool/args/user.
        
        This allows re-using approvals within a time window.
        """
        import sqlite3
        
        # Hash args same way as create
        args_str = json.dumps(args, sort_keys=True)
        args_hash = hashlib.sha256(args_str.encode()).hexdigest()
        
        cutoff_time = time.time() - max_age_seconds
        
        with self._get_conn() as conn:
            row = conn.execute("""
                SELECT * FROM approval_requests 
                WHERE tool_name = ? AND user_id = ? AND args_hash = ? 
                AND status = ? AND resolved_at > ?
                ORDER BY resolved_at DESC LIMIT 1
            """, (tool_name, user_id, args_hash, 
                  ApprovalStatus.APPROVED.value, cutoff_time)).fetchone()
            
            if row:
                return self._row_to_request(row)
        return None
    
    def approve_request(self, request_id: str, admin_id: str) -> bool:
        """Approve a pending request atomically.

        Uses a single conditional UPDATE so two admins clicking approve/deny
        in the same millisecond can't both pass the status check and
        overwrite each other.
        """
        import sqlite3

        now = time.time()
        conn = self._get_conn()
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE approval_requests "
                "SET status=?, resolved_at=?, resolved_by=? "
                "WHERE request_id=? AND status=? AND expires_at>?",
                (ApprovalStatus.APPROVED.value, now, admin_id,
                 request_id, ApprovalStatus.PENDING.value, now),
            )
            conn.commit()
            if cur.rowcount == 0:
                logger.warning(
                    f"[ASK_ADMIN] Approve failed: request {request_id} "
                    f"not pending or already expired"
                )
                return False
            logger.info(f"[ASK_ADMIN] Approved request {request_id} by {admin_id}")
            return True
        except sqlite3.OperationalError as e:
            logger.error(f"[ZEF v1] approve_request SQLITE_BUSY for {request_id}: {e}")
            try:
                conn.rollback()
            except Exception:
                pass
            return False
        finally:
            conn.close()

    def deny_request(self, request_id: str, admin_id: str) -> bool:
        """Deny a pending request atomically (see approve_request)."""
        import sqlite3

        now = time.time()
        conn = self._get_conn()
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE approval_requests "
                "SET status=?, resolved_at=?, resolved_by=? "
                "WHERE request_id=? AND status=?",
                (ApprovalStatus.DENIED.value, now, admin_id,
                 request_id, ApprovalStatus.PENDING.value),
            )
            conn.commit()
            if cur.rowcount == 0:
                logger.warning(
                    f"[ASK_ADMIN] Deny failed: request {request_id} not pending"
                )
                return False
            logger.info(f"[ASK_ADMIN] Denied request {request_id} by {admin_id}")
            return True
        except sqlite3.OperationalError as e:
            logger.error(f"[ZEF v1] deny_request SQLITE_BUSY for {request_id}: {e}")
            try:
                conn.rollback()
            except Exception:
                pass
            return False
        finally:
            conn.close()
    
    def list_pending(self, limit: int = 100) -> list:
        """Return all pending approval requests, oldest first.

        The canonical "what needs admin attention" query. Supersedes
        go_gate_approval_daemon.get_pending_transactions, which read
        from a parallel go_transactions table that's now
        legacy-compat only.
        """
        import sqlite3

        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT request_id, tool_name, user_id, reason, args_hash, "
                "args_len, status, created_at, expires_at, resolved_at, "
                "resolved_by, raw_params "
                "FROM approval_requests "
                "WHERE status=? AND expires_at>? "
                "ORDER BY created_at ASC LIMIT ?",
                (ApprovalStatus.PENDING.value, time.time(), limit),
            ).fetchall()
            return [self._row_to_request(r) for r in rows]

    def expire_old_requests(self) -> int:
        """Mark expired requests and return count. ZEF v1: BEGIN IMMEDIATE."""
        import sqlite3

        now = time.time()
        conn = self._get_conn()
        try:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute("""
                SELECT request_id FROM approval_requests
                WHERE status = ? AND expires_at < ?
            """, (ApprovalStatus.PENDING.value, now)).fetchall()

            count = 0
            for (request_id,) in rows:
                conn.execute("""
                    UPDATE approval_requests
                    SET status = ?
                    WHERE request_id = ?
                """, (ApprovalStatus.EXPIRED.value, request_id))
                count += 1
                logger.info(f"[ASK_ADMIN] Expired request {request_id}")

            conn.commit()
            return count
        except sqlite3.OperationalError as e:
            logger.error(f"[ZEF v1] expire_old_requests SQLITE_BUSY: {e}")
            try:
                conn.rollback()
            except Exception:
                pass
            return 0
        finally:
            conn.close()

    def _row_to_request(self, row) -> ApprovalRequest:
        """Convert DB row to ApprovalRequest"""
        return ApprovalRequest(
            request_id=row[0],
            tool_name=row[1],
            user_id=row[2],
            reason=row[3],
            args_hash=row[4],
            args_len=row[5],
            status=ApprovalStatus(row[6]),
            created_at=row[7],
            expires_at=row[8],
            resolved_at=row[9],
            resolved_by=row[10],
            raw_params=row[11] if len(row) > 11 else '{}',
        )


# Global store instance
_approval_store: Optional[ApprovalStore] = None


def get_approval_store() -> ApprovalStore:
    """Get singleton approval store"""
    global _approval_store
    if _approval_store is None:
        _approval_store = ApprovalStore()
    return _approval_store


def check_tool_permission(
    tool_name: str,
    user_id: str,
    args: Dict[str, Any],
    policy_config: Dict[str, Any]
) -> Tuple[bool, Optional[str], str]:
    """
    Check if tool call requires admin approval.
    
    Returns: (approved, request_id, status_message)
    - approved: True if can proceed, False if blocked
    - request_id: Approval request ID (if created/pending)
    - status_message: Human-readable status
    """
    store = get_approval_store()
    
    # Check tool policy
    tool_policy = policy_config.get('tools', {}).get(tool_name, {})
    permission = tool_policy.get('permission', 'allow')
    
    if permission != 'ask_admin':
        # Tool doesn't require approval
        return True, None, "allowed"
    
    # Check for recently approved request (auto_resume re-execution)
    approved_existing = store.find_approved_request(tool_name, user_id, args)
    if approved_existing:
        return True, approved_existing.request_id, "approved"

    # Check for existing pending duplicate
    existing = store.find_pending_duplicate(tool_name, user_id, args)
    if existing:
        return False, existing.request_id, "PAUSED_FOR_APPROVAL_DUPLICATE"
    
    # Create new approval request
    ttl = tool_policy.get('timeout', 300)
    reason = tool_policy.get('description', f"Access {tool_name}")
    
    request = store.create_request(
        tool_name=tool_name,
        user_id=user_id,
        reason=reason,
        args=args,
        ttl_seconds=ttl
    )
    if request is None:
        # Persistence failed — fail closed.
        return False, None, "APPROVAL_STORE_UNAVAILABLE"

    return False, request.request_id, "PAUSED_FOR_APPROVAL"


def get_request_status(request_id: str) -> Optional[Dict[str, Any]]:
    """Get status of an approval request"""
    store = get_approval_store()
    
    # Expire old requests first
    store.expire_old_requests()
    
    request = store.get_request(request_id)
    if not request:
        return None
    
    result = {
        'request_id': request.request_id,
        'tool_name': request.tool_name,
        'status': request.status.value,
        'created_at': request.created_at,
        'expires_at': request.expires_at,
        'time_remaining': request.time_remaining(),
        'is_expired': request.is_expired()
    }
    
    # If approved, include receipt info
    if request.status == ApprovalStatus.APPROVED and request.resolved_by:
        result['receipt'] = {
            'request_id': request.request_id,
            'status': 'APPROVED',
            'approved_by': request.resolved_by,
            'approved_at': request.resolved_at,
            'tool': request.tool_name
        }
    
    return result


def get_approval_receipt(request_id: str) -> Optional[Dict[str, Any]]:
    """
    Get a valid approval receipt for execution.
    
    Returns receipt only if request is APPROVED and not expired.
    """
    status = get_request_status(request_id)
    
    if not status:
        return None
    
    if status.get('status') != 'approved':
        return None
    
    if status.get('is_expired'):
        return None
    
    return status.get('receipt')


# =============================================================================
# R5.1: Zeph Iron Link Integration
# =============================================================================

class ApprovalResult(Enum):
    """Result of approval request via Iron Link"""
    APPROVED = "approved"
    DENIED = "denied"
    PENDING = "pending"
    LINK_BROKEN = "link_broken"
    TIMEOUT = "timeout"


def ask_admin_iron_link(
    tool_name: str,
    user_id: str,
    args: Dict[str, Any],
    policy_config: Dict[str, Any],
    timeout_seconds: int = 300
) -> Tuple[ApprovalResult, str]:
    """
    R5.1: Request admin approval via Zeph Iron Link (Telegram).
    
    This is the main entry point for RISKY/CRITICAL tool approval.
    
    Args:
        tool_name: Tool being requested
        user_id: User requesting access
        args: Tool arguments
        policy_config: Tool policy configuration
        timeout_seconds: How long to wait for approval
    
    Returns:
        (result, message) tuple
        - result: ApprovalResult enum
        - message: Human-readable status/explanation
    """
    import asyncio
    from core.telegram_bot import get_telegram_manager
    from core.zeph_state import get_zeph_state, ApprovalStatus
    
    store = get_approval_store()
    
    # Step 1: Create approval request in local store
    tool_policy = policy_config.get('tools', {}).get(tool_name, {})
    reason = tool_policy.get('description', f"Access {tool_name}")
    
    request = store.create_request(
        tool_name=tool_name,
        user_id=user_id,
        reason=reason,
        args=args,
        ttl_seconds=timeout_seconds
    )
    
    # Step 2: Send via Zeph Iron Link
    telegram = get_telegram_manager()
    
    if not telegram.zeph_app or not telegram.zeph_verified:
        logger.error("[IRON_LINK] 🛑 Zeph Iron Link not available (bot not verified)")
        return ApprovalResult.LINK_BROKEN, "🛑 Zeph Iron Link ikke tilgjengelig. Kontakt administrator."
    
    # Send approval request using thread pool to avoid event loop conflict
    import concurrent.futures
    
    def send_via_zeph():
        loop = None
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(telegram.send_approval_request(
                request_id=request.request_id,
                tool=tool_name,
                user=user_id,
                reason=reason,
                timeout_minutes=timeout_seconds // 60,
                raw_params=request.raw_params,
            ))
        finally:
            if loop is not None:
                loop.close()
    
    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(send_via_zeph)
            send_result = future.result(timeout=15)
    except Exception as e:
        logger.error(f"Failed to send Iron Link request: {e}")
        return ApprovalResult.LINK_BROKEN, f"🛑 Kunne ikke sende forespørsel: {e}"
    
    if send_result['status'] == 'LINK_BROKEN':
        reason = send_result.get('reason', 'Ukjent feil')
        logger.error(f"[IRON_LINK] 🛑 Iron Link broken: {reason}")
        return ApprovalResult.LINK_BROKEN, f"🛑 Ingen kontakt med admin. Send /start til Zeph på Telegram.\n({reason})"
    
    # Step 3: Wait for approval (polling)
    logger.info(f"⏳ Waiting for approval: {request.request_id}")
    
    import time
    poll_interval = 2  # seconds
    elapsed = 0
    
    while elapsed < timeout_seconds:
        time.sleep(poll_interval)
        elapsed += poll_interval
        
        # Check Zeph state for resolution
        zeph_state = get_zeph_state()
        pending = zeph_state.get_pending(request.request_id)
        
        if pending:
            status = pending['status']
            
            if status == ApprovalStatus.APPROVED.value:
                # Sync to local store
                store.approve_request(request.request_id, pending.get('resolved_by', 'zeph'))
                logger.info(f"[IRON_LINK] ✅ Approved via Iron Link: {request.request_id}")
                return ApprovalResult.APPROVED, "✅ Godkjent!"
            
            elif status == ApprovalStatus.DENIED.value:
                store.deny_request(request.request_id, pending.get('resolved_by', 'zeph'))
                logger.info(f"⛔ Denied via Iron Link: {request.request_id}")
                return ApprovalResult.DENIED, "⛔ Avslått."
        
        # Also check local store (in case resolved via other means)
        local_status = get_request_status(request.request_id)
        if local_status:
            if local_status['status'] == 'approved':
                return ApprovalResult.APPROVED, "✅ Godkjent!"
            elif local_status['status'] == 'denied':
                return ApprovalResult.DENIED, "⛔ Avslått."
    
    # Timeout
    logger.warning(f"⏰ Approval timeout: {request.request_id}")
    return ApprovalResult.TIMEOUT, "⏰ Timeout - ingen respons i tide."


def check_tool_permission_with_roles(
    tool_name: str,
    user_id: str,
    action_class: str,  # SAFE, MEDIUM, HIGH, CRITICAL
    policy_config: Dict[str, Any]
) -> Tuple[bool, str]:
    """
    R5.1: Check permission based on family role and action class.
    
    Returns: (allowed, reason)
    """
    try:
        from core.succession_store import get_succession_store, ActionClass
        store = get_succession_store()
        
        # Convert string to ActionClass enum
        action = ActionClass(action_class.upper())
        user_id_int = int(user_id) if isinstance(user_id, str) else user_id
        
        allowed, reason = store.get_action_permission(user_id_int, action)
        return allowed, reason
    except Exception as e:
        logger.warning(f"[ASK_ADMIN] Role check failed: {e}, falling back to policy")
        # Fallback to policy-based
        tool_policy = policy_config.get('tools', {}).get(tool_name, {})
        permission = tool_policy.get('permission', 'allow')
        return permission == 'allow', f"Fallback: {permission}"


def check_tool_permission_iron_link(
    tool_name: str,
    user_id: str,
    args: Dict[str, Any],
    policy_config: Dict[str, Any]
) -> Tuple[bool, Optional[str], str]:
    """
    R5.1: Check tool permission with Zeph Iron Link approval.
    
    Returns: (approved, request_id, status_message)
    """
    store = get_approval_store()
    
    # Check tool policy
    tool_policy = policy_config.get('tools', {}).get(tool_name, {})
    permission = tool_policy.get('permission', 'allow')
    action_class = tool_policy.get('action_class', 'SAFE')  # R5.1: Get action class
    
    if permission == 'allow':
        return True, None, "allowed"
    
    if permission == 'deny':
        return False, None, "denied"
    
    if permission != 'ask_admin':
        return True, None, "allowed"
    
    # R5.1: Check role-based permissions first
    role_allowed, role_reason = check_tool_permission_with_roles(
        tool_name, user_id, action_class, policy_config
    )
    
    if action_class == 'CRITICAL' and not role_allowed:
        return False, None, f"⛔ CRITICAL actions require SUPER_ADMIN. {role_reason}"
    
    if action_class == 'HIGH' and not role_allowed:
        return False, None, f"⛔ HIGH actions require SUPER_ADMIN. {role_reason}"
    
    # CO_ADMIN can do MEDIUM, but need Iron Link approval
    # FAMILY 18+ can do MEDIUM, but need Iron Link approval
    
    # Check for existing approved request (re-use)
    existing_approved = store.find_approved_request(tool_name, user_id, args)
    if existing_approved:
        return True, existing_approved.request_id, "approved_from_cache"
    
    # Check for existing pending duplicate
    existing_pending = store.find_pending_duplicate(tool_name, user_id, args)
    if existing_pending:
        return False, existing_pending.request_id, "PAUSED_FOR_APPROVAL_DUPLICATE"
    
    # Request approval via Iron Link
    result, message = ask_admin_iron_link(
        tool_name=tool_name,
        user_id=user_id,
        args=args,
        policy_config=policy_config
    )
    
    if result == ApprovalResult.APPROVED:
        # Get the request_id from the store
        # (ask_admin_iron_link creates and resolves it)
        recent = store.find_approved_request(tool_name, user_id, args)
        req_id = recent.request_id if recent else None
        return True, req_id, message
    elif result == ApprovalResult.DENIED:
        return False, None, message
    elif result == ApprovalResult.LINK_BROKEN:
        return False, None, message
    elif result == ApprovalResult.TIMEOUT:
        return False, None, message
    else:
        return False, None, message
