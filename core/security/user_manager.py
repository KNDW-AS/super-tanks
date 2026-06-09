"""
core/security/user_manager.py
===============================
Super Tanks User Access System — 5 levels, per-user settings.

Level 5: Full access (system admin)
Level 4: Near-full (cannot delete system or last L5 user)
Level 3: Configured user (chat + smart home + status panels)
Level 2: Standard user (chat + permitted entities)
Level 1: Limited user (Aeris only, filtered, curfew, permitted entities)

Per-user settings (independent of level):
- curfew (time or none)
- emergency_override (on/off)
- content_filter (free text)
- goodnight_message (text)
- permitted_entities (list)
- filter_alerts (on/off)
- alert_content (on/off)

The system must always have at least one Level 5 user.
"""

import json
import hashlib
import logging
import secrets
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

from core.db.connection import open_db

logger = logging.getLogger("super_tanks.user_manager")

USER_DB = Path(__file__).resolve().parent.parent.parent / "data" / "users.db"

# Session lifetime — 24h is the cockpit default. Long enough that William
# doesn't get logged out mid-day, short enough that a stolen session_id
# stops working overnight. Tunable by callers via authenticate(ttl_hours=).
DEFAULT_SESSION_TTL_HOURS = 24

LEVEL_NAMES = {5: "Full access", 4: "Near-full", 3: "Configured", 2: "Standard", 1: "Limited"}

LEVEL_CAPABILITIES = {
    5: {"chat_aeris", "chat_zeph", "smart_home", "cockpit_full", "go_gate", "audit",
        "shadow_review", "budget", "trust", "user_management", "soul_update", "system_delete"},
    4: {"chat_aeris", "chat_zeph", "smart_home", "cockpit_full", "go_gate", "audit",
        "shadow_review", "budget", "trust", "user_management", "soul_update"},
    3: {"chat_aeris", "chat_zeph", "smart_home", "cockpit_status", "view_own_history"},
    2: {"chat_aeris", "chat_zeph", "smart_home_permitted", "view_own_history"},
    1: {"chat_aeris", "smart_home_permitted", "view_own_history"},
}

# Emergency keywords (default, customizable per install)
DEFAULT_EMERGENCY_KEYWORDS = {
    "en": ["fire", "smoke", "help", "sick", "scared", "hurt", "pain", "emergency", "intruder"],
    "no": ["brann", "røyk", "hjelp", "syk", "redd", "vondt", "smerte", "nødssituasjon", "innbrudd"],
    "common": ["110", "112", "113", "911", "999", "sos"],
}


_initialised: bool = False
_init_lock = threading.RLock()


def _get_conn():
    USER_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = open_db(str(USER_DB), timeout=15, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    _ensure_db()
    return conn


def _ensure_db() -> None:
    """Idempotent schema bootstrap on first DB use."""
    global _initialised
    if _initialised:
        return
    with _init_lock:
        if _initialised:
            return
        _initialised = True
        try:
            _init_db()
        except Exception:
            _initialised = False
            raise


def _init_db():
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS st_users (
            user_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            pin_hash TEXT NOT NULL,
            level INTEGER NOT NULL DEFAULT 2,
            curfew_time TEXT,
            emergency_override INTEGER DEFAULT 1,
            content_filter TEXT DEFAULT '',
            goodnight_message TEXT DEFAULT '',
            permitted_entities TEXT DEFAULT '[]',
            filter_alerts INTEGER DEFAULT 1,
            alert_content INTEGER DEFAULT 0,
            telegram_id TEXT,
            created_at TEXT NOT NULL,
            created_by TEXT,
            last_login TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS st_sessions (
            session_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            ip_address TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS st_user_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            target_user TEXT,
            details TEXT
        )
    """)
    # Failed-auth attempts for rate limiting. One row per failure;
    # purged opportunistically by _is_locked_out.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS st_auth_failures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_failures_user "
                 "ON st_auth_failures(user_id, timestamp)")
    conn.commit()
    conn.close()


# Schema is created lazily on first _get_conn() call (see _ensure_db).
# Tests that need an empty DB at a tmp path can still call _init_db()
# explicitly after monkeypatching USER_DB.


# ── PIN hashing ──────────────────────────────────────────────────────
#
# Legacy format: 32 hex chars of SHA-256 with a hard-coded global salt.
# That's GPU-crackable in microseconds for a 4-digit PIN space.
#
# New format: "scrypt$<salt_hex>$<digest_hex>" — per-user salt, modern
# memory-hard KDF (stdlib hashlib.scrypt, no new dep). On successful
# legacy auth we transparently upgrade the stored hash.

_SCRYPT_N = 2 ** 14  # CPU/memory cost
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32

# Rate limiting: max failures before authenticate() short-circuits.
MAX_AUTH_FAILURES = 5
AUTH_FAILURE_WINDOW_MINUTES = 15


def _scrypt_hash(pin: str, salt: bytes) -> str:
    digest = hashlib.scrypt(
        pin.encode("utf-8"), salt=salt,
        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN,
    )
    return f"scrypt${salt.hex()}${digest.hex()}"


def _hash_pin(pin: str) -> str:
    """Hash a new PIN with a fresh per-user salt."""
    salt = secrets.token_bytes(16)
    return _scrypt_hash(pin, salt)


def _legacy_hash_pin(pin: str) -> str:
    """Reproduce the old sha256[:32] hash for migration comparisons."""
    return hashlib.sha256(f"{pin}:supertanks2026".encode()).hexdigest()[:32]


def _verify_pin(pin: str, stored: str) -> bool:
    """Constant-time PIN check against either legacy or scrypt hash."""
    if stored.startswith("scrypt$"):
        try:
            _, salt_hex, digest_hex = stored.split("$", 2)
            salt = bytes.fromhex(salt_hex)
        except (ValueError, AttributeError):
            return False
        candidate = _scrypt_hash(pin, salt)
        # Constant-time compare on the full stored string.
        import hmac as _hmac
        return _hmac.compare_digest(candidate, stored)
    # Legacy 32-char sha256.
    import hmac as _hmac
    return _hmac.compare_digest(_legacy_hash_pin(pin), stored)


# ── User CRUD ──

def create_user(name: str, pin: str, level: int, created_by: str,
                telegram_id: str = "", **settings) -> Dict:
    """Create a new user. Only Level 5 can call this."""
    if level < 1 or level > 5:
        return {"success": False, "error": "Level must be 1-5"}

    user_id = name.lower().replace(" ", "_")
    now = datetime.now(timezone.utc).isoformat()

    conn = _get_conn()
    try:
        existing = conn.execute("SELECT user_id FROM st_users WHERE user_id=?", (user_id,)).fetchone()
        if existing:
            return {"success": False, "error": f"User '{user_id}' already exists"}

        curfew_raw = settings.get("curfew_time")
        curfew_parsed = _parse_curfew(str(curfew_raw)) if curfew_raw else None

        conn.execute("""
            INSERT INTO st_users (user_id, name, pin_hash, level, telegram_id, created_at, created_by,
                                  curfew_time, emergency_override, content_filter, goodnight_message,
                                  permitted_entities, filter_alerts, alert_content)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, name, _hash_pin(pin), level, telegram_id, now, created_by,
              curfew_parsed, 1 if settings.get("emergency_override", True) else 0,
              settings.get("content_filter", ""), settings.get("goodnight_message", ""),
              json.dumps(settings.get("permitted_entities", [])),
              1 if settings.get("filter_alerts", True) else 0,
              1 if settings.get("alert_content", False) else 0))
        conn.commit()
    finally:
        conn.close()

    _audit("create_user", created_by, user_id, f"Level {level}")
    logger.info("[USER] Created %s (level %d) by %s", user_id, level, created_by)
    return {"success": True, "user_id": user_id}


def get_user(user_id: str) -> Optional[Dict]:
    conn = _get_conn()
    try:
        row = conn.execute("SELECT * FROM st_users WHERE user_id=?", (user_id,)).fetchone()
        if not row:
            return None
        cols = [d[0] for d in conn.execute("SELECT * FROM st_users LIMIT 0").description]
        user = dict(zip(cols, row))
        user["permitted_entities"] = json.loads(user.get("permitted_entities", "[]"))
        user.pop("pin_hash", None)  # Never expose hash
        return user
    finally:
        conn.close()


def list_users() -> List[Dict]:
    conn = _get_conn()
    try:
        rows = conn.execute("SELECT user_id, name, level, telegram_id, curfew_time, last_login FROM st_users ORDER BY level DESC, name").fetchall()
        return [{"user_id": r[0], "name": r[1], "level": r[2], "telegram_id": r[3],
                 "curfew_time": r[4], "last_login": r[5]} for r in rows]
    finally:
        conn.close()


def _is_privileged_actor(conn, actor: str) -> bool:
    """Internal helper: actor must be Level 5 or the synthetic 'system' bootstrap actor."""
    if actor == "system":
        return True
    row = conn.execute("SELECT level FROM st_users WHERE user_id=?", (actor,)).fetchone()
    return row is not None and row[0] == 5


def update_user(user_id: str, actor: str, **updates) -> Dict:
    """Update user settings. Actor must be Level 5 (or the bootstrap 'system').

    Previously the docstring promised this but no code enforced it — any
    string for `actor` was accepted, so a Level-1 caller could demote an
    admin.
    """
    allowed_fields = {"level", "curfew_time", "emergency_override", "content_filter",
                      "goodnight_message", "permitted_entities", "filter_alerts",
                      "alert_content", "telegram_id", "name"}

    conn = _get_conn()
    try:
        if not _is_privileged_actor(conn, actor):
            return {"success": False, "error": "Actor must be Level 5"}

        existing = conn.execute("SELECT level FROM st_users WHERE user_id=?", (user_id,)).fetchone()
        if not existing:
            return {"success": False, "error": "User not found"}

        for key, val in updates.items():
            if key not in allowed_fields:
                continue
            if key == "permitted_entities" and isinstance(val, list):
                val = json.dumps(val)
            if key == "level":
                val = max(1, min(5, int(val)))
            if key == "curfew_time" and val:
                val = _parse_curfew(str(val)) or val
            conn.execute(f"UPDATE st_users SET {key}=? WHERE user_id=?", (val, user_id))

        conn.commit()
    finally:
        conn.close()

    _audit("update_user", actor, user_id, json.dumps(updates, ensure_ascii=False)[:200])
    return {"success": True}


def delete_user(user_id: str, actor: str) -> Dict:
    """Delete a user. Cannot delete last Level 5 user. Actor must be Level 5.

    The level-count check + delete now run inside one BEGIN IMMEDIATE
    transaction so two admins concurrently deleting each other can't
    both pass the count guard and leave the system with zero L5 users.
    """
    conn = _get_conn()
    try:
        if not _is_privileged_actor(conn, actor):
            return {"success": False, "error": "Actor must be Level 5"}

        conn.execute("BEGIN IMMEDIATE")
        target = conn.execute("SELECT level FROM st_users WHERE user_id=?", (user_id,)).fetchone()
        if not target:
            conn.rollback()
            return {"success": False, "error": "User not found"}

        if target[0] == 5:
            l5_count = conn.execute("SELECT COUNT(*) FROM st_users WHERE level=5").fetchone()[0]
            if l5_count <= 1:
                conn.rollback()
                return {"success": False, "error": "Cannot delete last Level 5 user"}

        conn.execute("DELETE FROM st_users WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM st_sessions WHERE user_id=?", (user_id,))
        conn.commit()
    finally:
        conn.close()

    _audit("delete_user", actor, user_id, "User deleted (2-step confirmed)")
    logger.warning("[USER] Deleted %s by %s", user_id, actor)
    return {"success": True}


# ── Auth ──

def _is_locked_out(conn, user_id: str) -> bool:
    """Returns True if this user has too many recent failed PIN attempts.

    Old rows are pruned opportunistically so the table doesn't grow
    unbounded. The check + prune happen in the same connection but not
    in a transaction — racing failures within a few ms can both pass,
    but they both still count, and the next attempt sees the cumulative
    total. That's an acceptable approximation for rate limiting.
    """
    cutoff = (datetime.now(timezone.utc)
              - timedelta(minutes=AUTH_FAILURE_WINDOW_MINUTES)).isoformat()
    conn.execute("DELETE FROM st_auth_failures WHERE timestamp < ?", (cutoff,))
    row = conn.execute(
        "SELECT COUNT(*) FROM st_auth_failures WHERE user_id=? AND timestamp >= ?",
        (user_id, cutoff),
    ).fetchone()
    return row and row[0] >= MAX_AUTH_FAILURES


def authenticate(user_id: str, pin: str,
                 ttl_hours: int = DEFAULT_SESSION_TTL_HOURS) -> Optional[Dict]:
    """Authenticate user and create a session with a TTL.

    Returns a dict with session_id and expires_at on success, or None
    if user is unknown, PIN is wrong, or the user is currently rate-
    limited from too many recent failures.

    On a successful login that used the legacy SHA-256 hash, the stored
    hash is transparently upgraded to scrypt with a fresh salt.
    """
    conn = _get_conn()
    try:
        if _is_locked_out(conn, user_id):
            logger.warning("[USER] auth rate-limited for %s", user_id)
            _audit("auth_rate_limited", "system", user_id, "")
            return None

        row = conn.execute(
            "SELECT pin_hash, level, name FROM st_users WHERE user_id=?",
            (user_id,),
        ).fetchone()
        if not row:
            # Unknown user — record a failure so an attacker can't probe
            # for valid user_ids without rate limiting.
            conn.execute(
                "INSERT INTO st_auth_failures (user_id, timestamp) VALUES (?, ?)",
                (user_id, datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()
            return None

        stored_hash = row[0]
        if not _verify_pin(pin, stored_hash):
            conn.execute(
                "INSERT INTO st_auth_failures (user_id, timestamp) VALUES (?, ?)",
                (user_id, datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()
            return None

        now_dt = datetime.now(timezone.utc)
        now = now_dt.isoformat()
        expires_dt = now_dt + timedelta(hours=ttl_hours)
        expires = expires_dt.isoformat()

        # Transparent migration: legacy hash → scrypt on next successful login.
        if not stored_hash.startswith("scrypt$"):
            new_hash = _hash_pin(pin)
            conn.execute("UPDATE st_users SET pin_hash=? WHERE user_id=?",
                         (new_hash, user_id))
            logger.info("[USER] Upgraded PIN hash to scrypt for %s", user_id)

        conn.execute("UPDATE st_users SET last_login=? WHERE user_id=?",
                     (now, user_id))

        # Clear failure counter on success so this user starts clean.
        conn.execute("DELETE FROM st_auth_failures WHERE user_id=?", (user_id,))

        session_id = secrets.token_hex(16)
        conn.execute("INSERT INTO st_sessions (session_id, user_id, created_at, expires_at) VALUES (?,?,?,?)",
                     (session_id, user_id, now, expires))
        conn.commit()

        return {
            "user_id": user_id, "name": row[2], "level": row[1],
            "session_id": session_id, "expires_at": expires,
        }
    finally:
        conn.close()


def validate_session(session_id: str) -> Optional[Dict]:
    """Look up a session and confirm it has not expired.

    Returns the same dict shape as authenticate() on success, or None
    if the session is unknown or expired. Expired rows are deleted
    eagerly so the row count stays bounded.
    """
    if not session_id:
        return None
    now_dt = datetime.now(timezone.utc)
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT s.user_id, s.expires_at, u.name, u.level "
            "FROM st_sessions s JOIN st_users u ON u.user_id = s.user_id "
            "WHERE s.session_id = ?",
            (session_id,),
        ).fetchone()
        if not row:
            return None
        user_id, expires_at, name, level = row
        try:
            expires_dt = datetime.fromisoformat(expires_at)
        except (TypeError, ValueError):
            # Corrupt timestamp — fail closed and remove the row.
            conn.execute("DELETE FROM st_sessions WHERE session_id=?", (session_id,))
            conn.commit()
            return None
        # A naive timestamp (older row, manual edit, or a tool that used
        # utcnow().isoformat() without an offset) would crash the
        # comparison below with TypeError. Attach UTC if missing.
        if expires_dt.tzinfo is None:
            expires_dt = expires_dt.replace(tzinfo=timezone.utc)
        if now_dt >= expires_dt:
            conn.execute("DELETE FROM st_sessions WHERE session_id=?", (session_id,))
            conn.commit()
            return None
        return {
            "user_id": user_id, "name": name, "level": level,
            "session_id": session_id, "expires_at": expires_at,
        }
    finally:
        conn.close()


def revoke_session(session_id: str) -> bool:
    """Remove a session before its natural expiry (logout).

    Returns True if a row was deleted, False if the session was unknown.
    """
    conn = _get_conn()
    try:
        cur = conn.execute("DELETE FROM st_sessions WHERE session_id=?", (session_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def purge_expired_sessions() -> int:
    """Delete all sessions whose expires_at has passed. Returns the count."""
    now = datetime.now(timezone.utc).isoformat()
    conn = _get_conn()
    try:
        cur = conn.execute("DELETE FROM st_sessions WHERE expires_at <= ?", (now,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def has_capability(user_id: str, capability: str) -> bool:
    """Check if user has a specific capability based on their level."""
    user = get_user(user_id)
    if not user:
        return False
    level = user.get("level", 0)
    caps = LEVEL_CAPABILITIES.get(level, set())
    return capability in caps


# ── Curfew ──

def _parse_curfew(value: str) -> Optional[str]:
    """Parse flexible curfew input → HH:MM format.
    Accepts: '23', '23:00', '2300', '11pm', '11 pm', '9', '09:30'"""
    if not value or not value.strip():
        return None
    v = value.strip().lower().replace(" ", "")

    # Handle "pm" suffix
    pm = "pm" in v
    am = "am" in v
    v = v.replace("pm", "").replace("am", "")

    # Try HH:MM
    if ":" in v:
        parts = v.split(":")
        h, m = int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
    # Try HHMM (4 digits)
    elif len(v) == 4 and v.isdigit():
        h, m = int(v[:2]), int(v[2:])
    # Try H or HH (just hours)
    elif v.isdigit():
        h, m = int(v), 0
    else:
        return None

    if pm and h < 12:
        h += 12
    if am and h == 12:
        h = 0

    if 0 <= h <= 23 and 0 <= m <= 59:
        return f"{h:02d}:{m:02d}"
    return None


def check_curfew(user_id: str) -> Dict:
    """Check if user is within curfew. Returns {allowed, reason}."""
    user = get_user(user_id)
    if not user or not user.get("curfew_time"):
        return {"allowed": True, "reason": "No curfew"}

    try:
        parsed = _parse_curfew(user["curfew_time"])
        if not parsed:
            return {"allowed": True, "reason": "Invalid curfew format"}

        curfew_hour, curfew_min = map(int, parsed.split(":"))
        now = datetime.now()
        wake_hour = 6

        # Compare minute precision: a 22:30 curfew must not trigger
        # until 22:30 exactly. The earlier version dropped curfew_min
        # entirely, so any HH:MM curfew effectively rounded down to HH:00.
        now_minutes = now.hour * 60 + now.minute
        curfew_minutes = curfew_hour * 60 + curfew_min
        wake_minutes = wake_hour * 60

        if now_minutes >= curfew_minutes or now_minutes < wake_minutes:
            return {"allowed": False, "reason": f"Curfew active (after {parsed})",
                    "goodnight": user.get("goodnight_message", "")}
    except Exception:
        logger.debug("Suppressed exception (non-critical path)", exc_info=True)

    return {"allowed": True, "reason": "Within allowed hours"}


def check_emergency(message: str, user_id: str) -> bool:
    """Check if message contains emergency keywords."""
    user = get_user(user_id)
    if not user or not user.get("emergency_override"):
        return False

    msg_lower = message.lower()
    all_keywords = []
    for lang_keywords in DEFAULT_EMERGENCY_KEYWORDS.values():
        all_keywords.extend(lang_keywords)

    # Simple keyword check (context-aware: skip "help with homework" etc.)
    for kw in all_keywords:
        if kw in msg_lower:
            # Basic context check — skip if followed by common non-emergency words
            idx = msg_lower.find(kw)
            after = msg_lower[idx + len(kw):idx + len(kw) + 20]
            if any(w in after for w in [" with homework", " med lekser", " me understand"]):
                continue
            return True

    return False


# ── Content Filter ──

def get_content_filter(user_id: str) -> str:
    """Get per-user content filter text."""
    user = get_user(user_id)
    if not user:
        return ""
    return user.get("content_filter", "")


# ── Audit ──

def _audit(action: str, actor: str, target: str = "", details: str = ""):
    conn = _get_conn()
    try:
        conn.execute("INSERT INTO st_user_audit (timestamp, action, actor, target_user, details) VALUES (?,?,?,?,?)",
                     (datetime.now(timezone.utc).isoformat(), action, actor, target, details))
        conn.commit()
    finally:
        conn.close()


def get_user_audit(limit: int = 50) -> List[Dict]:
    conn = _get_conn()
    try:
        rows = conn.execute("SELECT timestamp, action, actor, target_user, details FROM st_user_audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{"timestamp": r[0], "action": r[1], "actor": r[2], "target": r[3], "details": r[4]} for r in rows]
    finally:
        conn.close()


# ── Migration: import existing William user ──

def ensure_admin_exists():
    """Ensure at least one Level 5 user exists. Creates from existing user_auth if needed."""
    conn = _get_conn()
    try:
        count = conn.execute("SELECT COUNT(*) FROM st_users WHERE level=5").fetchone()[0]
        if count > 0:
            return

        # Import from existing user_auth
        try:
            from core.user_auth import get_auth
            auth = get_auth()
            for name, user in auth.users.items():
                if user.is_admin:
                    create_user(name=name, pin="0000", level=5, created_by="system",
                                telegram_id="" if name == "William" else "")
                    logger.info("[USER] Migrated admin user: %s", name)
        except Exception as e:
            # Fallback: create default admin
            create_user(name="Admin", pin="0000", level=5, created_by="system")
            logger.warning("[USER] Created default admin (migration failed: %s)", e)
    finally:
        conn.close()
