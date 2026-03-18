"""
go_gate_approval_daemon.py
--------------------------
Daemon thread som poller aeris_gate_bot for /approve og /go kommandoer,
og oppdaterer go_gate.db slik at Zeph sin poll-loop kan plukke opp COMMITTED transaksjoner.

Legg til i main_loop.py:
    from go_gate_approval_daemon import start_approval_daemon
    start_approval_daemon()
"""

import os
import time
import sqlite3
import logging
import threading
import requests
from core.db.connection import open_db

# ── Config ────────────────────────────────────────────────────────────────────
TELEGRAM_TOKEN  = os.getenv("AERIS_GOGATE_TELEGRAM_TOKEN")
ADMIN_CHAT_ID   = int(os.getenv("AERIS_ADMIN_CHAT_ID", "0"))
DB_PATH         = os.getenv("GOGATE_DB_PATH", "data/go_gate.db")
POLL_INTERVAL   = float(os.getenv("GOGATE_POLL_INTERVAL", "3"))   # sekunder
TELEGRAM_TIMEOUT = 20                                               # long-poll timeout

BASE_URL = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}"

log = logging.getLogger("go_gate_approval")

# Dedup-cache: forhindrer doble svar fra stray-prosesser
_processed_update_ids: set = set()
_processed_lock = threading.Lock()

def _is_duplicate_update(update_id: int) -> bool:
    """Returnerer True hvis update_id allerede er behandlet (TTL: 120 sekunder)."""
    with _processed_lock:
        if update_id in _processed_update_ids:
            return True
        _processed_update_ids.add(update_id)
        # Begrens størrelse — behold kun de siste 500
        if len(_processed_update_ids) > 500:
            oldest = sorted(_processed_update_ids)[:250]
            for uid in oldest:
                _processed_update_ids.discard(uid)
        return False


def _trigger_auto_resume(tx_id: str) -> None:
    """
    Fire-and-forget: start auto-resume for tx_id i ein eigen daemon-thread.

    Brukar run_coroutine_threadsafe() mot Telegram-trådens event loop viss han
    køyrer (vanleg tilfelle). Fallback til asyncio.run() viss loopen ikkje er
    tilgjengeleg (t.d. i testar eller standalone-modus).
    """
    def _run() -> None:
        import asyncio
        try:
            from core.telegram_bot import get_telegram_manager, get_telegram_loop
            mgr = get_telegram_manager()
            if not mgr:
                return
            tg_loop = get_telegram_loop()
            if tg_loop and tg_loop.is_running():
                # Submit til Telegram sin eigen event loop — unngår "Event loop is closed"
                future = asyncio.run_coroutine_threadsafe(
                    mgr._auto_resume_request(tx_id), tg_loop
                )
                future.result(timeout=60)  # vent maks 60s; kaster exception viss feil
            else:
                # Fallback: ingen Telegram-loop køyrer (testar, standalone)
                asyncio.run(mgr._auto_resume_request(tx_id))
        except Exception as _e:
            log.warning(f"[AUTO_RESUME] Thread feilet for {tx_id}: {_e}")

    t = threading.Thread(target=_run, name=f"AutoResume-{tx_id[:8]}", daemon=True)
    t.start()
    log.info(f"[AUTO_RESUME] Trigger starta for tx_id={tx_id}")


def _ask_admin_approve(tx_id: str, admin_id: str = "human_telegram") -> bool:
    """Fallback: godkjenn via ask_admin.ApprovalStore (zeph_l1_gate-flyten)."""
    try:
        from core.ask_admin import get_approval_store
        store = get_approval_store()
        return store.approve_request(tx_id, admin_id=admin_id)
    except Exception as e:
        log.warning(f"[ask_admin] approve fallback feilet for {tx_id}: {e}")
        return False


def _ask_admin_deny(tx_id: str, admin_id: str = "human_telegram") -> bool:
    """Fallback: avvis via ask_admin.ApprovalStore (zeph_l1_gate-flyten)."""
    try:
        from core.ask_admin import get_approval_store
        store = get_approval_store()
        return store.deny_request(tx_id, admin_id=admin_id)
    except Exception as e:
        log.warning(f"[ask_admin] deny fallback feilet for {tx_id}: {e}")
        return False

# ── Database helpers ──────────────────────────────────────────────────────────

def _get_db() -> sqlite3.Connection:
    # isolation_level=None = autocommit/explicit mode so BEGIN IMMEDIATE doesn't conflict
    # with Python's implicit transaction management
    conn = open_db(DB_PATH, check_same_thread=False, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    # ZEF v1: WAL mode for concurrent read/write without blocking
    conn.execute("PRAGMA journal_mode=WAL")
    # ZEF v1: 15s busy timeout — log + deny on SQLITE_BUSY, never crash
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def commit_transaction(tx_id: str) -> bool:
    """
    Setter status='COMMITTED' for tx_id hvis nåværende status er PENDING_HUMAN_APPROVAL.
    Returnerer True hvis en rad ble oppdatert, False ellers.
    ZEF v1: BEGIN IMMEDIATE forhindrer double-spend race conditions.
    """
    try:
        conn = _get_db()
        conn.execute("BEGIN IMMEDIATE")
    except sqlite3.OperationalError as e:
        log.error(f"[ZEF v1] GO-GATE lock failed for tx_id={tx_id}: {e} — returning DENY")
        return False
    try:
        cur = conn.execute(
            """
            UPDATE go_transactions
               SET status = 'COMMITTED',
                   approved_at = CURRENT_TIMESTAMP,
                   approved_by = 'human_telegram',
                   approval_type = 'HUMAN'
             WHERE tx_id = ?
               AND status = 'PENDING_HUMAN_APPROVAL'
            """,
            (tx_id,),
        )
        conn.commit()
        updated = cur.rowcount > 0
        if updated:
            log.info(f"✅ tx_id={tx_id} → COMMITTED")
            # Oppdater også ask_admin ApprovalStore (det Zeph faktisk poller)
            try:
                import sys, os
                sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                from core.ask_admin import get_approval_store
                store = get_approval_store()
                store.approve_request(tx_id, admin_id="human_telegram")
                log.info(f"✅ tx_id={tx_id} → ask_admin APPROVED")
                _trigger_auto_resume(tx_id)
            except Exception as e:
                log.warning(f"⚠️  ask_admin approve feilet (ikke kritisk): {e}")
        else:
            log.warning(f"⚠️  tx_id={tx_id} ikke funnet eller allerede behandlet")
        return updated
    except Exception as e:
        log.error(f"[ZEF v1] commit_transaction failed for tx_id={tx_id}: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        return False
    finally:
        try:
            conn.close()
        except Exception:
            pass


def reject_transaction(tx_id: str) -> bool:
    """
    Setter status='REJECTED' for tx_id.
    ZEF v1: BEGIN IMMEDIATE forhindrer double-spend race conditions.
    """
    try:
        conn = _get_db()
        conn.execute("BEGIN IMMEDIATE")
    except sqlite3.OperationalError as e:
        log.error(f"[ZEF v1] GO-GATE lock failed for reject tx_id={tx_id}: {e} — returning DENY")
        return False
    try:
        cur = conn.execute(
            """
            UPDATE go_transactions
               SET status = 'ABORTED',
                   approved_at = CURRENT_TIMESTAMP,
                   approved_by = 'human_telegram_rejected'
             WHERE tx_id = ?
               AND status = 'PENDING_HUMAN_APPROVAL'
            """,
            (tx_id,),
        )
        conn.commit()
        updated = cur.rowcount > 0
        if updated:
            log.info(f"❌ tx_id={tx_id} → REJECTED")
        return updated
    except Exception as e:
        log.error(f"[ZEF v1] reject_transaction failed for tx_id={tx_id}: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        return False
    finally:
        try:
            conn.close()
        except Exception:
            pass


def get_pending_transactions() -> list[sqlite3.Row]:
    """Henter alle transaksjoner med status PENDING_HUMAN_APPROVAL."""
    with _get_db() as conn:
        return conn.execute(
            "SELECT tx_id, policy_snapshot_json, created_at FROM go_transactions WHERE status = 'PENDING_HUMAN_APPROVAL'"
        ).fetchall()


# ── Telegram helpers ──────────────────────────────────────────────────────────

def _send_message(chat_id: int, text: str) -> None:
    try:
        requests.post(
            f"{BASE_URL}/sendMessage",
            json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
            timeout=10,
        )
    except Exception as e:
        log.error(f"sendMessage feilet: {e}")


def _get_updates(offset: int) -> list[dict]:
    try:
        resp = requests.get(
            f"{BASE_URL}/getUpdates",
            params={"offset": offset, "timeout": TELEGRAM_TIMEOUT, "allowed_updates": ["message", "callback_query"]},
            timeout=TELEGRAM_TIMEOUT + 5,
        )
        data = resp.json()
        if data.get("ok"):
            return data.get("result", [])
    except Exception as e:
        log.error(f"getUpdates feilet: {e}")
    return []


# ── Command parser ────────────────────────────────────────────────────────────

def _handle_message(msg: dict) -> None:
    """Parser én innkommende Telegram-melding og oppdaterer DB."""
    chat_id = msg.get("chat", {}).get("id")
    text    = (msg.get("text") or "").strip()
    user_id = msg.get("from", {}).get("id")

    # Sikkerhetssjekk: kun admin-brukeren kan godkjenne
    if chat_id != ADMIN_CHAT_ID:
        log.debug(f"Ignorerer melding fra chat_id={chat_id} (ikke admin)")
        return

    lower = text.lower()

    # ── /approve <tx_id>  eller  /approve (godkjenner første ventende) ────────
    if lower.startswith("/approve"):
        parts = text.split(maxsplit=1)
        if len(parts) == 2:
            tx_id = parts[1].strip()
            ok = commit_transaction(tx_id)
            if not ok:
                # Fallback: approval_requests.db (ask_admin-flyten, ikkje go_gate.db)
                ok = _ask_admin_approve(tx_id, admin_id=str(user_id))
                if ok:
                    # commit_transaction() har allereie kalla _trigger_auto_resume viss go_gate.db,
                    # men fallback-stien mangla dette — fiks:
                    _trigger_auto_resume(tx_id)
            reply = f"✅ Transaksjon `{tx_id}` godkjent og satt til COMMITTED." if ok \
                    else f"⚠️ Fant ikke `{tx_id}` med status PENDING."
        else:
            # Godkjenn eldste ventende
            pending = get_pending_transactions()
            if pending:
                tx_id = pending[0]["tx_id"]
                commit_transaction(tx_id)
                reply = f"✅ Eldste ventende transaksjon `{tx_id}` godkjent."
            else:
                reply = "ℹ️ Ingen ventende transaksjoner å godkjenne."
        _send_message(chat_id, reply)

    # ── /go  →  godkjenn alle ventende ────────────────────────────────────────
    elif lower == "/go":
        pending = get_pending_transactions()
        if not pending:
            _send_message(chat_id, "ℹ️ Ingen ventende transaksjoner.")
            return
        approved = []
        for row in pending:
            if commit_transaction(row["tx_id"]):
                approved.append(row["tx_id"])
        ids = ", ".join(f"`{i}`" for i in approved)
        _send_message(chat_id, f"✅ Godkjente {len(approved)} transaksjon(er): {ids}")

    # ── /reject <tx_id>  eller  /deny <tx_id> ────────────────────────────────
    elif lower.startswith("/reject") or lower.startswith("/deny"):
        parts = text.split(maxsplit=1)
        if len(parts) == 2:
            tx_id = parts[1].strip()
            ok = reject_transaction(tx_id)
            if not ok:
                ok = _ask_admin_deny(tx_id, admin_id=str(user_id))
            reply = f"❌ Transaksjon `{tx_id}` avvist." if ok \
                    else f"⚠️ Fant ikke `{tx_id}` med status PENDING."
        else:
            reply = "Bruk: `/deny <tx_id>` eller `/reject <tx_id>`"
        _send_message(chat_id, reply)

    # ── /pending  →  list ventende ────────────────────────────────────────────
    elif lower == "/pending":
        rows = get_pending_transactions()
        if rows:
            lines = [f"• `{r['tx_id']}` — {r['created_at']}" for r in rows]
            _send_message(chat_id, "⏳ *Ventende transaksjoner:*\n" + "\n".join(lines))
        else:
            _send_message(chat_id, "✅ Ingen ventende transaksjoner.")



def _handle_callback_query(cbq: dict) -> None:
    """Parser inline-knapp trykk (✅ GODKJENN / ⛔ AVSLÅ)."""
    user_id  = cbq.get("from", {}).get("id")
    data     = cbq.get("data", "")
    cbq_id   = cbq.get("id")
    chat_id  = cbq.get("message", {}).get("chat", {}).get("id")

    # Bekreft at Telegram fikk klikket (fjerner spinner)
    try:
        requests.post(f"{BASE_URL}/answerCallbackQuery",
                      json={"callback_query_id": cbq_id}, timeout=5)
    except Exception:
        pass

    if user_id != ADMIN_CHAT_ID:
        log.debug(f"Ignorerer callback fra user_id={user_id}")
        return

    if ":" not in data:
        return

    action, tx_id = data.split(":", 1)
    tx_id = tx_id.strip()

    msg_id = cbq.get("message", {}).get("message_id")
    original_text = cbq.get("message", {}).get("text", "")

    if action == "approve":
        ok = commit_transaction(tx_id)
        if not ok:
            ok = _ask_admin_approve(tx_id, admin_id=str(user_id))
            if ok:
                _trigger_auto_resume(tx_id)
        status_line = "\n\n✅ *GODKJENT*" if ok else "\n\n⚠️ Ikkje funnen"
    elif action in ("deny", "reject"):
        ok = reject_transaction(tx_id)
        if not ok:
            ok = _ask_admin_deny(tx_id, admin_id=str(user_id))
        status_line = "\n\n❌ *AVVIST*" if ok else "\n\n⚠️ Ikkje funnen"
    else:
        return

    # Remove inline buttons and append status to original message
    if chat_id and msg_id:
        try:
            requests.post(
                f"{BASE_URL}/editMessageText",
                json={
                    "chat_id": chat_id,
                    "message_id": msg_id,
                    "text": original_text + status_line,
                    "parse_mode": "Markdown",
                },
                timeout=8,
            )
        except Exception as e:
            log.warning(f"editMessageText failed: {e}")
            _send_message(chat_id, status_line.strip())


# ── Main polling loop ─────────────────────────────────────────────────────────

def _poll_loop() -> None:
    log.info("🚀 Go-Gate approval daemon startet")
    offset = 0

    while True:
        try:
            updates = _get_updates(offset)
            for update in updates:
                update_id = update["update_id"]
                offset = update_id + 1
                if _is_duplicate_update(update_id):
                    log.debug(f"[DEDUP] Dropped duplicate update_id={update_id}")
                    continue
                msg = update.get("message")
                if msg:
                    _handle_message(msg)
                cbq = update.get("callback_query")
                if cbq:
                    _handle_callback_query(cbq)
        except Exception as e:
            log.exception(f"Uventet feil i poll-loop: {e}")
            time.sleep(POLL_INTERVAL)
            continue

        time.sleep(POLL_INTERVAL)


# ── Public API ────────────────────────────────────────────────────────────────

def start_approval_daemon() -> threading.Thread:
    """
    Starter daemon-tråden. Kall denne én gang fra main_loop.py.
    Tråden stopper automatisk når hovedprosessen avsluttes.
    """
    if not TELEGRAM_TOKEN:
        raise ValueError(
            "AERIS_GOGATE_TELEGRAM_TOKEN is not set — GO-Gate approval daemon "
            "cannot start. All DANGEROUS actions will be permanently blocked."
        )

    t = threading.Thread(target=_poll_loop, name="GoGateApprovalDaemon", daemon=True)
    t.start()
    log.info(f"GoGateApprovalDaemon kjører (thread id={t.ident})")
    return t


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    log.info("Kjører som standalone — trykk Ctrl+C for å avslutte")
    _poll_loop()   # blokkerende i standalone-modus
