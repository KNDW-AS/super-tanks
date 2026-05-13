"""
Tests for core/go_gate_approval_daemon.py.

Exercises the SQLite transaction-state machine (PENDING_HUMAN_APPROVAL
→ COMMITTED / ABORTED), the dedup cache for Telegram update_ids, and
the message + callback handlers. All Telegram and auto-resume side
effects are stubbed.
"""

import sys
import types

import pytest


@pytest.fixture
def daemon(tmp_path, monkeypatch):
    """Build a fully stubbed daemon module pointing at an isolated DB."""
    from core import go_gate_approval_daemon as d

    # Redirect DB.
    db_path = tmp_path / "go_gate.db"
    monkeypatch.setattr(d, "DB_PATH", str(db_path))
    monkeypatch.setattr(d, "ADMIN_CHAT_ID", 12345)

    # Initialise schema.
    conn = d._get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS go_transactions (
            tx_id TEXT PRIMARY KEY,
            policy_snapshot_json TEXT,
            status TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            approved_at TEXT,
            approved_by TEXT,
            approval_type TEXT
        )
    """)
    conn.commit()
    conn.close()

    # Reset dedup cache.
    monkeypatch.setattr(d, "_processed_update_ids", set())

    # Capture sent Telegram messages.
    posts = []

    def fake_post(url, *a, **kw):
        posts.append((url, kw.get("json", {})))
        return types.SimpleNamespace(json=lambda: {"ok": True}, status_code=200)

    def fake_get(url, *a, **kw):
        return types.SimpleNamespace(
            json=lambda: {"ok": True, "result": []}, status_code=200)

    monkeypatch.setattr(d.requests, "post", fake_post)
    monkeypatch.setattr(d.requests, "get", fake_get)

    # Stub auto-resume to avoid background threads.
    resume_calls = []
    monkeypatch.setattr(d, "_trigger_auto_resume",
                        lambda tx_id: resume_calls.append(tx_id))

    # Stub ask_admin store with controllable returns.
    ask_admin_calls = {"approve": [], "deny": []}
    fake_store = types.SimpleNamespace(
        approve_request=lambda req_id, admin_id: (
            ask_admin_calls["approve"].append((req_id, admin_id)) or True),
        deny_request=lambda req_id, admin_id: (
            ask_admin_calls["deny"].append((req_id, admin_id)) or True),
    )
    fake_ask_admin = types.ModuleType("core.ask_admin")
    fake_ask_admin.get_approval_store = lambda: fake_store
    monkeypatch.setitem(sys.modules, "core.ask_admin", fake_ask_admin)

    return types.SimpleNamespace(
        d=d, db_path=db_path, posts=posts,
        resume_calls=resume_calls, ask_admin_calls=ask_admin_calls,
    )


def _insert_pending(daemon, tx_id):
    conn = daemon.d._get_db()
    conn.execute(
        "INSERT INTO go_transactions (tx_id, status) "
        "VALUES (?, 'PENDING_HUMAN_APPROVAL')", (tx_id,))
    conn.commit()
    conn.close()


# ── _is_duplicate_update ───────────────────────────────────────────────────

class TestDedupCache:
    def test_first_seen_is_not_duplicate(self, daemon):
        assert daemon.d._is_duplicate_update(100) is False

    def test_second_seen_is_duplicate(self, daemon):
        daemon.d._is_duplicate_update(100)
        assert daemon.d._is_duplicate_update(100) is True

    def test_distinct_ids_independent(self, daemon):
        daemon.d._is_duplicate_update(100)
        assert daemon.d._is_duplicate_update(200) is False

    def test_cache_prunes_when_oversized(self, daemon, monkeypatch):
        for i in range(600):
            daemon.d._is_duplicate_update(i)
        # After 600 inserts, cache should have been pruned to <=350.
        assert len(daemon.d._processed_update_ids) <= 400


# ── commit_transaction / reject_transaction ────────────────────────────────

class TestCommitTransaction:
    def test_commits_pending_row(self, daemon):
        _insert_pending(daemon, "tx-1")
        assert daemon.d.commit_transaction("tx-1") is True
        conn = daemon.d._get_db()
        row = conn.execute(
            "SELECT status FROM go_transactions WHERE tx_id=?", ("tx-1",)
        ).fetchone()
        conn.close()
        assert row["status"] == "COMMITTED"

    def test_returns_false_for_unknown(self, daemon):
        assert daemon.d.commit_transaction("missing") is False

    def test_returns_false_if_not_pending(self, daemon):
        _insert_pending(daemon, "tx-1")
        daemon.d.commit_transaction("tx-1")
        # Second commit on already-COMMITTED row is a no-op.
        assert daemon.d.commit_transaction("tx-1") is False

    def test_triggers_auto_resume_and_ask_admin_sync(self, daemon):
        _insert_pending(daemon, "tx-1")
        daemon.d.commit_transaction("tx-1")
        assert daemon.resume_calls == ["tx-1"]
        assert daemon.ask_admin_calls["approve"][0][0] == "tx-1"


class TestRejectTransaction:
    def test_aborts_pending_row(self, daemon):
        _insert_pending(daemon, "tx-1")
        assert daemon.d.reject_transaction("tx-1") is True
        conn = daemon.d._get_db()
        row = conn.execute(
            "SELECT status, approved_by FROM go_transactions WHERE tx_id=?",
            ("tx-1",)).fetchone()
        conn.close()
        assert row["status"] == "ABORTED"
        assert "rejected" in row["approved_by"]

    def test_returns_false_for_unknown(self, daemon):
        assert daemon.d.reject_transaction("missing") is False


class TestGetPendingTransactions:
    def test_empty_when_none(self, daemon):
        assert daemon.d.get_pending_transactions() == []

    def test_returns_only_pending(self, daemon):
        _insert_pending(daemon, "tx-1")
        _insert_pending(daemon, "tx-2")
        daemon.d.commit_transaction("tx-1")
        rows = daemon.d.get_pending_transactions()
        tx_ids = {r["tx_id"] for r in rows}
        assert tx_ids == {"tx-2"}


# ── _handle_message: command parser ────────────────────────────────────────

class TestHandleMessage:
    def _msg(self, text, chat_id=12345, user_id=12345):
        return {"chat": {"id": chat_id}, "from": {"id": user_id}, "text": text}

    def test_non_admin_ignored(self, daemon):
        _insert_pending(daemon, "tx-1")
        daemon.d._handle_message(self._msg("/approve tx-1", chat_id=9999))
        # Status unchanged.
        conn = daemon.d._get_db()
        row = conn.execute(
            "SELECT status FROM go_transactions WHERE tx_id=?", ("tx-1",)
        ).fetchone()
        conn.close()
        assert row["status"] == "PENDING_HUMAN_APPROVAL"

    def test_approve_specific_tx(self, daemon):
        _insert_pending(daemon, "tx-1")
        daemon.d._handle_message(self._msg("/approve tx-1"))
        conn = daemon.d._get_db()
        row = conn.execute(
            "SELECT status FROM go_transactions WHERE tx_id=?", ("tx-1",)
        ).fetchone()
        conn.close()
        assert row["status"] == "COMMITTED"

    def test_approve_without_id_picks_first(self, daemon):
        _insert_pending(daemon, "tx-A")
        _insert_pending(daemon, "tx-B")
        daemon.d._handle_message(self._msg("/approve"))
        # First pending should be committed.
        pending = daemon.d.get_pending_transactions()
        assert len(pending) == 1

    def test_go_commits_all(self, daemon):
        for tx in ("a", "b", "c"):
            _insert_pending(daemon, tx)
        daemon.d._handle_message(self._msg("/go"))
        assert daemon.d.get_pending_transactions() == []

    def test_deny_specific_tx(self, daemon):
        _insert_pending(daemon, "tx-1")
        daemon.d._handle_message(self._msg("/deny tx-1"))
        conn = daemon.d._get_db()
        row = conn.execute(
            "SELECT status FROM go_transactions WHERE tx_id=?", ("tx-1",)
        ).fetchone()
        conn.close()
        assert row["status"] == "ABORTED"

    def test_reject_specific_tx(self, daemon):
        _insert_pending(daemon, "tx-1")
        daemon.d._handle_message(self._msg("/reject tx-1"))
        conn = daemon.d._get_db()
        row = conn.execute(
            "SELECT status FROM go_transactions WHERE tx_id=?", ("tx-1",)
        ).fetchone()
        conn.close()
        assert row["status"] == "ABORTED"

    def test_pending_command_sends_list(self, daemon):
        _insert_pending(daemon, "tx-X")
        daemon.d._handle_message(self._msg("/pending"))
        assert daemon.posts  # at least one outbound message
        last_text = daemon.posts[-1][1]["text"]
        assert "tx-X" in last_text

    def test_pending_command_when_empty(self, daemon):
        daemon.d._handle_message(self._msg("/pending"))
        last_text = daemon.posts[-1][1]["text"]
        assert "Ingen" in last_text

    def test_approve_unknown_falls_back_to_ask_admin(self, daemon):
        # No matching row in go_transactions → commit returns False.
        daemon.d._handle_message(self._msg("/approve unknown-tx"))
        assert daemon.ask_admin_calls["approve"][0][0] == "unknown-tx"
        assert daemon.resume_calls[-1] == "unknown-tx"


# ── _handle_callback_query ─────────────────────────────────────────────────

class TestCallbackQuery:
    def _cbq(self, data, user_id=12345):
        return {
            "id": "cbq-1",
            "from": {"id": user_id},
            "data": data,
            "message": {
                "message_id": 99,
                "chat": {"id": 12345},
                "text": "Original text",
            },
        }

    def test_non_admin_ignored(self, daemon):
        _insert_pending(daemon, "tx-1")
        daemon.d._handle_callback_query(self._cbq("approve:tx-1",
                                                  user_id=9999))
        conn = daemon.d._get_db()
        row = conn.execute(
            "SELECT status FROM go_transactions WHERE tx_id=?", ("tx-1",)
        ).fetchone()
        conn.close()
        assert row["status"] == "PENDING_HUMAN_APPROVAL"

    def test_approve_callback_commits(self, daemon):
        _insert_pending(daemon, "tx-1")
        daemon.d._handle_callback_query(self._cbq("approve:tx-1"))
        conn = daemon.d._get_db()
        row = conn.execute(
            "SELECT status FROM go_transactions WHERE tx_id=?", ("tx-1",)
        ).fetchone()
        conn.close()
        assert row["status"] == "COMMITTED"

    def test_deny_callback_aborts(self, daemon):
        _insert_pending(daemon, "tx-1")
        daemon.d._handle_callback_query(self._cbq("deny:tx-1"))
        conn = daemon.d._get_db()
        row = conn.execute(
            "SELECT status FROM go_transactions WHERE tx_id=?", ("tx-1",)
        ).fetchone()
        conn.close()
        assert row["status"] == "ABORTED"

    def test_malformed_data_ignored(self, daemon):
        _insert_pending(daemon, "tx-1")
        daemon.d._handle_callback_query(self._cbq("no_colon_here"))
        # No status change.
        conn = daemon.d._get_db()
        row = conn.execute(
            "SELECT status FROM go_transactions WHERE tx_id=?", ("tx-1",)
        ).fetchone()
        conn.close()
        assert row["status"] == "PENDING_HUMAN_APPROVAL"


# ── start_approval_daemon ──────────────────────────────────────────────────

class TestStartDaemon:
    def test_raises_when_token_missing(self, monkeypatch):
        from core import go_gate_approval_daemon as d
        monkeypatch.setattr(d, "TELEGRAM_TOKEN", None)
        with pytest.raises(ValueError, match="TELEGRAM_TOKEN"):
            d.start_approval_daemon()
