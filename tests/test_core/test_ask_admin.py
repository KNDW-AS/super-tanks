"""
Tests for core/ask_admin.py.

Covers the ApprovalRequest dataclass, the SQLite-backed ApprovalStore
(create, get, duplicate detection, approval re-use, approve/deny/expire),
and the policy dispatcher `check_tool_permission`. The Iron-Link
Telegram flow depends on external modules (telegram_bot, zeph_state,
succession_store) and is not tested here.
"""

import time

import pytest

from core.ask_admin import (
    ApprovalRequest, ApprovalStatus, ApprovalStore,
    check_tool_permission, get_request_status, get_approval_receipt,
)
from core import ask_admin


@pytest.fixture
def store(tmp_path):
    return ApprovalStore(db_path=str(tmp_path / "approvals.db"))


@pytest.fixture
def fresh_singleton(tmp_path, monkeypatch):
    """Reset the module-level _approval_store singleton with a tmp path."""
    monkeypatch.setattr(ask_admin, "_approval_store",
                        ApprovalStore(db_path=str(tmp_path / "approvals.db")))
    return ask_admin._approval_store


# ── ApprovalRequest dataclass ──────────────────────────────────────────────

class TestApprovalRequest:
    def _make(self, expires_in=300):
        return ApprovalRequest(
            request_id="abc12345",
            tool_name="shell_exec",
            user_id="zeph",
            reason="install",
            args_hash="dead", args_len=10,
            status=ApprovalStatus.PENDING,
            created_at=time.time(),
            expires_at=time.time() + expires_in,
        )

    def test_to_dict_round_trip(self):
        r = self._make()
        d = r.to_dict()
        assert d["status"] == "pending"
        r2 = ApprovalRequest.from_dict(d)
        assert r2.request_id == r.request_id
        assert r2.status == ApprovalStatus.PENDING

    def test_is_expired_false_when_in_future(self):
        assert self._make(expires_in=300).is_expired() is False

    def test_is_expired_true_when_past(self):
        r = self._make(expires_in=-10)
        assert r.is_expired() is True

    def test_time_remaining_clamped_at_zero(self):
        r = self._make(expires_in=-100)
        assert r.time_remaining() == 0


# ── ApprovalStore: create / get ────────────────────────────────────────────

class TestStoreCreateGet:
    def test_creates_with_short_request_id(self, store):
        req = store.create_request("shell_exec", "zeph", "reason", {"a": 1})
        assert len(req.request_id) == 8
        assert req.status == ApprovalStatus.PENDING
        assert req.tool_name == "shell_exec"

    def test_can_get_back_by_id(self, store):
        req = store.create_request("shell_exec", "zeph", "reason", {"a": 1})
        fetched = store.get_request(req.request_id)
        assert fetched.request_id == req.request_id
        assert fetched.tool_name == "shell_exec"

    def test_get_unknown_returns_none(self, store):
        assert store.get_request("no-such-id") is None

    def test_args_are_hashed_deterministically(self, store):
        r1 = store.create_request("t", "u", "x", {"b": 2, "a": 1})
        r2 = store.create_request("t", "u", "x", {"a": 1, "b": 2})
        assert r1.args_hash == r2.args_hash

    def test_raw_params_stored_for_display(self, store):
        req = store.create_request("t", "u", "x", {"cmd": "ls -la"})
        fetched = store.get_request(req.request_id)
        assert "ls -la" in fetched.raw_params

    def test_raw_params_truncated_when_huge(self, store):
        huge = {"data": "X" * 10_000}
        req = store.create_request("t", "u", "x", huge)
        fetched = store.get_request(req.request_id)
        assert "truncated" in fetched.raw_params
        assert len(fetched.raw_params) <= 4050

    def test_ttl_default_is_300_seconds(self, store):
        req = store.create_request("t", "u", "x", {})
        assert req.expires_at - req.created_at == pytest.approx(300, abs=1)

    def test_custom_ttl_respected(self, store):
        req = store.create_request("t", "u", "x", {}, ttl_seconds=60)
        assert req.expires_at - req.created_at == pytest.approx(60, abs=1)


# ── Duplicate detection ────────────────────────────────────────────────────

class TestFindPendingDuplicate:
    def test_finds_matching_pending(self, store):
        first = store.create_request("t", "u", "x", {"a": 1})
        dup = store.find_pending_duplicate("t", "u", {"a": 1})
        assert dup is not None
        assert dup.request_id == first.request_id

    def test_different_args_not_dup(self, store):
        store.create_request("t", "u", "x", {"a": 1})
        assert store.find_pending_duplicate("t", "u", {"a": 2}) is None

    def test_different_user_not_dup(self, store):
        store.create_request("t", "u1", "x", {"a": 1})
        assert store.find_pending_duplicate("t", "u2", {"a": 1}) is None

    def test_expired_not_dup(self, store):
        store.create_request("t", "u", "x", {"a": 1}, ttl_seconds=-1)
        # Wait until clock advances past expires_at (it's already past).
        time.sleep(0.01)
        assert store.find_pending_duplicate("t", "u", {"a": 1}) is None

    def test_approved_request_not_returned_as_pending_dup(self, store):
        req = store.create_request("t", "u", "x", {"a": 1})
        store.approve_request(req.request_id, admin_id="william")
        assert store.find_pending_duplicate("t", "u", {"a": 1}) is None


# ── Approval re-use ────────────────────────────────────────────────────────

class TestFindApprovedRequest:
    def test_returns_recent_approval(self, store):
        req = store.create_request("t", "u", "x", {"a": 1})
        store.approve_request(req.request_id, admin_id="william")
        found = store.find_approved_request("t", "u", {"a": 1})
        assert found is not None
        assert found.request_id == req.request_id

    def test_older_than_window_excluded(self, store):
        req = store.create_request("t", "u", "x", {"a": 1})
        store.approve_request(req.request_id, admin_id="william")
        # Manually backdate resolved_at far in the past.
        conn = store._get_conn()
        try:
            conn.execute(
                "UPDATE approval_requests SET resolved_at=? WHERE request_id=?",
                (time.time() - 10_000, req.request_id))
        finally:
            conn.close()
        found = store.find_approved_request("t", "u", {"a": 1},
                                            max_age_seconds=3600)
        assert found is None


# ── approve_request / deny_request ─────────────────────────────────────────

class TestApproveDeny:
    def test_approve_sets_status_and_admin(self, store):
        req = store.create_request("t", "u", "x", {})
        assert store.approve_request(req.request_id, "william") is True
        fetched = store.get_request(req.request_id)
        assert fetched.status == ApprovalStatus.APPROVED
        assert fetched.resolved_by == "william"

    def test_approve_fails_when_not_pending(self, store):
        req = store.create_request("t", "u", "x", {})
        store.approve_request(req.request_id, "william")
        assert store.approve_request(req.request_id, "william") is False

    def test_approve_fails_when_expired(self, store):
        req = store.create_request("t", "u", "x", {}, ttl_seconds=-1)
        time.sleep(0.01)
        assert store.approve_request(req.request_id, "william") is False

    def test_approve_unknown_request_fails(self, store):
        assert store.approve_request("no-such", "william") is False

    def test_deny_sets_status(self, store):
        req = store.create_request("t", "u", "x", {})
        assert store.deny_request(req.request_id, "william") is True
        fetched = store.get_request(req.request_id)
        assert fetched.status == ApprovalStatus.DENIED

    def test_deny_fails_when_already_denied(self, store):
        req = store.create_request("t", "u", "x", {})
        store.deny_request(req.request_id, "william")
        assert store.deny_request(req.request_id, "william") is False


# ── expire_old_requests ────────────────────────────────────────────────────

class TestExpireOldRequests:
    def test_marks_expired_only(self, store):
        live = store.create_request("t", "u", "x", {}, ttl_seconds=300)
        dead = store.create_request("t", "u", "y", {}, ttl_seconds=-10)
        time.sleep(0.01)
        count = store.expire_old_requests()
        assert count == 1
        assert store.get_request(live.request_id).status == ApprovalStatus.PENDING
        assert store.get_request(dead.request_id).status == ApprovalStatus.EXPIRED

    def test_returns_zero_when_nothing_expired(self, store):
        store.create_request("t", "u", "x", {})
        assert store.expire_old_requests() == 0


# ── check_tool_permission ──────────────────────────────────────────────────

class TestCheckToolPermission:
    def test_allow_policy_passes_through(self, fresh_singleton):
        allowed, req_id, status = check_tool_permission(
            "ha_search", "aeris", {},
            policy_config={"tools": {"ha_search": {"permission": "allow"}}})
        assert allowed is True
        assert req_id is None
        assert status == "allowed"

    def test_unknown_tool_defaults_to_allow(self, fresh_singleton):
        allowed, req_id, status = check_tool_permission(
            "wholly_new", "aeris", {}, policy_config={"tools": {}})
        assert allowed is True
        assert status == "allowed"

    def test_ask_admin_creates_pending(self, fresh_singleton):
        allowed, req_id, status = check_tool_permission(
            "shell_exec", "zeph", {"cmd": "rm"},
            policy_config={"tools": {"shell_exec": {"permission": "ask_admin"}}})
        assert allowed is False
        assert req_id is not None
        assert status == "PAUSED_FOR_APPROVAL"

    def test_duplicate_request_returns_existing(self, fresh_singleton):
        policy = {"tools": {"shell_exec": {"permission": "ask_admin"}}}
        a, id_a, _ = check_tool_permission("shell_exec", "zeph",
                                           {"cmd": "rm"}, policy)
        b, id_b, status_b = check_tool_permission("shell_exec", "zeph",
                                                  {"cmd": "rm"}, policy)
        assert id_b == id_a
        assert status_b == "PAUSED_FOR_APPROVAL_DUPLICATE"

    def test_recent_approval_reused(self, fresh_singleton):
        policy = {"tools": {"shell_exec": {"permission": "ask_admin"}}}
        _, rid, _ = check_tool_permission("shell_exec", "zeph", {"cmd": "rm"}, policy)
        fresh_singleton.approve_request(rid, admin_id="william")
        allowed, rid2, status = check_tool_permission(
            "shell_exec", "zeph", {"cmd": "rm"}, policy)
        assert allowed is True
        assert rid2 == rid
        assert status == "approved"


# ── get_request_status / get_approval_receipt ──────────────────────────────

class TestRequestStatus:
    def test_returns_none_for_unknown(self, fresh_singleton):
        assert get_request_status("missing") is None

    def test_pending_status(self, fresh_singleton):
        req = fresh_singleton.create_request("t", "u", "x", {})
        status = get_request_status(req.request_id)
        assert status["status"] == "pending"
        assert status["is_expired"] is False

    def test_approved_status_includes_receipt(self, fresh_singleton):
        req = fresh_singleton.create_request("t", "u", "x", {})
        fresh_singleton.approve_request(req.request_id, "william")
        status = get_request_status(req.request_id)
        assert status["status"] == "approved"
        assert status["receipt"]["approved_by"] == "william"

    def test_approval_receipt_only_for_approved(self, fresh_singleton):
        req = fresh_singleton.create_request("t", "u", "x", {})
        assert get_approval_receipt(req.request_id) is None
        fresh_singleton.approve_request(req.request_id, "william")
        receipt = get_approval_receipt(req.request_id)
        assert receipt is not None
        assert receipt["status"] == "APPROVED"
