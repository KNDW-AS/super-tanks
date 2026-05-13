"""
Tests for core/memory/shadow_store.py.

Covers proposal creation with classification (sensitive vs. routine
vs. low-confidence), pending listing, approve/reject lifecycle, the
auto-approve sweeper, and TTL-based expiration. The HierarchicalMemoryStore
default root is redirected to tmp, and hybrid_search embedding generation
is stubbed.
"""

import json
import sys
import types
from datetime import datetime, timedelta, timezone

import pytest


@pytest.fixture
def shadow(tmp_path, monkeypatch):
    from core.memory import shadow_store, hierarchical_store

    monkeypatch.setattr(shadow_store, "SHADOW_DB", tmp_path / "shadow.db")
    monkeypatch.setattr(hierarchical_store, "STORE_ROOT", tmp_path / "hm")
    shadow_store._init_db()

    # Stub hybrid_search.store_embedding to a no-op so approve() doesn't
    # try to load embedding models.
    fake_hs = types.ModuleType("core.memory.hybrid_search")
    fake_hs.store_embedding = lambda *a, **kw: None
    monkeypatch.setitem(sys.modules, "core.memory.hybrid_search", fake_hs)

    # Stub audit_log.log_access to silent no-op so propose() doesn't
    # touch the real audit DB at production path.
    fake_audit = types.ModuleType("core.memory.audit_log")
    fake_audit.log_access = lambda **kw: None
    monkeypatch.setitem(sys.modules, "core.memory.audit_log", fake_audit)

    return shadow_store


# ── propose: classification ────────────────────────────────────────────────

class TestProposeClassification:
    def test_high_confidence_create_gets_auto_approve_window(self, shadow):
        result = shadow.propose("zeph", "/family/preferences/lighting",
                                "abstract", "overview",
                                {"k": "v"}, confidence=0.9)
        assert result["status"] == "pending"
        assert result["operation"] == "create"
        assert result["auto_approve_at"] is not None
        # Window is ~24h from now.
        target = datetime.fromisoformat(result["auto_approve_at"])
        diff = target - datetime.now(timezone.utc)
        assert timedelta(hours=23) < diff < timedelta(hours=25)

    def test_low_confidence_auto_rejected(self, shadow):
        result = shadow.propose("zeph", "/family/preferences/x",
                                "a", "b", "c", confidence=0.3)
        assert result["status"] == "auto_rejected"
        assert "Confidence too low" in result["reason"]

    def test_sensitive_path_pending_no_auto_approve(self, shadow):
        result = shadow.propose("zeph", "/family/health/illness",
                                "a", "b", "c", confidence=0.95)
        assert result["status"] == "pending"
        assert result["auto_approve_at"] is None
        assert "Sensitive path" in result["reason"]

    def test_returns_unique_branch_id(self, shadow):
        a = shadow.propose("zeph", "/family/preferences/a", "x", "y", "z",
                           confidence=0.9)
        b = shadow.propose("zeph", "/family/preferences/b", "x", "y", "z",
                           confidence=0.9)
        assert a["branch_id"] != b["branch_id"]


class TestSensitivePathDetection:
    @pytest.mark.parametrize("path", [
        "/family/health/diabetes",
        "/family/finance/account",
        "/system/config/x",
        "/system/passwords",
        "/system/admin/keys",
        "/william/age/info",
    ])
    def test_sensitive(self, shadow, path):
        assert shadow._is_sensitive_path(path) is True

    @pytest.mark.parametrize("path", [
        "/family/preferences/lighting",
        "/family/routines",
        "/aeris/learned/x",
        "/random/path",
    ])
    def test_not_sensitive(self, shadow, path):
        assert shadow._is_sensitive_path(path) is False


# ── get_pending ────────────────────────────────────────────────────────────

class TestGetPending:
    def test_lists_pending_only(self, shadow):
        a = shadow.propose("zeph", "/family/preferences/a", "x", "y", "z",
                           confidence=0.9)
        b = shadow.propose("zeph", "/family/preferences/b", "x", "y", "z",
                           confidence=0.3)  # auto_rejected
        pending = shadow.get_pending()
        branch_ids = {p["branch_id"] for p in pending}
        assert a["branch_id"] in branch_ids
        assert b["branch_id"] not in branch_ids

    def test_ordered_newest_first(self, shadow):
        a = shadow.propose("zeph", "/family/preferences/a", "x", "y", "z",
                           confidence=0.9)
        b = shadow.propose("zeph", "/family/preferences/b", "x", "y", "z",
                           confidence=0.9)
        pending = shadow.get_pending()
        assert pending[0]["branch_id"] == b["branch_id"]
        assert pending[1]["branch_id"] == a["branch_id"]

    def test_limit_respected(self, shadow):
        for i in range(5):
            shadow.propose("zeph", f"/family/preferences/p{i}",
                           "x", "y", "z", confidence=0.9)
        assert len(shadow.get_pending(limit=3)) == 3


# ── approve / reject ───────────────────────────────────────────────────────

class TestApprove:
    def test_merges_into_hierarchical_store(self, shadow):
        r = shadow.propose("zeph", "/family/preferences/lighting",
                           "abs", "ov", {"warm": True}, confidence=0.9)
        result = shadow.approve(r["branch_id"], reviewed_by="william")
        assert result["success"] is True
        # Verify it actually landed in the hierarchical store.
        from core.memory.hierarchical_store import HierarchicalMemoryStore
        store = HierarchicalMemoryStore()
        m = store.read("/family/preferences/lighting")
        assert m is not None
        assert m.l2_full == {"warm": True}

    def test_unknown_branch_id_fails(self, shadow):
        result = shadow.approve("no-such-id")
        assert result["success"] is False
        assert "not found" in result["error"]

    def test_already_approved_cannot_be_reapproved(self, shadow):
        r = shadow.propose("zeph", "/family/preferences/a", "x", "y", "z",
                           confidence=0.9)
        shadow.approve(r["branch_id"])
        result = shadow.approve(r["branch_id"])
        assert result["success"] is False


class TestReject:
    def test_marks_rejected(self, shadow):
        r = shadow.propose("zeph", "/family/preferences/a", "x", "y", "z",
                           confidence=0.9)
        result = shadow.reject(r["branch_id"], reason="not useful")
        assert result["success"] is True

    def test_only_pending_can_be_rejected(self, shadow):
        r = shadow.propose("zeph", "/family/preferences/a", "x", "y", "z",
                           confidence=0.9)
        shadow.approve(r["branch_id"])
        result = shadow.reject(r["branch_id"])
        assert result["success"] is False


# ── process_auto_approvals ─────────────────────────────────────────────────

class TestProcessAutoApprovals:
    def test_approves_proposals_past_their_window(self, shadow):
        r = shadow.propose("zeph", "/family/preferences/a", "x", "y", "z",
                           confidence=0.9)
        # Manually backdate auto_approve_at.
        conn = shadow._get_conn()
        try:
            past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
            conn.execute(
                "UPDATE shadow_proposals SET auto_approve_at=? WHERE branch_id=?",
                (past, r["branch_id"]))
            conn.commit()
        finally:
            conn.close()
        count = shadow.process_auto_approvals()
        assert count == 1
        assert shadow.get_pending() == []

    def test_does_not_approve_proposals_still_in_window(self, shadow):
        shadow.propose("zeph", "/family/preferences/a", "x", "y", "z",
                       confidence=0.9)
        assert shadow.process_auto_approvals() == 0


# ── expire_old_proposals ───────────────────────────────────────────────────

class TestExpireOld:
    def test_expires_past_ttl(self, shadow):
        r = shadow.propose("zeph", "/family/preferences/a", "x", "y", "z",
                           confidence=0.9)
        conn = shadow._get_conn()
        try:
            old = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
            conn.execute(
                "UPDATE shadow_proposals SET created_at=? WHERE branch_id=?",
                (old, r["branch_id"]))
            conn.commit()
        finally:
            conn.close()
        affected = shadow.expire_old_proposals()
        assert affected == 1
        assert shadow.get_pending() == []

    def test_keeps_proposals_within_ttl(self, shadow):
        shadow.propose("zeph", "/family/preferences/a", "x", "y", "z",
                       confidence=0.9)
        assert shadow.expire_old_proposals() == 0
