"""
Tests for core/security/dispatch_audit.py.

Verifies the gateway-level dispatch log: schema bootstrap, row
recording, correlation_id ContextVar, history queries by
correlation_id / agent_id, and graceful handling of DB failures.
"""

import asyncio
import sqlite3

import pytest


@pytest.fixture
def audit(tmp_path, monkeypatch):
    from core.security import dispatch_audit
    monkeypatch.setattr(dispatch_audit, "DB_PATH", tmp_path / "dispatch.db")
    monkeypatch.setattr(dispatch_audit, "_initialised", False)
    return dispatch_audit


# ── new_correlation_id / ContextVar ────────────────────────────────────────

class TestCorrelationId:
    def test_each_call_produces_unique_id(self, audit):
        a = audit.new_correlation_id()
        b = audit.new_correlation_id()
        assert a != b
        # UUID4 → 36-char with dashes
        assert len(a) == 36

    def test_context_var_default_none(self, audit):
        assert audit.current_correlation_id.get() is None

    def test_context_var_set_visible_to_caller_in_same_context(self, audit):
        token = audit.current_correlation_id.set("test-corr-id")
        try:
            assert audit.current_correlation_id.get() == "test-corr-id"
        finally:
            audit.current_correlation_id.reset(token)

    def test_context_var_isolates_concurrent_async_tasks(self, audit):
        # ContextVar (vs threading.local) means each asyncio task sees
        # its own value — concurrent dispatches don't pollute each other.
        async def task_with(value):
            token = audit.current_correlation_id.set(value)
            try:
                await asyncio.sleep(0)  # yield to other tasks
                assert audit.current_correlation_id.get() == value
            finally:
                audit.current_correlation_id.reset(token)

        async def all_tasks():
            await asyncio.gather(
                task_with("alpha"),
                task_with("beta"),
                task_with("gamma"),
            )
        asyncio.run(all_tasks())


# ── record_dispatch / get_dispatch_history ─────────────────────────────────

class TestRecordDispatch:
    def test_basic_round_trip(self, audit):
        audit.record_dispatch(
            correlation_id="corr-1", agent_id="aeris", tool_name="ha_search",
            agent_role="READ", verdict="allowed",
            result_success=True, error=None,
        )
        rows = audit.get_dispatch_history(correlation_id="corr-1")
        assert len(rows) == 1
        r = rows[0]
        assert r["agent_id"] == "aeris"
        assert r["tool_name"] == "ha_search"
        assert r["verdict"] == "allowed"
        assert r["result_success"] == 1
        assert r["error"] is None

    def test_failed_dispatch_recorded(self, audit):
        audit.record_dispatch(
            correlation_id="corr-2", agent_id="aeris", tool_name="shell_exec",
            agent_role="READ", verdict="denied_role",
            result_success=False, error="Access denied",
        )
        r = audit.get_dispatch_history(correlation_id="corr-2")[0]
        assert r["verdict"] == "denied_role"
        assert r["result_success"] == 0
        assert "Access denied" in r["error"]

    def test_no_wrapper_dispatch_recorded(self, audit):
        # When get_tool returns None, we still record the dispatch so
        # the history is complete.
        audit.record_dispatch(
            correlation_id="corr-3", agent_id="aeris", tool_name="unknown",
            agent_role="READ", verdict="no_wrapper",
            result_success=None, error=None,
        )
        r = audit.get_dispatch_history(correlation_id="corr-3")[0]
        assert r["verdict"] == "no_wrapper"
        assert r["result_success"] is None

    def test_multiple_rows_under_same_correlation_id(self, audit):
        # Useful for tracking a chained operation: dispatch → side
        # effect → secondary dispatch all under one corr_id.
        for i, tool in enumerate(("ha_search", "memory_read", "notify_home")):
            audit.record_dispatch(
                correlation_id="incident-x", agent_id="aeris",
                tool_name=tool, agent_role="READ", verdict="allowed",
                result_success=True,
            )
        rows = audit.get_dispatch_history(correlation_id="incident-x")
        assert [r["tool_name"] for r in rows] == [
            "ha_search", "memory_read", "notify_home"
        ]

    def test_per_agent_history_newest_first(self, audit):
        for i in range(5):
            audit.record_dispatch(
                correlation_id=f"c-{i}", agent_id="zeph",
                tool_name=f"tool-{i}", agent_role="EXEC",
                verdict="allowed", result_success=True,
            )
        rows = audit.get_dispatch_history(agent_id="zeph")
        # Newest (c-4) first, oldest (c-0) last.
        assert [r["correlation_id"] for r in rows] == [
            "c-4", "c-3", "c-2", "c-1", "c-0",
        ]

    def test_system_wide_tail(self, audit):
        for agent in ("aeris", "zeph", "system"):
            audit.record_dispatch(
                correlation_id=f"c-{agent}", agent_id=agent,
                tool_name="ha_search", agent_role="READ",
                verdict="allowed", result_success=True,
            )
        rows = audit.get_dispatch_history(limit=10)
        agents = {r["agent_id"] for r in rows}
        assert agents == {"aeris", "zeph", "system"}


# ── Schema + isolation ────────────────────────────────────────────────────

class TestSchema:
    def test_table_created_on_first_use(self, audit):
        # Force lazy init via a record call.
        audit.record_dispatch(
            correlation_id="x", agent_id="a", tool_name="t",
            agent_role="READ", verdict="allowed",
        )
        conn = sqlite3.connect(str(audit.DB_PATH))
        try:
            row = conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name='dispatch_log'"
            ).fetchone()
            assert row is not None
        finally:
            conn.close()

    def test_indexes_exist(self, audit):
        audit.record_dispatch(
            correlation_id="x", agent_id="a", tool_name="t",
            agent_role="READ", verdict="allowed",
        )
        conn = sqlite3.connect(str(audit.DB_PATH))
        try:
            indexes = {row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()}
            assert "idx_dispatch_corr" in indexes
            assert "idx_dispatch_agent_ts" in indexes
        finally:
            conn.close()

    def test_query_filters_to_correlation_id_only(self, audit):
        audit.record_dispatch("c-A", "aeris", "t", "READ", "allowed", True)
        audit.record_dispatch("c-B", "aeris", "t", "READ", "allowed", True)
        rows = audit.get_dispatch_history(correlation_id="c-A")
        assert len(rows) == 1
        assert rows[0]["correlation_id"] == "c-A"


# ── Robustness ────────────────────────────────────────────────────────────

class TestRobustness:
    def test_record_does_not_raise_on_db_error(self, audit, monkeypatch):
        # If the DB write fails, the dispatch path should still complete.
        def boom(*a, **kw):
            raise sqlite3.OperationalError("disk full")

        monkeypatch.setattr(audit, "_open", boom)
        # Must not raise.
        audit.record_dispatch(
            correlation_id="x", agent_id="a", tool_name="t",
            agent_role="READ", verdict="allowed",
        )

    def test_query_returns_empty_on_db_error(self, audit, monkeypatch):
        def boom(*a, **kw):
            raise sqlite3.OperationalError("disk full")

        monkeypatch.setattr(audit, "_open", boom)
        assert audit.get_dispatch_history() == []
