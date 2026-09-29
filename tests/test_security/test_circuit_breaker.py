"""Layer 7 — core/security/circuit_breaker.py (fail-closed port)."""

import sqlite3
import time

import pytest

from core.security import circuit_breaker as cb
from core.security.circuit_breaker import CircuitBreaker, CircuitBreakerError


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = tmp_path / "cb.db"
    monkeypatch.setattr(cb, "DB_PATH", path)
    cb.reset_breakers()
    yield path
    cb.reset_breakers()


def test_allows_until_budget_then_trips(db):
    br = CircuitBreaker("a", max_actions=3, window_seconds=60, lockout_seconds=60, db_path=db)
    for _ in range(3):
        assert br.check_and_record("t") is True
    with pytest.raises(CircuitBreakerError) as exc:
        br.check_and_record("t")
    assert exc.value.locked_until > time.time()
    assert br.get_status()["is_locked"] is True


def test_lockout_persists_across_instances(db):
    CircuitBreaker("a", max_actions=1, db_path=db).check_and_record("t")
    with pytest.raises(CircuitBreakerError):
        CircuitBreaker("a", max_actions=1, db_path=db).check_and_record("t")
    # A fresh instance (e.g. after a restart) still sees the lockout,
    # even with a bigger budget.
    with pytest.raises(CircuitBreakerError):
        CircuitBreaker("a", max_actions=100, db_path=db).check_and_record("t")


def test_weights_consume_budget(db):
    br = CircuitBreaker("a", max_actions=5, db_path=db)
    br.check_and_record("t", weight=3.0)
    with pytest.raises(CircuitBreakerError):
        br.check_and_record("t", weight=3.0)


def test_agents_are_independent(db):
    CircuitBreaker("a", max_actions=1, db_path=db).check_and_record("t")
    assert CircuitBreaker("b", max_actions=1, db_path=db).check_and_record("t")


def test_window_expiry_frees_budget(db, monkeypatch):
    br = CircuitBreaker("a", max_actions=1, window_seconds=10, db_path=db)
    now = [1000.0]
    monkeypatch.setattr(cb.time, "time", lambda: now[0])
    br.check_and_record("t")
    now[0] += 11
    assert br.check_and_record("t") is True


def test_lockout_expires(db, monkeypatch):
    br = CircuitBreaker("a", max_actions=1, window_seconds=10, lockout_seconds=30, db_path=db)
    now = [1000.0]
    monkeypatch.setattr(cb.time, "time", lambda: now[0])
    br.check_and_record("t")
    with pytest.raises(CircuitBreakerError):
        br.check_and_record("t")
    now[0] += 31
    assert br.check_and_record("t") is True


def test_reset_clears_lockout_and_calls_hook(db, monkeypatch):
    events = []
    monkeypatch.setattr(cb, "alert_hook", lambda e, a, d: events.append((e, a)))
    br = CircuitBreaker("a", max_actions=1, db_path=db)
    br.check_and_record("t")
    with pytest.raises(CircuitBreakerError):
        br.check_and_record("t")
    br.reset("reviewed")
    assert br.check_and_record("t") is True
    assert events == [("lockout", "a"), ("reset", "a")]


def test_hook_failure_does_not_change_decision(db, monkeypatch):
    def boom(*_):
        raise RuntimeError("pager down")
    monkeypatch.setattr(cb, "alert_hook", boom)
    br = CircuitBreaker("a", max_actions=1, db_path=db)
    br.check_and_record("t")
    with pytest.raises(CircuitBreakerError):
        br.check_and_record("t")


def test_db_error_fails_closed(db, monkeypatch):
    br = CircuitBreaker("a", db_path=db)

    def broken(*_a, **_k):
        raise sqlite3.OperationalError("disk I/O error")
    monkeypatch.setattr(cb, "open_db", broken)
    with pytest.raises(sqlite3.OperationalError):
        br.check_and_record("t")


def test_get_breaker_follows_db_path_and_defaults(db, monkeypatch, tmp_path):
    first = cb.get_breaker("a")
    assert first is cb.get_breaker("a")
    assert first.db_path == db
    monkeypatch.setattr(CircuitBreaker, "DEFAULT_MAX_ACTIONS", 7)
    cb.reset_breakers()
    assert cb.get_breaker("a").max_actions == 7
    monkeypatch.setattr(cb, "DB_PATH", tmp_path / "other.db")
    assert cb.get_breaker("a").db_path == tmp_path / "other.db"


def test_check_records_nothing_but_denies_when_locked(db):
    br = CircuitBreaker("a", max_actions=2, db_path=db)
    for _ in range(5):
        br.check("t")
    assert br.get_status()["load_in_window"] == 0
    br.check_and_record("t")
    br.check_and_record("t")
    with pytest.raises(CircuitBreakerError):
        br.check("t")                       # over budget → trips lockout
    assert br.get_status()["is_locked"] is True
    with pytest.raises(CircuitBreakerError):
        br.check("t")


def test_concurrent_first_use_on_fresh_db(tmp_path):
    import threading
    path = tmp_path / "fresh.db"
    admitted, errors = [], []

    def worker():
        try:
            CircuitBreaker("conc", max_actions=10, db_path=path).check_and_record("t")
            admitted.append(1)
        except CircuitBreakerError:
            pass
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))
    threads = [threading.Thread(target=worker) for _ in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert len(admitted) == 10
