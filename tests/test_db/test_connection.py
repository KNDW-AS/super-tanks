"""
Tests for core/db/connection.py.

The wrapper ensures every SQLite connection in the project gets WAL
mode and a 15s busy_timeout. These tests verify both defaults and the
keyword-argument pass-through.
"""

import sqlite3


from core.db.connection import open_db


class TestOpenDb:
    def test_returns_sqlite_connection(self, tmp_path):
        conn = open_db(tmp_path / "x.db")
        try:
            assert isinstance(conn, sqlite3.Connection)
        finally:
            conn.close()

    def test_wal_journal_mode_enabled(self, tmp_path):
        conn = open_db(tmp_path / "x.db")
        try:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            assert mode.lower() == "wal"
        finally:
            conn.close()

    def test_busy_timeout_configured(self, tmp_path):
        conn = open_db(tmp_path / "x.db")
        try:
            timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]
            assert timeout == 15_000
        finally:
            conn.close()

    def test_default_python_timeout(self, tmp_path, monkeypatch):
        # We can't read the python-side timeout directly, but we can
        # verify the kwarg default is applied by overriding sqlite3.connect.
        captured = {}
        real_connect = sqlite3.connect

        def spy(path, *args, **kwargs):
            captured.update(kwargs)
            return real_connect(path, *args, **kwargs)

        monkeypatch.setattr(sqlite3, "connect", spy)
        conn = open_db(tmp_path / "x.db")
        try:
            assert captured["timeout"] == 15
        finally:
            conn.close()

    def test_explicit_kwargs_passed_through(self, tmp_path):
        conn = open_db(tmp_path / "x.db", isolation_level=None,
                       check_same_thread=False)
        try:
            assert conn.isolation_level is None
        finally:
            conn.close()

    def test_explicit_timeout_overrides_default(self, tmp_path, monkeypatch):
        captured = {}
        real_connect = sqlite3.connect

        def spy(path, *args, **kwargs):
            captured.update(kwargs)
            return real_connect(path, *args, **kwargs)

        monkeypatch.setattr(sqlite3, "connect", spy)
        conn = open_db(tmp_path / "x.db", timeout=30)
        try:
            assert captured["timeout"] == 30
        finally:
            conn.close()

    def test_accepts_pathlib_path(self, tmp_path):
        conn = open_db(tmp_path / "from_path.db")
        try:
            conn.execute("SELECT 1")
        finally:
            conn.close()

    def test_creates_database_file_on_first_open(self, tmp_path):
        path = tmp_path / "fresh.db"
        assert not path.exists()
        conn = open_db(path)
        try:
            assert path.exists()
        finally:
            conn.close()
