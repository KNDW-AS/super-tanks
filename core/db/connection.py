"""
core/db/connection.py — Standardized SQLite connection with WAL + busy_timeout.

Every database connection in the codebase should use open_db() instead of
bare sqlite3.connect(). This ensures:
  - WAL journal mode (readers don't block writers)
  - busy_timeout=15000 (15s grace period before SQLITE_BUSY)
  - Consistent timeout across all modules
"""

import sqlite3


def open_db(path, **kwargs) -> sqlite3.Connection:
    """Open a SQLite connection with WAL mode and busy_timeout.

    Accepts all sqlite3.connect() keyword arguments (timeout,
    check_same_thread, isolation_level, etc.). Defaults timeout to 15s
    if not specified.

    Usage:
        conn = open_db("data/my.db")
        conn = open_db(self.db_path, isolation_level=None)
        with open_db(DB_PATH) as conn:
            conn.execute(...)
    """
    kwargs.setdefault("timeout", 15)
    conn = sqlite3.connect(str(path), **kwargs)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn
