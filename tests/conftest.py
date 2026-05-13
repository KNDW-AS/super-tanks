"""
Shared pytest fixtures for Super Tanks tests.

The `user_db` fixture redirects the user_manager module's USER_DB constant
to a per-test temporary SQLite file and re-initialises the schema, giving
each test a clean, isolated database.
"""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture
def user_db(tmp_path, monkeypatch):
    """Provide a fresh, isolated users.db for each test."""
    from core.security import user_manager

    db_path = tmp_path / "users.db"
    monkeypatch.setattr(user_manager, "USER_DB", db_path)
    user_manager._init_db()
    return user_manager


@pytest.fixture
def seed_admin(user_db):
    """Create a single Level 5 admin so tests start from a usable state."""
    user_db.create_user(name="Admin", pin="0000", level=5, created_by="system")
    return user_db
