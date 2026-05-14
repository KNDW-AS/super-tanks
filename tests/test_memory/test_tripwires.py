"""
Tests for core/memory/tripwires.py.

Covers the tripwire registry (paths, canary marker) and the
ensure_tripwires_exist deployment routine on a real
HierarchicalMemoryStore against tmp_path.
"""

import pytest

from core.memory import tripwires
from core.memory.hierarchical_store import HierarchicalMemoryStore


@pytest.fixture
def store(tmp_path):
    return HierarchicalMemoryStore(store_root=tmp_path / "hm")


# ── is_tripwire / get_tripwire_paths ───────────────────────────────────────

class TestRegistry:
    @pytest.mark.parametrize("path", [
        "/system/passwords_backup",
        "/system/admin_keys",
        "/system/ssh_private_key",
        "/family/finance/bank_login",
        "/william/secrets",
    ])
    def test_known_paths_are_tripwires(self, path):
        assert tripwires.is_tripwire(path) is True

    @pytest.mark.parametrize("path", [
        "/family/preferences",
        "/aeris/learned",
        "/system/logs",
        "/random/made/up",
    ])
    def test_unknown_paths_are_not_tripwires(self, path):
        assert tripwires.is_tripwire(path) is False

    def test_normalisation_strips_slashes(self):
        # Leading/trailing slash variations all classify identically.
        assert tripwires.is_tripwire("system/admin_keys") is True
        assert tripwires.is_tripwire("/system/admin_keys/") is True
        assert tripwires.is_tripwire("system/admin_keys/") is True

    def test_subpath_is_not_a_tripwire(self):
        # The registry holds exact paths only.
        assert tripwires.is_tripwire("/system/admin_keys/extra") is False

    def test_get_tripwire_paths_returns_sorted_unique(self):
        paths = tripwires.get_tripwire_paths()
        assert paths == sorted(paths)
        assert len(paths) == len(set(paths))
        assert len(paths) == 5


# ── ensure_tripwires_exist ─────────────────────────────────────────────────

class TestEnsureTripwiresExist:
    def test_first_run_creates_all_tripwires(self, store):
        created = tripwires.ensure_tripwires_exist(store)
        assert created == 5
        for tw_path in tripwires.get_tripwire_paths():
            m = store.read(tw_path)
            assert m is not None
            assert m.l2_full == tripwires.TRIPWIRE_CANARY

    def test_second_run_creates_zero(self, store):
        tripwires.ensure_tripwires_exist(store)
        created = tripwires.ensure_tripwires_exist(store)
        assert created == 0

    def test_metadata_marks_files_as_tripwire(self, store):
        tripwires.ensure_tripwires_exist(store)
        m = store.read("/william/secrets")
        assert m.metadata["is_tripwire"] is True
        assert m.metadata["do_not_delete"] is True
        assert m.metadata["source_agent"] == "system"
        assert m.metadata["trust_level"] == "tripwire"

    def test_partial_deployment_fills_only_missing(self, store):
        # Pre-create one tripwire with bogus content.
        store.store("/system/admin_keys", "fake", "fake", "fake content")
        created = tripwires.ensure_tripwires_exist(store)
        assert created == 4
        # Pre-existing entry is preserved untouched (canary check).
        m = store.read("/system/admin_keys")
        assert m.l2_full == "fake content"

    def test_all_paths_have_distinct_metadata_strings(self, store):
        tripwires.ensure_tripwires_exist(store)
        abstracts = set()
        for path in tripwires.get_tripwire_paths():
            m = store.read(path)
            abstracts.add(m.l0_abstract)
        # All five abstracts are unique to avoid pattern-matching
        # attackers spotting a generic decoy template.
        assert len(abstracts) == 5
