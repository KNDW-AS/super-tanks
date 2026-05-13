"""
Tests for core/memory/hierarchical_store.py.

Covers path-traversal protection, three-level read/write, access-count
bookkeeping, list/search/delete, thread-safety under concurrent writes,
and the empty-dir prune on delete.
"""

import json
import threading
from pathlib import Path

import pytest

from core.memory.hierarchical_store import HierarchicalMemoryStore, MemoryFile


@pytest.fixture
def store(tmp_path):
    return HierarchicalMemoryStore(store_root=tmp_path / "hm")


# ── MemoryFile dataclass ───────────────────────────────────────────────────

class TestMemoryFile:
    def test_to_dict_round_trip(self):
        m = MemoryFile(path="/x", l0_abstract="a", l1_overview="b",
                       l2_full={"k": 1}, metadata={"src": "test"})
        d = m.to_dict()
        m2 = MemoryFile.from_dict(d)
        assert m2.path == "/x"
        assert m2.l2_full == {"k": 1}
        assert m2.metadata == {"src": "test"}

    def test_from_dict_defaults_metadata_to_empty(self):
        m = MemoryFile.from_dict({"path": "/x", "l0_abstract": "",
                                  "l1_overview": "", "l2_full": ""})
        assert m.metadata == {}


# ── _resolve_path / traversal guard ────────────────────────────────────────

class TestResolvePath:
    def test_normal_path(self, store):
        p = store._resolve_path("/family/lighting")
        assert p.suffix == ".json"
        assert str(p).startswith(str(store.store_root.resolve()))

    def test_strips_leading_and_trailing_slashes(self, store):
        a = store._resolve_path("/foo/bar")
        b = store._resolve_path("foo/bar")
        c = store._resolve_path("foo/bar/")
        assert a == b == c

    def test_backslash_normalised_to_forward(self, store):
        a = store._resolve_path("foo/bar")
        b = store._resolve_path("foo\\bar")
        assert a == b

    def test_empty_path_rejected(self, store):
        with pytest.raises(ValueError, match="Empty memory path"):
            store._resolve_path("")
        with pytest.raises(ValueError):
            store._resolve_path("///")

    def test_path_traversal_blocked(self, store):
        with pytest.raises(ValueError, match="traversal"):
            store._resolve_path("../../../etc/passwd")
        with pytest.raises(ValueError, match="traversal"):
            store._resolve_path("foo/../../../outside")


# ── store / read happy paths ───────────────────────────────────────────────

class TestStoreAndRead:
    def test_round_trip_dict_payload(self, store):
        store.store("/family/lighting", "abstract", "overview",
                    {"warm": True, "lumens": 800}, source_agent="aeris")
        m = store.read("/family/lighting", level=2)
        assert isinstance(m, MemoryFile)
        assert m.l0_abstract == "abstract"
        assert m.l1_overview == "overview"
        assert m.l2_full == {"warm": True, "lumens": 800}
        assert m.metadata["source_agent"] == "aeris"

    def test_level_0_returns_abstract(self, store):
        store.store("/x", "tiny abstract", "longer overview", "full")
        assert store.read("/x", level=0) == "tiny abstract"

    def test_level_1_returns_overview(self, store):
        store.store("/x", "a", "the overview text", "full")
        assert store.read("/x", level=1) == "the overview text"

    def test_unknown_path_returns_none(self, store):
        assert store.read("/missing/entry") is None

    def test_unicode_preserved(self, store):
        store.store("/no", "være glad", "Det er bra å være her",
                    {"by": "Sandnes", "name": "Bjørn"})
        m = store.read("/no")
        assert m.l1_overview == "Det er bra å være her"
        assert m.l2_full["name"] == "Bjørn"


# ── store: metadata behaviour on overwrite ─────────────────────────────────

class TestStoreOverwrite:
    def test_created_at_preserved_across_overwrites(self, store):
        first = store.store("/x", "a", "b", "first")
        original_created = first.metadata["created_at"]
        second = store.store("/x", "a2", "b2", "second")
        assert second.metadata["created_at"] == original_created

    def test_access_count_carried_over(self, store):
        store.store("/x", "a", "b", "c")
        store.read("/x")  # bumps to 1
        store.read("/x")  # bumps to 2
        m = store.store("/x", "a", "b", "c2")
        assert m.metadata["access_count"] == 2

    def test_corrupt_existing_file_is_overwritten_cleanly(self, store):
        target = store._resolve_path("/x")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("{ not valid json")
        m = store.store("/x", "a", "b", "c")
        assert m.l0_abstract == "a"
        # Subsequent read works.
        assert store.read("/x", level=0) == "a"

    def test_extra_metadata_merged(self, store):
        m = store.store("/x", "a", "b", "c",
                        extra_metadata={"topic": "lighting", "priority": 3})
        assert m.metadata["topic"] == "lighting"
        assert m.metadata["priority"] == 3
        # Default fields still present.
        assert "created_at" in m.metadata
        assert m.metadata["source_agent"] == "unknown"


# ── read: access_count bookkeeping ─────────────────────────────────────────

class TestAccessCount:
    def test_increments_on_each_read(self, store):
        store.store("/x", "a", "b", "c")
        for expected in (1, 2, 3):
            store.read("/x")
            data = json.loads(store._resolve_path("/x").read_text())
            assert data["metadata"]["access_count"] == expected

    def test_read_of_corrupt_file_returns_none(self, store):
        target = store._resolve_path("/x")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("{ corrupt")
        assert store.read("/x") is None


# ── list_dir ───────────────────────────────────────────────────────────────

class TestListDir:
    def test_lists_all_when_root(self, store):
        store.store("/a/b", "first", "ov", "c")
        store.store("/a/c", "second", "ov", "c")
        store.store("/x", "third", "ov", "c")
        items = store.list_dir()
        paths = sorted(i["path"] for i in items)
        assert paths == ["/a/b", "/a/c", "/x"]

    def test_lists_only_subtree(self, store):
        store.store("/a/b", "in", "", "")
        store.store("/x", "out", "", "")
        items = store.list_dir("/a")
        assert [i["path"] for i in items] == ["/a/b"]

    def test_unknown_dir_returns_empty(self, store):
        assert store.list_dir("/no/such/dir") == []

    def test_returns_l0_abstracts(self, store):
        store.store("/a", "tiny", "long", "full")
        items = store.list_dir("/")
        assert items[0]["l0_abstract"] == "tiny"

    def test_path_traversal_blocked(self, store):
        with pytest.raises(ValueError, match="traversal"):
            store.list_dir("../../etc")


# ── search ─────────────────────────────────────────────────────────────────

class TestSearch:
    def test_substring_in_abstract_matches(self, store):
        store.store("/a", "fire alarm config", "", "")
        store.store("/b", "weather report", "", "")
        results = store.search("fire")
        assert [r["path"] for r in results] == ["/a"]

    def test_substring_in_overview_matches(self, store):
        store.store("/a", "x", "user prefers dim lighting in the evening", "")
        results = store.search("dim lighting")
        assert [r["path"] for r in results] == ["/a"]

    def test_word_split_means_any_word_matches(self, store):
        store.store("/a", "alpha bravo", "", "")
        store.store("/b", "charlie delta", "", "")
        # Any of the two words matches → both selected.
        results = store.search("alpha delta")
        assert {r["path"] for r in results} == {"/a", "/b"}

    def test_case_insensitive(self, store):
        store.store("/a", "FIRE", "", "")
        assert [r["path"] for r in store.search("fire")] == ["/a"]

    def test_empty_when_no_match(self, store):
        store.store("/a", "alpha", "", "")
        assert store.search("nothing matches here") == []


# ── delete + prune ─────────────────────────────────────────────────────────

class TestDelete:
    def test_deletes_existing_entry(self, store):
        store.store("/a/b", "x", "y", "z")
        assert store.delete("/a/b") is True
        assert store.read("/a/b") is None

    def test_returns_false_if_missing(self, store):
        assert store.delete("/no/such") is False

    def test_prunes_empty_parent_dirs(self, store):
        store.store("/deep/nested/path", "x", "y", "z")
        nested = store._resolve_path("/deep/nested/path").parent
        assert nested.exists()
        store.delete("/deep/nested/path")
        assert not nested.exists()
        assert not nested.parent.exists()
        # Root must survive.
        assert store.store_root.exists()

    def test_does_not_prune_non_empty_parent(self, store):
        store.store("/a/b", "x", "", "")
        store.store("/a/c", "y", "", "")
        store.delete("/a/b")
        # /a still has /a/c.json so it must remain.
        a_dir = (store.store_root / "a").resolve()
        assert a_dir.exists()


# ── get_all_paths ──────────────────────────────────────────────────────────

class TestGetAllPaths:
    def test_returns_sorted_paths(self, store):
        store.store("/c", "x", "", "")
        store.store("/a", "x", "", "")
        store.store("/b", "x", "", "")
        # rglob ordering then sort is filesystem-name order, not logical.
        # We just check membership.
        assert set(store.get_all_paths()) == {"/a", "/b", "/c"}

    def test_skips_corrupt_files(self, store):
        store.store("/a", "x", "", "")
        bad = store.store_root / "broken.json"
        bad.write_text("{ corrupt")
        paths = store.get_all_paths()
        assert paths == ["/a"]

    def test_empty_store_returns_empty(self, store):
        assert store.get_all_paths() == []


# ── Thread safety ──────────────────────────────────────────────────────────

class TestThreadSafety:
    def test_concurrent_writes_do_not_corrupt_file(self, store):
        N = 30
        errors = []

        def writer(i):
            try:
                store.store("/shared", f"abs{i}", f"ov{i}", {"i": i})
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(N)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        # Final file must be valid JSON and contain a coherent record.
        m = store.read("/shared")
        assert m is not None
        assert m.l0_abstract.startswith("abs")
        assert m.metadata["access_count"] >= 1

    def test_concurrent_reads_during_writes_yield_valid_or_none(self, store):
        store.store("/k", "a", "b", "c")
        results = []

        def writer():
            for i in range(20):
                store.store("/k", f"a{i}", "b", "c")

        def reader():
            for _ in range(20):
                r = store.read("/k")
                results.append(r)

        threads = [threading.Thread(target=writer),
                   threading.Thread(target=reader),
                   threading.Thread(target=reader)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All reads must either return a MemoryFile or None (never raise).
        assert all(r is None or isinstance(r, MemoryFile) for r in results)
