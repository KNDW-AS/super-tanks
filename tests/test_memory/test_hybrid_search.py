"""
Tests for core/memory/hybrid_search.py.

Covers the pure-Python helpers (cosine similarity, RRF merge,
hierarchical text scoring), the embedding fingerprint cache, and the
full hybrid pipeline with vector + RBAC + tripwire collaborators
stubbed.
"""

import json
import struct
import sys
import types
from datetime import datetime, timezone

import pytest


@pytest.fixture
def hs(tmp_path, monkeypatch):
    from core.memory import hybrid_search, hierarchical_store

    monkeypatch.setattr(hybrid_search, "EMBEDDING_DB", tmp_path / "embed.db")
    monkeypatch.setattr(hierarchical_store, "STORE_ROOT", tmp_path / "hm")
    hybrid_search._init_db()

    # Stub the embedding network call by default; tests can override.
    monkeypatch.setattr(hybrid_search, "generate_embedding",
                        lambda text: None)

    # Stub audit_log used by hybrid_search. The real signature accepts
    # both positional and keyword arguments, so the stub must be permissive.
    fake_audit = types.ModuleType("core.memory.audit_log")
    fake_audit.log_access = lambda *a, **kw: None
    monkeypatch.setitem(sys.modules, "core.memory.audit_log", fake_audit)

    return hybrid_search


# ── Cosine similarity ─────────────────────────────────────────────────────

class TestCosine:
    def test_identical_vectors_score_one(self, hs):
        v = [1.0, 2.0, 3.0]
        assert hs._cosine_similarity(v, v) == pytest.approx(1.0)

    def test_orthogonal_vectors_score_zero(self, hs):
        assert hs._cosine_similarity([1, 0], [0, 1]) == pytest.approx(0.0)

    def test_opposite_vectors_score_negative_one(self, hs):
        assert hs._cosine_similarity([1, 0], [-1, 0]) == pytest.approx(-1.0)

    def test_zero_vector_handled(self, hs):
        assert hs._cosine_similarity([0, 0, 0], [1, 2, 3]) == 0.0
        assert hs._cosine_similarity([1, 2, 3], [0, 0, 0]) == 0.0


# ── RRF merge ──────────────────────────────────────────────────────────────

class TestRrfMerge:
    def test_paths_in_both_lists_rank_higher(self, hs):
        vec = [{"path": "/a", "vector_score": 0.9},
               {"path": "/b", "vector_score": 0.8}]
        text = [{"path": "/a", "text_score": 0.9, "l0_abstract": "A"},
                {"path": "/c", "text_score": 0.7, "l0_abstract": "C"}]
        merged = hs.rrf_merge(vec, text)
        # /a appears in both lists → highest rrf.
        assert merged[0]["path"] == "/a"
        assert merged[0]["l0_abstract"] == "A"

    def test_includes_paths_unique_to_each_source(self, hs):
        vec = [{"path": "/v", "vector_score": 0.5}]
        text = [{"path": "/t", "text_score": 0.5}]
        merged = hs.rrf_merge(vec, text)
        paths = {m["path"] for m in merged}
        assert paths == {"/v", "/t"}

    def test_rrf_formula_decreases_with_rank(self, hs):
        vec = [{"path": f"/p{i}", "vector_score": 1.0 - i * 0.1}
               for i in range(5)]
        merged = hs.rrf_merge(vec, [])
        scores = [m["rrf_score"] for m in merged]
        assert scores == sorted(scores, reverse=True)


# ── hierarchical_search (text) ─────────────────────────────────────────────

class TestHierarchicalSearch:
    def test_matches_word_overlap(self, hs, tmp_path):
        from core.memory.hierarchical_store import HierarchicalMemoryStore
        store = HierarchicalMemoryStore()
        store.store("/family/preferences/lighting",
                    "user prefers dim lighting in the evening", "ov", "")
        store.store("/family/preferences/music",
                    "user prefers classical music", "ov", "")
        results = hs.hierarchical_search("dim lighting")
        # Lighting entry must have higher text_score than music.
        scored = {r["path"]: r["text_score"] for r in results}
        assert scored["/family/preferences/lighting"] > \
               scored.get("/family/preferences/music", 0)

    def test_returns_empty_when_store_empty(self, hs):
        assert hs.hierarchical_search("nothing") == []

    def test_minimum_text_score_floor(self, hs):
        from core.memory.hierarchical_store import HierarchicalMemoryStore
        store = HierarchicalMemoryStore()
        store.store("/x", "alpha bravo charlie delta", "", "")
        results = hs.hierarchical_search("zzz")  # no hits
        # Module only returns rows that the substring search already matched,
        # so an empty result set here is fine — the floor only applies to
        # explicit matches.
        # Add a known matcher to confirm floor.
        store.store("/y", "alpha bravo", "", "")
        results = hs.hierarchical_search("alpha")
        for r in results:
            assert r["text_score"] >= 0.1


# ── Embedding cache ────────────────────────────────────────────────────────

class TestStoreEmbedding:
    def test_skips_tripwires(self, hs, monkeypatch):
        called = []
        monkeypatch.setattr(hs, "generate_embedding",
                            lambda t: called.append(t) or [0.0] * hs.EMBED_DIM)
        hs.store_embedding("/william/secrets", "abstract", "overview")
        assert called == []  # never invoked

    def test_skips_when_text_empty(self, hs, monkeypatch):
        called = []
        monkeypatch.setattr(hs, "generate_embedding",
                            lambda t: called.append(t) or [0.0] * hs.EMBED_DIM)
        hs.store_embedding("/family/preferences/x", "", "")
        assert called == []

    def test_persists_blob_when_embedding_succeeds(self, hs, monkeypatch):
        vec = [0.1] * hs.EMBED_DIM
        monkeypatch.setattr(hs, "generate_embedding", lambda t: vec)
        hs.store_embedding("/family/preferences/lighting", "abs", "ov")

        conn = hs._get_conn()
        try:
            row = conn.execute(
                "SELECT path, embedding FROM memory_embeddings WHERE path=?",
                ("/family/preferences/lighting",)).fetchone()
        finally:
            conn.close()
        assert row is not None
        stored = struct.unpack(f"{hs.EMBED_DIM}f", row[1])
        assert stored[0] == pytest.approx(0.1)

    def test_unchanged_text_does_not_regenerate(self, hs, monkeypatch):
        call_count = [0]

        def fake_embed(text):
            call_count[0] += 1
            return [0.5] * hs.EMBED_DIM

        monkeypatch.setattr(hs, "generate_embedding", fake_embed)
        hs.store_embedding("/family/preferences/lighting", "abs", "ov")
        hs.store_embedding("/family/preferences/lighting", "abs", "ov")
        # Same text_hash on second call → skip embedding generation.
        assert call_count[0] == 1


# ── vector_search ──────────────────────────────────────────────────────────

class TestVectorSearch:
    def test_returns_results_ordered_by_similarity(self, hs, monkeypatch):
        from core.memory import hybrid_search

        # Seed the embeddings table directly.
        conn = hs._get_conn()
        try:
            vec_a = [1.0] + [0.0] * (hs.EMBED_DIM - 1)
            vec_b = [0.5, 0.5] + [0.0] * (hs.EMBED_DIM - 2)
            conn.execute(
                "INSERT INTO memory_embeddings (path, embedding, text_hash, updated_at) VALUES (?, ?, ?, ?)",
                ("/a", struct.pack(f"{hs.EMBED_DIM}f", *vec_a),
                 "h1", datetime.now(timezone.utc).isoformat()))
            conn.execute(
                "INSERT INTO memory_embeddings (path, embedding, text_hash, updated_at) VALUES (?, ?, ?, ?)",
                ("/b", struct.pack(f"{hs.EMBED_DIM}f", *vec_b),
                 "h2", datetime.now(timezone.utc).isoformat()))
            conn.commit()
        finally:
            conn.close()

        # Query embedding matches /a perfectly.
        query_vec = [1.0] + [0.0] * (hs.EMBED_DIM - 1)
        monkeypatch.setattr(hybrid_search, "generate_embedding",
                            lambda text: query_vec)
        results = hybrid_search.vector_search("anything", top_k=5)
        assert results[0]["path"] == "/a"
        assert results[0]["vector_score"] > results[1]["vector_score"]

    def test_returns_empty_when_query_embed_fails(self, hs, monkeypatch):
        # generate_embedding returns None by default in the fixture.
        assert hs.vector_search("x") == []


# ── hybrid_search full pipeline ────────────────────────────────────────────

class TestHybridSearchPipeline:
    def test_tripwire_in_results_aborts_with_alarm(self, hs, monkeypatch):
        # Stub vector_search to return a tripwire path.
        monkeypatch.setattr(hs, "vector_search",
                            lambda q, top_k=20: [{"path": "/william/secrets",
                                                   "vector_score": 0.99}])
        monkeypatch.setattr(hs, "hierarchical_search",
                            lambda q, top_k=20: [])

        alarm_calls = []
        from core.memory import access_control
        monkeypatch.setattr(access_control, "trigger_tripwire_alarm",
                            lambda path, agent: alarm_calls.append((path, agent)))

        # Mode getter must work.
        from core.security import super_tanks_mode
        monkeypatch.setattr(super_tanks_mode, "get_mode",
                            lambda: super_tanks_mode.TankMode.AUTONOMOUS)

        result = hs.hybrid_search("any query", "aeris", top_k=5)
        assert result["success"] is False
        assert result["tripwire"] is True
        assert alarm_calls == [("/william/secrets", "aeris")]

    def test_normal_search_applies_rbac_filter(self, hs, monkeypatch):
        monkeypatch.setattr(hs, "vector_search",
                            lambda q, top_k=20: [
                                {"path": "/family/preferences/lighting",
                                 "vector_score": 0.9},
                                {"path": "/family/finance/account",
                                 "vector_score": 0.8}])
        monkeypatch.setattr(hs, "hierarchical_search",
                            lambda q, top_k=20: [])

        from core.memory import access_control
        # Sensitive path blocked in autonomous mode → filtered out.
        from core.security import super_tanks_mode
        monkeypatch.setattr(super_tanks_mode, "get_mode",
                            lambda: super_tanks_mode.TankMode.AUTONOMOUS)
        result = hs.hybrid_search("preferences", "aeris", top_k=5)
        assert result["success"] is True
        paths = [r["path"] for r in result["results"]]
        assert "/family/preferences/lighting" in paths
        assert "/family/finance/account" not in paths

    def test_tripwire_fires_for_admin_agents_too(self, hs, monkeypatch):
        # Honeypot hits are alarming regardless of who claims to be calling.
        # An attacker who can spoof agent_id="william" must NOT walk past
        # the tripwire silently.
        monkeypatch.setattr(hs, "vector_search",
                            lambda q, top_k=20: [{"path": "/william/secrets",
                                                   "vector_score": 0.99}])
        monkeypatch.setattr(hs, "hierarchical_search",
                            lambda q, top_k=20: [])

        alarm_calls = []
        from core.memory import access_control
        monkeypatch.setattr(access_control, "trigger_tripwire_alarm",
                            lambda path, agent: alarm_calls.append((path, agent)))

        from core.security import super_tanks_mode
        monkeypatch.setattr(super_tanks_mode, "get_mode",
                            lambda: super_tanks_mode.TankMode.LOCKDOWN)

        result = hs.hybrid_search("x", "william", top_k=5)
        assert result["success"] is False
        assert result["tripwire"] is True
        assert alarm_calls == [("/william/secrets", "william")]
