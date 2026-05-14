"""
core/memory/hybrid_search.py
==============================
Hybrid Search — vector + hierarchical path search with RRF ranking.

Uses nomic-embed-text via Ollama (local, no cloud) for vector embeddings.
Only L0_abstract + L1_overview are embedded — L2_full is never sent to embedder.

Tripwire check runs BEFORE RBAC filter and BEFORE results are returned.
A tripwire hit in Top-K aborts the search immediately and triggers LOCKDOWN.
"""

import json
import logging
import math
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.db.connection import open_db

logger = logging.getLogger("super_tanks.memory.hybrid_search")

EMBEDDING_DB = Path(__file__).resolve().parent.parent.parent / "data" / "memory_embeddings.db"
OLLAMA_URL = "http://localhost:11434/api/embeddings"
EMBED_MODEL = "nomic-embed-text"
EMBED_DIM = 768


def _get_conn():
    EMBEDDING_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = open_db(str(EMBEDDING_DB), timeout=15, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def _init_db():
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS memory_embeddings (
            path TEXT PRIMARY KEY,
            embedding BLOB NOT NULL,
            text_hash TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    conn.close()


_init_db()


def generate_embedding(text: str) -> Optional[List[float]]:
    """Generate embedding via local Ollama nomic-embed-text."""
    if not text or not text.strip():
        return None
    try:
        payload = json.dumps({"model": EMBED_MODEL, "prompt": text[:2000]}).encode()
        req = urllib.request.Request(
            OLLAMA_URL, data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
            emb = result.get("embedding")
            if emb and len(emb) == EMBED_DIM:
                return emb
    except Exception as e:
        logger.warning("[EMBED] Ollama embedding failed (continuing without): %s", e)
    return None


def store_embedding(path: str, l0: str, l1: str):
    """Generate and store embedding for a memory file. Only embeds L0+L1. Skips tripwires."""
    import hashlib
    from datetime import datetime, timezone
    from core.memory.tripwires import is_tripwire

    # Never embed tripwire files — they catch via text search only
    if is_tripwire(path):
        return

    text = f"{l0}\n{l1}".strip()
    if not text:
        return

    text_hash = hashlib.sha256(text.encode()).hexdigest()[:16]

    # Check if unchanged
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT text_hash FROM memory_embeddings WHERE path=?", (path,)
        ).fetchone()
        if row and row[0] == text_hash:
            return  # Unchanged, skip re-embedding
    finally:
        conn.close()

    emb = generate_embedding(text)
    if not emb:
        return

    import struct
    emb_blob = struct.pack(f"{EMBED_DIM}f", *emb)

    conn = _get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("""
            INSERT OR REPLACE INTO memory_embeddings (path, embedding, text_hash, updated_at)
            VALUES (?, ?, ?, ?)
        """, (path, emb_blob, text_hash, datetime.now(timezone.utc).isoformat()))
        conn.commit()
    finally:
        conn.close()

    logger.debug("[EMBED] Stored embedding for %s (%d dims)", path, EMBED_DIM)


def _cosine_similarity(a: List[float], b: List[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def vector_search(query: str, top_k: int = 10) -> List[Dict[str, Any]]:
    """Search memory embeddings by cosine similarity."""
    query_emb = generate_embedding(query)
    if not query_emb:
        return []

    import struct
    conn = _get_conn()
    try:
        rows = conn.execute("SELECT path, embedding FROM memory_embeddings").fetchall()
    finally:
        conn.close()

    results = []
    for path, emb_blob in rows:
        stored_emb = list(struct.unpack(f"{EMBED_DIM}f", emb_blob))
        score = _cosine_similarity(query_emb, stored_emb)
        results.append({"path": path, "vector_score": score})

    results.sort(key=lambda x: x["vector_score"], reverse=True)
    return results[:top_k]


def hierarchical_search(query: str, top_k: int = 10) -> List[Dict[str, Any]]:
    """Search by path/L0/L1 text matching."""
    from core.memory.hierarchical_store import HierarchicalMemoryStore
    store = HierarchicalMemoryStore()
    results = store.search(query)[:top_k]
    # Score by word overlap
    query_words = [w for w in query.lower().split() if len(w) > 2]
    scored = []
    for r in results:
        path = r.get("path", "").lower()
        l0 = r.get("l0_abstract", "").lower()
        l1 = r.get("l1_overview", "").lower()
        combined = f"{path} {l0} {l1}"
        if not query_words:
            scored.append({**r, "text_score": 0.1})
            continue
        hits = sum(1 for w in query_words if w in combined)
        score = hits / len(query_words)  # 0.0 to 1.0
        scored.append({**r, "text_score": max(0.1, score)})
    return scored


def rrf_merge(vector_results: List[Dict], text_results: List[Dict], k: int = 60) -> List[Dict]:
    """Reciprocal Rank Fusion — merge two ranked lists."""
    scores = {}

    for rank, r in enumerate(vector_results):
        path = r["path"]
        scores.setdefault(path, {"path": path, "rrf_score": 0.0, "vector_score": 0.0, "text_score": 0.0})
        scores[path]["rrf_score"] += 1.0 / (k + rank + 1)
        scores[path]["vector_score"] = r.get("vector_score", 0.0)

    for rank, r in enumerate(text_results):
        path = r["path"]
        scores.setdefault(path, {"path": path, "rrf_score": 0.0, "vector_score": 0.0, "text_score": 0.0})
        scores[path]["rrf_score"] += 1.0 / (k + rank + 1)
        scores[path]["text_score"] = r.get("text_score", 0.0)
        if "l0_abstract" in r:
            scores[path]["l0_abstract"] = r["l0_abstract"]

    merged = sorted(scores.values(), key=lambda x: x["rrf_score"], reverse=True)
    return merged


def hybrid_search(
    query: str,
    agent_id: str,
    top_k: int = 5,
) -> Dict[str, Any]:
    """
    Full hybrid search pipeline:
    1. Vector search (Ollama nomic-embed-text)
    2. Hierarchical text search
    3. RRF merge
    4. Tripwire check (ABORT if hit)
    5. RBAC filter
    6. Return top_k
    """
    from core.memory.tripwires import is_tripwire
    from core.memory.access_control import is_path_accessible, trigger_tripwire_alarm
    from core.security.super_tanks_mode import get_mode
    from core.memory.audit_log import log_access

    # 1+2: Parallel searches
    vec_results = vector_search(query, top_k=20)
    text_results = hierarchical_search(query, top_k=20)

    # 3: RRF merge
    merged = rrf_merge(vec_results, text_results)

    # 4: Tripwire check FIRST — abort if any tripwire in top results.
    # Runs for EVERY agent_id. Honeypot paths have no legitimate caller,
    # so even "william"/"system" hitting one is a signal that something
    # has spoofed identity or that a tool is misbehaving. The previous
    # bypass for non-(aeris|zeph) callers let prompt-injection trivially
    # walk past tripwires by asserting agent_id="william".
    for r in merged[:top_k * 2]:
        if is_tripwire(r["path"]):
            logger.critical(
                "TRIPWIRE HIT in search: agent=%s query=%r path=%s",
                agent_id, query[:50], r["path"],
            )
            trigger_tripwire_alarm(r["path"], agent_id)
            log_access(agent_id, "search_tripwire_hit", r["path"], 0, "search", False)
            return {
                "success": False,
                "error": "Security alert triggered",
                "results": [],
                "tripwire": True,
            }

    # 5: RBAC filter
    mode = get_mode()
    accessible = []
    for r in merged:
        if is_path_accessible(r["path"], agent_id, mode):
            # Add L0 abstract if not already present
            if "l0_abstract" not in r:
                from core.memory.hierarchical_store import HierarchicalMemoryStore
                store = HierarchicalMemoryStore()
                l0 = store.read(r["path"], level=0)
                r["l0_abstract"] = l0 if isinstance(l0, str) else ""
            accessible.append(r)
        if len(accessible) >= top_k:
            break

    trajectory = {
        "steps": ["vector_search", "text_search", "rrf_merge", "tripwire_check", "rbac_filter"],
        "vector_matches": len(vec_results),
        "text_matches": len(text_results),
        "merged": len(merged),
        "accessible": len(accessible),
    }

    log_access(agent_id, "hybrid_search", query[:100], 0, str(mode), True,
               trajectory=json.dumps(trajectory))

    return {
        "success": True,
        "results": accessible,
        "count": len(accessible),
        "vector_hits": len(vec_results),
        "text_hits": len(text_results),
        "trajectory": trajectory,
    }
