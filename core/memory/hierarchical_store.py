"""
core/memory/hierarchical_store.py
==================================
Super Tanks v3.0 — Hierarchical Memory Store.

Stores memory files as JSON on disk with three detail levels:
  L0: one-sentence abstract (for directory listings)
  L1: paragraph overview (for planning)
  L2: full content (dict, list, or string)

Storage layout: memory/hierarchical/<path>.json

Thread-safe file operations via a reentrant lock.
Path traversal protection via resolve() + startswith() check.
"""

import json
import logging
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger("super_tanks.memory.hierarchical")

# Base directory for all hierarchical memory files
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
STORE_ROOT = _PROJECT_ROOT / "memory" / "hierarchical"


@dataclass
class MemoryFile:
    """A single hierarchical memory entry with three detail levels."""

    path: str
    l0_abstract: str
    l1_overview: str
    l2_full: Union[dict, list, str]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to a JSON-safe dict."""
        return {
            "path": self.path,
            "l0_abstract": self.l0_abstract,
            "l1_overview": self.l1_overview,
            "l2_full": self.l2_full,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MemoryFile":
        """Deserialize from a dict (loaded from JSON)."""
        return cls(
            path=data["path"],
            l0_abstract=data["l0_abstract"],
            l1_overview=data["l1_overview"],
            l2_full=data["l2_full"],
            metadata=data.get("metadata", {}),
        )


class HierarchicalMemoryStore:
    """
    Disk-backed hierarchical memory store.

    Each memory is a JSON file at memory/hierarchical/<path>.json
    containing l0 (abstract), l1 (overview), l2 (full content),
    and metadata.
    """

    def __init__(self, store_root: Optional[Path] = None):
        self.store_root = Path(store_root) if store_root else STORE_ROOT
        self.store_root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        logger.info(
            "HierarchicalMemoryStore initialized at %s", self.store_root
        )

    # ------------------------------------------------------------------
    # Path safety
    # ------------------------------------------------------------------

    def _resolve_path(self, memory_path: str) -> Path:
        """
        Convert a logical memory path to a filesystem path.

        Raises ValueError on path traversal attempts.
        """
        # Normalize: strip leading/trailing slashes, collapse doubles
        clean = memory_path.strip("/").replace("\\", "/")
        if not clean:
            raise ValueError("Empty memory path")

        target = (self.store_root / clean).with_suffix(".json").resolve()

        # Path traversal guard
        if not str(target).startswith(str(self.store_root.resolve())):
            raise ValueError(
                f"Path traversal blocked: {memory_path!r} resolved outside store"
            )

        return target

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def store(
        self,
        path: str,
        l0_abstract: str,
        l1_overview: str,
        l2_full: Union[dict, list, str],
        source_agent: str = "unknown",
        trust_level: str = "normal",
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> MemoryFile:
        """
        Store or overwrite a memory file.

        Args:
            path: Logical memory path, e.g. "/family/preferences/lighting".
            l0_abstract: One-sentence summary.
            l1_overview: Paragraph-level overview.
            l2_full: Full content (dict, list, or string).
            source_agent: Which agent wrote this memory.
            trust_level: Trust classification ("normal", "high", "low").
            extra_metadata: Optional additional metadata fields.

        Returns:
            The stored MemoryFile.
        """
        file_path = self._resolve_path(path)
        now = datetime.now(timezone.utc).isoformat()

        # Build metadata — preserve created_at on updates
        metadata: Dict[str, Any] = {
            "created_at": now,
            "updated_at": now,
            "source_agent": source_agent,
            "access_count": 0,
            "trust_level": trust_level,
        }
        if extra_metadata:
            metadata.update(extra_metadata)

        with self._lock:
            # If file already exists, preserve created_at and accumulate access_count
            if file_path.exists():
                try:
                    existing = json.loads(file_path.read_text(encoding="utf-8"))
                    old_meta = existing.get("metadata", {})
                    metadata["created_at"] = old_meta.get("created_at", now)
                    metadata["access_count"] = old_meta.get("access_count", 0)
                except (json.JSONDecodeError, KeyError):
                    pass  # Corrupt file — overwrite cleanly

            memory = MemoryFile(
                path=path,
                l0_abstract=l0_abstract,
                l1_overview=l1_overview,
                l2_full=l2_full,
                metadata=metadata,
            )

            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(
                json.dumps(memory.to_dict(), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

        logger.debug("Stored memory: %s (agent=%s)", path, source_agent)
        return memory

    def read(self, path: str, level: int = 2) -> Optional[Union[str, dict, MemoryFile]]:
        """
        Read a memory entry at a given detail level.

        Args:
            path: Logical memory path.
            level: 0 = l0 abstract, 1 = l1 overview, 2 = full MemoryFile.

        Returns:
            String (level 0 or 1), MemoryFile (level 2), or None if not found.
        """
        file_path = self._resolve_path(path)

        with self._lock:
            if not file_path.exists():
                return None

            try:
                data = json.loads(file_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to read memory %s: %s", path, exc)
                return None

            # Bump access count
            data.setdefault("metadata", {})
            data["metadata"]["access_count"] = (
                data["metadata"].get("access_count", 0) + 1
            )
            try:
                file_path.write_text(
                    json.dumps(data, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
            except OSError as exc:
                logger.warning("Failed to update access_count for %s: %s", path, exc)

        if level == 0:
            return data.get("l0_abstract", "")
        elif level == 1:
            return data.get("l1_overview", "")
        else:
            return MemoryFile.from_dict(data)

    def list_dir(self, path: str = "") -> List[Dict[str, str]]:
        """
        List memory entries under a directory prefix.

        Returns a list of dicts with 'path' and 'l0_abstract' keys,
        suitable for directory-style browsing.
        """
        clean = path.strip("/").replace("\\", "/")
        target_dir = (self.store_root / clean).resolve() if clean else self.store_root.resolve()

        # Safety check
        if not str(target_dir).startswith(str(self.store_root.resolve())):
            raise ValueError(f"Path traversal blocked: {path!r}")

        results: List[Dict[str, str]] = []

        if not target_dir.exists():
            return results

        with self._lock:
            for json_file in sorted(target_dir.rglob("*.json")):
                try:
                    data = json.loads(json_file.read_text(encoding="utf-8"))
                    results.append({
                        "path": data.get("path", ""),
                        "l0_abstract": data.get("l0_abstract", ""),
                    })
                except (json.JSONDecodeError, OSError):
                    continue

        return results

    def search(self, query: str) -> List[Dict[str, str]]:
        """
        Simple substring search across l0, l1, and path fields.

        Returns a list of dicts with 'path', 'l0_abstract', 'l1_overview'.
        For production use, consider indexing or vector search.
        """
        query_lower = query.lower()
        results: List[Dict[str, str]] = []

        with self._lock:
            for json_file in sorted(self.store_root.rglob("*.json")):
                try:
                    data = json.loads(json_file.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    continue

                mem_path = data.get("path", "").lower()
                l0 = data.get("l0_abstract", "").lower()
                l1 = data.get("l1_overview", "").lower()

                # Match if ANY query word appears in path, L0, or L1
                combined = f"{mem_path} {l0} {l1}"
                query_words = query_lower.split()
                if any(word in combined for word in query_words):
                    results.append({
                        "path": data.get("path", ""),
                        "l0_abstract": data.get("l0_abstract", ""),
                        "l1_overview": data.get("l1_overview", ""),
                    })

        return results

    def delete(self, path: str) -> bool:
        """
        Delete a memory entry.

        Returns True if the file existed and was deleted, False otherwise.
        """
        file_path = self._resolve_path(path)

        with self._lock:
            if file_path.exists():
                file_path.unlink()
                logger.info("Deleted memory: %s", path)
                # Clean up empty parent directories
                self._prune_empty_dirs(file_path.parent)
                return True

        return False

    def get_all_paths(self) -> List[str]:
        """
        Return all stored memory paths.

        Returns:
            Sorted list of logical memory paths.
        """
        paths: List[str] = []

        with self._lock:
            for json_file in sorted(self.store_root.rglob("*.json")):
                try:
                    data = json.loads(json_file.read_text(encoding="utf-8"))
                    p = data.get("path")
                    if p:
                        paths.append(p)
                except (json.JSONDecodeError, OSError):
                    continue

        return paths

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _prune_empty_dirs(self, directory: Path) -> None:
        """Remove empty directories up to (but not including) store_root."""
        resolved_root = self.store_root.resolve()
        current = directory.resolve()
        while current != resolved_root and current.is_dir():
            try:
                current.rmdir()  # Only succeeds if empty
                current = current.parent
            except OSError:
                break
