"""
DIQ Memory Contract — DO NOT MODIFY
Version: 1.0

Memory and vector store contract.
ChromaDB collections and SQLite audit store implement this.
Hard memory boundaries (Aeris/Zeph isolation) are enforced by implementations — this file never changes.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class MemoryEntry:
    """Immutable memory entry to write."""
    agent_id: str           # "aeris" or "zeph"
    collection: str         # "aeris_memory", "system_knowledge", "user_facts"
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0


@dataclass(frozen=True)
class MemoryQuery:
    """Immutable memory query."""
    agent_id: str
    collection: str
    query: str
    top_k: int = 3
    max_chars: int = 40000


@dataclass(frozen=True)
class MemoryResult:
    """Immutable memory query result."""
    entries: List[Dict[str, Any]]
    collection: str
    query_hash: str
    total_chars: int


class DIQMemory(ABC):
    """
    Contract for memory read/write operations.
    Enforces agent isolation — Aeris cannot read zeph_audit, Zeph cannot read aeris_memory.
    """

    @abstractmethod
    async def write(self, entry: MemoryEntry) -> bool:
        """Write an entry to memory. Returns True on success."""
        ...

    @abstractmethod
    async def query(self, query: MemoryQuery) -> MemoryResult:
        """Query memory via semantic search."""
        ...

    @abstractmethod
    async def can_access(self, agent_id: str, collection: str, operation: str) -> bool:
        """Check if agent_id may perform 'read' or 'write' on collection."""
        ...
