"""
DIQ A2A Contract — DO NOT MODIFY
Version: 1.0

Agent-to-Agent communication contract.
All A2A messages flow through this interface.
Implementations live in core/a2a.py — this file never changes.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class A2AMessage:
    """Immutable A2A message envelope."""
    sender: str                        # "aeris" or "zeph"
    recipient: str                     # "aeris" or "zeph"
    message_type: str                  # "request", "response", "notify"
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    correlation_id: Optional[str] = None


class DIQA2AChannel(ABC):
    """
    Contract for A2A communication.
    The gateway calls these methods. Implementation lives elsewhere.
    """

    @abstractmethod
    async def send(self, message: A2AMessage) -> bool:
        """Send a message to another agent."""
        ...

    @abstractmethod
    async def receive(self, agent_id: str) -> Optional[A2AMessage]:
        """Check for the next pending message for an agent."""
        ...

    @abstractmethod
    async def receive_all(self, agent_id: str) -> List[A2AMessage]:
        """Drain all pending messages for an agent."""
        ...

    @abstractmethod
    async def broadcast(self, sender: str, payload: Dict[str, Any]) -> bool:
        """Broadcast to all agents."""
        ...
