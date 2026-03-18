"""
DIQ Cloud Cortex Contract — DO NOT MODIFY
Version: 1.0

LLM routing contract. All LLM calls go through this interface.
Provider selection, fallback, and routing live in aeris_brain.py — this file never changes.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class LLMRequest:
    """Immutable LLM request."""
    messages: List[Dict[str, str]]
    agent_id: str
    complexity_score: Optional[float] = None
    preferred_provider: Optional[str] = None   # "ollama", "gemini", "claude", "kimi"
    max_tokens: int = 2048
    temperature: float = 0.7
    tools: Optional[List[Dict[str, Any]]] = None


@dataclass(frozen=True)
class LLMResponse:
    """Immutable LLM response."""
    content: str
    provider_used: str
    model_used: str
    tokens_used: int = 0
    error: Optional[str] = None
    tool_calls: Optional[List[Dict[str, Any]]] = field(default=None)


class DIQCloudCortex(ABC):
    """
    Contract for LLM routing.
    Implementation handles provider selection, fallback, etc.
    """

    @abstractmethod
    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Route an LLM request to the appropriate provider."""
        ...

    @abstractmethod
    def available_providers(self) -> List[str]:
        """List currently available providers."""
        ...

    @abstractmethod
    def classify_complexity(self, message: str) -> float:
        """Return complexity score 0.0–1.0. Above threshold → cloud."""
        ...
