"""
DIQ Home Assistant Contract — DO NOT MODIFY
Version: 1.0

Home Assistant integration contract.
HA is the single source of truth for all smart home state.
Implementation lives in skills/homeassistant.py — this file never changes.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class HACommand:
    """Immutable HA command."""
    domain: str             # e.g. "light", "switch", "climate"
    service: str            # e.g. "turn_on", "turn_off", "set_temperature"
    entity_id: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    agent_id: str = "aeris"


@dataclass(frozen=True)
class HAStateQuery:
    """Immutable HA state query."""
    entity_id: str
    agent_id: str = "aeris"


@dataclass(frozen=True)
class HAResponse:
    """Immutable HA response."""
    success: bool
    entity_id: str
    state: Optional[str] = None
    attributes: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class DIQHA(ABC):
    """
    Contract for Home Assistant operations.
    All smart home reads and writes go through this interface.

    NOTE: The actual access policy is enforced by `tool_allowlists.py`,
    not by this contract. As of v3.2 both Aeris and Zeph have
    `home_assistant` in their allowlists (Aeris is the family-facing
    smart-home agent and must be able to control lights/locks/climate).
    The "Aeris READ_ONLY" line in this docstring earlier was a lie —
    a maintainer who "fixed" the allowlist to match would have broken
    Aeris's smarthus control.
    """

    @abstractmethod
    async def call_service(self, command: HACommand) -> HAResponse:
        """Call an HA service (light/switch/climate etc.)."""
        ...

    @abstractmethod
    async def get_state(self, query: HAStateQuery) -> HAResponse:
        """Read entity state from HA."""
        ...

    @abstractmethod
    async def list_entities(self, domain: Optional[str] = None) -> List[Dict[str, Any]]:
        """List HA entities, optionally filtered by domain."""
        ...

    @abstractmethod
    async def is_available(self, entity_id: str) -> bool:
        """Return False if entity is unavailable (silent failure guard)."""
        ...
