"""
core/security/tool_zones.py — Layer 8: tool zone isolation.

OWASP Agentic Top 10 (2026): ASI02 Tool Misuse & Exploitation;
Agentic Skills Top 10: AST03 Over-Privileged Skills.

Every tool maps to exactly one zone. Each zone has an action the gateway
enforces:

  ALLOW    — proceed to the next layer
  GO_GATE  — human approval required (core.ask_admin GO-Gate); the call
             is paused and returns `pending_approval` until approved
  DENY     — never executed

Zone map and zone actions are owned by the deployment (this module), not
by the tool: a tool cannot declare itself low-risk. Tools not in
TOOL_ZONES fall into UNCATEGORIZED, which requires GO-Gate (fail-closed
but recoverable — a human can still approve a new tool while its zone
is being decided).

The default map covers the tool names used by this repository's
registry and allowlists. Deployments add their own tools with
`set_tool_zone("my_tool", Zone.NETWORK_READ)` at startup (or edit the
map) and can tighten or relax a whole zone with `set_zone_action`.

Risk weights feed the circuit breaker (layer 7): riskier zones consume
the per-agent budget faster.
"""
from __future__ import annotations

import logging
from enum import Enum
from typing import Dict, List

logger = logging.getLogger("super_tanks.tool_zones")


class Zone(str, Enum):
    FILESYSTEM_RO = "filesystem_ro"   # read local files / memory
    NETWORK_READ = "network_read"     # public read-only network, pure compute
    SMARTHOUSE = "smarthouse"         # home automation / local devices
    AGENT_COMMS = "agent_comms"       # signed inter-agent messaging (A2A)
    FILESYSTEM_RW = "filesystem_rw"   # write files / memory
    NETWORK_WRITE = "network_write"   # outbound side effects (send, post, generate)
    EXEC = "exec"                     # code / shell execution
    ADMIN = "admin"                   # high-privilege mutations
    UNCATEGORIZED = "uncategorized"   # unknown tool — fail-closed default


class ZoneAction(str, Enum):
    ALLOW = "allow"
    GO_GATE = "go_gate"
    DENY = "deny"


TOOL_ZONES: Dict[str, Zone] = {
    # filesystem_ro
    "file_read": Zone.FILESYSTEM_RO,
    "memory_read": Zone.FILESYSTEM_RO,
    "memory_read_file": Zone.FILESYSTEM_RO,
    "memory_list_dir": Zone.FILESYSTEM_RO,
    "memory_hierarchy_search": Zone.FILESYSTEM_RO,
    "memory_skill": Zone.FILESYSTEM_RO,
    "semantic_search": Zone.FILESYSTEM_RO,
    "hybrid_search": Zone.FILESYSTEM_RO,
    "self_inspect": Zone.FILESYSTEM_RO,
    "trace_reflect": Zone.FILESYSTEM_RO,
    "task_list": Zone.FILESYSTEM_RO,
    "status": Zone.FILESYSTEM_RO,
    "system_monitor": Zone.FILESYSTEM_RO,
    # network_read
    "web_search": Zone.NETWORK_READ,
    "web_browse": Zone.NETWORK_READ,
    "web_context": Zone.NETWORK_READ,
    "weather_met": Zone.NETWORK_READ,
    "github_read": Zone.NETWORK_READ,
    "plan_task": Zone.NETWORK_READ,
    "calculator": Zone.NETWORK_READ,
    # smarthouse
    "home_assistant": Zone.SMARTHOUSE,
    "ha_search": Zone.SMARTHOUSE,
    "ha_config": Zone.SMARTHOUSE,
    "yale": Zone.SMARTHOUSE,
    "pet_camera": Zone.SMARTHOUSE,
    "notify_home": Zone.SMARTHOUSE,
    # agent_comms
    "a2a_send": Zone.AGENT_COMMS,
    "a2a_receive": Zone.AGENT_COMMS,
    # filesystem_rw
    "file_write": Zone.FILESYSTEM_RW,
    "memory_store": Zone.FILESYSTEM_RW,
    "memory_store_hierarchical": Zone.FILESYSTEM_RW,
    "memory_tools": Zone.FILESYSTEM_RW,
    "memory_consolidate": Zone.FILESYSTEM_RW,
    "shadow_store_propose": Zone.FILESYSTEM_RW,
    "task_add": Zone.FILESYSTEM_RW,
    "task_done": Zone.FILESYSTEM_RW,
    # network_write
    "image_generate": Zone.NETWORK_WRITE,
    # exec
    "shell_exec": Zone.EXEC,
    "python_exec": Zone.EXEC,
    "code_edit": Zone.EXEC,
    # admin
    "memory_delete": Zone.ADMIN,
    "propose_code_change": Zone.ADMIN,
    "password": Zone.ADMIN,
}

ZONE_ACTIONS: Dict[Zone, ZoneAction] = {
    Zone.FILESYSTEM_RO: ZoneAction.ALLOW,
    Zone.NETWORK_READ: ZoneAction.ALLOW,
    Zone.SMARTHOUSE: ZoneAction.ALLOW,
    Zone.AGENT_COMMS: ZoneAction.ALLOW,
    Zone.FILESYSTEM_RW: ZoneAction.GO_GATE,
    Zone.NETWORK_WRITE: ZoneAction.GO_GATE,
    Zone.EXEC: ZoneAction.GO_GATE,
    Zone.ADMIN: ZoneAction.GO_GATE,
    Zone.UNCATEGORIZED: ZoneAction.GO_GATE,
}

ZONE_RISK_WEIGHT: Dict[Zone, float] = {
    Zone.FILESYSTEM_RO: 1.0,
    Zone.NETWORK_READ: 1.0,
    Zone.SMARTHOUSE: 1.0,
    Zone.AGENT_COMMS: 1.0,
    Zone.FILESYSTEM_RW: 1.5,
    Zone.NETWORK_WRITE: 2.0,
    Zone.EXEC: 3.0,
    Zone.ADMIN: 3.0,
    Zone.UNCATEGORIZED: 5.0,
}


def get_zone(tool_name: str) -> Zone:
    """Zone for a tool; UNCATEGORIZED if not mapped."""
    zone = TOOL_ZONES.get(tool_name)
    if zone is None:
        logger.warning("tool %r has no zone — treating as UNCATEGORIZED (GO-Gate)", tool_name)
        return Zone.UNCATEGORIZED
    return zone


def zone_action(tool_name: str) -> ZoneAction:
    """Action the gateway must take for this tool. Unknown zone → GO_GATE."""
    return ZONE_ACTIONS.get(get_zone(tool_name), ZoneAction.GO_GATE)


def requires_go_gate(tool_name: str) -> bool:
    return zone_action(tool_name) is ZoneAction.GO_GATE


def risk_weight(tool_name: str) -> float:
    return ZONE_RISK_WEIGHT.get(get_zone(tool_name), ZONE_RISK_WEIGHT[Zone.UNCATEGORIZED])


def set_tool_zone(tool_name: str, zone: Zone) -> None:
    """Map (or re-map) a tool. Call at startup, before dispatching."""
    TOOL_ZONES[tool_name] = Zone(zone)


def set_zone_action(zone: Zone, action: ZoneAction) -> None:
    """Change what the gateway does for every tool in a zone."""
    ZONE_ACTIONS[Zone(zone)] = ZoneAction(action)


def get_tools_in_zone(zone: Zone) -> List[str]:
    return sorted(name for name, z in TOOL_ZONES.items() if z is zone)


def coverage_report() -> dict:
    """Zone inventory for audits."""
    by_zone = {z.value: 0 for z in Zone}
    for z in TOOL_ZONES.values():
        by_zone[z.value] += 1
    return {
        "total_tools_mapped": len(TOOL_ZONES),
        "by_zone": by_zone,
        "zone_actions": {z.value: a.value for z, a in ZONE_ACTIONS.items()},
    }
