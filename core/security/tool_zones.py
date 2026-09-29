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
    FILESYSTEM_RO = "filesystem_ro"   # read local files / memory / status
    NETWORK_READ = "network_read"     # read-only network (public or LAN), pure compute
    TASKS = "tasks"                   # the agents' own task list
    AGENT_COMMS = "agent_comms"       # signed A2A messages, household notifications
    SMARTHOUSE = "smarthouse"         # physical actuation: locks, climate, lights
    FILESYSTEM_RW = "filesystem_rw"   # write files / memory
    NETWORK_WRITE = "network_write"   # outbound side effects (send, post, generate)
    EXEC = "exec"                     # code / shell execution
    ADMIN = "admin"                   # destructive or high-privilege mutations
    UNCATEGORIZED = "uncategorized"   # unknown tool — fail-closed default


class ZoneAction(str, Enum):
    ALLOW = "allow"
    GO_GATE = "go_gate"
    DENY = "deny"


# Rationale for the defaults (the rule, then the judgement calls):
#   Rule: anything that changes the physical world, writes durable
#   state, sends data out, executes code or deletes needs a human GO.
#   Reading, pure computation and the agents' own bookkeeping do not.
#   - home_assistant: can switch lights, climate and locks → SMARTHOUSE
#     (GO-Gate).
#   - yale: the reference implementation only reads lock status and
#     history, but the name maps to lock hardware and this repo ships no
#     implementation, so it defaults to SMARTHOUSE (GO-Gate). A
#     deployment whose `yale` is provably read-only can re-map it.
#   - pet_camera: the reference implementation reads camera status and
#     keeps an in-memory feeding log; it drives no hardware → NETWORK_READ.
#   - ha_search / ha_config: read Home Assistant state only → NETWORK_READ.
#   - notify_home: pushes a message/TTS to household devices; no state
#     change beyond the notification → AGENT_COMMS (allow).
#   - task_add / task_done / task_list: the agents' own task list, no
#     execution path → TASKS (allow).
#   - password: a stateless local generator (secrets module); it reads
#     and stores nothing → NETWORK_READ with calculator (allow).
#   - plan_task: sends the task text to an external LLM for a plan,
#     read-only → NETWORK_READ. Provider stripping (layer 11) applies to
#     that call, not this layer.
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
    "password": Zone.NETWORK_READ,
    "ha_search": Zone.NETWORK_READ,
    "ha_config": Zone.NETWORK_READ,
    "pet_camera": Zone.NETWORK_READ,
    # tasks
    "task_list": Zone.TASKS,
    "task_add": Zone.TASKS,
    "task_done": Zone.TASKS,
    # agent_comms
    "a2a_send": Zone.AGENT_COMMS,
    "a2a_receive": Zone.AGENT_COMMS,
    "notify_home": Zone.AGENT_COMMS,
    # smarthouse (physical actuation)
    "home_assistant": Zone.SMARTHOUSE,
    "yale": Zone.SMARTHOUSE,
    # filesystem_rw
    "file_write": Zone.FILESYSTEM_RW,
    "memory_store": Zone.FILESYSTEM_RW,
    "memory_store_hierarchical": Zone.FILESYSTEM_RW,
    "memory_tools": Zone.FILESYSTEM_RW,
    "memory_consolidate": Zone.FILESYSTEM_RW,
    "shadow_store_propose": Zone.FILESYSTEM_RW,
    # network_write
    "image_generate": Zone.NETWORK_WRITE,
    # exec
    "shell_exec": Zone.EXEC,
    "python_exec": Zone.EXEC,
    "code_edit": Zone.EXEC,
    # admin
    "memory_delete": Zone.ADMIN,
    "propose_code_change": Zone.ADMIN,
}

ZONE_ACTIONS: Dict[Zone, ZoneAction] = {
    Zone.FILESYSTEM_RO: ZoneAction.ALLOW,
    Zone.NETWORK_READ: ZoneAction.ALLOW,
    Zone.TASKS: ZoneAction.ALLOW,
    Zone.AGENT_COMMS: ZoneAction.ALLOW,
    Zone.SMARTHOUSE: ZoneAction.GO_GATE,
    Zone.FILESYSTEM_RW: ZoneAction.GO_GATE,
    Zone.NETWORK_WRITE: ZoneAction.GO_GATE,
    Zone.EXEC: ZoneAction.GO_GATE,
    Zone.ADMIN: ZoneAction.GO_GATE,
    Zone.UNCATEGORIZED: ZoneAction.GO_GATE,
}

ZONE_RISK_WEIGHT: Dict[Zone, float] = {
    Zone.FILESYSTEM_RO: 1.0,
    Zone.NETWORK_READ: 1.0,
    Zone.TASKS: 1.0,
    Zone.AGENT_COMMS: 1.0,
    Zone.FILESYSTEM_RW: 1.5,
    Zone.SMARTHOUSE: 2.0,
    Zone.NETWORK_WRITE: 2.0,
    Zone.EXEC: 3.0,
    Zone.ADMIN: 3.0,
    Zone.UNCATEGORIZED: 5.0,
}


def get_zone(tool_name: str, warn: bool = True) -> Zone:
    """Zone for a tool; UNCATEGORIZED if not mapped (warns once per call
    when `warn` is true — the gateway's zone check is the one caller
    that warns)."""
    zone = TOOL_ZONES.get(tool_name)
    if zone is None:
        if warn:
            logger.warning("tool %r has no zone — treating as UNCATEGORIZED (GO-Gate)", tool_name)
        return Zone.UNCATEGORIZED
    return zone


def zone_action(tool_name: str) -> ZoneAction:
    """Action the gateway must take for this tool. Unknown zone → GO_GATE."""
    return ZONE_ACTIONS.get(get_zone(tool_name, warn=False), ZoneAction.GO_GATE)


def requires_go_gate(tool_name: str) -> bool:
    return zone_action(tool_name) is ZoneAction.GO_GATE


def risk_weight(tool_name: str) -> float:
    return ZONE_RISK_WEIGHT.get(get_zone(tool_name, warn=False),
                                ZONE_RISK_WEIGHT[Zone.UNCATEGORIZED])


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
