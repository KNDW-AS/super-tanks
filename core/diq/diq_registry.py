"""
DIQ Registry — THE ONLY MUTABLE DIQ FILE
Version: 1.0

This is the ONLY file in core/diq/ that changes when adding new
tools, skills, or subsystems. All other DIQ files are frozen (chmod 444).

To add a new tool:
  1. Import your tool class below
  2. Call register_tool(YourTool()) in _bootstrap()
  3. That's it. Nothing else changes.

To add a new skill:
  Same pattern — register_skill(YourSkill())

To wire A2A, Cloud, HA, Memory:
  register_a2a(), register_cloud(), register_ha(), register_memory()
  Called once at gateway startup.
"""

from typing import Dict, List, Optional

from core.diq.diq_tools import DIQTool
from core.diq.diq_a2a import DIQA2AChannel
from core.diq.diq_cloud import DIQCloudCortex
from core.diq.diq_memory import DIQMemory
from core.diq.diq_skills import DIQSkill
from core.diq.diq_ha import DIQHA


# ─────────────────────────────────────────────────────────────────────────────
# TOOL REGISTRY
# Add new tools here. Only here. Nowhere else.
# ─────────────────────────────────────────────────────────────────────────────

_tool_registry: Dict[str, DIQTool] = {}


def register_tool(tool: DIQTool) -> None:
    """Register a tool. Called at startup or after hot-reload."""
    _tool_registry[tool.name()] = tool


def get_tool(name: str) -> Optional[DIQTool]:
    """Get a tool by name. Called by gateway."""
    return _tool_registry.get(name)


def all_tools() -> Dict[str, DIQTool]:
    """Get all registered tools. Used for LLM function schemas."""
    return dict(_tool_registry)


# ─────────────────────────────────────────────────────────────────────────────
# SKILL REGISTRY
# ─────────────────────────────────────────────────────────────────────────────

_skill_registry: Dict[str, DIQSkill] = {}


def register_skill(skill: DIQSkill) -> None:
    _skill_registry[skill.skill_name()] = skill


def get_skill(name: str) -> Optional[DIQSkill]:
    return _skill_registry.get(name)


def all_skills() -> Dict[str, DIQSkill]:
    return dict(_skill_registry)


# ─────────────────────────────────────────────────────────────────────────────
# A2A CHANNEL REGISTRY
# ─────────────────────────────────────────────────────────────────────────────

_a2a_channel: Optional[DIQA2AChannel] = None


class _VerifyingA2AChannel(DIQA2AChannel):
    """Wraps a registered A2A channel so every receive() output is
    re-verified through `escalation_rules.verify_or_drop` before it
    can reach the agent runtime. R-06: a forged-sender A2A message is
    the canonical privilege escalation path on this bus, so the gate
    must sit at the registration boundary — individual channel
    implementations are not trusted to enforce it themselves.

    `send` and `broadcast` pass through unchanged; sender-side signing
    happens in `core.security.agent_identity.sign_a2a_message` at the
    callsite that builds the message.
    """

    def __init__(self, inner: DIQA2AChannel):
        self._inner = inner

    async def send(self, message):
        return await self._inner.send(message)

    async def receive(self, agent_id: str):
        from core.a2a.escalation_rules import verify_or_drop
        return verify_or_drop(await self._inner.receive(agent_id))

    async def receive_all(self, agent_id: str):
        from core.a2a.escalation_rules import verify_or_drop
        msgs = await self._inner.receive_all(agent_id)
        return [m for m in (verify_or_drop(msg) for msg in msgs) if m is not None]

    async def broadcast(self, sender: str, payload):
        return await self._inner.broadcast(sender, payload)


def register_a2a(channel: DIQA2AChannel) -> None:
    """Register an A2A channel. The channel is wrapped in
    `_VerifyingA2AChannel` so unsigned/forged messages are dropped
    before they reach the recipient's policy logic.
    """
    global _a2a_channel
    if isinstance(channel, _VerifyingA2AChannel):
        # Already wrapped — don't double-wrap.
        _a2a_channel = channel
    else:
        _a2a_channel = _VerifyingA2AChannel(channel)


def get_a2a() -> Optional[DIQA2AChannel]:
    return _a2a_channel


# ─────────────────────────────────────────────────────────────────────────────
# CLOUD CORTEX REGISTRY
# ─────────────────────────────────────────────────────────────────────────────

_cloud_cortex: Optional[DIQCloudCortex] = None


def register_cloud(cortex: DIQCloudCortex) -> None:
    global _cloud_cortex
    _cloud_cortex = cortex


def get_cloud() -> Optional[DIQCloudCortex]:
    return _cloud_cortex


# ─────────────────────────────────────────────────────────────────────────────
# MEMORY REGISTRY
# ─────────────────────────────────────────────────────────────────────────────

_memory: Optional[DIQMemory] = None


def register_memory(memory: DIQMemory) -> None:
    global _memory
    _memory = memory


def get_memory() -> Optional[DIQMemory]:
    return _memory


# ─────────────────────────────────────────────────────────────────────────────
# HOME ASSISTANT REGISTRY
# ─────────────────────────────────────────────────────────────────────────────

_ha: Optional[DIQHA] = None


def register_ha(ha: DIQHA) -> None:
    global _ha
    _ha = ha


def get_ha() -> Optional[DIQHA]:
    return _ha


# ─────────────────────────────────────────────────────────────────────────────
# BOOTSTRAP
# Called once at gateway startup. Add registrations here.
# ─────────────────────────────────────────────────────────────────────────────

def bootstrap() -> None:
    """
    Register all tools, skills, and subsystem adapters.
    This is the only function that needs to grow as the system expands.
    """
    # ── Tools ────────────────────────────────────────────────────────────────
    # Phase 1.1 — ha_search
    from tools.diq.ha_search_diq import HASearch
    register_tool(HASearch())

    # Phase 1.2 — task_add
    from tools.diq.task_add_diq import TaskAdd
    register_tool(TaskAdd())

    # Phase 1.3 — task_list
    from tools.diq.task_list_diq import TaskList
    register_tool(TaskList())

    # Phase 1.4 — memory_read
    from tools.diq.memory_read_diq import MemoryRead
    register_tool(MemoryRead())

    # Phase 1.5 — notify_home (outbound comms)
    from tools.diq.notify_home_diq import NotifyHome
    register_tool(NotifyHome())

    # Phase 1.6 — home_assistant (HA read+write)
    from tools.diq.home_assistant_diq import HomeAssistant
    register_tool(HomeAssistant())

    # Phase 1.7 — a2a_send (inter-agent channel)
    from tools.diq.a2a_send_diq import A2ASend
    register_tool(A2ASend())

    # Phase 1.8 — a2a_receive (inter-agent channel)
    from tools.diq.a2a_receive_diq import A2AReceive
    register_tool(A2AReceive())

    # Phase 2.1 — memory_store (WRITE role — Aeris denied, Zeph allowed)
    from tools.diq.memory_store_diq import MemoryStore
    register_tool(MemoryStore())

    # Phase 2.2 — cloud_cortex (DIQCloudCortex adapter over aeris_brain)
    from tools.diq.cloud_cortex_diq import CloudCortexDIQ
    register_cloud(CloudCortexDIQ())

    # Phase 3.1 — weather_met, web_context, web_search, web_browse (READ)
    from tools.diq.weather_met_diq import WeatherMet
    register_tool(WeatherMet())

    from tools.diq.web_context_diq import WebContext
    register_tool(WebContext())

    from tools.diq.web_search_diq import WebSearch
    register_tool(WebSearch())

    from tools.diq.web_browse_diq import WebBrowse
    register_tool(WebBrowse())

    # Phase 3.2 — calculator (READ)
    from tools.diq.calculator_diq import Calculator
    register_tool(Calculator())

    # Phase 3.3 — file_read (READ), file_write (WRITE)
    from tools.diq.file_read_diq import FileRead
    register_tool(FileRead())

    from tools.diq.file_write_diq import FileWrite
    register_tool(FileWrite())

    # Phase 3.4 — code_edit (EXEC), shell_exec (EXEC), python_exec (EXEC)
    from tools.diq.code_edit_diq import CodeEdit
    register_tool(CodeEdit())

    from tools.diq.shell_exec_diq import ShellExec
    register_tool(ShellExec())

    from tools.diq.python_exec_diq import PythonExec
    register_tool(PythonExec())

    # Phase 3.5 — propose_code_change (WRITE)
    from tools.diq.propose_code_change_diq import ProposeCodeChange
    register_tool(ProposeCodeChange())

    # Phase 3.6 — trace_reflect (READ), memory_consolidate (ADMIN)
    from tools.diq.trace_reflect_diq import TraceReflect
    register_tool(TraceReflect())

    from tools.diq.memory_consolidate_diq import MemoryConsolidate
    register_tool(MemoryConsolidate())

    # Phase 3.7 — image_generate (WRITE)
    from tools.diq.image_generate_diq import ImageGenerate
    register_tool(ImageGenerate())

    # Phase 4 — Skill gap closure (batch wrap)
    from tools.diq.password_diq import Password
    register_tool(Password())

    from tools.diq.pet_camera_diq import PetCamera
    register_tool(PetCamera())

    from tools.diq.yale_diq import Yale
    register_tool(Yale())

    from tools.diq.system_monitor_diq import SystemMonitor
    register_tool(SystemMonitor())

    from tools.diq.status_diq import Status
    register_tool(Status())

    from tools.diq.memory_skill_diq import MemorySkill
    register_tool(MemorySkill())

    from tools.diq.memory_tools_diq import MemoryTools
    register_tool(MemoryTools())

    from tools.diq.ha_config_diq import HaConfig
    register_tool(HaConfig())

    from tools.diq.self_inspect_diq import SelfInspect
    register_tool(SelfInspect())

    from tools.diq.task_done_diq import TaskDone
    register_tool(TaskDone())

    from tools.diq.plan_task_diq import PlanTask
    register_tool(PlanTask())

    from tools.diq.semantic_search_diq import SemanticSearch
    register_tool(SemanticSearch())

    from tools.diq.github_read_diq import GithubRead
    register_tool(GithubRead())

    # Phase 5 — Hierarchical Memory (Super Tanks v3.0)
    from tools.diq.memory_list_dir_diq import MemoryListDir
    register_tool(MemoryListDir())

    from tools.diq.memory_read_file_diq import MemoryReadFile
    register_tool(MemoryReadFile())

    from tools.diq.memory_store_hierarchical_diq import MemoryStoreHierarchical
    register_tool(MemoryStoreHierarchical())

    from tools.diq.memory_hierarchy_search_diq import MemoryHierarchySearch
    register_tool(MemoryHierarchySearch())

    from tools.diq.memory_delete_diq import MemoryDelete
    register_tool(MemoryDelete())

    # A2A, Cloud, HA, Memory adapters are wired by main_loop.py
    # after their respective subsystems are initialized.

