"""
core/security/tool_allowlists.py
==================================
Super Tanks — Per-Agent Tool Allowlists.

Defense-in-depth layer: even if DIQ role check passes, the agent must be
explicitly listed as allowed to call the tool. This limits blast radius if
an agent is compromised or prompt-injected past the ZEF filter.

Integration point: core/gateway.py → dispatch_tool(), AFTER role check.

Rules for adding tools:
  - Each tool entry must be a deliberate decision, not a copy-paste
  - Aeris is READ/CHAT only — she should never appear on EXEC-tier tools
  - Zeph additions require justification (EXEC/ADMIN tools are high risk)
  - Unknown agent_id → deny by default (fail-closed)
"""

import logging
from typing import List

logger = logging.getLogger("zef.allowlist")

# ── Explicit allowlists ───────────────────────────────────────────────────
# Tool names must match exactly what is registered in core/diq/diq_registry.py
# via register_tool(SomeClass()). Check DIQTool.name() for each class.

AGENT_ALLOWLISTS: dict[str, List[str]] = {
    "aeris": [
        # Information retrieval — Aeris is the family assistant (READ/CHAT)
        "ha_search",        # Search HA entities — read-only
        "task_list",        # Read task list
        "memory_read",      # Read episodic memory
        "notify_home",      # TTS / push notification (low risk)
        "calculator",       # Math — stateless, harmless
        # Inter-agent communication
        "a2a_send",         # Send message to Zeph
        "a2a_receive",      # Receive messages from Zeph
        # Task creation (not execution)
        "task_add",         # Add a task — no exec path
        # Web & weather — READ only
        "weather_met",      # Weather data from MET/YR
        "web_search",       # DuckDuckGo search
        "web_browse",       # Read webpage content
        "web_context",      # Extract readable text from URL
        # File reading (not writing)
        "file_read",        # Read files within allowed roots
        # Smart home — Aeris is the family assistant, must control HA
        "home_assistant",   # WRITE — turn on/off lights, climate, locks, sensors
        # Reflection — READ only, no writes
        "trace_reflect",    # Analyze tool-call history
        # Phase 4: Skill gap closure — READ tools for Aeris
        "password",         # Generate passwords (stateless)
        "pet_camera",       # Pet/camera status (read-only)
        "yale",             # Yale lock status (read-only)
        "system_monitor",   # System metrics (read-only)
        "status",           # Quick system status (read-only)
        "memory_skill",     # RAG query (read-only)
        "ha_config",        # HA config reading (read-only)
        "self_inspect",     # System inspection (read-only)
        "plan_task",        # Task planning (read-only, uses Kimi)
        "semantic_search",  # Vector DB search (read-only)
        "github_read",      # GitHub repo reading (read-only)
        # Phase 5: Hierarchical Memory (READ only for Aeris)
        "memory_list_dir",  # List memory directories
        "memory_read_file", # Read memory files
        "memory_hierarchy_search",  # Search hierarchical memory
        # Aeris should NOT have: code_edit, python_exec, shell_exec,
        # file_write, git_commit, propose_code_change, memory_write,
        # memory_store, memory_consolidate, image_generate,
        # memory_tools, task_done
    ],
    "zeph": [
        # Zeph gets all Aeris tools plus WRITE/EXEC/ADMIN tools
        "ha_search",
        "task_list",
        "task_add",
        "memory_read",
        "memory_store",     # Write to memory — WRITE role
        "notify_home",
        "calculator",
        "a2a_send",
        "a2a_receive",
        # Web & weather — READ
        "weather_met",
        "web_search",
        "web_browse",
        "web_context",
        # File system — READ + WRITE
        "file_read",
        "file_write",       # WRITE — GO-GATE gated
        # Code & execution — EXEC
        "code_edit",        # Edit code files
        "python_exec",      # Run Python in sandbox
        "shell_exec",       # Run shell commands (allowlisted)
        # Code proposals — WRITE
        "propose_code_change",  # Send to quarantine for review
        # Smarthome — WRITE
        "home_assistant",   # Call HA services (lights, locks, etc.)
        # Analysis & memory
        "trace_reflect",    # Tool-call history analysis
        "memory_consolidate",  # ADMIN — consolidate episodic memory
        "image_generate",   # Generate images via Gemini
        # Phase 4: Skill gap closure — all READ tools + WRITE tools for Zeph
        "password",         # Generate passwords
        "pet_camera",       # Pet/camera status
        "yale",             # Yale lock status
        "system_monitor",   # System metrics
        "status",           # Quick system status
        "memory_skill",     # RAG query
        "memory_tools",     # WRITE — save/recall episodic memory
        "ha_config",        # HA config reading
        "self_inspect",     # System inspection
        "task_done",        # WRITE — mark tasks complete
        "plan_task",        # Task planning
        "semantic_search",  # Vector DB search
        "github_read",      # GitHub repo reading
        # Phase 5: Hierarchical Memory (READ + WRITE + DELETE for Zeph)
        "memory_list_dir",  # List memory directories
        "memory_read_file", # Read memory files
        "memory_hierarchy_search",  # Search hierarchical memory
        "memory_store_hierarchical",  # WRITE — store memory files
        "memory_delete",    # ADMIN — delete memory files
    ],
    # ── Cody: third digital child — code-review and refactor agent ──
    # Cody is the "is this code right?" agent. He reads memory + audit
    # to do informed reviews, and proposes changes via shadow_store. He
    # has NO direct write path to the working tree; every diff routes
    # through GO-Gate and a human merge.
    #
    # Invariants live in core/security/cody_directives.py. The canonical
    # allow-set is CODY_ALLOWED_TOOLS in that file. Keeping the list
    # here mirrors the Aeris/Zeph pattern; the two MUST stay in sync —
    # tests/test_security/test_cody_directives.py asserts equality.
    "cody": [
        # READ-only inspection
        "memory_read_file",
        "memory_list_dir",
        "memory_hierarchy_search",
        "hybrid_search",
        "trace_reflect",
        "self_inspect",
        "status",
        "semantic_search",
        "file_read",
        "calculator",
        # Proposals only — these write into data/shadow_proposals/
        # which is read by GO-Gate / human review, not into the
        # live codebase.
        "shadow_store_propose",
        "propose_code_change",
        # A2A so Cody can collaborate with Aeris/Zeph on triage.
        "a2a_send",
        "a2a_receive",
        # Cody should NOT have: shell_exec, python_exec, code_edit,
        # file_write, memory_delete, memory_store_hierarchical,
        # home_assistant, notify_home, image_generate,
        # propose_code_change_apply.
    ],
}


def is_tool_allowed(agent_id: str, tool_name: str) -> bool:
    """
    Check whether agent_id is permitted to call tool_name.

    Unknown agents are denied by default (fail-closed).
    Returns True only if agent_id has an explicit entry in AGENT_ALLOWLISTS
    and tool_name appears in that entry's list.
    """
    allowlist = AGENT_ALLOWLISTS.get(agent_id)
    if allowlist is None:
        # Unknown agent — fail-closed
        logger.warning(
            "🛡️ ALLOWLIST DENIED: unknown agent %r tried to call %r",
            agent_id, tool_name,
        )
        return False

    allowed = tool_name in allowlist
    if not allowed:
        logger.warning(
            "🛡️ ALLOWLIST DENIED: agent=%r tried tool=%r (not in allowlist)",
            agent_id, tool_name,
        )
    return allowed
