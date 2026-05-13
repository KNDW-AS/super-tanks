"""
Tests for core/security/tool_allowlists.py.

The allowlist is defense-in-depth: even if DIQ role check passes, the
agent must be explicitly listed for the tool. This suite verifies
fail-closed defaults, the agent-specific allowlists, and the explicit
forbidden tools called out in the module docstring.
"""

import pytest

from core.security import tool_allowlists


class TestIsToolAllowed:
    def test_aeris_can_call_read_tool(self):
        assert tool_allowlists.is_tool_allowed("aeris", "memory_read") is True

    def test_zeph_can_call_exec_tool(self):
        assert tool_allowlists.is_tool_allowed("zeph", "python_exec") is True

    def test_unknown_agent_denied(self):
        assert tool_allowlists.is_tool_allowed("ghost", "memory_read") is False

    def test_empty_agent_id_denied(self):
        assert tool_allowlists.is_tool_allowed("", "memory_read") is False

    def test_unknown_tool_denied(self):
        assert tool_allowlists.is_tool_allowed("aeris", "not_a_real_tool") is False

    @pytest.mark.parametrize("forbidden", [
        # From the module docstring — Aeris must NOT have these.
        "code_edit", "python_exec", "shell_exec", "file_write",
        "propose_code_change", "memory_store",
        "memory_consolidate", "image_generate", "task_done",
        "memory_store_hierarchical", "memory_delete",
    ])
    def test_aeris_never_has_exec_or_write_tools(self, forbidden):
        assert tool_allowlists.is_tool_allowed("aeris", forbidden) is False

    @pytest.mark.parametrize("tool", [
        "ha_search", "task_list", "memory_read", "weather_met",
        "web_search", "file_read", "home_assistant", "calculator",
        "a2a_send", "a2a_receive",
    ])
    def test_aeris_read_chat_tools(self, tool):
        assert tool_allowlists.is_tool_allowed("aeris", tool) is True

    @pytest.mark.parametrize("tool", [
        "code_edit", "python_exec", "shell_exec", "file_write",
        "memory_store", "memory_consolidate", "memory_delete",
        "propose_code_change",
    ])
    def test_zeph_has_exec_and_write_tools(self, tool):
        assert tool_allowlists.is_tool_allowed("zeph", tool) is True


class TestAllowlistInvariants:
    def test_only_aeris_and_zeph_have_entries(self):
        assert set(tool_allowlists.AGENT_ALLOWLISTS.keys()) == {"aeris", "zeph"}

    def test_no_duplicates_within_allowlist(self):
        for agent, tools in tool_allowlists.AGENT_ALLOWLISTS.items():
            assert len(tools) == len(set(tools)), \
                f"duplicate tool entries for {agent!r}"

    def test_aeris_subset_excludes_exec_tools(self):
        exec_tools = {"code_edit", "python_exec", "shell_exec", "file_write",
                      "memory_delete", "memory_store"}
        aeris_set = set(tool_allowlists.AGENT_ALLOWLISTS["aeris"])
        assert exec_tools.isdisjoint(aeris_set), \
            "Aeris allowlist must contain zero exec/write tools"

    def test_zeph_is_superset_of_aeris_read_tools(self):
        read_tools = {"ha_search", "memory_read", "weather_met",
                      "web_search", "calculator", "a2a_send", "a2a_receive"}
        zeph_set = set(tool_allowlists.AGENT_ALLOWLISTS["zeph"])
        assert read_tools.issubset(zeph_set), \
            "Zeph should have all of Aeris's read tools too"
