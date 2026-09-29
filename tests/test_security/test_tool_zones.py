"""Layer 8 — core/security/tool_zones.py."""

import pytest

from core.security import tool_zones as tz
from core.security.tool_zones import Zone, ZoneAction


@pytest.fixture(autouse=True)
def isolated_maps(monkeypatch):
    monkeypatch.setattr(tz, "TOOL_ZONES", dict(tz.TOOL_ZONES))
    monkeypatch.setattr(tz, "ZONE_ACTIONS", dict(tz.ZONE_ACTIONS))


def test_unknown_tool_is_uncategorized_and_gated():
    assert tz.get_zone("never_heard_of_it") is Zone.UNCATEGORIZED
    assert tz.zone_action("never_heard_of_it") is ZoneAction.GO_GATE
    assert tz.risk_weight("never_heard_of_it") == max(tz.ZONE_RISK_WEIGHT.values())


@pytest.mark.parametrize("tool,action", [
    ("file_read", ZoneAction.ALLOW),
    ("web_search", ZoneAction.ALLOW),
    ("a2a_send", ZoneAction.ALLOW),
    ("file_write", ZoneAction.GO_GATE),
    ("shell_exec", ZoneAction.GO_GATE),
    ("memory_delete", ZoneAction.GO_GATE),
])
def test_default_actions(tool, action):
    assert tz.zone_action(tool) is action


def test_every_zone_has_action_and_weight():
    for zone in Zone:
        assert zone in tz.ZONE_ACTIONS
        assert zone in tz.ZONE_RISK_WEIGHT


def test_every_allowlisted_tool_has_a_zone():
    from core.security.tool_allowlists import AGENT_ALLOWLISTS
    missing = {t for tools in AGENT_ALLOWLISTS.values() for t in tools} - set(tz.TOOL_ZONES)
    assert not missing, f"allowlisted tools without a zone: {sorted(missing)}"


def test_set_tool_zone_and_zone_action():
    tz.set_tool_zone("my_tool", Zone.NETWORK_READ)
    assert tz.zone_action("my_tool") is ZoneAction.ALLOW
    tz.set_zone_action(Zone.NETWORK_READ, ZoneAction.DENY)
    assert tz.zone_action("my_tool") is ZoneAction.DENY
    with pytest.raises(ValueError):
        tz.set_tool_zone("x", "not-a-zone")


def test_coverage_report_counts():
    report = tz.coverage_report()
    assert report["total_tools_mapped"] == len(tz.TOOL_ZONES)
    assert sum(report["by_zone"].values()) == len(tz.TOOL_ZONES)
    assert report["zone_actions"]["uncategorized"] == "go_gate"
    assert "shell_exec" in tz.get_tools_in_zone(Zone.EXEC)
