"""
tests/test_memory/test_raw_store_allowlist.py
=============================================
R-08 enforcement: production code must reach memory through SecureMemoryStore.

`HierarchicalMemoryStore` is the raw data plane and enforces nothing — no
tripwire, no RBAC, no audit entry. `SecureMemoryStore` is the only class
agent-facing code should import.

Migrating the call sites once is not enough: without this test the count
creeps back up, and the risk register keeps saying "Medium" while everyone
believes it was fixed. So the allowlist below is the contract. Adding a new
raw import is allowed — but it has to be argued for here, in writing, by
someone who read this docstring.

Each entry states WHY that file is exempt. "It was already there" is not a
reason; if you cannot write the reason, migrate the call instead.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCANNED_DIRS = ("core", "scripts")

# file path → why raw access is correct there
ALLOWLIST = {
    "core/memory/hierarchical_store.py":
        "Defines the class — this is the raw data plane itself.",
    "core/memory/tripwires.py":
        "ensure_tripwires_exist() takes the raw store as a parameter and writes "
        "the honeypots. Same reason as bootstrap: the code that lays the traps "
        "cannot go through the layer that alarms on them.",
    "core/memory/secure_store.py":
        "The sanctioned wrapper — it exists to hold the only raw handle.",
    "core/bootstrap.py":
        "Deploys the honeypot files themselves. Through SecureMemoryStore the "
        "write would hit is_tripwire() on the very paths being created and "
        "raise the alarm on every boot.",
    "core/zeph/proactive_monitor.py":
        "Verifies the honeypots are intact. Reading a tripwire path through "
        "SecureMemoryStore is by design an alarm; the daily health check would "
        "force LOCKDOWN every time it ran.",
    "core/memory/hybrid_search.py":
        "hierarchical_search() generates unranked candidates across all paths. "
        "Its only production caller RBAC-filters the result set in step 5 "
        "before anything is returned to an agent. Must never be exposed "
        "directly to agent-facing tools.",
}

PATTERN = re.compile(r"\bHierarchicalMemoryStore\b")


def _python_files():
    for d in SCANNED_DIRS:
        root = REPO_ROOT / d
        if root.exists():
            yield from root.rglob("*.py")


def test_no_unlisted_raw_store_usage():
    """Any file touching the raw store must be on the allowlist, with a reason."""
    offenders = []
    for path in _python_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        if not PATTERN.search(text):
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel not in ALLOWLIST:
            offenders.append(rel)

    assert not offenders, (
        "These files reach the raw HierarchicalMemoryStore without being on the "
        "R-08 allowlist:\n  " + "\n  ".join(sorted(offenders)) +
        "\n\nRoute the call through SecureMemoryStore (it needs an agent_id), or "
        "add the file to ALLOWLIST in this test with a written reason for why "
        "raw access is correct there."
    )


def test_allowlist_has_no_stale_entries():
    """An allowlist entry that no longer uses the raw store must be removed.

    A stale exemption is worse than no exemption: it silently re-permits raw
    access the day someone adds a call back into that file.
    """
    stale = []
    for rel in ALLOWLIST:
        path = REPO_ROOT / rel
        if not path.exists():
            stale.append(f"{rel} (file is gone)")
            continue
        if not PATTERN.search(path.read_text(encoding="utf-8", errors="ignore")):
            stale.append(f"{rel} (no longer uses the raw store)")

    assert not stale, (
        "Stale R-08 allowlist entries — remove them from ALLOWLIST:\n  "
        + "\n  ".join(sorted(stale))
    )


def test_every_allowlist_entry_states_a_reason():
    """The reason is the point. An empty or token reason fails."""
    weak = [rel for rel, why in ALLOWLIST.items() if len((why or "").strip()) < 20]
    assert not weak, (
        "These allowlist entries lack a real justification: " + ", ".join(sorted(weak))
    )
