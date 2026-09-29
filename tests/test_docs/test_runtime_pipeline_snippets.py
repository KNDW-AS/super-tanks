"""Every ```python block in docs/RUNTIME_PIPELINE.md must run as written.

Each block runs in its own subprocess from the repo root. A short
prelude (not part of the doc) only redirects the SQLite stores and keys
to a temp dir so the test never writes to data/. Blocks whose first line
is `# requires: <module>` are skipped when that module is missing, and
blocks starting with `# not run by the doc test` (they need a live
service) are always skipped.
When a block is followed by an "Output" text block, stdout must match it
(UUIDs masked).
"""

import importlib.util
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "RUNTIME_PIPELINE.md"

PRELUDE = textwrap.dedent("""
    import os, pathlib, tempfile
    _tmp = pathlib.Path(tempfile.mkdtemp(prefix="st_doc_"))
    os.environ["SUPER_TANKS_APPROVAL_DB"] = str(_tmp / "approvals.db")
    os.environ["SUPER_TANKS_IDENTITY_KEY"] = "doc-test-identity-key"
    os.environ["SUPER_TANKS_AUDIT_KEY"] = "doc-test-audit-key"
    from core.security import circuit_breaker as _cb, dispatch_audit as _da, mcp_security as _ms
    _da.DB_PATH = _tmp / "dispatch.db"; _da._initialised = False
    _cb.DB_PATH = _tmp / "cb.db"; _ms.DB_PATH = _tmp / "mcp.db"
""")


_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def _blocks():
    """[(code, expected_output_or_None)] for every ```python block.

    The expected output is the first ```text block after the code block
    (and before the next ```python block) that is introduced by a line
    starting with "Output".
    """
    text = DOC.read_text(encoding="utf-8")
    out = []
    for m in re.finditer(r"```python\n(.*?)```", text, flags=re.S):
        tail = text[m.end():]
        nxt = tail.find("```python")
        tail = tail if nxt < 0 else tail[:nxt]
        exp = re.search(r"^Output[^\n]*\n\n```text\n(.*?)```", tail, flags=re.S | re.M)
        out.append((m.group(1), exp.group(1) if exp else None))
    return out


def _normalise(s):
    return [_UUID.sub("<UUID>", line.rstrip()) for line in s.strip().splitlines()]


BLOCKS = _blocks()


def test_doc_has_python_blocks():
    assert len(BLOCKS) >= 4
    assert sum(1 for _, exp in BLOCKS if exp) >= 3


@pytest.mark.timeout(120)
@pytest.mark.parametrize("index", range(len(BLOCKS)))
def test_block_runs(index, tmp_path):
    code, expected = BLOCKS[index]
    first = code.lstrip().splitlines()[0]
    if first.startswith("# not run by the doc test"):
        pytest.skip(first)
    m = re.match(r"#\s*requires:\s*(\w+)", first)
    if m and importlib.util.find_spec(m.group(1)) is None:
        pytest.skip(f"{m.group(1)} not installed")
    script = tmp_path / f"block_{index}.py"
    script.write_text(PRELUDE + "\n" + code, encoding="utf-8")
    proc = subprocess.run([sys.executable, str(script)], cwd=str(ROOT),
                          capture_output=True, text=True, encoding="utf-8",
                          env={**os.environ, "PYTHONPATH": str(ROOT),
                               "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"},
                          timeout=110)
    assert proc.returncode == 0, proc.stderr[-2000:]
    if expected is not None:
        assert _normalise(proc.stdout) == _normalise(expected), proc.stdout
