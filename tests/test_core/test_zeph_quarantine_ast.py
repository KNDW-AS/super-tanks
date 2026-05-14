"""
Tests for core/zeph_quarantine_ast.py.

The AST scanner has to catch obfuscation that the old regex scanner
silently passed. These tests focus on the obfuscation cases — the
straight-import cases are already covered by test_zeph_quarantine.py
since ZephScanner._scan_sandbox_escapes now delegates to the AST scan.
"""

import pytest

from core.zeph_quarantine_ast import scan_python_source


# ── Bypasses the regex scanner used to miss ───────────────────────────

class TestObfuscationBypasses:
    def test_aliased_dangerous_import_caught(self):
        # `from os import system as s; s("rm -rf /")` was a regex bypass.
        code = "from os import system as s\ns('rm -rf /')\n"
        violations = scan_python_source(code, "evil.py")
        assert violations, "aliased os.system import not caught"
        assert any("os.system" in v["pattern"] for v in violations)

    def test_getattr_string_concat_obfuscation_caught(self):
        # `getattr(__builtins__, "ex" + "ec")("...")` — split exec name.
        code = 'getattr(__builtins__, "ex" + "ec")("payload")\n'
        violations = scan_python_source(code, "evil.py")
        assert any("getattr-obfuscation" in v["pattern"] for v in violations)

    def test_builtins_dunder_access_caught(self):
        code = "x = __builtins__.exec\n"
        violations = scan_python_source(code, "evil.py")
        assert any("__builtins__" in v["pattern"] for v in violations)

    def test_subclasses_walk_caught(self):
        # `().__class__.__bases__[0].__subclasses__()` — classic escape.
        code = "().__class__.__bases__[0].__subclasses__()\n"
        violations = scan_python_source(code, "evil.py")
        patterns = {v["pattern"] for v in violations}
        assert any("__subclasses__" in p for p in patterns)
        assert any("__bases__" in p for p in patterns)

    def test_importlib_aliased_to_innocent_name(self):
        # `import importlib as i; i.import_module("os").system(...)`
        code = (
            "import importlib as i\n"
            'i.import_module("os").system("evil")\n'
        )
        violations = scan_python_source(code, "evil.py")
        # The import itself is banned.
        assert any("importlib" in v["pattern"] for v in violations)


# ── Direct calls to banned builtins ───────────────────────────────────

class TestBannedBuiltins:
    @pytest.mark.parametrize("call,expected", [
        ('exec("payload")', "exec"),
        ('eval("1+1")', "eval"),
        ('compile("x", "<>", "exec")', "compile"),
        ('__import__("os")', "__import__"),
    ])
    def test_direct_call_caught(self, call, expected):
        violations = scan_python_source(call + "\n", "evil.py")
        assert any(expected in v["pattern"] for v in violations)


# ── Banned attribute access via the module ────────────────────────────

class TestBannedAttributes:
    @pytest.mark.parametrize("code,expected", [
        ('import os\nos.remove("/tmp/x")\n', "os.remove"),
        ('import os\nos.execvp("/bin/sh", [])\n', "os.exec*"),
        ('import os\nos.spawnl(0, "x")\n', "os.spawn*"),
        ('import shutil\nshutil.rmtree("/")\n', "shutil.rmtree"),
        ('import threading\nthreading.Timer(60, lambda: None)\n', "threading.Timer"),
        ('import sched\nsched.scheduler()\n', "sched.scheduler"),
        ('import signal\nsignal.alarm(10)\n', "signal.alarm"),
        ('import aiohttp\naiohttp.ClientSession()\n', "aiohttp.ClientSession"),
    ])
    def test_attribute_access_flagged(self, code, expected):
        violations = scan_python_source(code, "evil.py")
        assert any(expected in v["pattern"] for v in violations), \
            f"missed {expected} in {code!r}: got {violations}"


# ── Syntax errors fail closed ─────────────────────────────────────────

class TestSyntaxError:
    def test_unparseable_file_yields_violation(self):
        code = "def x(:\n    pass\n"
        violations = scan_python_source(code, "broken.py")
        assert len(violations) == 1
        assert "syntax_error" in violations[0]["pattern"]
        assert violations[0]["severity"] == "CRITICAL"


# ── Clean files don't trigger ─────────────────────────────────────────

class TestCleanCode:
    @pytest.mark.parametrize("code", [
        "def add(a, b):\n    return a + b\n",
        "import math\nx = math.sqrt(2)\n",
        "import json\ndata = json.loads('{}')\n",
        "class Foo:\n    def bar(self): return 1\n",
    ])
    def test_no_violations(self, code):
        assert scan_python_source(code, "clean.py") == []


# ── Comment-only lines are ignored (no NameError from harmless mentions) ──

class TestComments:
    def test_subprocess_in_comment_is_clean(self):
        # AST never sees comments, so this is implicitly safe — but
        # asserting it here pins the contract.
        code = "# we deliberately do NOT import subprocess here\nx = 1\n"
        assert scan_python_source(code, "ok.py") == []


# ── Line numbers are correct ──────────────────────────────────────────

class TestLineNumbers:
    def test_violation_records_actual_line(self):
        code = (
            "x = 1\n"
            "y = 2\n"
            'exec("payload")\n'
        )
        violations = scan_python_source(code, "evil.py")
        exec_v = [v for v in violations if "exec" in v["pattern"]][0]
        assert exec_v["line"] == 3
