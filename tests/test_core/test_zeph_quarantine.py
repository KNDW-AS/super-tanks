"""
Tests for core/zeph_quarantine.py — focused on the ZephScanner.

The scanner is the security gate every code proposal must pass through.
We cover sandbox-escape pattern matching (line-by-line, comment-skip),
syntax checking, secret detection, protected-path matching, score
calculation, and the full scan_proposal pipeline against a tmp
quarantine directory.

The higher-level ZephQuarantineService and approval bridges depend on
modules outside this repo's test scope (watchdog, skills.propose_code_change,
core.quarantine.transaction_log) and are not exercised here.
"""

import asyncio
import json
from pathlib import Path

import pytest

from core.zeph_quarantine import ZephScanner


@pytest.fixture
def scanner():
    return ZephScanner()


# ── _scan_sandbox_escapes (pattern catalogue) ──────────────────────────────

class TestSandboxEscapes:
    @pytest.mark.parametrize("snippet,expected_pattern", [
        ("import subprocess", "subprocess"),
        ("subprocess.run(['ls'])", "subprocess"),
        ("os.system('rm -rf /')", "os.system"),
        ("os.popen('ls')", "os.popen"),
        ("os.execvp('/bin/sh', [])", "os.exec"),
        ("os.spawnl(0, 'foo')", "os.spawn"),
        ("exec('payload')", "exec()"),
        ("eval('1+1')", "eval()"),
        ("compile(src, '', 'exec')", "compile()"),
        ("__import__('os')", "__import__"),
        ("import importlib", "importlib"),
        ("os.remove('/tmp/x')", "os.remove"),
        ("os.rmdir('/tmp/d')", "os.rmdir"),
        ("os.rename('a', 'b')", "os.rename"),
        ("shutil.rmtree('/')", "shutil.rmtree"),
        ("shutil.move('a', 'b')", "shutil.move"),
        ("import socket", "socket"),
        ("import urllib", "urllib"),
        ("import requests", "requests"),
        ("aiohttp.ClientSession()", "aiohttp.ClientSession"),
        ("import httpx", "httpx"),
        ("os.setuid(0)", "os.setuid"),
        ("os.setgid(0)", "os.setgid"),
        ("import ctypes", "ctypes"),
        ("crontab -e", "crontab"),
        ("threading.Timer(60, fn)", "threading.Timer"),
        ("sched.scheduler()", "sched.scheduler"),
        ("from apscheduler.schedulers import x", "apscheduler"),
        ("signal.alarm(10)", "signal.alarm"),
    ])
    def test_detects_each_pattern(self, scanner, snippet, expected_pattern):
        violations = scanner._scan_sandbox_escapes(snippet, "test.py")
        assert violations
        assert any(expected_pattern in v["pattern"] for v in violations)

    def test_comment_only_lines_skipped(self, scanner):
        content = "# import subprocess  # mention in comment\nprint('ok')\n"
        violations = scanner._scan_sandbox_escapes(content, "test.py")
        assert violations == []

    def test_inline_comment_still_scanned(self, scanner):
        # The "stripped.startswith('#')" check skips only PURE comment lines.
        content = "import subprocess  # inline note\n"
        violations = scanner._scan_sandbox_escapes(content, "test.py")
        assert violations  # subprocess on the executable side counts.

    def test_line_numbers_correct(self, scanner):
        content = "x = 1\ny = 2\nimport socket\n"
        violations = scanner._scan_sandbox_escapes(content, "test.py")
        assert violations[0]["line"] == 3

    def test_severity_is_critical(self, scanner):
        violations = scanner._scan_sandbox_escapes("eval('x')", "test.py")
        assert violations[0]["severity"] == "CRITICAL"

    def test_safe_code_yields_no_violations(self, scanner):
        content = "def add(a, b):\n    return a + b\nprint(add(1, 2))\n"
        assert scanner._scan_sandbox_escapes(content, "test.py") == []


# ── _check_syntax ──────────────────────────────────────────────────────────

class TestSyntaxCheck:
    def test_valid_python_returns_none(self, scanner):
        assert scanner._check_syntax("a = 1\nb = 2\n") is None

    def test_syntax_error_returns_message_with_line(self, scanner):
        err = scanner._check_syntax("def foo(:\n    pass\n")
        assert err is not None
        assert "Line" in err


# ── Secret detection ───────────────────────────────────────────────────────

class TestSecretDetection:
    @pytest.fixture
    def writer(self, tmp_path):
        def _write(content, name="x.py"):
            p = tmp_path / name
            p.write_text(content)
            return p
        return _write

    def test_api_key_assignment_flagged(self, scanner, writer):
        p = writer("api_key = 'sk-abcdef'\n")
        issues, _ = asyncio.run(scanner._scan_file(p, {}))
        assert any("security" in i.get("category", "") for i in issues)

    def test_password_assignment_flagged(self, scanner, writer):
        p = writer("password = 'hunter2'\n")
        issues, _ = asyncio.run(scanner._scan_file(p, {}))
        assert any("security" in i.get("category", "") for i in issues)

    def test_aws_key_flagged(self, scanner, writer):
        p = writer("KEY = 'AKIA0123456789ABCDEF'\n")
        issues, _ = asyncio.run(scanner._scan_file(p, {}))
        assert any("security" in i.get("category", "") for i in issues)

    def test_clean_file_no_issues(self, scanner, writer):
        p = writer("def foo():\n    return 1\n")
        issues, violations = asyncio.run(scanner._scan_file(p, {}))
        assert issues == []
        assert violations == []


# ── Protected paths ────────────────────────────────────────────────────────

class TestProtectedPaths:
    @pytest.mark.parametrize("path", [
        "core/caller_context.py",
        "core/telegram_bot.py",
        "skills/propose_code_change.py",
        "quarantine/incoming/x",
        "QUARANTINE/INCOMING/x",  # case insensitive
    ])
    def test_protected(self, scanner, path):
        assert scanner._is_protected_path(path) is True

    @pytest.mark.parametrize("path", [
        "core/some_other.py",
        "skills/random.py",
        "data/file.json",
    ])
    def test_not_protected(self, scanner, path):
        assert scanner._is_protected_path(path) is False


# ── _calculate_score ───────────────────────────────────────────────────────

class TestScore:
    def test_no_issues_is_perfect(self, scanner):
        assert scanner._calculate_score([]) == 1.0

    def test_warning_penalty(self, scanner):
        assert scanner._calculate_score(
            [{"severity": "warning"}]) == pytest.approx(0.9)

    def test_error_penalty(self, scanner):
        assert scanner._calculate_score(
            [{"severity": "error"}]) == pytest.approx(0.7)

    def test_score_clamped_at_zero(self, scanner):
        many_errors = [{"severity": "error"} for _ in range(10)]
        assert scanner._calculate_score(many_errors) == 0.0


# ── scan_proposal end-to-end ───────────────────────────────────────────────

def _make_proposal(base: Path, name: str, files: dict, manifest=None):
    """Helper to create a quarantine proposal directory."""
    pdir = base / name
    pdir.mkdir(parents=True, exist_ok=True)
    files_dir = pdir / "files"
    files_dir.mkdir(exist_ok=True)
    for fname, content in files.items():
        (files_dir / fname).write_text(content)
    manifest = manifest or {"proposal_id": name, "files": []}
    (pdir / "manifest.json").write_text(json.dumps(manifest))
    return pdir


class TestScanProposal:
    def test_missing_manifest_fails(self, scanner, tmp_path):
        pdir = tmp_path / "prop_missing"
        pdir.mkdir()
        result = asyncio.run(scanner.scan_proposal(pdir))
        assert result.status == "fail"
        assert "manifest" in result.message.lower()

    def test_clean_proposal_passes(self, scanner, tmp_path):
        pdir = _make_proposal(tmp_path, "prop_clean", {
            "hello.py": "def hi():\n    return 'hi'\n"
        })
        result = asyncio.run(scanner.scan_proposal(pdir))
        assert result.status == "pass"
        assert result.score == 1.0

    def test_sandbox_violation_hard_fails(self, scanner, tmp_path):
        pdir = _make_proposal(tmp_path, "prop_evil", {
            "evil.py": "import subprocess\nsubprocess.run(['rm', '-rf', '/'])\n"
        })
        result = asyncio.run(scanner.scan_proposal(pdir))
        assert result.status == "fail"
        assert result.score == 0.0
        assert result.violations is not None
        assert len(result.violations) >= 1
        assert "Sikkerheitsstopp" in result.message

    def test_syntax_error_yields_warn_or_fail(self, scanner, tmp_path):
        pdir = _make_proposal(tmp_path, "prop_syntax", {
            "broken.py": "def x(:\n    pass\n"
        })
        result = asyncio.run(scanner.scan_proposal(pdir))
        assert result.status == "fail"

    def test_protected_path_yields_warning(self, scanner, tmp_path):
        pdir = _make_proposal(tmp_path, "prop_protected", {
            "main.py": "print('hi')\n"
        }, manifest={
            "proposal_id": "prop_protected",
            "files": [{"path": "core/telegram_bot.py"}],
        })
        result = asyncio.run(scanner.scan_proposal(pdir))
        assert result.status == "warn"
        assert any("protected" in i["message"].lower()
                   for i in result.issues)

    def test_scan_duration_recorded(self, scanner, tmp_path, monkeypatch):
        # Strengthened from `>= 0` (which accepted the
        # missing-manifest early-return path's literal 0). We inject a
        # fake clock so duration is deterministically positive without
        # depending on real wall-clock timing.
        import time as _time
        ticks = iter([1000.0, 1000.123])  # start, end
        monkeypatch.setattr(_time, "time", lambda: next(ticks))

        pdir = _make_proposal(tmp_path, "prop_t", {"x.py": "x = 1\n"})
        result = asyncio.run(scanner.scan_proposal(pdir))
        assert result.scan_duration_ms == 123
