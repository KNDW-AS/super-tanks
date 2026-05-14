"""
Tests for core/soul_guard.py.

The guard hashes soul files against a sealed manifest at startup and
flips SOUL_SAFE_MODE if anything has changed. These tests redirect
REPO_ROOT to a tmp path so each test runs with a controlled manifest +
soul files, and stub the Telegram alert.
"""

import hashlib
import json
import sys
import types
from pathlib import Path

import pytest


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def soul_env(tmp_path, monkeypatch):
    """Build a fake repo layout and patch soul_guard module pointers."""
    from core import soul_guard

    # Reset the global flag — earlier tests in the same session might
    # have left it set.
    monkeypatch.setattr(soul_guard, "SOUL_SAFE_MODE", False)
    monkeypatch.setattr(soul_guard, "SOUL_SAFE_MODE_REASON", "")

    # Repo layout: tmp/core/aeris_soul.py + tmp/core/zeph_soul.py + manifest
    core_dir = tmp_path / "core"
    core_dir.mkdir()
    aeris = core_dir / "aeris_soul.py"
    zeph = core_dir / "zeph_soul.py"
    aeris.write_bytes(b"# aeris soul\nprint('hi')\n")
    zeph.write_bytes(b"# zeph soul\nprint('hi')\n")

    manifest = {
        "souls": {
            "aeris": {"file": "core/aeris_soul.py",
                      "sha256": _sha256(aeris.read_bytes())},
            "zeph": {"file": "core/zeph_soul.py",
                     "sha256": _sha256(zeph.read_bytes())},
        }
    }
    integrity_file = core_dir / "soul_integrity.json"
    integrity_file.write_text(json.dumps(manifest))

    monkeypatch.setattr(soul_guard, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(soul_guard, "INTEGRITY_FILE", integrity_file)

    # Capture Telegram alerts.
    alerts = []
    monkeypatch.setattr(soul_guard, "_send_telegram_alert",
                        lambda msg: alerts.append(msg))

    return types.SimpleNamespace(
        sg=soul_guard,
        root=tmp_path,
        aeris=aeris,
        zeph=zeph,
        manifest_path=integrity_file,
        alerts=alerts,
    )


# ── _hash_file ─────────────────────────────────────────────────────────────

class TestHashFile:
    def test_matches_known_sha256(self, tmp_path):
        from core.soul_guard import _hash_file
        f = tmp_path / "x.bin"
        f.write_bytes(b"hello")
        assert _hash_file(f) == _sha256(b"hello")

    def test_streams_large_file_correctly(self, tmp_path):
        from core.soul_guard import _hash_file
        f = tmp_path / "big.bin"
        # 200 KB > the 64 KB read chunk → exercises the streaming loop.
        payload = b"A" * (200 * 1024)
        f.write_bytes(payload)
        assert _hash_file(f) == _sha256(payload)


# ── check_soul_integrity — happy path ──────────────────────────────────────

class TestIntegrityClean:
    def test_unchanged_files_return_ok(self, soul_env):
        ok, reason = soul_env.sg.check_soul_integrity()
        assert ok is True
        assert reason == "ok"
        assert soul_env.sg.is_safe_mode() is False

    def test_clean_run_does_not_alert(self, soul_env):
        soul_env.sg.check_soul_integrity()
        assert soul_env.alerts == []


# ── check_soul_integrity — missing manifest ────────────────────────────────

class TestIntegrityNoManifest:
    def test_missing_manifest_passes_with_warning(self, soul_env):
        soul_env.manifest_path.unlink()
        ok, reason = soul_env.sg.check_soul_integrity()
        assert ok is True
        assert "soul_integrity.json not found" in reason
        assert soul_env.sg.is_safe_mode() is False


# ── check_soul_integrity — corrupt manifest ────────────────────────────────

class TestIntegrityCorruptManifest:
    def test_invalid_json_forces_safe_mode(self, soul_env):
        soul_env.manifest_path.write_text("{ not valid json")
        ok, reason = soul_env.sg.check_soul_integrity()
        assert ok is False
        assert soul_env.sg.is_safe_mode() is True
        assert "Cannot read soul_integrity.json" in reason


# ── check_soul_integrity — hash mismatch ───────────────────────────────────

class TestIntegrityMismatch:
    def test_modified_soul_triggers_safe_mode(self, soul_env):
        soul_env.aeris.write_bytes(b"# TAMPERED soul\n")
        ok, reason = soul_env.sg.check_soul_integrity()
        assert ok is False
        assert soul_env.sg.is_safe_mode() is True
        assert "HASH MISMATCH" in reason
        assert "aeris" in reason

    def test_modified_soul_sends_telegram_alert(self, soul_env):
        soul_env.zeph.write_bytes(b"# TAMPERED\n")
        soul_env.sg.check_soul_integrity()
        assert len(soul_env.alerts) == 1
        assert "SOUL INTEGRITY ALERT" in soul_env.alerts[0]
        assert "/approve_soul_start" in soul_env.alerts[0]

    def test_safe_mode_reason_exposed(self, soul_env):
        soul_env.aeris.write_bytes(b"# TAMPERED\n")
        soul_env.sg.check_soul_integrity()
        assert "aeris" in soul_env.sg.get_safe_mode_reason()


# ── check_soul_integrity — missing soul file ───────────────────────────────

class TestIntegrityMissingSoul:
    def test_missing_soul_file_triggers_safe_mode(self, soul_env):
        soul_env.aeris.unlink()
        ok, reason = soul_env.sg.check_soul_integrity()
        assert ok is False
        assert soul_env.sg.is_safe_mode() is True
        assert "FILE MISSING" in reason


# ── safe_mode_response ─────────────────────────────────────────────────────

class TestSafeModeResponse:
    def test_returns_canned_norwegian_message(self):
        from core.soul_guard import safe_mode_response
        text = safe_mode_response()
        assert "SAFE MODE" in text
        assert "/approve_soul_start" in text


# ── _send_telegram_alert ───────────────────────────────────────────────────

class TestTelegramAlert:
    def test_skips_when_token_missing(self, monkeypatch):
        from core import soul_guard
        monkeypatch.delenv("AERIS_TELEGRAM_TOKEN", raising=False)
        monkeypatch.delenv("ZEPH_TELEGRAM_TOKEN", raising=False)

        called = []
        fake_requests = types.SimpleNamespace(
            post=lambda *a, **kw: called.append((a, kw)))
        monkeypatch.setitem(sys.modules, "requests", fake_requests)

        soul_guard._send_telegram_alert("hello")
        assert called == []

    def test_swallows_network_errors(self, monkeypatch):
        from core import soul_guard
        monkeypatch.setenv("AERIS_TELEGRAM_TOKEN", "fake-token")
        monkeypatch.setenv("ADMIN_USER_ID", "12345")

        def boom(*a, **kw):
            raise RuntimeError("network down")

        fake_requests = types.SimpleNamespace(post=boom)
        monkeypatch.setitem(sys.modules, "requests", fake_requests)

        # Must not raise.
        soul_guard._send_telegram_alert("hello")

    def test_posts_to_telegram_api_when_token_present(self, monkeypatch):
        from core import soul_guard
        monkeypatch.setenv("AERIS_TELEGRAM_TOKEN", "fake-token")
        monkeypatch.setenv("ADMIN_USER_ID", "55")

        seen = []
        fake_requests = types.SimpleNamespace(
            post=lambda url, json, timeout: seen.append((url, json, timeout)))
        monkeypatch.setitem(sys.modules, "requests", fake_requests)

        soul_guard._send_telegram_alert("hello")
        assert len(seen) == 1
        url, payload, _ = seen[0]
        assert "sendMessage" in url
        assert payload["chat_id"] == "55"
        assert payload["text"] == "hello"
        assert payload["parse_mode"] == "Markdown"
