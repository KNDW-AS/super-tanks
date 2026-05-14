"""
Tests for scripts/verify_frozen.py.

Pure SHA256-against-manifest check. The script imports as a module
without side effects so we can call `verify_frozen()` directly after
redirecting the manifest path via monkeypatch.
"""

import hashlib
import json
import sys
from pathlib import Path

import pytest

# Load the script as a module by path.
_SCRIPT = Path(__file__).resolve().parent.parent.parent / "scripts" / "verify_frozen.py"


@pytest.fixture
def vf(tmp_path, monkeypatch):
    """Import the script with __file__ pointing at a tmp scratch dir."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("verify_frozen_test",
                                                  str(_SCRIPT))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    # Build a tmp repo layout: tmp/<files> + tmp/core_locked/FROZEN_MANIFEST.json
    repo = tmp_path
    locked = repo / "core_locked"
    locked.mkdir()
    scripts = repo / "scripts"
    scripts.mkdir()

    # The script computes `manifest_path = Path(__file__).parent.parent / "core_locked"`.
    # Monkeypatching __file__ on a module is tricky; we instead inject a
    # mini Path-rooted helper by reusing the module's function with a
    # patched manifest_path discovery.
    monkeypatch.setattr(mod, "__file__", str(scripts / "verify_frozen.py"))
    return mod, repo


def _seed_files(repo: Path, files: dict) -> dict:
    """Drop files into the repo and build a manifest entry list."""
    entries = []
    for relpath, content in files.items():
        target = repo / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        entries.append({
            "path": relpath,
            "sha256": hashlib.sha256(content).hexdigest(),
        })
    return entries


def _write_manifest(repo: Path, entries: list, commit="abc123", created="2024-01-01"):
    manifest = {
        "git_commit": commit,
        "created": created,
        "frozen_files": entries,
    }
    (repo / "core_locked" / "FROZEN_MANIFEST.json").write_text(
        json.dumps(manifest))


# ── calculate_sha256 ───────────────────────────────────────────────────────

class TestCalculateSha256:
    def test_matches_known(self, vf, tmp_path):
        mod, _ = vf
        p = tmp_path / "x.bin"
        p.write_bytes(b"hello")
        assert mod.calculate_sha256(p) == hashlib.sha256(b"hello").hexdigest()

    def test_streams_large_files(self, vf, tmp_path):
        mod, _ = vf
        p = tmp_path / "big.bin"
        payload = b"A" * (10 * 4096 + 17)  # > one read-chunk
        p.write_bytes(payload)
        assert mod.calculate_sha256(p) == hashlib.sha256(payload).hexdigest()


# ── verify_frozen ──────────────────────────────────────────────────────────

class TestVerifyFrozen:
    def test_missing_manifest_returns_false(self, vf):
        mod, _ = vf
        assert mod.verify_frozen() is False

    def test_clean_manifest_returns_true(self, vf, capsys):
        mod, repo = vf
        entries = _seed_files(repo, {
            "core/a.py": b"a content\n",
            "core/b.py": b"b content\n",
        })
        _write_manifest(repo, entries)
        assert mod.verify_frozen() is True
        out = capsys.readouterr().out
        assert "ALL FROZEN FILES VERIFIED" in out

    def test_tampered_file_returns_false(self, vf, capsys):
        mod, repo = vf
        entries = _seed_files(repo, {"core/a.py": b"original\n"})
        _write_manifest(repo, entries)
        # Mutate file after sealing.
        (repo / "core" / "a.py").write_bytes(b"TAMPERED\n")
        assert mod.verify_frozen() is False
        assert "TAMPERED" in capsys.readouterr().out

    def test_missing_file_returns_false(self, vf, capsys):
        mod, repo = vf
        entries = _seed_files(repo, {"core/a.py": b"a\n"})
        _write_manifest(repo, entries)
        (repo / "core" / "a.py").unlink()
        assert mod.verify_frozen() is False
        assert "MISSING" in capsys.readouterr().out
