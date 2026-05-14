"""
Tests for scripts/verify_frozen.py.

The script delegates to DIQ_CHECKSUMS.json. Tests redirect both
PROJECT_ROOT / DIQ_DIR / CHECKSUMS_FILE to a tmp scratch tree so each
run starts from a clean manifest.
"""

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent.parent / "scripts" / "verify_frozen.py"


@pytest.fixture
def vf(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("verify_frozen_test",
                                                  str(_SCRIPT))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    diq_dir = tmp_path / "core" / "diq"
    diq_dir.mkdir(parents=True)
    monkeypatch.setattr(mod, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(mod, "DIQ_DIR", diq_dir)
    monkeypatch.setattr(mod, "CHECKSUMS_FILE", diq_dir / "DIQ_CHECKSUMS.json")
    return mod, diq_dir


def _seed_files(diq_dir: Path, files: dict) -> dict:
    """Write files and return {name: sha256} manifest."""
    manifest = {}
    for name, content in files.items():
        (diq_dir / name).write_bytes(content)
        manifest[name] = hashlib.sha256(content).hexdigest()
    return manifest


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
        payload = b"A" * (10 * 4096 + 17)
        p.write_bytes(payload)
        assert mod.calculate_sha256(p) == hashlib.sha256(payload).hexdigest()


# ── verify_frozen ──────────────────────────────────────────────────────────

class TestVerifyFrozen:
    def test_missing_manifest_returns_false(self, vf, capsys):
        mod, _ = vf
        assert mod.verify_frozen() is False
        assert "not found" in capsys.readouterr().out

    def test_corrupt_manifest_returns_false(self, vf, capsys):
        mod, diq_dir = vf
        (diq_dir / "DIQ_CHECKSUMS.json").write_text("{ not json")
        assert mod.verify_frozen() is False
        assert "corrupt" in capsys.readouterr().out

    def test_clean_manifest_returns_true(self, vf, capsys):
        mod, diq_dir = vf
        manifest = _seed_files(diq_dir, {
            "diq_tools.py": b"contract A\n",
            "diq_a2a.py":   b"contract B\n",
        })
        (diq_dir / "DIQ_CHECKSUMS.json").write_text(json.dumps(manifest))
        assert mod.verify_frozen() is True
        assert "ALL FROZEN FILES VERIFIED" in capsys.readouterr().out

    def test_tampered_file_returns_false(self, vf, capsys):
        mod, diq_dir = vf
        manifest = _seed_files(diq_dir, {"diq_tools.py": b"original\n"})
        (diq_dir / "DIQ_CHECKSUMS.json").write_text(json.dumps(manifest))
        (diq_dir / "diq_tools.py").write_bytes(b"TAMPERED\n")
        assert mod.verify_frozen() is False
        assert "TAMPERED" in capsys.readouterr().out

    def test_missing_file_returns_false(self, vf, capsys):
        mod, diq_dir = vf
        manifest = _seed_files(diq_dir, {"diq_tools.py": b"x\n"})
        (diq_dir / "DIQ_CHECKSUMS.json").write_text(json.dumps(manifest))
        (diq_dir / "diq_tools.py").unlink()
        assert mod.verify_frozen() is False
        assert "MISSING" in capsys.readouterr().out
