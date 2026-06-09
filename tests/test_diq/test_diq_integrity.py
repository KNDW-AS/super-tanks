"""
Tests for core/diq/diq_integrity.py.

Verifies the SHA256-manifest verification used at gateway startup,
the first-boot tolerance (missing manifest → warning, not failure),
and the failure modes (missing files, missing entries, tampered hashes).
The module operates on its own filesystem layout, so we redirect
`_DIQ_DIR` and `_CHECKSUMS_FILE` to a tmp scratch directory.
"""

import hashlib
import json
import shutil

import pytest

from core.diq import diq_integrity as di


@pytest.fixture
def scratch(tmp_path, monkeypatch):
    """Build a sandboxed copy of the DIQ frozen files in tmp_path."""
    real_dir = di._DIQ_DIR
    diq_dir = tmp_path / "diq"
    diq_dir.mkdir()
    for name in di.FROZEN_FILES:
        shutil.copy(real_dir / name, diq_dir / name)
    checksums_path = diq_dir / "DIQ_CHECKSUMS.json"
    monkeypatch.setattr(di, "_DIQ_DIR", diq_dir)
    monkeypatch.setattr(di, "_CHECKSUMS_FILE", checksums_path)
    return diq_dir


# ── compute_checksums / write_checksums ────────────────────────────────────

class TestComputeChecksums:
    def test_returns_all_frozen_files(self, scratch):
        checks = di.compute_checksums()
        assert set(checks.keys()) == set(di.FROZEN_FILES)

    def test_hashes_match_sha256(self, scratch):
        checks = di.compute_checksums()
        for name, digest in checks.items():
            expected = hashlib.sha256(
                (scratch / name).read_bytes()).hexdigest()
            assert digest == expected

    def test_write_then_read_roundtrip(self, scratch):
        di.write_checksums()
        data = json.loads((scratch / "DIQ_CHECKSUMS.json").read_text())
        assert set(data.keys()) == set(di.FROZEN_FILES)


# ── verify_diq_integrity ───────────────────────────────────────────────────

class TestVerifyDiqIntegrity:
    def test_missing_manifest_raises(self, scratch):
        # Missing manifest is indistinguishable from tampering — fail closed.
        with pytest.raises(RuntimeError, match="not found"):
            di.verify_diq_integrity()

    def test_sealed_files_verify_cleanly(self, scratch):
        di.write_checksums()
        di.verify_diq_integrity()  # no exception

    def test_missing_file_raises(self, scratch):
        di.write_checksums()
        (scratch / di.FROZEN_FILES[0]).unlink()
        with pytest.raises(RuntimeError, match="MISSING"):
            di.verify_diq_integrity()

    def test_tampered_file_raises(self, scratch):
        di.write_checksums()
        target = scratch / di.FROZEN_FILES[0]
        target.write_bytes(target.read_bytes() + b"\n# malicious tail\n")
        with pytest.raises(RuntimeError, match="TAMPERED"):
            di.verify_diq_integrity()

    def test_unsealed_new_file_raises(self, scratch):
        di.write_checksums()
        # Remove one file from the manifest but keep it on disk.
        manifest = json.loads(di._CHECKSUMS_FILE.read_text())
        removed = di.FROZEN_FILES[0]
        manifest.pop(removed)
        di._CHECKSUMS_FILE.write_text(json.dumps(manifest))
        with pytest.raises(RuntimeError, match="NOT IN CHECKSUMS"):
            di.verify_diq_integrity()
