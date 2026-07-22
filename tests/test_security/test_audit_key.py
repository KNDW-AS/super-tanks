"""
Tests for core/security/audit_key.py — the dedicated audit-chain key.

The point of the module is key SEPARATION (STA-01 Threat 06): the
audit-chain key must be independent material from the identity key, so
stealing one does not compromise both authentication and evidence
integrity.
"""

import pytest


@pytest.fixture
def fresh_audit_key(tmp_path, monkeypatch):
    """audit_key with no cached key and a tmp key file path."""
    from core.security import audit_key
    monkeypatch.setattr(audit_key, "_KEY", None)
    monkeypatch.setattr(audit_key, "_KEY_FILE_PATH", tmp_path / ".audit_chain_key")
    monkeypatch.delenv("SUPER_TANKS_AUDIT_KEY", raising=False)
    return audit_key


class TestKeyAcquisition:
    def test_env_var_wins(self, fresh_audit_key, monkeypatch):
        monkeypatch.setenv("SUPER_TANKS_AUDIT_KEY", "env-secret")
        assert fresh_audit_key._load_key() == b"env-secret"
        # Env-sourced key never touches the filesystem.
        assert not fresh_audit_key._KEY_FILE_PATH.exists()

    def test_generates_and_persists_key_file(self, fresh_audit_key):
        key = fresh_audit_key._load_key()
        assert len(key) == 32
        assert fresh_audit_key._KEY_FILE_PATH.read_bytes() == key
        mode = fresh_audit_key._KEY_FILE_PATH.stat().st_mode & 0o777
        assert mode == 0o600

    def test_reloads_existing_key_file(self, fresh_audit_key, monkeypatch):
        fresh_audit_key._KEY_FILE_PATH.write_bytes(b"persisted-key-32-bytes-material!")
        assert fresh_audit_key._load_key() == b"persisted-key-32-bytes-material!"

    def test_idempotent_within_process(self, fresh_audit_key):
        assert fresh_audit_key._load_key() is fresh_audit_key._load_key()


class TestKeySeparation:
    def test_audit_key_differs_from_identity_key(self, fresh_audit_key,
                                                 tmp_path, monkeypatch):
        from core.security import agent_identity
        monkeypatch.setattr(agent_identity, "_KEY", None)
        monkeypatch.setattr(agent_identity, "_KEY_FILE_PATH",
                            tmp_path / ".identity_key")
        monkeypatch.delenv("SUPER_TANKS_IDENTITY_KEY", raising=False)

        audit = fresh_audit_key._load_key()
        identity = agent_identity._load_key()
        assert audit != identity

    def test_chain_uses_audit_key_not_identity_key(self, fresh_audit_key,
                                                   monkeypatch):
        """Forging a chain row must require the audit key specifically."""
        import hashlib
        import hmac as hmac_mod
        from core.security import agent_identity, audit_chain

        monkeypatch.setattr(agent_identity, "_KEY", b"identity-key")
        monkeypatch.setattr(fresh_audit_key, "_KEY", b"audit-key")

        row = {"ts": "t0", "agent": "aeris"}
        h = audit_chain.compute_hmac(None, row)
        with_audit = hmac_mod.new(b"audit-key",
                                  audit_chain.canonical_bytes(row),
                                  hashlib.sha256).hexdigest()
        with_identity = hmac_mod.new(b"identity-key",
                                     audit_chain.canonical_bytes(row),
                                     hashlib.sha256).hexdigest()
        assert h == with_audit
        assert h != with_identity


class TestConfigureHooks:
    def test_configure_key(self, fresh_audit_key):
        fresh_audit_key.configure_key(b"explicit")
        assert fresh_audit_key._load_key() == b"explicit"

    def test_configure_key_file_resets_cache(self, fresh_audit_key, tmp_path):
        fresh_audit_key.configure_key(b"old")
        newfile = tmp_path / "other_key"
        newfile.write_bytes(b"from-file")
        fresh_audit_key.configure_key_file(newfile)
        assert fresh_audit_key._load_key() == b"from-file"
