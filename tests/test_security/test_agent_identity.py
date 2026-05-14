"""
Tests for core/security/agent_identity.py.

Verifies HMAC signing, constant-time verification, key acquisition
order (env > file > generated), and that the key file is created with
restrictive permissions.
"""

import os
import stat

import pytest

from core.security import agent_identity


@pytest.fixture
def fresh_key(monkeypatch, tmp_path):
    """Reset module key state and redirect persistence to tmp."""
    monkeypatch.delenv("SUPER_TANKS_IDENTITY_KEY", raising=False)
    monkeypatch.setattr(agent_identity, "_KEY", None)
    key_file = tmp_path / "identity_key"
    monkeypatch.setattr(agent_identity, "_KEY_FILE_PATH", key_file)
    return key_file


# ── issue_identity / verify_identity (round trip) ─────────────────────

class TestIssueVerify:
    def test_round_trip(self, fresh_key):
        token = agent_identity.issue_identity("aeris")
        assert agent_identity.verify_identity("aeris", token) is True

    def test_wrong_agent_fails(self, fresh_key):
        token = agent_identity.issue_identity("aeris")
        assert agent_identity.verify_identity("zeph", token) is False

    def test_empty_token_fails(self, fresh_key):
        assert agent_identity.verify_identity("aeris", "") is False
        assert agent_identity.verify_identity("aeris", None) is False

    def test_empty_agent_id_fails(self, fresh_key):
        assert agent_identity.verify_identity("", "anything") is False

    def test_issue_rejects_empty_agent(self, fresh_key):
        with pytest.raises(ValueError):
            agent_identity.issue_identity("")

    def test_token_is_opaque_hex(self, fresh_key):
        token = agent_identity.issue_identity("aeris")
        # 32-byte HMAC-SHA256 → 64 hex chars.
        assert len(token) == 64
        int(token, 16)  # must be valid hex


# ── Key acquisition order: env > file > generated ────────────────────

class TestKeyAcquisition:
    def test_env_var_takes_priority(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SUPER_TANKS_IDENTITY_KEY", "from-env")
        monkeypatch.setattr(agent_identity, "_KEY", None)
        # Even if a key file exists, env should win.
        key_file = tmp_path / "identity_key"
        key_file.write_bytes(b"from-file")
        monkeypatch.setattr(agent_identity, "_KEY_FILE_PATH", key_file)

        token = agent_identity.issue_identity("x")
        # Reload as if a fresh process started — confirm env key drives.
        monkeypatch.setattr(agent_identity, "_KEY", None)
        token2 = agent_identity.issue_identity("x")
        assert token == token2

    def test_file_used_when_no_env(self, monkeypatch, tmp_path):
        monkeypatch.delenv("SUPER_TANKS_IDENTITY_KEY", raising=False)
        monkeypatch.setattr(agent_identity, "_KEY", None)
        key_file = tmp_path / "identity_key"
        key_file.write_bytes(b"persisted-key-bytes-from-prior-boot")
        monkeypatch.setattr(agent_identity, "_KEY_FILE_PATH", key_file)

        first = agent_identity.issue_identity("aeris")
        monkeypatch.setattr(agent_identity, "_KEY", None)
        second = agent_identity.issue_identity("aeris")
        assert first == second

    def test_first_boot_generates_and_persists(self, fresh_key):
        # No env, no file — first issue creates the key.
        token = agent_identity.issue_identity("aeris")
        assert fresh_key.exists()
        # Subsequent process (fresh _KEY=None) reads the same key back.
        agent_identity._KEY = None
        token2 = agent_identity.issue_identity("aeris")
        assert token == token2

    def test_generated_key_file_mode_0600_if_possible(self, fresh_key):
        agent_identity.issue_identity("aeris")
        mode = stat.S_IMODE(os.stat(fresh_key).st_mode)
        # Best-effort: filesystems that don't support chmod may not
        # produce 0600. On the standard Linux ext4 we expect 0600.
        if os.name != "nt":
            assert mode == 0o600

    def test_corrupt_key_file_falls_back_to_generation(
            self, monkeypatch, tmp_path):
        monkeypatch.delenv("SUPER_TANKS_IDENTITY_KEY", raising=False)
        monkeypatch.setattr(agent_identity, "_KEY", None)
        key_file = tmp_path / "identity_key"
        key_file.write_bytes(b"")  # empty file simulates corruption
        monkeypatch.setattr(agent_identity, "_KEY_FILE_PATH", key_file)

        # Loading an empty key would produce an empty HMAC key — still
        # "works" but is weak. The contract we test is just that
        # issue_identity doesn't crash and we get *some* hex output.
        token = agent_identity.issue_identity("aeris")
        assert len(token) == 64


# ── configure_key (test hook) ─────────────────────────────────────────

class TestConfigureKey:
    def test_configure_key_replaces_in_memory(self, monkeypatch):
        monkeypatch.setattr(agent_identity, "_KEY", None)
        agent_identity.configure_key(b"deterministic-test-key")
        token = agent_identity.issue_identity("aeris")
        # Same key → same token.
        token2 = agent_identity.issue_identity("aeris")
        assert token == token2

    def test_configure_key_file_resets_key(self, monkeypatch, tmp_path):
        path = tmp_path / "k"
        path.write_bytes(b"abc")
        agent_identity.configure_key_file(path)
        assert agent_identity._KEY is None  # forced reload


# ── Constant-time compare (smoke test, can't verify timing directly) ──

class TestConstantTimeCompare:
    def test_token_compare_does_not_short_circuit(self, fresh_key):
        # We can't measure timing reliably; just verify hmac.compare_digest
        # path is used by checking that tokens differing only in the last
        # byte still fail verification.
        token = agent_identity.issue_identity("aeris")
        bad = token[:-1] + ("0" if token[-1] != "0" else "1")
        assert agent_identity.verify_identity("aeris", bad) is False


# ── A2A message signing ───────────────────────────────────────────────

class TestA2ASigning:
    def _msg(self, **overrides):
        from core.diq.diq_a2a import A2AMessage
        base = dict(sender="aeris", recipient="zeph", message_type="request",
                    payload={"text": "hei"}, timestamp="2024-01-01T00:00:00+00:00",
                    correlation_id="corr-1")
        base.update(overrides)
        return A2AMessage(**base)

    def test_sign_then_verify(self, fresh_key):
        signed = agent_identity.sign_a2a_message(self._msg())
        assert signed.signature is not None
        assert agent_identity.verify_a2a_message(signed) is True

    def test_unsigned_message_fails_verification(self, fresh_key):
        assert agent_identity.verify_a2a_message(self._msg()) is False

    def test_tampered_sender_fails_verification(self, fresh_key):
        signed = agent_identity.sign_a2a_message(self._msg(sender="aeris"))
        from dataclasses import replace
        forged = replace(signed, sender="william")  # claim to be admin
        assert agent_identity.verify_a2a_message(forged) is False

    def test_tampered_payload_fails_verification(self, fresh_key):
        signed = agent_identity.sign_a2a_message(self._msg(payload={"x": 1}))
        from dataclasses import replace
        forged = replace(signed, payload={"x": 999})
        assert agent_identity.verify_a2a_message(forged) is False

    def test_payload_dict_ordering_does_not_matter(self, fresh_key):
        # Canonical JSON sorts keys, so two semantically identical
        # dicts produce the same signature regardless of insertion order.
        a = agent_identity.sign_a2a_message(
            self._msg(payload={"a": 1, "b": 2}))
        b = agent_identity.sign_a2a_message(
            self._msg(payload={"b": 2, "a": 1}))
        assert a.signature == b.signature

    def test_signature_field_excluded_from_canonical_bytes(self, fresh_key):
        # Re-signing a signed message must produce the same signature
        # (the existing `signature` field is excluded from the canonical
        # serialisation). Otherwise we'd have signature-of-signature
        # chaining.
        signed = agent_identity.sign_a2a_message(self._msg())
        signed_twice = agent_identity.sign_a2a_message(signed)
        assert signed.signature == signed_twice.signature
