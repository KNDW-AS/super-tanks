"""
Tests for core/security/audit_sanitizer.py.

Verifies each redaction pattern catches its intended secret class and
that nested dicts/lists are recursively sanitised. Clean text must
pass through unchanged.
"""

import pytest

from core.security.audit_sanitizer import sanitize, sanitize_dict


# ── sanitize() string-level patterns ───────────────────────────────────────

class TestSanitizeText:
    def test_clean_text_unchanged(self):
        assert sanitize("Hello, world.") == "Hello, world."

    def test_empty_passes_through(self):
        assert sanitize("") == ""
        assert sanitize(None) is None  # type: ignore[arg-type]

    @pytest.mark.parametrize("text", [
        "api_key=abcdef1234567890",
        "API-KEY: superSecretToken123",
        'password = "hunter2hunter2"',
        "token=ghp_abcdefghijklmnop1234",
        "secret=THIS_IS_SECRET",
    ])
    def test_credential_key_value_redacted(self, text):
        out = sanitize(text)
        assert "REDACTED" in out

    def test_bearer_token_redacted(self):
        out = sanitize("Authorization: Bearer eyJabc.eyJdef.signature99")
        assert "Bearer ***REDACTED***" in out

    def test_jwt_redacted(self):
        jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.SflKxw"
        out = sanitize(f"got token {jwt} here")
        assert "JWT_REDACTED" in out

    def test_norwegian_fnummer_redacted(self):
        out = sanitize("Fødselsnummer: 010199 12345")
        assert "FNUMMER_REDACTED" in out
        assert "010199" not in out

    def test_card_number_redacted(self):
        out = sanitize("VISA 4242 4242 4242 4242")
        assert "CARD_REDACTED" in out
        out2 = sanitize("Card: 4242-4242-4242-4242")
        assert "CARD_REDACTED" in out2

    def test_ssh_private_key_block_redacted(self):
        key_block = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEAxxxxxxxxxxxx\n"
            "-----END RSA PRIVATE KEY-----"
        )
        assert "SSH_KEY_REDACTED" in sanitize(key_block)

    def test_long_hex_redacted(self):
        # 40+ hex chars = likely a token/hash.
        out = sanitize("hash = " + "a" * 40)
        assert "HEX_REDACTED" in out

    @pytest.mark.parametrize("env_line", [
        "OPENAI_API_KEY=sk-abc123",
        "ANTHROPIC_API_KEY=sk-ant-...",
        "GEMINI_API_KEY=ABC",
        "TELEGRAM_BOT_TOKEN=12345:abcde",
        "HOMEASSISTANT_TOKEN=longtoken",
        "MOONSHOT_API_KEY=foo",
    ])
    def test_well_known_env_vars_redacted(self, env_line):
        out = sanitize(env_line)
        assert "REDACTED" in out


# ── sanitize_dict() recursion ──────────────────────────────────────────────

class TestSanitizeDict:
    def test_top_level_string(self):
        d = {"name": "william", "password": "password=hunter2hunter2hunter"}
        out = sanitize_dict(d)
        assert out["name"] == "william"
        assert "REDACTED" in out["password"]

    def test_nested_dict(self):
        d = {"outer": {"inner": {"api_key": "api_key=abcdefghij"}}}
        out = sanitize_dict(d)
        assert "REDACTED" in out["outer"]["inner"]["api_key"]

    def test_list_of_strings(self):
        d = {"keys": ["clean", "token=secret_abcdefgh"]}
        out = sanitize_dict(d)
        assert out["keys"][0] == "clean"
        assert "REDACTED" in out["keys"][1]

    def test_list_of_dicts(self):
        d = {"entries": [{"password": "password=longvalue99"}, {"plain": "ok"}]}
        out = sanitize_dict(d)
        assert "REDACTED" in out["entries"][0]["password"]
        assert out["entries"][1]["plain"] == "ok"

    def test_non_string_values_preserved(self):
        d = {"count": 42, "active": True, "tags": None}
        assert sanitize_dict(d) == d
