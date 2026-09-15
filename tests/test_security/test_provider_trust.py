"""
Tests for core/security/provider_trust.py (Layer 11 — Provider Trust Tier).

Covers tier mapping (fail-closed for unknown providers), config overrides,
strip rules per tier, configured PII terms, and that the shipped module carries
no deployer-specific personal data.
"""

import textwrap

import pytest

from core.security import provider_trust as pt


@pytest.fixture(autouse=True)
def _reset_defaults():
    pt.load_provider_config("/nonexistent/providers.yaml")
    yield
    pt.load_provider_config()


# ── tier mapping ────────────────────────────────────────────────────────────

def test_default_tiers():
    assert pt.get_tier("ollama") == pt.TIER_1_LOCAL
    assert pt.get_tier("anthropic") == pt.TIER_2_TRUSTED
    assert pt.get_tier("google") == pt.TIER_3_MIXED
    assert pt.get_tier("groq") == pt.TIER_3_MIXED
    assert pt.get_tier("openrouter") == pt.TIER_4_OPEN
    assert pt.get_tier("deepseek") == pt.TIER_4_OPEN


def test_unknown_provider_fails_closed():
    assert pt.get_tier("brand-new-vendor") == pt.TIER_4_OPEN
    assert pt.get_tier("") == pt.TIER_4_OPEN


def test_lookup_is_case_insensitive():
    assert pt.get_tier("Anthropic") == pt.TIER_2_TRUSTED


def test_tier_and_strip_names():
    assert pt.get_tier_name(pt.TIER_1_LOCAL) == "LOCAL"
    assert pt.get_tier_name(99) == "UNKNOWN(99)"
    assert pt.get_strip_level(pt.TIER_3_MIXED) == "secrets+pii"
    assert pt.get_strip_level(99) == "full"


# ── config ──────────────────────────────────────────────────────────────────

def test_config_overrides_tiers_and_adds_pii_terms(tmp_path):
    cfg = tmp_path / "providers.yaml"
    cfg.write_text(textwrap.dedent("""
        provider_tiers:
          google: 2
          my-endpoint: 1
          bad: 9
          worse: notanumber
        pii_terms:
          - "Jane Doe"
          - ""
    """), encoding="utf-8")
    pt.load_provider_config(str(cfg))
    assert pt.get_tier("google") == pt.TIER_2_TRUSTED
    assert pt.get_tier("my-endpoint") == pt.TIER_1_LOCAL
    assert pt.get_tier("bad") == pt.TIER_4_OPEN        # out of range ignored → unknown
    assert pt.get_tier("worse") == pt.TIER_4_OPEN
    assert "Jane Doe" not in pt.strip_context_for_tier("Hei Jane Doe", pt.TIER_3_MIXED)
    assert "Jane Doe" in pt.strip_context_for_tier("Hei Jane Doe", pt.TIER_2_TRUSTED)


def test_malformed_config_falls_back_to_defaults(tmp_path):
    cfg = tmp_path / "providers.yaml"
    cfg.write_text("provider_tiers: [not, a, mapping", encoding="utf-8")
    pt.load_provider_config(str(cfg))
    assert pt.get_tier("anthropic") == pt.TIER_2_TRUSTED


def test_shipped_module_has_no_deployer_pii():
    import inspect
    src = inspect.getsource(pt)
    for forbidden in ("Park", "Røyksund", "Varanesvegen", "5546"):
        assert forbidden not in src
    assert pt._extra_pii == []


# ── strip rules ─────────────────────────────────────────────────────────────

SAMPLE = ("api_key=sk-abcdefghijklmnopqrstuvwxyz1234 mail jane@example.com "
          "ip 10.0.0.12 path /home/deployer/x device light.livingroom")


def test_tier1_strips_nothing():
    assert pt.strip_context_for_tier(SAMPLE, pt.TIER_1_LOCAL) == SAMPLE


def test_tier2_strips_secrets_only():
    out = pt.strip_context_for_tier(SAMPLE, pt.TIER_2_TRUSTED)
    assert "sk-abcdefghijklmnopqrstuvwxyz1234" not in out
    assert "jane@example.com" in out
    assert "/home/deployer/x" in out


def test_tier3_strips_pii():
    out = pt.strip_context_for_tier(SAMPLE, pt.TIER_3_MIXED)
    assert "jane@example.com" not in out
    assert "10.0.0.12" not in out
    assert "/home/deployer/x" in out          # paths first at tier 4


def test_tier4_strips_paths_and_entities():
    out = pt.strip_context_for_tier(SAMPLE, pt.TIER_4_OPEN)
    assert "/home/deployer" not in out
    assert "light.livingroom" not in out


def test_jwt_and_google_keys_stripped_at_tier2():
    text = "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0 and AIzaSyA-1234567890abcdefghijklmnopqrstuvw"
    out = pt.strip_context_for_tier(text, pt.TIER_2_TRUSTED)
    assert "[JWT]" in out and "[GOOGLE_KEY]" in out


def test_none_passthrough():
    assert pt.strip_context_for_tier(None, pt.TIER_4_OPEN) is None


# ── config loading without PyYAML (CI installs no yaml package) ─────────────

def test_builtin_parser_matches_pyyaml_on_shipped_config():
    yaml = pytest.importorskip("yaml")
    import pathlib
    text = pathlib.Path(pt._default_config_path()).read_text(encoding="utf-8")
    assert pt._load_yaml_subset(text) == yaml.safe_load(text)


def test_config_loads_without_pyyaml(tmp_path, monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "yaml", None)   # makes `import yaml` raise ImportError
    cfg = tmp_path / "providers.yaml"
    cfg.write_text(textwrap.dedent("""
        # comment line
        provider_tiers:
          google: 2        # trailing comment
          my-endpoint: 1
        pii_terms:
          - "Jane Doe"
          - Example Street 1
        fallback_chains:
          default: ["anthropic", "google", "ollama"]
        downgrade_approval_timeout_s: 7
    """), encoding="utf-8")
    pt.load_provider_config(str(cfg))
    assert pt.get_tier("google") == pt.TIER_2_TRUSTED
    assert pt.get_tier("my-endpoint") == pt.TIER_1_LOCAL
    assert pt._extra_pii == ["Jane Doe", "Example Street 1"]
    parsed = pt._load_yaml_subset(cfg.read_text(encoding="utf-8"))
    assert parsed["fallback_chains"]["default"] == ["anthropic", "google", "ollama"]
    assert parsed["downgrade_approval_timeout_s"] == 7


def test_builtin_parser_rejects_unsupported_yaml():
    with pytest.raises(ValueError):
        pt._load_yaml_subset("just a line without a colon")
    with pytest.raises(ValueError):
        pt._load_yaml_subset("a: 1\n- orphan item")
