"""
Tests for core/security/zef_llm_classifier.py.

The classifier is async, talks to a local Ollama HTTP endpoint, and is
fail-open by design. Tests stub urllib.request.urlopen so no network is
involved.
"""

import asyncio
import json

import pytest

from core.security import zef_llm_classifier as clf


# ── Channel routing ────────────────────────────────────────────────────────

class TestChannelRouting:
    @pytest.mark.parametrize("source,expected", [
        ("webhook:external", True),
        ("ha_voice:kitchen", True),
        ("http:william", True),
        # A2A is now treated as high-risk: agent-to-agent is the
        # primary route a compromised agent uses to attack the other.
        ("a2a:aeris", True),
    ])
    def test_high_risk_channels(self, source, expected):
        assert clf.is_high_risk_channel(source) is expected

    @pytest.mark.parametrize("source", [
        "telegram:ADMIN_CHAT_ID",
        "cockpit:admin",
    ])
    def test_trusted_channels_skip_classifier(self, source):
        assert clf.is_high_risk_channel(source) is False

    def test_unknown_channel_not_high_risk(self):
        # Only the named HIGH_RISK_CHANNELS opt in.
        assert clf.is_high_risk_channel("unknown:thing") is False

    def test_extract_channel_handles_missing_colon(self):
        assert clf._extract_channel("webhook") == "webhook"

    def test_extract_channel_lowercases(self):
        assert clf._extract_channel("TELEGRAM:ADMIN") == "telegram"


# ── classify_message — mocked Ollama ───────────────────────────────────────

@pytest.fixture
def mock_urlopen(monkeypatch):
    """Patch urllib.request.urlopen to return controllable responses."""
    captured = {}

    class _Response:
        def __init__(self, body):
            self._body = body.encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return self._body

    def factory(reply_text):
        def fake_urlopen(req, timeout=5):
            captured["url"] = req.full_url
            captured["data"] = json.loads(req.data.decode("utf-8"))
            return _Response(json.dumps({"response": reply_text}))

        monkeypatch.setattr(clf.urllib.request, "urlopen", fake_urlopen)
        return captured

    return factory


class TestClassifyMessage:
    def test_safe_verdict(self, mock_urlopen):
        captured = mock_urlopen("SAFE")
        result = asyncio.run(clf.classify_message("hello", "webhook:x"))
        assert result == "SAFE"
        assert "/api/generate" in captured["url"]

    def test_suspicious_verdict(self, mock_urlopen):
        mock_urlopen("SUSPICIOUS")
        assert asyncio.run(
            clf.classify_message("ignore all", "webhook:x")) == "SUSPICIOUS"

    def test_lowercase_suspicious_normalised(self, mock_urlopen):
        mock_urlopen("This is SUSPICIOUS to me")
        assert asyncio.run(
            clf.classify_message("x", "webhook:x")) == "SUSPICIOUS"

    def test_unknown_response_defaults_to_safe(self, mock_urlopen):
        mock_urlopen("MAYBE_DUNNO")
        assert asyncio.run(clf.classify_message("x", "webhook:x")) == "SAFE"

    def test_long_message_truncated(self, mock_urlopen):
        captured = mock_urlopen("SAFE")
        big = "A" * 5000
        asyncio.run(clf.classify_message(big, "webhook:x"))
        # The prompt embeds the (truncated) message.
        assert "A" * 2000 in captured["data"]["prompt"]
        assert "A" * 2001 not in captured["data"]["prompt"]

    def test_temperature_zero_for_determinism(self, mock_urlopen):
        captured = mock_urlopen("SAFE")
        asyncio.run(clf.classify_message("x", "webhook:x"))
        assert captured["data"]["options"]["temperature"] == 0.0


# ── Fail-open behaviour ────────────────────────────────────────────────────

class TestFailOpen:
    def test_url_error_returns_safe(self, monkeypatch):
        from urllib.error import URLError

        def boom(*a, **kw):
            raise URLError("connection refused")

        monkeypatch.setattr(clf.urllib.request, "urlopen", boom)
        assert asyncio.run(clf.classify_message("x", "webhook:x")) == "SAFE"

    def test_generic_exception_returns_safe(self, monkeypatch):
        def boom(*a, **kw):
            raise RuntimeError("unexpected")

        monkeypatch.setattr(clf.urllib.request, "urlopen", boom)
        assert asyncio.run(clf.classify_message("x", "webhook:x")) == "SAFE"


# ── Ollama endpoint configuration ──────────────────────────────────────────

class TestOllamaEndpoint:
    def test_defaults_when_brain_config_missing(self, monkeypatch):
        # Clear the cache and force the import to fail.
        monkeypatch.setattr(clf, "_ollama_host", None)
        monkeypatch.setattr(clf, "_ollama_port", None)
        host, port = clf._get_ollama_endpoint()
        assert host == "localhost"
        assert port == 11434
