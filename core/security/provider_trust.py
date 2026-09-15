"""
core/security/provider_trust.py
================================
Layer 11 — Provider Trust Tier.

Classifies every LLM provider by how much you trust it with your data, and
strips content accordingly *before* a prompt leaves the process. An agent
that runs on a local model can see everything; the same agent talking to a
free-tier cloud API must not leak secrets, personal data or internal
identifiers.

Tiers (lower number = more trusted):

    TIER_1_LOCAL    local inference (Ollama, llama.cpp) — nothing stripped
    TIER_2_TRUSTED  paid cloud under a data-processing agreement — secrets stripped
    TIER_3_MIXED    free tiers / data may be used for training — + PII stripped
    TIER_4_OPEN     unknown routing or jurisdiction — + paths, device ids

Unknown providers are TIER_4_OPEN (fail-closed). Override the mapping and add
your own PII terms in ``config/providers.yaml``:

    provider_tiers:
      my-private-endpoint: 2
    pii_terms:
      - "Jane Doe"
      - "Example Street 1"

Integration points:
    - ``core/council/council.py``: every voice's prompt and system prompt are
      passed through :func:`strip_context_for_tier` for the voice's tier, and
      the tier is audited per call.
    - ``core/security/provider_failover.py`` (Layer 12): moving to a lower tier
      requires a GO-Gate approval.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Dict, List, Optional

logger = logging.getLogger("supertanks.provider_trust")

# ── Trust tiers ──────────────────────────────────────────────────────────────

TIER_1_LOCAL = 1
TIER_2_TRUSTED = 2
TIER_3_MIXED = 3
TIER_4_OPEN = 4

TIER_NAMES = {
    TIER_1_LOCAL: "LOCAL",
    TIER_2_TRUSTED: "TRUSTED",
    TIER_3_MIXED: "MIXED",
    TIER_4_OPEN: "OPEN",
}

STRIP_LEVELS = {
    TIER_1_LOCAL: "none",
    TIER_2_TRUSTED: "secrets",
    TIER_3_MIXED: "secrets+pii",
    TIER_4_OPEN: "full",
}

# ── Provider → tier mapping (defaults; override in config/providers.yaml) ────
# Keys are the vendor tags used by council Voices and the provider adapters.
# Free tiers default to MIXED because their terms typically allow training on
# submitted data. If you pay for a plan with a data-processing agreement, move
# the vendor to tier 2 in your config.

DEFAULT_PROVIDER_MAP: Dict[str, int] = {
    # TIER 1 — local, full trust
    "ollama": TIER_1_LOCAL,
    "llama.cpp": TIER_1_LOCAL,
    "koboldcpp": TIER_1_LOCAL,
    "lm_studio": TIER_1_LOCAL,
    "local": TIER_1_LOCAL,

    # TIER 2 — paid cloud, DPA / no-training terms
    "anthropic": TIER_2_TRUSTED,
    "openai": TIER_2_TRUSTED,
    "gemini-paid": TIER_2_TRUSTED,
    "kimi": TIER_2_TRUSTED,
    "moonshot": TIER_2_TRUSTED,

    # TIER 3 — free tiers, data may be used for training
    "google": TIER_3_MIXED,
    "gemini": TIER_3_MIXED,
    "gemini-free": TIER_3_MIXED,
    "groq": TIER_3_MIXED,

    # TIER 4 — open / unknown routing or jurisdiction
    "openrouter": TIER_4_OPEN,
    "openrouter-free": TIER_4_OPEN,
    "deepseek": TIER_4_OPEN,
}

_provider_map: Dict[str, int] = dict(DEFAULT_PROVIDER_MAP)
_extra_pii: List[str] = []
_config_path_loaded: Optional[str] = None


def _default_config_path() -> str:
    return os.path.join(os.path.dirname(__file__), "..", "..", "config", "providers.yaml")


def _parse_scalar(raw: str):
    raw = raw.strip()
    if raw == "" or raw in ("null", "~"):
        return None
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1].strip()
        return [_parse_scalar(x) for x in inner.split(",")] if inner else []
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
        return raw[1:-1]
    low = raw.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        return raw


def _load_yaml_subset(text: str) -> dict:
    """Minimal YAML reader for ``providers.yaml``-style files: nested ``key: value``
    mappings, ``- item`` block lists, inline ``[a, b]`` lists, ``#`` comments. Used
    when PyYAML is not installed, so the two trust layers never depend on an
    optional package. Raises ``ValueError`` on anything outside that subset."""
    root: dict = {}
    # stack entries: (indent, container, (parent_dict, key) that owns the container)
    stack: list = [(-1, root, None)]
    for raw_line in text.splitlines():
        stripped = raw_line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        line = raw_line.split(" #", 1)[0].rstrip() if " #" in raw_line else raw_line.rstrip()
        indent = len(line) - len(line.lstrip(" "))
        content = line.strip()
        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()
        _, container, owner = stack[-1]
        if content.startswith("- ") or content == "-":
            if isinstance(container, dict):
                if container or owner is None:
                    raise ValueError(f"list item inside a mapping: {raw_line!r}")
                container = []
                owner[0][owner[1]] = container          # empty placeholder becomes a list
                stack[-1] = (stack[-1][0], container, owner)
            container.append(_parse_scalar(content[1:].strip()))
            continue
        if not isinstance(container, dict):
            raise ValueError(f"mapping key inside a list: {raw_line!r}")
        if ":" not in content:
            raise ValueError(f"cannot parse line: {raw_line!r}")
        key, _, value = content.partition(":")
        key = key.strip().strip("\"'")
        value = value.strip()
        if value == "":
            child: dict = {}
            container[key] = child
            stack.append((indent, child, (container, key)))
            continue
        container[key] = _parse_scalar(value)
    return root


def load_config_file(path: str) -> dict:
    """Read a small YAML config; PyYAML when available, built-in subset parser otherwise."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    try:
        import yaml  # type: ignore
    except Exception:
        yaml = None
    if yaml is not None:
        return yaml.safe_load(text) or {}
    return _load_yaml_subset(text)


def load_provider_config(config_path: Optional[str] = None) -> None:
    """Load ``provider_tiers`` and ``pii_terms`` from YAML. Missing file = defaults."""
    global _provider_map, _extra_pii, _config_path_loaded
    path = config_path or _default_config_path()
    _provider_map = dict(DEFAULT_PROVIDER_MAP)
    _extra_pii = []
    try:
        cfg = load_config_file(path)
        if not isinstance(cfg, dict):
            raise ValueError("top level is not a mapping")
    except FileNotFoundError:
        _config_path_loaded = None
        return
    except Exception as exc:  # malformed config must not take the gateway down
        logger.warning("[PROVIDER_TRUST] could not load %s: %s — using defaults", path, exc)
        _config_path_loaded = None
        return

    custom = cfg.get("provider_tiers") or {}
    for name, tier in custom.items():
        try:
            tier_int = int(tier)
        except (TypeError, ValueError):
            logger.warning("[PROVIDER_TRUST] ignoring non-integer tier for %r", name)
            continue
        if tier_int not in TIER_NAMES:
            logger.warning("[PROVIDER_TRUST] ignoring out-of-range tier %r for %r", tier, name)
            continue
        _provider_map[str(name).lower()] = tier_int

    terms = cfg.get("pii_terms") or []
    _extra_pii = [str(t) for t in terms if str(t).strip()]
    _config_path_loaded = path
    logger.info(
        "[PROVIDER_TRUST] loaded %d provider tier overrides and %d PII terms from %s",
        len(custom), len(_extra_pii), path,
    )


def get_tier(provider: str) -> int:
    """Trust tier for a provider. Unknown providers → TIER_4_OPEN (fail-closed)."""
    key = (provider or "").lower()
    if key not in _provider_map:
        logger.warning("[PROVIDER_TRUST] unknown provider %r — defaulting to TIER_4_OPEN", provider)
        return TIER_4_OPEN
    return _provider_map[key]


def get_tier_name(tier: int) -> str:
    return TIER_NAMES.get(tier, f"UNKNOWN({tier})")


def get_strip_level(tier: int) -> str:
    return STRIP_LEVELS.get(tier, "full")


def get_provider_map() -> Dict[str, int]:
    """Copy of the effective provider → tier mapping."""
    return dict(_provider_map)


# ── Context stripping ────────────────────────────────────────────────────────

_PII_PATTERNS = [
    (r"\b\d{11}\b", "[NATIONAL_ID]"),                                    # 11-digit national id numbers
    (r"\b\d{4}\s?\d{4}\s?\d{3}\b", "[ACCOUNT_NO]"),                       # 11-digit bank account numbers
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[EMAIL]"),
    (r"\b(?:\+\d{1,3}|00\d{1,3})?\s?\d{3}\s?\d{2}\s?\d{3}\b", "[PHONE]"),  # 8-digit phone numbers
    (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[IP]"),
]

_SECRET_PATTERNS = [
    (r"(?:api[_-]?key|token|secret|password|bearer)\s*[:=]\s*\S+", "[REDACTED_SECRET]"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "[JWT]"),
    (r"sk-[a-zA-Z0-9]{20,}", "[API_KEY]"),
    (r"AIza[A-Za-z0-9_-]{35}", "[GOOGLE_KEY]"),
]


def strip_context_for_tier(text: str, tier: int) -> str:
    """
    Strip sensitive content from text before it goes to a provider of ``tier``.

    TIER_1: nothing
    TIER_2: API keys, tokens, passwords, JWTs
    TIER_3: + PII patterns and configured ``pii_terms``
    TIER_4: + smart-home entity ids and filesystem paths
    """
    if text is None:
        return text
    if tier <= TIER_1_LOCAL:
        return text

    result = text
    if tier >= TIER_2_TRUSTED:
        for pattern, replacement in _SECRET_PATTERNS:
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)

    if tier >= TIER_3_MIXED:
        for pattern, replacement in _PII_PATTERNS:
            result = re.sub(pattern, replacement, result)
        for term in _extra_pii:
            result = result.replace(term, "[PERSON]")
            result = result.replace(term.lower(), "[person]")

    if tier >= TIER_4_OPEN:
        result = re.sub(r"\b(light|switch|sensor|binary_sensor|media_player|climate|cover|lock)\.\w+", "[ENTITY]", result)
        result = re.sub(r"/home/\S+", "[PATH]", result)
        result = re.sub(r"/etc/\S+", "[PATH]", result)

    return result


# Load config on import
load_provider_config()
