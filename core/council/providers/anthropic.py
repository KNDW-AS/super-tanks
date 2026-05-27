"""Anthropic Claude provider — frontier tier. Pay-tier; included for completeness.
The Council can run without it (using only Gemini + Ollama free tiers)."""

from __future__ import annotations

import json
import os
import urllib.request


def speak_claude(prompt: str, system_prompt: str = "", *,
                 model: str = "claude-opus-4-7",
                 api_key: str | None = None,
                 max_tokens: int = 2048,
                 timeout_s: int = 120) -> str:
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY not set")
    body: dict = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system_prompt:
        body["system"] = system_prompt
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        payload = json.loads(resp.read())
    parts = payload.get("content") or []
    return "".join(p.get("text", "") for p in parts if p.get("type") == "text")
