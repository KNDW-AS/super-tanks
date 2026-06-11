"""OpenRouter provider — unified API for Qwen, Mistral, DeepSeek, Llama, etc.
Several free-tier models available. Stub until OPENROUTER_API_KEY is
provisioned."""

from __future__ import annotations

import json
import os
import urllib.request


def speak_openrouter(prompt: str, system_prompt: str = "", *,
                     model: str = "qwen/qwen-2.5-72b-instruct:free",
                     api_key: str | None = None,
                     timeout_s: int = 90) -> str:
    key = api_key or os.environ.get("OPENROUTER_API_KEY")
    if not key:
        raise RuntimeError("OPENROUTER_API_KEY not set")
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})
    body = json.dumps({"model": model, "messages": messages}).encode()
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
            "HTTP-Referer": "https://github.com/kndw-as/super-tanks",
            "X-Title": "Super Tanks Council",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        payload = json.loads(resp.read())
    return payload["choices"][0]["message"]["content"]
