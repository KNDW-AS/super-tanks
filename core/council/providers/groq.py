"""Groq provider — free tier with Llama 3.3 70B at very high throughput. Stub
until GROQ_API_KEY is provisioned."""

from __future__ import annotations

import json
import os
import urllib.request


def speak_groq(prompt: str, system_prompt: str = "", *,
               model: str = "llama-3.3-70b-versatile",
               api_key: str | None = None,
               timeout_s: int = 60) -> str:
    key = api_key or os.environ.get("GROQ_API_KEY")
    if not key:
        raise RuntimeError("GROQ_API_KEY not set")
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})
    body = json.dumps({"model": model, "messages": messages}).encode()
    req = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        payload = json.loads(resp.read())
    return payload["choices"][0]["message"]["content"]
