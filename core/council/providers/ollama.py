"""Ollama provider — local open-weight models. No API key required."""

from __future__ import annotations

import json
import urllib.error
import urllib.request


def speak_ollama(prompt: str, system_prompt: str = "", *,
                 model: str = "llama3.2:3b",
                 host: str = "http://localhost:11434",
                 timeout_s: int = 60) -> str:
    """One-shot completion via Ollama's /api/chat endpoint."""
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})
    body = json.dumps({"model": model, "messages": messages, "stream": False}).encode()
    req = urllib.request.Request(
        f"{host.rstrip('/')}/api/chat",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        payload = json.loads(resp.read())
    return payload.get("message", {}).get("content", "")
