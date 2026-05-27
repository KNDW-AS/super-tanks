"""Google Gemini provider — free tier via AI Studio."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


def speak_gemini(prompt: str, system_prompt: str = "", *,
                 model: str = "gemini-2.5-pro",
                 api_key: str | None = None,
                 timeout_s: int = 90) -> str:
    """One-shot completion via Gemini's generateContent endpoint."""
    key = api_key or os.environ.get("GEMINI_API_KEY")
    if not key:
        raise RuntimeError("GEMINI_API_KEY not set")

    body: dict = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.7},
    }
    if system_prompt:
        body["systemInstruction"] = {"parts": [{"text": system_prompt}]}

    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model}:generateContent?key={key}"
    )
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        payload = json.loads(resp.read())
    candidates = payload.get("candidates") or []
    if not candidates:
        raise RuntimeError(f"no candidates: {payload}")
    parts = candidates[0].get("content", {}).get("parts") or []
    return "".join(p.get("text", "") for p in parts)
