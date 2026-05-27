"""Town Council CLI.

Usage:
    python -m core.council.cli "Question to ask the council"
    python -m core.council.cli --file question.md
    python -m core.council.cli --no-synth "Quick question, raw votes only"

Voices that need API keys are skipped automatically if the key is missing.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from .council import Council, Voice
from .providers.anthropic import speak_claude
from .providers.deepseek import speak_deepseek
from .providers.gemini import speak_gemini
from .providers.groq import speak_groq
from .providers.ollama import speak_ollama
from .providers.openrouter import speak_openrouter
from .synthesizer import fallback_synthesize, synthesize


def _build_voices() -> list[Voice]:
    voices: list[Voice] = []

    # Always-on local voice
    voices.append(
        Voice(
            name="Llama-Local",
            vendor="ollama",
            role="open-weight",
            speak=lambda p, s: speak_ollama(p, s, model="llama3.2:3b"),
            timeout_s=90,
        )
    )

    if os.environ.get("GEMINI_API_KEY"):
        # Two Gemini voices: a fast generalist and a slower deeper-thinker.
        voices.append(
            Voice(
                name="Gemini-2.5-Flash",
                vendor="google",
                role="fast-generalist",
                speak=lambda p, s: speak_gemini(p, s, model="gemini-2.5-flash"),
                timeout_s=60,
            )
        )
        voices.append(
            Voice(
                name="Gemini-2.5-Pro",
                vendor="google",
                role="deep-thinker",
                speak=lambda p, s: speak_gemini(p, s, model="gemini-2.5-pro"),
                timeout_s=120,
            )
        )
    if os.environ.get("DEEPSEEK_API_KEY"):
        voices.append(
            Voice(
                name="DeepSeek-R1",
                vendor="deepseek",
                role="reasoner",
                speak=lambda p, s: speak_deepseek(p, s),
                timeout_s=120,
            )
        )
    if os.environ.get("GROQ_API_KEY"):
        voices.append(
            Voice(
                name="Llama-3.3-70B",
                vendor="groq",
                role="open-weight-fast",
                speak=lambda p, s: speak_groq(p, s),
                timeout_s=45,
            )
        )
    if os.environ.get("OPENROUTER_API_KEY"):
        voices.append(
            Voice(
                name="Qwen-2.5-72B",
                vendor="openrouter",
                role="cross-cultural-critic",
                speak=lambda p, s: speak_openrouter(p, s),
                timeout_s=90,
            )
        )
    if os.environ.get("ANTHROPIC_API_KEY"):
        voices.append(
            Voice(
                name="Claude-Opus-4.7",
                vendor="anthropic",
                role="strategist",
                speak=lambda p, s: speak_claude(p, s),
                timeout_s=120,
            )
        )

    return voices


def _pick_synthesizer(voices: list[Voice]):
    """Use the strongest available model as synthesizer."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        return lambda v: synthesize(v, lambda p, s: speak_claude(p, s))
    if os.environ.get("GEMINI_API_KEY"):
        return lambda v: synthesize(
            v, lambda p, s: speak_gemini(p, s, model="gemini-2.5-pro")
        )
    return None  # fall back to deterministic format


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convene the Town Council")
    parser.add_argument("question", nargs="?", help="The question to ask")
    parser.add_argument("--file", help="Read question from file")
    parser.add_argument("--system", default="", help="System prompt / framing")
    parser.add_argument(
        "--no-synth", action="store_true", help="Skip synthesis; print raw votes"
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.file:
        question = Path(args.file).read_text()
    elif args.question:
        question = args.question
    else:
        question = sys.stdin.read()

    if not question.strip():
        parser.error("no question provided")

    voices = _build_voices()
    if not voices:
        print("No voices available. Need at least Ollama running locally.",
              file=sys.stderr)
        return 2

    print(
        f"# Council convened ({len(voices)} voices: "
        f"{', '.join(v.name for v in voices)})\n",
        file=sys.stderr,
    )

    council = Council(voices)
    synth = None if args.no_synth else _pick_synthesizer(voices)

    verdict = council.ask(question, system_prompt=args.system, synthesizer=synth)

    if verdict.synthesis:
        print(verdict.synthesis)
        print("\n---\n")
    print(fallback_synthesize(verdict))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
