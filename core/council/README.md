# Town Council

Multi-vendor AI deliberation for Super Tanks. Ask one question, get N independent
voices from N vendors, synthesised into one structured answer.

This is the architectural expression of the AI-for-AI mission: when an agent
needs to deliberate, it does not borrow one mind — it asks the council.

## Voices

Each voice is a frontier-tier or top open-weight model from a different vendor.
The Council runs on whatever voices have credentials available.

| Voice | Vendor | Model | Free? | Required env var |
|---|---|---|---|---|
| Llama-Local | Ollama | llama3.2:3b | ✅ free, local | (none — needs Ollama running) |
| Gemini-2.5-Flash | Google | gemini-2.5-flash | ✅ free tier | `GEMINI_API_KEY` |
| Gemini-2.5-Pro | Google | gemini-2.5-pro | ✅ free tier | `GEMINI_API_KEY` |
| Llama-3.3-70B | Groq | llama-3.3-70b-versatile | ✅ free tier | `GROQ_API_KEY` |
| DeepSeek-R1 | DeepSeek | deepseek-reasoner | ✅ cheap | `DEEPSEEK_API_KEY` |
| Qwen-2.5-72B | OpenRouter | qwen-2.5-72b-instruct:free | ✅ free tier | `OPENROUTER_API_KEY` |
| Claude-Opus-4.7 | Anthropic | claude-opus-4-7 | 💰 pay tier | `ANTHROPIC_API_KEY` |

## Usage

```bash
# Minimal: just ask
python -m core.council.cli "Should we ship the OSS release on July 1 or August 1?"

# With system framing
python -m core.council.cli --system "You are advising KNDW Shelter Solutions." \
  "Should we accept the Horizon co-funding rate of 70%?"

# From a file
python -m core.council.cli --file question.md

# Raw votes, no synthesis
python -m core.council.cli --no-synth "What is the capital of Norway?"
```

## Output

```
# Council convened (3 voices: Llama-Local, Gemini-2.5-Flash, Gemini-2.5-Pro)

[Synthesizer's verdict: convergence + divergence]

---

# Council Verdict (3/3 voices)

## Gemini-2.5-Flash (google, fast-generalist)
[full answer]

## Gemini-2.5-Pro (google, deep-thinker)
[full answer]

## Llama-Local (ollama, open-weight)
[full answer]
```

## Adding voices

Just set the env var. Voices that don't have a key are silently skipped.

```bash
export GROQ_API_KEY=...
export DEEPSEEK_API_KEY=...
export OPENROUTER_API_KEY=...
```

The synthesizer picks the strongest available model (Claude Opus → Gemini Pro
→ deterministic fallback).

## Programmatic use

```python
from core.council import Council, Voice
from core.council.providers.ollama import speak_ollama
from core.council.providers.gemini import speak_gemini

council = Council([
    Voice("Llama", "ollama", lambda p, s: speak_ollama(p, s)),
    Voice("Gemini", "google", lambda p, s: speak_gemini(p, s)),
])

verdict = council.ask("What's the safest day to merge?")
for r in verdict.replies:
    print(r.voice, r.text)
```

## Why this is in Super Tanks

Super Tanks is a compliance-by-design runtime for autonomous AI agents.
Single-vendor agents are a supply-chain risk and a freedom problem. The
Council makes vendor-pluralism a first-class architectural choice: an agent
that disagrees with itself is harder to capture, harder to manipulate, and
more honest about what it doesn't know.

Built 2026-05-27 night-shift. Apache 2.0 with the rest of the framework.
