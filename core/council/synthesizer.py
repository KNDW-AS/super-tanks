"""Synthesizer: collapse N voices into one structured answer."""

from __future__ import annotations

import textwrap

from .council import Verdict


SYNTH_PROMPT = textwrap.dedent("""\
    You are the Speaker of the Council. Your job is to read the votes of the
    council members below and write a single synthesis for the human asking
    the question.

    Rules:
    - Do NOT just average the answers. Identify CONVERGENCE (where the council
      agrees) and DIVERGENCE (where they disagree).
    - When the council disagrees, surface BOTH positions with attribution.
    - When a voice is clearly wrong, say so — minority report is part of the job.
    - Stay terse. No filler. No "as an AI" preamble. Lead with the answer, then
      show the deliberation.
    - End with: "Convergence: ... / Divergence: ..." one-line summary.
""")


def format_council_prompt(verdict: Verdict) -> str:
    """Build the synthesizer-input from a verdict."""
    parts = [f"## Question\n{verdict.question}\n"]
    if verdict.system_prompt:
        parts.append(f"## System framing\n{verdict.system_prompt}\n")
    parts.append("## Council members and their answers\n")
    for reply in verdict.replies:
        header = f"### {reply.voice} ({reply.vendor}, role={reply.role})"
        if reply.error:
            parts.append(f"{header}\n_failed: {reply.error}_\n")
        else:
            parts.append(f"{header}\n{reply.text}\n")
    return "\n".join(parts)


def synthesize(verdict: Verdict, speak) -> str:
    """Run the synthesizer over a Verdict using the given speak callable.

    `speak` has the same signature as a Voice.speak: (prompt, system) -> str.
    The synthesizer should typically be a different (or larger) model than the
    council members — Claude Opus or Gemini Pro work well here.
    """
    prompt = format_council_prompt(verdict)
    return speak(prompt, SYNTH_PROMPT).strip()


def fallback_synthesize(verdict: Verdict) -> str:
    """Cheap deterministic synthesizer when no synth-model is available. Lists
    voices and their answers; no inter-voice reasoning."""
    lines = [f"# Council Verdict ({verdict.quorum}/{verdict.total} voices)"]
    lines.append(f"\n**Question:** {verdict.question}\n")
    for reply in verdict.replies:
        lines.append(f"\n## {reply.voice} ({reply.vendor}, {reply.role})")
        if reply.error:
            lines.append(f"*failed: {reply.error}*")
        else:
            lines.append(reply.text)
            lines.append(f"\n_({reply.elapsed_s:.1f}s)_")
    return "\n".join(lines)
