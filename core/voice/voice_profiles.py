"""
core/voice/voice_profiles.py
==============================
Canonical voice-id map for the two agents.

Aeris is the family-facing agent; her voice should be warm, clear,
unhurried — the one telling bedtime stories. Zeph is the technical
agent; his voice should be calm, precise, and a little flatter — the
one reporting that the dispatch audit chain just verified.

The mapping below is the ONE PLACE these are decided. Tests pin to
the keys here. The operator can override via env vars without
touching code:

  ST_VOICE_AERIS   override voice_id for Aeris
  ST_VOICE_ZEPH    override voice_id for Zeph
  ST_VOICE_LANG    override language code (default nb_NO)

Default voice ids assume a Piper installation with the canonical
Norwegian models from rhasspy/piper. If you switch backend (e.g. to
ElevenLabs), the operator overrides above pick up the new ids.

Adding new agents: add a new entry to _DEFAULT_PROFILES. The voice
pipeline refuses to speak with a voice_id that doesn't resolve via
this module, so a typo crashes loudly at TTS-time instead of using
"some default voice" silently.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Dict, Optional

logger = logging.getLogger("super_tanks.voice.profiles")


@dataclass(frozen=True)
class VoiceProfile:
    agent_id: str
    voice_id: str
    language: str
    description: str


_DEFAULT_PROFILES: Dict[str, VoiceProfile] = {
    "aeris": VoiceProfile(
        agent_id="aeris",
        # Piper Norwegian female. The medium quality model balances
        # latency vs naturalness for the family-facing use cases.
        voice_id="nb_NO-talesyntese-medium",
        language="nb_NO",
        description="Warm Norwegian female — Aeris's family voice",
    ),
    "zeph": VoiceProfile(
        agent_id="zeph",
        # Piper has only one mainstream Norwegian male voice family;
        # we use the same model family with a slightly different
        # speaker id when available. The operator likely needs to
        # override this with whatever they actually have installed.
        voice_id="nb_NO-talesyntese-medium#1",
        language="nb_NO",
        description="Calm Norwegian male — Zeph's technical voice",
    ),
}


def get_voice_profile(agent_id: str) -> VoiceProfile:
    """Resolve the voice profile for an agent. Operator env-var
    overrides win. Raises KeyError if the agent is unknown — voice
    must be an explicit choice, never a silent fallback.
    """
    if agent_id not in _DEFAULT_PROFILES:
        raise KeyError(
            f"No voice profile for agent {agent_id!r}. "
            f"Add one to core/voice/voice_profiles.py._DEFAULT_PROFILES."
        )
    base = _DEFAULT_PROFILES[agent_id]
    override_id = os.environ.get(f"ST_VOICE_{agent_id.upper()}")
    override_lang = os.environ.get("ST_VOICE_LANG")
    if override_id or override_lang:
        return VoiceProfile(
            agent_id=base.agent_id,
            voice_id=override_id or base.voice_id,
            language=override_lang or base.language,
            description=base.description + " (operator override)",
        )
    return base


def list_profiles() -> Dict[str, VoiceProfile]:
    """Snapshot of all profiles with env-var overrides applied."""
    return {a: get_voice_profile(a) for a in _DEFAULT_PROFILES}
