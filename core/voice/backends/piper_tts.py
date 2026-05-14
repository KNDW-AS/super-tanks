"""
core/voice/backends/piper_tts.py
==================================
Piper TTS backend skeleton.

Piper (https://github.com/rhasspy/piper) is the local, fast Norwegian
TTS engine. This module is the adapter — it shells out to the `piper`
binary or, when available, the python bindings, and ships the
resulting WAV to a Home Assistant media_player via HA's `play_media`
service.

This file is INTENTIONALLY a skeleton. The Piper binary, the model
files, and the HA call_service plumbing all live outside the unit-
testable surface of this repo. The structure here is:

  - `PiperTTSBackend.speak(utterance)` synthesises audio via Piper
  - hands the audio to `play_via_ha` (or a configured player)
  - returns True/False per the DIQVoiceTTS contract

Operators wire the binary path + model dir via env vars:

    ST_PIPER_BIN           path to the piper executable
    ST_PIPER_MODEL_DIR     dir containing nb_NO-*-medium.onnx files
    ST_PIPER_HA_PLAY_URL   HA REST URL for play_media (optional)

Without those, every call returns False and logs a single line — the
pipeline will fall back to Telegram so the user is never silently
ignored.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shlex
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from core.diq.diq_voice import DIQVoiceTTS, Utterance

logger = logging.getLogger("super_tanks.voice.piper")

ENV_PIPER_BIN = "ST_PIPER_BIN"
ENV_PIPER_MODEL_DIR = "ST_PIPER_MODEL_DIR"
ENV_HA_PLAY_URL = "ST_PIPER_HA_PLAY_URL"


class PiperTTSBackend(DIQVoiceTTS):
    def __init__(self,
                 piper_bin: str = "",
                 model_dir: str = "",
                 ha_play_url: str = ""):
        self.piper_bin = piper_bin or os.environ.get(ENV_PIPER_BIN, "")
        self.model_dir = model_dir or os.environ.get(ENV_PIPER_MODEL_DIR, "")
        self.ha_play_url = ha_play_url or os.environ.get(ENV_HA_PLAY_URL, "")

    def _ready(self) -> bool:
        return bool(self.piper_bin and Path(self.piper_bin).exists()
                    and self.model_dir and Path(self.model_dir).exists())

    async def speak(self, utterance: Utterance) -> bool:
        if not self._ready():
            logger.warning(
                "[PIPER] not configured (set %s + %s); cannot speak '%s'",
                ENV_PIPER_BIN, ENV_PIPER_MODEL_DIR,
                utterance.text[:80],
            )
            return False
        model_path = self._resolve_model_path(utterance.voice_id)
        if model_path is None:
            logger.error("[PIPER] unknown voice_id %r in %s",
                         utterance.voice_id, self.model_dir)
            return False
        try:
            wav_path = await self._synthesise(utterance.text, model_path)
        except Exception as exc:
            logger.error("[PIPER] synthesise failed: %s", exc)
            return False
        try:
            return await self._play(wav_path, utterance.speaker_entity)
        finally:
            try:
                Path(wav_path).unlink(missing_ok=True)
            except Exception:
                pass

    def _resolve_model_path(self, voice_id: str) -> "Path | None":
        # voice_id forms: "nb_NO-talesyntese-medium" or
        # "nb_NO-talesyntese-medium#1" (speaker idx).
        base = voice_id.split("#", 1)[0]
        candidate = Path(self.model_dir) / f"{base}.onnx"
        return candidate if candidate.exists() else None

    async def _synthesise(self, text: str, model_path: Path) -> str:
        out_path = Path(tempfile.mkstemp(suffix=".wav")[1])
        cmd = [self.piper_bin, "--model", str(model_path),
               "--output_file", str(out_path)]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate(text.encode("utf-8"))
        if proc.returncode != 0:
            raise RuntimeError(
                f"piper rc={proc.returncode} {stderr.decode(errors='ignore')[:200]}"
            )
        return str(out_path)

    async def _play(self, wav_path: str, speaker_entity: str) -> bool:
        # When ST_PIPER_HA_PLAY_URL isn't set, we play locally — useful
        # for single-machine dev where the box also has speakers.
        if not self.ha_play_url:
            return await self._play_local(wav_path)
        return await self._play_via_ha(wav_path, speaker_entity)

    async def _play_local(self, wav_path: str) -> bool:
        for player in ("paplay", "aplay", "afplay"):
            if shutil.which(player):
                proc = await asyncio.create_subprocess_exec(
                    player, wav_path,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await proc.wait()
                return proc.returncode == 0
        logger.warning("[PIPER] no local audio player found "
                       "(paplay/aplay/afplay)")
        return False

    async def _play_via_ha(self, wav_path: str,
                           speaker_entity: str) -> bool:
        # Production deployments inject a richer client; the
        # skeleton path delegates to a placeholder for clarity.
        try:
            from core.voice.backends.ha_play_media import play_wav_on_entity
        except Exception as exc:
            logger.warning("[PIPER] HA play bridge unavailable: %s", exc)
            return False
        return await play_wav_on_entity(wav_path, speaker_entity,
                                        ha_play_url=self.ha_play_url)

    def list_voices(self) -> List[Dict[str, Any]]:
        if not Path(self.model_dir).exists():
            return []
        out: List[Dict[str, Any]] = []
        for path in sorted(Path(self.model_dir).glob("*.onnx")):
            out.append({
                "voice_id": path.stem,
                "language": path.stem.split("-", 1)[0],
                "gender": "unknown",  # piper model metadata is opt-in
                "description": f"Piper model {path.name}",
            })
        return out
