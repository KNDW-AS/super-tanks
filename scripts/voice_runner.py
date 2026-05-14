"""
scripts/voice_runner.py
=========================
Long-running voice I/O daemon for the Super Tanks deployment.

Wires together the existing voice infrastructure:

    Wyoming satellite (HA-Voice) → WhisperSTTBackend
                                      ↓
                          voice_pipeline.handle_transcript
                                      ↓
                                  PiperTTSBackend → speaker

Service form (systemd unit shipped by scripts/install_voice.sh):

    [Service]
    ExecStart=.venv/bin/python -m scripts.voice_runner

Local testing without satellites:

    python -m scripts.voice_runner --mode once \\
        --transcript "lås opp døra" --room kitchen

The runner intentionally does NOT bundle an agent runtime. The agent
hook is a hot-swap: production deployments wire it to the live
Aeris/Zeph gateway via --agent-hook 'module.path:callable' (or the
ST_AGENT_HOOK env var). This open-source release ships a polite stub
so the audit trail and TTS path are still exercisable end-to-end.

Three run modes:

  --mode wyoming   (default) Listen for HA-Voice satellites on TCP.
                   Requires `pip install wyoming`. Production form.
  --mode stdin     Read 'room|text' lines from stdin and dispatch
                   each through the pipeline. Useful for debugging
                   the agent hook without an STT/satellite present.
  --mode once      Process one synthetic transcript from --transcript
                   and exit. Used by the smoke-test in install_voice.sh.

Exit codes:
  0  clean shutdown / smoke-test success
  1  smoke-test blocked by voice_security (expected for critical
     commands; the runner still returns success when called by cron)
  2  configuration error (bad agent hook, wyoming missing, etc.)
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
from typing import Awaitable, Callable, Optional

from core.diq.diq_voice import Transcript
from core.voice.backends.piper_tts import PiperTTSBackend
from core.voice.backends.whisper_stt import WhisperSTTBackend
from core.voice.voice_pipeline import VoiceResponse, handle_transcript
from core.voice.voice_security import VoiceIntent

logger = logging.getLogger("super_tanks.voice.runner")

ENV_RUNNER_MODE = "ST_VOICE_RUNNER_MODE"          # wyoming|stdin|once
ENV_WYOMING_HOST = "ST_VOICE_WYOMING_HOST"
ENV_WYOMING_PORT = "ST_VOICE_WYOMING_PORT"
ENV_AGENT_HOOK = "ST_AGENT_HOOK"


AgentHook = Callable[[VoiceIntent], Awaitable[str]]


# ── Agent hook (stub) ────────────────────────────────────────────────────

async def _stub_agent_hook(intent: VoiceIntent) -> str:
    """Default agent hook for the open-source repo.

    Returns a polite Norwegian acknowledgement explaining that the
    agent runtime isn't wired up. Production deployments override
    this with `--agent-hook module:callable` or `ST_AGENT_HOOK`.
    """
    logger.info(
        "[VOICE_RUNNER] stub hook fired for intent corr=%s target=%s text=%r",
        intent.correlation_id, intent.routing_target,
        intent.transcript.text[:80],
    )
    return (
        "Eg høyrer deg, men agent-køyringa er ikkje kopla til endå. "
        "Operatør må peike ST_AGENT_HOOK på Aeris- eller Zeph-gateway."
    )


def _resolve_agent_hook(spec: Optional[str]) -> AgentHook:
    """Load `module.path:callable` from the spec; fall back to the stub
    on any failure with a loud log line. We don't crash here because
    a misconfigured agent hook should fail closed to the stub, not
    take the whole voice runner down on systemd start-up."""
    if not spec:
        return _stub_agent_hook
    try:
        module_name, attr = spec.split(":", 1)
    except ValueError:
        logger.error(
            "[VOICE_RUNNER] agent hook spec %r must be 'module.path:callable'",
            spec,
        )
        return _stub_agent_hook
    try:
        import importlib
        mod = importlib.import_module(module_name)
        hook = getattr(mod, attr)
    except Exception as exc:
        logger.error(
            "[VOICE_RUNNER] could not load agent hook %r: %s — using stub",
            spec, exc,
        )
        return _stub_agent_hook
    if not callable(hook):
        logger.error(
            "[VOICE_RUNNER] agent hook %r is not callable — using stub",
            spec,
        )
        return _stub_agent_hook
    logger.info("[VOICE_RUNNER] agent hook loaded: %s", spec)
    return hook


# ── Once-mode (CLI smoke test) ──────────────────────────────────────────

async def _run_once(transcript_text: str, room_id: str,
                    tts: PiperTTSBackend,
                    agent_hook: AgentHook) -> int:
    """Process one synthetic transcript and exit. Useful for
    smoke-testing the full pipeline without standing up a satellite.
    Returns 0 on a clean run; 1 if voice_security blocked the
    transcript (expected for genuinely critical commands)."""
    transcript = Transcript(text=transcript_text, room_id=room_id,
                            confidence=0.9)
    response: VoiceResponse = await handle_transcript(
        transcript, tts=tts, agent_hook=agent_hook,
    )
    logger.info(
        "[VOICE_RUNNER] once: blocked=%s spoken_on=%s gogate=%s "
        "text=%r audit=%s",
        response.blocked, response.spoken_on, response.requires_go_gate,
        response.response_text[:80], response.audit_notes,
    )
    print(f"blocked={response.blocked} "
          f"requires_go_gate={response.requires_go_gate} "
          f"spoken_on={response.spoken_on}")
    print(f"response: {response.response_text}")
    return 0 if not response.blocked else 1


# ── Stdin-mode (operator-driven testing) ────────────────────────────────

async def _run_stdin(tts: PiperTTSBackend, agent_hook: AgentHook) -> int:
    """Read one transcript per line from stdin. Format `room|text`,
    or plain text (treated as room=unknown). Loops until EOF."""
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    logger.info(
        "[VOICE_RUNNER] stdin mode — input format 'room|text' per line",
    )
    while True:
        line = await reader.readline()
        if not line:
            return 0
        s = line.decode("utf-8", errors="ignore").strip()
        if not s:
            continue
        if "|" in s:
            room, text = s.split("|", 1)
        else:
            room, text = "unknown", s
        transcript = Transcript(text=text.strip(), room_id=room.strip(),
                                confidence=0.9)
        try:
            resp = await handle_transcript(transcript, tts=tts,
                                           agent_hook=agent_hook)
            print(
                f"[blocked={resp.blocked} spoken_on={resp.spoken_on}] "
                f"{resp.response_text}", flush=True,
            )
        except Exception:
            logger.exception("[VOICE_RUNNER] handle_transcript raised")


# ── Wyoming-mode (production satellites) ────────────────────────────────

async def _run_wyoming(host: str, port: int,
                       stt: WhisperSTTBackend,
                       tts: PiperTTSBackend,
                       agent_hook: AgentHook) -> int:
    """Stand up a Wyoming TCP server. HA-Voice satellites connect,
    stream audio chunks, this runner buffers + transcribes via Whisper,
    then dispatches the resulting Transcript through the pipeline.

    The wyoming protocol implementation lives in a separate pip
    package (`pip install wyoming`). The runner refuses to start in
    wyoming mode without it — operators can fall back to --mode stdin
    for local testing without satellites.
    """
    try:
        from wyoming.server import AsyncServer, AsyncEventHandler
        from wyoming.audio import AudioChunk, AudioStart, AudioStop
        from wyoming.event import Event
    except ImportError as exc:
        logger.error(
            "[VOICE_RUNNER] wyoming not installed (%s). "
            "Install with: pip install wyoming. "
            "Or run with --mode stdin for local testing.", exc,
        )
        return 2

    class _Handler(AsyncEventHandler):
        """One Wyoming connection = one satellite = one room. The
        satellite's name is read from the AudioStart context and used
        as the room_id so room_router can pick the right speaker."""

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._buf = bytearray()
            self._sample_rate = 16000
            self._sample_width = 2
            self._channels = 1
            self._room_id = "unknown"

        async def handle_event(self, event: Event) -> bool:
            if AudioStart.is_type(event.type):
                info = AudioStart.from_event(event)
                self._buf.clear()
                self._sample_rate = info.rate or 16000
                self._sample_width = info.width or 2
                self._channels = info.channels or 1
                # Wyoming's context is free-form; pull a sensible room id.
                ctx = getattr(info, "context", None) or {}
                self._room_id = (ctx.get("satellite_id")
                                 or ctx.get("name")
                                 or "unknown")
                return True
            if AudioChunk.is_type(event.type):
                self._buf.extend(AudioChunk.from_event(event).audio)
                return True
            if AudioStop.is_type(event.type):
                await self._finalise()
                return True
            return True

        async def _finalise(self) -> None:
            if not self._buf:
                return
            import tempfile
            import wave
            wav_fd, wav_path = tempfile.mkstemp(suffix=".wav")
            os.close(wav_fd)
            try:
                with wave.open(wav_path, "wb") as wf:
                    wf.setnchannels(self._channels)
                    wf.setsampwidth(self._sample_width)
                    wf.setframerate(self._sample_rate)
                    wf.writeframes(bytes(self._buf))
                self._buf.clear()
                stt_result = await stt.transcribe(wav_path, language="no")
                transcript = Transcript(
                    text=stt_result.text, room_id=self._room_id,
                    confidence=stt_result.confidence,
                    audio_ref=wav_path,
                )
                if not transcript.text:
                    logger.info(
                        "[VOICE_RUNNER] empty transcript from %s (conf=%.2f)",
                        self._room_id, transcript.confidence,
                    )
                    return
                await handle_transcript(transcript, tts=tts,
                                        agent_hook=agent_hook)
            except Exception:
                logger.exception("[VOICE_RUNNER] finalise raised")
            finally:
                try:
                    os.unlink(wav_path)
                except OSError:
                    pass

    server = AsyncServer.from_uri(f"tcp://{host}:{port}")
    logger.info(
        "[VOICE_RUNNER] wyoming server listening on tcp://%s:%d", host, port,
    )
    try:
        await server.run(_Handler)
    except asyncio.CancelledError:
        logger.info("[VOICE_RUNNER] wyoming server cancelled — shutting down")
    return 0


# ── Entrypoint ────────────────────────────────────────────────────────────

def _setup_logging() -> None:
    logging.basicConfig(
        level=os.environ.get("ST_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="scripts.voice_runner")
    p.add_argument(
        "--mode", choices=("wyoming", "stdin", "once"),
        default=os.environ.get(ENV_RUNNER_MODE, "wyoming"),
        help="Run mode. Default: wyoming (production).",
    )
    p.add_argument(
        "--host", default=os.environ.get(ENV_WYOMING_HOST, "0.0.0.0"),
        help="TCP host for wyoming mode.",
    )
    p.add_argument(
        "--port", type=int,
        default=int(os.environ.get(ENV_WYOMING_PORT, "10300")),
        help="TCP port for wyoming mode.",
    )
    p.add_argument(
        "--transcript",
        help="(once mode) Synthetic transcript text.",
    )
    p.add_argument(
        "--room", default="kitchen",
        help="(once mode) Synthetic room id.",
    )
    p.add_argument(
        "--agent-hook", default=os.environ.get(ENV_AGENT_HOOK),
        help="'module.path:callable' loaded as agent hook. "
             "Defaults to a stub.",
    )
    return p


def main(argv=None) -> int:
    _setup_logging()
    args = _build_argparser().parse_args(argv)

    stt = WhisperSTTBackend()
    tts = PiperTTSBackend()
    agent_hook = _resolve_agent_hook(args.agent_hook)

    if args.mode == "once":
        if not args.transcript:
            logger.error("--transcript required in once mode")
            return 2
        return asyncio.run(
            _run_once(args.transcript, args.room, tts, agent_hook),
        )
    if args.mode == "stdin":
        return asyncio.run(_run_stdin(tts, agent_hook))

    async def _run() -> int:
        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()

        def _stop() -> None:
            logger.info("[VOICE_RUNNER] signal received — stopping")
            stop_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _stop)
            except NotImplementedError:
                # Windows / restricted environments — best effort.
                pass

        wyoming_task = asyncio.create_task(
            _run_wyoming(args.host, args.port, stt, tts, agent_hook),
        )
        stop_task = asyncio.create_task(stop_event.wait())
        done, pending = await asyncio.wait(
            {wyoming_task, stop_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        if wyoming_task in done:
            return wyoming_task.result()
        return 0

    return asyncio.run(_run())


if __name__ == "__main__":
    sys.exit(main())
