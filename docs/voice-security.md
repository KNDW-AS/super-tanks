# Voice Security

How the Super Tanks voice stack handles spoken input. The microphone
is the loudest attack surface in a home AI system — anyone in
earshot, including the TV, can attempt to issue commands. This
document spells out the gates voice goes through before it becomes
action.

## The core principle

> Voice is a low-confidence authentication channel by design. Anyone
> in earshot is "authenticated as voice", and that is not enough for
> irreversible operations.

— `core/voice/voice_security.py` module docstring

Every voice transcript is treated as untrusted input. Trust score
does NOT lower the bar for voice. A command Aeris would accept from
William's text channel (trusted source) is held to a stricter
standard when it comes in through a microphone — because the
microphone cannot tell who is speaking.

## Pipeline

```
mic / Wyoming satellite
   ↓
super-tanks-voice.service (tcp://0.0.0.0:10400)
   ↓
WhisperSTTBackend.transcribe()         ← audio → text
   ↓
voice_security.vet_transcript()        ← ZEF scan + critical detect
   ↓
voice_pipeline.handle_transcript()     ← orchestrator
   ↓
       blocked? → drop, log, no action
       critical? → GO-Gate ACK, await Telegram approval
       neither  → agent_hook
   ↓
aeris_bridge → A2A SQLite queue
   ↓
aeris-gateway main_loop (separate process)
   ↓
Aeris / Zeph brain → reply
   ↓
A2A reply → bridge polls → returns
   ↓
voice_profiles.get_voice_profile()     ← pick voice
   ↓
PiperTTSBackend.speak()                ← synthesise
   ↓
HA media_player.* in the right room
```

Four Python processes — `aeris-gateway`, `super-tanks-voice`,
`aeris-mcp`, plus whatever tool execution spawns — coordinate purely
through SQLite-WAL. No HTTP between them, no tokens to leak. Audit
follows the correlation_id end-to-end.

## Gates, in order

### 1. ZEF prompt-injection scan

Every transcript is passed through the same
`core.security.zef_injection_filter.scan_message()` that protects
text input. Verdicts:

- **BLOCK** — drop the transcript, do not call the agent. Logged at
  CRITICAL with the matched patterns. The speaker hears nothing.
- **WARN** — proceed, but the warning lands in the audit trail and
  trust score takes a small hit.
- **ALLOW** — pass through.

The filter looks for instruction-override patterns ("ignore previous
instructions"), data-exfil keywords (`curl https://...`), system
prompt injection (`[system]`), path traversal, and known jailbreak
templates. The same gate covers webhook, Telegram, and voice — one
filter, three channels.

### 2. Critical-command elevation

`voice_security.is_critical_command()` runs a regex against the
transcript looking for verbs that touch irreversible state. Today's
list (`core/voice/voice_security.py::_CRITICAL_PATTERNS`):

| Category | Patterns |
|---|---|
| Locks | `unlock`, `lock`, `lås opp`, `lås`, `open door`, `åpne døra` |
| Alarms | `disarm`, `arm`, `alarmen av`, `alarm på/av`, `avvepn`, `bevæpn` |
| Garage | `garage` |
| System mode | `safe mode`, `lockdown`, `autonomous` |
| Data | `delete`, `drop`, `wipe`, `slett`, `sletta` |
| Money | `transfer ... money`, `overfør ... penger/kroner`, `buy`, `order`, `kjøp`, `bestill` |

The pattern list is intentionally broad. False positives — Aeris
asking "do you want me to lock the door?" tripping the elevation —
just mean William taps approve. False negatives mean an unlocked
door.

Add patterns by editing `_CRITICAL_PATTERNS` and bumping the test
suite. The patterns ship as Norwegian + English alternation, because
a household command might come in either.

### 3. GO-Gate force-route

When `is_critical_command()` returns True, the pipeline:

1. Sets `requires_go_gate=True` on the `VoiceIntent`
2. Speaks a fixed acknowledgement ("Eg har sendt forespurnaden til
   godkjenning. Du må stadfeste det på Telegram før eg gjer noko.")
3. Does **not** call the agent runtime
4. Returns the `VoiceResponse` with `requires_go_gate=True` so the
   voice-runtime layer can route the GO-Gate handshake to William's
   Telegram

The ACK text is identical for Aeris and Zeph by design — an
attacker can't infer which agent picked up by listening for a
different phrase.

The actual GO-Gate enqueue happens one layer up, in the voice
runtime — not in the pipeline. This keeps the pipeline pure and
unit-testable; the runtime is what knows how to reach William.

## Zeph as Voice-Gatekeeper

Per the 6 March 2026 briefing and the architecture above, Zeph is
the routing target for every critical voice command. The pipeline
sets `routing_target="zeph"` on the `VoiceIntent` when
`is_critical` is True, regardless of which name the speaker invoked
or which agent Aeris would have handled the request for.

Zeph's GO-Gate Telegram bot (`AERIS_GOGATE_TELEGRAM_TOKEN`) gets the
approval request. William taps `/approve <id>` or `/deny <id>`. The
voice runtime hears the resolution and either executes the action
or speaks a refusal.

If Zeph's bot doesn't respond within 30 seconds the pipeline times
out and gives the speaker an explicit message. Silent timeouts are
exactly the failure mode this whole stack exists to prevent.

## Audit trail per voice event

Every event written by `handle_transcript()` carries:

| Field | Source |
|---|---|
| `correlation_id` | uuid4 minted at `vet_transcript()` |
| `room_id` | `Transcript.room_id` from the Wyoming satellite context |
| `confidence` | Whisper `avg_logprob → exp` mapped to 0..1 |
| `routing_target` | "aeris" / "zeph" picked by `vet_transcript()` |
| `is_critical` | boolean from the regex |
| `requires_go_gate` | always == is_critical today; separate field for future trust-based escalation |
| `blocked` | True if ZEF said BLOCK |
| `block_reason` | textual reason if blocked |
| `response_text` | what the agent said (or the GO-Gate ACK) |
| `spoken_on` | `media_player.*` entity that played the audio, or None |
| `voice_id` | which profile spoke (incl. `#N` suffix for multi-speaker disambiguation) |

The correlation_id threads through Aeris's brain audit, the GO-Gate
queue, and the dispatch log, so post-incident review can trace a
spoken word all the way to whatever it did or didn't do.

## Voice identity vs voice distinguishability

A subtle invariant: Aeris and Zeph have distinct `voice_id` strings
(`no_NO-talesyntese-medium` vs `no_NO-talesyntese-medium#1`) even
when the underlying Piper model has only one speaker. The audit
trail tells them apart; the human ear might not.

This is intentional defence-in-depth, articulated by Zeph in the
A2A conversation that drove the speaker-support PR:

> If an attacker spoofs a critical command, they cannot tell from
> the spoken ACK whether Aeris or Zeph handled it — but they DO
> know it came from "the system". That is actually a security
> feature (obscurity by design).

So the system maintains:

- **External indistinguishability**: same voice means an attacker
  listening to the spoken response cannot map trust state to audio
  features.
- **Internal observability**: distinct `voice_id` means an operator
  reading the audit log knows exactly which agent answered.

When a multi-speaker Norwegian Piper model is imported later, the
`--speaker N` support added in PR #7 will make the audio actually
distinct without any further code change. The audit-vs-audio gap
closes silently.

## Threat model

The microphone hears, by default:

- William, Karianne, David, Nicole — the household
- Guests
- Children imitating commands
- TV ads ("Hey Aeris, buy the…")
- Audio deepfakes played from a phone
- The neighbour shouting through an open window

The stack assumes ALL of these can speak. The defences:

| Threat | Defence |
|---|---|
| TV/ad replay | `requires_go_gate` on every critical action; William must tap approve |
| Deepfake of William | Same — voice is not authentication |
| Child playing | Same — and `voice_security` looks for the *intent*, not the speaker |
| Guest curious | Same |
| Prompt injection in spoken text | ZEF scan before agent runtime |
| Confused speech routed to wrong agent | `routing_target` is set deterministically by `vet_transcript`, not by the speaker's word choice |
| Approval-channel hijack | Telegram GO-Gate bot uses its own token (`AERIS_GOGATE_TELEGRAM_TOKEN`), audited separately |

Not in scope today:

- **Voice biometrics**: `Transcript.speaker_hint` exists as a weak
  field, but it is NOT used for authentication. Voice biometrics
  are spoofable by recording. They live in the audit trail as a
  hint for review, not a gate.
- **Anti-replay of approved actions**: if William approved
  "unlock the door" yesterday, that approval does not authorise
  the same command today. Each GO-Gate request is one-shot.

## File map

| File | Role |
|---|---|
| `core/diq/diq_voice.py` | Frozen contract: `DIQVoiceSTT`, `DIQVoiceTTS`, `DIQWakeWord`, `Transcript`, `Utterance`, `WakeEvent` |
| `core/voice/voice_security.py` | `vet_transcript()`, `_CRITICAL_PATTERNS`, `is_critical_command()` |
| `core/voice/voice_pipeline.py` | `handle_transcript()` orchestrator |
| `core/voice/voice_profiles.py` | Voice-id map per agent (with env overrides) |
| `core/voice/room_router.py` | Mic-to-speaker routing |
| `core/voice/backends/piper_tts.py` | Local TTS adapter (with `--speaker` support since PR #7) |
| `core/voice/backends/whisper_stt.py` | Local STT adapter |
| `scripts/voice_runner.py` | Wyoming server + agent-hook loader (PR #5) |
| `scripts/install_voice.sh` | One-shot installer |
| `tests/test_voice/` | Unit + integration tests (49 today) |

## Pull requests of record

| PR | What |
|---|---|
| #5 | `scripts/voice_runner.py` added with wyoming/stdin/once modes |
| #6 | `nb_NO` → `no_NO` language code fix across voice_profiles + tests |
| #7 | Piper `--speaker N` support with graceful single-speaker clamp |

## Where to push next

- Import a multi-speaker Norwegian Piper model so Aeris and Zeph
  actually sound different.
- Add `voice_biometrics` field to `VoiceIntent` (still informational
  only, never authoritative).
- Wire Wyoming satellites into HA, populate the `mics` lists in
  `config/voice_rooms.json` so `room_for_mic()` returns the right
  room.
- Replay-attack tests for the GO-Gate one-shot invariant.

## Authoring notes

This document is operator-facing. It deliberately does not list
specific token values, satellite IPs, or William's home topology.
That information lives in `~/.config/super-tanks/env` and the HA
configuration — out of git, out of this doc, out of search indexes.
