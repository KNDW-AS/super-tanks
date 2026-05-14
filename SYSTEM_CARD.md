# Super Tanks — System Card

**Version:** v3.2 (post-PR #2)
**Last reviewed:** 2026-05-14
**Maintainer:** William (KNDW Shelter Solutions AS)

This document is the deployer-facing description of the assembled
Super Tanks system. It complements the API-level docstrings in `core/`
and is intended for: external researchers reviewing the security
posture, anyone deploying their own copy, and any conformity-assessment
exercise (NIST AI RMF, ISO/IEC 42001 Annex A.8, EU AI Act Annex IV).

It is deliberately short. Source-of-truth for any specific control is
the cited file:line in the codebase.

## Intended purpose

A multi-agent in-home assistant for one family. Two agents:

- **Aeris** — family-facing. READ + CHAT only. Talks to William, his
  partner, and (with stricter limits) the children. Controls the smart
  home (lights, climate, locks). Reads memory; does not write to
  family-shared paths without human approval.
- **Zeph** — system-facing. EXEC. Runs maintenance, code proposals,
  diagnostics. Cannot talk to the family directly except via Telegram
  to William.

The system is deployed by an individual on personal hardware
(Linux, Z620 + Legion). It is **not** placed on the EU market, and
is **not** offered as a service to anyone outside the household.
Per Article 2(10) of EU Regulation 2024/1689, it is a personal
non-professional use of AI and falls outside the scope of the EU AI
Act's high-risk obligations. The architecture is nonetheless designed
to be reachable for those obligations should the system later be
commercialised.

## Capability surface

### What the agents can do

- **Aeris (READ/CHAT, level 2):** smart-home reads + writes
  (`home_assistant`), task list, memory hierarchy reads, weather, web
  search/browse, file reads under allowed roots, calculator, agent-to-agent
  messaging, push notifications.
- **Zeph (EXEC, level 4):** everything Aeris can do plus shell, Python
  exec (sandboxed), code edits via the quarantine flow, file writes,
  memory hierarchy writes, image generation, hierarchical memory
  delete (ADMIN).

Full per-agent allowlists in
`core/security/tool_allowlists.py:28-152`.

### What the agents cannot do

- Aeris cannot use `propose_code_change`, `file_write`, `code_edit`,
  `shell_exec`, `python_exec`, `memory_consolidate`, `memory_delete`,
  `memory_store`, `memory_store_hierarchical`, `image_generate`,
  `memory_tools`, or `task_done`. Asserted at module import:
  `core/security/aeris_security_directives.py:78-94` raises
  RuntimeError if a future change leaks any forbidden tool into the
  Aeris allowlist.
- Neither agent can modify its own soul file
  (`core/aeris_soul.py`, `core/zeph_soul.py`) — change → SHA-256
  mismatch → SAFE_MODE.
- Neither agent can modify the DIQ frozen contracts
  (`core/diq/diq_*.py` except `diq_registry.py`) — change → DIQ
  integrity check refuses startup.
- Neither agent can dispatch a tool without a valid HMAC identity
  token (`core/security/agent_identity.py:91-117`).
- Neither agent can call `DIQTool.execute()` directly — it's gated
  by a ContextVar set only by `core.gateway.dispatch_tool`
  (`core/diq/diq_tools.py:96-117`). Subclasses overriding `execute()`
  fail at class definition time.

## Models in use

| Provider | Model | Use | Trust tier | Where invoked |
|---|---|---|---|---|
| Anthropic | Claude (varying) | Aeris primary brain | High | core/aeris_brain.py (out-of-tree) |
| Google | Gemini | Vision + reasoning fallback | High | core/aeris_brain.py |
| Moonshot | Kimi | Code planning | Medium | tools/diq/plan_task_diq.py (out-of-tree) |
| Local Ollama | llama3.2:3b | ZEF secondary classifier | Low (untrusted output) | `core/security/zef_llm_classifier.py` |
| Local Ollama | nomic-embed-text | Memory embeddings | Low | `core/memory/hybrid_search.py` |

The local Ollama models run on the same machine; their outputs are
treated as untrusted by design and pass through the same security
gates as user input. Cloud-provider tokens live in env vars; raw
prompts are scrubbed by `core/security/audit_sanitizer.py` before
being committed to the audit log.

## Security architecture (12 layers)

In dispatch order. Each layer is independent — failure of any layer
does not silently bypass the next.

1. **Identity verification** — HMAC-SHA-256 on every dispatch
   (`core/security/agent_identity.py`, `core/gateway.py:66-76`).
2. **DIQ role check** — `READ < CHAT < WRITE < EXEC < ADMIN`
   hierarchy (`core/diq/diq_tools.py:128-152`).
3. **Per-agent tool allowlist** (`core/security/tool_allowlists.py`).
4. **Gateway chokepoint** — `DIQTool.execute()` refuses dispatch
   outside gateway context (`core/diq/diq_tools.py:96-117`).
5. **ZEF prompt-injection filter** — regex (40+ patterns EN/NO,
   Unicode normalisation) + LLM classifier on high-risk channels
   (`core/security/zef_injection_filter.py`,
   `core/security/zef_llm_classifier.py`).
6. **Memory RBAC + tripwires** — every memory op gates on
   `is_path_accessible` and `is_tripwire`
   (`core/memory/secure_store.py`, `core/memory/access_control.py`,
   `core/memory/tripwires.py`).
7. **Append-only audit log** — every memory op recorded WAL-mode
   SQLite (`core/memory/audit_log.py`).
8. **GO-Gate human approval** — atomic SQL transitions, single-use
   request IDs, full-256-bit args hash, 5-min TTL
   (`core/ask_admin.py`).
9. **Mode controller** — LOCKDOWN by default, AUTONOMOUS times out
   to LOCKDOWN, Night Mode (21:00–06:00 + 2h inactivity) shrinks
   Zeph to observation-only (`core/security/super_tanks_mode.py`).
10. **Trust score** — five behavioural levels (probation → principal),
    daily decay −0.5, tripwire = −100 instant probation
    (`core/security/trust_score.py`).
11. **Code quarantine** — every Aeris-authored code change runs the
    AST sandbox-escape scanner; sandbox-escape patterns are HARD
    FAIL with no override (`core/zeph_quarantine.py`,
    `core/zeph_quarantine_ast.py`).
12. **Soul integrity + DIQ frozen contracts** — SHA-256 sealed at
    build time; runtime mismatch → SAFE_MODE / refuses startup
    (`core/soul_guard.py`, `core/diq/diq_integrity.py`).

Bootstrap sequence in `core/bootstrap.py` runs steps 12 → 1 in fail-
fast order at process start. The entry point (`main_loop.py`) lives
outside this open-source release and is responsible for calling
`boot()`.

## What this system does NOT defend against

- **Compromised host.** An attacker with shell as the deploying user
  can read `data/.identity_key`, modify SQLite databases, and rewrite
  source files. Anchor that trust in OS controls, not in Super Tanks.
- **Indirect prompt injection in tool outputs.** Memory contents and
  web/file outputs are not re-scanned before being re-fed to the
  LLM context. Memory poisoning via a crafted `web_browse` result is
  the canonical path; not yet defended at this layer.
- **Runtime escape from approved code.** The AST scan is preventative
  but static. Once a quarantine proposal is approved it runs in the
  same Python process with the same privileges as the agent. A
  cleverly-crafted call sequence that the AST scanner accepted can
  still misbehave at runtime.
- **Capability uplift in the underlying LLMs.** Super Tanks treats
  the upstream models (Claude, Gemini, Kimi, llama3.2) as black
  boxes with known capability levels. It does not run capability
  evaluations before integration; it relies on the upstream provider's
  refusal training and on the layered defenses above to contain
  misbehaviour.
- **Adversaries with physical access** to the deployment hardware.
- **Side-channels** (timing, power, EM) — not in scope.

## Validation

- Test surface: 969 pytest tests, ~79% line coverage on `core/` and
  `scripts/` (`pytest.ini` enforces 70% floor in CI).
- Concurrency tests for trust_score, audit_log, hierarchical_store,
  approval store atomicity.
- Fail-closed tests for every defense layer (gateway, soul guard,
  DIQ integrity, allowlist, ZEF, mode detection failure).
- `tests/test_diq/test_diq_tools.py::TestGatewayChokepoint` verifies
  direct-execute outside gateway is refused and subclasses overriding
  `execute()` fail at class definition.
- `tests/test_security/test_agent_identity.py` covers HMAC sign +
  verify, key acquisition order, A2A signing, constant-time compare.

What's NOT validated:

- No measured jailbreak resistance (no documented FPR/FNR on the
  ZEF filter against an adversarial corpus). See P1 in
  `docs/RISK_REGISTER.md`.
- No formal accuracy benchmark on Aeris responses to children
  (Article 15 EU AIA gap if commercialised).
- No bias / fairness evaluation. Out of scope for personal use;
  required if commercialised.

## Operational lifecycle

- **Boot:** `core/bootstrap.py` runs the canonical sequence. DIQ
  integrity check is a hard fail; soul integrity failure enters
  SAFE_MODE without aborting.
- **Steady state:** AUTONOMOUS or LOCKDOWN per William's choice.
  AUTONOMOUS auto-reverts to LOCKDOWN after `_timeout_hours` (default
  8 h). Night Mode kicks in 21:00–06:00 after 2 h of inactivity.
- **Daily:** `core/zeph/proactive_monitor.py` runs the
  `daily_health` schedule (disk, memory, failed services, log errors,
  DIQ integrity, soul integrity, trust scores, GO-Gate pending).
- **Weekly:** outdated packages, tripwire status (real check now —
  see `docs/RISK_REGISTER.md` for what changed), failed logins, ZEF
  block count, quarantine review backlog, shadow proposal backlog.
- **Monthly:** `core/zeph/self_diagnostic.py` produces a self-review.
- **Incident:** see `docs/INCIDENT_RESPONSE.md`.

## How to update this document

This file is **not** in `DIQ_CHECKSUMS.json`. Edit freely. The
rule of thumb: any change that adjusts the "Capability surface" or
"Security architecture" sections should be paired with the
corresponding code change in the same commit, and the version
header at the top should be bumped.

## Related documents

- `SECURITY.md` — vulnerability disclosure policy
- `docs/RISK_REGISTER.md` — risk → control → residual risk table
- `docs/INCIDENT_RESPONSE.md` — what to do when a tripwire / soul /
  trust event fires
- `README.md` — installer / quickstart
- `LICENSE` — Apache 2.0
