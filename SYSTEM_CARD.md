# Super Tanks — System Card

**Version:** v3.3
**Last reviewed:** 2026-09-29
**Maintainer:** William (KNDW Shelter Solutions AS)

This document is the deployer-facing description of the assembled
Super Tanks system. It complements the API-level docstrings in `core/`
and is intended for: external researchers reviewing the security
posture, anyone deploying their own copy, and any conformity-assessment
exercise (NIST AI RMF, ISO/IEC 42001 Annex A.8, EU AI Act Annex IV).

It is deliberately short. Source-of-truth for any specific control is
the cited file and symbol in the codebase.

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
`core/security/tool_allowlists.py::AGENT_ALLOWLISTS`.

### What the agents cannot do

- Aeris cannot use `propose_code_change`, `file_write`, `code_edit`,
  `shell_exec`, `python_exec`, `memory_consolidate`, `memory_delete`,
  `memory_store`, `memory_store_hierarchical`, `image_generate`,
  `memory_tools`, or `task_done`. Asserted at module import:
  `core/security/aeris_security_directives.py::_assert_allowlist_consistent` raises
  RuntimeError if a future change leaks any forbidden tool into the
  Aeris allowlist.
- Neither agent can modify its own soul file
  (`core/aeris_soul.py`, `core/zeph_soul.py`) — change → SHA-256
  mismatch → SAFE_MODE.
- Neither agent can modify the DIQ frozen contracts
  (`core/diq/diq_*.py` except `diq_registry.py`) — change → DIQ
  integrity check refuses startup.
- Neither agent can dispatch a tool without a valid HMAC identity
  token (`core/security/agent_identity.py::verify_identity`).
- Neither agent can call `DIQTool.execute()` directly — it's gated
  by a ContextVar set only by `core.gateway.dispatch_tool`
  (`core/diq/diq_tools.py::DIQTool.execute`). Subclasses overriding `execute()`
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

## Security architecture (14 checks)

The README's "12 security layers" is the product view (one entry per
defensive mechanism, numbered L1–L12 below). The 14 checks are the same
controls as they actually run: checks 1–8 in the order
`core.gateway.dispatch_tool` executes them on every tool call, checks
9–14 at other points (boot, memory access, code proposals, LLM calls).
The full dispatch pipeline with outcomes per check is in
`docs/RUNTIME_PIPELINE.md`.

**No silent bypass.** Every gateway check fails closed: a check that
raises, or whose store is unavailable, produces a deny with an audit row
(`denied_subsystem`), never a pass. Two deliberate exceptions to "every
check applies to every caller", both documented and tested: the
reserved agent ids `system`, `internal` and `test` skip check 3 (the
per-agent allowlist is keyed by LLM agent and has no entry for them —
they still need a valid identity token and still pass checks 2 and
4–8); and an unregistered tool returns `None` (`no_wrapper`) so the
caller can fall back to its own non-DIQ handler, which is outside this
gateway's control.

### In the dispatch path (`core/gateway.py::_dispatch_inner`)

1. **Identity verification** — HMAC-SHA-256 token per agent, checked
   before the registry lookup so unauthenticated callers cannot probe
   the tool surface (`core/security/agent_identity.py::verify_identity`).
   Part of L3.
2. **DIQ role check** — `READ < CHAT < WRITE < EXEC < ADMIN`
   (`core/diq/diq_tools.py::DIQTool.validate_access`). L3.
3. **Per-agent tool allowlist** — unknown agent → deny
   (`core/security/tool_allowlists.py::is_tool_allowed`). L4.
4. **allowed_agents** — per-tool agent scope; `[]` means all
   (`DIQTool.allowed_agents`, `core/gateway.py::_check_allowed_agents`).
   L10.
5. **Tool zone + GO-Gate** — the tool's zone decides allow / GO-Gate /
   deny; unknown tools require GO-Gate. GO-Gate pauses the call
   (`pending_approval`, approval request id in the response metadata)
   until a human approves it in `ApprovalStore`; a human deny of the
   identical call stays a deny (`core/security/tool_zones.py`,
   `core/ask_admin.py::gate_tool_call`). L8 + L5.
6. **MCP server trust** — only for tools whose `mcp_server()` is set:
   verified → allow, provisional → GO-Gate, quarantined/unknown → deny
   (`core/security/mcp_security.py`). L9.
7. **Circuit breaker** — per-agent weighted rate limit, weight from the
   tool's zone; lockout persisted in SQLite
   (`core/security/circuit_breaker.py`). L7.
8. **Gateway chokepoint + output scan** — `DIQTool.execute()` refuses
   to run outside the gateway ContextVar (`core/diq/diq_tools.py::
   DIQTool.execute`; overriding `execute()` fails at class definition),
   and tool output is re-scanned by the ZEF filter before it is
   returned: high-confidence injection is redacted, WARN-level content
   is tagged `untrusted_content`, and output that cannot be scanned is
   withheld (`core/gateway.py::_scan_response_for_injection`). L3 + L1.

Every outcome of checks 1–8 is written to the HMAC-chained
`dispatch_log` with a per-dispatch `correlation_id`
(`core/security/dispatch_audit.py`).

### Outside the dispatch path

9. **ZEF prompt-injection filter on input** — regex (40+ patterns
   EN/NO, Unicode normalisation) + optional local LLM classifier
   (`core/security/zef_injection_filter.py`,
   `core/security/zef_llm_classifier.py`). Called by the agent loop on
   inbound messages; the agent loop is not part of this repository. L1.
10. **Memory RBAC + tripwires** — every memory op gates on
    `is_path_accessible` and `is_tripwire` (`core/memory/secure_store.py`,
    `core/memory/access_control.py`, `core/memory/tripwires.py`).
11. **Tamper-evident audit evidence** — dispatch, memory, threat,
    trust and approval rows are HMAC-chained
    (`core/security/audit_chain.py`) with a key separate from the
    identity key (`core/security/audit_key.py`); the threat monitor
    verifies all chains (P4–P7) and forces SAFE_MODE on a break.
12. **Mode controller + trust score** — LOCKDOWN by default,
    AUTONOMOUS times out to LOCKDOWN, Night Mode shrinks Zeph to
    observation-only (`core/security/super_tanks_mode.py`); five
    behavioural trust levels with decay and tripwire penalties
    (`core/security/trust_score.py`).
13. **Code quarantine** — static AST scan of agent-authored code
    proposals; sandbox-escape patterns are a hard fail with no override
    (`core/zeph_quarantine.py`, `core/zeph_quarantine_ast.py`). This is
    L6 "Sandbox": a static scan, not a runtime container.
14. **Integrity + provider controls** — soul files (L2) and DIQ frozen
    contracts (L3) are SHA-256 sealed with an anti-rollback generation
    floor (`core/soul_guard.py`, `core/diq/diq_integrity.py`,
    `core/security/integrity_floor.py`); LLM providers are tiered and
    prompts stripped per tier (L11, `core/security/provider_trust.py`);
    moving to a less-trusted provider needs GO-Gate (L12,
    `core/security/provider_failover.py`).

### Layer → check map

| Layer | Check(s) |
|---|---|
| L1 ZEF Firewall | 8 (output), 9 (input) |
| L2 Soul Files | 14 |
| L3 DIQ Layer | 1, 2, 8, 14 |
| L4 Allowlists | 3 |
| L5 GO-Gate | 5, 6 (provisional MCP), 14 (L12) |
| L6 Sandbox (static AST scan) | 13 |
| L7 Circuit Breaker | 7 |
| L8 Tool Zone Isolation | 5 |
| L9 MCP Security Manager | 6 |
| L10 allowed_agents | 4 |
| L11 Provider Trust Tier | 14 |
| L12 Provider Failover GO-Gate | 14 |

Checks 10–12 (memory RBAC, audit chain, mode/trust) are supporting
controls without their own README layer number.

`core/bootstrap.py::boot` runs the start-up checks in order (DIQ
integrity, soul integrity, mode, admin, tripwires, upstream tier,
threat intel, tool registration) at process start. The entry point (`main_loop.py`) lives
outside this open-source release and is responsible for calling
`boot()`.

## What this system does NOT defend against

- **Compromised host.** An attacker with shell as the deploying user
  can read `data/.identity_key`, modify SQLite databases, and rewrite
  source files. Anchor that trust in OS controls, not in Super Tanks.
- **Indirect prompt injection in tool outputs — partial.** Tool output
  is now re-scanned through the ZEF filter before reaching the agent
  (`gateway._scan_response_for_injection`, R-02): high-confidence
  injection is redacted, and lower-confidence ("WARN") content is kept
  but tagged with `untrusted_content` provenance so the agent treats it
  as data, not instructions. What remains undefended here: semantic or
  encoded payloads that no regex/normalisation pattern matches — those
  rely on the upstream model's refusal training and on the downstream
  allowlist / GO-Gate limits on what the agent can do with the content.
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
- **GO-Gate approval reuse.** An approval covers the identical call
  (same tool, agent and SHA-256 of the arguments) for one hour
  (`ApprovalStore.find_approved_request`), and a human deny blocks the
  identical call for one hour. Within that window a repeated identical
  call is not re-asked.
- **MCP servers themselves.** Layer 9 is a trust gate on dispatch. It
  does not scan, sign-check or sandbox an MCP server; trust levels are
  set by a human.
- **Adversaries with physical access** to the deployment hardware.
- **Side-channels** (timing, power, EM) — not in scope.

## Validation

- Test surface: 1,543 pytest tests (collected in CI; `pytest.ini` enforces a
  70% coverage floor on `core/` and `scripts/`).
- Concurrency tests for trust_score, audit_log, hierarchical_store,
  approval store atomicity.
- Fail-closed tests for every defense layer (gateway, soul guard,
  DIQ integrity, allowlist, ZEF, mode detection failure, and layers
  7–10: `tests/test_core/test_gateway_layers.py`).
- `tests/test_diq/test_diq_tools.py::TestGatewayChokepoint` verifies
  direct-execute outside gateway is refused and subclasses overriding
  `execute()` fail at class definition.
- `tests/test_security/test_agent_identity.py` covers HMAC sign +
  verify, key acquisition order, A2A signing, constant-time compare.

Measured:

- ZEF filter resistance against the adversarial corpus
  (`tests/security/redteam/corpus.py`, `scripts/zef_baseline.py`),
  as of 2026-06-07: block_rate 100% (57/57 attacks), false-positive
  rate 0% (0/28 clean cases, including Norwegian near-misses), warn
  surfacing 100% (3/3). These cover the regex/normalisation layer; the
  LLM-classifier path is evaluated separately when Ollama is present.

What's NOT validated:

- The corpus is high-signal, not exhaustive. The open follow-up (R-22
  in `docs/RISK_REGISTER.md`) is a larger adversarial fuzzing harness
  for the ZEF filter and the AST scanner that tracks FPR/FNR over a
  much wider input space.
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
