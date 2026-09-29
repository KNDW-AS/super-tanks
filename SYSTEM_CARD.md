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
  (`home_assistant`; the zone action applies per tool name, so every
  `home_assistant` and `yale` call pauses for GO-Gate, reads included —
  layer 8), task list, memory hierarchy reads, weather, web
  search/browse, file reads under allowed roots, calculator, agent-to-agent
  messaging, push notifications.
- **Zeph (EXEC, level 4):** everything Aeris can do plus shell and
  Python exec, code edits via the quarantine flow, file writes, memory
  hierarchy writes, image generation, hierarchical memory delete
  (ADMIN). There is no runtime sandbox for shell/Python exec in this
  repository; every such call pauses for GO-Gate (layer 8) and counts
  triple against the circuit breaker (layer 7).

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
  fail at class definition time. Limit: the guard covers `execute()`
  only. Python code running in the same process can still call a
  tool's `_execute_impl()` directly or set the ContextVar with
  `mark_gateway_active()`; the guard stops accidental and
  prompt-constructed bypasses, not deliberately written in-process code.

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
Three checks have no README layer number: memory RBAC + tripwires (10),
the audit chain (11) and the mode controller + trust score (12). The
dispatch pipeline with the outcome of each check is in
`docs/RUNTIME_PIPELINE.md`.

**No silent bypass — what that means exactly.** Every gateway check
fails closed: a check that raises, or whose store is unavailable,
produces a deny with an audit row (`denied_subsystem`), never a pass. An
exception from the tool itself is returned as `tool_error` with an audit
row, and a last-resort handler in `dispatch_tool` turns any other
exception into an audited `denied_subsystem`, so no exception escapes
`dispatch_tool`. Known exceptions to "every call is checked and
audited", all documented and tested:

- the reserved agent ids `system` and `internal` skip check 3 (the
  per-agent allowlist is keyed by LLM agent and has no entry for them).
  They still need a valid identity token and pass checks 2 and 4–8;
- an unregistered tool returns `None` (`no_wrapper`, audited) so the
  caller can fall back to its own non-DIQ handler, which is outside this
  gateway;
- the audit write itself is fail-open: if `record_dispatch` cannot write,
  it logs an error and the dispatch result is still returned. The chain
  verifier detects missing or altered rows afterwards.

**`agent_role` is asserted by the caller.** `dispatch_tool` does not
verify it. It is bound only by the identity token (who is calling) and
the allowlist (which tools that agent may call): an agent with a valid
token can claim ADMIN for any tool on its allowlist. The role check
(check 2) protects against honest mistakes, not against a caller that
lies about its role.

`dispatch_tool` does **not** consult the mode controller or the trust
score (check 12). Those are used by memory access control, code
quarantine and the agent loop (the loop is not in this repository).

### In the dispatch path (`core/gateway.py::_dispatch_inner`)

1. **Identity verification** — HMAC-SHA-256 token per agent, checked
   before the registry lookup so unauthenticated callers cannot probe
   the tool surface (`core/security/agent_identity.py::verify_identity`).
   L3.
2. **DIQ role check** — `READ < CHAT < WRITE < EXEC < ADMIN`
   (`core/diq/diq_tools.py::DIQTool.validate_access`). Caller-asserted
   role, see above. L3.
3. **Per-agent tool allowlist** — unknown agent → deny
   (`core/security/tool_allowlists.py::is_tool_allowed`). L4.
4. **allowed_agents** — per-tool agent scope; `[]` means all
   (`DIQTool.allowed_agents`, `core/gateway.py::_check_allowed_agents`).
   L10. The skill contract declares the same rule
   (`DIQSkill.allowed_agents`), but skills do not pass through the
   gateway and this repository has no skill dispatch path, so it is not
   enforced for skills.
5. **Circuit breaker** — per-agent weighted rate limit, weight from the
   tool's zone; lockout persisted in SQLite
   (`core/security/circuit_breaker.py`). Checked twice: a pre-check
   before GO-Gate that records nothing (a locked-out agent cannot open
   approval requests), and check-and-record as the last step before
   execute (only executed calls consume budget). Keyed by `agent_id`:
   all in-process callers dispatching as `system` share one budget. L7.
6. **Tool zone + GO-Gate** — the tool's zone decides allow / GO-Gate /
   deny; unknown tools require GO-Gate. GO-Gate returns
   `pending_approval` with the approval request id; the call is not
   resumed automatically — after a human approves in `ApprovalStore`,
   the caller re-issues the identical call (within 1 h). Approvals are
   single-use: consumed atomically right before the call executes, so
   one approval = one execution. A human deny of the identical call
   stays a deny for 1 h
   (`core/security/tool_zones.py`, `core/ask_admin.py::gate_tool_call`).
   L8 + L5.
7. **MCP server trust** — only for tools whose `mcp_server()` is set:
   verified → allow, provisional → GO-Gate, quarantined/unknown → deny
   (`core/security/mcp_security.py`). One approval covers both the zone
   gate and the provisional-MCP gate in the same dispatch and is
   consumed once (same tool + agent + argument
   key). L9.
8. **Gateway chokepoint + output scan** — `DIQTool.execute()` refuses
   to run outside the gateway ContextVar (limits above), and tool output
   is re-scanned by the ZEF regex filter before it is returned:
   high-confidence injection is redacted, WARN-level content is tagged
   `untrusted_content`, and output that cannot be scanned is withheld
   (`core/gateway.py::_scan_response_for_injection`). L3 + L1.

Every outcome of checks 1–8 is written to the HMAC-chained
`dispatch_log` with a per-dispatch `correlation_id`
(`core/security/dispatch_audit.py`), subject to the fail-open audit
write noted above.

### Outside the dispatch path

9. **ZEF prompt-injection filter on input** — regex (40+ patterns
   EN/NO, Unicode normalisation) + optional local LLM classifier
   (`core/security/zef_injection_filter.py`,
   `core/security/zef_llm_classifier.py`). Called by the agent loop on
   inbound messages; the agent loop is not part of this repository. L1.
10. **Memory RBAC + tripwires** — every memory op gates on
    `is_path_accessible` and `is_tripwire` (`core/memory/secure_store.py`,
    `core/memory/access_control.py`, `core/memory/tripwires.py`). No
    layer number.
11. **Tamper-evident audit evidence** — dispatch, memory, threat,
    trust and approval rows are HMAC-chained
    (`core/security/audit_chain.py`) with a key separate from the
    identity key (`core/security/audit_key.py`); the threat monitor
    verifies all chains (P4–P7) and forces SAFE_MODE on a break. No
    layer number.
12. **Mode controller + trust score** — LOCKDOWN by default,
    AUTONOMOUS times out to LOCKDOWN, Night Mode shrinks Zeph to
    observation-only (`core/security/super_tanks_mode.py`); five
    behavioural trust levels with decay and tripwire penalties
    (`core/security/trust_score.py`). Not consulted by `dispatch_tool`.
    No layer number.
13. **Code quarantine** — static AST scan of agent-authored code
    proposals; sandbox-escape patterns are a hard fail with no override
    (`core/zeph_quarantine.py`, `core/zeph_quarantine_ast.py`). This is
    L6 "Sandbox": a static scan, not a runtime container.
14. **Integrity + provider controls** — soul files (L2) and DIQ frozen
    contracts (L3) are SHA-256 sealed with an anti-rollback generation
    floor (`core/soul_guard.py`, `core/diq/diq_integrity.py`,
    `core/security/integrity_floor.py`); LLM providers are tiered and
    prompts regex-stripped per tier (L11, `core/security/provider_trust.py`);
    moving to a less-trusted provider needs GO-Gate and is refused (not
    queued) when denied (L12, `core/security/provider_failover.py`).

### Layer → check map

| Layer | Check(s) |
|---|---|
| L1 ZEF Firewall | 8 (output), 9 (input) |
| L2 Soul Files | 14 |
| L3 DIQ Layer | 1, 2, 8, 14 |
| L4 Allowlists | 3 |
| L5 GO-Gate | 6, 7 (provisional MCP), 14 (L12) |
| L6 Sandbox (static AST scan) | 13 |
| L7 Circuit Breaker | 5 |
| L8 Tool Zone Isolation | 6 |
| L9 MCP Security Manager | 7 |
| L10 allowed_agents | 4 |
| L11 Provider Trust Tier | 14 |
| L12 Provider Failover GO-Gate | 14 |
| no layer number | 10, 11, 12 |

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
- **GO-Gate approval scope.** An approval is bound to the identical call
  (same tool, agent and SHA-256 of the arguments) and is single-use: it
  lets that call execute once, within one hour, and is consumed
  atomically (`ApprovalStore.consume_approval`). A human deny blocks the
  identical call for one hour. The approval does not bind the asserted
  `agent_role` or the conversation.
- **MCP servers themselves.** Layer 9 is a trust gate on dispatch. It
  does not scan, sign-check or sandbox an MCP server; trust levels are
  set by a human.
- **Adversaries with physical access** to the deployment hardware.
- **Side-channels** (timing, power, EM) — not in scope.

## Validation

- Test surface: 1,604 tests collected by pytest (2 skipped without agentdojo / a live Ollama server). The 70% coverage floor on `core/`
  and `scripts/` is enforced by the `pytest` job in
  `.github/workflows/tests.yml` (`--cov-fail-under=70`), not by
  `pytest.ini`; the cross-platform `quickstart` jobs run with `--no-cov`.
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
