# Agent Control Specification (ACS) mapping

Super Tanks maps to the [Agent Control Specification (ACS)](https://commandline.microsoft.com/agent-control-specification-runtime-governance/)
— the Apache-2.0, community-governed open standard launched 27 May 2026 (Microsoft + Zenity)
for **deterministic, runtime allow/deny governance of AI agents**. Where OWASP ASI and MITRE
ATLAS describe *threats*, ACS describes *where you put controls*: it defines five enforcement
checkpoints across the agent lifecycle at which a policy engine can deterministically allow,
deny, or modify what an agent is about to do.

Super Tanks predates ACS, but its layered architecture lines up with the model: every Super
Tanks control sits at one of the five lifecycle checkpoints, and most checkpoints are covered
by more than one layer (defence-in-depth rather than a single chokepoint).

## The five ACS checkpoints

1. **Input** — controls applied to data entering the agent (user prompts, retrieved content,
   incoming agent-to-agent messages) before it reaches the model.
2. **LLM** — controls around the model invocation itself (what the model is allowed to be
   asked, jailbreak/guardrail enforcement, mode constraints on the call).
3. **State** — controls over the agent's persistent identity, memory, and context, preventing
   poisoning or drift of long-lived state.
4. **Tool execution** — controls at the point an agent invokes a tool/action: allow/deny,
   human approval, sandboxing, isolation.
5. **Output** — controls applied to what the agent returns or emits downstream (responses,
   onward messages, exfiltration paths).

## Checkpoint → Super Tanks enforcement

| ACS checkpoint | Super Tanks layer(s) / module(s) | Where it is enforced |
|---|---|---|
| **1. Input** | ZEF Firewall (1) — regex + secondary-LLM classifier; A2A signature verification on inbound messages | `core/security/zef_injection_filter.py`, `core/security/zef_llm_classifier.py`; inbound A2A `verify_or_drop` in `core/a2a/escalation_rules.py` (delegates to `verify_a2a_message` in `core/security/agent_identity.py`) |
| **2. LLM** | ZEF Firewall (1) as a pre-model filter; Circuit Breaker (7) modes (LOCKDOWN / Night) and trust score constraining when/whether the model is invoked | `core/security/zef_llm_classifier.py`; `core/security/super_tanks_mode.py`, `core/security/trust_score.py` |
| **3. State** | Soul Files (2) — SHA256-sealed identity, SAFE_MODE on mismatch; memory tripwires / RBAC store; DIQ frozen contracts (3) preventing tool-surface drift | `core/soul_guard.py` (SHA256 verify vs `soul_integrity.json`, sets `SOUL_SAFE_MODE`); `core/memory/tripwires.py`, `core/memory/secure_store.py`; `core/diq/` (e.g. `diq_tools.py`, `diq_integrity.py`) |
| **4. Tool execution** | Allowlists (4, default-deny) + GO-Gate (5, human-in-the-loop) + Sandbox (6, Docker + AST scan) + Circuit Breaker (7) + Tool Zone Isolation (8) + MCP Security Manager (9) + allowed_agents (10) | Dispatch gate `dispatch_tool` / `_dispatch_inner` in `core/gateway.py` calling `is_tool_allowed` (`core/security/tool_allowlists.py`, fails closed); GO-Gate daemon `core/go_gate_approval_daemon.py`; AST scanner `core/zeph_quarantine_ast.py`; skill-level isolation via `allowed_agents` in `core/diq/diq_skills.py` |
| **5. Output** | ZEF re-scan of tool outputs before they re-enter the agent; audit sanitiser on emitted records; A2A signing of outbound messages | `_scan_response_for_injection` in `core/gateway.py`; `core/security/audit_sanitizer.py`; outbound A2A HMAC signing in `core/security/agent_identity.py` |

## Where Super Tanks goes beyond ACS

ACS defines *where* deterministic controls run; it does not mandate the following, which Super
Tanks adds:

- **SHA256-sealed soul identity with fail-safe** — agent identity files are hashed at startup
  against sealed values; on mismatch the system enters `SAFE_MODE` rather than crashing
  (`core/soul_guard.py`). This is a tamper-evidence control over the agent's own definition.
- **HMAC agent identity + A2A signing** — every inter-agent message is HMAC-signed and verified
  on receipt; unsigned or tampered messages are dropped (`core/security/agent_identity.py`,
  `core/a2a/escalation_rules.py`). ACS treats inbound messages as input but does not specify
  cryptographic peer authentication between agents.
- **Tamper-evident, hash-chained audit** — each audit row carries an HMAC over
  `previous_row_hmac || row_bytes`, so history cannot be rewritten without the (mode-0600,
  never-serialised) key; `verify_chain` detects the first tampered row
  (`core/security/audit_chain.py`).
- **Correlation-tracked dispatch audit** — every tool dispatch gets a `correlation_id` propagated
  via a ContextVar for end-to-end traceability (`core/security/dispatch_audit.py`).

## Honest coverage notes

- **Checkpoint 2 (LLM) is partial.** Super Tanks constrains the model call indirectly — pre-model
  input filtering (ZEF) and mode/trust-based gating — rather than a dedicated, deterministic
  policy object wrapping the model invocation itself. There is no separate per-call LLM policy
  module; LLM-checkpoint enforcement is emergent from layers 1 and 7.
- **Checkpoint 5 (Output) is partial.** The strongest output control is the ZEF re-scan of tool
  outputs (defending indirect injection) plus audit sanitisation and A2A signing. Broad
  egress/DLP filtering of *final responses to humans* is lighter than the inbound and
  tool-execution paths.
- **MCP Security Manager (9) and Tool Zone Isolation (8)** are architectural controls referenced
  in the layer model and applied at the tool-execution checkpoint; their enforcement is
  distributed across the dispatch path and DIQ contracts rather than a single named file, so the
  table cites the dispatch gate and DIQ modules that realise them.

---

*ACS is an evolving, community-governed standard. Checkpoint definitions and conformance
expectations may change; this mapping reflects the spec as published at
[commandline.microsoft.com/agent-control-specification-runtime-governance](https://commandline.microsoft.com/agent-control-specification-runtime-governance/)
and the Super Tanks code at time of writing. Verify against the current spec and the codebase
before any formal audit or conformance claim.*
