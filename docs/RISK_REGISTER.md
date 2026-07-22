# Super Tanks — Risk Register

This is the EU AI Act Article 9 / NIST AI RMF MAP-MEASURE-MANAGE
artefact for Super Tanks. One row per identified risk. Each row maps
risk → mitigating control(s) → residual risk after the control runs.

The list is exhaustive for **what's actually instrumented in this
codebase**. Risks rated *high residual* are open follow-ups —
prioritised list at the bottom.

Severity scale: **Critical** (security boundary breach), **High**
(privilege escalation / data exfil), **Medium** (incorrect behaviour
without escalation), **Low** (degraded service, no security impact).

| ID | Risk | Severity | Likelihood | Mitigating control(s) | Residual |
|---|---|---|---|---|---|
| **R-01** | An agent (Aeris or Zeph) executes attacker-supplied instructions hidden in user input | Critical | High | ZEF regex filter (`core/security/zef_injection_filter.py:102-225`); LLM secondary classifier on webhook/ha_voice/a2a (`core/security/zef_llm_classifier.py:97-152`); per-agent tool allowlist (`core/security/tool_allowlists.py`); HMAC identity gate (`core/gateway.py:66-76`) | **Medium** — regex+LLM may miss novel encodings; LLM fails open if Ollama is down |
| **R-02** | Indirect prompt injection via memory/web/file content re-fed to LLM | Critical | Medium | ZEF runs at message ingress; tool outputs are now re-scanned at the gateway — `core/gateway.py:_scan_response_for_injection` (217, 243-303): BLOCK-verdict output is redacted before reaching the agent, WARN-verdict output is forwarded but tagged `untrusted_content`/`provenance=external_tool_output` so the agent loop treats it as data, not instructions; tripwires detect read attempts on honeypot paths | **Medium** — re-scan relies on the ZEF regex/heuristic `scan_message`, so novel encodings can still pass; there is no full dataflow taint-tracking from source → LLM re-injection. Remaining gap, smaller surface. |
| **R-03** | Aeris escalates to Zeph's tool surface by spoofing agent_id | Critical | Low | HMAC identity verification (`core/security/agent_identity.py`); allowlist hard-fail on unknown agent (`core/security/tool_allowlists.py:136-141`); gateway chokepoint enforced via ContextVar (`core/diq/diq_tools.py:96-117`) | **Low** |
| **R-04** | Compromised agent self-modifies code via `propose_code_change` | Critical | Medium | Aeris allowlist excludes `propose_code_change` (asserted at import); Zeph's proposals enter quarantine; AST scanner hard-fails on `subprocess`/`exec`/`eval`/`importlib`/`getattr` obfuscation/dunder probes/sleeper actions (`core/zeph_quarantine_ast.py:35-242`); `super_tanks_mode.MODE_CONFIG[LOCKDOWN].quarantine_auto_approve = False` | **Low** in LOCKDOWN; **Medium** in AUTONOMOUS where PASS proposals auto-merge |
| **R-05** | Compromised agent modifies its own soul file or DIQ contract (incl. rollback to an older sealed state) | Critical | Low | SHA-256 sealed at boot; mismatch → SAFE_MODE (`core/soul_guard.py:65-148`); DIQ integrity refuses startup on missing manifest (`core/diq/diq_integrity.py`); daily re-check via `core/zeph/proactive_monitor.py:_check_soul_integrity`; anti-rollback: manifests carry `meta.generation`, checked against the deployment floor (`core/security/integrity_floor.py`) — an older-but-valid restored manifest fails the check | **Medium** — manifests stored alongside protected files; an attacker with write access to `core/` updates both atomically. Open follow-up: manifests signed with an offline key. |
| **R-06** | Attacker forges A2A messages claiming `sender="william"` to escalate via inter-agent channel | High | Low | `sign_a2a_message` / `verify_a2a_message` (`core/security/agent_identity.py`); `core/a2a/escalation_rules.py:verify_or_drop` (27-52) runs every incoming message through `verify_a2a_message` and drops bad/missing-signature messages (loud log, silent to caller); the gate is enforced at the registration boundary by `_VerifyingA2AChannel` in `core/diq/diq_registry.py:80-106`, which wraps every channel's `receive`/`receive_all`; A2A in HIGH_RISK_CHANNELS for ZEF | **Low** — verification now wired into the in-tree receive path; sender-side signing happens at the `sign_a2a_message` callsite. |
| **R-07** | Tool execution bypasses gateway checks via direct `tool.execute()` call | High | Low | `DIQTool.execute()` is concrete + final; refuses dispatches outside the `_gateway_active` ContextVar; `__init_subclass__` rejects subclasses overriding `execute()` at class-definition time (`core/diq/diq_tools.py:38-117`) | **Low** |
| **R-08** | An agent mass-reads or writes memory paths it shouldn't | High | Medium | `SecureMemoryStore` enforces tripwire + RBAC + audit on every op (`core/memory/secure_store.py`); `is_path_accessible` denies unknown paths fail-closed (`core/memory/access_control.py`); tripwire honeypots at 5 paths trigger −100 trust + forced LOCKDOWN | **Low** for code that uses SecureMemoryStore; **Medium** for any caller that imports raw `HierarchicalMemoryStore`. Open follow-up: deprecate raw-store imports across `core/`. |
| **R-09** | Memory poisoning — agent writes attacker-supplied "facts" that it later treats as ground truth | High | Medium | `shadow_store.propose` queues every write for human review; auto-approve restricted to the agent's own private namespace (`/aeris/...` / `/zeph/...`) at confidence ≥ 0.8 after 24 h; sensitive paths force manual review | **Medium** — the 24 h auto-approve window in agent-private namespace remains a small surface |
| **R-10** | Approval forgery / replay (attacker reuses a previously-granted approval) | High | Low | Single-use `request_id` (full UUID-128, no truncation); 5-min TTL; `INSERT OR REPLACE` with `BEGIN IMMEDIATE` for atomicity; full SHA-256 args hash (no longer truncated to 64 bits); SQLITE_BUSY surfaces as DENY (`core/ask_admin.py`) | **Low** |
| **R-11** | Brute-force or guess of 4-digit PIN | High | Medium | scrypt KDF (N=2^14) with per-user salt; transparent migration from legacy SHA-256; rate limit 5 failures / 15 min, including unknown-user attempts (`core/security/user_manager.py:154-256`) | **Low** |
| **R-12** | Audit log tampered to hide an action | High | Medium | Per-row chained HMAC `HMAC(key, prev_row_hmac \|\| row_canonical_bytes)` via `core/security/audit_chain.py` on all five evidence tables — `dispatch_log`, `memory_access_log`, `threats`, `trust_events`, `approval_events` — under a dedicated audit key (`core/security/audit_key.py`, deliberately separate from the identity key so one key compromise can't both forge identity and rewrite evidence); signed chain-head checkpoints (`write_checkpoint`/`verify_checkpoint`) detect tail truncation the per-row chain can't; threat monitor P4–P7 verifies the chains and forces SAFE_MODE on a break | **Low** — rewriting history requires the mode-0600 audit key (never serialised through SQLite); an attacker holding host-user access is out of scope (threat class 3) |
| **R-13** | Aeris controls smart home in unintended way (wrong entity, wrong service) | Medium | Medium | `home_assistant` requires WRITE role; gated by allowlist; per-user `permitted_entities` filter | **Medium** — rests on the LLM choosing the right entity; no schema validation of HA service args at this layer |
| **R-14** | Trust score gamed by repeated `successful_task` events from a compromised agent | Medium | Low | `record_event` / `set_score` require an open `_TrustAuthority` context — only internal security subsystems (proactive monitor, GO-Gate flow, tripwire reaction, threat monitor) open it; agent-reachable code paths get `PermissionError`. Events atomically applied with score-clamp `[0,100]`; daily decay −0.5; tripwire = −100 instant probation; trust_events HMAC-chained (R-12) | **Low** |
| **R-15** | A long-running tool call ignores LOCKDOWN flip during its execution | Medium | Low | Mode state under `_state_lock` (`core/security/super_tanks_mode.py`); LOCKDOWN affects new dispatches | **Medium** — there's no kill-switch for in-flight calls; documented limitation |
| **R-16** | Token-budget exhaustion DoS by adversarial input that triggers many LLM calls | Medium | Medium | Per-task limit + per-day limit per agent; soft warning at 80%, hard cutoff at 100% (`core/security/token_budget.py`); UTC date bucketing (no tz-induced rollover) | **Low** |
| **R-17** | Stolen `session_id` used after admin's intent expired | Medium | Low | Sessions get a 24 h TTL by default; `validate_session` checks expiry on every call and deletes expired rows; `revoke_session` for explicit logout; user delete cascades | **Low** |
| **R-18** | Ollama unreachable → ZEF LLM classifier fails open → reduced injection coverage | Medium | High | Primary regex filter still runs; logged at WARNING (`core/security/zef_llm_classifier.py:147-152`) | **Medium** — design choice (fail-open keeps system usable when local LLM crashes); revisit when fail-closed is acceptable |
| **R-19** | Path-traversal via crafted memory path | High | Low | `_resolve_path` uses `Path.relative_to` after `.resolve()` (rejects sibling-dir-prefix attacks); 3 places fixed (`core/memory/hierarchical_store.py`, `access_control.py`, `shadow_store.py`) | **Low** |
| **R-20** | A2A message with forged sender field reaches the recipient | High | Medium | `A2AMessage.signature` field with HMAC; `verify_a2a_message` invoked on every receive via `escalation_rules.verify_or_drop`, enforced at the channel registration boundary (`_VerifyingA2AChannel`, `core/diq/diq_registry.py:80-106`); see R-06 | **Low** — forged/unsigned messages are dropped before reaching the agent runtime |
| **R-21** | Tool dispatch happens but no record exists tying it to a session / approval / trust event | Medium | High | `core/security/dispatch_audit.py` records every dispatch (allowed + each denied verdict: identity/role/allowlist/subsystem/no_wrapper) to `data/dispatch_audit.db` (WAL, indexed, chained-HMAC); `core/gateway.py:dispatch_tool` (82-95) mints a fresh `correlation_id` and publishes it via the `current_correlation_id` ContextVar for the dispatch's duration, calling `record_dispatch` at every verdict branch; `core/memory/audit_log.py:log_access` (129-146) reads that ContextVar so memory rows carry the same `correlation_id` (also a stored column) — `grep <id>` reconstructs one incident across DBs | **Low** — every dispatch is now persisted and correlatable; correlation propagation into trust_events / approval_requests rows is the ContextVar mechanism's intended next consumer |
| **R-22** | Sandbox-escape pattern not yet in the AST scanner's catalogue | Critical | Low | AST visitor catches imports + attribute access + getattr-obfuscation + dunder probes + alias rebinding + concat-string trick (`core/zeph_quarantine_ast.py:35-242`); 24 tests cover known bypasses | **Medium** — no fuzzing harness; novel obfuscation is an unknown-unknown |
| **R-23** | New tool added to allowlist accidentally undoes a forbidden-set assertion | High | Medium | `core/security/aeris_security_directives.py:78-94` raises RuntimeError at import if `AERIS_FORBIDDEN_TOOLS` ∩ `AGENT_ALLOWLISTS["aeris"]` is non-empty | **Low** |
| **R-24** | Configuration drift — `super_tanks_state.json` modified outside the system | Medium | Low | `load_mode_from_state` defaults to LOCKDOWN on parse error; expired-during-downtime AUTONOMOUS reverts to LOCKDOWN | **Low** |
| **R-25** | Schedule fires at wrong wall-clock time due to tz drift | Low | Medium | `core/zeph/proactive_monitor.py` uses `SUPER_TANKS_TZ` env var (default UTC); production deploys can set `Europe/Oslo` to fix wall-clock semantics | **Low** |

## Open follow-ups (high residual risk)

Ranked by severity × likelihood × ease-of-fix.

| Rank | ID | Title | Estimate |
|:---:|---|---|:---:|
| 1 | R-04 | Runtime sandbox (nsjail/firejail/docker-uid) wrapping approved code execution AND the pip dependency-upgrade path (`core/security/dep_upgrade_apply.py`); AST is preventative-only today | Large |
| 2 | R-22 | Adversarial fuzzing harness for AST scanner + ZEF filter; track FPR/FNR — novel obfuscation is still an unknown-unknown | Medium |
| 3 | R-05 | Sign integrity manifests (`soul_integrity.json`, `DIQ_CHECKSUMS.json`) with offline / TPM key — the generation floor now catches rollback, not co-located forgery | Large |
| 4 | R-02 | Expand the adversarial corpus (encodings, HTML/Markdown tricks, staged payloads, tool-output transformation chains); longer term, dataflow taint-tracking from external source → LLM re-injection | Medium / Large |
| 5 | R-08 | Audit + deprecate every direct caller of `HierarchicalMemoryStore`; route through `SecureMemoryStore` | Medium |
| 6 | R-15 | Cooperative cancellation of in-flight tool calls when LOCKDOWN engages | Large |

### Closed since the 2026-05-14 review — verified against current code

- **R-12** — per-row chained HMAC on all five evidence tables plus
  signed chain-head checkpoints against tail truncation
  (`core/security/audit_chain.py`), under a dedicated audit key
  separated from the identity key (`core/security/audit_key.py`).
  Existing deployments: run `scripts/rotate_audit_chain_key.py` once
  after upgrading. Residual High → Low.
- **R-21** — gateway dispatch audit with cross-DB `correlation_id`
  (`core/security/dispatch_audit.py` + ContextVar propagation).
  Residual High → Low.
- **R-06 / R-20** — A2A signature verify wired at the channel
  registration boundary (`_VerifyingA2AChannel`). Residual High → Low.
- **R-02 (partial)** — gateway re-scan of tool outputs with
  `untrusted_content` provenance tagging. Residual High → Medium;
  narrower follow-up remains above.
- **R-14** — trust mutations gated behind `_TrustAuthority`;
  `trust_events` rows chained. Residual Medium → Low.
- **R-05 (partial)** — anti-rollback generation floor for both
  integrity manifests (`core/security/integrity_floor.py`,
  `scripts/seal_souls.py`); offline signing remains above.

## How to use this register

- **Reviewing a PR:** check whether the change touches a control. If it
  weakens or removes a control, the corresponding row's residual risk
  needs to be re-assessed in the PR description.
- **After a tripwire fires:** identify which row(s) anticipate that
  failure mode. If the event isn't anticipated, add a new row.
- **Quarterly:** re-rank the open follow-ups; bump anything overdue.

Last reviewed: 2026-07-22.
