# Super Tanks v3.3.0

Three groups of changes since v3.2.0. Test suite: 1,576 tests.

## Gateway layers 7–10 now enforce

Previously documented but not present in this repository.

- New modules `core/security/circuit_breaker.py`, `core/security/tool_zones.py`,
  `core/security/mcp_security.py`, wired into `core.gateway.dispatch_tool`.
  Order after the allowlist: allowed_agents (10) → circuit-breaker
  pre-check (7, records nothing) → tool zone + GO-Gate (8, 5) → MCP server
  trust (9) → circuit-breaker record (7) → execute → output scan. See
  `docs/RUNTIME_PIPELINE.md`.
- Every check fails closed (`denied_subsystem`). Exceptions from a tool's
  `validate_access` or `execute`, or from anywhere else in the pipeline,
  are caught and audited (`denied_subsystem` / `tool_error`) instead of
  escaping `dispatch_tool`.
- New audit verdicts: `denied_agent`, `denied_zone`, `pending_approval`,
  `denied_mcp`, `denied_circuit_breaker`, `tool_error`.
- GO-Gate is part of the gateway via `core.ask_admin.gate_tool_call`. A
  paused call returns `pending_approval` with `approval_request_id`; it is
  not resumed automatically — re-issue the identical call after approval
  (an approval covers that call for 1 h; a human deny blocks it for 1 h).
- `DIQTool` contract v1.2: optional `allowed_agents()` (default `[]` = all)
  and `mcp_server()` (default `None`). Existing tools work unchanged.
  **Re-seal after upgrading:** `python -m supertanks seal`.
- SQLite work in the gateway runs in a worker thread
  (`asyncio.to_thread`), so a busy database no longer blocks the event loop.
- `ApprovalStore()` now defaults to `<repo>/data/approval_requests.db`
  (was relative to the working directory); override with
  `SUPER_TANKS_APPROVAL_DB`.

**Behaviour changes for existing users**

- Tools not in the zone map are `UNCATEGORIZED` and pause for GO-Gate on
  every call. Map your tools with `tool_zones.set_tool_zone(...)`.
- These tools now pause for GO-Gate: `home_assistant`, `yale`
  (physical actuation); `file_write`, `memory_store`,
  `memory_store_hierarchical`, `memory_tools`, `memory_consolidate`,
  `shadow_store_propose`; `image_generate`; `shell_exec`, `python_exec`,
  `code_edit`; `memory_delete`, `propose_code_change`.
- The agent id `test` is no longer exempt from the per-agent allowlist.
  Only `system` and `internal` are.
- A per-agent circuit breaker applies to every agent, including `system`
  and `internal`: 30 weighted units per 60 s (weight 1 for read/task/comms
  tools … up to 5 for an unmapped tool), 300 s lockout. Benchmarks should
  raise `CircuitBreaker.DEFAULT_MAX_ACTIONS`.
- The tool-output injection scan fails closed: if the ZEF filter cannot
  run or returns something unexpected, the output is withheld.

## Provider layers 11–12

- **Provider Trust Tier** (`core/security/provider_trust.py`,
  `config/providers.yaml`): every LLM provider is LOCAL / TRUSTED / MIXED /
  OPEN (unknown → OPEN). Prompts and system prompts are regex-stripped for
  the target tier before they leave the process: labelled secrets, Bearer
  tokens, JWTs and known key formats (`sk-`/`sk-ant-`, `ghp_`/`gho_`/
  `github_pat_`, `xox?-`, `AKIA`/`ASIA`, `AIza`) from tier 2; PII patterns
  and configured `pii_terms` from tier 3; paths and device ids at tier 4.
  Secrets in other, unlabelled formats are not recognised. Every provider
  call is audited with metadata only.
- **Provider Failover GO-Gate** (`core/security/provider_failover.py`):
  moving an agent to a less-trusted provider requires a GO-Gate approval
  through the shared `ApprovalStore`. If denied or timed out, the message
  is not sent to that provider and the caller gets an error
  (`FailoverResult.queued=True`); there is no queue or retry in this
  repository. Wired into the Council (`Voice.fallback`,
  `Council.ask(max_tier=…)`).

## Evidence-integrity hardening (7ASecurity STA-01, Threats 05 and 06)

- **Dedicated audit-chain key** (`core/security/audit_key.py`,
  `data/.audit_chain_key` / `SUPER_TANKS_AUDIT_KEY`): chain HMACs no
  longer share key material with identity tokens — one stolen key can
  no longer both forge agent identity and rewrite evidence.
  **Existing deployments must run `scripts/rotate_audit_chain_key.py`
  once after upgrading**, otherwise the threat monitor flags
  pre-upgrade rows as tampered and forces SAFE_MODE.
- **Chained trust + approval evidence**: `trust_events` rows and a new
  append-only `approval_events` transition log (created / approved /
  denied / expired) are HMAC-chained like dispatch/memory/threat rows.
  An approval status flip commits atomically with its evidence row.
  Threat monitor gains P6/P7 chain checks → SAFE_MODE on a break.
- **Anti-rollback for integrity manifests**: `soul_integrity.json` and
  `DIQ_CHECKSUMS.json` now carry `meta.generation` (+ seal timestamp
  and git commit); boot compares against a monotonic deployment floor
  (`data/.integrity_floor.json`). Restoring an older-but-valid sealed
  state fails integrity. New sealing tool: `scripts/seal_souls.py`;
  `diq_integrity.write_checksums()` bumps the generation. Legacy
  flat manifests still verify (warning only) until re-sealed.
- Docs synchronized with implemented controls (RISK_REGISTER residuals
  for R-02/05/06/12/14/20/21, SECURITY.md known limitations,
  SYSTEM_CARD v3.3).

# Super Tanks v3.2.0 — first public release

A compliance-by-design governance framework for autonomous AI agents. Instead of
detecting bad behavior after the fact, Super Tanks mediates **every** action an
agent takes through **10 simultaneous enforcement layers** before it reaches a
tool, a model, or the outside world.

Apache 2.0 · local-first (Ollama) · works fully offline · 1,398 tests.

## Highlights

- **10 enforcement layers** running at once — ZEF prompt-injection firewall,
  SHA256-sealed Soul Files (tamper-evident identity), frozen declarative tool
  contracts (DIQ), default-deny allowlists, human-in-the-loop GO-Gate approvals,
  Docker sandboxing, per-agent circuit breakers, tool-zone isolation, MCP trust
  enforcement, and skill-level `allowed_agents` isolation.
- **Full OWASP Top 10 for Agentic Applications (ASI 2026) mapping** — every
  category mapped to the concrete layers that address it (see README).
- **EU AI Act posture** — identity/access/audit controls, human oversight, full
  logging and traceability, mapped to Articles 12–15 ahead of the Act's phased
  obligations (most high-risk duties now deferred to ~December 2027 under the
  Digital Omnibus; Art. 13 from August 2026). Not legal advice — see the README.
- **Published System Card + threat model** — every decision auditable.
- **5-level user access** and **Dual Mode** (LOCKDOWN / time-boxed AUTONOMOUS).

## Designed to prevent — real 2026 incident classes

Mapped against documented agentic-AI incidents: MCP SDK command execution,
context/memory poisoning, credential breaches via LiteLLM, ~200,000 exposed
unauthenticated MCP instances, and poisoned MCP registries. See the README
incident table for the specific layer that addresses each.

## Install

```bash
git clone https://github.com/kndw-as/super-tanks.git
cd super-tanks
less install.sh        # review the script before running it
./install.sh
```

Requires Docker and (for local inference) Ollama. See the README for platform
notes. The dashboard and GO-Gate approvals are reachable from any browser or via
Telegram, so you can approve agent actions from your phone.

## Security

Report vulnerabilities via the repository **Security** tab or **security@aeris.no**
(see [SECURITY.md](SECURITY.md)). PGP fingerprint published per the security policy.

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

Built by [KNDW Shelter Solutions AS](https://kndw.no) (Norway), with R&D
supported by Innovation Norway.
