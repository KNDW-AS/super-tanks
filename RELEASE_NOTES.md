# Unreleased (v3.3) — evidence-integrity hardening

Hardening pass driven by the published 7ASecurity STA-01 threat model
(Threats 05 and 06). 1,436 tests green.

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
