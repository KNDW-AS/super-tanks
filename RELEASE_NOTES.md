# Super Tanks v3.2.0 — first public release

A compliance-by-design governance framework for autonomous AI agents. Instead of
detecting bad behavior after the fact, Super Tanks mediates **every** action an
agent takes through **10 simultaneous enforcement layers** before it reaches a
tool, a model, or the outside world.

Apache 2.0 · local-first (Ollama) · works fully offline · 1,378 tests.

## Highlights

- **10 enforcement layers** running at once — ZEF prompt-injection firewall,
  SHA256-sealed Soul Files (tamper-evident identity), frozen declarative tool
  contracts (DIQ), default-deny allowlists, human-in-the-loop GO-Gate approvals,
  Docker sandboxing, per-agent circuit breakers, tool-zone isolation, MCP trust
  enforcement, and skill-level `allowed_agents` isolation.
- **Full OWASP Top 10 for Agentic Applications (ASI 2026) mapping** — every
  category mapped to the concrete layers that address it (see README).
- **EU AI Act posture** — identity/access/audit controls, human oversight, full
  logging and traceability, mapped to Articles 12–15 ahead of the August 2, 2026
  deadline.
- **Published System Card + threat model** — every decision auditable.
- **5-level user access** and **Dual Mode** (LOCKDOWN / time-boxed AUTONOMOUS).

## Designed to prevent — real 2026 incident classes

Mapped against documented agentic-AI incidents: MCP SDK command execution,
context/memory poisoning, credential breaches via LiteLLM, ~200,000 exposed
unauthenticated MCP instances, and poisoned MCP registries. See the README
incident table for the specific layer that addresses each.

## Install

```bash
git clone https://github.com/billyxp74/super-tanks.git
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
