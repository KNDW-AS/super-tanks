# Super Tanks v3.2

**The governance layer that makes AI autonomy possible.**

Not a detection tool that reacts after something goes wrong. 12 simultaneous security layers that prevent it from happening in the first place.

```bash
curl -sSL https://aeris.no/install.sh | bash
```

## What is Super Tanks?

Super Tanks is a security and governance framework for AI home assistants. It controls what AI agents can and cannot do, giving you full control over your AI system.

- **10 security layers** running simultaneously
- **5-level user access** — you decide who can do what
- **Works offline** — local AI via Ollama, no cloud required
- **Smart home ready** — Home Assistant integration
- **Open source** — Apache 2.0

## The 12 Security Layers

| # | Layer | What it does |
|---|-------|-------------|
| 1 | **ZEF Firewall** | Blocks prompt injection attacks (30+ patterns, EN/NO) + MCP tool-call filtering |
| 2 | **Soul Files** | Agent identities are sealed and tamper-proof (SHA256) |
| 3 | **DIQ Contracts** | Frozen interface contracts — agents can't modify their own tools |
| 4 | **Allowlists** | Per-agent tool permissions — explicit allow, default deny |
| 5 | **GO-Gate** | Risky actions require human approval via Telegram |
| 6 | **Quarantine** | Code proposals scanned for sandbox escapes (28 patterns) |
| 7 | **Memory RBAC** | Role-based access control on agent memory |
| 8 | **Tripwires** | Honeypot files that trigger instant lockdown |
| 9 | **Trust Score** | Behavioral reputation — good behavior earns autonomy |
| 10 | **Token Budget** | Per-agent daily spending limits |
| 11 | **Provider Trust Tier** | Data filtering per LLM provider — local/trusted/mixed/open |
| 12 | **Soul Split** | Tier-based prompt separation — identity vs capabilities |

## Install

### Linux / macOS
```bash
curl -sSL https://aeris.no/install.sh | bash
```

### Windows
Download `install.exe` from [Releases](https://github.com/billyxp74/super-tanks/releases) and double-click.

### What happens
1. Docker is installed (if needed)
2. Ollama is installed (local AI engine)
3. Super Tanks containers start
4. Setup wizard opens at `http://localhost:8765/setup`
5. Answer a few questions — your AI home is ready

## User Access Levels

| Level | Name | Access |
|-------|------|--------|
| 5 | Full | Everything — system admin |
| 4 | Near-full | Like 5, but can't delete system or last admin |
| 3 | Configured | Chat + smart home + status panels |
| 2 | Standard | Chat + permitted smart home devices |
| 1 | Limited | One agent only, content filter + curfew apply |

Per-user settings (independent of level): curfew, emergency override, content filter, permitted devices, alert preferences.

## Dual Mode

**LOCKDOWN** — All write/exec operations require human approval.
**AUTONOMOUS** — Agents act independently. Timed (auto-returns to lockdown). Night mode reduces autonomy after 21:00.

## Philosophy

Super Tanks has no opinion about who lives in your home. Not how many people. Not their ages. Not their relationships. You assign access levels. You set filters. You decide who can do what. Super Tanks enforces whatever you decide — nothing more, nothing less.

## Tech Stack

- **Python 3.12** — core framework
- **SQLite** (WAL mode) — all databases
- **Ollama** — local LLM inference (llama3.2:3b, nomic-embed-text)
- **Docker** — containerized deployment
- **Telegram Bot API** — notifications and approvals

## Project Structure

```
super-tanks/
├── core/
│   ├── security/     ZEF, trust, budget, mode, allowlists, users
│   ├── diq/          Frozen contracts + tool registry
│   ├── memory/       RBAC, audit, tripwires, hierarchical store
│   ├── a2a/          Agent escalation rules
│   ├── zeph/         Proactive monitoring
│   ├── gateway.py    Tool dispatch
│   ├── ask_admin.py  GO-Gate approval system
│   └── db/           SQLite connection helper
├── scripts/          Verification + review scripts
├── installer/        Windows/macOS install helpers
├── dashboard-static/ Setup wizard
├── config/           Templates (no real data)
├── Dockerfile
├── docker-compose.yml
└── install.sh
```

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Author

William Louis Park — [KNDW Shelter Solutions AS](https://aeris.no)

Built with Claude (Anthropic), Gemini (Google), and Kimi (Moonshot).
