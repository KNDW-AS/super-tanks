# Super Tanks v3.2

**The governance layer that makes AI autonomy possible.**

Not a detection tool that reacts after something goes wrong. 10 simultaneous security layers that prevent it from happening in the first place.

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

## The 10 Security Layers

| # | Layer | What it does |
|---|-------|-------------|
| 1 | **ZEF Firewall** | Secondary LLM filter against obfuscated prompt injection |
| 2 | **Soul Files** | SHA256-sealed agent identity — tamper-evident |
| 3 | **DIQ Layer** | Declarative interface contracts — frozen tool surfaces |
| 4 | **Allowlists** | Per-agent access control — explicit allow, default deny |
| 5 | **GO-Gate** | Human-in-the-loop approval for risky actions |
| 6 | **Sandbox** | Docker isolation for untrusted execution |
| 7 | **Circuit Breaker** | Per-agent rate-limit on tool invocations |
| 8 | **Tool Zone Isolation** | 49 tools partitioned into 7 zones |
| 9 | **MCP Security Manager** | Trust-level enforcement for MCP servers |
| 10 | **allowed_agents** | Skill-level isolation per agent (added 2026-05-25) |

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
