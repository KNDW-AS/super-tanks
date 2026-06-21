# Super Tanks — NIST AI Governance Mapping

This document maps Super Tanks' 10 security layers and supporting modules to the
NIST AI governance corpus, complementing the OWASP Agentic Top 10, MITRE ATLAS,
and EU AI Act mappings published in the [README](../README.md).

The frameworks covered here are:

- **NIST AI RMF** — *Artificial Intelligence Risk Management Framework* (NIST AI 100-1), with its four core functions GOVERN, MAP, MEASURE, MANAGE.
- **NIST AI 600-1** — *Generative Artificial Intelligence Profile* (a companion to AI 100-1, July 2024).
- **NIST IR 8596** — *Cybersecurity Framework Profile for Artificial Intelligence (Cyber AI Profile)*, a CSF 2.0-based profile ([preliminary draft](https://csrc.nist.gov/pubs/ir/8596/iprd) released 16 Dec 2025, comment period to 30 Jan 2026). It names AI agents as one of three deployment archetypes but does **not yet** contain agent-specific controls — those are being developed separately under NIST's **COSAiS** project (*SP 800-53 Control Overlays for Securing AI Systems*: single-agent and multi-agent use cases, in draft as of 2026).

> **Self-assessment caveat.** This is a self-assessment mapping produced by the
> Super Tanks maintainers, **not** a certification, audit, or attestation by NIST
> or any third party. NIST does not certify products against the AI RMF. The
> mapping reflects architectural intent and the code present in this repository;
> coverage is partial where noted. NIST AI 100-1, AI 600-1, and the **IR 8596**
> Cyber AI Profile / **COSAiS** overlays are evolving (IR 8596 and the agentic
> overlays are still in draft); identifiers and subcategory wording should be
> verified against the current published NIST documents before any formal or
> contractual use.

---

## The 10 layers and key modules (reference)

For convenience, the controls referenced below:

| # | Layer | Primary module(s) verified in repo |
|---|-------|------------------------------------|
| 1 | ZEF Firewall | `core/security/zef_injection_filter.py`, `core/security/zef_llm_classifier.py`; tool-output re-scan `core/gateway.py` (`_scan_response_for_injection`) |
| 2 | Soul Files | `core/soul_guard.py` (SHA256 check → `SOUL_SAFE_MODE`) |
| 3 | DIQ Layer | `core/diq/` (`diq_integrity.py`, `diq_tools.py`, `diq_registry.py`, `diq_a2a.py`, …) |
| 4 | Allowlists | `core/security/tool_allowlists.py` |
| 5 | GO-Gate | `core/go_gate_approval_daemon.py` (Telegram approval, `request_id`) |
| 6 | Sandbox | `core/zeph_quarantine_ast.py`, `core/zeph_quarantine.py`; Docker (`Dockerfile`, `docker-compose.yml`) |
| 7 | Circuit Breaker | `core/security/trust_score.py`, `core/security/super_tanks_mode.py` (LOCKDOWN / Night) |
| 8 | Tool Zone Isolation | tool-zone partitioning enforced via gateway dispatch + allowlists |
| 9 | MCP Security Manager | trust-level enforcement for MCP servers (described as Layer 9; no dedicated `mcp_*` module is present in this OSS snapshot — see caveat below) |
| 10 | allowed_agents | skill-level isolation per agent (enforced in `core/diq/diq_skills.py` + allowlists) |
| — | HMAC agent identity | `core/security/agent_identity.py` |
| — | Tamper-evident audit | `core/security/audit_chain.py` (hash-chained, HMAC per row + checkpoint sidecar) |
| — | Dispatch audit | `core/security/dispatch_audit.py` (`correlation_id`) |
| — | A2A signature verify | `core/a2a/escalation_rules.py` (`verify_or_drop`) → `core/security/agent_identity.py` (`verify_a2a_message`) |
| — | User access | `core/security/user_manager.py` (5-level user access) |

> **Layer 9 honesty note.** "MCP Security Manager" is documented as an
> architectural layer (trust-level enforcement for MCP servers). In this
> open-source snapshot there is no standalone `mcp_security_manager.py` module;
> MCP trust handling is realised through DIQ frozen contracts (`core/diq/`),
> allowlists, and tool-zone isolation rather than a single named file. Treat
> Layer 9's *code* coverage as partial.

---

## 1. NIST AI RMF (AI 100-1) — Core Functions

The AI RMF is organised around four functions. Each function below lists
representative categories and the Super Tanks layers/modules that contribute,
followed by an honest coverage note. Subcategory codes (e.g. GOVERN 1.1) are
illustrative pointers to the published taxonomy and should be checked against
AI 100-1.

### GOVERN

Policies, accountability, and structures that make risk management work.

| RMF area | Super Tanks layer(s) / module(s) | Coverage |
|---|---|---|
| GOVERN 1 — policies & processes mapped to risk | `default-deny` allowlists (4) `core/security/tool_allowlists.py`; DIQ frozen contracts (3) `core/diq/diq_integrity.py`; published [SYSTEM_CARD.md](../SYSTEM_CARD.md), [SECURITY.md](../SECURITY.md) | Strong (technical policy is code-enforced) |
| GOVERN 2 — accountability, roles, authority | 5-level user access `core/security/user_manager.py`; `allowed_agents` (10); per-agent identity (HMAC) `core/security/agent_identity.py` | Strong |
| GOVERN 3 — workforce / human oversight culture | GO-Gate human-in-the-loop (5) `core/go_gate_approval_daemon.py`; [docs/INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md), [docs/CODY_ONBOARDING.md](CODY_ONBOARDING.md) | Strong for oversight; organisational culture is out of software scope |
| GOVERN 4 — risk-aware org commitments | [docs/RISK_REGISTER.md](RISK_REGISTER.md) (tracked risks, e.g. R-06, R-22); Soul Files integrity commitment (2) | Moderate (process docs + identity sealing) |
| GOVERN 5 — engagement with affected parties / feedback | `SECURITY.md` disclosure process; GO-Gate operator notifications | Partial |
| GOVERN 6 — third-party / supply-chain risk policy | MCP Security Manager (9) trust levels; DIQ frozen contracts (3); Sandbox (6) | Moderate — see Layer 9 honesty note |

### MAP

Establish context and identify risks of the AI system in use.

| RMF area | Super Tanks layer(s) / module(s) | Coverage |
|---|---|---|
| MAP 1 — context established | [SYSTEM_CARD.md](../SYSTEM_CARD.md) documents intended use, agents, and boundaries; Tool Zone Isolation (8) defines the action surface | Strong |
| MAP 2 — system categorisation & capabilities mapped | DIQ declarative interface contracts (3) `core/diq/`; tool zones (8); `allowed_agents` (10) — frozen, enumerable tool/skill surface per agent | Strong |
| MAP 3 — AI capabilities, benefits, costs | [SYSTEM_CARD.md](../SYSTEM_CARD.md); [docs/RISK_REGISTER.md](RISK_REGISTER.md) | Moderate |
| MAP 4 — risks to/from third parties identified | MCP Security Manager (9); A2A signature verification `core/a2a/escalation_rules.py` (`verify_or_drop`) for inter-agent trust | Moderate |
| MAP 5 — impacts characterised | Risk register + incident catalogue (README "Designed to prevent" table) | Partial (qualitative, not formal impact assessment) |

### MEASURE

Analyse, assess, and track identified risks with metrics.

| RMF area | Super Tanks layer(s) / module(s) | Coverage |
|---|---|---|
| MEASURE 1 — appropriate methods/metrics identified | ZEF adversarial baseline `scripts/zef_baseline.py`, `tests/security/redteam/`; CI run on every commit | Strong for prompt-injection; narrow scope |
| MEASURE 2 — systems evaluated for trustworthy characteristics | ZEF block-rate / false-positive measurement (README "Measured baseline"); AST scanner `core/zeph_quarantine_ast.py` for untrusted code | Moderate (security characteristics; not fairness/bias) |
| MEASURE 3 — mechanisms to track risks over time | Hash-chained audit `core/security/audit_chain.py`; dispatch audit with `correlation_id` `core/security/dispatch_audit.py`; trust score `core/security/trust_score.py` | Strong (traceability); metric dashboards partial |
| MEASURE 4 — feedback on measurement efficacy | RISK_REGISTER R-22 (planned fuzzing harness) acknowledges corpus is high-signal, not exhaustive | Partial / honest gap |

> **Honest gap:** MEASURE coverage is concentrated on **security** trustworthiness
> (prompt injection, code safety, traceability). Other AI RMF trustworthiness
> characteristics — fairness/bias, accuracy/validity of model *outputs*,
> explainability of model decisions — are **largely out of scope** for Super
> Tanks, which is a control plane around agents rather than a model-quality
> harness.

### MANAGE

Prioritise and act on risks; respond, recover, communicate.

| RMF area | Super Tanks layer(s) / module(s) | Coverage |
|---|---|---|
| MANAGE 1 — risks prioritised & acted on | [docs/RISK_REGISTER.md](RISK_REGISTER.md); default-deny allowlists (4) act on highest-impact tool-misuse risk by construction | Strong |
| MANAGE 2 — strategies to maximise benefit / minimise harm | GO-Gate (5) gates risky actions; Sandbox (6) contains untrusted execution; Circuit Breaker (7) | Strong |
| MANAGE 3 — third-party risk managed | MCP Security Manager (9) trust levels; A2A `verify_or_drop` drops unsigned/tampered messages | Moderate |
| MANAGE 4 — risk treatment monitored & responses planned | Circuit Breaker LOCKDOWN / Night mode `core/security/super_tanks_mode.py`; Soul `SAFE_MODE` on hash mismatch `core/soul_guard.py`; [docs/INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md) | Strong |

---

## 2. NIST AI 600-1 — Generative AI Profile (risk actions)

AI 600-1 enumerates GenAI-specific risks and suggested **actions** keyed to the
RMF functions. The Super Tanks coverage is strongest on the agent/tooling and
security-adjacent risks; content-quality risks (CBRN uplift, hallucination
accuracy, harmful-bias output) are out of scope.

| AI 600-1 risk theme | Suggested action class | Super Tanks layer(s) / module(s) | Coverage |
|---|---|---|---|
| Information Security (incl. prompt injection, model/agent compromise) | MEASURE / MANAGE security actions | ZEF Firewall (1) + tool-output re-scan (`gateway._scan_response_for_injection`); Sandbox (6); Soul Files (2); allowlists (4) | Strong |
| Data Privacy / leakage | MAP / MANAGE | Tool Zone Isolation (8); allowlists (4); audit sanitiser (`core/security/audit_sanitizer.py`); egress restrictions | Moderate |
| Value Chain & Component Integration (third-party tools/MCP) | GOVERN / MAP | MCP Security Manager (9); DIQ frozen contracts (3); Sandbox (6) | Moderate — Layer 9 honesty note applies |
| Human-AI Configuration / over-reliance | GOVERN / MANAGE | GO-Gate human-in-the-loop (5) with Telegram approval and operator notification | Strong (oversight); behavioural over-reliance not measured |
| Confabulation / inaccurate output | MEASURE | *Not addressed* — Super Tanks does not evaluate model factual accuracy | Out of scope |
| Dangerous/violent/CBRN content; obscene content; harmful bias & homogenisation | MEASURE / MANAGE | *Not addressed by the control plane* — content-safety filtering of model outputs is outside Super Tanks' threat model (a deployer would add a content classifier) | Out of scope |
| Traceability / incident response for GenAI | MANAGE | Hash-chained audit `core/security/audit_chain.py`; dispatch audit `correlation_id`; [docs/INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md) | Strong |

> **Scope statement.** Super Tanks is an *agent control and governance plane*.
> AI 600-1 risks that concern the **content** a generative model produces
> (confabulation, toxicity, bias, CBRN uplift) are deliberately out of scope and
> would be addressed by complementary controls a deployer layers on top.

---

## 3. NIST agentic-AI security guidance (Cyber AI Profile + COSAiS overlays)

NIST's agent-specific security guidance is still emerging. The umbrella structure
is **IR 8596 — Cybersecurity Framework Profile for Artificial Intelligence (Cyber
AI Profile)** (CSF 2.0-based, [preliminary draft](https://csrc.nist.gov/pubs/ir/8596/iprd)
16 Dec 2025), which lists AI agents as a deployment archetype but **defers
agent-specific controls** to NIST's **COSAiS** project — *SP 800-53 Control
Overlays for Securing AI Systems* — whose single-agent and multi-agent overlays
are in development as of 2026.

> **Status caveat.** IR 8596 is a preliminary draft and its agent-specific
> controls are not yet published; the COSAiS single/multi-agent overlays are
> still in draft. The rows below therefore map well-established *agent-security
> concerns* (and the Super Tanks controls that address them) to where this
> guidance is heading — **not** to finalized NIST control identifiers. Re-check
> against the published profiles before any formal use.

| Agentic concern (profile theme) | Super Tanks layer(s) / module(s) | Coverage |
|---|---|---|
| Agent identity & authentication | HMAC agent identity `core/security/agent_identity.py`; Soul Files (2) SHA256-sealed identity → `SAFE_MODE` on mismatch | Strong |
| Least-privilege / scoped autonomy | Default-deny allowlists (4); `allowed_agents` (10); Tool Zone Isolation (8); 5-level user access | Strong |
| Bounded tool use / frozen action surface | DIQ declarative contracts (3) `core/diq/`; Tool Zone Isolation (8) | Strong |
| Human oversight of consequential actions | GO-Gate (5) human-in-the-loop, single-use `request_id`, time-bounded approval via Telegram | Strong |
| Indirect / tool-mediated prompt injection | ZEF Firewall (1) + tool-output re-scan and provenance tagging (`gateway._scan_response_for_injection`) | Strong |
| Inter-agent (A2A) communication integrity | A2A signature verify `core/a2a/escalation_rules.py` (`verify_or_drop`) → `agent_identity.verify_a2a_message`; unsigned/tampered messages dropped | Strong |
| Containment of untrusted execution | Sandbox (6) Docker isolation + AST scanner `core/zeph_quarantine_ast.py` | Strong |
| Cascading-failure / runaway containment | Circuit Breaker (7) `core/security/trust_score.py`; LOCKDOWN / Night mode `core/security/super_tanks_mode.py` | Strong |
| Memory / context poisoning resistance | Soul Files (2); memory tripwires `core/memory/tripwires.py`; secure store `core/memory/secure_store.py`; DIQ (3) | Moderate |
| Tamper-evident agent action logging | Hash-chained audit `core/security/audit_chain.py` (per-row HMAC + checkpoint sidecar); dispatch audit with `correlation_id` `core/security/dispatch_audit.py` | Strong |
| Supply-chain trust for agent tools/MCP | MCP Security Manager (9) trust levels; DIQ frozen contracts (3); Sandbox (6) | Moderate — Layer 9 honesty note applies |

---

## Summary of coverage posture

- **Strongest:** agent identity, least-privilege tool access, human-in-the-loop
  oversight, prompt-injection defence, inter-agent message integrity, untrusted-
  code containment, and tamper-evident traceability — the core of an agentic
  control plane.
- **Moderate / partial:** supply-chain (MCP) trust enforcement (Layer 9 has no
  dedicated module in this OSS snapshot), memory-poisoning resistance, and
  quantitative measurement beyond the prompt-injection baseline.
- **Out of scope:** generative-content quality and safety (confabulation, bias,
  toxicity, CBRN uplift) and other non-security trustworthiness characteristics
  (fairness, output accuracy/validity, model explainability). Deployers should
  add complementary controls for these.

This document is **compliance-by-design self-mapping**, not a certification. See
the top-of-file caveat. For the OWASP, MITRE ATLAS, and EU AI Act mappings, see
the [README](../README.md); for tracked risks and known gaps see
[docs/RISK_REGISTER.md](RISK_REGISTER.md).
