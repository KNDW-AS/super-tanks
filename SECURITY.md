# Security Policy

Super Tanks is a multi-agent AI governance framework. Agents (Aeris and Zeph)
talk to a family, control a smart home, and execute code under tight
constraints. A flaw in any of the layers below can let one agent escalate
beyond its allowed surface — so we want to hear about it.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security reports. Use one of:

- **Email:** security@aeris.no  *(monitored; replies within 5 working days)*
- **GitHub Security Advisory:** Use the *Report a vulnerability* button under
  the **Security** tab of this repository.

Encrypt sensitive reports with our PGP key:

- **Fingerprint:** `6D64 161B 5468 22B4 2CE5 2C29 0503 8155 61CC 87EB`
- **Public key:** https://aeris.no/.well-known/security-pgp-key.txt

A machine-readable, PGP-signed security policy (RFC 9116) is published at
`https://aeris.no/.well-known/security.txt`.

### What to include

A useful report contains:

1. The Super Tanks commit / release you tested against.
2. The threat-model assumption you broke (see [Threat Model](#threat-model)).
3. Reproduction steps — the smallest input or sequence that triggers the issue.
4. The observed effect (what the system did) vs. the expected effect.
5. Any logs from `data/memory_audit.db`, the systemd journal, or
   `data/.identity_key`-related files. **Redact PINs and Telegram tokens.**

### What we'll do

- **Within 5 working days:** acknowledge receipt and assign a tracking ID.
- **Within 30 days:** initial assessment with severity (Critical / High /
  Medium / Low) using a local adaptation of CVSS that weights *agentic
  blast radius* (can the bypass let one agent gain another's tool surface?
  Cross trust boundaries? Reach the smart home?).
- **Within 90 days for Critical/High:** patched release + advisory.

We will credit reporters in the advisory unless you request anonymity.

## Scope

In scope:

- Anything in `core/` and `scripts/` that is part of the security layer:
  - Agent identity (`core/security/agent_identity.py`)
  - Tool dispatch + allowlist (`core/gateway.py`,
    `core/security/tool_allowlists.py`)
  - Prompt-injection filter (`core/security/zef_injection_filter.py`,
    `core/security/zef_llm_classifier.py`)
  - Memory access control (`core/memory/access_control.py`,
    `core/memory/secure_store.py`, `core/memory/tripwires.py`)
  - GO-Gate human approval (`core/ask_admin.py`,
    `core/go_gate_approval_daemon.py`)
  - Mode controller (`core/security/super_tanks_mode.py`)
  - Trust scoring (`core/security/trust_score.py`)
  - PIN auth (`core/security/user_manager.py`)
  - Soul integrity / DIQ frozen contracts (`core/soul_guard.py`,
    `core/diq/diq_integrity.py`, `core/security/integrity_floor.py`)
  - Tamper-evident audit chains (`core/security/audit_chain.py`,
    `core/security/audit_key.py`, `core/security/dispatch_audit.py`)
  - Code-proposal sandbox scan (`core/zeph_quarantine.py`,
    `core/zeph_quarantine_ast.py`)
  - Bootstrap (`core/bootstrap.py`)
- Documented threat-model assumptions in this file or in module docstrings.

Out of scope (not security bugs):

- The `tools/` directory is not part of this open-source release; bugs in
  individual tool implementations should be reported to the respective
  upstream where possible.
- Issues that require physical access to the deployment hardware.
- Issues that require an attacker who has already compromised the host
  user account (`pin_hash` exfiltration via local read, etc.).
- Denial-of-service via malformed input where the system fails closed
  (tripwire-forced LOCKDOWN, soul SAFE_MODE, etc.) is not a vulnerability —
  failing closed is the intended behaviour.
- Underlying LLM provider issues (Claude, Gemini, Ollama). Report those
  to the providers directly.

## Threat Model

Super Tanks defends against three classes of attacker, ordered by likelihood:

### 1. Prompt-injected agent (most likely)

An agent receives a message from a user, a memory file, or a tool output
that contains hidden instructions. The agent executes those instructions
instead of (or in addition to) the user's request.

Defenses:

- ZEF regex filter (40+ EN/NO patterns, Unicode normalisation, confusable
  folding)
- ZEF LLM classifier (secondary check on `webhook` / `ha_voice` / `a2a`
  channels — fails open if Ollama is unreachable)
- Per-agent tool allowlist (Aeris is READ/CHAT, Zeph is EXEC; the
  intersection is empty for `propose_code_change`, `file_write`,
  `code_edit`, `shell_exec`, `python_exec`)
- DIQ role check on every dispatch
- HMAC identity token on every tool call
- Tripwire honeypots in memory paths

### 2. Compromised agent self-modification

A jailbroken agent attempts to write code, modify its own soul file,
add tools to the allowlist, or escalate trust.

Defenses:

- Soul files SHA-256 sealed; mismatch → SAFE_MODE
- DIQ frozen contracts SHA-256 sealed; missing checksum → refuses startup
- All Aeris-authored code goes through `zeph_quarantine` AST scan
  (subprocess, exec/eval, importlib, getattr-obfuscation, dunder probes,
  sleeper actions all hard-fail with no override)
- Trust score with daily decay and -100 instant probation on tripwire
- AERIS_FORBIDDEN_TOOLS set is asserted disjoint from
  `tool_allowlists["aeris"]` at module import (RuntimeError on drift)

### 3. Local user with shell access

Out of scope. If the attacker has a shell as the host user they can
read `data/.identity_key`, modify SQLite databases, and rewrite source
files. Anchor the trust model in OS-level controls (file permissions,
disk encryption, separate user account) — not in Super Tanks.

## Known limitations

These are explicitly NOT vulnerabilities; the maintainer knows. Patches
are welcome.

- **Integrity manifests are stored in the same filesystem as the files
  they protect.** An attacker with write access to `core/` can update
  both `aeris_soul.py` and `core/soul_integrity.json` atomically.
  Rollback to an older-but-valid sealed state is now caught (manifests
  carry `meta.generation`, checked against a deployment floor in
  `core/security/integrity_floor.py`), but same-filesystem forgery is
  not. A future release will sign both manifests with an offline key
  (or store the digest in a TPM/HSM).
- **The ZEF LLM classifier fails OPEN** when Ollama is unreachable. The
  primary regex filter still runs.
- **Tool-output re-scanning is pattern-based.** The gateway re-scans
  tool output before LLM re-injection (high-confidence injection is
  redacted; WARN-level content is tagged `untrusted_content`), but
  semantic or encoded payloads that no regex/normalisation pattern
  matches can still pass. Corpus expansion is the open follow-up (R-02).
- **No runtime sandbox** wraps approved code. The AST scan is the only
  gate; once `pending_review` becomes `approved`, the change is applied
  to the live tree. The pip dependency-upgrade path likewise runs
  without separate containment (R-04).
- **A2A verification is wired in-repo but the runtime lives outside.**
  `verify_a2a_message` is invoked in `core/a2a/escalation_rules.py`
  (unsigned/invalid messages are dropped); out-of-tree runtime
  components must call it on every receive path too.

## Contact

- Email: security@aeris.no
- Maintainer: William (KNDW Shelter Solutions AS)
- License: Apache 2.0 (see `LICENSE`)
