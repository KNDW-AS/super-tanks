# Developer / research install (no Docker)

Use this if you want to read the code, run the test suite, run the ZEF red-team
corpus, or do security research on the governance layers. It needs Python 3.10+
and Git. No Docker, no GPU. `install.sh` / the Docker path is for the packaged
product and expects the agent main loop, which is not part of this repository.

## Windows 11
Double-click `installer\windows\install-dev.bat`, or in PowerShell:
```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\installer\windows\install-dev.ps1            # install + run tests
.\installer\windows\install-dev.ps1 -Ollama    # also install Ollama and local models
```
Installs Git and Python 3.12 through winget if missing, creates `.venv`, installs
the package with the `dev` extras, runs the tests and the ZEF baseline.
Afterwards: `.\.venv\Scripts\Activate.ps1`, then `python -m pytest -q --no-cov`.
`installer\windows\run-tests.bat` reruns the tests.

## macOS
```bash
bash installer/macos/install-dev.sh            # install + run tests
bash installer/macos/install-dev.sh --ollama   # also install Ollama and local models
```
Needs Homebrew (https://brew.sh). Installs Git and Python 3.12 through brew if
missing, then the same steps as on Windows.

## Linux
On Debian/Ubuntu, `python3 -m venv` needs the `python3-venv` package
(`sudo apt install python3-venv git`).
```bash
git clone https://github.com/KNDW-AS/super-tanks.git
cd super-tanks
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m supertanks doctor      # environment check, prints exact fixes
python -m supertanks seal        # write core/diq/DIQ_CHECKSUMS.json (boot refuses without it)
python -m supertanks boot        # run the boot sequence, see "What boot prints" below
python -m supertanks demo        # GO-Gate demo through dispatch_tool (DEMO_FAST=1 skips pauses)
python -m supertanks test        # full test suite, offline
python -m scripts.zef_baseline --tier local-dev --report-only
```

## What `boot` prints in the open-source edition
On a fresh clone, after `seal`:
```text
[SOUL_GUARD] soul_integrity.json missing — entering SAFE MODE. Run the soul-sealing tool to (re)generate the manifest.
[BOOT] Soul integrity FAILED — entering SAFE MODE
[USER] No Level-5 user exists. Create one explicitly: python -m supertanks create-admin --name <name>
Tripwire deployment complete: 5/5 created
  success        True
  steps_completed ['verify_diq_integrity', 'check_soul_integrity', 'load_mode_from_state', 'ensure_admin_exists', 'ensure_tripwires_exist', 'load_upstream_tier', 'register_threat_intel', 'register_tools']
  safe_mode      True
  safe_mode_reason [SOUL_GUARD] soul_integrity.json missing — entering SAFE MODE. Run the soul-sealing tool to (re)generate the manifest.
  errors         []
```
This is expected:
- **SAFE MODE** — no agent soul files ship with this repository, so there
  is nothing sealed. To exercise the soul check, write your own soul file
  and seal it: `python scripts/seal_souls.py path/to/your_soul.py`.
  `dispatch_tool` does not consult SAFE MODE; the flag is read by the
  agent loop (not in this repository) and by some monitors.
- **No Level-5 user** — no account is created automatically (earlier
  versions created `Admin` with PIN `0000`). If you need the user
  manager, run `python -m supertanks create-admin --name <name>`; it asks
  for a PIN (≥ 6 characters, not trivial) or reads `SUPER_TANKS_ADMIN_PIN`.
  The gateway itself does not use user accounts.
- **No tools registered** — the maintainer's `tools/` package is not
  shipped; register your own with `core.diq.diq_registry.register_tool`
  (see `docs/RUNTIME_PIPELINE.md`). This is logged at INFO, not as an
  error.

## Requirements
| What | Needs |
|---|---|
| Code, tests, ZEF corpus | Any laptop, 8 GB RAM, Python 3.10+ |
| Ollama local models (`llama3.2:3b`, `nomic-embed-text`) | 8–16 GB RAM, ~3 GB disk, CPU is fine |
| AgentDojo runs | `pip install agentdojo` and any OpenAI-compatible endpoint — a cloud API key or a local Ollama server. The gateway adapter and the local-model pitfalls are in [`RUNTIME_PIPELINE.md`](RUNTIME_PIPELINE.md#agentdojo) |

## Where to start reading
`README.md` → `SECURITY.md` → `core/security/` → `tests/security/redteam/corpus.py`
→ `core/ask_admin.py` (GO-Gate) → `core/diq/` → `docs/RISK_REGISTER.md`.
