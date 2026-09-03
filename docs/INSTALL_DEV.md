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
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m supertanks doctor      # environment check, prints exact fixes
python -m supertanks demo        # GO-Gate console demo
python -m supertanks test        # 1,440 tests
python -m scripts.zef_baseline --tier local-dev --report-only
```

## Requirements
| What | Needs |
|---|---|
| Code, tests, ZEF corpus | Any laptop, 8 GB RAM, Python 3.10+ |
| Ollama local models (`llama3.2:3b`, `nomic-embed-text`) | 8–16 GB RAM, ~3 GB disk, CPU is fine |
| AgentDojo runs | An LLM API key; the eval harness is shared separately |

## Where to start reading
`README.md` → `SECURITY.md` → `core/security/` → `tests/security/redteam/corpus.py`
→ `core/ask_admin.py` (GO-Gate) → `core/diq/` → `docs/RISK_REGISTER.md`.
