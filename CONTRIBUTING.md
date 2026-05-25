# Contributing to Super Tanks

Thanks for considering a contribution. Super Tanks is compliance-by-design infrastructure for autonomous AI agents — that mission shapes how changes land.

## Quick start

```bash
git clone https://github.com/billyxp74/super-tanks
cd super-tanks
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest --no-cov -q
```

A passing run is currently 1361 tests in ~50s on commodity Linux.

## Two ways to land code

### 1. Direct pull request

For straightforward improvements — tests, docs, small fixes, scoped features. Open a PR against `main`. CODEOWNERS reviews it.

### 2. Shadow proposal (Cody flow)

For AI-agent-authored changes. Cody (the in-system code-review agent) cannot directly write to the repo; she submits `shadow_store_propose` artifacts via the gateway, William reviews, and the approved diff is materialised into a PR. This path exists so AI contributions stay subject to the same human-in-the-loop guarantees we apply to runtime agent actions.

If you're authoring as a human, you do not need this flow.

## What we look for

- **Small, focused commits.** The recent PRs (#5–#11) range from ~20 to ~180 lines. We merge those quickly. 500-line PRs sit.
- **Tests with new behavior.** Coverage is currently >95% on `core/`; new code is expected to land covered. Mock external dependencies (`faster_whisper`, subprocess, urllib) — `tests/test_voice/backends/test_whisper_stt.py` shows the pattern.
- **Conventional Commit subjects.** `test(scope):`, `fix(scope):`, `feat(scope):`, `docs(scope):`, `chore(ci):`. Body explains the *why*.
- **Apache 2.0 only.** New dependencies must be Apache 2.0, MIT, BSD, or PSF. GPL/AGPL/LGPL cannot land — they are incompatible with the Super Tanks commercial story. Run `pip-licenses` and check before adding to `requirements.txt`.

## What we won't merge

- Changes to **soul files** (`core/security/cody_directives.py`, `core/soul_guard.py`, anything under `core/security/agent_identity.py` that affects trust-level invariants). Those are sealed and require a separate governance process.
- Disabling tests to make a PR pass. If a test is genuinely wrong, fix it; if your change breaks it, that's a signal to reconsider.
- Silent error handling. `except Exception: pass` and bare `try/except` that swallows are blockers. Errors must be logged with enough context to diagnose.
- Removing audit-chain entries, dispatch_log writes, or any persistence layer used as compliance evidence.

## Test isolation

Tests must not leak state. Use `monkeypatch` for environment, fixtures with `tmp_path` for filesystem, and module-scoped `autouse` fixtures for shared resources (see PRs #9 and #10 for the patterns we settled on after past leakage incidents). Do not modify global singletons in test setup without restoring them in teardown.

## Security disclosures

Do not open issues for security findings. Email `security@kndw.no` with details. We respond within 72 hours.

## License

By contributing, you agree your changes are licensed under [Apache 2.0](LICENSE).
