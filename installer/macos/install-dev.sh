#!/usr/bin/env bash
# Super Tanks — developer / research install for macOS (no Docker needed)
# Usage:  bash installer/macos/install-dev.sh [--ollama] [--skip-tests] [--dir ~/super-tanks]
set -euo pipefail
OLLAMA=0; SKIP=0; DIR=""
while [ $# -gt 0 ]; do case "$1" in --ollama) OLLAMA=1;; --skip-tests) SKIP=1;; --dir) DIR="$2"; shift;; *) echo "unknown arg $1"; exit 2;; esac; shift; done
say(){ printf '  \033[36m%s\033[0m\n' "$*"; }; ok(){ printf '  \033[32m[OK] %s\033[0m\n' "$*"; }; warn(){ printf '  \033[33m[!!] %s\033[0m\n' "$*"; }
echo; echo "  Super Tanks — developer install (macOS)"; echo

# 1. Homebrew
if ! command -v brew >/dev/null 2>&1; then
  warn "Homebrew not found. Install it from https://brew.sh (one command), then rerun."; exit 1
fi
ok "Homebrew found"

# 2. Git + Python 3.12
command -v git >/dev/null 2>&1 || { say "Installing git"; brew install git; }
PY=""
for c in python3.12 python3; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info[:2]>=(3,10) else 1)'; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then say "Installing Python 3.12"; brew install python@3.12; PY="$(brew --prefix python@3.12)/bin/python3.12"; fi
ok "Python: $($PY --version)"

# 3. Repo
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$HERE/../../pyproject.toml" ]; then TARGET="$(cd "$HERE/../.." && pwd)"; ok "Using this checkout: $TARGET"
else
  DIR="${DIR:-$HOME/super-tanks}"
  if [ -d "$DIR/.git" ]; then say "Updating $DIR"; git -C "$DIR" pull --ff-only; else say "Cloning into $DIR"; git clone https://github.com/KNDW-AS/super-tanks.git "$DIR"; fi
  TARGET="$DIR"
fi
cd "$TARGET"

# 4. venv + package
[ -d .venv ] || { say "Creating virtual environment"; "$PY" -m venv .venv; }
.venv/bin/python -m pip install --upgrade pip --quiet
say "Installing super-tanks with dev extras (a few minutes the first time)"
.venv/bin/python -m pip install -e ".[dev]" --quiet
ok "Package installed"

# 5. Tests
if [ "$SKIP" -eq 0 ]; then
  say "Running unit tests (expect ~1,300 passed)"
  if .venv/bin/python -m pytest -q --no-cov -p no:cacheprovider; then ok "All tests passed"; else warn "Some tests failed — see above. Installation itself is complete."; fi
  say "ZEF red-team baseline (report only)"
  .venv/bin/python -m scripts.zef_baseline --tier local-dev --report-only || true
fi

# 6. Ollama (optional)
if [ "$OLLAMA" -eq 1 ]; then
  command -v ollama >/dev/null 2>&1 || { say "Installing Ollama"; brew install ollama; }
  (ollama serve >/dev/null 2>&1 &) ; sleep 3
  say "Pulling local models (llama3.2:3b ~2 GB, nomic-embed-text ~0.3 GB)"
  ollama pull llama3.2:3b; ollama pull nomic-embed-text
  ok "Ollama ready on http://localhost:11434"
fi

echo; echo "  Done. Next steps:"
echo "    cd $TARGET && source .venv/bin/activate"
echo "    python -m pytest -q --no-cov"
echo "    python -m scripts.zef_baseline --tier local-dev --report-only"
echo "    open core/security tests/security/redteam   # start reading here"
echo
