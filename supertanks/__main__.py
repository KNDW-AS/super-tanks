"""`python -m supertanks <command>` — the one entry point a fresh clone can rely on.

Commands
  doctor   check Python, package import, DIQ seal, Ollama; print the exact fix for anything missing
  demo     run the GO-Gate console demo (no dependencies, no network)
  seal     write core/diq/DIQ_CHECKSUMS.json so core.bootstrap.boot() can run
  boot     run the 8-step boot sequence and print the report
  test     run the unit tests (pytest -q --no-cov)

What is NOT in this repository: the agent main loop (`main_loop.py`) and the
dashboard API on port 8765. They are part of the maintainer's private
deployment. Everything you need to read, test and red-team the governance
layers is here.
"""
from __future__ import annotations
import argparse, importlib, os, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OK, BAD, WARN = "[OK]", "[!!]", "[--]"
NOT_INCLUDED = (
    "main_loop is not part of the open-source edition. You do not need it to read the code, "
    "run the tests or the GO-Gate demo. Run: python -m supertanks demo  (see docs/INSTALL_DEV.md)"
)


def _line(tag: str, msg: str) -> None:
    print(f"  {tag} {msg}")


def cmd_doctor(_args) -> int:
    bad = 0
    v = sys.version_info
    if v >= (3, 10):
        _line(OK, f"Python {v.major}.{v.minor}.{v.micro}")
    else:
        _line(BAD, f"Python {v.major}.{v.minor} — need 3.10 or newer"); bad += 1
    try:
        importlib.import_module("core.bootstrap"); importlib.import_module("core.gateway")
        _line(OK, "core package imports")
    except Exception as e:  # noqa: BLE001
        _line(BAD, f"core import failed: {e}\n       Fix: pip install -e \".[dev]\"  (from the repo root)"); bad += 1
    try:
        importlib.import_module("pytest"); _line(OK, "pytest available")
    except Exception:
        _line(WARN, "pytest missing — Fix: pip install -e \".[dev]\"")
    seal = ROOT / "core" / "diq" / "DIQ_CHECKSUMS.json"
    if seal.exists():
        _line(OK, "DIQ contracts sealed (core/diq/DIQ_CHECKSUMS.json)")
    else:
        _line(WARN, "DIQ contracts not sealed — boot() will refuse to start.\n       Fix: python -m supertanks seal")
    try:
        import urllib.request
        with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=1.5) as r:  # noqa: S310
            _line(OK, "Ollama answering on localhost:11434" if r.status == 200 else "Ollama reachable")
    except Exception:
        _line(WARN, "Ollama not running (optional). Only needed for the secondary LLM filter. Install: https://ollama.com")
    if (ROOT / "main_loop.py").exists():
        _line(OK, "main_loop.py present (private deployment)")
    else:
        _line(WARN, NOT_INCLUDED)
    print()
    print("  Next: python -m supertanks demo   |   python -m supertanks test")
    return 1 if bad else 0


def cmd_demo(_args) -> int:
    script = ROOT / "scripts" / "demo_go_gate.py"
    return subprocess.call([sys.executable, str(script)], cwd=str(ROOT))


def cmd_seal(_args) -> int:
    from core.diq.diq_integrity import write_checksums
    write_checksums()
    _line(OK, "DIQ_CHECKSUMS.json written — boot() can now verify the frozen contracts")
    return 0


def cmd_boot(args) -> int:
    from core.bootstrap import boot
    try:
        res = boot(force=args.force)
    except RuntimeError as e:
        _line(BAD, str(e))
        if "DIQ_CHECKSUMS" in str(e):
            _line(WARN, "Fix: python -m supertanks seal")
        return 1
    for k, v in vars(res).items():
        print(f"  {k:14} {v}")
    return 0


def cmd_test(_args) -> int:
    return subprocess.call([sys.executable, "-m", "pytest", "-q", "--no-cov", "-p", "no:cacheprovider"], cwd=str(ROOT))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="supertanks", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("doctor", help="check the environment and print exact fixes").set_defaults(f=cmd_doctor)
    sub.add_parser("demo", help="GO-Gate console demo").set_defaults(f=cmd_demo)
    sub.add_parser("seal", help="write DIQ_CHECKSUMS.json").set_defaults(f=cmd_seal)
    b = sub.add_parser("boot", help="run the boot sequence"); b.add_argument("--force", action="store_true"); b.set_defaults(f=cmd_boot)
    sub.add_parser("test", help="run the unit tests").set_defaults(f=cmd_test)
    a = ap.parse_args(argv)
    os.chdir(ROOT)
    return a.f(a)


if __name__ == "__main__":
    sys.exit(main())
