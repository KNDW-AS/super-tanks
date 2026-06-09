"""
core/zeph_quarantine_ast.py
============================
AST-based sandbox escape detection for code proposals.

The legacy regex scanner in `zeph_quarantine.ZephScanner` is trivially
bypassed by simple obfuscation:

    >>> getattr(__builtins__, "ex" + "ec")("import os; os.system('rm -rf /')")
    >>> from os import system as s; s("rm -rf /")
    >>> import importlib; importlib.import_module("os").system(...)

This module replaces the regex check with an `ast.NodeVisitor` that:
  * tracks imports including `from X import Y as Z` aliases,
  * flags attribute access on banned modules even through aliases,
  * catches builtin obfuscation (__builtins__, __class__, __subclasses__),
  * detects dynamic execution (exec/eval/compile/__import__),
  * recognises sleeper-action patterns (threading.Timer, sched.scheduler, etc).

Files that fail to parse fall back to a single "syntax_error" violation
rather than silently passing — a proposal whose code can't be parsed
must not be deployable.
"""

import ast
import logging
from typing import Dict, List, Set

logger = logging.getLogger("zeph.scanner.ast")


# ── Policy configuration ────────────────────────────────────────────

# Any `import X` or `from X import …` of these modules is a violation.
BANNED_MODULES: Dict[str, str] = {
    "subprocess": "subprocess (direkte prosesseksekvering)",
    "socket":     "socket (direkte nettverkstilgang)",
    "urllib":     "urllib (direkte nettverksforespurnad)",
    "requests":   "requests (direkte HTTP-kall)",
    "aiohttp":    "aiohttp (direkte HTTP-klient)",
    "httpx":      "httpx (direkte HTTP-klient)",
    "ctypes":    "ctypes (direkte C-funksjonskall)",
    "importlib":  "importlib (dynamisk modullasting)",
    "apscheduler": "apscheduler (bakgrunnsplanleggar)",
    "crontab":    "crontab (planlagde bakgrunnsoppgåver)",
}

# `module.attr` accesses banned even on modules that themselves are OK
# to import (e.g. `os` is allowed but `os.system` is not).
BANNED_ATTRIBUTES: Dict[str, Set[str]] = {
    "os": {
        "system", "popen", "remove", "rmdir", "rename", "setuid", "setgid",
    },
    "shutil": {"rmtree", "move"},
    "threading": {"Timer"},
    "sched": {"scheduler"},
    "signal": {"alarm"},
    "aiohttp": {"ClientSession"},
}

# `os` attributes matched by *prefix* (covers os.exec*, os.spawn*).
BANNED_ATTR_PREFIXES: Dict[str, List[str]] = {
    "os": ["exec", "spawn"],
}

# Built-in function names that allow arbitrary code execution.
BANNED_BUILTINS: Dict[str, str] = {
    "exec":        "exec() (vilkårleg kodekøyring)",
    "eval":        "eval() (vilkårleg uttrykksvurdering)",
    "compile":     "compile() (dynamisk kodekompilering)",
    "__import__":  "__import__() (dynamisk import)",
}

# Dunder-style obfuscation handles. Any access to these is a violation —
# they're the standard routes for breaking out of a sandbox.
BANNED_DUNDERS: Set[str] = {
    "__builtins__", "__subclasses__", "__bases__", "__mro__",
    "__globals__", "__import__",
}


# ── Scanner ──────────────────────────────────────────────────────────

class _SandboxVisitor(ast.NodeVisitor):
    """Walks an AST and accumulates violation dicts."""

    def __init__(self, filename: str):
        self.filename = filename
        self.violations: List[Dict] = []
        # Map alias-name -> canonical "module" or "module.attr" so a
        # `from os import system as s` rebinds `s()` to `os.system(...)`.
        self.aliases: Dict[str, str] = {}

    def _flag(self, node: ast.AST, pattern: str, content: str) -> None:
        self.violations.append({
            "file": self.filename,
            "line": getattr(node, "lineno", 0),
            "content": content[:200],
            "pattern": pattern,
            "severity": "CRITICAL",
        })

    # ---- import bookkeeping --------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            top = alias.name.split(".")[0]
            local = alias.asname or alias.name
            self.aliases[local] = alias.name
            if top in BANNED_MODULES:
                self._flag(node, BANNED_MODULES[top], f"import {alias.name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        top = module.split(".")[0]
        if top in BANNED_MODULES:
            self._flag(node, BANNED_MODULES[top],
                       f"from {module} import ...")
        for alias in node.names:
            local = alias.asname or alias.name
            # Reaching specific banned attributes by name still counts.
            self.aliases[local] = f"{module}.{alias.name}"
            if module in BANNED_ATTRIBUTES and alias.name in BANNED_ATTRIBUTES[module]:
                self._flag(node, f"{module}.{alias.name}",
                           f"from {module} import {alias.name}")
            prefixes = BANNED_ATTR_PREFIXES.get(module, [])
            for p in prefixes:
                if alias.name.startswith(p):
                    self._flag(node, f"{module}.{p}*",
                               f"from {module} import {alias.name}")
        self.generic_visit(node)

    # ---- function calls -----------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        # Direct call to a banned builtin (exec, eval, compile, __import__)
        if isinstance(node.func, ast.Name) and node.func.id in BANNED_BUILTINS:
            self._flag(node, BANNED_BUILTINS[node.func.id],
                       ast.unparse(node) if hasattr(ast, "unparse") else node.func.id + "(...)")
        # Calls via an alias (e.g. `s(...)` where s = os.system)
        if isinstance(node.func, ast.Name):
            canonical = self.aliases.get(node.func.id)
            if canonical:
                self._check_canonical(node, canonical)
        # getattr(<obj>, "name") where obj or name is suspicious
        if (isinstance(node.func, ast.Name) and node.func.id == "getattr"
                and len(node.args) >= 2):
            second = node.args[1]
            target_name = None
            if isinstance(second, ast.Constant) and isinstance(second.value, str):
                target_name = second.value
            elif isinstance(second, ast.BinOp) and isinstance(second.op, ast.Add):
                # `"ex" + "ec"` style string concatenation
                if (isinstance(second.left, ast.Constant)
                        and isinstance(second.right, ast.Constant)
                        and isinstance(second.left.value, str)
                        and isinstance(second.right.value, str)):
                    target_name = second.left.value + second.right.value
            if target_name and (target_name in BANNED_BUILTINS
                                or target_name in BANNED_DUNDERS):
                self._flag(node,
                           "getattr-obfuscation",
                           f"getattr(..., {target_name!r})")
        self.generic_visit(node)

    # ---- attribute access ---------------------------------------------

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # Dunder probes anywhere in an attribute chain.
        if node.attr in BANNED_DUNDERS:
            self._flag(node, f"dunder:{node.attr}",
                       ast.unparse(node) if hasattr(ast, "unparse")
                       else f".{node.attr}")
        # module.attr access (e.g. os.system, os.exec*)
        if isinstance(node.value, ast.Name):
            mod_name = node.value.id
            # Resolve module alias back to canonical name.
            mod_canonical = self.aliases.get(mod_name, mod_name)
            mod_top = mod_canonical.split(".")[0]
            attr = node.attr
            if mod_top in BANNED_ATTRIBUTES and attr in BANNED_ATTRIBUTES[mod_top]:
                self._flag(node, f"{mod_top}.{attr}",
                           f"{mod_name}.{attr}")
            for p in BANNED_ATTR_PREFIXES.get(mod_top, []):
                if attr.startswith(p):
                    self._flag(node, f"{mod_top}.{p}*",
                               f"{mod_name}.{attr}")
        self.generic_visit(node)

    # ---- name probes --------------------------------------------------

    def visit_Name(self, node: ast.Name) -> None:
        # Bare reference to __builtins__ etc.
        if node.id in BANNED_DUNDERS:
            self._flag(node, f"dunder:{node.id}", node.id)
        # Bare reference to a banned module name (catches usage that
        # would NameError at runtime in this snippet but indicates an
        # import is intended elsewhere, plus the case where this file
        # *is* the import site referenced from another scanner pass).
        if node.id in BANNED_MODULES:
            self._flag(node, BANNED_MODULES[node.id], node.id)
        self.generic_visit(node)

    # ---- helpers ------------------------------------------------------

    def _check_canonical(self, node: ast.AST, canonical: str) -> None:
        """Check whether a canonical name like 'os.system' is banned."""
        if "." in canonical:
            mod, attr = canonical.rsplit(".", 1)
            mod_top = mod.split(".")[0]
            if mod_top in BANNED_ATTRIBUTES and attr in BANNED_ATTRIBUTES[mod_top]:
                self._flag(node, f"{mod_top}.{attr}", canonical)
            for p in BANNED_ATTR_PREFIXES.get(mod_top, []):
                if attr.startswith(p):
                    self._flag(node, f"{mod_top}.{p}*", canonical)
        if canonical in BANNED_BUILTINS:
            self._flag(node, BANNED_BUILTINS[canonical], canonical + "(...)")


def scan_python_source(content: str, filename: str = "<inline>") -> List[Dict]:
    """Scan Python source text via AST.

    Returns a list of violation dicts (same shape as the legacy regex
    scanner produced). Unparseable files yield a single 'syntax_error'
    violation — a proposal that fails to parse must not be silently
    accepted as "no violations found".
    """
    try:
        tree = ast.parse(content, filename=filename)
    except SyntaxError as exc:
        return [{
            "file": filename,
            "line": exc.lineno or 0,
            "content": exc.text or "",
            "pattern": f"syntax_error: {exc.msg}",
            "severity": "CRITICAL",
        }]

    visitor = _SandboxVisitor(filename)
    visitor.visit(tree)
    return visitor.violations
