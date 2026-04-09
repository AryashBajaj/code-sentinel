"""Minimal taint-tracking core for Python AST analysis (0.4.0).

Provides a lightweight per-function taint model:
- Sources: user-controlled input points (HTTP requests, input(), envs)
- Sinks: dangerous operations (os.system, subprocess with shell, eval/exec, pickle, render_template_string, DB cursor.execute etc.)
- Propagation: taint propagates through simple assignments within a function.

This module is intentionally small and conservative to minimize false positives
while providing a concrete foundation for end-to-end taint analysis in the Python
AST path. It is designed to be extended in future iterations for cross-file and
inter-procedural taint tracking.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Optional, Set, Dict, List

Finding = Dict[str, object]


class TaintTracker:
    def __init__(self, file_path: Path, seed_taint: Optional[Set[str]] = None):
        self.file_path = Path(file_path)
        self.current_func: Optional[str] = None
        # Initialize taint context with optional seed vars
        # Keep a separate copy of seeds to reset per function
        self._seed_vars: Set[str] = set(seed_taint or set())
        self.tainted_vars: Set[str] = set(self._seed_vars)
        if seed_taint:
            try:
                print(f"[CodeSentinel][TAINT] seed for {self.file_path}: {sorted(list(seed_taint))}")
            except Exception:
                print(f"[CodeSentinel][TAINT] seed for {self.file_path}: {seed_taint}")
        self.findings: List[Finding] = []

    # --- function/state management ---
    def start_function(self, func_name: str) -> None:
        self.current_func = func_name
        # Reset taint to the original seeds at the start of each function
        self.tainted_vars = set(self._seed_vars)

    def end_function(self) -> None:
        self.current_func = None
        self.tainted_vars = set()

    def taint_var(self, name: str) -> None:
        self.tainted_vars.add(name)

    # naive check: does a given expression contain tainted identifiers?
    def _expr_contains_taint(self, node: ast.AST) -> bool:
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and n.id in self.tainted_vars:
                return True
        return False

    def is_source_call(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        f = node.func
        # Flask/Django style: request.*.get(...) (e.g., request.args.get("cmd"))
        # input()
        if isinstance(f, ast.Name) and f.id == "input":
            return True
        # JSON input: request.get_json(...)
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "request" and f.attr == "get_json":
            return True
        # os.getenv(...)
        if isinstance(f, ast.Attribute) and f.attr == "getenv" and isinstance(f.value, ast.Name) and f.value.id == "os":
            return True
        # os.environ.get(...)
        if isinstance(f, ast.Attribute) and f.attr == "get" and isinstance(f.value, ast.Attribute):
            inner = f.value
            if isinstance(inner.value, ast.Name) and inner.value.id == "request":
                # request.GET.get(...), request.POST.get(...), request.args.get(...), request.query_params.get(...)
                if inner.attr in {"GET", "POST", "args", "data", "META", "FILES", "headers", "COOKIES", "query_params"}:
                    return True
        # Django/Flask-ish: request.GET.get("x") or request.args.get("x") within a Call
        if isinstance(f, ast.Attribute) and f.attr == "get" and isinstance(f.value, ast.Attribute):
            inner = f.value
            if isinstance(inner.value, ast.Name) and inner.value.id == "request":
                if inner.attr in {"GET", "POST", "args", "data", "query_params"}:
                    return True
        # Explicit fastapi path: request.query_params.get('...')
        if isinstance(f, ast.Attribute) and f.attr == "get" and isinstance(f.value, ast.Attribute):
            inner = f.value
            if isinstance(inner.value, ast.Attribute) and isinstance(inner.value.value, ast.Name) and inner.value.value.id == "request":
                if inner.value.attr == "query_params" and inner.attr == "get":
                    return True
        return False

    def is_sink_call(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        f = node.func
        # os.system / os.popen
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "os" and f.attr in {"system", "popen"}:
            return True
        # subprocess.run / Popen / call with shell
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "subprocess" and f.attr in {"run", "Popen", "call"}:
            # if shell=True
            for kw in getattr(node, 'keywords', []):
                if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return True
            # otherwise, conservative: still consider as potential sink if first arg is a string (dangerous pattern)
            if node.args:
                first = node.args[0]
                if isinstance(first, ast.Str) or (hasattr(ast, 'Constant') and isinstance(first, ast.Constant) and isinstance(first.value, str)):
                    return True
        # eval/exec
        if isinstance(f, ast.Name) and f.id in {"eval", "exec"}:
            return True
        # pickle.loads / pickle.loads
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "pickle" and f.attr in {"loads", "load"}:
            return True
        # YAML safe/unsafe loading patterns (yaml.load can be unsafe)
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "yaml" and f.attr in {"load", "load_all"}:
            return True
        # render_template_string (Flask) potentially taintable
        if isinstance(f, ast.Name) and f.id == "render_template_string":
            return True
        if isinstance(f, ast.Attribute) and f.attr == "render_template_string":
            return True
        # cursor.execute / executemany (dynamic SQL)
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "cursor" and f.attr in {"execute", "executemany"}:
            return True
        return False

    def has_taint_in_args(self, node: ast.Call) -> bool:
        for a in getattr(node, 'args', []):
            if self._expr_contains_taint(a):
                return True
        for kw in getattr(node, 'keywords', []):
            if kw and kw.value and self._expr_contains_taint(kw.value):
                return True
        return False

    def has_taint_in_expr(self, node: ast.AST) -> bool:
        return self._expr_contains_taint(node)

    def contains_source_call(self, node: ast.AST) -> bool:
        """Return True if the given AST node contains a source call anywhere in it."""
        for n in ast.walk(node):
            if self.is_source_call(n):
                return True
        return False

    def mark_taint_in_result(self, taint_var_name: str) -> None:
        self.taint_var(taint_var_name)

    def add_finding(self, lineno: int, message: str, severity: str = "high", category: str = "security", finding_id: str = "TAINT001", suggestion: Optional[str] = None) -> Finding:
        finding = {
            "id": finding_id,
            "file": str(self.file_path),
            "line": lineno,
            "severity": severity,
            "category": category,
            "message": message,
            "suggestion": suggestion,
        }
        self.findings.append(finding)
        return finding
