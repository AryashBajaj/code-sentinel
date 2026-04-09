"""Interprocedural taint analysis (lightweight, multi-file).

This is an initial pass that propagates taint across function boundaries
within a Python project. It seeds callee functions with tainted parameters when
a tainted variable from a caller is passed as an argument to the callee. If the
callee uses that parameter in a sink, a TAINT001 finding is produced.
This implementation is intentionally conservative and incremental to avoid
breaking the existing analysis pipeline.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, List, Set, Optional

from analyzer.ast_analyzer import PythonAstAnalyzer  # type: ignore


class InterproceduralTaintAnalyzer:
    def __init__(self, project_path: Path, project_info):
        self.project_path = Path(project_path)
        self.project_info = project_info

    def analyze(self) -> Dict[str, List[Dict]]:
        # 1) Collect all Python files and functions
        print(f"[CodeSentinel][TAINT] [IP] Starting interprocedural taint analysis for {self.project_path}")
        files: List[Path] = []
        for p in self.project_path.rglob("*.py"):
            if p.is_file():
                files.append(p)

        # Build a function map: key = abs_path:file_name -> {name, file, params, node}
        functions: Dict[str, Dict] = {}
        for fp in files:
            try:
                code = fp.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(code, filename=str(fp))
            except Exception:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    key = f"{str(fp)}:{node.name}"
                    params = [a.arg for a in node.args.args]
                    functions[key] = {
                        "file": str(fp),
                        "name": node.name,
                        "params": params,
                        "node": node,
                    }

        if not functions:
            return {"findings": []}

        # 2) Compute local taints per function (naive) – tainted vars due to sources
        taint_seeds: Dict[str, Set[str]] = {}
        for key, info in functions.items():
            seeds = self._collect_local_taints_in_function(info["node"])  # type: ignore
            if seeds:
                taint_seeds[key] = seeds
        print(f"[CodeSentinel][TAINT] IP seeds per function: { {k: sorted(list(v)) for k, v in taint_seeds.items()} }")

        # 3) Build cross-function seeds: if caller taints arg i and calls a callee
        cross_seeds: Dict[str, Set[str]] = {}
        for caller_key, caller_info in functions.items():
            call_list = self._collect_calls_in_function(caller_info["node"], caller_key, caller_info["file"], functions)
            caller_tainted = taint_seeds.get(caller_key, set())
            for call in call_list:
                callee_key = call.get("callee_key")
                if not callee_key or callee_key not in functions:
                    continue
                arg_names = call.get("arg_names", [])
                tainted_args = [a for a in arg_names if a in caller_tainted]
                if not tainted_args:
                    continue
                callee_params = functions[callee_key]["params"]
                callee_file = functions[callee_key]["file"]
                callee_name = functions[callee_key]["name"]
                for idx, tainted_arg in enumerate(tainted_args):
                    if idx < len(callee_params):
                        param_name = callee_params[idx]
                        # Normalize the callee path to an absolute, resolved form for a stable key
                        callee_path = Path(callee_file).resolve()
                        cross_key = f"{str(callee_path)}:{callee_name}"
                        cross_seeds.setdefault(cross_key, set()).add(param_name)

        if not cross_seeds:
            return {"findings": []}

        # 4) Re-run analysis for callees with seeds
        seed_map: Dict[str, Set[str]] = cross_seeds
        pa = PythonAstAnalyzer(self.project_path, self.project_info, seed_map=seed_map)  # type: ignore
        result = pa.analyze()
        print(f"[CodeSentinel][TAINT] IP analysis finished with {len(result.get('findings', []))} findings")
        return {"findings": result.get("findings", [])}

    def _collect_local_taints_in_function(self, func_node: ast.AST) -> Set[str]:
        tainted: Set[str] = set()
        class LocalTaintVisitor(ast.NodeVisitor):
            def __init__(self, seed: Optional[Set[str]] = None):
                # Seed initial tainted variables if provided
                self.tainted_vars: Set[str] = set(seed) if seed else set()
            def _is_source_call(self, call: ast.AST) -> bool:
                # More robust source detection using structural checks (avoid relying solely on ast.unparse)
                def node_contains_request(n: ast.AST) -> bool:
                    if isinstance(n, ast.Name) and n.id == 'request':
                        return True
                    for c in ast.iter_child_nodes(n):
                        if node_contains_request(c):
                            return True
                    return False

                try:
                    if isinstance(call, ast.Call):
                        f = call.func
                        # request.*.get(...) patterns
                        if isinstance(f, ast.Attribute) and f.attr == 'get':
                            inner = f.value
                            if isinstance(inner, ast.Attribute) and inner.attr in {'GET','POST','args','data','META','FILES','headers','COOKIES','query_params'}:
                                if isinstance(inner.value, ast.Name) and inner.value.id == 'request':
                                    return True
                            if isinstance(inner, ast.Name) and inner.id == 'request':
                                return True
                        # request.get_json()
                        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == 'request' and f.attr == 'get_json':
                            return True
                        # input()
                        if isinstance(f, ast.Name) and f.id == 'input':
                            return True
                        # os.getenv(...) or os.environ.get(...)
                        if isinstance(f, ast.Attribute) and f.attr == 'getenv' and isinstance(f.value, ast.Name) and f.value.id == 'os':
                            return True
                        if isinstance(f, ast.Attribute) and f.attr == 'get' and isinstance(f.value, ast.Attribute) and isinstance(f.value.value, ast.Name) and f.value.value.id == 'os' and f.value.attr == 'environ':
                            return True
                        # Fallback: search AST for any 'request' in the call
                        if node_contains_request(call):
                            return True
                    return False
                except Exception:
                    return False

            def visit_Assign(self, node: ast.Assign):
                rhs = node.value
                if isinstance(rhs, ast.Call) and self._is_source_call(rhs):
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            self.tainted_vars.add(t.id)
                else:
                    if any(isinstance(n, ast.Name) and n.id in self.tainted_vars for n in ast.walk(rhs)):
                        for t in node.targets:
                            if isinstance(t, ast.Name):
                                self.tainted_vars.add(t.id)
                    else:
                        # Fallback: if the RHS contains a source-like call structurally, taint the LHS
                        if self._is_source_call(rhs):
                            for t in node.targets:
                                if isinstance(t, ast.Name):
                                    self.tainted_vars.add(t.id)
                self.generic_visit(node)

        try:
            v = LocalTaintVisitor(tainted)
            v.visit(func_node)
            tainted = v.tainted_vars
        except Exception:
            tainted = set()
        return tainted

    def _collect_calls_in_function(self, func_node: ast.AST, caller_key: str, caller_file: str, functions: Dict[str, Dict]) -> List[Dict]:
        calls: List[Dict] = []
        class CallVisitor(ast.NodeVisitor):
            def __init__(self):
                self.calls: List[Dict] = []
            def visit_Call(self, node: ast.Call):
                callee_keys: List[str] = []
                arg_names: List[str] = []
                if isinstance(node.func, ast.Name):
                    callee_names = [node.func.id]
                elif isinstance(node.func, ast.Attribute):
                    callee_names = [node.func.attr]
                else:
                    callee_names = []
                for callee_name in callee_names:
                    for k, info in functions.items():
                        if info["name"] == callee_name:
                            callee_keys.append(k)
                for a in getattr(node, "args", []):
                    if isinstance(a, ast.Name):
                        arg_names.append(a.id)
                    else:
                        arg_names.append("<expr>")
                for ck in callee_keys:
                    self.calls.append({"callee_key": ck, "arg_names": arg_names, "node": node})
                self.generic_visit(node)
        try:
            cv = CallVisitor()
            cv.visit(func_node)
            calls = cv.calls
        except Exception:
            calls = []
        return calls
