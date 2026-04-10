"""End-to-end Python call graph (production-grade MVP).

This module provides a clean, production-ready API to build an end-to-end
call graph across multiple files using Python AST. It focuses on stable, static
resolution and a clear API that is easy to test, extend, and optimize.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, List, Optional, Set

from .graph import Graph, Node, Edge
from .parser import CallGraphParser
from .resolver import ImportResolver


class CallGraphBuilder:
    def __init__(self, root_path: str):
        self.root_path = Path(root_path).resolve()
        self.graph = Graph()
        self.resolver = ImportResolver(self.root_path)
        self._parser = None
        self._import_maps = {}
        self._func_by_id = {}

    def _collect(self) -> Graph:
        self._parser = CallGraphParser(self.root_path)
        graph = self._parser.build()
        self.graph = graph
        self._import_maps = getattr(self._parser, 'import_maps', {}) or {}
        self._func_by_id = getattr(self._parser, 'func_by_id', {}) or {}
        return self.graph

    def _resolve_module_path(self, module_name: str) -> Optional[Path]:
        candidate = self.root_path / f"{module_name}.py"
        if candidate.exists():
            return candidate.resolve()
        dir_candidate = self.root_path / module_name
        if (dir_candidate / "__init__.py").exists():
            return (dir_candidate / "__init__.py").resolve()
        return None

    def build_graph(self) -> Graph:
        graph = self._collect()
        function_ids: Set[str] = set(self._func_by_id.keys())
        # Wire edge by re-scanning files for calls
        for py in self.root_path.rglob("*.py"):
            if not py.is_file():
                continue
            file_path = str(py.resolve())
            try:
                code = py.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(code, filename=file_path)
            except Exception:
                continue
            import_map = self._import_maps.get(file_path, {})
            local_funcs: Dict[str, str] = {}
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    fid = f"{file_path}::{node.name}"
                    local_funcs[node.name] = fid
            for fname, caller_id in local_funcs.items():
                func_node = None
                for n in ast.walk(tree):
                    if isinstance(n, ast.FunctionDef) and n.name == fname:
                        func_node = n
                        break
                if func_node is None:
                    continue
                for call in ast.walk(func_node):
                    if not isinstance(call, ast.Call):
                        continue
                    callee_id = None
                    if isinstance(call.func, ast.Name):
                        name = call.func.id
                        if name in import_map:
                            mod_name, func_name = import_map[name]
                            mod_path = self._resolve_module_path(mod_name)
                            if mod_path:
                                candidate = f"{str(mod_path.resolve())}::{func_name}"
                                if candidate in function_ids:
                                    callee_id = candidate
                    elif isinstance(call.func, ast.Attribute):
                        if isinstance(call.func.value, ast.Name):
                            alias = call.func.value.id
                            if alias in import_map:
                                mod_name, func_name = import_map[alias]
                                mod_path = self._resolve_module_path(mod_name)
                                if mod_path:
                                    candidate = f"{str(mod_path.resolve())}::{call.func.attr}"
                                    if candidate in function_ids:
                                        callee_id = candidate
                    if callee_id:
                        graph.add_edge(Edge(src_id=caller_id, dst_id=callee_id, kind='CALL', line=getattr(call, 'lineno', None)))
        return graph
