"""Parser for building a Python call graph (production-end MVP).

This module collects modules and functions across a Python project using static
AST analysis and exposes key artifacts (import maps and function symbol table)
that the CallGraphBuilder consumes.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, List, Tuple, Optional

from .graph import Graph, Node


class CallGraphParser:
    def __init__(self, root_path: Path):
        self.root_path = Path(root_path).resolve()
        self.graph = Graph()
        self.import_maps: Dict[str, Dict[str, Tuple[str, Optional[str]]]] = {}
        self.func_by_id: Dict[str, Tuple[str, str]] = {}

    def _collect_modules_and_functions(self) -> None:
        for p in self.root_path.rglob("*.py"):
            if not p.is_file():
                continue
            module_path = str(p.resolve())
            self.graph.add_node(Node(id=module_path, type="module", name=p.stem, path=module_path))
            try:
                code = p.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(code, filename=module_path)
            except Exception:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    fid = f"{module_path}::{node.name}"
                    self.graph.add_node(Node(id=fid, type="function", name=node.name, path=module_path, line_start=node.lineno))
                    self.func_by_id[fid] = (module_path, node.name)

    def _build_import_maps(self) -> None:
        for p in self.root_path.rglob("*.py"):
            if not p.is_file():
                continue
            fp = str(p.resolve())
            try:
                code = p.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(code, filename=fp)
            except Exception:
                continue
            imap: Dict[str, Tuple[str, Optional[str]]] = {}
            # Collect imports anywhere in the file (including inside functions)
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    for n in node.names:
                        alias = n.asname or n.name
                        imap[alias] = (module, n.name)
                elif isinstance(node, ast.Import):
                    for n in node.names:
                        alias = n.asname or n.name
                        imap[alias] = (n.name, None)
            self.import_maps[fp] = imap

    def build(self) -> Graph:
        self._collect_modules_and_functions()
        self._build_import_maps()
        return self.graph
