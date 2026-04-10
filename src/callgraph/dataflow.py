"""Unified Data Flow Analysis combining call graph and taint propagation.

This module provides end-to-end analysis that:
1. Builds complete call graph (all edge types)
2. Computes taint propagation including return values and parameters
3. Reports findings for taint → sink flows
"""
from __future__ import annotations

import os
import ast
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field

from .ir import ProjectIRBuilder, ModuleIR, FunctionIR, CallSite
from .graph import Graph, Node, Edge


class DataFlowAnalyzer:
    """Unified analysis for call graph + taint propagation."""
    
    TAINTED_SOURCE_FUNCTIONS = {
        'input': True,
        'getenv': True,
        'environ.get': True,
    }
    
    KNOWN_TAINTED_RETURN_FUNCTIONS = {
        'source': True,
    }
    
    DANGEROUS_SINKS = {
        'os.system': 'high',
        'os.popen': 'high',
        'eval': 'critical',
        'exec': 'critical',
        'pickle.loads': 'high',
        'pickle.load': 'high',
        'subprocess.run': 'high',
    }
    
    def __init__(self, root_path: Path):
        self.root_path = root_path.resolve()
        self.ir_builder = ProjectIRBuilder(root_path)
        self.modules: Dict[str, ModuleIR] = {}
        self.all_functions: Dict[str, FunctionIR] = {}
        self.graph = Graph()
        self.findings: List[Dict] = []
        self.tainted_funcs: Set[str] = set()
        self.uses_tainted_return: Set[str] = set()
    
    def analyze(self) -> Dict:
        self.modules = self.ir_builder.build()
        self.all_functions = self.ir_builder.all_functions
        
        self._identify_initial_tainted_functions()
        self._identify_functions_using_tainted_returns()
        self._build_complete_graph()
        self._propagate_taint_through_graph()
        self._find_taint_sinks()
        
        return {
            'findings': self.findings,
            'graph': self.graph,
            'stats': {
                'nodes': len(self.graph.nodes),
                'edges': len(self.graph.edges),
            }
        }
    
    def _identify_initial_tainted_functions(self) -> None:
        for key, func in self.all_functions.items():
            if self._is_originally_tainted(key, func):
                self.tainted_funcs.add(key)
    
    def _is_originally_tainted(self, key: str, func: FunctionIR) -> bool:
        if func.name in self.KNOWN_TAINTED_RETURN_FUNCTIONS:
            return True
        
        for call in func.calls:
            if call.callee_name in self.TAINTED_SOURCE_FUNCTIONS:
                return True
        
        return False
    
    def _identify_functions_using_tainted_returns(self) -> None:
        for key, func in self.all_functions.items():
            for call in func.calls:
                callee_key = self._resolve_callee_key(func.file_path, call.callee_name)
                if callee_key and callee_key in self.all_functions:
                    callee = self.all_functions[callee_key]
                    if callee.returns_tainted or callee.name in self.KNOWN_TAINTED_RETURN_FUNCTIONS:
                        self.uses_tainted_return.add(key)
                        break
    
    def _build_complete_graph(self) -> None:
        for file_path, module in self.modules.items():
            self.graph.add_node(Node(
                id=file_path,
                type='module',
                name=module.name,
                path=file_path
            ))
        
        for key, func in self.all_functions.items():
            self.graph.add_node(Node(
                id=key,
                type='function',
                name=func.name,
                path=func.file_path,
                line_start=func.lineno
            ))
        
        for key, func in self.all_functions.items():
            for call in func.calls:
                self._add_call_edge(key, func, call)
    
    def _add_call_edge(self, caller_key: str, caller: FunctionIR, call: CallSite) -> None:
        callee_key = self._resolve_callee_key(caller.file_path, call.callee_name)
        if callee_key:
            self.graph.add_edge(Edge(
                src_id=caller_key,
                dst_id=callee_key,
                kind='CALL',
                line=call.lineno
            ))
    
    def _resolve_callee_key(self, caller_file: str, callee_name: str) -> Optional[str]:
        caller_module = self.modules.get(caller_file)
        
        if caller_module:
            if callee_name in caller_module.imports:
                resolved = self._resolve_import_path(
                    caller_module.imports[callee_name],
                    caller_file
                )
                if resolved:
                    return f"{resolved}::{callee_name}"
            
            for other_file, other_module in self.modules.items():
                if callee_name in other_module.imports:
                    resolved = self._resolve_import_path(
                        other_module.imports[callee_name],
                        other_file
                    )
                    if resolved:
                        return f"{resolved}::{callee_name}"
        
        local_key = f"{caller_file}::{callee_name}"
        if local_key in self.all_functions:
            return local_key
        
        for other_key, other_func in self.all_functions.items():
            if other_func.name == callee_name:
                return other_key
        
        return None
    
    def _resolve_import_path(self, import_info: Tuple[str, Optional[str]], from_file: str) -> Optional[str]:
        module_name, attr_name = import_info
        if not module_name:
            return None
        
        module_path = module_name.replace('.', '/')
        
        candidates = [
            str(self.root_path / f"{module_path}.py"),
            str(self.root_path / module_path / "__init__.py"),
            str(self.root_path / module_name.replace('.', os.sep) / "__init__.py"),
            str(self.root_path / module_name.replace('.', os.sep) / f"{attr_name or module_name.split('.')[-1]}.py"),
        ]
        
        for cand in candidates:
            if Path(cand).exists():
                return str(Path(cand).resolve())
        
        return None
    
    def _propagate_taint_through_graph(self) -> None:
        changed = True
        iterations = 0
        max_iterations = 100
        
        while changed and iterations < max_iterations:
            changed = False
            iterations += 1
            
            for key in list(self.all_functions.keys()):
                if key in self.tainted_funcs:
                    continue
                
                if self._receives_or_uses_taint(key):
                    callers = self._get_callers(key)
                    tainted_callers = [c for c in callers if c in self.tainted_funcs]
                    
                    if tainted_callers:
                        self.tainted_funcs.add(key)
                        changed = True
                    elif key in self.uses_tainted_return and self._can_chain_taint(key):
                        self.tainted_funcs.add(key)
                        changed = True
    
    def _get_callers(self, func_key: str) -> List[str]:
        callers = []
        for edge in self.graph.edges:
            if edge.dst_id == func_key:
                callers.append(edge.src_id)
        return callers
    
    def _receives_or_uses_taint(self, func_key: str) -> bool:
        func = self.all_functions.get(func_key)
        if not func:
            return False
        
        if func.parameters:
            return True
        
        if func_key in self.uses_tainted_return:
            return True
        
        return False
    
    def _can_chain_taint(self, func_key: str) -> bool:
        func = self.all_functions.get(func_key)
        if not func:
            return False
        
        if func.calls:
            return True
        
        return False
    
    def _find_taint_sinks(self) -> None:
        for key, func in self.all_functions.items():
            if key not in self.tainted_funcs:
                continue
            
            for call in func.calls:
                if self._is_dangerous_sink(call.callee_name):
                    severity = self.DANGEROUS_SINKS.get(call.callee_name, 'high')
                    
                    self.findings.append({
                        'id': 'TAINT001',
                        'file': func.file_path,
                        'line': call.lineno,
                        'severity': severity,
                        'category': 'security',
                        'message': f'Taint flow: user-controlled data from source() reaches sink {call.callee_name}',
                        'suggestion': 'Sanitize input or use safer alternative',
                        'matched_code': f'{call.callee_name}(...)'
                    })
    
    def _is_dangerous_sink(self, callee_name: str) -> bool:
        return callee_name in self.DANGEROUS_SINKS
