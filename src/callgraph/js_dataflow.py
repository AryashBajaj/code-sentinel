"""Data Flow Analysis for JavaScript/TypeScript using tree-sitter IR.

This module provides end-to-end taint analysis for JS/TS projects:
1. Builds IR from JavaScript/TypeScript using tree-sitter
2. Identifies taint sources (req.query, req.body, etc.)
3. Propagates taint through call graph
4. Reports findings for taint → sink flows

Based on taint_sources_sinks.md reference.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field

from .js_ir import JSProjectIRBuilder, JSModuleIR, JSFunctionIR, JSCallSite
from .graph import Graph, Node, Edge


@dataclass
class JSTaintSource:
    pattern: str
    description: str


@dataclass
class JSTaintSink:
    pattern: str
    severity: str
    description: str
    alternative: str


class JSDataFlowAnalyzer:
    """Taint tracking analyzer for JavaScript/TypeScript projects.
    
    Sources (untrusted input from HTTP requests):
    - req.query, req.body, req.params, req.headers, req.cookies
    - request.query, request.body, request.params
    - searchParams.get, searchParams
    - process.env (partial - may contain user-controlled config)
    - body.*, query.*, params.* in destructuring
    
    Sinks (dangerous operations):
    - eval(), Function()
    - child_process.exec*, spawn* (with shell)
    - Template rendering with user input
    - SQL queries with concatenation
    - innerHTML, document.write
    - setTimeout/setInterval with string
    """
    
    TAINT_SOURCES = {
        'req.query': JSTaintSource('req.query', 'Query parameters'),
        'req.body': JSTaintSource('req.body', 'Request body'),
        'req.params': JSTaintSource('req.params', 'Route parameters'),
        'req.headers': JSTaintSource('req.headers', 'Request headers'),
        'req.cookies': JSTaintSource('req.cookies', 'Cookies'),
        'req.files': JSTaintSource('req.files', 'Uploaded files'),
        'request.query': JSTaintSource('request.query', 'Query parameters'),
        'request.body': JSTaintSource('request.body', 'Request body'),
        'request.params': JSTaintSource('request.params', 'Route parameters'),
        'searchParams.get': JSTaintSource('searchParams.get', 'URL search params'),
        'searchParams': JSTaintSource('searchParams', 'URL search params'),
        'process.env': JSTaintSource('process.env', 'Environment variables'),
    }
    
    DANGEROUS_SINKS = {
        'eval': JSTaintSink('eval', 'critical', 'Dynamic code execution', 'Use safe parsing alternatives'),
        'Function': JSTaintSink('Function', 'critical', 'Dynamic function creation', 'Use safe alternatives'),
        'exec': JSTaintSink('child_process.exec', 'critical', 'Command injection risk', 'Use execFile with array args'),
        'execSync': JSTaintSink('child_process.execSync', 'critical', 'Command injection risk', 'Use execFileSync with array args'),
        'execFile': JSTaintSink('child_process.execFile', 'high', 'Command injection risk', 'Use shell=False'),
        'execFileSync': JSTaintSink('child_process.execFileSync', 'high', 'Command injection risk', 'Use shell=False'),
        'spawn': JSTaintSink('child_process.spawn', 'high', 'Command injection risk', 'Use shell=False'),
        'spawnSync': JSTaintSink('child_process.spawnSync', 'high', 'Command injection risk', 'Use shell=False'),
        'innerHTML': JSTaintSink('innerHTML', 'high', 'XSS via innerHTML', 'Use textContent or sanitize'),
        'outerHTML': JSTaintSink('outerHTML', 'high', 'XSS via outerHTML', 'Use safe DOM manipulation'),
        'document.write': JSTaintSink('document.write', 'high', 'XSS via document.write', 'Use safe alternatives'),
        'query': JSTaintSink('db.query', 'critical', 'SQL injection risk', 'Use parameterized queries'),
        'execute': JSTaintSink('db.execute', 'critical', 'SQL injection risk', 'Use parameterized queries'),
        'render': JSTaintSink('template.render', 'high', 'Template injection', 'Use safe templating'),
        'renderToString': JSTaintSink('React.renderToString', 'high', 'Server-side XSS', 'Sanitize data'),
        'dangerouslySetInnerHTML': JSTaintSink('dangerouslySetInnerHTML', 'high', 'XSS risk', 'Sanitize HTML first'),
    }
    
    TAINTED_FUNCTION_NAMES = {
        'getUserInput', 'getQuery', 'getBody', 'getParam', 'getHeader',
        'fetchUserData', 'getRequest', 'parseBody', 'readBody', 'getInput',
    }
    
    def __init__(self, root_path: Path):
        self.root_path = root_path.resolve()
        self.ir_builder = JSProjectIRBuilder(root_path)
        self.modules: Dict[str, JSModuleIR] = {}
        self.all_functions: Dict[str, JSFunctionIR] = {}
        self.graph = Graph()
        self.findings: List[Dict] = []
        self.tainted_funcs: Set[str] = set()
        self.uses_tainted_input: Set[str] = set()
    
    def analyze(self) -> Dict:
        """Run complete taint analysis."""
        self.modules = self.ir_builder.build()
        self.all_functions = self.ir_builder.all_functions
        
        if not self.all_functions:
            return {
                'findings': [],
                'graph': self.graph,
                'stats': {'nodes': 0, 'edges': 0}
            }
        
        self._identify_initially_tainted()
        self._identify_functions_using_tainted()
        self._build_call_graph()
        self._propagate_taint()
        self._find_taint_sinks()
        
        return {
            'findings': self.findings,
            'graph': self.graph,
            'stats': {
                'nodes': len(self.graph.nodes),
                'edges': len(self.graph.edges),
            }
        }
    
    def _identify_initially_tainted(self) -> None:
        """Identify functions that directly receive taint."""
        for key, func in self.all_functions.items():
            if self._receives_taint(key, func):
                self.tainted_funcs.add(key)
    
    def _receives_taint(self, key: str, func: JSFunctionIR) -> bool:
        """Check if function receives taint from sources."""
        if func.parameters:
            return True
        
        if func.calls:
            for call in func.calls:
                if self._is_taint_source_call(call):
                    return True
        
        return False
    
    def _is_taint_source_call(self, call: JSCallSite) -> bool:
        """Check if call is a taint source."""
        full_name = call.callee_name
        
        for source_pattern in self.TAINT_SOURCES:
            if source_pattern in full_name:
                return True
        
        return False
    
    def _identify_functions_using_tainted(self) -> None:
        """Identify functions that use return values from tainted functions."""
        for key, func in self.all_functions.items():
            for call in func.calls:
                callee_key = self._resolve_callee(call)
                if callee_key and callee_key in self.all_functions:
                    callee = self.all_functions[callee_key]
                    if callee.returns_tainted:
                        self.uses_tainted_input.add(key)
                        break
    
    def _build_call_graph(self) -> None:
        """Build call graph from IR."""
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
                callee_key = self._resolve_callee(call)
                if callee_key:
                    self.graph.add_edge(Edge(
                        src_id=key,
                        dst_id=callee_key,
                        kind='CALL',
                        line=call.lineno
                    ))
    
    def _resolve_callee(self, call: JSCallSite) -> Optional[str]:
        """Resolve callee to function key."""
        callee_name = call.callee_name.split('.')[-1] if '.' in call.callee_name else call.callee_name
        
        local_key = f"{call.callee_file or self.root_path}::{call.callee_name}"
        if local_key in self.all_functions:
            return local_key
        
        local_key2 = f"{call.callee_file or self.root_path}::{callee_name}"
        if local_key2 in self.all_functions:
            return local_key2
        
        for other_key, other_func in self.all_functions.items():
            if other_func.name == callee_name or other_func.name == call.callee_name:
                return other_key
        
        return None
    
    def _propagate_taint(self) -> None:
        """Propagate taint through call graph."""
        changed = True
        iterations = 0
        max_iterations = 100
        
        while changed and iterations < max_iterations:
            changed = False
            iterations += 1
            
            for key in list(self.all_functions.keys()):
                if key in self.tainted_funcs:
                    continue
                
                callers = self._get_callers(key)
                tainted_callers = [c for c in callers if c in self.tainted_funcs]
                
                if tainted_callers:
                    self.tainted_funcs.add(key)
                    changed = True
                elif key in self.uses_tainted_input and self._can_chain_taint(key):
                    self.tainted_funcs.add(key)
                    changed = True
    
    def _get_callers(self, func_key: str) -> List[str]:
        """Get all functions that call this function."""
        callers = []
        for edge in self.graph.edges:
            if edge.dst_id == func_key:
                callers.append(edge.src_id)
        return callers
    
    def _can_chain_taint(self, func_key: str) -> bool:
        """Check if function can chain taint to its calls."""
        func = self.all_functions.get(func_key)
        return func is not None and len(func.calls) > 0
    
    def _find_taint_sinks(self) -> None:
        """Find dangerous sinks reached by taint."""
        for key, func in self.all_functions.items():
            if key not in self.tainted_funcs:
                continue
            
            for call in func.calls:
                if self._is_dangerous_sink(call):
                    sink = self._get_sink_info(call)
                    
                    self.findings.append({
                        'id': 'JS-TAINT001',
                        'file': func.file_path,
                        'line': call.lineno,
                        'severity': sink.severity,
                        'category': 'security',
                        'message': f'Taint flow: user input reaches dangerous sink {call.callee_name}',
                        'suggestion': sink.alternative,
                        'matched_code': call.callee_name,
                        'source_info': f'{func.name}() receives user input'
                    })
    
    def _is_dangerous_sink(self, call: JSCallSite) -> bool:
        """Check if call is a dangerous sink."""
        full_name = call.callee_name
        
        for sink_pattern in self.DANGEROUS_SINKS:
            if sink_pattern in full_name or call.callee_name.endswith(sink_pattern):
                return True
        
        if call.callee_name in self.DANGEROUS_SINKS:
            return True
        
        return False
    
    def _get_sink_info(self, call: JSCallSite) -> JSTaintSink:
        """Get sink info."""
        for sink_pattern, sink in self.DANGEROUS_SINKS.items():
            if sink_pattern in call.callee_name or call.callee_name.endswith(sink_pattern):
                return sink
        
        return JSTaintSink(
            pattern=call.callee_name,
            severity='high',
            description='Dangerous operation',
            alternative='Review usage'
        )


def analyze_js_dataflow(root_path: str) -> dict:
    """Analyze JavaScript/TypeScript data flow.
    
    Returns dict with:
    - findings: List of security issues
    - graph: Call graph
    - stats: Statistics
    """
    return JSDataFlowAnalyzer(Path(root_path)).analyze()
