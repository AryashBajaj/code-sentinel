"""Intermediate Representation for JavaScript/TypeScript code analysis.

Provides a clean, unified representation of JS/TS code that captures:
- Functions with their parameters and return statements
- All call sites (local, imported, methods)
- Taint source/sink information

This module uses tree-sitter for robust parsing of JavaScript/TypeScript.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
import re
import sys
from pathlib import Path as P

sys.path.insert(0, str(P(__file__).parent.parent))
from analyzer.tree_sitter.parser import TreeSitterParser


@dataclass
class JSParameter:
    name: str
    lineno: int


@dataclass
class JSReturnStmt:
    lineno: int
    returns_value: bool
    value_source: Optional[str] = None


@dataclass
class JSCallSite:
    lineno: int
    callee_name: str
    callee_module: Optional[str] = None
    callee_file: Optional[str] = None
    callee_key: Optional[str] = None
    args: List[str] = field(default_factory=list)
    is_local: bool = False
    is_method: bool = False
    receiver: Optional[str] = None


@dataclass
class JSFunctionIR:
    file_path: str
    name: str
    lineno: int
    parameters: List[JSParameter] = field(default_factory=list)
    returns: List[JSReturnStmt] = field(default_factory=list)
    calls: List[JSCallSite] = field(default_factory=list)
    local_vars: Set[str] = field(default_factory=set)
    receives_user_input: bool = False
    returns_tainted: bool = False


@dataclass
class JSModuleIR:
    file_path: str
    name: str
    functions: List[JSFunctionIR] = field(default_factory=list)
    imports: Dict[str, tuple] = field(default_factory=dict)
    exports: Set[str] = field(default_factory=set)


class JSTaintIRBuilder:
    """Builds IR from JavaScript/TypeScript code using tree-sitter.
    
    Sources (untrusted input):
    - req.query, req.body, req.params, req.headers, req.cookies
    - request.query, request.body, request.params
    - searchParams.get, searchParams
    - process.env (may contain user-controlled config)
    - body.*, query.*, params.*, headers.*
    """
    
    TAINTED_SOURCE_PATTERNS = {
        'req.query': True,
        'req.body': True,
        'req.params': True,
        'req.headers': True,
        'req.cookies': True,
        'req.files': True,
        'request.query': True,
        'request.body': True,
        'request.params': True,
        'searchParams.get': True,
        'searchParams': True,
        'process.env': True,
    }
    
    KNOWN_TAINTED_FUNCTIONS = {
        'getUserInput': True,
        'getQuery': True,
        'getBody': True,
        'getParam': True,
        'getHeader': True,
        'fetchUserData': True,
        'getRequest': True,
        'parseBody': True,
    }
    
    def __init__(self, file_path: str, source: str):
        self.file_path = file_path
        self.source = source
        self.functions: Dict[str, JSFunctionIR] = {}
        self.imports: Dict[str, tuple] = {}
        self.exports: Set[str] = set()
        self.parser = TreeSitterParser()
        self._current_func: Optional[JSFunctionIR] = None
        self._local_vars: Set[str] = set()
        self._param_vars: Set[str] = set()
        self._in_function = False
        
    def build(self) -> JSModuleIR:
        """Build module IR from source code."""
        try:
            result = self.parser.parse(self.source, 'javascript', self.file_path)
            if result and result.root_node:
                self._visit_node(result.root_node)
        except Exception:
            pass
        
        return JSModuleIR(
            file_path=self.file_path,
            name=Path(self.file_path).stem,
            functions=list(self.functions.values()),
            imports=self.imports,
            exports=self.exports
        )
    
    def _visit_node(self, node, depth: int = 0) -> None:
        """Recursively visit AST nodes."""
        node_type = node.node_type
        
        if node_type in ('function_declaration', 'function', 'arrow_function'):
            self._process_function(node)
        elif node_type == 'method_definition':
            self._process_method(node)
        elif node_type == 'export_statement':
            self._process_export(node)
        elif node_type == 'import_statement':
            self._process_import(node)
        elif node_type == 'call_expression' and self._in_function:
            self._process_call(node)
        elif node_type == 'variable_declaration' and self._in_function:
            self._process_variable_decl(node)
        elif node_type == 'assignment_expression' and self._in_function:
            self._process_assignment(node)
        elif node_type == 'return_statement' and self._in_function:
            self._process_return(node)
        
        for child in node.children:
            self._visit_node(child, depth + 1)
    
    def _process_function(self, node) -> None:
        """Process function declaration."""
        old_func = self._current_func
        old_in_func = self._in_function
        old_local_vars = self._local_vars.copy()
        old_param_vars = self._param_vars.copy()
        
        self._in_function = True
        
        func_name = self._get_function_name(node)
        lineno = node.start_point[0] + 1 if hasattr(node, 'start_point') else 1
        
        params = self._extract_params(node)
        param_names = {p.name for p in params}
        
        func = JSFunctionIR(
            file_path=self.file_path,
            name=func_name,
            lineno=lineno,
            parameters=params,
        )
        func.receives_user_input = bool(params)
        
        self._current_func = func
        self._local_vars = set()
        self._param_vars = param_names
        
        for child in node.children:
            self._visit_node(child)
        
        key = f"{self.file_path}::{func_name}"
        self.functions[key] = func
        
        self._current_func = old_func
        self._in_function = old_in_func
        self._local_vars = old_local_vars
        self._param_vars = old_param_vars
    
    def _process_method(self, node) -> None:
        """Process class method."""
        old_func = self._current_func
        old_in_func = self._in_function
        old_local_vars = self._local_vars.copy()
        old_param_vars = self._param_vars.copy()
        
        self._in_function = True
        
        func_name = self._get_method_name(node)
        lineno = node.start_point[0] + 1 if hasattr(node, 'start_point') else 1
        
        params = self._extract_params(node)
        param_names = {p.name for p in params}
        
        func = JSFunctionIR(
            file_path=self.file_path,
            name=func_name,
            lineno=lineno,
            parameters=params,
        )
        func.receives_user_input = bool(params)
        
        self._current_func = func
        self._local_vars = set()
        self._param_vars = param_names
        
        for child in node.children:
            self._visit_node(child)
        
        key = f"{self.file_path}::{func_name}"
        self.functions[key] = func
        
        self._current_func = old_func
        self._in_function = old_in_func
        self._local_vars = old_local_vars
        self._param_vars = old_param_vars
    
    def _process_export(self, node) -> None:
        """Process export statements."""
        text = node.text if hasattr(node, 'text') else ''
        if 'export' in text:
            for child in node.children:
                if child.node_type == 'identifier':
                    self.exports.add(child.text)
                elif child.node_type == 'identifier' in [c.node_type for c in child.children]:
                    for c in child.children:
                        if c.node_type == 'identifier':
                            self.exports.add(c.text)
    
    def _process_import(self, node) -> None:
        """Process import statements."""
        source = ''
        imported_names = []
        
        for child in node.children:
            if child.node_type == 'string':
                source = child.text.strip('"\'')
            elif child.node_type == 'import_clause':
                for c in child.children:
                    if c.node_type == 'identifier':
                        imported_names.append((c.text, None))
                    elif c.node_type == 'named_imports':
                        for nc in c.children:
                            if nc.node_type == 'identifier':
                                imported_names.append((nc.text, None))
        
        for name, alias in imported_names:
            self.imports[name] = (source, alias)
    
    def _process_call(self, node) -> None:
        """Process call expression."""
        if self._current_func is None:
            return
        
        func_text = node.text if hasattr(node, 'text') else ''
        lineno = node.start_point[0] + 1 if hasattr(node, 'start_point') else 1
        
        callee_name, receiver, args = self._extract_call_info(node)
        
        if not callee_name:
            return
        
        is_method = receiver is not None
        is_local = self._is_local_call(callee_name)
        
        call_site = JSCallSite(
            lineno=lineno,
            callee_name=callee_name,
            args=args,
            is_local=is_local,
            is_method=is_method,
            receiver=receiver
        )
        
        self._current_func.calls.append(call_site)
        
        if self._is_taint_source(callee_name, func_text):
            self._current_func.receives_user_input = True
            for arg in args:
                self._local_vars.add(arg)
    
    def _process_variable_decl(self, node) -> None:
        """Process variable declaration."""
        for child in node.children:
            if child.node_type == 'variable_declarator':
                name_node = child.children[0] if child.children else None
                if name_node and name_node.node_type == 'identifier':
                    self._local_vars.add(name_node.text)
    
    def _process_assignment(self, node) -> None:
        """Process assignment expression."""
        if len(node.children) >= 1:
            target = node.children[0]
            if target.node_type == 'identifier':
                self._local_vars.add(target.text)
    
    def _process_return(self, node) -> None:
        """Process return statement."""
        if self._current_func is None:
            return
        
        lineno = node.start_point[0] + 1 if hasattr(node, 'start_point') else 1
        has_value = len(node.children) > 1
        
        ret = JSReturnStmt(
            lineno=lineno,
            returns_value=has_value
        )
        
        if has_value:
            value_node = node.children[1] if len(node.children) > 1 else None
            if value_node:
                value_text = value_node.text if hasattr(value_node, 'text') else ''
                
                if self._is_tainted_value(value_node):
                    ret.value_source = 'tainted'
                    self._current_func.returns_tainted = True
                elif value_node.node_type == 'identifier':
                    if value_node.text in self._local_vars or value_node.text in self._param_vars:
                        ret.value_source = 'variable'
                        if self._current_func.receives_user_input:
                            self._current_func.returns_tainted = True
        
        self._current_func.returns.append(ret)
    
    def _is_tainted_value(self, node) -> bool:
        """Check if a value node is tainted."""
        text = node.text if hasattr(node, 'text') else ''
        
        for source_pattern in self.TAINTED_SOURCE_PATTERNS:
            if source_pattern in text:
                return True
        
        return False
    
    def _get_function_name(self, node) -> str:
        """Extract function name from declaration."""
        for child in node.children:
            if child.node_type == 'identifier':
                return child.text
        return '<anonymous>'
    
    def _get_method_name(self, node) -> str:
        """Extract method name from definition."""
        for child in node.children:
            if child.node_type == 'property_identifier':
                return child.text
            elif child.node_type == 'identifier':
                return child.text
        return '<anonymous>'
    
    def _extract_params(self, node) -> List[JSParameter]:
        """Extract parameters from function."""
        params = []
        for child in node.children:
            if child.node_type == 'formal_parameters':
                for param_child in child.children:
                    if param_child.node_type == 'required_parameter':
                        for pc in param_child.children:
                            if pc.node_type == 'identifier':
                                params.append(JSParameter(
                                    name=pc.text,
                                    lineno=pc.start_point[0] + 1 if hasattr(pc, 'start_point') else 1
                                ))
                    elif param_child.node_type == 'identifier':
                        params.append(JSParameter(
                            name=param_child.text,
                            lineno=param_child.start_point[0] + 1 if hasattr(param_child, 'start_point') else 1
                        ))
                    elif param_child.node_type == 'assignment_pattern':
                        for ac in param_child.children:
                            if ac.node_type == 'identifier':
                                params.append(JSParameter(
                                    name=ac.text,
                                    lineno=ac.start_point[0] + 1 if hasattr(ac, 'start_point') else 1
                                ))
                                break
        return params
    
    def _extract_call_info(self, node) -> tuple:
        """Extract callee name, receiver, and args from call expression."""
        if not node.children:
            return None, None, []
        
        func_node = node.children[0]
        args = []
        receiver = None
        
        for child in node.children:
            if child.node_type == 'member_expression':
                parts = []
                for c in child.children:
                    if c.node_type == 'this':
                        receiver = 'this'
                        parts.append('this')
                    elif c.node_type == 'identifier':
                        parts.append(c.text)
                    elif c.node_type == 'property_identifier':
                        parts.append(c.text)
                callee_name = '.'.join(parts)
                if not receiver and parts:
                    receiver = parts[0]
                return callee_name, receiver, args
            elif child.node_type == 'identifier':
                return child.text, None, args
        
        for child in node.children:
            if child.node_type == 'arguments':
                for arg_child in child.children:
                    if arg_child.node_type == 'identifier':
                        args.append(arg_child.text)
                    elif arg_child.node_type == 'member_expression':
                        parts = []
                        for c in arg_child.children:
                            if c.node_type == 'identifier':
                                parts.append(c.text)
                            elif c.node_type == 'property_identifier':
                                parts.append(c.text)
                        args.append('.'.join(parts))
        
        return callee_name if 'callee_name' in dir() else None, receiver, args
    
    def _is_local_call(self, callee_name: str) -> bool:
        """Check if callee is defined in same file."""
        func_key = f"{self.file_path}::{callee_name}"
        return func_key in self.functions
    
    def _is_taint_source(self, callee_name: str, full_text: str) -> bool:
        """Check if call is a taint source."""
        if callee_name in self.KNOWN_TAINTED_FUNCTIONS:
            return True
        
        for source_pattern in self.TAINTED_SOURCE_PATTERNS:
            if source_pattern in full_text:
                return True
        
        return False


class JSProjectIRBuilder:
    """Builds IR for entire JavaScript/TypeScript project."""
    
    JS_EXTENSIONS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
    
    def __init__(self, root_path: Path):
        self.root_path = root_path.resolve()
        self.modules: Dict[str, JSModuleIR] = {}
        self.all_functions: Dict[str, JSFunctionIR] = {}
    
    def build(self) -> Dict[str, JSModuleIR]:
        """Build IR for all JS/TS files in project."""
        ignore_dirs = {'node_modules', '.git', 'dist', 'build', '__pycache__'}
        
        for ext in self.JS_EXTENSIONS:
            for file_path in self.root_path.rglob(f"*{ext}"):
                if not file_path.is_file():
                    continue
                if any(ign in file_path.parts for ign in ignore_dirs):
                    continue
                
                try:
                    source = file_path.read_text(encoding="utf-8", errors="ignore")
                    builder = JSTaintIRBuilder(str(file_path.resolve()), source)
                    module_ir = builder.build()
                    self.modules[str(file_path.resolve())] = module_ir
                    for key, func in builder.functions.items():
                        self.all_functions[key] = func
                except Exception:
                    continue
        
        return self.modules
