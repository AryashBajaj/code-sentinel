"""Intermediate Representation for Python code analysis.

Provides a clean, unified representation of Python code that captures:
- Functions with their parameters and return statements
- All call sites (local, imported, inner imports)
- Taint source/sink information
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Any


@dataclass
class Parameter:
    name: str
    lineno: int


@dataclass
class ReturnStmt:
    lineno: int
    returns_value: bool
    value_source: Optional[str] = None  # 'literal', 'call', 'name', 'attribute', etc.


@dataclass
class CallSite:
    lineno: int
    callee_name: str
    callee_module: Optional[str] = None
    callee_file: Optional[str] = None
    callee_key: Optional[str] = None
    args: List[str] = field(default_factory=list)  # argument names
    is_local: bool = False
    is_inner_import: bool = False


@dataclass
class FunctionIR:
    file_path: str
    name: str
    lineno: int
    parameters: List[Parameter] = field(default_factory=list)
    returns: List[ReturnStmt] = field(default_factory=list)
    calls: List[CallSite] = field(default_factory=list)
    local_vars: Set[str] = field(default_factory=set)
    has_source_call: bool = False
    returns_tainted: bool = False
    tainted_returns: List[str] = field(default_factory=list)


@dataclass
class ModuleIR:
    file_path: str
    name: str
    functions: List[FunctionIR] = field(default_factory=list)
    imports: Dict[str, tuple] = field(default_factory=dict)  # alias -> (module, name)
    inner_imports: List[CallSite] = field(default_factory=list)


class PythonIRBuilder(ast.NodeVisitor):
    """Builds IR from Python AST."""
    
    KNOWN_TAINTED_RETURN_FUNCTIONS = {
        'getenv': True,
        'environ.get': True,
        'environ[]': True,
    }
    
    def __init__(self, file_path: str, source: str):
        self.file_path = file_path
        self.source = source
        self.functions: Dict[str, FunctionIR] = {}
        self.imports: Dict[str, tuple] = {}
        self.inner_imports: List[CallSite] = []
        self._current_func: Optional[FunctionIR] = None
        self._local_vars: Set[str] = set()
        self._in_function = False
        self._function_stack: List[FunctionIR] = []
    
    def build(self) -> ModuleIR:
        tree = ast.parse(self.source, filename=self.file_path)
        self.visit(tree)
        return ModuleIR(
            file_path=self.file_path,
            name=Path(self.file_path).stem,
            functions=list(self.functions.values()),
            imports=self.imports,
            inner_imports=self.inner_imports
        )
    
    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.asname or alias.name
            self.imports[name] = (alias.name, None)
    
    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ''
        for alias in node.names:
            name = alias.asname or alias.name
            self.imports[name] = (module, alias.name)
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._process_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._process_function(node)

    def _process_function(self, node):
        old_func = self._current_func
        old_in_func = self._in_function
        old_local_vars = self._local_vars.copy()
        
        self._in_function = True
        self._current_func = FunctionIR(
            file_path=self.file_path,
            name=node.name,
            lineno=node.lineno,
            parameters=[Parameter(arg.arg, arg.lineno) for arg in node.args.args]
        )
        self._function_stack.append(self._current_func)
        self._local_vars = set()
        
        self.generic_visit(node)
        
        key = f"{self.file_path}::{node.name}"
        self.functions[key] = self._current_func
        
        self._function_stack.pop()
        self._current_func = old_func
        self._in_function = old_in_func
        self._local_vars = old_local_vars
    

    
    def visit_Call(self, node: ast.Call):
        if self._current_func is None:
            self.generic_visit(node)
            return
        
        callee_name = self._get_callee_name(node.func)
        if not callee_name:
            self.generic_visit(node)
            return
        
        args = []
        for arg in node.args:
            if isinstance(arg, ast.Name):
                args.append(arg.id)
            elif isinstance(arg, ast.Attribute):
                args.append(self._get_attribute_path(arg))
        
        is_local = self._is_local_call(callee_name)
        
        call_site = CallSite(
            lineno=node.lineno,
            callee_name=callee_name,
            args=args,
            is_local=is_local,
            is_inner_import=self._in_function and not is_local
        )
        
        if call_site.is_inner_import:
            self.inner_imports.append(call_site)
        
        self._current_func.calls.append(call_site)
        
        if self._is_source_call(node):
            self._current_func.has_source_call = True
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    self._local_vars.add(arg.id)
        
        self.generic_visit(node)
    
    def visit_Return(self, node: ast.Return):
        if self._current_func is None:
            return
        
        ret = ReturnStmt(
            lineno=node.lineno,
            returns_value=node.value is not None
        )
        
        if node.value:
            if isinstance(node.value, ast.Call):
                if self._is_source_call(node.value):
                    ret.value_source = 'call'
                    self._current_func.returns_tainted = True
            elif isinstance(node.value, ast.Name):
                if node.value.id in self._local_vars:
                    ret.value_source = 'name'
                    self._current_func.returns_tainted = True
            elif isinstance(node.value, ast.Attribute):
                ret.value_source = 'attribute'
                if self._is_tainted_attribute(node.value):
                    self._current_func.returns_tainted = True
        
        self._current_func.returns.append(ret)
        self.generic_visit(node)
    
    def visit_Assign(self, node: ast.Assign):
        if self._current_func:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._local_vars.add(target.id)
        self.generic_visit(node)
    
    def _get_callee_name(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return self._get_attribute_path(node)
        return None
    
    def _get_attribute_path(self, node: ast.Attribute) -> str:
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return '.'.join(reversed(parts))
    
    def _is_local_call(self, callee_name: str) -> bool:
        if self._current_func is None:
            return False
        for func in self.functions.values():
            if func.name == callee_name and func.file_path == self.file_path:
                return True
        return False
    
    def _is_source_call(self, node: ast.Call) -> bool:
        if not isinstance(node.func, ast.Name):
            if isinstance(node.func, ast.Attribute):
                attr_path = self._get_attribute_path(node.func)
                if attr_path in {'os.getenv', 'os.environ.get', 'os.environ[]'}:
                    return True
                if isinstance(node.func.value, ast.Name) and node.func.value.id == 'request':
                    return True
            return False
        name = node.func.id
        return name in {'input', 'getenv'} or name.startswith('environ')
    
    def _is_tainted_attribute(self, node: ast.Attribute) -> bool:
        path = self._get_attribute_path(node)
        return path in {'os.environ.get', 'os.getenv', 'os.environ[]'}


class ProjectIRBuilder:
    """Builds IR for entire project."""
    
    def __init__(self, root_path: Path):
        self.root_path = root_path.resolve()
        self.modules: Dict[str, ModuleIR] = {}
        self.all_functions: Dict[str, FunctionIR] = {}
    
    def build(self) -> Dict[str, ModuleIR]:
        for py_file in self.root_path.rglob("*.py"):
            if not py_file.is_file():
                continue
            try:
                source = py_file.read_text(encoding="utf-8", errors="ignore")
                builder = PythonIRBuilder(str(py_file.resolve()), source)
                module_ir = builder.build()
                self.modules[str(py_file.resolve())] = module_ir
                for key, func in builder.functions.items():
                    self.all_functions[key] = func
            except Exception:
                continue
        return self.modules
