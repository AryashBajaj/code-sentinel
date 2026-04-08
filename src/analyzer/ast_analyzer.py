"""AST-based static analysis for Python code (production-ready 0.2.0).

This module replaces regex-based checks with syntax-aware analysis using Python's
AST. It's designed to be extended to other languages via Tree-sitter in future
versions.
"""
import ast
from pathlib import Path
from typing import Dict, List, Any, Optional
from .taint import TaintTracker


class PythonAstAnalyzer:
    def __init__(self, project_path: Path, project_info: Dict[str, Any]):
        self.project_path = project_path
        self.project_info = project_info
        self.findings: List[Dict[str, Any]] = []

    def analyze(self) -> Dict[str, Any]:
        # Indicate explicitly that the AST-based analysis path is in use (0.2.0)
        print("[CodeSentinel][0.2.0] AST path activated: Python AST analysis")
        language = self.project_info.get("language", "python")
        if language != "python":
            return {"findings": [], "stats": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}}

        self.findings = []
        for file_path in self.project_info.get("files", []):
            full_path = self.project_path / file_path
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    source = f.read()
            except Exception:
                continue
            try:
                tree = ast.parse(source, filename=str(full_path))
            except SyntaxError:
                continue
            lines = source.splitlines()
            visitor = _ASTVisitor(full_path, lines, self.findings)
            visitor.visit(tree)

        return {"findings": self.findings, "stats": self._compute_stats(self.findings)}

    def _compute_stats(self, findings: List[Dict[str, Any]]):
        total = len(findings)
        critical = len([f for f in findings if f.get("severity") == "critical"])
        high = len([f for f in findings if f.get("severity") == "high"])
        medium = len([f for f in findings if f.get("severity") == "medium"])
        low = len([f for f in findings if f.get("severity") == "low"])
        return {"total": total, "critical": critical, "high": high, "medium": medium, "low": low}


class _ASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, lines: List[str], findings: List[Dict[str, Any]]):
        self.file_path = file_path
        self.lines = lines
        self.findings = findings
        self._taint: Optional[TaintTracker] = None

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Begin a new taint-tracking context for this function
        self._taint = TaintTracker(self.file_path)
        if node.name:
            self._taint.start_function(node.name)
        # CSRF protection check: warn if a view is decorated with csrf_exempt
        for dec in getattr(node, 'decorator_list', []):
            dec_name = None
            if isinstance(dec, ast.Name):
                dec_name = dec.id
            elif isinstance(dec, ast.Attribute):
                dec_name = dec.attr
            if dec_name == 'csrf_exempt':
                self._add("CSRF001", node.lineno, "high", "security", "CSRF protection disabled via csrf_exempt", "Review CSRF protection in this view")
        self.generic_visit(node)
        if self._taint:
            self._taint.end_function()
        self._taint = None


    def _snip(self, lineno: int, radius: int = 1) -> str:
        idx = max(0, lineno - 1 - radius)
        end = min(len(self.lines), lineno + radius)
        return "\n".join(self.lines[idx:end])

    def _add(self, pattern_id: str, lineno: int, severity: str, category: str, message: str, suggestion: Optional[str] = None):
        self.findings.append({
            "id": pattern_id,
            "file": str(self.file_path),
            "line": lineno,
            "severity": severity,
            "category": category,
            "message": message,
            "suggestion": suggestion,
            "matched_code": self._snip(lineno),
        })

    # Assignments for secrets (SEC001)
    def visit_Assign(self, node: ast.Assign):
        taint = self._taint
        if taint is not None:
            value = node.value
            # Source -> taint target variables (enhanced to catch nested source calls)
            if taint.contains_source_call(value):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        taint.taint_var(t.id)
            # Propagate taint through expressions
            elif taint.has_taint_in_expr(value):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        taint.taint_var(t.id)
        value = node.value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            text = value.value.lower()
            secrets = ["password", "secret", "api_key", "apikey", "token", "credential"]
            if any(s in text for s in secrets):
                target_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
                name = target_names[0] if target_names else "<unknown>"
                self._add("SEC001", node.lineno, "high", "security", f"Hardcoded secret in {name}: '{value.value[:60]}...'", "Move secrets to environment/config")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        taint = self._taint
        if taint is not None and taint.has_taint_in_args(node) and taint.is_sink_call(node):
            finding = taint.add_finding(node.lineno, "Taint flow from user input to unsafe sink", "high", "security", "TAINT001", "Sanitize input or avoid tainted data in sink")
            if finding:
                self.findings.append(finding)
        
        # 1) os.system(cmd)
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "os" and node.func.attr == "system":
            self._add("PY001", node.lineno, "high", "security", "Use of os.system allows command injection", "Use subprocess.run() with shell=False")
        # 2) eval()
        if isinstance(node.func, ast.Name) and node.func.id == "eval":
            self._add("PY002", node.lineno, "critical", "security", "Use of eval() is dangerous", "Use ast.literal_eval()")
        # 3) exec()
        if isinstance(node.func, ast.Name) and node.func.id == "exec":
            self._add("PY003", node.lineno, "critical", "security", "Use of exec() allows code execution", "Refactor to avoid exec")
        # 4) pickle.loads
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle" and node.func.attr == "loads":
            self._add("PY004", node.lineno, "high", "security", "Unsafe deserialization with pickle.loads", "Use json or other safe formats")
        # 5) render_template_string (XSS)
        if isinstance(node.func, ast.Name) and node.func.id == "render_template_string":
            self._add("PY009", node.lineno, "high", "security", "XSS risk with render_template_string", "Use templates with escaping")
        # 6) hashlib.md5
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib" and node.func.attr == "md5":
            self._add("PY010", node.lineno, "medium", "security", "MD5 is weak for cryptographic purposes", "Use sha256/Argon2")
        # 7) SQL-like dynamic SQL patterns
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"execute", "executemany"}:
            if node.args:
                arg0 = node.args[0]
                if isinstance(arg0, (ast.BinOp, ast.JoinedStr)):
                    self._add("SQL001", node.lineno, "high", "security", "Possible SQL injection via dynamic SQL construction", "Use parameterized queries or ORM")
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            self._add("SQL001", node.lineno, "high", "security", "Potential SQL injection via string formatting", "Use parameterized queries")
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try):
        for handler in node.handlers:
            if handler.type is None:
                self._add("SAFE001", node.lineno, "medium", "safety", "Bare except catches all exceptions", "Use except Exception")
        self.generic_visit(node)
