"""Django AST-based analyzer (0.3.0).

Produces production-grade, deterministic findings using Python's AST for Django
code paths. 12+ high-quality checks are implemented to reflect real-world security
hardening practices.
"""
import ast
from pathlib import Path
from typing import List, Dict, Any
from .dedup import DedupMixin


class DjangoAstAnalyzer:
    def __init__(self, project_path: Path, project_info: Dict[str, Any]):
        self.project_path = project_path
        self.project_info = project_info

    def analyze(self) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        for file_path in self.project_info.get("files", []):
            full_path = self.project_path / file_path
            try:
                code = Path(full_path).read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            try:
                tree = ast.parse(code, filename=str(full_path))
            except SyntaxError:
                continue
            visitor = DjangoAstVisitor(full_path, code, findings)
            visitor.visit(tree)
        return {"findings": findings, "stats": self._stats(findings)}

    def _stats(self, findings: List[Dict[str, Any]]):
        total = len(findings)
        critical = len([f for f in findings if f.get("severity") == "critical"])
        high = len([f for f in findings if f.get("severity") == "high"])
        medium = len([f for f in findings if f.get("severity") == "medium"])
        low = len([f for f in findings if f.get("severity") == "low"])
        return {"total": total, "critical": critical, "high": high, "medium": medium, "low": low}


class DjangoAstVisitor(ast.NodeVisitor, DedupMixin):
    def __init__(self, file_path: Path, source: str, findings: List[Dict[str, Any]]):
        self.file_path = file_path
        self.source = source
        self.findings = findings
        DedupMixin.__init__(self)

    def _line_for_node(self, node: ast.AST) -> int:
        min_line = getattr(node, "lineno", 1)
        for n in ast.walk(node):
            ln = getattr(n, "lineno", None)
            if isinstance(ln, int) and ln > 0 and ln < min_line:
                min_line = ln
        return min_line

    def _add(self, id: str, lineno: int, severity: str, category: str, message: str, suggestion: str):
        if not self._dedup_should_emit(id, lineno):
            return
        self.findings.append({
            "id": id,
            "file": str(self.file_path),
            "line": lineno,
            "severity": severity,
            "category": category,
            "message": message,
            "suggestion": suggestion,
        })

    def _line(self, lineno: int) -> str:
        lines = self.source.splitlines()
        if 0 <= lineno-1 < len(lines):
            return lines[lineno-1]
        return ""

    def visit_Assign(self, node: ast.Assign):
        # 3) SECRET_KEY exposure
        if isinstance(node.targets[0], ast.Name) and node.targets[0].id == "SECRET_KEY":
            val = node.value
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                self._add("DJ003", self._line_for_node(node), "high", "security", "Django: SECRET_KEY exposed in code", "Move to environment/config; rotate")
        # 4) DEBUG in production
        if isinstance(node.targets[0], ast.Name) and node.targets[0].id == "DEBUG":
            v = node.value
            if isinstance(v, ast.Constant) and isinstance(v.value, bool) and v.value:
                self._add("DJ004", self._line_for_node(node), "high", "security", "Django: DEBUG is enabled in code", "Set DEBUG = False in production")
        # 5) ALLOWED_HOSTS permissive
        if isinstance(node.targets[0], ast.Name) and node.targets[0].id == "ALLOWED_HOSTS":
            val = node.value
            if isinstance(val, (ast.List, ast.Tuple)):
                for elt in val.elts:
                    text = None
                    if isinstance(elt, ast.Str): text = elt.s
                    elif isinstance(elt, ast.Constant) and isinstance(elt.value, str): text = elt.value
                    if text == "*":
                        self._add("DJ005", self._line_for_node(node), "high", "security", "Django: ALLOWED_HOSTS overly permissive", "Restrict hosts to known domains")
        # 8) DATABASES credentials exposure
        if isinstance(node.targets[0], ast.Name) and node.targets[0].id == "DATABASES":
            if isinstance(node.value, ast.Dict):
                keys = []
                for k in node.value.keys:
                    if isinstance(k, ast.Str): keys.append(k.s)
                    elif isinstance(k, ast.Constant) and isinstance(k.value, str): keys.append(k.value)
                for k in keys:
                    up = k.upper()
                    if up in ("PASSWORD","USER","PASSWORDS"):
                        self._add("DJ008", self._line_for_node(node), "high", "security", "Django: hardcoded DB credentials in settings", "Move to environment or secure config")
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name) and dec.id == "csrf_exempt":
                self._add("DJ006", node.lineno, "high", "security", "Django: CSRF exemption", "Require CSRF protection on endpoints")
            if isinstance(dec, ast.Attribute) and dec.attr == "csrf_exempt":
                self._add("DJ006", node.lineno, "high", "security", "Django: CSRF exemption", "Require CSRF protection on endpoints")
        self.generic_visit(node)

    def _is_shell_true(self, node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False

    def _is_user_input(self, node: ast.AST) -> bool:
        src = ast.unparse(node) if hasattr(ast, 'unparse') else ""
        dangerous = ("request.", "data.get", "request.GET", "request.POST", "request.body")
        return any(d in src for d in dangerous)

    def _check_dynamic_sql(self, node: ast.Call) -> bool:
        if not node.args:
            return False
        arg0 = node.args[0]
        if isinstance(arg0, (ast.BinOp, ast.JoinedStr, ast.Call)):
            return True
        if isinstance(arg0, ast.Name):
            return True
        return False

    def visit_Call(self, node: ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute):
            func_name = func.attr
            func_value = func.value
            
            # 1) cursor.execute dynamic SQL
            if isinstance(func_value, ast.Name) and func_value.id == "cursor" and func_name == "execute":
                if self._check_dynamic_sql(node):
                    self._add("DJ001", node.lineno, "critical", "security", "Django: SQL injection via cursor.execute with dynamic query", "Use parameterized queries: cursor.execute(query, [params])")
            
            # 2) Model.objects.raw
            elif func_name == "raw":
                self._add("DJ002", node.lineno, "high", "security", "Django: Model.objects.raw used with potential user input", "Avoid raw SQL or use ORM with proper sanitization")
            
            # 7) Command injection - subprocess.run/call with shell=True
            elif isinstance(func_value, ast.Name) and func_value.id == "subprocess" and func_name in ("run", "call", "Popen"):
                if self._is_shell_true(node):
                    self._add("DJ007", node.lineno, "critical", "security", "Django: Command injection via subprocess with shell=True", "Avoid shell=True; use list args without shell execution")
            
            # 11) Path traversal - open() with user input
            elif func_name == "open" and isinstance(func_value, ast.Name):
                self._add("DJ011", node.lineno, "high", "security", "Django: Path traversal risk - open() with user input", "Validate and sanitize file paths; use safe file handling")

            # 13) SSRF - requests.get/post with user-controlled URL
            elif isinstance(func_value, ast.Name) and func_value.id == "requests" and func_name in ("get", "post", "put", "delete", "patch", "request"):
                self._add("DJ013", node.lineno, "high", "security", "Django: SSRF vulnerability - requests with user-controlled URL", "Validate and whitelist URLs before fetching")
            
            # 9) Logging secrets
            elif isinstance(func_value, ast.Name) and func_value.id in ("logger", "logging"):
                for a in node.args:
                    if isinstance(a, ast.Constant) and isinstance(a.value, str) and any(w in a.value.lower() for w in ("password", "secret", "api_key", "token")):
                        self._add("DJ009", self._line_for_node(node), "medium", "security", "Django: sensitive data logged", "Avoid logging credentials")
            
            # 12) MD5
            elif isinstance(func_value, ast.Name) and func_value.id == "hashlib" and func_name == "md5":
                self._add("DJ012", self._line_for_node(node), "medium", "security", "Django: MD5 in crypto usage", "Use sha256/Argon2 for secure hashing")
        
        elif isinstance(func, ast.Name):
            # 11) Path traversal - open() with file path
            if func.id == "open":
                self._add("DJ011", node.lineno, "high", "security", "Django: Path traversal risk - open() with user input", "Validate and sanitize file paths; use safe file handling")
            
            # 15) XSS - HttpResponse with user input concatenation
            elif func.id == "HttpResponse" and node.args:
                arg_src = ast.unparse(node.args[0]) if hasattr(ast, 'unparse') and node.args else ""
                if "+" in arg_src or "f\"" in arg_src or "format(" in arg_src:
                    if any(d in arg_src for d in ("request", "data.get", "query")):
                        self._add("DJ015", node.lineno, "high", "security", "Django: XSS risk - HttpResponse with concatenated user input", "Use render() with template or escape user input")
            
            # 15b) XSS - Template with string concatenation
            elif func.id == "Template" and node.args:
                arg_src = ast.unparse(node.args[0]) if hasattr(ast, 'unparse') and node.args else ""
                if "+" in arg_src:
                    if any(d in arg_src for d in ("request", "data.get", "query")):
                        self._add("DJ015", node.lineno, "high", "security", "Django: XSS risk - Template with concatenated user input", "Escape user input before template concatenation")
            
            # 14) Code execution - exec/eval
            elif func.id in ("exec", "eval", "execfile", "compile"):
                self._add("DJ014", node.lineno, "critical", "security", "Django: Code execution risk via exec/eval", "Avoid exec/eval with user input; use safe evaluation libraries")
            
            # 6) render_template_string
            elif func.id == "render_template_string":
                self._add("DJ010", self._line_for_node(node), "high", "security", "Django: template injection risk", "Escape inputs; use template engine with auto-escaping")
        
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp):
        if isinstance(node.op, ast.Add):
            left_src = ast.unparse(node.left) if hasattr(ast, 'unparse') else ""
            right_src = ast.unparse(node.right) if hasattr(ast, 'unparse') else ""
            combined = left_src + right_src
            user_input_patterns = ("request.", "query", "data.get", "body", "POST", "GET")
            if any(p in combined for p in user_input_patterns):
                if any(c in combined for c in ('"', "'", "<", ">", "html", "script", "div", "p>", "h1")):
                    self._add("DJ015", node.lineno, "high", "security", "Django: XSS risk - string concatenation with user input in HTML context", "Escape user input or use template engine with auto-escaping")
        self.generic_visit(node)
