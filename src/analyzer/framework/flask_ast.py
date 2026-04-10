"""Flask AST-based analyzer (0.3.0).

Production-grade checks for Flask applications using Python AST and
robust heuristics. 12+ checks target common security, safety, and quality
issues observed in real-world Flask code.
"""
import ast
from pathlib import Path
from typing import List, Dict, Any
from .dedup import DedupMixin


class FlaskAstAnalyzer:
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
            visitor = FlaskAstVisitor(full_path, code, findings)
            visitor.visit(tree)
        return {"findings": findings, "stats": self._stats(findings)}

    def _stats(self, findings: List[Dict[str, Any]]):
        total = len(findings)
        critical = len([f for f in findings if f.get("severity") == "critical"])
        high = len([f for f in findings if f.get("severity") == "high"])
        medium = len([f for f in findings if f.get("severity") == "medium"])
        low = len([f for f in findings if f.get("severity") == "low"])
        return {"total": total, "critical": critical, "high": high, "medium": medium, "low": low}


class FlaskAstVisitor(ast.NodeVisitor, DedupMixin):
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
            "matched_code": self._snip(lineno),
        })

    def _snip(self, lineno: int, radius: int = 1) -> str:
        lines = self.source.splitlines()
        idx = max(0, lineno - 1 - radius)
        end = min(len(lines), lineno + radius)
        return "\n".join(lines[idx:end])

    def _contains_request(self, node: ast.AST) -> bool:
        for n in ast.walk(node):
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "request":
                return True
            if isinstance(n, ast.Name) and n.id in {"request", "request_args"}:
                return True
        return False

    def visit_Call(self, node: ast.Call):
        # FL001: render_template_string with potential user input
        if isinstance(node.func, ast.Name) and node.func.id == "render_template_string":
            if node.args:
                arg = node.args[0]
                if isinstance(arg, ast.JoinedStr):
                    if any(self._contains_request(v) for v in arg.values if isinstance(v, ast.FormattedValue)):
                        self._add("FL001", self._line_for_node(node), "high", "security", "XSS: render_template_string with user input", "Escape or avoid direct user input in templates")
                elif isinstance(arg, ast.BinOp):
                    if self._contains_request(arg):
                        self._add("FL001", self._line_for_node(node), "high", "security", "XSS: render_template_string with user input", "Escape or avoid direct user input in templates")
        # FL002: app.run(debug=True)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "run":
            for kw in getattr(node, 'keywords', []):
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._add("FL002", node.lineno, "high", "security", "Flask: debug mode enabled in production", "Disable debug in production")
        # FL003: set_cookie without Secure/HttpOnly
        if isinstance(node.func, ast.Attribute) and node.func.attr == "set_cookie":
            has_secure = any(kw.arg == "secure" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in getattr(node, 'keywords', []))
            has_http = any(kw.arg == "httponly" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in getattr(node, 'keywords', []))
            if not (has_secure and has_http):
                self._add("FL003", node.lineno, "high", "security", "Flask: missing Secure/HttpOnly on cookies", "Set secure=True and httponly=True on cookies")
        # FL004: request.files handling without validation
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "files":
            self._add("FL004", node.lineno, "high", "security", "Flask: file upload handling without validation", "Validate file types and sizes")
        # FL005: os.system usage with user input
        if isinstance(node.func, ast.Attribute) and node.func.value and isinstance(node.func.value, ast.Name) and node.func.value.id == "os" and node.func.attr == "system":
            if any(self._contains_request(a) for a in node.args):
                self._add("FL005", node.lineno, "high", "security", "Flask: OS command execution with user input", "Use safer API with strict args")
        # FL006: eval/exec in endpoints
        if isinstance(node.func, ast.Name) and node.func.id in {"eval","exec"}:
            self._add("FL006", node.lineno, "critical", "security", "Flask: dynamic code execution via eval/exec", "Remove dynamic code execution or sandbox it")
        # FL007: mark_safe
        if isinstance(node.func, ast.Name) and node.func.id == "mark_safe":
            self._add("FL007", node.lineno, "high", "security", "Flask: mark_safe may bypass escaping", "Avoid mark_safe; escape inputs or templates")
        # FL008: SECRET_KEY exposure
        if isinstance(node.func, ast.Name) and node.func.id == "SECRET_KEY":
            self._add("FL008", node.lineno, "high", "security", "Flask: SECRET_KEY exposed in code", "Move to environment/config; rotate")
        # FL009: logging secrets (scoped to actual sensitive data in this call)
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id in {"logger", "logging"}:
            for a in getattr(node, 'args', []):
                if isinstance(a, ast.Constant) and isinstance(a.value, str) and any(x in a.value.lower() for x in ("password", "secret", "api_key", "token")):
                    self._add("FL009", node.lineno, "medium", "security", "Flask: secrets logged", "Avoid logging credentials")
        # FL010: input validation laxity (trigger when accessing request.args/form)
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Attribute) and node.func.value.attr in {"args", "form"}:
            self._add("FL010", self._line_for_node(node), "medium", "safety", "Flask: potential lacking validation on inputs", "Add explicit validation")
        # FL011: potential SQL injection in dynamic SQL (only check cursor.execute calls)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            if isinstance(node.func.value, ast.Attribute) and node.func.value.attr == "cursor":
                if node.args and any(isinstance(a, (ast.BinOp, ast.JoinedStr, ast.Call, ast.Name)) for a in node.args):
                    self._add("FL011", node.lineno, "high", "security", "Flask: possible SQL injection via dynamic SQL", "Use parameterized queries or ORM")
        # FL012: template injection risk via template strings (attach to render_template calls that carry user-influenced templates)
        if isinstance(node.func, ast.Name) and node.func.id in {"render_template", "render_template_string"}:
            if node.args:
                arg = node.args[0]
                template_text = ""
                if isinstance(arg, ast.Str):
                    template_text = arg.s
                elif isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    template_text = arg.value
                tmpl = template_text if isinstance(template_text, str) else ""
                if (tmpl.find("user") != -1) or (tmpl.find("{{") != -1):
                    self._add("FL012", node.lineno, "high", "security", "Flask: potential template injection via render_template", "Validate inputs or use safe templates")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        # Detect request.files usage (file uploads)
        try:
            if isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name) and node.value.value.id == 'request' and node.value.attr == 'files':
                self._add("FL004", node.lineno, "high", "security", "Flask: file upload handling without validation", "Validate file types and sizes")
        except Exception:
            pass
        self.generic_visit(node)
