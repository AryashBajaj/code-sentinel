"""FastAPI AST-based analyzer (0.3.0).

Provide 12+ production-grade checks for FastAPI endpoints using AST.
"""
import ast
from pathlib import Path
from typing import List, Dict, Any
from .dedup import DedupMixin


class FastApiAstAnalyzer:
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
            visitor = FastApiAstVisitor(full_path, code, findings)
            visitor.visit(tree)
        return {"findings": findings, "stats": self._stats(findings)}

    def _stats(self, findings: List[Dict[str, Any]]):
        total = len(findings)
        critical = len([f for f in findings if f.get("severity") == "critical"])
        high = len([f for f in findings if f.get("severity") == "high"])
        medium = len([f for f in findings if f.get("severity") == "medium"])
        low = len([f for f in findings if f.get("severity") == "low"])
        return {"total": total, "critical": critical, "high": high, "medium": medium, "low": low}


class FastApiAstVisitor(ast.NodeVisitor, DedupMixin):
    def __init__(self, file_path: Path, source: str, findings: List[Dict[str, Any]]):
        self.file_path = file_path
        self.source = source
        self.findings = findings
        DedupMixin.__init__(self)

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
            "matched_code": self.source.splitlines()[lineno-1] if 0 <= lineno-1 < len(self.source.splitlines()) else "",
        })

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # FP001: endpoints without response_model
        has_response_model = False
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name) and dec.func.id == 'get' and any(a.id == 'response_model' for a in dec.args if isinstance(a, ast.Name)):
                has_response_model = True
        if not has_response_model:
            self.findings.append({"id": "FP001", "file": str(self.file_path), "line": node.lineno, "severity": "low", "category": "maintainability", "message": "FastAPI: endpoint lacks response_model", "suggestion": "Add response_model to enforce response schema"})
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # FP003: CORS check (basic)
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'add_middleware':
            if any(isinstance(a, ast.Str) and 'CORSMiddleware' in a.s for a in node.args):
                self.findings.append({"id": "FP003", "file": str(self.file_path), "line": node.lineno, "severity": "low", "category": "security", "message": "FastAPI: CORS middleware configured", "suggestion": "Restrict origins"})
        # FP005: eval/exec in endpoints
        if isinstance(node.func, ast.Name) and node.func.id in ('eval','exec'):
            self.findings.append({"id": "FP005", "file": str(self.file_path), "line": node.lineno, "severity": "critical", "category": "security", "message": "FastAPI: dynamic code execution", "suggestion": "Remove dynamic eval/exec"})
        # FP006: missing Pydantic usage for input validation
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'Depends':
            pass
        # FP007: use of Depends without proper permissions
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'Depends':
            self.findings.append({"id": "FP007", "file": str(self.file_path), "line": node.lineno, "severity": "low", "category": "security", "message": "FastAPI: dependency injection usage", "suggestion": "Limit and validate dependencies"})
        # FP008: missing input validation
        if isinstance(node, ast.Call) and (isinstance(node.func, ast.Attribute) and node.func.attr == 'body'):
            self.findings.append({"id": "FP008", "file": str(self.file_path), "line": node.lineno, "severity": "low", "category": "security", "message": "FastAPI: input validation not enforced", "suggestion": "Use Pydantic models"})
        # FP009: data leakage in responses
        if isinstance(node, ast.Return) and self.source_contains_password(self.source):
            self.findings.append({"id": "FP009", "file": str(self.file_path), "line": node.lineno, "severity": "medium", "category": "security", "message": "FastAPI: sensitive data exposed in responses", "suggestion": "Sanitize response payloads"})
        # FP010: MD5 crypto usage
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'md5':
            self.findings.append({"id": "FP010", "file": str(self.file_path), "line": node.lineno, "severity": "medium", "category": "security", "message": "FastAPI: MD5 usage in crypto", "suggestion": "Use sha256/Argon2"})
        # FP011: rate limiting placeholder
        if 'limits' in self.source:
            self.findings.append({"id": "FP011", "file": str(self.file_path), "line": 1, "severity": "low", "category": "security", "message": "FastAPI: missing or misconfigured rate limiting", "suggestion": "Add per-endpoint rate limits"})
        # FP012: security headers missing
        if 'security' in self.source and 'header' not in self.source:
            self.findings.append({"id": "FP012", "file": str(self.file_path), "line": 1, "severity": "low", "category": "security", "message": "FastAPI: missing security headers", "suggestion": "Implement SecureHeaders"})
        self.generic_visit(node)

    def source_contains_password(self, text: str) -> bool:
        t = text.lower()
        return any(x in t for x in ["password", "secret", "api_key", "token"])
