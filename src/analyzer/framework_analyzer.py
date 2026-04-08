"""Framework orchestrator for 0.3.0: Django/Flask/FastAPI AST checks."""
from pathlib import Path
from typing import Dict, Any, List

from .django_ast import DjangoAstAnalyzer
from .flask_ast import FlaskAstAnalyzer
from .fastapi_ast import FastApiAstAnalyzer


class FrameworkAnalyzer:
    def __init__(self, framework: str, project_path: Path, project_info: Dict[str, Any]):
        self.framework = framework
        self.project_path = project_path
        self.project_info = project_info

    def analyze(self, static_results: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        findings: List[Dict[str, Any]] = []
        if self.framework == "django":
            try:
                a = DjangoAstAnalyzer(self.project_path, self.project_info)
                res = a.analyze()
                findings.extend(res.get("findings", []))
            except Exception:
                pass
        elif self.framework == "flask":
            try:
                a = FlaskAstAnalyzer(self.project_path, self.project_info)
                res = a.analyze()
                findings.extend(res.get("findings", []))
            except Exception:
                pass
        elif self.framework == "fastapi":
            try:
                a = FastApiAstAnalyzer(self.project_path, self.project_info)
                res = a.analyze()
                findings.extend(res.get("findings", []))
            except Exception:
                pass
        return {"findings": findings}
