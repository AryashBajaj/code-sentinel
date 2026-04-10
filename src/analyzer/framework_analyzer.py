"""Framework orchestrator for 0.3.0+: Django/Flask/FastAPI/Next.js/Express AST checks."""
from pathlib import Path
from typing import Dict, Any, List

from .framework.django_ast import DjangoAstAnalyzer
from .framework.flask_ast import FlaskAstAnalyzer
from .framework.fastapi_ast import FastApiAstAnalyzer
from .framework.nextjs_ast import NextJSAstAnalyzer
from .framework.express_ast import ExpressAstAnalyzer


class FrameworkAnalyzer:
    def __init__(self, framework: str, project_path: Path, project_info: Dict[str, Any]):
        self.framework = framework
        self.project_path = project_path
        self.project_info = project_info

    def analyze(self, static_results: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        findings: List[Dict[str, Any]] = []
        
        if self.framework in ("django", "flask", "fastapi"):
            findings.extend(self._analyze_python_framework())
        elif self.framework in ("nextjs", "express"):
            findings.extend(self._analyze_js_framework())
        
        return {"findings": findings}
    
    def _analyze_python_framework(self) -> List[Dict[str, Any]]:
        findings = []
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
        return findings
    
    def _analyze_js_framework(self) -> List[Dict[str, Any]]:
        findings = []
        
        js_extensions = {".js", ".jsx", ".ts", ".tsx"}
        js_files = []
        for ext in js_extensions:
            js_files.extend(list(self.project_path.rglob(f"*{ext}")))
        
        ignore_dirs = {"node_modules", ".git", "__pycache__", "dist", "build"}
        js_files = [f for f in js_files if not any(ign in f.parts for ign in ignore_dirs)]
        
        for file_path in js_files:
            try:
                source = file_path.read_text(encoding="utf-8", errors="ignore")
                
                if self.framework == "nextjs":
                    analyzer = NextJSAstAnalyzer()
                    results = analyzer.analyze(source, str(file_path))
                    findings.extend(results)
                elif self.framework == "express":
                    analyzer = ExpressAstAnalyzer()
                    results = analyzer.analyze(source, str(file_path))
                    findings.extend(results)
            except Exception:
                pass
        
        return findings
