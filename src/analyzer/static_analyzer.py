"""Static analysis engine."""
from pathlib import Path
from typing import Dict, List, Any
import re
from .ast_analyzer import PythonAstAnalyzer

class StaticAnalyzer:
    SECURITY_PATTERNS = [
        {"id": "PY001", "pattern": r"os\.system\(", "message": "Use of os.system allows command injection", "severity": "high", "category": "security", "suggestion": "Use subprocess.run() with shell=False"},
        {"id": "PY002", "pattern": r"eval\(", "message": "Use of eval() is dangerous", "severity": "critical", "category": "security", "suggestion": "Use ast.literal_eval()"},
        {"id": "PY003", "pattern": r"exec\(", "message": "Use of exec() allows code execution", "severity": "critical", "category": "security", "suggestion": "Refactor to avoid exec"},
    ]
    PERFORMANCE_PATTERNS = [
        {"id": "PERF001", "pattern": r"for .* in .*:.*\.append\(", "message": "Consider list comprehension", "severity": "low", "category": "performance", "suggestion": "Use list comprehension"},
    ]
    SAFETY_PATTERNS = [
        {"id": "SAFE001", "pattern": r"except:", "message": "Bare except catches all exceptions", "severity": "medium", "category": "safety", "suggestion": "Use except Exception"},
    ]
    
    def __init__(self, project_path: Path, project_info: Dict):
        self.project_path = project_path
        self.project_info = project_info
        self.patterns = self.SECURITY_PATTERNS + self.PERFORMANCE_PATTERNS + self.SAFETY_PATTERNS
    
    def analyze(self) -> Dict[str, Any]:
        findings = []
        language = self.project_info.get("language", "python")
        if language == "python":
            try:
                ast_analyzer = PythonAstAnalyzer(self.project_path, self.project_info)
                ast_result = ast_analyzer.analyze()
                findings.extend(ast_result.get("findings", []))
            except Exception:
                pass
        # Fallback to regex-based analysis if AST path fails or language not python
        if not findings:
            for file_path in self.project_info.get("files", []):
                file_full_path = self.project_path / file_path
                findings.extend(self._analyze_file(file_path, file_full_path))
        total = len(findings)
        return {"findings": findings, "stats": {"total": total, "critical": len([f for f in findings if f["severity"] == "critical"]), "high": len([f for f in findings if f["severity"] == "high"]), "medium": len([f for f in findings if f["severity"] == "medium"]), "low": len([f for f in findings if f["severity"] == "low"]) } }
    
    def _analyze_file(self, file_path: str, file_full_path: Path) -> List[Dict]:
        findings = []
        try:
            with open(file_full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                for pattern in self.patterns:
                    for match in re.finditer(pattern["pattern"], content, re.MULTILINE):
                        line_num = content[:match.start()].count(chr(10)) + 1
                        findings.append({"id": pattern["id"], "file": file_path, "line": line_num, "message": pattern["message"], "severity": pattern["severity"], "category": pattern["category"], "suggestion": pattern["suggestion"], "matched_code": match.group(0)[:50]})
        except Exception:
            pass
        return findings
