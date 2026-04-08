"""Framework detector for Python projects (0.3.0 enhancement).

This module provides lightweight heuristics to detect common web frameworks
present in a codebase. It focuses on Python web frameworks (Django, Flask,
FastAPI) as a first step, with a clear path to extend to Node/Express later
via Tree-sitter-based ASTs.
"""
from pathlib import Path
from typing import List
import re


class FrameworkDetector:
    def __init__(self, project_path: Path):
        self.project_path = project_path

    def _iter_python_files(self) -> List[Path]:
        py_files = []
        for p in self.project_path.rglob("*.py"):
            if p.is_file():
                py_files.append(p)
        return py_files

    def _read_file(self, path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""

    def detect(self) -> str:
        # Normalize detection priority:
        # 1) Django (common patterns: manage.py, django in settings/urls)
        # 2) Flask (patterns: Flask(...) or from flask import ...)
        # 3) FastAPI (patterns: from fastapi import FastAPI or app = FastAPI())
        framework = "unknown"
        # Quick root indicators
        if (self.project_path / "manage.py").exists():
            return "django"

        py_files = self._iter_python_files()
        for path in py_files:
            text = self._read_file(path).lower()
            if "from django" in text or "import django" in text or "django.urls" in text:
                return "django"
            if "from flask" in text or "flask import" in text or "flask(" in text or "app = flask" in text:
                return "flask"
            if "from fastapi" in text or "fastapi" in text or "app = fastapi" in text:
                return "fastapi"
        return framework
