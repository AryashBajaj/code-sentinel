"""Framework detector (0.3.0+ enhancement).

This module provides lightweight heuristics to detect common web frameworks
present in a codebase. Supports Python (Django, Flask, FastAPI) and 
JavaScript (Next.js, Express) frameworks.
"""
from pathlib import Path
from typing import List, Optional
import json


class FrameworkDetector:
    def __init__(self, project_path: Path):
        self.project_path = project_path

    def _iter_files(self, pattern: str = "*.py") -> List[Path]:
        files = []
        for p in self.project_path.rglob(pattern):
            if p.is_file():
                files.append(p)
        return files

    def _read_file(self, path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""

    def detect(self) -> str:
        framework = "unknown"
        
        js_files = self._iter_files("*.js")
        js_files.extend(self._iter_files("*.jsx"))
        js_files.extend(self._iter_files("*.ts"))
        js_files.extend(self._iter_files("*.tsx"))
        
        package_json = self.project_path / "package.json"
        if package_json.exists():
            try:
                pkg = json.loads(package_json.read_text(encoding="utf-8", errors="ignore"))
                deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
                
                if "next" in deps:
                    return "nextjs"
                if "express" in deps:
                    return "express"
            except Exception:
                pass
        
        has_pages_api = any("pages/api" in str(f) or "app/api" in str(f) for f in js_files)
        has_use_client = False
        has_nextjs_pattern = False
        for f in js_files:
            text = self._read_file(f)
            if "'use client'" in text or '"use client"' in text:
                has_use_client = True
            if any(p in text for p in ["getServerSideProps", "getStaticProps", "getStaticPaths", "NextPage", "next/router", "next/image"]):
                has_nextjs_pattern = True
        
        if has_use_client or has_nextjs_pattern or has_pages_api:
            if has_pages_api or has_nextjs_pattern:
                return "nextjs"
            if has_use_client:
                return "nextjs"
        
        has_express_pattern = False
        for f in js_files:
            text = self._read_file(f)
            if "require('express')" in text or 'require("express")' in text:
                return "express"
            if "from 'express'" in text or 'from "express"' in text:
                return "express"
        
        if (self.project_path / "manage.py").exists():
            return "django"

        py_files = self._iter_files("*.py")
        for path in py_files:
            text = self._read_file(path).lower()
            if "from django" in text or "import django" in text or "django.urls" in text:
                return "django"
            if "from flask" in text or "flask import" in text or "flask(" in text or "app = flask" in text:
                return "flask"
            if "from fastapi" in text or "fastapi" in text or "app = fastapi" in text:
                return "fastapi"
        
        return framework
