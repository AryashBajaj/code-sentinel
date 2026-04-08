#!/usr/bin/env python3
"""Auto-detect and run analyzers for an input Python project.

This CLI auto-detects Django/Flask/FastAPI projects within a given path
by inspecting requirements, file patterns, and code, then runs the
corresponding static AST analyzers and prints a consolidated JSON report.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List

def _prepare_sys_path(code_src: Path):
    # Ensure the analyzer modules can be imported when running this script.
    if code_src.exists():
        sys.path.insert(0, str(code_src))

def _collect_py_files(root: Path) -> List[str]:
    files = []
    for p in root.rglob("*.py"):
        if p.is_file():
            files.append(str(p.relative_to(root)))
    return sorted(files)

def _detect_dependencies(root: Path) -> List[str]:
    frameworks = set()
    req = root / "requirements.txt"
    if req.exists():
        try:
            text = req.read_text(encoding="utf-8", errors="ignore").lower()
            if "django" in text:
                frameworks.add("django")
            if "flask" in text:
                frameworks.add("flask")
            if "fastapi" in text:
                frameworks.add("fastapi")
        except Exception:
            pass
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            text = pyproject.read_text(encoding="utf-8", errors="ignore").lower()
            if "django" in text:
                frameworks.add("django")
            if "flask" in text:
                frameworks.add("flask")
            if "fastapi" in text:
                frameworks.add("fastapi")
        except Exception:
            pass
    # heuristic: scan code for imports/usages
    for py in root.rglob("*.py"):
        try:
            content = py.read_text(encoding="utf-8", errors="ignore").lower()
        except Exception:
            continue
        if "from django" in content or "import django" in content:
            frameworks.add("django")
        if "from flask" in content or "flask(" in content:
            frameworks.add("flask")
        if "from fastapi" in content or "fastapi(" in content:
            frameworks.add("fastapi")
    return sorted(list(frameworks))

def _framework_paths(root: Path, frameworks: List[str]) -> Dict[str, Path]:
    paths: Dict[str, Path] = {}
    if "django" in frameworks:
        p = root / "django_project"
        paths["django"] = p if p.exists() else root
    if "flask" in frameworks:
        p = root / "flask_project"
        paths["flask"] = p if p.exists() else root
    if "fastapi" in frameworks:
        p = root / "fastapi_project"
        paths["fastapi"] = p if p.exists() else root
    return paths

def _run_analyzers(root: Path, project_paths: Dict[str, Path]) -> Dict[str, dict]:
    results: Dict[str, dict] = {}
    # Import lazily to ensure the path is set up
    from analyzer.django_ast import DjangoAstAnalyzer
    from analyzer.flask_ast import FlaskAstAnalyzer
    from analyzer.fastapi_ast import FastApiAstAnalyzer

    for fw, path in project_paths.items():
        files = _collect_py_files(path)
        project_info = {"files": files}
        if fw == "django":
            analyzer = DjangoAstAnalyzer(path, project_info)
        elif fw == "flask":
            analyzer = FlaskAstAnalyzer(path, project_info)
        elif fw == "fastapi":
            analyzer = FastApiAstAnalyzer(path, project_info)
        else:
            continue
        results[fw] = analyzer.analyze()
    return results

def main():
    parser = argparse.ArgumentParser(description="Auto-detect and run framework analyzers on a Python project")
    parser.add_argument("path", help="Path to the repository or codebase to analyze")
    parser.add_argument("--no-detect", action="store_true", help="Disable auto-detection and run all frameworks if present")
    parser.add_argument("--out", help="Output JSON file path (default: stdout)")
    args = parser.parse_args()

    root = Path(args.path).resolve()
    if not root.exists():
        print(json.dumps({"error": "Path not found"}, indent=2))
        sys.exit(2)

    code_src = Path(__file__).resolve().parents[0] / 'src'
    _prepare_sys_path(code_src)

    results: Dict[str, dict] = {}
    frameworks: List[str] = []
    if args.no_detect:
        frameworks = ["django", "flask", "fastapi"]
    else:
        frameworks = _detect_dependencies(root)
        if not frameworks:
            frameworks = []
        else:
            # also try directory-based discovery if present
            discovered = _framework_paths(root, frameworks)
            frameworks = sorted(list(set(list(frameworks))))
    project_paths = _framework_paths(root, frameworks)
    if project_paths:
        results = _run_analyzers(root, project_paths)

    output = {
        "detected": frameworks,
        "results": results,
    }
    out_text = json.dumps(output, indent=2)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(out_text, encoding="utf-8")
    else:
        print(out_text)

if __name__ == "__main__":
    main()
