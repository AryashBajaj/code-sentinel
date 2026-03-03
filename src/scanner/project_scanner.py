"""Project scanner."""
from pathlib import Path
from typing import Dict, List, Any
import toml
import json

class ProjectScanner:
    EXTENSION_LANGUAGE_MAP = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".jsx": "javascript",
        ".tsx": "typescript",
        ".go": "go",
        ".rs": "rust",
        ".java": "java",
        ".c": "c",
        ".cpp": "cpp",
    }
    
    def __init__(self, project_path: Path):
        self.project_path = project_path
    
    def scan(self) -> Dict[str, Any]:
        files = self._collect_files()
        language = self._detect_language(files)
        entry_points = self._find_entry_points(language)
        
        return {
            "name": self.project_path.name,
            "path": str(self.project_path),
            "language": language,
            "framework": "unknown",
            "files": files,
            "entry_points": entry_points,
            "dependencies": {},
        }
    
    def _collect_files(self) -> List[str]:
        ignore_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build"}
        files = []
        for path in self.project_path.rglob("*"):
            if path.is_file():
                if any(ignored in path.parts for ignored in ignore_dirs):
                    continue
                if path.suffix in self.EXTENSION_LANGUAGE_MAP:
                    files.append(str(path.relative_to(self.project_path)))
        return files
    
    def _detect_language(self, files: List[str]) -> str:
        if not files:
            return "unknown"
        extensions = {}
        for f in files:
            ext = Path(f).suffix
            if ext in self.EXTENSION_LANGUAGE_MAP:
                lang = self.EXTENSION_LANGUAGE_MAP[ext]
                extensions[lang] = extensions.get(lang, 0) + 1
        if not extensions:
            return "unknown"
        return max(extensions.items(), key=lambda x: x[1])[0]
    
    def _find_entry_points(self, language: str) -> List[str]:
        common_entries = {
            "python": ["main.py", "app.py", "server.py"],
            "javascript": ["index.js", "main.js"],
        }
        candidates = common_entries.get(language, [])
        entry_points = []
        for entry in candidates:
            if (self.project_path / entry).exists():
                entry_points.append(entry)
        return entry_points
