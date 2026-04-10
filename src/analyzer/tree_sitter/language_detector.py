"""Language detection for tree-sitter parser.

Detects programming languages from file extensions and content.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional, Set


class LanguageDetector:
    """Detects programming language from file path or content."""
    
    EXTENSION_MAP: Dict[str, str] = {
        '.py': 'python',
        '.pyw': 'python',
        '.pyi': 'python',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.mjs': 'javascript',
        '.cjs': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.mts': 'typescript',
        '.cts': 'typescript',
        '.go': 'go',
        '.rs': 'rust',
        '.java': 'java',
        '.c': 'c',
        '.h': 'c',
        '.cpp': 'cpp',
        '.cc': 'cpp',
        '.cxx': 'cpp',
        '.hpp': 'cpp',
        '.cs': 'csharp',
        '.rb': 'ruby',
        '.php': 'php',
        '.swift': 'swift',
        '.kt': 'kotlin',
        '.kts': 'kotlin',
        '.scala': 'scala',
        '.lua': 'lua',
        '.r': 'r',
        '.R': 'r',
        '.ex': 'elixir',
        '.exs': 'elixir',
        '.erl': 'erlang',
        '.hs': 'haskell',
        '.ml': 'ocaml',
        '.fs': 'fsharp',
        '.fsx': 'fsharp',
    }
    
    HASH_BANG_MAP: Dict[str, str] = {
        'python': '#!/usr/bin/python',
        'python3': '#!/usr/bin/python3',
        'node': '#!/usr/bin/node',
        'nodejs': '#!/usr/bin/nodejs',
        'ruby': '#!/usr/bin/ruby',
        'perl': '#!/usr/bin/perl',
        'bash': '#!/bin/bash',
        'sh': '#!/bin/sh',
    }
    
    SHEBANG_LANGUAGES = {
        'python', 'python3', 'node', 'nodejs', 'ruby', 'perl', 'bash', 'sh'
    }
    
    def detect_from_path(self, file_path: str) -> Optional[str]:
        """Detect language from file extension.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Language identifier (e.g., 'python', 'javascript') or None
        """
        path = Path(file_path)
        extension = path.suffix.lower()
        return self.EXTENSION_MAP.get(extension)
    
    def detect_language(self, file_path: str, source: str = "") -> Optional[str]:
        """Detect language from file path and optionally content.
        
        Args:
            file_path: Path to the file
            source: Optional source code content for deeper detection
            
        Returns:
            Language identifier or None
        """
        lang = self.detect_from_path(file_path)
        if lang:
            return lang
        
        if source:
            lang = self._detect_from_content(source)
            if lang:
                return lang
        
        return None
    
    def _detect_from_content(self, source: str) -> Optional[str]:
        """Detect language from source content.
        
        Args:
            source: Source code content
            
        Returns:
            Language identifier or None
        """
        lines = source.split('\n')
        if not lines:
            return None
        
        first_line = lines[0].strip()
        
        if first_line.startswith('#!'):
            return self._detect_from_shebang(first_line)
        
        if self._looks_like_python(source):
            return 'python'
        
        if self._looks_like_javascript(source):
            return 'javascript'
        
        if self._looks_like_typescript(source):
            return 'typescript'
        
        return None
    
    def _detect_from_shebang(self, shebang: str) -> Optional[str]:
        """Detect language from shebang line."""
        shebang_lower = shebang.lower()
        
        for lang, pattern in self.HASH_BANG_MAP.items():
            if pattern in shebang_lower:
                if lang in ('python', 'python3'):
                    return 'python'
                elif lang in ('node', 'nodejs'):
                    return 'javascript'
                elif lang == 'ruby':
                    return 'ruby'
                elif lang == 'perl':
                    return 'perl'
                elif lang in ('bash', 'sh'):
                    return 'bash'
        
        return None
    
    def _looks_like_python(self, source: str) -> bool:
        """Heuristic check for Python code."""
        python_indicators = [
            'import ',
            'from ',
            'def ',
            'class ',
            'if __name__',
            'print(',
            'self.',
            'elif ',
        ]
        
        score = sum(1 for indicator in python_indicators if indicator in source)
        return score >= 2
    
    def _looks_like_javascript(self, source: str) -> bool:
        """Heuristic check for JavaScript code."""
        js_indicators = [
            'const ',
            'let ',
            'var ',
            'function ',
            '=> ',
            'require(',
            'module.exports',
            'console.log',
            'async function',
            'import ',
            'export ',
        ]
        
        score = sum(1 for indicator in js_indicators if indicator in source)
        return score >= 2
    
    def _looks_like_typescript(self, source: str) -> bool:
        """Heuristic check for TypeScript code."""
        ts_indicators = [
            ': string',
            ': number',
            ': boolean',
            ': any',
            'interface ',
            'type ',
            'as ',
            '<T>',
            'import type',
            'export type',
        ]
        
        score = sum(1 for indicator in ts_indicators if indicator in source)
        return score >= 2
    
    def get_supported_extensions(self) -> Set[str]:
        """Get all supported file extensions."""
        return set(self.EXTENSION_MAP.keys())
    
    def is_supported(self, file_path: str) -> bool:
        """Check if a file type is supported."""
        return self.detect_from_path(file_path) is not None
