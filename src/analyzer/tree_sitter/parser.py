"""Tree-sitter based multi-language parser for CodeSentinel.

Provides parsing capabilities for:
- Python
- JavaScript
- TypeScript
- And any other language supported by tree-sitter-languages
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
import tree_sitter_languages

from .language_detector import LanguageDetector
from .ast_converter import ASTConverter, GenericASTNode


@dataclass
class ParsedFile:
    file_path: str
    language: str
    source: str
    tree: Any
    root_node: Optional[GenericASTNode] = None
    functions: List[GenericASTNode] = field(default_factory=list)
    classes: List[GenericASTNode] = field(default_factory=list)
    calls: List[GenericASTNode] = field(default_factory=list)
    imports: List[GenericASTNode] = field(default_factory=list)
    assignments: List[GenericASTNode] = field(default_factory=list)


class TreeSitterParser:
    """Multi-language parser using tree-sitter.
    
    Usage:
        parser = TreeSitterParser()
        result = parser.parse_file("path/to/file.py")
        result = parser.parse_file("path/to/file.js")
        result = parser.parse_directory("path/to/project")
    """
    
    LANGUAGE_MAP = {
        'python': 'python',
        'py': 'python',
        'javascript': 'javascript',
        'js': 'javascript',
        'jsx': 'javascript',
        'typescript': 'typescript',
        'ts': 'typescript',
        'tsx': 'typescript',
        'go': 'go',
        'rust': 'rust',
        'java': 'java',
        'c': 'c',
        'cpp': 'cpp',
        'csharp': 'c_sharp',
        'ruby': 'ruby',
        'php': 'php',
    }
    
    def __init__(self):
        self.language_detector = LanguageDetector()
        self._parsers: Dict[str, Any] = {}
        self._languages: Dict[str, Any] = {}
    
    def _get_parser(self, language: str):
        """Get or create a parser for the given language."""
        if language not in self._parsers:
            try:
                lang_code = self.LANGUAGE_MAP.get(language, language)
                parser = tree_sitter_languages.get_parser(lang_code)
                self._parsers[language] = parser
                self._languages[language] = tree_sitter_languages.get_language(lang_code)
            except Exception as e:
                raise ValueError(f"Unsupported language: {language}. Error: {e}")
        return self._parsers[language]
    
    def parse_file(self, file_path: str) -> Optional[ParsedFile]:
        """Parse a single file.
        
        Args:
            file_path: Path to the file to parse
            
        Returns:
            ParsedFile object with AST and extracted information, or None if parsing fails
        """
        path = Path(file_path)
        if not path.exists():
            return None
        
        try:
            source = path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return None
        
        language = self.language_detector.detect_language(file_path, source)
        if not language:
            return None
        
        return self.parse(source, language, file_path)
    
    def parse(self, source: str, language: str, file_path: str = "") -> Optional[ParsedFile]:
        """Parse source code string.
        
        Args:
            source: Source code as string
            language: Language identifier (e.g., 'python', 'javascript')
            file_path: Optional file path for reference
            
        Returns:
            ParsedFile object with AST and extracted information
        """
        try:
            lang_code = self.LANGUAGE_MAP.get(language, language)
            parser = self._get_parser(lang_code)
            tree = parser.parse(bytes(source, 'utf-8'))
            
            result = ParsedFile(
                file_path=file_path,
                language=language,
                source=source,
                tree=tree,
                root_node=None
            )
            
            converter = ASTConverter(language)
            result.root_node = converter.convert(tree.root_node)
            result.functions = converter.extract_functions(tree.root_node, source)
            result.classes = converter.extract_classes(tree.root_node, source)
            result.calls = converter.extract_calls(tree.root_node, source)
            result.imports = converter.extract_imports(tree.root_node, source)
            result.assignments = converter.extract_assignments(tree.root_node, source)
            
            return result
            
        except Exception as e:
            return None
    
    def parse_directory(self, dir_path: str, extensions: Optional[Set[str]] = None) -> List[ParsedFile]:
        """Parse all supported files in a directory.
        
        Args:
            dir_path: Path to directory to parse
            extensions: Optional set of file extensions to include (e.g., {'.py', '.js'})
                      If None, all supported languages are parsed.
        
        Returns:
            List of ParsedFile objects for each successfully parsed file
        """
        results = []
        path = Path(dir_path)
        
        if not path.is_dir():
            return results
        
        for file_path in path.rglob('*'):
            if not file_path.is_file():
                continue
            
            if extensions and file_path.suffix not in extensions:
                continue
            
            parsed = self.parse_file(str(file_path))
            if parsed:
                results.append(parsed)
        
        return results
    
    def get_supported_languages(self) -> List[str]:
        """Get list of supported language names."""
        return list(set(self.LANGUAGE_MAP.keys()))
    
    def detect_language(self, file_path: str) -> Optional[str]:
        """Detect language from file path.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Language identifier or None if not supported
        """
        return self.language_detector.detect_from_path(file_path)


def parse_file(file_path: str) -> Optional[ParsedFile]:
    """Convenience function to parse a single file."""
    parser = TreeSitterParser()
    return parser.parse_file(file_path)


def parse_directory(dir_path: str, extensions: Optional[Set[str]] = None) -> List[ParsedFile]:
    """Convenience function to parse all files in a directory."""
    parser = TreeSitterParser()
    return parser.parse_directory(dir_path, extensions)
