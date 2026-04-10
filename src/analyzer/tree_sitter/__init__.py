"""Tree-sitter based multi-language parsing for CodeSentinel.

This module provides parsing capabilities for multiple programming languages
using tree-sitter, enabling CodeSentinel to analyze codebases beyond Python.

Supported Languages:
- Python (.py)
- JavaScript (.js, .jsx)
- TypeScript (.ts, .tsx)
- Go (.go)
- Rust (.rs)
- Java (.java)
- C/C++ (.c, .cpp)
- Ruby (.rb)
- And more via tree-sitter-languages

Usage:
    from analyzer.tree_sitter import TreeSitterParser, parse_file, parse_directory
    
    # Parse a single file
    result = parse_file("path/to/file.py")
    print(f"Functions: {[f.text for f in result.functions]}")
    
    # Parse entire directory
    results = parse_directory("path/to/project")
    for result in results:
        print(f"{result.file_path}: {len(result.functions)} functions")
"""
from .parser import TreeSitterParser, ParsedFile, parse_file, parse_directory
from .language_detector import LanguageDetector
from .ast_converter import GenericASTNode, ASTConverter

__all__ = [
    'TreeSitterParser',
    'ParsedFile', 
    'parse_file',
    'parse_directory',
    'LanguageDetector',
    'GenericASTNode',
    'ASTConverter',
]
