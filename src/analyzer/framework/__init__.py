"""Framework-specific analyzers for CodeSentinel.

Provides deep analysis for:
- Python: Flask, Django, FastAPI (using Python AST)
- JavaScript: Express, Next.js (using tree-sitter AST)
"""
from .flask_ast import FlaskAstAnalyzer as FlaskAnalyzer
from .django_ast import DjangoAstAnalyzer as DjangoAnalyzer
from .fastapi_ast import FastApiAstAnalyzer as FastAPIAnalyzer
from .express_ast import ExpressAstAnalyzer as ExpressAnalyzer
from .nextjs_ast import NextJSAstAnalyzer as NextJSAnalyzer

__all__ = [
    'FlaskAnalyzer',
    'DjangoAnalyzer', 
    'FastAPIAnalyzer',
    'ExpressAnalyzer',
    'NextJSAnalyzer',
]
