"""LLM-powered analysis modules for CodeSentinel.

This module provides LLM-based analysis capabilities including:
- LLM code analysis (OpenAI, Anthropic, Gemini)
- Rich context building for findings
- Natural language rule parsing
- Finding enrichment with explanations
- Organization-specific style guides
"""
from .code_analyzer import LLMAnalyzer
from .context_builder import ContextBuilder
from .rule_parser import NaturalLanguageRuleParser
from .finding_enricher import FindingEnricher

try:
    from .style_guide import StyleGuide, StyleGuideLoader
    _has_style_guide = True
except ImportError:
    _has_style_guide = False

__all__ = [
    'LLMAnalyzer',
    'ContextBuilder',
    'NaturalLanguageRuleParser',
    'FindingEnricher',
]
if _has_style_guide:
    __all__.extend(['StyleGuide', 'StyleGuideLoader'])
