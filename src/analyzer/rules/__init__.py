"""Rule system for CodeSentinel.

This module provides a rule engine for security and quality analysis:
- Base rule classes
- YAML rule loading (Semgrep-compatible format)
- Python and JavaScript security rules
"""
from .base import BaseRule, RuleResult, RuleSeverity
from .loader import RuleLoader

__all__ = [
    'BaseRule',
    'RuleResult',
    'RuleSeverity',
    'RuleLoader',
]
