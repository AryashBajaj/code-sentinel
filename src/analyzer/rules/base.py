"""Base rule classes for CodeSentinel rule system.

Provides abstract base classes and enums for defining security and quality rules.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class RuleSeverity(Enum):
    """Severity levels for rules."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RuleCategory(Enum):
    """Categories for rules."""
    SECURITY = "security"
    CORRECTNESS = "correctness"
    PERFORMANCE = "performance"
    MAINTAINABILITY = "maintainability"
    BEST_PRACTICE = "best-practice"


@dataclass
class RuleResult:
    """Result of applying a rule to code.
    
    Attributes:
        rule_id: Unique identifier for the rule that matched
        message: Human-readable message explaining the finding
        severity: Severity level of the finding
        file_path: Path to the file containing the finding
        line_number: Line number where the finding occurs
        column: Column number where the finding occurs
        matched_code: The specific code that matched the rule
        suggestion: Optional suggestion for fixing the issue
        metadata: Additional metadata about the finding
    """
    rule_id: str
    message: str
    severity: str
    file_path: str
    line_number: int
    column: int = 0
    matched_code: str = ""
    suggestion: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'id': self.rule_id,
            'message': self.message,
            'severity': self.severity,
            'file': self.file_path,
            'line': self.line_number,
            'column': self.column,
            'matched_code': self.matched_code,
            'suggestion': self.suggestion,
            'metadata': self.metadata,
        }


class BaseRule(ABC):
    """Abstract base class for all rules.
    
    Rules define patterns to detect in code and generate findings
    when those patterns are matched.
    
    Attributes:
        id: Unique identifier for the rule
        name: Human-readable name
        description: Detailed description of what the rule detects
        severity: Default severity level
        category: Category of the rule
        languages: Set of languages this rule applies to
    """
    
    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        severity: RuleSeverity = RuleSeverity.MEDIUM,
        category: RuleCategory = RuleCategory.SECURITY,
        languages: Optional[Set[str]] = None,
    ):
        self.id = rule_id
        self.name = name
        self.description = description
        self.severity = severity
        self.category = category
        self.languages = languages or {'python'}
    
    @abstractmethod
    def match(self, source: str, file_path: str, language: str) -> List[RuleResult]:
        """Check if the rule matches in the given source code.
        
        Args:
            source: Source code to check
            file_path: Path to the file (for reporting)
            language: Programming language of the source
            
        Returns:
            List of RuleResult objects for each match found
        """
        pass
    
    def applies_to_language(self, language: str) -> bool:
        """Check if this rule applies to the given language."""
        return language.lower() in self.languages or '*' in self.languages
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary representation."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'severity': self.severity.value,
            'category': self.category.value,
            'languages': list(self.languages),
        }


class PatternRule(BaseRule):
    """Rule that matches based on a regex pattern.
    
    Simple pattern matching rule that uses regular expressions
    to detect code patterns.
    """
    
    def __init__(
        self,
        rule_id: str,
        name: str,
        pattern: str,
        message: str,
        description: str = "",
        severity: RuleSeverity = RuleSeverity.MEDIUM,
        languages: Optional[Set[str]] = None,
        suggestion: Optional[str] = None,
    ):
        import re
        super().__init__(
            rule_id=rule_id,
            name=name,
            description=description or message,
            severity=severity,
            languages=languages,
        )
        self.pattern = re.compile(pattern)
        self.message = message
        self.suggestion = suggestion
    
    def match(self, source: str, file_path: str, language: str) -> List[RuleResult]:
        """Match the pattern against the source code."""
        if not self.applies_to_language(language):
            return []
        
        results = []
        for match in self.pattern.finditer(source):
            line_number = source[:match.start()].count('\n') + 1
            column = match.start() - source[:match.start()].rfind('\n')
            
            results.append(RuleResult(
                rule_id=self.id,
                message=self.message,
                severity=self.severity.value,
                file_path=file_path,
                line_number=line_number,
                column=column,
                matched_code=match.group(0),
                suggestion=self.suggestion,
                metadata={'pattern': self.pattern.pattern},
            ))
        
        return results


class CompositeRule(BaseRule):
    """Rule that combines multiple rules with AND/OR logic."""
    
    def __init__(
        self,
        rule_id: str,
        name: str,
        rules: List[BaseRule],
        operator: str = "AND",
        **kwargs,
    ):
        super().__init__(rule_id=rule_id, name=name, **kwargs)
        self.rules = rules
        self.operator = operator.upper()
    
    def match(self, source: str, file_path: str, language: str) -> List[RuleResult]:
        """Match based on the operator (AND/OR)."""
        if not self.applies_to_language(language):
            return []
        
        all_results = []
        for rule in self.rules:
            if not rule.applies_to_language(language):
                continue
            
            results = rule.match(source, file_path, language)
            
            if self.operator == "OR":
                all_results.extend(results)
            elif self.operator == "AND" and not results:
                return []
        
        return all_results
