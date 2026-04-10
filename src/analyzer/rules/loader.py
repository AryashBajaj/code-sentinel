"""Rule loader for CodeSentinel.

Loads rules from YAML files in Semgrep-compatible format.
"""
from __future__ import annotations

import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .base import BaseRule, PatternRule, RuleSeverity, RuleCategory


class RuleLoader:
    """Loads rules from YAML files.
    
    Supports Semgrep-compatible YAML format:
    
    Example:
        rules:
          - id: python.lang.security.subprocess-shell
            pattern: subprocess.$FUNC(..., shell=True, ...)
            message: Found subprocess with shell=True
            severity: ERROR
            languages: [python]
    """
    
    def __init__(self):
        self.loaded_rules: List[BaseRule] = []
    
    def load_file(self, path: str) -> List[BaseRule]:
        """Load rules from a YAML file.
        
        Args:
            path: Path to YAML rule file
            
        Returns:
            List of loaded BaseRule objects
        """
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Rule file not found: {path}")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        rules = self._parse_rules(data)
        self.loaded_rules.extend(rules)
        return rules
    
    def load_directory(self, dir_path: str, pattern: str = "*.yaml") -> List[BaseRule]:
        """Load all rule files from a directory.
        
        Args:
            dir_path: Path to directory containing rule files
            pattern: Glob pattern for matching files
            
        Returns:
            List of all loaded BaseRule objects
        """
        rules = []
        directory = Path(dir_path)
        
        for yaml_file in directory.rglob(pattern):
            try:
                file_rules = self.load_file(str(yaml_file))
                rules.extend(file_rules)
            except Exception:
                continue
        
        for yaml_file in directory.rglob("*.yml"):
            try:
                file_rules = self.load_file(str(yaml_file))
                rules.extend(file_rules)
            except Exception:
                continue
        
        return rules
    
    def _parse_rules(self, data: Dict[str, Any]) -> List[BaseRule]:
        """Parse rules from YAML data."""
        rules = []
        rules_data = data.get('rules', [])
        
        for rule_data in rules_data:
            rule = self._parse_rule(rule_data)
            if rule:
                rules.append(rule)
        
        return rules
    
    def _parse_rule(self, data: Dict[str, Any]) -> Optional[BaseRule]:
        """Parse a single rule from YAML data."""
        rule_id = data.get('id')
        if not rule_id:
            return None
        
        pattern = data.get('pattern')
        patterns = data.get('patterns', [])
        
        message = data.get('message', 'Security issue detected')
        description = data.get('description', message)
        severity = self._parse_severity(data.get('severity', 'WARNING'))
        languages = self._parse_languages(data.get('languages', ['python']))
        
        fix = data.get('fix')
        
        metadata = data.get('metadata', {})
        category = self._parse_category(metadata.get('category', 'security'))
        
        if pattern:
            return PatternRule(
                rule_id=rule_id,
                name=rule_id,
                pattern=pattern,
                message=message,
                description=description,
                severity=severity,
                languages=languages,
                suggestion=fix,
            )
        
        elif patterns:
            return PatternRule(
                rule_id=rule_id,
                name=rule_id,
                pattern=self._patterns_to_regex(patterns),
                message=message,
                description=description,
                severity=severity,
                languages=languages,
                suggestion=fix,
            )
        
        return None
    
    def _parse_severity(self, severity: str) -> RuleSeverity:
        """Parse severity string to RuleSeverity enum."""
        severity_map = {
            'CRITICAL': RuleSeverity.CRITICAL,
            'ERROR': RuleSeverity.HIGH,
            'HIGH': RuleSeverity.HIGH,
            'WARNING': RuleSeverity.MEDIUM,
            'MEDIUM': RuleSeverity.MEDIUM,
            'INFO': RuleSeverity.LOW,
            'LOW': RuleSeverity.LOW,
        }
        return severity_map.get(severity.upper(), RuleSeverity.MEDIUM)
    
    def _parse_languages(self, languages: Any) -> Set[str]:
        """Parse languages list."""
        if isinstance(languages, str):
            return {languages.lower()}
        if isinstance(languages, list):
            return {lang.lower() for lang in languages}
        return {'python'}
    
    def _parse_category(self, category: str) -> RuleCategory:
        """Parse category string to RuleCategory enum."""
        category_map = {
            'security': RuleCategory.SECURITY,
            'correctness': RuleCategory.CORRECTNESS,
            'performance': RuleCategory.PERFORMANCE,
            'maintainability': RuleCategory.MAINTAINABILITY,
            'best-practice': RuleCategory.BEST_PRACTICE,
            'best_practice': RuleCategory.BEST_PRACTICE,
        }
        return category_map.get(category.lower(), RuleCategory.SECURITY)
    
    def _patterns_to_regex(self, patterns: List[Any]) -> str:
        """Convert Semgrep patterns list to a single regex.
        
        This is a simplified conversion - full Semgrep pattern
        support requires the actual Semgrep engine.
        """
        import re
        
        combined = []
        for pattern in patterns:
            if isinstance(pattern, dict):
                p = pattern.get('pattern', '')
            else:
                p = str(pattern)
            
            p = p.replace('...', '.*?')
            p = re.escape(p)
            combined.append(p)
        
        return '|'.join(combined)
    
    def get_rules_for_language(self, language: str) -> List[BaseRule]:
        """Get all loaded rules applicable to a specific language."""
        return [rule for rule in self.loaded_rules if rule.applies_to_language(language)]
    
    def get_rules_by_category(self, category: RuleCategory) -> List[BaseRule]:
        """Get all loaded rules in a specific category."""
        return [rule for rule in self.loaded_rules if rule.category == category]
    
    def get_rules_by_severity(self, severity: RuleSeverity) -> List[BaseRule]:
        """Get all loaded rules at or above a severity level."""
        severity_order = {
            RuleSeverity.CRITICAL: 4,
            RuleSeverity.HIGH: 3,
            RuleSeverity.MEDIUM: 2,
            RuleSeverity.LOW: 1,
            RuleSeverity.INFO: 0,
        }
        
        threshold = severity_order.get(severity, 0)
        return [
            rule for rule in self.loaded_rules
            if severity_order.get(rule.severity, 0) >= threshold
        ]
