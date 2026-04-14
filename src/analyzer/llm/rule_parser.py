"""Natural language rule parser for CodeSentinel.

Parses custom rules written in natural language and converts them
to executable patterns.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class NaturalLanguageRule:
    """A rule parsed from natural language description."""
    name: str
    description: str
    severity: str
    languages: Set[str]
    pattern_keywords: List[str] = field(default_factory=list)
    dangerous_patterns: List[str] = field(default_factory=list)
    safe_patterns: List[str] = field(default_factory=list)
    validation_required: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    owasp: List[str] = field(default_factory=list)
    cwe: List[str] = field(default_factory=list)


class NaturalLanguageRuleParser:
    """Parses natural language rules into structured rule objects.
    
    Example input:
        Rule: SQL injection through unsanitized user input
        Severity: CRITICAL
        Languages: [python, javascript]
        Description: |
            SQL queries built from user input without proper parameterization
            can allow attackers to inject malicious SQL code.
        
        Dangerous Patterns:
            - "SELECT * FROM users WHERE id=" + user_id
            - cursor.execute("SELECT ..." + request.args.get('id'))
            - db.query("SELECT ..." + req.body.id)
        
        Validation Required:
            - Use parameterized queries
            - ORM methods instead of raw SQL
            - Input validation and sanitization
    """
    
    SEVERITY_MAP = {
        'critical': 'CRITICAL',
        'high': 'HIGH',
        'medium': 'MEDIUM',
        'low': 'LOW',
    }
    
    def __init__(self):
        self.rules: List[NaturalLanguageRule] = []
    
    def parse(self, rule_text: str) -> List[NaturalLanguageRule]:
        """Parse natural language rules from text.
        
        Args:
            rule_text: Text containing one or more natural language rules
            
        Returns:
            List of parsed NaturalLanguageRule objects
        """
        self.rules = []
        
        rule_blocks = self._split_rules(rule_text)
        
        for block in rule_blocks:
            rule = self._parse_rule_block(block)
            if rule:
                self.rules.append(rule)
        
        return self.rules
    
    def _split_rules(self, text: str) -> List[str]:
        """Split text into individual rule blocks."""
        blocks = []
        current = []
        
        for line in text.split('\n'):
            if line.strip().startswith('Rule:') and current:
                blocks.append('\n'.join(current))
                current = []
            current.append(line)
        
        if current:
            blocks.append('\n'.join(current))
        
        return blocks
    
    def _parse_rule_block(self, block: str) -> Optional[NaturalLanguageRule]:
        """Parse a single rule block."""
        lines = block.strip().split('\n')
        if not lines:
            return None
        
        name = self._extract_field(lines, 'Rule:', 'name')
        if not name:
            return None
        
        severity = self._extract_severity(lines)
        languages = self._extract_languages(lines)
        description = self._extract_description(lines)
        dangerous = self._extract_list(lines, 'Dangerous Patterns:')
        safe = self._extract_list(lines, 'Safe Patterns:')
        validation = self._extract_validation(lines)
        examples = self._extract_list(lines, 'Example:')
        
        keywords = self._extract_keywords(description, dangerous)
        
        return NaturalLanguageRule(
            name=name,
            description=description,
            severity=severity,
            languages=languages,
            pattern_keywords=keywords,
            dangerous_patterns=dangerous,
            safe_patterns=safe,
            validation_required=validation,
            examples=examples
        )
    
    def _extract_field(self, lines: List[str], prefix: str, field_name: str) -> Optional[str]:
        """Extract a field value from lines."""
        for line in lines:
            if line.strip().startswith(prefix):
                value = line.strip()[len(prefix):].strip()
                if field_name == 'name':
                    return value
        return None
    
    def _extract_severity(self, lines: List[str]) -> str:
        """Extract severity level."""
        for line in lines:
            if 'Severity:' in line:
                severity = line.split('Severity:')[1].strip().lower()
                return self.SEVERITY_MAP.get(severity, 'MEDIUM')
        return 'MEDIUM'
    
    def _extract_languages(self, lines: List[str]) -> Set[str]:
        """Extract languages from lines."""
        languages = set()
        in_languages = False
        
        for line in lines:
            if 'Languages:' in line:
                in_languages = True
                lang_content = line.split('Languages:')[1].strip()
                if '[' in lang_content:
                    lang_content = lang_content[lang_content.index('['):]
                    langs = self._parse_language_list(lang_content)
                    languages.update(langs)
            elif in_languages:
                langs = self._parse_language_list(line)
                if langs:
                    languages.update(langs)
                elif ']' in line:
                    in_languages = False
                elif line.strip().startswith('-'):
                    continue
                elif line.strip() and not line.strip().startswith('#'):
                    in_languages = False
        
        if not languages:
            languages = {'python', 'javascript', 'typescript'}
        
        return languages
    
    def _parse_language_list(self, text: str) -> Set[str]:
        """Parse a language list from text."""
        langs = set()
        text = text.strip()
        
        text = text.strip('[]')
        
        for lang in text.replace(',', ' ').split():
            lang = lang.strip().strip('"\',')
            if lang.lower() in ('python', 'javascript', 'js', 'typescript', 'ts', 'go', 'java', 'rust', 'c', 'c++', 'ruby', 'php'):
                lang_map = {'js': 'javascript', 'ts': 'typescript'}
                langs.add(lang_map.get(lang.lower(), lang.lower()))
        
        return langs
    
    def _extract_description(self, lines: List[str]) -> str:
        """Extract rule description."""
        description_lines = []
        in_description = False
        
        for line in lines:
            if 'Description:' in line:
                in_description = True
                desc = line.split('Description:')[1].strip()
                if desc:
                    description_lines.append(desc)
            elif in_description:
                stripped = line.strip()
                if not stripped or stripped.startswith('Dangerous') or stripped.startswith('Safe') or stripped.startswith('Validation'):
                    break
                if stripped.startswith('- '):
                    description_lines.append(stripped[2:])
                else:
                    description_lines.append(stripped)
        
        return ' '.join(description_lines)
    
    def _extract_list(self, lines: List[str], section_header: str) -> List[str]:
        """Extract a list section from lines."""
        items = []
        in_section = False
        
        for line in lines:
            if section_header in line:
                in_section = True
                content = line.split(section_header)[1].strip()
                if content.startswith('-'):
                    items.append(content[1:].strip())
            elif in_section:
                stripped = line.strip()
                if not stripped or stripped.startswith('Example') or stripped.startswith('Validation') or stripped.startswith('Rule:'):
                    break
                if stripped.startswith('-'):
                    items.append(stripped[1:].strip())
        
        return items
    
    def _extract_validation(self, lines: List[str]) -> List[str]:
        """Extract validation requirements."""
        return self._extract_list(lines, 'Validation Required:')
    
    def _extract_keywords(self, description: str, dangerous: List[str]) -> List[str]:
        """Extract keywords for pattern matching."""
        keywords = []
        
        dangerous_lower = [d.lower() for d in dangerous]
        keywords.extend([d for d in dangerous_lower if len(d) > 3])
        
        description_words = re.findall(r'\b\w{4,}\b', description.lower())
        important_keywords = ['sql', 'input', 'query', 'execute', 'eval', 'exec', 'system', 
                            'command', 'injection', 'sanitize', 'validate', 'parameter']
        for word in description_words:
            if any(k in word for k in important_keywords):
                keywords.append(word)
        
        return list(set(keywords))
    
    def to_dict(self) -> List[Dict[str, Any]]:
        """Convert rules to dictionary format."""
        return [
            {
                'name': rule.name,
                'description': rule.description,
                'severity': rule.severity,
                'languages': list(rule.languages),
                'keywords': rule.pattern_keywords,
                'dangerous_patterns': rule.dangerous_patterns,
                'safe_patterns': rule.safe_patterns,
                'validation_required': rule.validation_required,
            }
            for rule in self.rules
        ]
