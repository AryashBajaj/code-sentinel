"""Style guide support for CodeSentinel.

Loads and manages organization-specific coding standards and rules.
"""
from __future__ import annotations

import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class StyleRule:
    """A single style guide rule."""
    id: str
    description: str
    pattern: str
    severity: str = 'WARNING'
    languages: List[str] = field(default_factory=list)
    fix: Optional[str] = None


@dataclass
class StyleGuide:
    """Organization-specific style guide."""
    name: str
    version: str = "1.0"
    security_rules: List[StyleRule] = field(default_factory=list)
    code_quality_rules: List[StyleRule] = field(default_factory=list)
    performance_rules: List[StyleRule] = field(default_factory=list)
    custom_rules: Dict[str, Any] = field(default_factory=dict)
    
    def get_all_rules(self) -> List[StyleRule]:
        """Get all rules from the style guide."""
        return (
            self.security_rules + 
            self.code_quality_rules + 
            self.performance_rules
        )
    
    def get_rules_for_language(self, language: str) -> List[StyleRule]:
        """Get rules applicable to a specific language."""
        all_rules = self.get_all_rules()
        return [
            rule for rule in all_rules
            if not rule.languages or language in rule.languages
        ]


class StyleGuideLoader:
    """Loads style guides from files."""
    
    def __init__(self):
        self.loaded_guides: Dict[str, StyleGuide] = {}
    
    def load(self, path: str) -> StyleGuide:
        """Load a style guide from a YAML file.
        
        Args:
            path: Path to the style guide YAML file
            
        Returns:
            Loaded StyleGuide object
        """
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Style guide not found: {path}")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        return self._parse_style_guide(data)
    
    def load_directory(self, dir_path: str) -> Dict[str, StyleGuide]:
        """Load all style guides from a directory.
        
        Args:
            dir_path: Path to directory containing style guide YAML files
            
        Returns:
            Dict mapping guide names to StyleGuide objects
        """
        guides = {}
        dir_path = Path(dir_path)
        
        for yaml_file in dir_path.rglob('*.yaml'):
            try:
                guide = self.load(str(yaml_file))
                guides[guide.name] = guide
                self.loaded_guides[guide.name] = guide
            except Exception:
                continue
        
        for yml_file in dir_path.rglob('*.yml'):
            try:
                guide = self.load(str(yml_file))
                guides[guide.name] = guide
                self.loaded_guides[guide.name] = guide
            except Exception:
                continue
        
        return guides
    
    def _parse_style_guide(self, data: Dict[str, Any]) -> StyleGuide:
        """Parse YAML data into a StyleGuide object."""
        name = data.get('name', 'Unnamed Style Guide')
        version = data.get('version', '1.0')
        
        security_rules = []
        for rule_data in data.get('security_baseline', []):
            rule = self._parse_rule(rule_data, 'security')
            if rule:
                security_rules.append(rule)
        
        quality_rules = []
        for rule_data in data.get('code_quality', []):
            rule = self._parse_rule(rule_data, 'quality')
            if rule:
                quality_rules.append(rule)
        
        perf_rules = []
        for rule_data in data.get('performance', []):
            rule = self._parse_rule(rule_data, 'performance')
            if rule:
                perf_rules.append(rule)
        
        return StyleGuide(
            name=name,
            version=version,
            security_rules=security_rules,
            code_quality_rules=quality_rules,
            performance_rules=perf_rules,
            custom_rules=data.get('custom', {})
        )
    
    def _parse_rule(self, rule_data: Dict[str, Any], category: str) -> Optional[StyleRule]:
        """Parse a rule from YAML data."""
        rule_id = rule_data.get('id')
        if not rule_id:
            return None
        
        description = rule_data.get('description', '')
        pattern = rule_data.get('pattern', '')
        severity = rule_data.get('severity', 'WARNING')
        languages = rule_data.get('languages', [])
        fix = rule_data.get('fix')
        
        return StyleRule(
            id=rule_id,
            description=description,
            pattern=pattern,
            severity=severity,
            languages=languages,
            fix=fix
        )
    
    def get_loaded_guide(self, name: str) -> Optional[StyleGuide]:
        """Get a previously loaded guide by name."""
        return self.loaded_guides.get(name)
    
    def get_default_guide(self) -> StyleGuide:
        """Get or create the default style guide."""
        if 'default' in self.loaded_guides:
            return self.loaded_guides['default']
        
        return StyleGuide(
            name='default',
            version='1.0',
            security_rules=self._default_security_rules(),
            code_quality_rules=self._default_quality_rules(),
        )
    
    def _default_security_rules(self) -> List[StyleRule]:
        """Get default security rules."""
        return [
            StyleRule(
                id='default-no-eval',
                description='eval() is dangerous and should not be used',
                pattern='eval(',
                severity='ERROR',
                languages=['python']
            ),
            StyleRule(
                id='default-no-exec',
                description='exec() is dangerous and should not be used',
                pattern='exec(',
                severity='ERROR',
                languages=['python']
            ),
            StyleRule(
                id='default-no-shell-injection',
                description='shell=True allows command injection',
                pattern='shell=True',
                severity='ERROR',
                languages=['python']
            ),
        ]
    
    def _default_quality_rules(self) -> List[StyleRule]:
        """Get default code quality rules."""
        return [
            StyleRule(
                id='default-no-bare-except',
                description='Bare except clauses catch all exceptions',
                pattern='except:',
                severity='WARNING',
                languages=['python']
            ),
            StyleRule(
                id='default-no-print',
                description='Use logging instead of print for production code',
                pattern='print(',
                severity='INFO',
                languages=['python']
            ),
        ]
