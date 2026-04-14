"""Finding enricher for LLM-powered analysis.

Enriches static analysis findings with LLM-generated explanations,
fix suggestions, and severity adjustments.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class EnrichedFinding:
    """A finding enriched with LLM analysis."""
    original: Dict[str, Any]
    llm_explanation: Optional[str] = None
    llm_fix_example: Optional[str] = None
    llm_severity_adjustment: Optional[str] = None
    related_issues: List[str] = field(default_factory=list)
    confidence: str = 'medium'
    false_positive_likelihood: float = 0.0


class FindingEnricher:
    """Enriches findings with LLM-generated context and explanations.
    
    This class takes raw static analysis findings and enhances them
    with LLM-powered analysis to provide:
    - Clear explanations of why something is dangerous
    - Code examples of how to fix the issue
    - Severity adjustments based on context
    - Related issues that might also be present
    """
    
    def __init__(self, llm_analyzer=None):
        self.llm_analyzer = llm_analyzer
    
    def enrich_finding(self, finding: Dict[str, Any]) -> EnrichedFinding:
        """Enrich a single finding with LLM analysis.
        
        Args:
            finding: The original finding from static analysis
            
        Returns:
            EnrichedFinding with LLM-generated content
        """
        enriched = EnrichedFinding(original=finding)
        
        if self.llm_analyzer:
            enriched = self._llm_enrich(finding)
        
        return enriched
    
    def enrich_findings(self, findings: List[Dict[str, Any]]) -> List[EnrichedFinding]:
        """Enrich multiple findings.
        
        Args:
            findings: List of findings from static analysis
            
        Returns:
            List of EnrichedFinding objects
        """
        return [self.enrich_finding(f) for f in findings]
    
    def _llm_enrich(self, finding: Dict[str, Any]) -> EnrichedFinding:
        """Use LLM to enrich a finding."""
        enriched = EnrichedFinding(original=finding)
        
        context = self._build_context(finding)
        
        prompt = self._build_prompt(context, finding)
        
        try:
            response = self._call_llm(prompt)
            self._parse_response(response, enriched)
        except Exception:
            pass
        
        return enriched
    
    def _build_context(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Build context for LLM analysis."""
        return {
            'file': finding.get('file', 'unknown'),
            'line': finding.get('line', 0),
            'code': finding.get('matched_code', ''),
            'rule_id': finding.get('id', ''),
            'category': finding.get('category', ''),
            'severity': finding.get('severity', 'medium'),
            'message': finding.get('message', ''),
        }
    
    def _build_prompt(self, context: Dict[str, Any], finding: Dict[str, Any]) -> str:
        """Build LLM prompt for finding enrichment."""
        return f"""Analyze this code security finding and provide additional context.

Finding Details:
- File: {context['file']}
- Line: {context['line']}
- Code: {context['code']}
- Rule ID: {context['rule_id']}
- Category: {context['category']}
- Current Severity: {context['severity']}
- Message: {context['message']}

Please provide:
1. A clear explanation of why this is dangerous in this specific context
2. A code example showing how to fix it
3. Whether the severity should be adjusted (higher/lower) based on context
4. Any related security issues that might also be present

Respond in JSON format:
{{
    "explanation": "why this is dangerous...",
    "fix_example": "example code to fix...",
    "severity_adjustment": "higher/lower/same",
    "adjusted_severity": "HIGH/MEDIUM/LOW",
    "related_issues": ["related issue 1", "related issue 2"],
    "confidence": "high/medium/low"
}}"""
    
    def _call_llm(self, prompt: str) -> str:
        """Call the LLM with the prompt."""
        if not self.llm_analyzer:
            return "{}"
        
        try:
            result = self.llm_analyzer.analyze(prompt)
            return result
        except Exception:
            return "{}"
    
    def _parse_response(self, response: str, enriched: EnrichedFinding) -> None:
        """Parse LLM response into enriched finding."""
        try:
            data = json.loads(response)
            enriched.llm_explanation = data.get('explanation')
            enriched.llm_fix_example = data.get('fix_example')
            
            adjustment = data.get('severity_adjustment', '').lower()
            if adjustment in ('higher', 'lower', 'same'):
                enriched.llm_severity_adjustment = adjustment
                enriched.original['adjusted_severity'] = data.get('adjusted_severity', 
                                                                enriched.original.get('severity'))
            
            enriched.related_issues = data.get('related_issues', [])
            enriched.confidence = data.get('confidence', 'medium')
            
        except (json.JSONDecodeError, KeyError):
            pass
    
    def get_explanation(self, finding: Dict[str, Any]) -> str:
        """Get a human-readable explanation for a finding.
        
        Args:
            finding: The finding to explain
            
        Returns:
            String explanation of the finding
        """
        rule_explanations = {
            'TAINT001': 'User-controlled data flows to a dangerous operation',
            'SQL001': 'SQL query may be vulnerable to injection',
            'CMD001': 'Command execution with user input may allow injection',
            'XSS001': 'Unescaped user input in HTML output',
            'AUTH001': 'Authentication may be bypassed',
        }
        
        rule_id = finding.get('id', '')
        return rule_explanations.get(rule_id, finding.get('message', 'Security issue detected'))
    
    def suggest_fix(self, finding: Dict[str, Any]) -> Optional[str]:
        """Suggest a fix for the finding.
        
        Args:
            finding: The finding to fix
            
        Returns:
            Suggested fix code or None
        """
        code = finding.get('matched_code', '')
        rule_id = finding.get('id', '')
        
        fixes = {
            'TAINT001': self._fix_taint,
            'os.system': lambda c: 'subprocess.run({}, shell=False)'.format(c),
            'eval(': lambda c: 'ast.literal_eval({})'.format(c),
            'pickle.loads': lambda c: 'json.loads() or marshal.loads()',
            'subprocess.run': lambda c: c.replace('shell=True', 'shell=False'),
        }
        
        for key, fix_fn in fixes.items():
            if key in code:
                if callable(fix_fn):
                    return fix_fn(code)
                return fix_fn
        
        return None
    
    def _fix_taint(self, code: str) -> str:
        """Generate fix for taint-related findings."""
        if 'os.system' in code:
            return code.replace('os.system', 'subprocess.run')
        return 'Sanitize user input before use'
