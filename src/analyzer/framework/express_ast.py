"""Express.js AST-based analyzer using tree-sitter.

Production-grade security checks for Express.js applications using
tree-sitter AST parsing for accurate, robust analysis.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Set, Optional
import warnings

from ..tree_sitter.parser import TreeSitterParser, ParsedFile
from .dedup import DedupMixin


class ExpressAstAnalyzer:
    """Security analyzer for Express.js applications using tree-sitter AST."""
    
    SENSITIVE_PATTERNS = {'password', 'secret', 'key', 'token', 'credential', 'api_key'}
    
    def __init__(self):
        self.parser = TreeSitterParser()
        self.findings: List[Dict[str, Any]] = []
        self.dedup = DedupMixin()
        self.dedup.file_path = Path("")
        self.dedup.source = ""
    
    def analyze(self, source: str, file_path: str) -> List[Dict[str, Any]]:
        """Analyze Express.js code for security issues.
        
        Args:
            source: Source code to analyze
            file_path: Path to the source file
            
        Returns:
            List of security findings
        """
        self.findings = []
        self.dedup._dedup_seen = set()
        self.dedup.file_path = Path(file_path)
        self.dedup.source = source
        
        try:
            result = self.parser.parse(source, 'javascript', file_path)
            if result:
                self._visit_file(result, source)
        except Exception:
            pass
        
        self._check_hardcoded_secrets(source)
        
        return self.findings
    
    def _visit_file(self, parsed: ParsedFile, source: str) -> None:
        """Visit all nodes in the parsed file."""
        if parsed.root_node:
            self._walk_node(parsed.root_node, source)
    
    def _walk_node(self, node, source: str) -> None:
        """Recursively walk AST nodes."""
        node_type = node.node_type
        
        if node_type == 'call_expression':
            self._check_call(node, source)
        elif node_type == 'identifier':
            self._check_identifier(node, source)
        
        for child in node.children:
            self._walk_node(child, source)
    
    def _check_call(self, node, source: str) -> None:
        """Check call expressions for security issues."""
        func_name = self._get_callee_name(node)
        line = node.line_number
        text = node.text if hasattr(node, 'text') else ''
        
        if not func_name:
            return
        
        if func_name == 'helmet':
            pass
        elif func_name == 'require':
            self._check_dangerous_require(node, source)
        elif 'cookie' in func_name.lower():
            self._check_cookie_settings(node, source)
        elif 'cors' in func_name.lower():
            self._check_cors(node, source)
        elif func_name in ('eval', 'Function'):
            self._add_finding('EXPRESS005', line, 'critical', 
                            f'Dangerous code execution: {func_name}() is dangerous',
                            'Avoid dynamic code execution. Use safe alternatives.', source, node)
        elif 'query' in func_name.lower() or 'execute' in func_name.lower():
            self._check_sql_injection(node, source)
        elif 'send' in func_name.lower() or 'write' in func_name.lower() or 'render' in func_name.lower():
            self._check_xss(node, source)
        elif func_name == 'random' or 'Math.random' in text:
            self._check_insecure_random(node, source)
    
    def _get_callee_name(self, node) -> Optional[str]:
        """Get the function name from a call expression."""
        if hasattr(node, 'children') and node.children:
            callee = node.children[0] if node.children else None
            if callee and callee.node_type == 'identifier':
                return callee.text
            if callee and callee.node_type == 'member_expression':
                return self._get_member_name(callee)
        return None
    
    def _get_member_name(self, node) -> str:
        """Get name from member expression like console.log."""
        if hasattr(node, 'children') and node.children:
            parts = []
            for child in node.children:
                if child.node_type == 'identifier':
                    parts.append(child.text)
                elif child.node_type == 'property_identifier':
                    parts.append(child.text)
            return '.'.join(parts)
        return ''
    
    def _check_dangerous_require(self, node, source: str) -> None:
        """Check for dangerous require statements."""
        if hasattr(node, 'children') and len(node.children) >= 2:
            arg = node.children[1]
            if arg.text in ('"vm"', "'vm'", '"vm2"', "'vm2'"):
                self._add_finding('EXPRESS005', node.line_number, 'critical',
                                'VM module can be dangerous',
                                'Avoid dynamic code execution with VM module', source, node)
    
    def _check_cookie_settings(self, node, source: str) -> None:
        """Check for unsafe cookie settings."""
        has_secure = self._has_keyword(node, 'secure', 'true')
        has_httponly = self._has_keyword(node, 'httpOnly', 'true')
        
        if not (has_secure and has_httponly):
            self._add_finding('EXPRESS002', node.line_number, 'medium',
                            'Potentially unsafe cookie configuration: missing secure/httpOnly flags',
                            'Ensure cookies have secure, httpOnly, and sameSite flags set appropriately',
                            source, node)
    
    def _check_cors(self, node, source: str) -> None:
        """Check for insecure CORS configuration."""
        origin_text = self._get_cors_origin(node)
        if origin_text and ('*' in origin_text):
            self._add_finding('EXPRESS003', node.line_number, 'high',
                            'CORS configured with wildcard origin or with credentials',
                            'Use specific origins instead of "*" and ensure credentials are used safely',
                            source, node)
    
    def _get_cors_origin(self, node) -> Optional[str]:
        """Extract origin value from CORS call."""
        if hasattr(node, 'children'):
            for child in node.children:
                if hasattr(child, 'text') and 'origin' in child.text.lower():
                    return child.text
        return None
    
    def _has_keyword(self, node, key: str, value: str) -> bool:
        """Check if call has a keyword with specific value."""
        text = node.text if hasattr(node, 'text') else ''
        return f'{key}: {value}' in text or f'{key}:{value}' in text
    
    def _check_sql_injection(self, node, source: str) -> None:
        """Check for SQL injection patterns."""
        text = node.text if hasattr(node, 'text') else ''
        func_name = self._get_callee_name(node)
        
        is_query_call = func_name and 'query' in func_name.lower()
        
        if not is_query_call:
            return
        
        has_inline_concat = ('+' in text or '`' in text) and any(
            p in text for p in ['req.', 'request.', 'body.', 'query.', 'params.'])
        
        if has_inline_concat:
            self._add_finding('EXPRESS006', node.line_number, 'critical',
                            'Potential SQL injection via string concatenation',
                            'Use parameterized queries or ORM methods instead of string concatenation',
                            source, node)
            return
        
        first_arg_text = text.split(',')[0] if ',' in text else text
        is_variable = first_arg_text.strip().split('(')[-1].strip() not in ['\'', '"']
        
        if is_variable and any(p in source for p in ['req.query', 'req.body', 'req.params', 'req.headers']):
            if self._has_sql_concat_in_scope(source):
                self._add_finding('EXPRESS006', node.line_number, 'high',
                                'Potential SQL injection: variable query may contain user input',
                                'Use parameterized queries or ORM methods instead of string concatenation',
                                source, node)
    
    def _has_sql_concat_in_scope(self, source: str) -> bool:
        """Check if there's SQL-related string concatenation with user input."""
        lines = source.split('\n')
        has_concat = any(('+' in line or '`' in line) and any(p in line for p in ['req.', 'body.', 'query.', 'params.']) for line in lines)
        return has_concat
    
    def _check_xss(self, node, source: str) -> None:
        """Check for XSS patterns."""
        text = node.text if hasattr(node, 'text') else ''
        has_user_input = any(p in text for p in ['req.', 'request.', 'body.', 'query.', 'params.'])
        
        if ('innerHTML' in text or 'document.write' in text) and has_user_input:
            self._add_finding('EXPRESS007', node.line_number, 'high',
                            f'Potential XSS via unsanitized user input in response',
                            'Sanitize user input before rendering. Use DOMPurify or template engines with auto-escaping.',
                            source, node)
        elif ('res.send' in text or 'res.render' in text) and has_user_input:
            self._add_finding('EXPRESS007', node.line_number, 'medium',
                            'Potential XSS: user input in response without escaping',
                            'Ensure user input is escaped before sending in response', source, node)
    
    def _check_insecure_random(self, node, source: str) -> None:
        """Check for insecure random number generation."""
        text = node.text if hasattr(node, 'text') else ''
        if 'Math.random' in text:
            self._add_finding('EXPRESS008', node.line_number, 'medium',
                            'Math.random() is not cryptographically secure',
                            'Use crypto.randomBytes() or crypto.randomUUID() for security-sensitive operations',
                            source, node)
    
    def _check_identifier(self, node, source: str) -> None:
        """Check identifiers for patterns."""
        name = node.text if hasattr(node, 'text') else ''
        
        if name == 'helmet':
            pass
    
    def _check_hardcoded_secrets(self, source: str) -> None:
        """Check for hardcoded secrets in source code."""
        import re
        secret_patterns = [
            (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\'](?:sk-|AKIA|AIza)[^"\']{8,}', 'API key'),
            (r'(?:secret|password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}', 'secret/password'),
            (r'(?:token|auth[_-]?token)\s*[=:]\s*["\'][^"\']{10,}', 'token'),
            (r'(?:jwt|bearer)\s*[=:]\s*["\'][^"\']{10,}', 'JWT token'),
            (r'["\'][a-zA-Z0-9]{32,}["\']', 'potential secret'),
        ]
        
        for pattern, label in secret_patterns:
            for match in re.finditer(pattern, source, re.IGNORECASE):
                line = source[:match.start()].count('\n') + 1
                self._add_finding('EXPRESS009', line, 'high',
                                f'Hardcoded secret detected: {label}',
                                'Move secrets to environment variables or secure configuration',
                                source, None)
    
    def _add_finding(self, id: str, line: int, severity: str, message: str, 
                    suggestion: str, source: str, node=None) -> None:
        """Add a finding with deduplication."""
        key = (id, str(self.dedup.file_path), line)
        if key in self.dedup._dedup_seen:
            return
        self.dedup._dedup_seen.add(key)
        
        matched = ''
        if node and hasattr(node, 'text'):
            matched = node.text[:100]
        
        self.findings.append({
            'id': id,
            'file': str(self.dedup.file_path),
            'line': line,
            'severity': severity,
            'category': 'security',
            'message': message,
            'suggestion': suggestion,
            'matched_code': matched,
        })
