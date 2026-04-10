"""Next.js AST-based analyzer using tree-sitter.

Production-grade security checks for Next.js applications using
tree-sitter AST parsing for accurate, robust analysis.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from ..tree_sitter.parser import TreeSitterParser, ParsedFile
from .dedup import DedupMixin


class NextJSAstAnalyzer:
    """Security analyzer for Next.js applications using tree-sitter AST."""
    
    SENSITIVE_PATTERNS = {'password', 'secret', 'key', 'token', 'credential', 'api_key', 'api_?key'}
    
    def __init__(self):
        self.parser = TreeSitterParser()
        self.findings: List[Dict[str, Any]] = []
        self.dedup = DedupMixin()
        self.dedup.file_path = Path("")
        self.dedup.source = ""
    
    def analyze(self, source: str, file_path: str) -> List[Dict[str, Any]]:
        """Analyze Next.js code for security issues.
        
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
        
        is_client = "'use client'" in source or '"use client"' in source
        normalized_path = file_path.replace('\\', '/')
        is_api_route = 'pages/api' in normalized_path or 'app/api' in normalized_path
        
        try:
            result = self.parser.parse(source, 'javascript', file_path)
            if result:
                self._visit_file(result, source, is_client, is_api_route)
        except Exception:
            pass
        
        self._check_env_exposure(source)
        
        return self.findings
    
    def _visit_file(self, parsed: ParsedFile, source: str, is_client: bool, is_api: bool) -> None:
        """Visit all nodes in the parsed file."""
        if parsed.root_node:
            self._walk_node(parsed.root_node, source, is_client, is_api)
    
    def _walk_node(self, node, source: str, is_client: bool, is_api: bool) -> None:
        """Recursively walk AST nodes."""
        node_type = node.node_type
        
        if node_type == 'call_expression':
            self._check_call(node, source, is_client, is_api)
        elif node_type == 'lexical_declaration':
            self._check_declaration(node, source)
        
        for child in node.children:
            self._walk_node(child, source, is_client, is_api)
    
    def _check_call(self, node, source: str, is_client: bool, is_api: bool) -> None:
        """Check call expressions for security issues."""
        func_name = self._get_callee_name(node)
        line = node.line_number
        
        if not func_name:
            return
        
        if 'fetch' in func_name or 'axios' in func_name or 'get' in func_name:
            self._check_ssrf(node, source)
        elif 'eval' in func_name or 'Function' in func_name:
            self._add_finding('NEXT008', line, 'medium',
                            f'Dangerous pattern: Use of {func_name}() is dangerous in Next.js',
                            'Review and avoid dynamic code execution patterns', source, node)
        elif 'innerHTML' in func_name:
            self._check_xss(node, source)
        elif 'prisma' in func_name or 'mongoose' in func_name or 'query' in func_name:
            self._check_sql_injection(node, source)
        elif 'console' in func_name:
            self._check_sensitive_logging(node, source)
    
    def _check_declaration(self, node, source: str) -> None:
        """Check variable declarations."""
        text = node.text if hasattr(node, 'text') else ''
        
        for pattern in self.SENSITIVE_PATTERNS:
            if pattern in text.lower():
                if 'return' in text or 'expose' in text or 'send' in text:
                    self._add_finding('NEXT005', node.line_number, 'high',
                                    f'Potential sensitive data exposure in declaration',
                                    'Remove sensitive fields from responses or mask them', source, node)
                    break
    
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
        """Get name from member expression."""
        if hasattr(node, 'children') and node.children:
            parts = []
            for child in node.children:
                if child.node_type == 'identifier':
                    parts.append(child.text)
                elif child.node_type == 'property_identifier':
                    parts.append(child.text)
                elif child.node_type == 'this':
                    parts.append('this')
            return '.'.join(parts)
        return ''
    
    def _check_ssrf(self, node, source: str) -> None:
        """Check for Server-Side Request Forgery vulnerabilities."""
        text = node.text if hasattr(node, 'text') else ''
        
        has_url_validation = self._has_url_validation(source)
        
        ssrf_patterns_in_call = ['req.query', 'req.params', 'req.body', 'req.headers', 
                                 'userInput', 'searchParams', 'params.', 'query.', 'body.']
        
        for pattern in ssrf_patterns_in_call:
            if pattern in text:
                if not has_url_validation:
                    self._add_finding('NEXT001', node.line_number, 'high',
                                    f'Potential SSRF vulnerability: {pattern} in URL fetch',
                                    'Validate and whitelist allowed URLs/domains before fetching', source, node)
                return
        
        if 'fetch' in text.lower() and not has_url_validation:
            if any(p in source for p in ['searchParams', 'req.query', 'req.params', 'req.body', 'params.', 'body.']):
                self._add_finding('NEXT001', node.line_number, 'medium',
                                'Potential SSRF: fetch with user-controlled data in file',
                                'Ensure URL is validated before fetch, use allowlist for domains', source, node)
    
    def _check_sql_injection(self, node, source: str) -> None:
        """Check for SQL/NoSQL injection patterns."""
        text = node.text if hasattr(node, 'text') else ''
        
        injection_patterns = ['+', '${', 'template']
        has_user_input = any(p in text for p in ['req.', 'params.', 'body.', 'query.'])
        
        if any(p in text for p in injection_patterns) and has_user_input:
            self._add_finding('NEXT002', node.line_number, 'critical',
                            f'Potential injection with user input in query',
                            'Use parameterized queries or Prisma/Mongoose with validated input', source, node)
    
    def _check_xss(self, node, source: str) -> None:
        """Check for XSS patterns."""
        text = node.text if hasattr(node, 'text') else ''
        
        if 'innerHTML' in text:
            if 'req.' in text or 'user' in text.lower():
                if not self._has_sanitization(source):
                    self._add_finding('NEXT003', node.line_number, 'high',
                                    'Potential XSS via innerHTML with user input',
                                    'Use React\'s built-in escaping or sanitize with DOMPurify', source, node)
        elif 'dangerouslySetInnerHTML' in text:
            self._add_finding('NEXT003', node.line_number, 'high',
                            'XSS via dangerouslySetInnerHTML requires careful sanitization',
                            'Use DOMPurify to sanitize the HTML before rendering', source, node)
    
    def _check_sensitive_logging(self, node, source: str) -> None:
        """Check for sensitive data in logs."""
        text = node.text if hasattr(node, 'text') else ''
        
        for pattern in self.SENSITIVE_PATTERNS:
            if pattern in text.lower():
                self._add_finding('NEXT005', node.line_number, 'high',
                                f'Sensitive data ({pattern}) in console output',
                                'Remove sensitive fields from logs', source, node)
                break
    
    def _check_env_exposure(self, source: str) -> None:
        """Check for sensitive environment variables exposed with NEXT_PUBLIC."""
        import re
        pattern = r'NEXT_PUBLIC_(?:DATABASE|SECRET|API|KEY|PASSWORD|TOKEN)'
        matches = re.finditer(pattern, source, re.IGNORECASE)
        
        for match in matches:
            line = source[:match.start()].count('\n') + 1
            self._add_finding('NEXT009', line, 'high',
                            'Environment variable security: sensitive env var exposed via NEXT_PUBLIC prefix',
                            'Only use NEXT_PUBLIC_ for vars safe to expose to browser', source, None)
    
    def _has_url_validation(self, source: str) -> bool:
        """Check if code has URL validation."""
        import re
        patterns = [
            r'validator\.isURL',
            r'const\s+allowedDomains\s*=',
            r'const\s+whitelist\s*=',
            r'const\s+safeList\s*=',
            r'const\s+allowedURLs\s*=',
            r'allowedDomains\.includes',
            r'whitelist\.includes',
            r'isValidUrl\s*\(',
            r'validateUrl\s*\(',
        ]
        return any(re.search(p, source, re.IGNORECASE) for p in patterns)
    
    def _has_sanitization(self, source: str) -> bool:
        """Check if code has XSS sanitization."""
        import re
        patterns = [
            r'DOMPurify',
            r'sanitize',
            r'he\.escape',
            r'encoder\.encodeForHTML',
            r'xss\s*\(',
        ]
        return any(re.search(p, source, re.IGNORECASE) for p in patterns)
    
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
