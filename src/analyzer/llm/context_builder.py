"""Context builder for LLM analysis.

Builds rich context for LLM analysis including:
- Call graph information
- Framework context
- Surrounding code
- Related findings
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class FindingContext:
    """Context for a single finding."""
    file_path: str
    line_number: int
    code_snippet: str
    function_name: Optional[str] = None
    function_signature: Optional[str] = None
    class_name: Optional[str] = None
    call_chain: List[str] = field(default_factory=list)
    framework_context: Optional[str] = None
    related_code: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)


class ContextBuilder:
    """Builds rich context for LLM analysis of code findings."""
    
    def __init__(self, project_path: str):
        self.project_path = project_path
    
    def build_finding_context(
        self,
        file_path: str,
        line_number: int,
        code_snippet: str,
        call_graph: Optional[Dict[str, Any]] = None,
        framework: Optional[str] = None,
        project_info: Optional[Dict[str, Any]] = None
    ) -> FindingContext:
        """Build comprehensive context for a finding.
        
        Args:
            file_path: Path to the file with the finding
            line_number: Line number of the finding
            code_snippet: The code that triggered the finding
            call_graph: Optional call graph data
            framework: Optional framework name (flask, django, etc.)
            project_info: Optional project information
            
        Returns:
            FindingContext with rich contextual information
        """
        context = FindingContext(
            file_path=file_path,
            line_number=line_number,
            code_snippet=code_snippet
        )
        
        if call_graph:
            context.call_chain = self._extract_call_chain(call_graph, file_path, line_number)
        
        if framework:
            context.framework_context = self._get_framework_context(framework, code_snippet)
        
        if project_info:
            context.imports = project_info.get('imports', [])
        
        context.related_code = self._get_related_code(file_path, line_number, code_snippet)
        
        return context
    
    def _extract_call_chain(
        self,
        call_graph: Dict[str, Any],
        file_path: str,
        line_number: int
    ) -> List[str]:
        """Extract the call chain leading to this finding."""
        chain = []
        
        edges = call_graph.get('edges', [])
        for edge in edges:
            if edge.get('dst_file') == file_path:
                chain.append(f"{edge.get('src_file')}:{edge.get('src_func')}()")
        
        return chain[:5]
    
    def _get_framework_context(self, framework: str, code: str) -> str:
        """Get framework-specific context for the code."""
        contexts = {
            'flask': self._flask_context,
            'django': self._django_context,
            'fastapi': self._fastapi_context,
            'express': self._express_context,
            'nestjs': self._nestjs_context,
        }
        
        context_fn = contexts.get(framework.lower())
        if context_fn:
            return context_fn(code)
        
        return ""
    
    def _flask_context(self, code: str) -> str:
        """Get Flask-specific context."""
        if '@app.route' in code or '@blueprint.route' in code:
            return "Flask route handler - user input may flow through request object"
        if 'render_template' in code:
            return "Template rendering - potential XSS if user input not escaped"
        if 'request.args' in code or 'request.form' in code:
            return "Request data access - validate and sanitize input"
        return "Flask application code"
    
    def _django_context(self, code: str) -> str:
        """Get Django-specific context."""
        if 'HttpRequest' in code:
            return "Django view receiving HTTP request"
        if '.queryset' in code or '.filter(' in code:
            return "Django ORM query - validate to prevent injection"
        if 'render(' in code:
            return "Template rendering - potential XSS"
        if '@login_required' in code:
            return "Authentication protected view"
        return "Django application code"
    
    def _fastapi_context(self, code: str) -> str:
        """Get FastAPI-specific context."""
        if '@app.get' in code or '@app.post' in code:
            return "FastAPI endpoint - user input through request body/params"
        if 'async def' in code:
            return "Async endpoint - ensure proper error handling"
        if 'Depends(' in code:
            return "FastAPI dependency injection - validate injected values"
        return "FastAPI application code"
    
    def _express_context(self, code: str) -> str:
        """Get Express.js-specific context."""
        if 'app.get' in code or 'app.post' in code:
            return "Express route handler - validate request data"
        if 'req.body' in code:
            return "Request body access - validate and sanitize"
        if 'res.render' in code:
            return "Template rendering - potential XSS"
        return "Express.js application code"
    
    def _nestjs_context(self, code: str) -> str:
        """Get NestJS-specific context."""
        if '@Get' in code or '@Post' in code:
            return "NestJS route handler"
        if '@Body()' in code or '@Query()' in code:
            return "Request data injection - validate DTOs"
        if '@Injectable' in code:
            return "NestJS injectable service"
        return "NestJS application code"
    
    def _get_related_code(
        self,
        file_path: str,
        line_number: int,
        code_snippet: str
    ) -> List[str]:
        """Get surrounding code for context."""
        return []
    
    def build_prompt_context(self, finding: FindingContext) -> str:
        """Build a prompt-ready context string for LLM analysis.
        
        Args:
            finding: The finding context
            
        Returns:
            Formatted string ready for LLM prompt
        """
        parts = []
        
        parts.append(f"File: {finding.file_path}")
        parts.append(f"Line: {finding.line_number}")
        parts.append(f"Code: {finding.code_snippet}")
        
        if finding.function_name:
            parts.append(f"Function: {finding.function_name}")
        
        if finding.class_name:
            parts.append(f"Class: {finding.class_name}")
        
        if finding.call_chain:
            parts.append(f"Call Chain: {' -> '.join(finding.call_chain)}")
        
        if finding.framework_context:
            parts.append(f"Framework Context: {finding.framework_context}")
        
        if finding.related_code:
            parts.append("Related Code:")
            for related in finding.related_code[:3]:
                parts.append(f"  {related}")
        
        return "\n".join(parts)
