"""LLM integration for code analysis."""
from typing import Dict, List, Any
import os
import json


class LLMAnalyzer:
    def __init__(self, settings, provider: str = "gemini"):
        self.settings = settings
        self.provider = provider
        self.client = None
        self.model_name = None
        self._setup_client()
    
    def _setup_client(self):
        if self.provider == "openai":
            from openai import OpenAI
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise ValueError("OPENAI_API_KEY not set. Get from https://platform.openai.com/")
            self.client = OpenAI(api_key=api_key)
            
        elif self.provider == "anthropic":
            from anthropic import Anthropic
            api_key = os.getenv("ANTHROPIC_API_KEY")
            if not api_key:
                raise ValueError("ANTHROPIC_API_KEY not set. Get from https://www.anthropic.com/")
            self.client = Anthropic(api_key=api_key)
            
        elif self.provider == "gemini":
            try:
                from google import genai
                api_key = os.getenv("GEMINI_API_KEY")
                if not api_key:
                    raise ValueError("GEMINI_API_KEY not set. Get free key from https://aistudio.google.com/app/apikey")
                self.client = genai.Client(api_key=api_key)
                self.model_name = "gemini-2.5-flash"
            except ImportError:
                raise ImportError("Please install google-genai: pip install google-genai")
    
    def analyze(self, project_info: Dict, static_results: Dict) -> Dict[str, Any]:
        findings = []
        static_summary = self._summarize_findings(static_results.get("findings", []))
        key_files = self._get_key_files(project_info)
        
        for file_path in key_files[:5]:
            file_full_path = os.path.join(project_info["path"], file_path)
            llm_findings = self._analyze_file(file_path, file_full_path, static_summary)
            findings.extend(llm_findings)
        
        return {"findings": findings}
    
    def _summarize_findings(self, findings: List[Dict]) -> str:
        if not findings:
            return "No static analysis findings."
        categories = {}
        for f in findings:
            cat = f.get("category", "unknown")
            categories[cat] = categories.get(cat, 0) + 1
        summary = "Static analysis found: "
        for cat, count in categories.items():
            summary += f"- {count} {cat} issues. "
        return summary
    
    def _get_key_files(self, project_info: Dict) -> List[str]:
        files = project_info.get("files", [])
        entry_points = project_info.get("entry_points", [])
        priority = entry_points + [f for f in files if "main" in f or "app" in f]
        result = list(set(priority + files))
        return result[:10]
    
    def _analyze_file(self, file_path: str, file_full_path: str, static_summary: str) -> List[Dict]:
        try:
            with open(file_full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return []
        
        if len(content) > 8000:
            content = content[:8000] + "\n... (truncated)"
        
        prompt = self._build_prompt(file_path, content, static_summary)
        
        try:
            if self.provider == "openai":
                response = self.client.chat.completions.create(
                    model="gpt-4o",
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.3,
                    max_tokens=2000
                )
                result = response.choices[0].message.content
                
            elif self.provider == "anthropic":
                response = self.client.messages.create(
                    model="claude-sonnet-4-20250514",
                    max_tokens=2000,
                    temperature=0.3,
                    messages=[{"role": "user", "content": prompt}]
                )
                result = response.content[0].text
                
            elif self.provider == "gemini":
                response = self.client.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config={
                        "temperature": 0.3,
                        "max_output_tokens": 8192,
                    }
                )
                result = response.text
            
            return self._parse_llm_response(file_path, result)
        except Exception as e:
            print(f"LLM analysis error for {file_path}: {e}")
            return []
    
    def _build_prompt(self, file_path: str, content: str, static_summary: str) -> str:
        return f"""You are a senior code reviewer analyzing Python code for security vulnerabilities, performance issues, and safety concerns.

File: {file_path}

Static analysis summary:
{static_summary}

Code to analyze:
```{content}
```

Analyze this code and identify issues beyond pattern matching. Consider:
1. SQL injection and input validation
2. Authentication/authorization flaws
3. Race conditions
4. Resource leaks
5. Error handling problems
6. Memory issues
7. Business logic flaws

Respond ONLY with valid JSON in this format (no explanation, no markdown):
{{
  "findings": [
    {{
      "severity": "critical|high|medium|low",
      "category": "security|performance|safety|maintainability",
      "message": "Issue description",
      "line": approximate_line_number,
      "suggestion": "How to fix"
    }}
  ]
}}
If no issues found, return: {{"findings": []}}"""
    
    def _parse_llm_response(self, file_path: str, response: str) -> List[Dict]:
        try:
            cleaned = response.strip()
            
            # Handle markdown code blocks
            if cleaned.startswith("```"):
                lines = cleaned.split("\n")
                if lines[0].strip().startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                cleaned = "\n".join(lines)
            
            cleaned = cleaned.strip()
            
            start = cleaned.find("{")
            end = cleaned.rfind("}") + 1
            
            if start == -1 or end == 0:
                return []
            
            json_str = cleaned[start:end]
            data = json.loads(json_str)
            
            findings = data.get("findings", [])
            for f in findings:
                f["file"] = file_path
                f["source"] = "llm"
            return findings
        except Exception:
            return []
