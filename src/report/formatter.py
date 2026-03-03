"""Report formatting."""
import json
from typing import Dict, List, Any
from datetime import datetime

class ReportFormatter:
    def __init__(self, format_type: str = "terminal"):
        self.format_type = format_type
    
    def format(self, findings: List[Dict], project_info: Dict) -> str:
        if self.format_type == "json":
            return self._format_json(findings, project_info)
        elif self.format_type == "markdown":
            return self._format_markdown(findings, project_info)
        else:
            return self._format_terminal(findings, project_info)
    
    def _format_json(self, findings: List[Dict], project_info: Dict) -> str:
        report = {
            "timestamp": datetime.now().isoformat(),
            "project": project_info,
            "summary": self._get_summary(findings),
            "findings": findings,
        }
        return json.dumps(report, indent=2)
    
    def _format_markdown(self, findings: List[Dict], project_info: Dict) -> str:
        lines = [
            f"# CodeSentinel Analysis Report",
            f"**Project:** {project_info.get('name', 'Unknown')}",
            f"**Language:** {project_info.get('language', 'Unknown')}",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "",
            "## Summary",
            f"- Total Issues: {len(findings)}",
            f"- Critical: {len([f for f in findings if f.get('severity') == 'critical'])}",
            f"- High: {len([f for f in findings if f.get('severity') == 'high'])}",
            f"- Medium: {len([f for f in findings if f.get('severity') == 'medium'])}",
            f"- Low: {len([f for f in findings if f.get('severity') == 'low'])}",
            "",
            "## Findings",
        ]
        for severity in ["critical", "high", "medium", "low"]:
            severity_findings = [f for f in findings if f.get("severity") == severity]
            if severity_findings:
                lines.append(f"### {severity.upper()}")
                for f in severity_findings:
                    lines.append(f"- **{f.get('file', 'unknown')}:{f.get('line', 0)}** - {f.get('message', '')}")
                    if f.get("suggestion"):
                        lines.append(f"  - Suggestion: {f['suggestion']}")
                lines.append("")
        return chr(10).join(lines)
    
    def _format_terminal(self, findings: List[Dict], project_info: Dict) -> str:
        return f"Analysis complete: {len(findings)} issues found"
    
    def _get_summary(self, findings: List[Dict]) -> Dict[str, int]:
        return {
            "total": len(findings),
            "critical": len([f for f in findings if f.get("severity") == "critical"]),
            "high": len([f for f in findings if f.get("severity") == "high"]),
            "medium": len([f for f in findings if f.get("severity") == "medium"]),
            "low": len([f for f in findings if f.get("severity") == "low"]),
        }
