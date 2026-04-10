"""CLI for CodeSentinel."""
import click
from rich.console import Console
from rich.panel import Panel
import sys
from pathlib import Path
import os

os.chdir(Path(__file__).parent)
sys.path.insert(0, str(Path(__file__).parent))

from src.scanner.project_scanner import ProjectScanner
from callgraph import CallGraphBuilder
from src.analyzer.static_analyzer import StaticAnalyzer
from src.analyzer.framework_analyzer import FrameworkAnalyzer
from src.llm.code_analyzer import LLMAnalyzer
from src.report.formatter import ReportFormatter
from src.config.settings import Settings

console = Console()

@click.group()
@click.version_option(version="0.1.0")
def main():
    """CodeSentinel - AI-powered code security and optimization analyzer."""
    pass

@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--llm", type=click.Choice(["gemini", "openai", "anthropic"]), default="gemini",
                help="LLM provider to use (default: gemini)")
@click.option("--api-key", help="API key for LLM provider (or set GEMINI_API_KEY env var)")
@click.option("--no-llm", is_flag=True, help="Skip LLM analysis (static only)")
@click.option("--graph-out", help="Export call graph to path (JSON by default)")
@click.option("--graph-format", type=click.Choice(["json", "dot"]), default="json", help="Graph export format (default json)")
def analyze(path, llm, api_key, no_llm, graph_out, graph_format):
    console.print("[bold blue]CodeSentinel[/bold blue] - AI-Powered Code Analysis")
    
    project_path = Path(path).resolve()
    settings = Settings()
    
    # Set API key from parameter if provided
    if api_key:
        if llm == "gemini":
            os.environ["GEMINI_API_KEY"] = api_key
        elif llm == "openai":
            os.environ["OPENAI_API_KEY"] = api_key
        elif llm == "anthropic":
            os.environ["ANTHROPIC_API_KEY"] = api_key
    
    console.print("Scanning project structure...")
    scanner = ProjectScanner(project_path)
    project_info = scanner.scan()
    console.print("Found " + str(len(project_info['files'])) + " files, Language: " + project_info['language'])
    
    console.print("Running static analysis...")
    analyzer = StaticAnalyzer(project_path, project_info)
    static_results = analyzer.analyze()
    console.print("Found " + str(len(static_results['findings'])) + " issues")
    
    # 0.3.0: Framework-aware enhancement (detect and analyze framework-specific issues)
    framework = project_info.get("framework", "unknown")
    if not no_llm:
        console.print("Running LLM analysis (" + llm + ")...")
        llm_analyzer = LLMAnalyzer(settings, llm)
        llm_results = llm_analyzer.analyze(project_info, static_results)
        console.print("LLM analysis complete")
    else:
        llm_results = {"findings": []}

    all_findings = static_results["findings"] + llm_results["findings"]

    # Graph export (end-to-end, production integration)
    try:
        if graph_out:
            graph_builder = CallGraphBuilder(str(project_path))
            graph = graph_builder.build_graph()
            # Quick diagnostics to help understand missing edges
            console.print(f"[GraphStats] nodes={len(graph.nodes)} edges={len(graph.edges)}")
            if graph_format == "json":
                graph_text = graph.to_json()
            else:
                graph_text = graph.to_dot()
            Path(graph_out).parent.mkdir(parents=True, exist_ok=True)
            Path(graph_out).write_text(graph_text, encoding="utf-8")
            console.print(f"Graph exported to {graph_out} ({graph_format})")
    except Exception as e:
        console.print(f"[Warning] Failed to export call graph: {e}")

    # 0.3.0: If framework detected, run framework-specific analyzer
    if framework != "unknown":
        try:
            fw = FrameworkAnalyzer(framework, project_path, project_info)
            fw_results = fw.analyze(static_results)
            all_findings += fw_results.get("findings", [])
        except Exception:
            pass
    
    console.print("\n=== Analysis Complete: " + str(len(all_findings)) + " issues found ===\n")
    
    for finding in all_findings:
        sev = finding.get("severity", "low")
        console.print("[" + sev.upper() + "] " + finding.get('file', 'unknown') + ":" + str(finding.get('line', 0)) + " - " + finding.get('message', ''))
        if finding.get("suggestion"):
            console.print("  => " + finding['suggestion'])

@main.command()
@click.argument("path", type=click.Path(exists=True))
def detect(path):
    """Detect project type and structure."""
    project_path = Path(path).resolve()
    scanner = ProjectScanner(project_path)
    info = scanner.scan()
    console.print("Project: " + info['name'] + ", Language: " + info['language'] + ", Files: " + str(len(info['files'])))

if __name__ == "__main__":
    main()
