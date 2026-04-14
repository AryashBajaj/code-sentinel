"""CLI for CodeSentinel."""
import click
from rich.console import Console
from rich.panel import Panel
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from scanner.project_scanner import ProjectScanner
from callgraph import analyze_dataflow
from callgraph.js_dataflow import analyze_js_dataflow
from callgraph.visualize import GraphVisualizer
from analyzer.static_analyzer import StaticAnalyzer
from analyzer.framework_analyzer import FrameworkAnalyzer
from analyzer.llm import LLMAnalyzer
from config.settings import Settings

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
@click.option("--dataflow", is_flag=True, help="Enable data flow analysis (taint propagation)")
@click.option("--graph-out", help="Export call graph to path (JSON by default)")
@click.option("--graph-format", type=click.Choice(["json", "dot"]), default="json", help="Graph export format (default json)")
@click.option("--visualise", "visualize", is_flag=True, help="Generate interactive HTML visualization (requires --dataflow and --graph-out)")
def analyze(path, llm, api_key, no_llm, dataflow, graph_out, graph_format, visualize):
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
    
    # 0.4.0: Data flow analysis with taint propagation
    dataflow_findings = []
    if dataflow:
        language = project_info.get('language', 'python')
        console.print("Running data flow analysis...")
        try:
            if language in ('javascript', 'typescript'):
                df_result = analyze_js_dataflow(str(project_path))
                console.print(f"[JS-DataFlow] nodes={df_result['stats']['nodes']} edges={df_result['stats']['edges']}")
            else:
                df_result = analyze_dataflow(str(project_path))
                console.print(f"[DataFlow] nodes={df_result['stats']['nodes']} edges={df_result['stats']['edges']}")
            dataflow_findings = df_result.get("findings", [])
            if graph_out:
                graph = df_result.get("graph")
                if graph:
                    if graph_format == "json":
                        graph_text = graph.to_json()
                    else:
                        graph_text = graph.to_dot()
                    Path(graph_out).parent.mkdir(parents=True, exist_ok=True)
                    Path(graph_out).write_text(graph_text, encoding="utf-8")
                    console.print(f"Graph exported to {graph_out}")
        except Exception as e:
            console.print(f"[Warning] Data flow analysis failed: {e}")
    
    # Visualization generation (requires --dataflow and --graph-out)
    if visualize:
        if not dataflow:
            console.print("[red]Error: --visualise requires --dataflow flag[/red]")
            return
        if not graph_out:
            console.print("[red]Error: --visualise requires --graph-out path[/red]")
            return
        
        try:
            console.print("Generating visualization...")
            viz = GraphVisualizer(graph_out)
            html_path = str(Path(graph_out).with_suffix('.html'))
            viz.visualize(html_path)
            console.print(f"[green]Visualization saved to {html_path}[/green]")
        except Exception as e:
            console.print(f"[Warning] Visualization failed: {e}")
    
    # 0.3.0: Framework-aware enhancement (detect and analyze framework-specific issues)
    framework = project_info.get("framework", "unknown")
    if not no_llm:
        console.print("Running LLM analysis (" + llm + ")...")
        llm_analyzer = LLMAnalyzer(settings, llm)
        llm_results = llm_analyzer.analyze(project_info, static_results)
        console.print("LLM analysis complete")
    else:
        llm_results = {"findings": []}

    all_findings = static_results["findings"] + llm_results["findings"] + dataflow_findings

    # 0.3.0: If framework detected, run framework-specific analyzer
    if framework != "unknown":
        try:
            fw = FrameworkAnalyzer(framework, project_path, project_info)
            fw_results = fw.analyze(static_results)
            all_findings.extend(fw_results.get("findings", []))
        except Exception:
            pass
    
    # Deduplicate findings by (file, line, id)
    seen = set()
    unique_findings = []
    for f in all_findings:
        key = (f.get('file', ''), f.get('line', 0), f.get('id', ''), f.get('message', ''))
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
    all_findings = unique_findings
    
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
