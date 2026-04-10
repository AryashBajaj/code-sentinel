"""Public API for call graph generation and data flow analysis."""
from pathlib import Path
from .callgraph import CallGraphBuilder
from .graph import Graph
from .dataflow import DataFlowAnalyzer

def build_graph(root_path: str) -> Graph:
    return CallGraphBuilder(root_path).build_graph()

def analyze_dataflow(root_path: str) -> dict:
    """Analyze data flow including taint propagation across function boundaries.
    
    Returns dict with:
    - findings: List of security issues found
    - graph: Complete call graph with all edges
    - stats: Graph statistics
    """
    return DataFlowAnalyzer(Path(root_path)).analyze()
