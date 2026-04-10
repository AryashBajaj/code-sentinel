"""Public API for call graph generation."""
from .callgraph import CallGraphBuilder
from .graph import Graph

def build_graph(root_path: str) -> Graph:
    return CallGraphBuilder(root_path).build_graph()
