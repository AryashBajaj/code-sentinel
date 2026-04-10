"""Export helpers for the call graph (JSON and DOT)."""
from __future__ import annotations
import json
from typing import Any
from .graph import Graph

def graph_to_json(graph: Graph) -> str:
    return json.dumps(graph.to_dict(), indent=2)

def graph_to_dot(graph: Graph) -> str:
    return graph.to_dot()
