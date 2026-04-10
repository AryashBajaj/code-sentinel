"""Core graph primitives for the CallGraph package."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class Node:
    id: str
    type: str  # e.g. 'module' or 'function'
    name: str
    path: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    src_id: str
    dst_id: str
    kind: str  # e.g. 'CALL' or 'IMPORT'
    line: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class Graph:
    def __init__(self) -> None:
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []

    def add_node(self, node: Node) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)

    def to_dict(self) -> Dict[str, object]:
        return {
            "nodes": [
                {
                    "id": n.id,
                    "type": n.type,
                    "name": n.name,
                    "path": n.path,
                    "line_start": n.line_start,
                    "line_end": n.line_end,
                    "metadata": n.metadata,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "src_id": e.src_id,
                    "dst_id": e.dst_id,
                    "kind": e.kind,
                    "line": e.line,
                    "metadata": e.metadata,
                }
                for e in self.edges
            ],
        }

    def to_json(self) -> str:
        import json
        return json.dumps(self.to_dict(), indent=2)

    def to_dot(self) -> str:
        lines = ["digraph CallGraph {"]
        for n in self.nodes.values():
            label = f"{n.name} ({n.path})"
            lines.append(f'  "{n.id}" [label="{label}"];')
        for e in self.edges:
            lines.append(f'  "{e.src_id}" -> "{e.dst_id}" [label="{e.kind}"];')
        lines.append("}")
        return "\n".join(lines)
