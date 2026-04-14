"""Call Graph Visualization Module.

Generates SVG tree visualizations of call graphs.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Set, Optional
from collections import defaultdict
from dataclasses import dataclass


@dataclass
class GraphNode:
    id: str
    type: str
    name: str
    path: str
    line_start: Optional[int] = None

    @property
    def short_path(self) -> str:
        return self.path.split('/')[-1] if '/' in self.path else self.path.split('\\')[-1]


@dataclass  
class GraphEdge:
    src_id: str
    dst_id: str
    kind: str
    line: int


class TreeNode:
    def __init__(self, node_id: str, node: GraphNode):
        self.node_id = node_id
        self.node = node
        self.children: List['TreeNode'] = []
        self.x = 0.0
        self.y = 0.0


class GraphVisualizer:
    """Generates SVG tree visualization of call graphs."""
    
    NODE_WIDTH = 160
    NODE_HEIGHT = 50
    H_SPACING = 40
    V_SPACING = 80
    
    def __init__(self, graph_json_path: str):
        self.graph_json_path = Path(graph_json_path)
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self._load_graph()
    
    def _load_graph(self) -> None:
        if not self.graph_json_path.exists():
            raise FileNotFoundError(f"Graph file not found: {self.graph_json_path}")
        
        with open(self.graph_json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        self.nodes = {}
        self.edges = []
        
        for node_data in data.get('nodes', []):
            node_id = node_data.get('id', '')
            node = GraphNode(
                id=node_id,
                type=node_data.get('type', 'function'),
                name=node_data.get('name', node_id),
                path=node_data.get('path', ''),
                line_start=node_data.get('line_start')
            )
            self.nodes[node_id] = node
        
        for edge_data in data.get('edges', []):
            edge = GraphEdge(
                src_id=edge_data.get('src_id', ''),
                dst_id=edge_data.get('dst_id', ''),
                kind=edge_data.get('kind', 'CALL'),
                line=edge_data.get('line', 0) or 0
            )
            self.edges.append(edge)
    
    def _detect_cycles(self) -> tuple[list[tuple], list[str]]:
        callees = defaultdict(list)
        for e in self.edges:
            if e.src_id in self.nodes and e.dst_id in self.nodes:
                callees[e.src_id].append(e.dst_id)
        
        cycles = []
        self_references = []
        visited = set()
        rec_stack = set()
        
        def dfs(node_id: str, path: list) -> None:
            if node_id in rec_stack:
                idx = path.index(node_id)
                cycle = tuple(path[idx:] + [node_id])
                cycles.append(cycle)
                return
            if node_id in visited:
                return
            
            visited.add(node_id)
            rec_stack.add(node_id)
            
            for callee in callees.get(node_id, []):
                if callee == node_id:
                    self_references.append(node_id)
                else:
                    dfs(callee, path + [node_id])
            
            rec_stack.remove(node_id)
        
        for node_id in list(callees.keys()):
            if node_id not in visited:
                dfs(node_id, [])
        
        return cycles, self_references
    
    def visualize(self, output_path: str) -> str:
        html = self._generate_html()
        
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(html, encoding='utf-8')
        
        return str(output)
    
    def _build_trees(self) -> List[TreeNode]:
        callees = defaultdict(list)
        callers = defaultdict(list)
        
        for e in self.edges:
            if e.src_id in self.nodes and e.dst_id in self.nodes:
                callees[e.src_id].append(e.dst_id)
                callers[e.dst_id].append(e.src_id)
        
        roots = [nid for nid, n in self.nodes.items() 
                 if n.type != 'module' and not callers[nid]]
        
        trees = []
        
        def make_tree(nid: str, path: Set[str]) -> Optional[TreeNode]:
            if nid in path or nid not in self.nodes:
                return None
            n = self.nodes[nid]
            if n.type == 'module':
                return None
            t = TreeNode(nid, n)
            new_path = path | {nid}
            for child_id in callees[nid]:
                child = make_tree(child_id, new_path)
                if child:
                    t.children.append(child)
            return t
        
        for root in roots:
            t = make_tree(root, set())
            if t and t.children:
                trees.append(t)
        
        return trees
    
    def _layout_trees(self, trees: List[TreeNode]) -> None:
        if not trees:
            return
        
        current_x = 100
        for tree in trees:
            subtree_w = self._get_subtree_width(tree)
            root_x = current_x + subtree_w / 2
            self._layout_subtree(tree, 30)
            self._offset_tree(tree, root_x)
            current_x += subtree_w + self.H_SPACING * 2
    
    def _offset_tree(self, node: TreeNode, offset_x: float) -> None:
        node.x += offset_x
        for child in node.children:
            self._offset_tree(child, offset_x)
    
    def _layout_subtree(self, node: TreeNode, y: float) -> float:
        node.y = y
        
        if not node.children:
            node.x = 0
            return self.NODE_WIDTH
        
        child_y = y + self.NODE_HEIGHT + self.V_SPACING
        child_widths = []
        
        for child in node.children:
            child_w = self._layout_subtree(child, child_y)
            child_widths.append(child_w)
        
        total_width = sum(child_widths) + self.H_SPACING * (len(node.children) - 1)
        
        start_x = -total_width / 2
        for i, child in enumerate(node.children):
            child.x = start_x + sum(child_widths[:i]) + i * self.H_SPACING + child_widths[i] / 2
        
        node.x = sum(c.x for c in node.children) / len(node.children)
        
        return max(total_width, self.NODE_WIDTH)
    
    def _get_subtree_width(self, node: TreeNode) -> float:
        if not node.children:
            return self.NODE_WIDTH
        total = sum(self._get_subtree_width(c) for c in node.children)
        total += self.H_SPACING * (len(node.children) - 1)
        return max(total, self.NODE_WIDTH)
    
    def _render_node(self, node: TreeNode, is_self_ref: bool = False) -> str:
        name = node.node.name or '<anon>'
        if len(name) > 16:
            name = name[:13] + '...'
        
        tooltip = f"{name}\n{node.node.short_path}:{node.node.line_start or '?'}\n{node.node.path}"
        if is_self_ref:
            tooltip = "[RECURSION] " + tooltip
        
        x = node.x - self.NODE_WIDTH / 2
        y = node.y
        
        class_name = 'node' + (' self-ref' if is_self_ref else '')
        
        return f'''<g class="{class_name}" transform="translate({x},{y})">
<rect width="{self.NODE_WIDTH}" height="{self.NODE_HEIGHT}" rx="6" fill="#1e1e1e" stroke="#3c3c3c" stroke-width="1.5"/>
<text x="{self.NODE_WIDTH/2}" y="18" text-anchor="middle" fill="#dcdcaa" font-size="11" font-family="monospace">{name}</text>
<text x="{self.NODE_WIDTH/2}" y="33" text-anchor="middle" fill="#608b4e" font-size="9" font-family="monospace">{node.node.short_path}:{node.node.line_start or '?'}</text>
<title>{tooltip}</title>
</g>'''
    
    def _render_edge(self, parent: TreeNode, child: TreeNode) -> str:
        x1 = parent.x
        y1 = parent.y + self.NODE_HEIGHT
        x2 = child.x
        y2 = child.y
        
        mid_y = (y1 + y2) / 2
        return f'<path d="M{x1},{y1} L{x1},{mid_y} L{x2},{mid_y} L{x2},{y2}" fill="none" stroke="#3c3c3c" stroke-width="1.5"/>'
    
    def _render_tree(self, node: TreeNode, self_refs: Set[str] = None) -> str:
        self_refs = self_refs or set()
        is_self_ref = node.node_id in self_refs
        svg = self._render_node(node, is_self_ref)
        for child in node.children:
            svg += self._render_edge(node, child)
            svg += self._render_tree(child, self_refs)
        return svg
    
    def _generate_svg(self, self_refs: List[str] = None) -> str:
        self_refs = self_refs or []
        trees = self._build_trees()
        
        if not trees:
            return '<svg></svg>'
        
        self._layout_trees(trees)
        
        all_x = []
        all_y = []
        
        def collect(node):
            all_x.append(node.x)
            all_y.append(node.y)
            for c in node.children:
                collect(c)
        
        for t in trees:
            collect(t)
        
        min_x, max_x = min(all_x) - self.NODE_WIDTH, max(all_x) + self.NODE_WIDTH
        min_y, max_y = min(all_y), max(all_y) + self.NODE_HEIGHT + self.V_SPACING
        
        width = max(800, max_x - min_x + 100)
        height = max(600, max_y + 100)
        
        svg = f'<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">'
        svg += '<style>.node rect{transition:all .2s;cursor:pointer}.node:hover rect{fill:#2d2d2d;stroke:#569cd6}.node.self-ref rect{fill:#3d1f1f;stroke:#e94560}</style>'
        svg += f'<rect width="100%" height="100%" fill="#1e1e1e"/>'
        
        for t in trees:
            svg += self._render_tree(t, set(self_refs))
        
        svg += '</svg>'
        return svg
    
    def _generate_html(self) -> str:
        cycles, self_refs = self._detect_cycles()
        svg = self._generate_svg(self_refs)
        func_count = len([n for n in self.nodes.values() if n.type != 'module'])
        
        warning_html = ''
        if cycles or self_refs:
            warnings = []
            if self_refs:
                names = [self.nodes[n].name for n in self_refs]
                warnings.append(f'<strong>Self-referencing:</strong> {", ".join(names)}')
            if cycles:
                for cycle in cycles[:3]:
                    cycle_names = []
                    for n in cycle:
                        if n in self.nodes:
                            cycle_names.append(self.nodes[n].name)
                        else:
                            cycle_names.append(n.split('::')[-1] if '::' in n else n)
                    names = ' → '.join(cycle_names)
                    warnings.append(f'<strong>Circular flow:</strong> {names}')
            
            warning_html = f'''
        <div class="warning-banner">
            <span class="warning-icon">!</span>
            <div class="warning-content">
                <strong>Circular references detected:</strong>
                <ul>
                    {''.join(f'<li>{w}</li>' for w in warnings)}
                </ul>
            </div>
        </div>'''
        
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodeSentinel - Call Graph</title>
    <style>
        *{{margin:0;padding:0;box-sizing:border-box}}
        body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;min-height:100vh}}
        .header{{background:#161b22;border-bottom:1px solid #30363d;padding:16px 24px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:10}}
        .header h1{{color:#e94560;font-size:20px;font-weight:600}}
        .stats{{color:#8b949e;font-size:14px}}
        .stats span{{color:#58a6ff;font-weight:600}}
        .container{{padding:24px}}
        .warning-banner{{background:#2d1f1f;border:1px solid #e94560;border-radius:8px;padding:16px;margin-bottom:20px;display:flex;align-items:flex-start;gap:12px}}
        .warning-icon{{font-size:24px}}
        .warning-content{{color:#f08888;font-size:13px}}
        .warning-content ul{{margin:8px 0 0 20px;padding:0}}
        .warning-content li{{margin:4px 0}}
        .graph-wrapper{{background:#1e1e1e;border:1px solid #3c3c3c;border-radius:8px;padding:20px;overflow:auto}}
        .legend{{margin-top:20px;padding:16px;background:#161b22;border:1px solid #30363d;border-radius:8px;display:flex;gap:24px;font-size:12px;color:#8b949e}}
        .legend-item{{display:flex;align-items:center;gap:8px}}
        .legend-color{{width:14px;height:14px;border-radius:4px}}
        .self-ref{{fill:#3d1f1f !important;stroke:#e94560 !important}}
    </style>
</head>
<body>
    <div class="header">
        <h1>CodeSentinel - Call Graph</h1>
        <div class="stats"><span>{func_count}</span> functions, <span>{len(self.edges)}</span> calls</div>
    </div>
    <div class="container">
        {warning_html}
        <div class="graph-wrapper">{svg}</div>
        <div class="legend">
            <div class="legend-item"><div class="legend-color" style="background:#dcdcaa;"></div><span>Function name</span></div>
            <div class="legend-item"><div class="legend-color" style="background:#608b4e;"></div><span>file:line</span></div>
            <div class="legend-item"><div class="legend-color" style="background:#569cd6;"></div><span>Call flow (top → bottom)</span></div>
            <div class="legend-item"><div class="legend-color" style="background:#e94560;"></div><span>Self-referencing (recursion)</span></div>
        </div>
    </div>
</body>
</html>'''
    
    def get_stats(self) -> Dict:
        func_nodes = [n for n in self.nodes.values() if n.type != 'module']
        return {'num_nodes': len(func_nodes), 'num_edges': len(self.edges)}
