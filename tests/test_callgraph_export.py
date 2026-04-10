import json
import textwrap
from pathlib import Path
import sys

# Ensure local path is in sys.path for imports
BASE = Path(__file__).resolve().parents[1] / 'src'
sys.path.insert(0, str(BASE))

from callgraph.callgraph import CallGraphBuilder


def test_export_json_and_dot_basic(tmp_path: Path):
    a = tmp_path / 'moduleA.py'
    b = tmp_path / 'moduleB.py'
    a.write_text(textwrap.dedent('''
        from moduleB import b
        def a():
            b(1)
    '''))
    b.write_text(textwrap.dedent('''
        def b(x):
            pass
    '''))

    cg = CallGraphBuilder(tmp_path)
    graph = cg.build_graph()
    # Export to JSON and DOT and ensure valid strings
    json_out = graph.to_json()
    dot_out = graph.to_dot()
    # Validate JSON parses
    data = json.loads(json_out)
    assert 'nodes' in data and 'edges' in data
    assert isinstance(dot_out, str) and dot_out.startswith("digraph CallGraph")
