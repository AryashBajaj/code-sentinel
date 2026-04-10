import json
import textwrap
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parents[1] / 'src'
sys.path.insert(0, str(BASE))

from callgraph.dataflow import DataFlowAnalyzer


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

    analyzer = DataFlowAnalyzer(tmp_path)
    result = analyzer.analyze()
    graph = result['graph']

    json_out = graph.to_json()
    dot_out = graph.to_dot()

    data = json.loads(json_out)
    assert 'nodes' in data and 'edges' in data, "JSON should contain nodes and edges"
    assert isinstance(dot_out, str) and dot_out.startswith("digraph CallGraph"), "DOT output should be valid"
