import textwrap
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parents[1] / 'src'
sys.path.insert(0, str(BASE))

from callgraph.dataflow import DataFlowAnalyzer


def test_end2end_basic_cross_file(tmp_path: Path):
    a = tmp_path / 'moduleA.py'
    b = tmp_path / 'moduleB.py'
    a.write_text(textwrap.dedent('''
        from moduleB import b
        def a():
            cmd = 'cmd'
            b(cmd)
    '''))
    b.write_text(textwrap.dedent('''
        def b(param):
            import os
            os.system(param)
    '''))

    analyzer = DataFlowAnalyzer(tmp_path)
    result = analyzer.analyze()
    graph = result['graph']
    moduleA = str(a.resolve())
    moduleB = str(b.resolve())

    assert any(n for n in graph.nodes.values() if n.id == moduleA and n.type == 'module'), "Module A should exist"
    assert any(n for n in graph.nodes.values() if n.id == moduleB and n.type == 'module'), "Module B should exist"
    assert any(n for n in graph.nodes.values() if n.id == f"{moduleA}::a" and n.type == 'function'), "Function A should exist"
    assert any(n for n in graph.nodes.values() if n.id == f"{moduleB}::b" and n.type == 'function'), "Function B should exist"
    assert any(e for e in graph.edges if e.src_id == f"{moduleA}::a" and e.dst_id == f"{moduleB}::b" and e.kind == 'CALL'), "Cross-file edge should exist"
