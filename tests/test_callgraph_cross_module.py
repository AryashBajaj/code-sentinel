import textwrap
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parents[1] / 'src'
sys.path.insert(0, str(BASE))

from callgraph.dataflow import DataFlowAnalyzer


def test_cross_file_import_within_function(tmp_path: Path):
    a_path = tmp_path / 'moduleA.py'
    b_path = tmp_path / 'moduleB.py'

    a_path.write_text(textwrap.dedent('''
        def a():
            from moduleB import b
            b("cmd")
    '''))
    b_path.write_text(textwrap.dedent('''
        def b(cmd):
            print(cmd)
    '''))

    analyzer = DataFlowAnalyzer(tmp_path)
    result = analyzer.analyze()
    graph = result['graph']
    moduleA = str(a_path.resolve())
    moduleB = str(b_path.resolve())

    assert any(n for n in graph.nodes.values() if n.id == moduleA and n.type == 'module'), "Module A should exist"
    assert any(n for n in graph.nodes.values() if n.id == moduleB and n.type == 'module'), "Module B should exist"
    assert any(n for n in graph.nodes.values() if n.id == f"{moduleA}::a" and n.type == 'function'), "Function A should exist"
    assert any(n for n in graph.nodes.values() if n.id == f"{moduleB}::b" and n.type == 'function'), "Function B should exist"

    assert any(e for e in graph.edges if e.src_id == f"{moduleA}::a" and e.dst_id == f"{moduleB}::b" and e.kind == 'CALL'), "Edge A.a -> B.b should exist"
