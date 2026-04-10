import textwrap
from pathlib import Path
import sys

# Ensure the local src is on sys.path for imports
BASE = Path(__file__).resolve().parents[1] / 'src'
sys.path.insert(0, str(BASE))

from callgraph.callgraph import CallGraphBuilder


def test_cross_file_import_within_function(tmp_path: Path):
    # Create a tiny two-file project where an import happens inside a function
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

    cg = CallGraphBuilder(str(tmp_path))
    graph = cg.build_graph()
    moduleA = str(a_path.resolve())
    moduleB = str(b_path.resolve())

    # Nodes exist
    assert any(n for n in graph.nodes.values() if n.id == moduleA and n.type == 'module')
    assert any(n for n in graph.nodes.values() if n.id == moduleB and n.type == 'module')
    assert any(n for n in graph.nodes.values() if n.id == f"{moduleA}::a" and n.type == 'function')
    assert any(n for n in graph.nodes.values() if n.id == f"{moduleB}::b" and n.type == 'function')

    # Edge from A.a to B.b
    assert any(e for e in graph.edges if e.src_id == f"{moduleA}::a" and e.dst_id == f"{moduleB}::b" and e.kind == 'CALL')
