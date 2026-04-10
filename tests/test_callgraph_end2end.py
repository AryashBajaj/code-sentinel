import textwrap
from pathlib import Path
import sys

# Ensure local path is in sys.path for imports
BASE = Path(__file__).resolve().parents[1] / 'src'
sys.path.insert(0, str(BASE))

from callgraph.callgraph import CallGraphBuilder


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

    cg = CallGraphBuilder(tmp_path)
    graph = cg.build_graph()
    moduleA = str(a.resolve())
    moduleB = str(b.resolve())
    # Check modules exist
    assert any(n for n in graph.nodes.values() if n.id == moduleA and n.type == 'module')
    assert any(n for n in graph.nodes.values() if n.id == moduleB and n.type == 'module')
    # Check functions exist
    assert any(n for n in graph.nodes.values() if n.id == f"{moduleA}::a" and n.type == 'function')
    assert any(n for n in graph.nodes.values() if n.id == f"{moduleB}::b" and n.type == 'function')
    # Cross-file edge
    assert any(e for e in graph.edges if e.src_id == f"{moduleA}::a" and e.dst_id == f"{moduleB}::b" and e.kind == 'CALL')
