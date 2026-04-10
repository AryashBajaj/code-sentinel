import textwrap
from pathlib import Path
import sys

# Ensure local src is on sys.path for imports
BASE = Path(__file__).resolve().parents[1] / 'src'
sys.path.insert(0, str(BASE))

from callgraph.callgraph import CallGraphBuilder
import os


def test_cross_module_source_return_taint(tmp_path: Path):
    # Create a three-file mini-project simulating: entry -> a_sink -> sink, with source() using environment
    root = tmp_path
    entry = root / 'entry.py'
    a = root / 'a.py'
    b = root / 'b.py'

    entry.write_text(textwrap.dedent('''
        import os
        def source():
            return os.environ.get('TAINT_CMD', 'echo benign')
        def main():
            cmd = source()
            from a import a_sink
            a_sink(cmd)
    '''))
    a.write_text(textwrap.dedent('''
        def a_sink(cmd):
            from b import sink
            sink(cmd)
    '''))
    b.write_text(textwrap.dedent('''
        def sink(cmd):
            import os
            os.system(cmd)
    '''))

    cg = CallGraphBuilder(str(root))
    graph = cg.build_graph()
    module_entry = str(entry.resolve())
    module_a = str(a.resolve())
    module_b = str(b.resolve())
    # Ensure modules and functions exist
    assert any(n for n in graph.nodes.values() if n.id == module_entry and n.type == 'module')
    assert any(n for n in graph.nodes.values() if n.id == f"{module_entry}::main" and n.type == 'function')
    assert any(n for n in graph.nodes.values() if n.id == module_a and n.type == 'module')
    assert any(n for n in graph.nodes.values() if n.id == f"{module_a}::a_sink" and n.type == 'function')
    assert any(n for n in graph.nodes.values() if n.id == module_b and n.type == 'module')
    assert any(n for n in graph.nodes.values() if n.id == f"{module_b}::sink" and n.type == 'function')
    # Edges: entry.main -> a_sink, a_sink -> sink
    assert any(e for e in graph.edges if e.src_id == f"{module_entry}::main" and e.dst_id == f"{module_a}::a_sink" and e.kind == 'CALL')
    assert any(e for e in graph.edges if e.src_id == f"{module_a}::a_sink" and e.dst_id == f"{module_b}::sink" and e.kind == 'CALL')
