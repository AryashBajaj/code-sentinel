import textwrap
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parents[1] / 'src'
sys.path.insert(0, str(BASE))

from callgraph.dataflow import DataFlowAnalyzer


def test_cross_module_source_return_taint(tmp_path: Path):
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

    analyzer = DataFlowAnalyzer(root)
    result = analyzer.analyze()
    graph = result['graph']
    findings = result['findings']

    module_entry = str(entry.resolve())
    module_a = str(a.resolve())
    module_b = str(b.resolve())

    assert any(n for n in graph.nodes.values() if n.id == module_entry and n.type == 'module'), "Entry module should exist"
    assert any(n for n in graph.nodes.values() if n.id == f"{module_entry}::main" and n.type == 'function'), "main() should exist"
    assert any(n for n in graph.nodes.values() if n.id == module_a and n.type == 'module'), "Module A should exist"
    assert any(n for n in graph.nodes.values() if n.id == f"{module_a}::a_sink" and n.type == 'function'), "a_sink() should exist"
    assert any(n for n in graph.nodes.values() if n.id == module_b and n.type == 'module'), "Module B should exist"
    assert any(n for n in graph.nodes.values() if n.id == f"{module_b}::sink" and n.type == 'function'), "sink() should exist"

    assert any(e for e in graph.edges if e.src_id == f"{module_entry}::main" and e.dst_id == f"{module_a}::a_sink" and e.kind == 'CALL'), "main -> a_sink edge should exist"
    assert any(e for e in graph.edges if e.src_id == f"{module_a}::a_sink" and e.dst_id == f"{module_b}::sink" and e.kind == 'CALL'), "a_sink -> sink edge should exist"

    assert any(f.get('id') == 'TAINT001' for f in findings), "Taint finding should be detected"
