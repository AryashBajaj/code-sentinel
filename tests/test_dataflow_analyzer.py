"""Comprehensive tests for DataFlowAnalyzer.

Tests cover:
- Graph structure (nodes, edges)
- Taint source detection
- Taint propagation (return values, parameters)
- Sink detection
- Full vulnerability paths
"""
import textwrap
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parents[1] / 'src'
sys.path.insert(0, str(BASE))

from callgraph.dataflow import DataFlowAnalyzer


class TestGraphStructure:
    """Tests for basic graph construction."""

    def test_single_file_single_function(self, tmp_path: Path):
        f = tmp_path / 'single.py'
        f.write_text('def foo(): pass')

        analyzer = DataFlowAnalyzer(tmp_path)
        result = analyzer.analyze()
        graph = result['graph']

        assert len(graph.nodes) == 2  # 1 module + 1 function
        assert len(graph.edges) == 0
        assert any(n.name == 'foo' for n in graph.nodes.values())

    def test_multiple_functions_same_file(self, tmp_path: Path):
        f = tmp_path / 'multi.py'
        f.write_text(textwrap.dedent('''
            def a(): pass
            def b(): pass
            def c(): a()
        '''))

        analyzer = DataFlowAnalyzer(tmp_path)
        result = analyzer.analyze()
        graph = result['graph']

        assert len(graph.nodes) == 4  # 1 module + 3 functions
        assert len(graph.edges) == 1  # c -> a

    def test_cross_file_imports(self, tmp_path: Path):
        a = tmp_path / 'a.py'
        b = tmp_path / 'b.py'
        a.write_text(textwrap.dedent('''
            from b import foo
            def bar():
                foo()
        '''))
        b.write_text('def foo(): pass')

        analyzer = DataFlowAnalyzer(tmp_path)
        result = analyzer.analyze()
        graph = result['graph']

        assert len(graph.edges) >= 1
        assert any(e.kind == 'CALL' for e in graph.edges)


class TestTaintSourceDetection:
    """Tests for identifying taint sources."""

    def test_source_function_marked(self, tmp_path: Path):
        f = tmp_path / 'source.py'
        f.write_text(textwrap.dedent('''
            def source():
                return "tainted"
        '''))

        analyzer = DataFlowAnalyzer(tmp_path)
        result = analyzer.analyze()

        func_key = f"{str(f.resolve())}::source"
        assert func_key in analyzer.tainted_funcs

    def test_input_call_marked(self, tmp_path: Path):
        f = tmp_path / 'input_demo.py'
        f.write_text(textwrap.dedent('''
            def get_user_input():
                return input()
        '''))

        analyzer = DataFlowAnalyzer(tmp_path)
        result = analyzer.analyze()

        func_key = f"{str(f.resolve())}::get_user_input"
        assert func_key in analyzer.tainted_funcs

    def test_normal_function_not_marked(self, tmp_path: Path):
        f = tmp_path / 'normal.py'
        f.write_text(textwrap.dedent('''
            def process(data):
                return data.upper()
        '''))

        analyzer = DataFlowAnalyzer(tmp_path)
        result = analyzer.analyze()

        func_key = f"{str(f.resolve())}::process"
        assert func_key not in analyzer.tainted_funcs


class TestTaintPropagation:
    """Tests for taint propagation through function calls."""

    def test_return_taint_propagates_to_caller(self, tmp_path: Path):
        a = tmp_path / 'a.py'
        b = tmp_path / 'b.py'
        a.write_text(textwrap.dedent('''
            def source():
                return "tainted"
            def main():
                return source()
        '''))
        b.write_text('def sink(x): pass')

        analyzer = DataFlowAnalyzer(tmp_path)
        result = analyzer.analyze()

        main_key = f"{str(a.resolve())}::main"
        assert main_key in analyzer.tainted_funcs

    def test_functions_with_parameters_receive_taint(self, tmp_path: Path):
        a = tmp_path / 'a.py'
        b = tmp_path / 'b.py'
        a.write_text(textwrap.dedent('''
            def source():
                return "tainted"
            def main():
                cmd = source()
                from b import sink
                sink(cmd)
        '''))
        b.write_text(textwrap.dedent('''
            def sink(x):
                pass
        '''))

        analyzer = DataFlowAnalyzer(tmp_path)
        result = analyzer.analyze()

        main_key = f"{str(a.resolve())}::main"
        assert main_key in analyzer.tainted_funcs


class TestSinkDetection:
    """Tests for detecting dangerous sinks with taint."""

    def test_os_system_with_taint_source(self, tmp_path: Path):
        entry = tmp_path / 'entry.py'
        b = tmp_path / 'b.py'
        entry.write_text(textwrap.dedent('''
            def source():
                return "tainted"
            def main():
                cmd = source()
                from b import run_cmd
                run_cmd(cmd)
        '''))
        b.write_text(textwrap.dedent('''
            import os
            def run_cmd(cmd):
                os.system(cmd)
        '''))

        analyzer = DataFlowAnalyzer(tmp_path)
        result = analyzer.analyze()
        findings = result['findings']

        assert any('os.system' in str(f.get('matched_code', '')) for f in findings)

    def test_eval_with_taint_source(self, tmp_path: Path):
        entry = tmp_path / 'entry.py'
        entry.write_text(textwrap.dedent('''
            def source():
                return "tainted"
            def main():
                code = source()
                exec(code)
        '''))

        analyzer = DataFlowAnalyzer(tmp_path)
        result = analyzer.analyze()
        findings = result['findings']

        assert any('exec' in str(f.get('matched_code', '')) for f in findings)


class TestFullVulnerabilityPath:
    """Tests for complete vulnerability detection."""

    def test_source_to_sink_full_path(self, tmp_path: Path):
        entry = tmp_path / 'entry.py'
        a = tmp_path / 'a.py'
        b = tmp_path / 'b.py'

        entry.write_text(textwrap.dedent('''
            def source():
                return "user_input"
            def main():
                cmd = source()
                from a import handler
                handler(cmd)
        '''))
        a.write_text(textwrap.dedent('''
            def handler(cmd):
                from b import execute
                execute(cmd)
        '''))
        b.write_text(textwrap.dedent('''
            def execute(cmd):
                import os
                os.system(cmd)
        '''))

        analyzer = DataFlowAnalyzer(tmp_path)
        result = analyzer.analyze()
        findings = result['findings']

        assert len(findings) > 0, "Should find taint-to-sink vulnerability"
        assert any(f.get('id') == 'TAINT001' for f in findings), "Should have TAINT001 finding"

    def test_environment_variable_to_command_injection(self, tmp_path: Path):
        entry = tmp_path / 'entry.py'
        sink = tmp_path / 'sink.py'

        entry.write_text(textwrap.dedent('''
            import os
            def get_cmd():
                return os.environ.get('CMD', 'safe')
            def run():
                from sink import exec_cmd
                cmd = get_cmd()
                exec_cmd(cmd)
        '''))
        sink.write_text(textwrap.dedent('''
            import os
            def exec_cmd(cmd):
                os.system(cmd)
        '''))

        analyzer = DataFlowAnalyzer(tmp_path)
        result = analyzer.analyze()
        findings = result['findings']

        assert any('TAINT001' in str(f.get('id', '')) for f in findings)

    def test_two_level_nested_calls(self, tmp_path: Path):
        entry = tmp_path / 'entry.py'
        middle = tmp_path / 'middle.py'

        entry.write_text(textwrap.dedent('''
            def source():
                return "tainted"
            def level1():
                x = source()
                from middle import level2
                level2(x)
        '''))
        middle.write_text(textwrap.dedent('''
            import os
            def level2(cmd):
                os.system(cmd)
        '''))

        analyzer = DataFlowAnalyzer(tmp_path)
        result = analyzer.analyze()
        findings = result['findings']

        assert len(findings) > 0, "Should detect taint through two levels of calls"


class TestGraphExport:
    """Tests for graph export functionality."""

    def test_json_export_valid(self, tmp_path: Path):
        a = tmp_path / 'a.py'
        b = tmp_path / 'b.py'
        a.write_text('from b import foo\ndef bar(): foo()')
        b.write_text('def foo(): pass')

        analyzer = DataFlowAnalyzer(tmp_path)
        result = analyzer.analyze()
        graph = result['graph']

        import json
        json_out = graph.to_json()
        data = json.loads(json_out)

        assert 'nodes' in data
        assert 'edges' in data
        assert len(data['nodes']) > 0

    def test_dot_export_valid(self, tmp_path: Path):
        f = tmp_path / 'simple.py'
        f.write_text('def foo(): pass')

        analyzer = DataFlowAnalyzer(tmp_path)
        result = analyzer.analyze()
        graph = result['graph']

        dot_out = graph.to_dot()

        assert 'digraph CallGraph' in dot_out
        assert 'foo' in dot_out


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_project(self, tmp_path: Path):
        analyzer = DataFlowAnalyzer(tmp_path)
        result = analyzer.analyze()

        assert result['stats']['nodes'] == 0
        assert result['stats']['edges'] == 0

    def test_no_python_files(self, tmp_path: Path):
        txt = tmp_path / 'readme.txt'
        txt.write_text('This is not Python code')

        analyzer = DataFlowAnalyzer(tmp_path)
        result = analyzer.analyze()

        assert result['stats']['nodes'] == 0
        assert result['stats']['edges'] == 0

    def test_inner_imports_create_edges(self, tmp_path: Path):
        a = tmp_path / 'inner.py'
        b = tmp_path / 'target.py'
        a.write_text(textwrap.dedent('''
            def caller():
                from target import target_func
                target_func()
        '''))
        b.write_text('def target_func(): pass')

        analyzer = DataFlowAnalyzer(tmp_path)
        result = analyzer.analyze()
        graph = result['graph']

        assert len(graph.edges) >= 1
        assert any(e.kind == 'CALL' for e in graph.edges)
