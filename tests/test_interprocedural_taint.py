import textwrap
import sys
from pathlib import Path

# Adjust Python path to import local library
BASE = Path(__file__).resolve().parents[1] / 'src'
sys.path.insert(0, str(BASE))

from analyzer.static_analyzer import StaticAnalyzer


def _analyze(tmp_path: Path, files: dict):
    # Write files to disk
    for fname, content in files.items():
        p = tmp_path / fname
        p.write_text(textwrap.dedent(content))
    project_path = tmp_path
    project_info = {
        "language": "python",
        "files": list(files.keys()),
    }
    sa = StaticAnalyzer(project_path, project_info)
    return sa.analyze()


def test_interprocedural_taint_across_modules(tmp_path: Path):
    code_a = '''
        from moduleB import b
        from flask import request

        def a():
            cmd = request.args.get('cmd')
            b(cmd)
    '''
    code_b = '''
        import os
        def b(param):
            os.system(param)
    '''
    files = {
        'moduleA.py': code_a,
        'moduleB.py': code_b,
    }
    result = _analyze(tmp_path, files)
    findings = result.get('findings', [])
    print(findings)
    assert any(f.get('id') == 'TAINT001' for f in findings), findings
