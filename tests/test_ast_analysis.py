import os
import textwrap
from pathlib import Path
import sys

# Adjust Python path to import the library from the local code-sentinel src
BASE = Path(__file__).resolve().parents[1] / 'src'
sys.path.insert(0, str(BASE))
from analyzer.static_analyzer import StaticAnalyzer

def test_python_ast_analysis_detects_os_system(tmp_path):
    # Create a tiny Python file with an OS command execution pattern
    code = textwrap.dedent("""
        import os
        def run(cmd):
            os.system(cmd)
    """)
    p = tmp_path / "example.py"
    p.write_text(code)

    project_path = tmp_path
    project_info = {
        "language": "python",
        "files": [str(p.name)],
    }

    sa = StaticAnalyzer(project_path, project_info)
    result = sa.analyze()
    findings = result.get("findings", [])
    assert isinstance(findings, list)
    assert any(f.get("id") == "PY001" for f in findings), f"Expected PY001, got {findings}"
