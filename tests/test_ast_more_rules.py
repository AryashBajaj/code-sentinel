import sys
from pathlib import Path
import textwrap

BASE = Path(__file__).resolve().parents[2] / 'src'
sys.path.insert(0, str(BASE))
from analyzer.static_analyzer import StaticAnalyzer

def test_ast_detector_hardcoded_secrets(tmp_path):
    code = textwrap.dedent("""
    SECRET_TOKEN = 'verysecret'
    PASSWORD = 'supersecret123'
    database_url = 'postgresql://user:pass@localhost/db'
    """)
    p = tmp_path / "sec.py"
    p.write_text(code)
    project_path = tmp_path
    project_info = {"language": "python", "files": [str(p.name)]}
    sa = StaticAnalyzer(project_path, project_info)
    result = sa.analyze()
    findings = result.get("findings", [])
    # Expect at least the SEC001 hardcoded secrets to be detected
    assert any(f.get("id") == "SEC001" for f in findings)
