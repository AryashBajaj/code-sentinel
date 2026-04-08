import sys
from pathlib import Path
import textwrap

BASE = Path(__file__).resolve().parents[2] / 'src'
sys.path.insert(0, str(BASE))
from analyzer.fastapi_ast import FastApiAstAnalyzer

def test_fastapi_endpoint_without_response_model(tmp_path):
    app_py = tmp_path / 'main.py'
    code = textwrap.dedent('''
        from fastapi import FastAPI
        app = FastAPI()

        @app.get("/")
        def read_root():
            return {"hello": "world"}
    ''')
    app_py.write_text(code)
    project_path = tmp_path
    project_info = {"language": "python", "files": [str(app_py.name)]}
    analyzer = FastApiAstAnalyzer(project_path, project_info)
    result = analyzer.analyze()
    findings = result.get("findings", [])
    assert isinstance(findings, list)
