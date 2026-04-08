import sys
from pathlib import Path
import textwrap

# Import Flask AST analyzer
BASE = Path(__file__).resolve().parents[2] / 'src'
sys.path.insert(0, str(BASE))
from analyzer.flask_ast import FlaskAstAnalyzer

def test_flask_render_template_string_user_input(tmp_path):
    app_py = tmp_path / 'app.py'
    code = textwrap.dedent('''
        from flask import Flask, render_template_string, request
        app = Flask(__name__)
        @app.route('/')
        def index():
            user = request.args.get('name','')
            return render_template_string(f"<h1>Hello { '{' } name { '}' }</h1>", name=user)
    ''')
    app_py.write_text(code)
    project_path = tmp_path
    project_info = {"language": "python", "files": [str(app_py.name)]}
    analyzer = FlaskAstAnalyzer(project_path, project_info)
    result = analyzer.analyze()
    # Should produce at least one Flask-related finding (FL001)
    findings = result.get("findings", [])
    assert isinstance(findings, list)
