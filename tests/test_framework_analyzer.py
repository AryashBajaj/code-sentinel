import sys
from pathlib import Path
import textwrap

# Ensure Python path includes src so we can import FrameworkAnalyzer
ROOT = Path(__file__).resolve().parents[2]  # repo root
SRC = ROOT / 'src'
sys.path.insert(0, str(SRC))

from analyzer.framework_analyzer import FrameworkAnalyzer
from scanner.framework_detector import FrameworkDetector

def test_framework_analyzer_flask_runs(tmp_path):
    # Create a minimal Flask-like Python file
    p = tmp_path / "app.py"
    p.write_text(textwrap.dedent("""
        from flask import Flask
        app = Flask(__name__)
    """))
    project_path = tmp_path
    project_info = {
        "language": "python",
        "files": [str(p.name)],
    }
    # Framework is Flask
    fa = FrameworkAnalyzer("flask", project_path, project_info)
    res = fa.analyze({"findings": []})
    assert isinstance(res, dict)
    assert isinstance(res.get("findings"), list)
