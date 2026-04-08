import sys
from pathlib import Path
import textwrap

# Ensure Python path includes src so we can import the detector
ROOT = Path(__file__).resolve().parents[2]  # code-sentinel/.. up to repo root
SRC = ROOT / 'src'
sys.path.insert(0, str(SRC))

from scanner.framework_detector import FrameworkDetector

def test_framework_detector_flask(tmp_path):
    # Create a minimal Flask-like Python file
    p = tmp_path / "app.py"
    p.write_text(textwrap.dedent('\n'.join([
        'from flask import Flask',
        'app = Flask(__name__)',
        'from flask import render_template',
    ])))
    det = FrameworkDetector(tmp_path)
    fw = det.detect()
    assert fw == 'flask'
