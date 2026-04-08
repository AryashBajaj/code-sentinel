# Compatibility shim to help tests import analyzer modules from the repo root
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / 'src'
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
