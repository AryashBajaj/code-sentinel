"""Import resolution utilities for call graph construction."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional, Tuple


class ImportResolver:
    def __init__(self, root_path: Path):
        self.root_path = Path(root_path).resolve()

    def resolve_module_path(self, module_name: str) -> Optional[Path]:
        # Simple heuristic: module.py or package/__init__.py
        candidate = self.root_path / f"{module_name}.py"
        if candidate.exists():
            return candidate.resolve()
        package_init = self.root_path / module_name / "__init__.py"
        if package_init.exists():
            return package_init.resolve()
        return None
