# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""A.2: src/ imports no third-party package other than the three runtime dependencies."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "sniper_mcp"
ALLOWED = {"mcp", "idna", "pydantic", "sniper_mcp"}


def _top_level_imports(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return names


def test_src_imports_only_the_stdlib_and_the_three_dependencies():
    files = sorted(SRC.rglob("*.py"))
    assert files
    offending = {
        f"{path.relative_to(SRC)}: {name}"
        for path in files
        for name in _top_level_imports(path)
        if name not in sys.stdlib_module_names and name not in ALLOWED
    }
    assert offending == set()
