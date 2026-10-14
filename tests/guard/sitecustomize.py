# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Installs the test guard in every ``sys.executable`` child of the test suite.

Test children get ``PYTHONPATH=<repo>/tests/guard`` (first entry), so Python
imports this module at startup. With ``SN1PER_MCP_TEST_GUARD`` the child gets
the same rules as the test session; without it every process creation and
network call is blocked. The variable only restricts; it never enables
anything (contract O.2, O.7).
"""

from __future__ import annotations

import importlib.util
import os
import sys

_HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hook.py")
_spec = importlib.util.spec_from_file_location("_sn1per_mcp_guard_hook", _HOOK)
if _spec is None or _spec.loader is None:  # pragma: no cover - guard must never be skipped
    raise SystemExit("sn1per-mcp test guard: cannot load hook.py")
_module = importlib.util.module_from_spec(_spec)
sys.modules["_sn1per_mcp_guard_hook"] = _module
_spec.loader.exec_module(_module)
_module.install_from_environment()
