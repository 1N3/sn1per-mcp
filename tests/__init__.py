# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""The test package refuses to load without the isolation guard (contract O.2).

Both guard layers live in ``tests/conftest.py``. ``pytest --noconftest``,
a ``--confcutdir`` below ``tests/`` or ``-p no:<conftest>`` would skip them,
and the tests would then run against the real host. This package therefore
puts an import check in front of every ``tests.*`` module other than the guard
itself: unless ``tests/conftest.py`` is loaded and has installed Layer 1, the
import fails, so pytest reports a collection error and no test body runs.
"""

from __future__ import annotations

import importlib.abc
import os
import sys

_CONFTEST = os.path.join(os.path.dirname(os.path.realpath(__file__)), "conftest.py")
_GUARD_STATE_ATTR = "_sn1per_mcp_test_guard_state"
# Modules the conftest itself needs before it can install the guard.
_UNCHECKED = frozenset({"tests.conftest", "tests.realpaths"})


def guard_armed() -> bool:
    """True when tests/conftest.py is loaded and its Layer 1 install has run."""
    if getattr(sys, _GUARD_STATE_ATTR, None) is None:
        return False
    for module in list(sys.modules.values()):
        path = getattr(module, "__file__", None)
        if path and os.path.realpath(path) == _CONFTEST:
            return getattr(module, "_GUARD_STATE", None) is not None
    return False


class _GuardRequired(importlib.abc.MetaPathFinder):
    """Refuses to import test modules while the guard is not armed."""

    def find_spec(self, fullname, path, target=None):
        if (fullname.startswith("tests.") and fullname not in _UNCHECKED
                and not fullname.startswith("tests.guard")
                and not guard_armed()):
            raise ImportError(
                f"refusing to import {fullname}: the sn1per-mcp test isolation guard "
                "(tests/conftest.py) is not active. Run the suite as "
                "'python -m pytest -q -p no:cacheprovider', without --noconftest, "
                "a --confcutdir below tests/ or -p no:<conftest> (contract O.2).")
        return None


sys.meta_path.insert(0, _GuardRequired())
