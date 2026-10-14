# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""``expect_violation()``: consume guard trips that a test causes on purpose.

Only tests/test_guard.py may import this (meta-test, contract O.2). Any other
recorded violation fails the test that caused it and the whole session.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

from tests.guard import hook

# Captured at import time, so patching attributes of the hook module or of the
# state object later cannot detach this from the hook's private ledger.
_STATE = hook.state()
_COUNT = _STATE.recorded_count if _STATE is not None else None
_SINCE = _STATE.recorded_since if _STATE is not None else None
_CONSUME = _STATE.consume if _STATE is not None else None
_CHILD_FILES = hook.child_violation_files
_READ_CHILD = hook.read_child_violations


@dataclass
class Expected:
    """What happened inside one ``expect_violation()`` block."""

    start: int
    violations: list[hook.Violation] = field(default_factory=list)

    def pending(self) -> list[hook.Violation]:
        """Violations recorded so far in this block and not yet consumed."""
        assert _SINCE is not None
        return [v for v in _SINCE(self.start) if not v.consumed]


@contextmanager
def expect_violation(kind: str | None = None) -> Iterator[Expected]:
    """Mark the violations recorded inside the block as expected.

    Fails if none was recorded, or if ``kind`` is given and none has that kind.
    """
    if _COUNT is None or _SINCE is None or _CONSUME is None:
        raise AssertionError("the test guard is not installed")
    record = Expected(start=_COUNT())
    try:
        yield record
    finally:
        new = _SINCE(record.start)
        for violation in new:
            _CONSUME(violation)
        record.violations = list(new)
    if not record.violations:
        raise AssertionError("expected a guard violation, none was recorded")
    if kind is not None and not any(v.kind == kind for v in record.violations):
        raise AssertionError(f"expected a {kind!r} guard violation, got "
                             f"{[v.describe() for v in record.violations]}")


@contextmanager
def expect_child_violation(root: str, kind: str | None = None) -> Iterator[list[dict]]:
    """Mark the violations that guarded children write below ``root`` as expected.

    ``root`` is a directory the test gave its children as their temp root. On
    exit the violations are checked like ``expect_violation()`` and their files
    are removed, which is how a child's trip is consumed; any other child file
    fails the test and the session. An entry named like a child violation file that
    a child cannot have written to (a link, a FIFO, a hard-linked file; the reader
    marks it ``unusable``) is never consumed: it fails the test here and stays in
    place, so the test's teardown check and the session fail too.
    """
    found: list[dict] = []
    unusable: list[dict] = []
    try:
        yield found
    finally:
        for item in _READ_CHILD(root, recursive=True):
            (unusable if item.get("unusable") else found).append(item)
        kept = {item.get("path") for item in unusable}
        for path in _CHILD_FILES(root, recursive=True):
            if path not in kept:
                os.remove(path)
    if unusable:
        raise AssertionError("a child violation file a guarded child cannot have written "
                             f"to (never consumed): {[item['detail'] for item in unusable]}")
    if not found:
        raise AssertionError(f"expected a guarded child's violation below {root}, none")
    if kind is not None and not any(item.get("kind") == kind for item in found):
        raise AssertionError(f"expected a {kind!r} child violation, got {found}")
