# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Untrusted-string sanitizing (contract J.6 steps 1-6 and 8).

Every string that comes from loot, logs, CLI output or filesystem names goes
through :func:`sanitize` (steps 1-6), then redaction (step 7,
``sniper_mcp.redact``), then :func:`truncate` or :func:`truncate_tail`
(step 8). Redaction always runs before truncation, on the whole line or
window, so a cut can never leave part of a secret unredacted.

The steps are regular-expression passes, so an 8 MiB job log is cheap to
sanitize for status classification (L.3).
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

TRUNCATION_MARK = "[truncated]"

# Step 2: CSI, OSC (ended by BEL or ST), charset selections, two-character ESC
# sequences. OSC comes before the two-character rule, whose class includes "]".
# J.6 runs per line, so no sequence spans a newline: an OSC opened in one loot record
# and "closed" by a BEL in a later one must not delete the records between them (no
# other alternative can match a newline).
_ANSI_RE = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"
    r"|\x1b\][^\x07\x1b\n]*(?:\x07|\x1b\\)"
    r"|\x1b[()][0-9A-Za-z]"
    r"|\x1b[@-Z\\-_]"
)
# Step 4: C0 controls other than tab and newline (carriage returns are handled
# by step 3), DEL and the C1 controls.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
# Step 5: the tag block and the variation selectors, dropped and counted.
_INVISIBLE_RE = re.compile("[\U000e0000-\U000e007f\ufe00-\ufe0f\U000e0100-\U000e01ef]")
# Step 6 looks only at non-ASCII characters.
_NON_ASCII_RE = re.compile(r"[^\x00-\x7f]")
_VISIBLE_CATEGORIES = frozenset({"Cf", "Co", "Cn", "Cs"})


@dataclass(frozen=True)
class Sanitized:
    """Output of :func:`sanitize`: the text and how many invisible characters were dropped."""

    text: str
    invisible_removed: int


def _decode(data: bytes | str) -> str:
    """Step 1."""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


def _carriage_returns(text: str) -> str:
    """Step 3: in each line keep the text after the last carriage return.

    Trailing carriage returns (CRLF line ends, a progress bar that ends with
    one) are dropped first, so the text before them is kept.
    """
    if "\r" not in text:
        return text
    lines = text.split("\n")
    for index, line in enumerate(lines):
        if "\r" in line:
            stripped = line.rstrip("\r")
            lines[index] = stripped.rsplit("\r", 1)[-1]
    return "\n".join(lines)


def _visible(match: re.Match[str]) -> str:
    """Step 6: format, private-use, unassigned (and surrogate) characters become visible."""
    ch = match.group(0)
    if unicodedata.category(ch) in _VISIBLE_CATEGORIES:
        return f"<U+{ord(ch):04X}>"
    return ch


def sanitize(data: bytes | str) -> Sanitized:
    """J.6 steps 1-6 on one string, line or window."""
    text = _decode(data)
    text = _ANSI_RE.sub("", text)
    text = _carriage_returns(text)
    text = _CONTROL_RE.sub("", text)
    text, invisible = _INVISIBLE_RE.subn("", text)
    if not text.isascii():
        text = _NON_ASCII_RE.sub(_visible, text)
    return Sanitized(text=text, invisible_removed=invisible)


def truncate(text: str, cap: int) -> tuple[str, bool]:
    """Step 8: keep at most ``cap`` characters, ending with ``[truncated]`` when cut."""
    if len(text) <= cap:
        return text, False
    keep = max(cap - len(TRUNCATION_MARK), 0)
    return text[:keep] + TRUNCATION_MARK, True


def truncate_cut(text: str, cap: int) -> str:
    """Step 8 for text whose source was already cut before step 1 (a ``grep_loot`` line
    cut while it streamed in, J.5): at most ``cap`` characters, always ending with
    ``[truncated]``."""
    keep = max(cap - len(TRUNCATION_MARK), 0)
    return text[:keep] + TRUNCATION_MARK


def truncate_tail(text: str, cap: int) -> tuple[str, bool]:
    """Step 8 for log tails: keep the last characters, marking the cut at the start."""
    if len(text) <= cap:
        return text, False
    keep = max(cap - len(TRUNCATION_MARK), 0)
    return TRUNCATION_MARK + (text[-keep:] if keep else ""), True
