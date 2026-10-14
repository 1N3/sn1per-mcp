# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Pattern redaction of secrets in untrusted strings (contract K).

:func:`redact` applies the 28 K.2 rules in order to one string, line or
window and returns the redacted text with a count per type. Every match is
replaced by ``[REDACTED:<type>]`` (some rules keep a visible prefix, such as
a user name or a header scheme word). A rule never rewrites text that an
earlier rule already replaced: replaced text is held aside as a protected
segment that later rules cannot see, so no token is redacted again or
counted twice (A-51).

Redaction is pattern-based, not data-loss prevention: new secret formats can
slip through, and personal data such as e-mail addresses is not redacted.

No literal in this module has the shape of a secret: markers are assembled
from parts, so the repository-wide secret-shape check (O.5 P0-11) stays clean.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Callable, Iterable

# A piece of builder output: (text, protected). Protected pieces are finished tokens.
Piece = tuple[str, bool]
Builder = Callable[[re.Match[str]], list[Piece]]
# What a rule's builder returns: the pieces that replace the match, the pieces plus the
# end of the text they replace (beyond the match), or None to leave the match as text.
RuleBuilder = Callable[[re.Match[str]], "list[Piece] | tuple[list[Piece], int] | None"]
# Internal: (text, kind). ``kind`` is None for plain text, the counted type for a token
# a rule inserted, and "" for a token that was already in the input (never counted).
Segment = tuple[str, str | None]

_DASHES = "-" * 5
_BEGIN = _DASHES + "BEGIN "
_END = _DASHES + "END "
# A key type is zero or more upper-case words before PRIVATE KEY (RSA, EC, OPENSSH, ...);
# OpenPGP armor adds BLOCK after it.
_KEY_TYPE = r"(?:[A-Z0-9]+ )*"
_KEY_TAIL = "PRIVATE KEY(?: BLOCK)?" + re.escape(_DASHES)
_BEGIN_RE = re.compile(re.escape(_BEGIN) + _KEY_TYPE + _KEY_TAIL)
_END_RE = re.compile(re.escape(_END) + _KEY_TYPE + _KEY_TAIL)
_ESCAPED_NEWLINE = "\\" + "n"
_KEY_BLOCK_MAX_LINES = 64

_HEX = "0-9A-Fa-f"
_SENSITIVE_SEARCH = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|apikey|api_key|api-key|access_key|private_key"
    r"|client_secret|auth_key)")
_SENSITIVE_WHOLE = re.compile(r"(?i)[A-Z0-9_]*(KEY|SECRET|TOKEN|PASS(WORD)?|WEBHOOK(_URL)?)")
_PASSWORD_KEY = re.compile(r"(?i).*(password|passwd|pwd|pass)")


def token(kind: str) -> str:
    return f"[REDACTED:{kind}]"


# --- rule 1: private keys ------------------------------------------------------------------

def _line_end(text: str, index: int) -> int:
    end = text.find("\n", index)
    return len(text) if end < 0 else end


def _nth_line_end(text: str, start: int, lines: int) -> int:
    """End (exclusive) of the ``lines``-th line counted from the line holding ``start``."""
    position = start
    for _ in range(lines):
        end = text.find("\n", position)
        if end < 0:
            return len(text)
        position = end + 1
    return position - 1


def _key_spans(text: str, *, record_line: bool = False) -> list[tuple[int, int]]:
    """Rule 1 spans: BEGIN through END blocks (also one-line blocks with literal newline
    escapes), and an END marker whose BEGIN is not in the text. In a grep or log window
    that span starts at most 64 lines back; in one loot record line (``record_line``)
    it covers only the key-shaped run glued to the marker, so a finding whose evidence
    is an END line keeps its severity and title. Merged and sorted; each span is
    ``(start, stop)`` with ``stop`` exclusive.

    Linear in the text (lines reach 64 KiB, grep re-reads 8 MiB, and both are
    attacker-written): the END markers are found once and looked up by position, the
    end of the current line is computed once per line, and the orphan-END walk-back
    never scans before the end of the previous span.
    """
    ends = [(m.start(), m.end()) for m in _END_RE.finditer(text)]
    end_starts = [start for start, _ in ends]
    spans: list[tuple[int, int]] = []
    position = 0
    line_end = -1  # first newline at or after ``after``, valid while after < line_end
    while True:
        begin = _BEGIN_RE.search(text, position)
        if begin is None:
            break
        after = begin.end()
        index = bisect.bisect_left(end_starts, after)
        following = ends[index] if index < len(ends) else None
        if text.startswith(_ESCAPED_NEWLINE, after):
            # One line with literal escapes (a JSON string): through the escaped END
            # marker, else through the end of the line.
            if after >= line_end:
                line_end = _line_end(text, after)
            stop = following[1] if following and following[1] <= line_end else line_end
        elif following is not None:
            stop = following[1]
        else:
            stop = _nth_line_end(text, begin.start(), _KEY_BLOCK_MAX_LINES)
        spans.append((begin.start(), stop))
        position = max(stop, after)
    spans = sorted(spans + _orphan_spans(text, ends, spans, record_line=record_line))
    merged: list[tuple[int, int]] = []
    for start, stop in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], stop))
        else:
            merged.append((start, stop))
    return merged


def _key_run_start(text: str, end_start: int, floor: int) -> int:
    """Start of the run of key-body characters (base64, literal newline escapes, blanks)
    that ends at ``end_start``, never before ``floor``."""
    start = end_start
    while start > floor and text[start - 1] in _KEY_RUN_CHARS:
        start -= 1
    return start


_KEY_RUN_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\\ \t")


def _orphan_spans(text: str, ends: list[tuple[int, int]], spans: list[tuple[int, int]],
                  *, record_line: bool) -> list[tuple[int, int]]:
    """END markers outside every BEGIN block (their BEGIN line lies before the window):
    from at most 64 lines back (a window) or from the start of the key-shaped run before
    the marker (a record line), never before the end of an earlier span, through END."""
    orphans: list[tuple[int, int]] = []
    index = 0
    last_stop = 0  # end of the latest span that ends before the current END marker
    for end_start, end_stop in ends:
        while index < len(spans) and spans[index][1] <= end_start:
            last_stop = max(last_stop, spans[index][1])
            index += 1
        if index < len(spans) and spans[index][0] <= end_start:
            continue  # inside a BEGIN block
        if record_line:
            orphans.append((_key_run_start(text, end_start, last_stop), end_stop))
            last_stop = max(last_stop, end_stop)
            continue
        # Every search below is bounded by last_stop, so the walk-backs of all END
        # markers together scan each character at most once.
        start = text.rfind("\n", last_stop, end_start) + 1
        for _ in range(_KEY_BLOCK_MAX_LINES - 1):
            if start <= last_stop:  # never walk back into an earlier span
                break
            start = text.rfind("\n", last_stop, start - 1) + 1
        orphans.append((max(start, last_stop), end_stop))
        last_stop = max(last_stop, end_stop)
    return orphans


def _private_keys(text: str, *, record_line: bool = False) -> list[Segment]:
    """Rule 1 on one string, line or window (``record_line``: one loot record line)."""
    if _DASHES not in text:
        return [(text, None)]
    merged = _key_spans(text, record_line=record_line)
    if not merged:
        return [(text, None)]
    segments: list[Segment] = []
    cursor = 0
    for start, stop in merged:
        if start > cursor:
            segments.append((text[cursor:start], None))
        segments.append((token("private-key"), "private-key"))
        cursor = stop
    if cursor < len(text):
        segments.append((text[cursor:], None))
    return segments


# Loot readers (J.3): a key block that spans lines is collapsed only when it is complete
# and every line inside it looks like PEM armor, so a stray or forged marker in one record
# can never swallow other records (J.6 runs per line). The bound covers RSA keys up to
# 16384 bits and long OpenPGP blocks.
_READER_BLOCK_MAX_LINES = 512
_PEM_BODY_RE = re.compile(r"[A-Za-z0-9+/=]*")
_PEM_HEADER_RE = re.compile(r"(?:Proc-Type|DEK-Info|Version|Comment|Hash|Charset|MessageID):.*")
# After a BEGIN line without its END (a file cut at 8 MiB): only lines that can only be key
# body (long base64 runs) or PEM headers are taken with it, at most 63 lines.
_PEM_STRONG_BODY_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def _pem_text(line: str) -> str:
    """The line without blanks and without an nmap NSE output prefix (``|`` or ``|_``),
    so a key that a script printed (``|   MIIE...``) is still recognized as key text."""
    text = line.strip()
    if text.startswith("|"):
        text = text[2:] if text.startswith("|_") else text[1:]
        text = text.strip()
    return text


def _pem_inner(line: str) -> bool:
    text = _pem_text(line)
    return bool(_PEM_BODY_RE.fullmatch(text) or _PEM_HEADER_RE.fullmatch(text))


def _pem_continuation(line: str) -> bool:
    text = _pem_text(line)
    return bool(_PEM_STRONG_BODY_RE.fullmatch(text) or _PEM_HEADER_RE.fullmatch(text))


def _multiline_begin(text: str) -> re.Match[str] | None:
    """The BEGIN marker of ``text`` whose block continues on the next lines: the first
    BEGIN after the last END marker of the text that is not followed by a literal
    newline escape. BEGIN markers before the last END marker belong to blocks that end
    on this line, and an escaped BEGIN runs to the end of the line; rule 1 on the line
    handles both. Each call scans ``text`` once."""
    if _BEGIN not in text:
        return None
    floor = 0
    if _END in text:
        for end in _END_RE.finditer(text):
            floor = end.end()
    for begin in _BEGIN_RE.finditer(text, floor):
        if not text.startswith(_ESCAPED_NEWLINE, begin.end()):
            return begin
    return None


def collapse_key_blocks(lines: list[str]) -> tuple[list[str], dict[int, int]]:
    """Rule 1 across the lines of one loot file (J.3, J.6).

    A BEGIN line, the lines after it and its END line become one line with one
    ``[REDACTED:private-key]`` token, but only when the END line follows within 512
    lines and every line in between is PEM body or header text. A BEGIN line without
    such an END loses the rest of its line and takes along only the following lines
    that can only be key body (base64 runs of 40 or more characters) or PEM headers,
    at most 63. Nothing else is ever joined, so a marker in one record cannot hide
    other records; markers on a single line are left to :func:`redact`.

    Returns the new lines and the number of tokens inserted per new line index.
    Linear in the input (loot files are attacker-written): each line is examined a
    bounded number of times, and when an END line opens the next block (a chain of
    ``END...BEGIN`` lines) only its own tail is searched; the joined line is built from
    a list of parts and joined once.
    """
    marker = token("private-key")
    out: list[str] = []
    counts: dict[int, int] = {}
    count = len(lines)
    index = 0
    while index < count:
        tail = lines[index]  # the part of the joined line not yet searched
        index += 1
        parts: list[str] = []
        tokens = 0
        while True:
            begin = _multiline_begin(tail)
            if begin is None:
                break
            last = min(count, index + _READER_BLOCK_MAX_LINES)
            end = None
            scan = index
            while scan < last:
                end = _END_RE.search(lines[scan]) if _END in lines[scan] else None
                if end is not None or not _pem_inner(lines[scan]):
                    break
                scan += 1
            tokens += 1
            parts += [tail[:begin.start()], marker]
            if end is not None:
                tail = lines[scan][end.end():]
                index = scan + 1
                continue  # the END line may open another block
            tail = ""
            stop = min(count, index + _KEY_BLOCK_MAX_LINES - 1)
            while index < stop and _pem_continuation(lines[index]):
                index += 1
            break
        if tokens:
            counts[len(out)] = tokens
            parts.append(tail)
            out.append("".join(parts))
        else:
            out.append(tail)
    return out, counts


def private_key_line_numbers(text: str) -> set[int]:
    """1-based numbers of every line that lies (at least partly) inside a private-key
    block of ``text``, a whole file re-read for ``grep_loot`` (J.5): a ``BEGIN`` line
    through its ``END`` line, or 64 lines when ``END`` is missing, and for an ``END``
    line without a ``BEGIN`` (a file that holds only the tail of a key) the up to 63
    lines before it, never reaching into an earlier block (K.2 rule 1 for grep).

    The look-back can hide grep matches on the lines just above a stray ``END``
    marker; that is the price of never returning the body of a key whose head was
    cut off (grep matches are single lines, so a body line cannot be recognized on
    its own)."""
    numbers: set[int] = set()
    position = 0
    line = 1  # the line number at ``position``; spans are sorted and disjoint
    for start, stop in _key_spans(text):
        line += text.count("\n", position, start)
        first = line
        last_char = max(stop - 1, start)
        line += text.count("\n", start, last_char)
        numbers.update(range(first, line + 1))
        position = last_char
    return numbers


# --- rules 2-28: one pattern each, applied to unprotected text --------------------------

def _whole(kind: str) -> Builder:
    def build(match: re.Match[str]) -> list[Piece]:
        return [(token(kind), True)]
    return build


def _keep_group(group: str, kind: str, *, after: str | None = None) -> Builder:
    """Keep the text of ``group`` (and of ``after``, if any) around the token."""
    def build(match: re.Match[str]) -> list[Piece]:
        pieces: list[Piece] = [(match.group(group), False), (token(kind), True)]
        if after is not None and match.group(after):
            pieces.append((match.group(after), False))
        return pieces
    return build


def _r12_pair(match: re.Match[str]) -> list[Piece]:
    return [(match.group("lead") + match.group("user") + ":", False),
            (token("password"), True), (" - Valid credentials", False)]


def _r12_single(match: re.Match[str]) -> list[Piece]:
    return [(token("password"), True), (" - Valid credentials", False)]


def _r13(match: re.Match[str]) -> list[Piece]:
    quote = match.group("q") or ""
    return [(f"{match.group('lead')}: {quote}{match.group('user')}:", False),
            (token("password"), True)]


def _r14(match: re.Match[str]) -> list[Piece]:
    return [(match.group("lead") + match.group("pre") + ":", False), (token("password"), True),
            ("@", False)]


_SCHEME_WORDS = ("basic", "bearer", "digest", "ntlm", "negotiate")


def _r15(match: re.Match[str]) -> list[Piece]:
    """Header value redacted; a leading scheme word (Basic, Bearer, ...) stays visible."""
    value = match.group("value")
    core = value.lstrip()
    pieces: list[Piece] = [(match.group("name") + match.group("sep") + value[:len(value)
                                                                            - len(core)], False)]
    words = core.split(None, 1)
    if not words:
        pieces.append((core, False))
    elif words[0].lower() in _SCHEME_WORDS:
        rest = core[len(words[0]):]
        if rest.strip():
            pieces.append((words[0] + rest[:len(rest) - len(rest.lstrip())], False))
            pieces.append((token("authorization"), True))
        else:
            pieces.append((core, False))
    else:
        pieces.append((token("authorization"), True))
    if match.group("close"):
        pieces.append((match.group("close"), False))
    return pieces


def _r16(match: re.Match[str]) -> list[Piece]:
    """Cookie values: every pair of Cookie, the first pair of Set-Cookie."""
    pieces: list[Piece] = [(match.group("name") + match.group("sep"), False)]
    set_cookie = match.group("name").lower().startswith("set")
    parts = match.group("value").split(";")
    for index, part in enumerate(parts):
        if index:
            pieces.append((";", False))
        name, equals, value = part.partition("=")
        if equals and value.strip() and (index == 0 or not set_cookie):
            lead = value[:len(value) - len(value.lstrip())]
            trail = value[len(value.rstrip()):]
            pieces.append((name + equals + lead, False))
            pieces.append((token("cookie"), True))
            if trail:
                pieces.append((trail, False))
        else:
            pieces.append((part, False))
    return pieces


def _r27(match: re.Match[str]) -> list[Piece]:
    return [("sig=", False), (token("azure-sas"), True)]


def _sensitive_key(key: str) -> bool:
    return bool(_SENSITIVE_SEARCH.search(key)) or bool(_SENSITIVE_WHOLE.fullmatch(key))


# Rule 28 tests at most the last 128 characters of a key (a longer run such as
# "<prefix>_PASSWORD" is judged by its end), which also bounds the work per key.
_R28_KEY_MAX = 128
# The value of a sensitive key, read from the end of the key/separator head. A quoted
# value ends at its matching quote, or at the end of the line when the quote is never
# closed (the value is still redacted); an unquoted value ends at whitespace, ";", ","
# or "&", so connection strings and query strings keep their structure.
_R28_DQ = re.compile(r"(?P<body>(?:[^\"\\\n]|\\.)*)(?P<close>\")?")
_R28_SQ = re.compile(r"(?P<body>[^'\n]*)(?P<close>')?")
_R28_UQ = re.compile(r"(?P<body>[^\s;,&\"']+)")


def _r28(match: re.Match[str]) -> tuple[list[Piece], int] | None:
    """Rule 28 on a key/separator head: the value is read only when the key is
    sensitive. A head whose key is not sensitive consumes nothing after its separator,
    so a value that holds a sensitive pair (a URL with ``?api_key=``, a JSON string
    holding a query string) is still searched."""
    key = match.group("key")[-_R28_KEY_MAX:]
    if not _sensitive_key(key):
        return None
    text, start, stop = match.string, match.end(), match.endpos
    if match.group("open_dq"):
        value = _R28_DQ.match(text, start, stop)
    elif match.group("open_sq"):
        value = _R28_SQ.match(text, start, stop)
    else:
        value = _R28_UQ.match(text, start, stop)
    if value is None:
        return None
    minimum = 1 if _PASSWORD_KEY.fullmatch(key) else 3
    if len(value.group("body")) < minimum:
        return None
    pieces: list[Piece] = [(match.group(0), False), (token("secret"), True)]
    closing = value.groupdict().get("close")
    if closing:
        pieces.append((closing, False))
    return pieces, value.end()


_RULES: tuple[tuple[str, re.Pattern[str], RuleBuilder], ...] = (
    # 2-5: Kerberos and timeroast hashes, through the following non-space run.
    ("krb5tgs", re.compile(r"\$krb5tgs\$\S+"), _whole("krb5tgs")),
    ("krb5asrep", re.compile(r"\$krb5asrep\$\S+"), _whole("krb5asrep")),
    ("krb5pa", re.compile(r"\$krb5pa\$\S+"), _whole("krb5pa")),
    ("sntp-ms", re.compile(r"\$sntp-ms\$\S+"), _whole("sntp-ms")),
    # Linear time, for every rule below: loot lines reach 64 KiB and are attacker-written,
    # so no pattern may start a long failing scan at every position of a run. A pattern
    # that opens with a repeated class starts only where that class run starts (a
    # lookbehind); the leftmost match always starts there, so the result is unchanged.
    # 6: NetNTLMv2 and NetNTLMv1 responses.
    ("netntlm", re.compile(
        rf"(?<![^\s:])[^\s:]+::[^\s:]*:(?:[{_HEX}]{{16}}:[{_HEX}]{{32,48}}:[{_HEX}]+"
        rf"|[{_HEX}]{{48}}:[{_HEX}]{{48}}:[{_HEX}]{{16}}(?![{_HEX}]))"), _whole("netntlm")),
    # 7: LM:NT pairs (pwdump, secretsdump) with an optional trailing ":::".
    ("lm-ntlm", re.compile(rf"(?<![{_HEX}])[{_HEX}]{{32}}:[{_HEX}]{{32}}(?![{_HEX}])(?::::)?"),
     _whole("lm-ntlm")),
    # 8: crypt(3), Apache, domain cached credential and NT hash formats.
    ("crypt-hash", re.compile(r"\$(?:1|2[abxy]|5|6|y|gy|7|apr1|DCC2|NT)\$\S+"),
     _whole("crypt-hash")),
    # 9: potfile "hash:plaintext" at a token boundary; to the end of the line, or to the
    # closing quote when it starts after a quote.
    ("potfile", re.compile(
        rf"(?:(?:^|(?<=[\s>]))[{_HEX}]{{32,128}}:[^\n]+"
        rf"|(?<=\")[{_HEX}]{{32,128}}:[^\"\n]+"
        rf"|(?<=')[{_HEX}]{{32,128}}:[^'\n]+)", re.MULTILINE), _whole("potfile")),
    # 10: base64 kirbi tickets.
    ("kerberos-ticket", re.compile(r"doI[A-Za-z0-9+/]{100,}={0,2}"), _whole("kerberos-ticket")),
    # 11: DOMAIN\user:password. Inside quotes (Metasploit "Success: '...'") the password
    # runs to the closing quote, so a password with a space never leaks in part (R13).
    ("password", re.compile(r"(?P<q>')?(?<![A-Za-z0-9._-])(?P<id>[A-Za-z0-9._-]+\\"
                            r"[A-Za-z0-9._$-]+):"
                            r"(?P<secret>(?(q)[^'\n]+|\S+))"),
     lambda m: [((m.group("q") or "") + m.group("id") + ":", False),
                (token("password"), True)]),
    # 12: nmap brute-script results (R12), the user:pass form first. The match starts
    # where its non-space run starts (leading colons are kept as "lead"), so a long run
    # of "a:a:a..." is scanned once, not once per colon.
    ("password", re.compile(r"(?:(?<!\S)|(?<=Valid credentials))(?P<lead>:*)"
                            r"(?P<user>[^\s:]+):(?P<secret>\S+) - Valid credentials"),
     _r12_pair),
    ("password", re.compile(r"(?<!\S)(?P<secret>[^\s:]+) - Valid credentials"), _r12_single),
    # 13: Metasploit login results (R13); a quoted credential up to its closing quote.
    ("password", re.compile(
        r"(?P<lead>Login Successful|Success):[^\S\n]*(?P<q>')?(?P<user>[^:'\"\s]+):"
        r"(?P<secret>(?(q)[^'\n]+|[^'\"\s]+))"), _r13),
    # 14: credentials in a URL. The scheme run is entered once at its start (digits and
    # "+.-" before the first letter are kept as "lead"); the password stops at the next
    # "://", so a run of "a://b:a://b:..." without "@" is not rescanned from every scheme.
    ("password", re.compile(r"(?<![A-Za-z0-9+.-])(?P<lead>[0-9+.-]*)"
                            r"(?P<pre>[A-Za-z][A-Za-z0-9+.-]*://[^\s:/@]+):"
                            r"(?P<secret>(?:(?!://)[^\s@])+)@"),
     _r14),
    # 15: Authorization and Proxy-Authorization header values (the scheme word stays).
    ("authorization", re.compile(
        r"(?i)(?<![A-Za-z0-9_-])(?P<name>(?:Proxy-)?Authorization)"
        r"(?:(?P<sep>\"[^\S\n]*:[^\S\n]*\")(?P<value>[^\"\n]*)(?P<close>\")"
        r"|(?P<sep2>[^\S\n]*:[ \t]*)(?P<value2>[^\r\n]+))"),
     lambda m: _r15(_HeaderMatch(m))),
    # 16: Cookie and Set-Cookie values (names and attributes stay).
    ("cookie", re.compile(
        r"(?i)(?<![A-Za-z0-9_-])(?P<name>Set-Cookie|Cookie)(?P<sep>[^\S\n]*:[ \t]*)"
        r"(?P<value>[^\r\n]+)"), _r16),
    # 17: Slack incoming-webhook and workflow URLs (R17).
    ("slack-webhook", re.compile(r"https://hooks\.slack\.com/(?:services|workflows)/\S+"),
     _whole("slack-webhook")),
    # 18: three-part JSON web tokens.
    ("jwt", re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"),
     _whole("jwt")),
    # 19-27: provider key and token formats.
    ("aws-access-key-id", re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
     _whole("aws-access-key-id")),
    ("github-token", re.compile(r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,}"
                                r"|github_pat_[A-Za-z0-9_]{20,})"), _whole("github-token")),
    ("gitlab-token", re.compile(r"(?<![A-Za-z0-9_-])glpat-[0-9A-Za-z_-]{20,}"),
     _whole("gitlab-token")),
    ("slack-token", re.compile(r"(?<![A-Za-z0-9_-])(?:xox[aboprs]|xapp)-[0-9A-Za-z-]{10,}"),
     _whole("slack-token")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_-]{35}"), _whole("google-api-key")),
    ("google-oauth-token", re.compile(r"ya29\.[0-9A-Za-z_-]{20,}"),
     _whole("google-oauth-token")),
    ("stripe-key", re.compile(r"(?<![A-Za-z0-9_])(?:sk|rk)_live_[0-9A-Za-z]{10,}"),
     _whole("stripe-key")),
    ("api-key", re.compile(r"(?<![A-Za-z0-9_-])(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}"
                           r"|hf_[A-Za-z0-9]{30,}|npm_[A-Za-z0-9]{36}"
                           r"|dckr_pat_[A-Za-z0-9_-]{20,})"), _whole("api-key")),
    ("azure-sas", re.compile(r"(?<=[?&])sig=[A-Za-z0-9%+/=]{16,}"), _r27),
    # 28: values of sensitive keys (R28), quotes and separators kept. The pattern is
    # only the key and its separator (and an opening quote): the builder decides whether
    # the key is sensitive before any value is consumed (see _r28). The key is a whole
    # run of key characters (the lookbehind), so a run is entered once and a failing
    # run is given up after one backtrack over it. A host after "://" or "@" is not a
    # key ("https://token.app.test:8443/").
    ("secret", re.compile(
        r"(?<![A-Za-z0-9_.-])(?<!://)(?<!@)(?:export[^\S\n]+)?(?P<kq>[\"']?)"
        r"(?P<key>[A-Za-z0-9_.-]+)(?P=kq)[^\S\n]*[:=][^\S\n]*"
        r"(?:(?P<open_dq>\")|(?P<open_sq>'))?"), _r28),
)


# --- prefilters ---------------------------------------------------------------------------
# One necessary condition per rule, aligned with _RULES: text in which it is False
# cannot hold a match of that rule, so the rule is skipped (loot files reach 8 MiB and
# the patterns cost about a second per MiB). Literals are assembled from parts so this
# module never holds a secret-shaped string.

def _has(*literals: str) -> Callable[[str], bool]:
    return lambda text: any(literal in text for literal in literals)


def _has_re(pattern: str) -> Callable[[str], bool]:
    compiled = re.compile(pattern)
    return lambda text: compiled.search(text) is not None


_D = "$"
_HAS_HEX32 = _has_re(rf"[{_HEX}]{{32}}")
_VALID = " - Valid credentials"
_R28_WORDS = re.compile(r"(?i)key|secret|token|pass|pwd|webhook")
_PREFILTERS: tuple[Callable[[str], bool], ...] = (
    _has(_D + "krb5tgs" + _D),
    _has(_D + "krb5asrep" + _D),
    _has(_D + "krb5pa" + _D),
    _has(_D + "sntp-ms" + _D),
    _has("::"),                                  # 6 netntlm
    _HAS_HEX32,                                  # 7 lm-ntlm
    _has(_D),                                    # 8 crypt-hash
    _HAS_HEX32,                                  # 9 potfile
    _has("doI"),                                 # 10 kerberos-ticket
    _has("\\"),                                # 11 DOMAIN\user
    _has(_VALID),                                # 12 pair
    _has(_VALID),                                # 12 single
    _has("Success"),                             # 13 (also "Login Successful")
    _has("://"),                                 # 14
    _has_re(r"(?i)authorization"),               # 15
    _has_re(r"(?i)cookie"),                      # 16
    _has("hooks.slack" + ".com/"),               # 17
    _has("eyJ"),                                 # 18
    _has("AKIA", "ASIA"),                        # 19
    _has_re(r"gh[pousr]_|github_pat_"),          # 20
    _has("glpat-"),                              # 21
    _has("xox", "xapp-"),                        # 22
    _has("AIza"),                                # 23
    _has("ya29."),                               # 24
    _has("_live_"),                              # 25
    _has("sk-", "hf_", "npm_", "dckr_pat_"),     # 26
    _has("sig="),                                # 27
    lambda text: _R28_WORDS.search(text) is not None,  # 28 (a sensitive key needs one)
)
if len(_PREFILTERS) != len(_RULES):  # pragma: no cover - a rule was added without one
    raise AssertionError("every K.2 rule needs a prefilter")


class _HeaderMatch:
    """Adapts the two alternatives of rule 15 to one set of group names."""

    def __init__(self, match: re.Match[str]) -> None:
        self._match = match

    def group(self, name: str) -> str:
        match = self._match
        quoted = match.group("sep") is not None
        if name == "name":
            return match.group("name")
        if name == "sep":
            return match.group("sep") if quoted else match.group("sep2")
        if name == "value":
            return match.group("value") if quoted else match.group("value2")
        if name == "close":
            return (match.group("close") or "") if quoted else ""
        raise KeyError(name)


def _apply(segments: list[Segment], kind: str, pattern: re.Pattern[str], build: RuleBuilder,
           prefilter: Callable[[str], bool]) -> list[Segment]:
    """One rule over the plain-text segments.

    Each segment is searched inside the whole current text (``pos``/``endpos``), so
    lookbehinds and ``^`` see the real neighbours of the segment: text right after a
    token is not at a token boundary. A prefilter that fails on the whole text fails
    on every segment, so the rule is skipped at the cost of one scan.

    A builder that returns ``None`` leaves the match as text, and the search resumes
    at the end of the match. A builder may return ``(pieces, stop)`` to replace text
    up to ``stop``, beyond the end of its match (rule 28 matches only a key and its
    separator, and reads the value itself); the search resumes at ``stop``.
    """
    full = "".join(text for text, _ in segments)
    if not prefilter(full):
        return segments
    out: list[Segment] = []
    offset = 0
    for text, seg_kind in segments:
        start = offset
        offset += len(text)
        if seg_kind is not None or not text or not prefilter(text):
            out.append((text, seg_kind))
            continue
        cursor = start
        position = start
        while position < offset:
            match = pattern.search(full, position, offset)
            if match is None:
                break
            if match.start() == match.end():
                position = match.end() + 1
                continue
            found = build(match)
            if found is None:
                position = match.end()
                continue
            pieces, stop = found if isinstance(found, tuple) else (found, match.end())
            if match.start() > cursor:
                out.append((full[cursor:match.start()], None))
            out.extend((piece, kind if protected else None) for piece, protected in pieces)
            cursor = position = stop
        if cursor < offset:
            out.append((full[cursor:offset], None))
    return _coalesce(out)


def _coalesce(segments: list[Segment]) -> list[Segment]:
    """Adjacent plain-text segments become one, so a rule searches the text as it reads.

    Linear: each run of plain text is collected in a list and joined once (a builder
    that emits only plain text, such as rule 15 on a bare scheme word or rule 16 on a
    cookie without ``=``, leaves one plain piece per match, and a batch holds up to
    8 MiB of them)."""
    out: list[Segment] = []
    run: list[str] = []
    for text, kind in segments:
        if not text:
            continue
        if kind is None:
            run.append(text)
            continue
        if run:
            out.append((run[0] if len(run) == 1 else "".join(run), None))
            run = []
        out.append((text, kind))
    if run:
        out.append((run[0] if len(run) == 1 else "".join(run), None))
    return out


_EXISTING_TOKEN_RE = re.compile(r"\[REDACTED:[a-z0-9-]{1,32}\]")


def partition_outside_tokens(text: str, separator: str) -> tuple[str, str, str]:
    """``str.partition`` on the first ``separator`` that is not inside a
    ``[REDACTED:<type>]`` token, so redacted text is never split inside a token."""
    start = 0
    for match in _EXISTING_TOKEN_RE.finditer(text):
        index = text.find(separator, start, match.start())
        if index >= 0:
            break
        start = match.end()
    else:
        index = text.find(separator, start)
    if index < 0:
        return text, "", ""
    return text[:index], separator, text[index + len(separator):]


def _protect_existing(segments: list[Segment]) -> list[Segment]:
    """Tokens already present in the input are never redacted again (or counted)."""
    out: list[Segment] = []
    for text, kind in segments:
        if kind is not None or "[REDACTED:" not in text:
            out.append((text, kind))
            continue
        cursor = 0
        for match in _EXISTING_TOKEN_RE.finditer(text):
            if match.start() > cursor:
                out.append((text[cursor:match.start()], None))
            out.append((match.group(0), ""))
            cursor = match.end()
        if cursor < len(text):
            out.append((text[cursor:], None))
    return out


def _run_rules(segments: list[Segment]) -> list[Segment]:
    """Rules 2-28, in order."""
    for (kind, pattern, build), prefilter in zip(_RULES, _PREFILTERS, strict=True):
        segments = _apply(segments, kind, pattern, build, prefilter)
    return segments


def _counts(segments: Iterable[Segment]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for _text, kind in segments:
        if kind:
            counts[kind] = counts.get(kind, 0) + 1
    return counts


def redact(text: str, *, record_line: bool = False) -> tuple[str, dict[str, int]]:
    """Apply the K.2 rules in order to one string, line or window (rule 1 sees the whole
    text, so a key block across the lines of a log window is one token); returns the
    redacted text and the count per type.

    ``record_line``: the text is one line of a loot file read by a reader (J.6 per
    line), not a grep or log window, so an END marker without its BEGIN takes only the
    key-shaped run glued to it, never the rest of the record (see :func:`_key_spans`).
    """
    segments = _run_rules(_coalesce(_protect_existing(
        _private_keys(text, record_line=record_line))))
    return "".join(text for text, _ in segments), _counts(segments)


def _redact_block(lines: list[str]) -> list[tuple[str, dict[str, int]]]:
    """:func:`redact` (``record_line``) on each of ``lines``, in one pass of rules 2-28
    over the block.

    Rule 1 runs per line. No pattern of rules 2-28 can match a newline (their
    whitespace classes exclude it) and every lookaround treats a newline like the
    start or end of a string, so the matches inside each line are those of
    :func:`redact` on that line alone.
    """
    segments: list[Segment] = []
    for index, line in enumerate(lines):
        if index:
            segments.append(("\n", None))
        segments.extend(_protect_existing(_private_keys(line, record_line=True)))
    segments = _run_rules(_coalesce(segments))
    texts: list[list[str]] = [[] for _ in lines]
    counts: list[dict[str, int]] = [{} for _ in lines]
    row = 0
    for text, kind in segments:
        if kind is None:
            parts = text.split("\n")
            texts[row].append(parts[0])
            for part in parts[1:]:
                row += 1
                texts[row].append(part)
            continue
        texts[row].append(text)
        if kind:
            counts[row][kind] = counts[row].get(kind, 0) + 1
    return [("".join(parts), found) for parts, found in zip(texts, counts, strict=True)]


# Rules 1-8, 10 and 17-27: the types whose match is a secret by its shape alone. The
# repository meta-test (O.5 P0-11) runs them over every committed file.
TOKEN_SHAPED_TYPES: frozenset[str] = frozenset({
    "private-key", "krb5tgs", "krb5asrep", "krb5pa", "sntp-ms", "netntlm", "lm-ntlm",
    "crypt-hash", "kerberos-ticket", "slack-webhook", "jwt", "aws-access-key-id",
    "github-token", "gitlab-token", "slack-token", "google-api-key", "google-oauth-token",
    "stripe-key", "api-key", "azure-sas",
})


def token_shaped(text: str) -> list[tuple[str, str]]:
    """``(type, matched text)`` for every token-shaped secret in ``text``."""
    found = [("private-key", text[start:stop]) for start, stop in _key_spans(text)]
    for kind, pattern, _build in _RULES:
        if kind in TOKEN_SHAPED_TYPES:
            found += [(kind, match.group(0)) for match in pattern.finditer(text)]
    return found


_BATCH_LINES = 512


def _may_match(text: str) -> bool:
    """True when some rule could change a line of ``text`` (a newline-joined block).

    Every lookaround treats a newline like a string boundary and rule 9's ``^`` is
    compiled MULTILINE, so a match inside one line of the block is also a match in the
    block, and so is every prefilter condition. Rule 28's pattern matches any
    ``key: value``, so only its prefilter (the words a sensitive key must contain) is
    used. A block for which this is False holds no line that :func:`redact` would
    change.
    """
    if _BEGIN_RE.search(text) or _END_RE.search(text):
        return True
    # Tokens already in the text are never redacted again, but their words ("key",
    # "secret", "password") would satisfy rule 28's prefilter on every line holding one.
    # A newline in their place is at least as permissive for every lookaround and "^".
    text = _EXISTING_TOKEN_RE.sub("\n", text)
    for (kind, pattern, _build), prefilter in zip(_RULES, _PREFILTERS, strict=True):
        if prefilter(text) and (kind == "secret" or pattern.search(text)):
            return True
    return False


def redact_lines(lines: list[str]) -> list[tuple[str, dict[str, int]]]:
    """:func:`redact` with ``record_line`` on every line of a loot file, with the same
    result line by line.

    Loot files hold up to 8 MiB of attacker-written lines; running the 28 rules
    once per line costs tens of seconds per file when every line holds a secret.
    Lines are handled in blocks of at most 512 lines and (unless one line is longer)
    256 KiB: a block in which no rule can match is returned as is, any other block
    goes through the rules in one pass.
    """
    out: list[tuple[str, dict[str, int]]] = []
    for block in _blocks(lines):
        if _may_match("\n".join(block)):
            out.extend(_redact_block(block))
        else:
            out.extend((line, {}) for line in block)
    return out


_BATCH_CHARS = 256 * 1024


def _blocks(lines: list[str]) -> Iterable[list[str]]:
    """Consecutive runs of ``lines``, each at most 512 lines and, unless it is a single
    line, at most 256 KiB of text (a block's cost grows with its size, not its lines)."""
    block: list[str] = []
    size = 0
    for line in lines:
        if block and (len(block) >= _BATCH_LINES or size + len(line) > _BATCH_CHARS):
            yield block
            block, size = [], 0
        block.append(line)
        size += len(line) + 1
    if block:
        yield block
