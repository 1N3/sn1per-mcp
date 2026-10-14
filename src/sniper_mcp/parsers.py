# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Loot readers (contract J.3) and the ``grep_loot`` runner (J.5).

Every reader works on an open workspace descriptor through ``lootfs`` (no
symbolic link is ever followed, J.1), reads only the files J.3 names, and
returns structured records whose strings went through the J.6 pipeline line
by line: sanitize, cut to the 64 KiB line cap (J.4), redact (K), then cut to
the 2,000-character field cap. Complete private-key blocks that span lines
are collapsed first, so a key body line never comes back as a record of its
own, and nothing but PEM lines is ever joined to a block.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import threading
import urllib.parse
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from sniper_mcp import lootfs, paths, proc, redact, sanitize, targets
from sniper_mcp.lootfs import FIELD_CAP, LINE_CAP, ReadStats

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Options:
    """Switches of one reader call: redaction (K.1) and the J.2 exclusions."""

    redact: bool = True
    exclude: bool = True


@dataclass
class Source:
    """One entry of the H.1 ``sources`` list."""

    path: str
    kind: str
    bytes: int
    records: int = 0
    truncated: bool = False

    def to_json(self) -> dict[str, Any]:
        return {"path": self.path, "kind": self.kind, "bytes": self.bytes,
                "records": self.records, "truncated": self.truncated}


@dataclass
class Strings:
    """Bookkeeping for the untrusted strings of one record (J.6)."""

    counts: dict[str, int] = field(default_factory=dict)
    shortened: bool = False

    def add_counts(self, counts: dict[str, int]) -> None:
        for kind, amount in counts.items():
            self.counts[kind] = self.counts.get(kind, 0) + amount

    def cap(self, text: str | None, limit: int = FIELD_CAP) -> str | None:
        """J.6 step 8 on one field."""
        if text is None:
            return None
        cut, was_cut = sanitize.truncate(text, limit)
        self.shortened = self.shortened or was_cut
        return cut

    def cap_cut(self, text: str, limit: int) -> str:
        """J.6 step 8 on a field whose source was already cut (J.5): always marked."""
        self.shortened = True
        return sanitize.truncate_cut(text, limit)


@dataclass
class ReadResult:
    """What a reader returns: records plus everything the payload reports about them."""

    records: list[Any] = field(default_factory=list)
    sources: list[Source] = field(default_factory=list)
    invisible_removed: int = 0
    unparsed_lines: int = 0
    rejected_lines: int = 0


@dataclass(frozen=True)
class Line:
    """One line of a loot file after sanitizing and redaction."""

    text: str
    counts: dict[str, int]


def clean_text(raw: bytes | str, options: Options) -> tuple[str, dict[str, int], int]:
    """J.6 steps 1-7 on one string: (text, redaction counts, invisible characters)."""
    cleaned = sanitize.sanitize(raw)
    text = cleaned.text
    counts: dict[str, int] = {}
    if options.redact and text:
        text, counts = redact.redact(text)
    return text, counts, cleaned.invisible_removed


def file_lines(data: bytes, options: Options) -> tuple[list[Line], int]:
    """The J.6 pipeline on every line of one loot file.

    Sanitizing runs over the file in one pass, but no step crosses a newline, so it
    equals sanitizing each line. Complete private-key blocks that span lines are
    collapsed (:func:`redact.collapse_key_blocks`; only PEM lines are ever joined, so
    a marker in one record never hides another). Each line is then cut to the 64 KiB
    line cap (J.4) and redacted on its own (K.2 rule 1 included, within the line).
    Returns the lines and the number of invisible characters removed.
    """
    cleaned = sanitize.sanitize(data)
    raw_lines = cleaned.text.split("\n")
    if raw_lines and raw_lines[-1] == "":
        raw_lines.pop()
    key_tokens: dict[int, int] = {}
    if options.redact:
        raw_lines, key_tokens = redact.collapse_key_blocks(raw_lines)
    raw_lines = [raw[:LINE_CAP] for raw in raw_lines]
    redacted = (redact.redact_lines(raw_lines) if options.redact
                else [(raw, {}) for raw in raw_lines])
    lines: list[Line] = []
    for index, (raw, more) in enumerate(redacted):
        counts = dict(more)
        if index in key_tokens:
            counts["private-key"] = counts.get("private-key", 0) + key_tokens[index]
        lines.append(Line(text=raw, counts=counts))
    return lines, cleaned.invisible_removed


# File-name patterns use re.DOTALL so a name holding a newline is still a candidate and is
# counted in source_names_skipped instead of being ignored silently.

# --- choosing source files ------------------------------------------------------------------

def candidates(dir_fd: int, stats: ReadStats, options: Options,
               wanted: Callable[[str], bool]) -> list[str]:
    """Names in ``dir_fd`` that ``wanted`` accepts and that may be read.

    Symbolic links and special files (FIFOs, sockets, devices) are never opened;
    names outside ``[A-Za-z0-9._-]{1,128}`` are counted in
    ``source_names_skipped`` (H.1); with the exclusions on, J.2 file names are
    left out.
    """
    names: list[str] = []
    for entry in lootfs.list_dir(dir_fd, stats):
        if not wanted(entry.name):
            continue
        if entry.kind == "symlink":
            stats.symlinks_skipped += 1
            continue
        if entry.kind != "file":
            stats.special_skipped += 1
            continue
        if not lootfs.SOURCE_NAME_RE.fullmatch(entry.name):
            stats.source_names_skipped += 1
            continue
        if options.exclude and lootfs.is_excluded_file(entry.name):
            stats.excluded_files += 1
            continue
        names.append(entry.name)
    return names


def _subdir(ws_fd: int, name: str, stats: ReadStats) -> int | None:
    return lootfs.open_dir(ws_fd, name, stats)


def _read_source(dir_fd: int, subdir: str, name: str, kind: str,
                 stats: ReadStats) -> tuple[Source, bytes] | None:
    if not stats.can_read():
        return None
    data = lootfs.read_file(dir_fd, name, stats)
    if data is None:
        return None
    return Source(path=f"{subdir}/{name}", kind=kind, bytes=len(data.data),
                  truncated=data.truncated), data.data


def _has_content(data: bytes) -> bool:
    return bool(data.strip())


# --- findings (J.3.1) ---------------------------------------------------------------------------

_P_HEAD_RE = re.compile(r"\s*P([1-5])\s*-\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s*", re.IGNORECASE)
_PART_SPLIT_RE = re.compile(r",\s*")
_URL_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://\S+")
_HOST_PORT_RE = re.compile(r"(?P<host>[^\s:/\[\]]+):(?P<port>\d{1,5})")
_V6_PORT_RE = re.compile(r"\[(?P<host>[0-9A-Fa-f:.]+)\]:(?P<port>\d{1,5})")
_IPV4_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")

AGGREGATE = "sc0pe-all-vulnerabilities-sorted.txt"
AI_COMBINED = "ai-findings-combined.csv"


@dataclass
class Finding:
    severity: str
    priority: str
    title: str
    location: str
    host: str | None
    detail: str
    source: str
    strings: Strings

    def to_json(self) -> dict[str, Any]:
        return {"severity": self.severity, "priority": self.priority, "title": self.title,
                "location": self.location, "host": self.host, "detail": self.detail,
                "source": self.source}


def _normalize_location_host(host: str) -> str | None:
    value = targets.loot_host(host)
    if value is not None:
        return value
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    return str(address)


def _location_host(part: str) -> str | None | bool:
    """The host of a location part, None when it qualifies without a usable host, or
    False when the part is not a location."""
    if _URL_RE.fullmatch(part):
        try:
            hostname = urllib.parse.urlsplit(part).hostname
        except ValueError:
            return None
        return _normalize_location_host(hostname) if hostname else None
    match = _V6_PORT_RE.fullmatch(part)
    if match:
        return _normalize_location_host(match.group("host"))
    match = _HOST_PORT_RE.fullmatch(part)
    if match:
        return _normalize_location_host(match.group("host"))
    if _IPV4_RE.fullmatch(part):
        return _normalize_location_host(part)
    if "." in part and targets.loot_hostname(part) is not None:
        return targets.loot_hostname(part)
    return False


@dataclass(frozen=True)
class PLine:
    severity: str
    priority: str
    title: str
    location: str
    host: str | None
    detail: str


def parse_p_line(line: str) -> PLine | None:
    """The J.3.1 line grammar; None when part 0 is not ``P<n> - <SEVERITY>``."""
    parts = _PART_SPLIT_RE.split(line)
    head = _P_HEAD_RE.fullmatch(parts[0])
    if head is None:
        return None
    severity = head.group(2).lower()  # the severity word wins over the P number
    priority = f"P{SEVERITY_RANK[severity] + 1}"
    stripped = [part.strip() for part in parts]
    location_index = None
    host: str | None = None
    for index in range(2, len(stripped)):
        found = _location_host(stripped[index])
        if found is not False:
            location_index = index
            host = found if isinstance(found, str) else None
            break
    if location_index is None:
        location_index = 2
        host = None
        if len(stripped) > 2:
            found = _location_host(stripped[2])
            host = found if isinstance(found, str) else None
    title = ", ".join(stripped[1:location_index])
    location = stripped[location_index] if location_index < len(stripped) else ""
    detail = ", ".join(stripped[location_index + 1:])
    return PLine(severity=severity, priority=priority, title=title, location=location,
                 host=host, detail=detail)


def _finding_files(vuln_fd: int, stats: ReadStats, options: Options
                   ) -> list[tuple[str, str, str]]:
    """(name, kind, record source) in reading order, before any file is read."""
    names = candidates(vuln_fd, stats, options,
                       lambda n: n.startswith(("sc0pe-", "ai-findings-"))
                       and n.endswith((".txt", ".csv")))
    plan: list[tuple[str, str, str]] = []
    if AGGREGATE in names:
        plan.append((AGGREGATE, "sc0pe-aggregate", "sc0pe"))
    plan += [(n, "sc0pe-check", "sc0pe") for n in names
             if n.startswith("sc0pe-") and n.endswith(".txt") and n != AGGREGATE]
    if AI_COMBINED in names:
        plan.append((AI_COMBINED, "ai-findings", "ai-findings"))
    plan += [(n, "ai-findings-each", "ai-findings") for n in names
             if n.startswith("ai-findings-") and n.endswith(".csv") and n != AI_COMBINED]
    return plan


def read_findings(ws_fd: int, stats: ReadStats, options: Options,
                  host: str | None = None) -> ReadResult:
    """J.3.1: the sc0pe aggregate (else the per-check files) plus the AI findings."""
    result = ReadResult()
    vuln_fd = _subdir(ws_fd, "vulnerabilities", stats)
    if vuln_fd is None:
        return result
    seen: set[str] = set()
    try:
        plan = _finding_files(vuln_fd, stats, options)
        aggregate_used = False
        ai_combined_used = False
        for name, kind, source in plan:
            if kind == "sc0pe-check" and aggregate_used:
                continue
            if kind == "ai-findings-each":
                if ai_combined_used:
                    continue
                kind = "ai-findings"
            read = _read_source(vuln_fd, "vulnerabilities", name, kind, stats)
            if read is None:
                continue
            src, data = read
            if name == AGGREGATE:
                aggregate_used = _has_content(data)
            if name == AI_COMBINED:
                ai_combined_used = _has_content(data)
            lines, invisible = file_lines(data, options)
            result.invisible_removed += invisible
            for line in lines:
                if not line.text.strip():
                    continue
                parsed = parse_p_line(line.text)
                if parsed is None:
                    result.unparsed_lines += 1
                    continue
                key = " ".join(line.text.split())
                if key in seen:
                    continue
                seen.add(key)
                if host is not None and parsed.host != host:
                    continue
                strings = Strings()
                strings.add_counts(line.counts)
                result.records.append(Finding(
                    severity=parsed.severity, priority=parsed.priority,
                    title=strings.cap(parsed.title) or "",
                    location=strings.cap(parsed.location) or "",
                    host=strings.cap(parsed.host), detail=strings.cap(parsed.detail) or "",
                    source=source, strings=strings))
                src.records += 1
            result.sources.append(src)
    finally:
        os.close(vuln_fd)
    result.records.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.host or "", f.title))
    return result


# --- ports (J.3.2) ------------------------------------------------------------------------------

_P1_RE = re.compile(r"(\d{1,5})/(tcp|udp|sctp)\s+(open|open\|filtered)\s+(\S+)(?:\s+(.*))?")
_P2_RE = re.compile(r"(?P<host>[^:\s]+):(\d{1,5})/(tcp|udp|sctp)\s+(\S+)\s+(\S+)")
_BARE_SPLIT_RE = re.compile(r"[\s,]+")
# CE 9.2 fullportscan writes nmap/nmap-<host>-udp.txt next to nmap-<host>.txt: the same
# host, so the "-udp" suffix is not part of the token.
_PORT_FILES = (
    ("nmap-text", re.compile(r"nmap-(.+?)(?:-udp)?\.txt", re.DOTALL)),
    ("open-ports", re.compile(r"open-ports-(.+)\.txt", re.DOTALL)),
    ("ports-bare", re.compile(r"ports-(.+)\.txt", re.DOTALL)),
)
_PORT_STATES = ("open", "open|filtered")


@dataclass
class Port:
    host: str
    port: int
    protocol: str
    state: str
    service: str | None
    version: str | None
    strings: Strings

    def to_json(self) -> dict[str, Any]:
        return {"host": self.host, "port": self.port, "protocol": self.protocol,
                "state": self.state, "service": self.service, "version": self.version}


def _port_number(text: str) -> int | None:
    if not text.isdigit():
        return None
    value = int(text)
    return value if 1 <= value <= 65535 else None


def _token_files(dir_fd: int, stats: ReadStats, options: Options,
                 patterns: Iterable[tuple[str, re.Pattern[str]]],
                 host: str | None) -> list[tuple[str, str, str]]:
    """(name, kind, normalized host token) of files named ``<prefix><host><suffix>``.

    The token must be a hostname or IPv4 address; the host filter is exact
    equality with it (never a prefix glob).
    """
    patterns = list(patterns)

    def kind_of(name: str) -> tuple[str, str] | None:
        for kind, pattern in patterns:
            match = pattern.fullmatch(name)
            if match:
                return kind, match.group(1)
        return None

    found: list[tuple[str, str, str]] = []
    for name in candidates(dir_fd, stats, options, lambda n: kind_of(n) is not None):
        kind, token = kind_of(name)  # type: ignore[misc]
        normalized = targets.loot_host(token)
        if normalized is None:
            continue
        if host is not None and normalized != host:
            continue
        found.append((name, kind, normalized))
    return found


def read_ports(ws_fd: int, stats: ReadStats, options: Options,
               host: str | None = None) -> ReadResult:
    """J.3.2: nmap text output, 11.x ``open-ports`` lines, then CE bare port lists."""
    result = ReadResult()
    nmap_fd = _subdir(ws_fd, "nmap", stats)
    if nmap_fd is None:
        return result
    records: dict[tuple[str, int, str], Port] = {}
    try:
        files = _token_files(nmap_fd, stats, options, _PORT_FILES, host)
        order = {"nmap-text": 0, "open-ports": 1, "ports-bare": 2}
        files.sort(key=lambda item: (order[item[1]], item[0]))
        hosts_with_records: set[str] = set()
        for name, kind, token in files:
            if kind == "ports-bare" and token in hosts_with_records:
                continue
            read = _read_source(nmap_fd, "nmap", name, kind, stats)
            if read is None:
                continue
            src, data = read
            lines, invisible = file_lines(data, options)
            result.invisible_removed += invisible
            for line in lines:
                for record in _port_records(kind, token, line):
                    key = (record.host, record.port, record.protocol)
                    existing = records.get(key)
                    if existing is None:
                        records[key] = record
                        src.records += 1
                    elif kind == "nmap-text":
                        records[key] = record
                    if kind != "ports-bare":
                        hosts_with_records.add(token)
            result.sources.append(src)
    finally:
        os.close(nmap_fd)
    result.records = sorted(records.values(), key=lambda p: (p.host, p.port, p.protocol))
    return result


def _port_records(kind: str, token: str, line: Line) -> list[Port]:
    text = line.text.strip()
    if not text:
        return []
    if kind == "nmap-text":
        match = _P1_RE.fullmatch(text)
        if match is None:
            return []
        number = _port_number(match.group(1))
        if number is None:
            return []
        strings = Strings()
        strings.add_counts(line.counts)
        version = (match.group(5) or "").strip() or None
        return [Port(host=token, port=number, protocol=match.group(2), state=match.group(3),
                     service=strings.cap(match.group(4)), version=strings.cap(version),
                     strings=strings)]
    if kind == "open-ports":
        match = _P2_RE.match(text)
        if match is None:
            return []
        if targets.loot_host(match.group("host")) != token:
            return []
        number = _port_number(match.group(2))
        state = match.group(4)
        if number is None or state not in _PORT_STATES:
            return []
        strings = Strings()
        strings.add_counts(line.counts)
        return [Port(host=token, port=number, protocol=match.group(3), state=state,
                     service=strings.cap(match.group(5)), version=None, strings=strings)]
    ports = []
    for item in _BARE_SPLIT_RE.split(text):
        number = _port_number(item)
        if number is not None:
            ports.append(Port(host=token, port=number, protocol="tcp", state="open",
                              service=None, version=None, strings=Strings()))
    return ports


# --- subdomains (J.3.3) -------------------------------------------------------------------------

_DOMAINS_ALL = "domains-all-sorted.txt"
_DOMAINS_FULL_RE = re.compile(r"domains-.+-full\.txt", re.DOTALL)


def read_subdomains(ws_fd: int, stats: ReadStats, options: Options) -> ReadResult:
    """J.3.3: ``domains-all-sorted.txt``, else every ``domains-*-full.txt``."""
    result = ReadResult()
    domains_fd = _subdir(ws_fd, "domains", stats)
    if domains_fd is None:
        return result
    names: set[str] = set()
    try:
        files = candidates(domains_fd, stats, options,
                           lambda n: n == _DOMAINS_ALL or bool(_DOMAINS_FULL_RE.fullmatch(n)))
        plan = [(n, "domains-all") for n in files if n == _DOMAINS_ALL]
        plan += [(n, "domains-full") for n in files if n != _DOMAINS_ALL]
        primary_used = False
        for name, kind in plan:
            if kind == "domains-full" and primary_used:
                continue
            read = _read_source(domains_fd, "domains", name, kind, stats)
            if read is None:
                continue
            src, data = read
            if kind == "domains-all":
                primary_used = _has_content(data)
            cleaned = sanitize.sanitize(data)
            result.invisible_removed += cleaned.invisible_removed
            for raw in cleaned.text.split("\n"):
                value = raw.strip()
                if not value:
                    continue
                hostname = targets.loot_hostname(value[:LINE_CAP])
                if hostname is None:
                    result.rejected_lines += 1
                    continue
                src.records += 1
                names.add(hostname)
            result.sources.append(src)
    finally:
        os.close(domains_fd)
    result.records = sorted(names)
    return result


# --- technologies (J.3.4) -----------------------------------------------------------------------

TECH_SOURCES: tuple[str, ...] = ("httpx", "webtech", "whatweb", "nuclei")
_HTTPX_FILE_RE = re.compile(r"httpx-(?P<host>.+)\.json", re.DOTALL)
# web/<kind>-<host>-<scheme>-port<N>.txt (11.x, and CE webporthttp/webporthttps), or
# web/<kind>-<host>-<scheme>.txt without the port (CE stealth and discover): the port is
# then the scheme's default.
_WEB_TEXT_FILE_RE = re.compile(
    r"(?P<kind>webtech|whatweb)-(?P<host>.+)-(?P<scheme>https?)(?:-port(?P<port>\d{1,5}))?"
    r"\.txt", re.DOTALL)
_DEFAULT_PORTS = {"http": 80, "https": 443}
_NUCLEI_FILE_RE = re.compile(r"nuclei-technologies-(.+)\.txt", re.DOTALL)
# nmap/nuclei-technologies-allsubs-<target>.txt covers every subdomain of the target;
# its name token is not a host, so it is not read as the file of host "allsubs-...".
_NUCLEI_ALLSUBS_PREFIX = "allsubs-"
_WHATWEB_SUMMARY_RE = re.compile(r"\s*Summary\s*:\s*(.*)")
_WHATWEB_ITEM_RE = re.compile(r"([^\[\]]+?)\s*(?:\[([^\]]*)\].*)?")
# The brief one-line format of whatweb without -v (every CE mode):
# "<url> [<status>] <Plugin[version]>, <Plugin>, ...". One line per URL of a redirect chain.
_WHATWEB_BRIEF_RE = re.compile(r"(?P<url>[A-Za-z][A-Za-z0-9+.-]*://\S+) \[[^\]]*\]\s*(?P<items>.*)")
# Brief-line plugins that the verbose format prints in the report header, not in the
# Summary line: they describe the response, not a technology.
_WHATWEB_HEADER_PLUGINS = frozenset({"country", "ip", "title"})


@dataclass
class Technology:
    host: str
    port: int | None
    scheme: str | None
    technology: str
    version: str | None
    sources: list[str]
    strings: Strings

    def to_json(self) -> dict[str, Any]:
        return {"host": self.host, "port": self.port, "scheme": self.scheme,
                "technology": self.technology, "version": self.version,
                "sources": [s for s in TECH_SOURCES if s in self.sources]}


class _TechTable:
    def __init__(self) -> None:
        self.items: dict[tuple[str, int | None, str], Technology] = {}

    def add(self, *, host: str, port: int | None, scheme: str | None, technology: str,
            version: str | None, source: str, strings: Strings) -> bool:
        technology = technology.strip()
        if not technology:
            return False
        key = (host, port, technology.lower())
        existing = self.items.get(key)
        if existing is None:
            self.items[key] = Technology(
                host=host, port=port, scheme=scheme, technology=strings.cap(technology) or "",
                version=strings.cap(version), sources=[source], strings=strings)
            return True
        if source not in existing.sources:
            existing.sources.append(source)
        if existing.version is None and version:
            existing.version = existing.strings.cap(version)
            existing.strings.add_counts(strings.counts)
        if existing.scheme is None and scheme:
            existing.scheme = scheme
        return True


def _url_port_scheme(location: str) -> tuple[int | None, str | None]:
    if _URL_RE.fullmatch(location):
        try:
            parts = urllib.parse.urlsplit(location)
            scheme = parts.scheme.lower()
            port = parts.port
        except ValueError:
            return None, None
        if scheme not in ("http", "https"):
            return port, None
        return port or (443 if scheme == "https" else 80), scheme
    match = _HOST_PORT_RE.fullmatch(location)
    if match:
        return _port_number(match.group("port")), None
    return None, None


def _url_host(url: str) -> str | None:
    """The host of a URL, normalized like a file-name token, or None."""
    try:
        hostname = urllib.parse.urlsplit(url).hostname
    except ValueError:
        return None
    return targets.loot_host(hostname) if hostname else None


def _httpx_record_host(item: dict[str, Any]) -> str | None:
    """The host an httpx record describes: its ``input`` (a URL or ``host[:port]``),
    else its ``host`` field, normalized like a file-name token; None when unusable."""
    for field_name in ("input", "host"):
        value = item.get(field_name)
        if not isinstance(value, str) or not value.strip():
            continue
        value = value.strip()
        if _URL_RE.fullmatch(value):
            try:
                hostname = urllib.parse.urlsplit(value).hostname
            except ValueError:
                return None
            return targets.loot_host(hostname) if hostname else None
        authority = value.split("/", 1)[0]
        match = _HOST_PORT_RE.fullmatch(authority)
        return targets.loot_host(match.group("host") if match else authority)
    return None


def _httpx_records(data: bytes, token: str, options: Options, table: _TechTable,
                   src: Source, result: ReadResult) -> int:
    """httpx JSON lines of ``web/httpx-<token>.json``. httpx runs over crawled URLs, so
    a line can describe another host (a subdomain, a CDN): only lines whose ``input``
    (else ``host``) is the file's host are used; the others count as rejected lines."""
    invisible = 0
    for raw in data.split(b"\n"):
        if not raw.strip() or len(raw) > LINE_CAP:
            continue
        try:
            item = json.loads(raw.decode("utf-8", errors="replace"))
        except (ValueError, RecursionError):
            continue
        if not isinstance(item, dict):
            continue
        if _httpx_record_host(item) != token:
            result.rejected_lines += 1
            continue
        port_value = item.get("port")
        port = None
        if isinstance(port_value, int) and not isinstance(port_value, bool):
            port = port_value if 1 <= port_value <= 65535 else None
        elif isinstance(port_value, str):
            port = _port_number(port_value)
        scheme = item.get("scheme") if item.get("scheme") in ("http", "https") else None
        techs = item.get("tech")
        if not isinstance(techs, list):
            continue
        for tech in techs:
            if not isinstance(tech, str):
                continue
            text, counts, removed = clean_text(tech, options)
            invisible += removed
            # Split after redaction (rule 28 needs "key: value" whole), but never inside
            # a token: "password=[REDACTED:secret]" is a name, not name and version.
            name, _, version = redact.partition_outside_tokens(text, ":")
            strings = Strings()
            strings.add_counts(counts)
            if table.add(host=token, port=port, scheme=scheme, technology=name,
                         version=version.strip() or None, source="httpx", strings=strings):
                src.records += 1
    return invisible


def _split_whatweb(summary: str) -> list[str]:
    items: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in summary:
        if ch == "[":
            depth += 1
        elif ch == "]" and depth:
            depth -= 1
        if ch == "," and depth == 0:
            items.append("".join(current))
            current = []
        else:
            current.append(ch)
    items.append("".join(current))
    return [item.strip() for item in items if item.strip()]


def _whatweb_items(items: str, skip: frozenset[str] = frozenset()
                   ) -> list[tuple[str, str | None]]:
    out = []
    for item in _split_whatweb(items):
        parsed = _WHATWEB_ITEM_RE.fullmatch(item)
        if parsed is None or parsed.group(1).strip().lower() in skip:
            continue
        out.append((parsed.group(1), (parsed.group(2) or "").strip() or None))
    return out


def _line_techs(kind: str, line: Line) -> list[tuple[str, str | None, str | None]]:
    """(technology, version, location) found on one line of a webtech, whatweb or
    nuclei file. A whatweb line is either the ``Summary`` line of the verbose format
    (11.x, location None) or a line of the brief format (CE, location = its URL)."""
    text = line.text.strip()
    if not text:
        return []
    if kind == "webtech":
        tokens = text.split()
        if len(tokens) > 1 and tokens[-1][:1].isdigit():
            return [(" ".join(tokens[:-1]), tokens[-1], None)]
        return [(text, None, None)]
    if kind == "whatweb":
        match = _WHATWEB_SUMMARY_RE.fullmatch(text)
        if match is not None:
            return [(name, version, None) for name, version in _whatweb_items(match.group(1))]
        brief = _WHATWEB_BRIEF_RE.fullmatch(text)
        if brief is None:
            return []
        url = brief.group("url")
        return [(name, version, url) for name, version
                in _whatweb_items(brief.group("items"), _WHATWEB_HEADER_PLUGINS)]
    parsed_line = parse_p_line(text)
    if parsed_line is None:
        return []
    return [(parsed_line.title, None, parsed_line.location)]


def _web_files(web_fd: int, stats: ReadStats, options: Options, host: str | None
               ) -> list[tuple[str, str, str, int | None, str | None]]:
    """(name, kind, host token, port, scheme) of the ``web/`` technology files, in
    source order (httpx, webtech, whatweb); the host filter is exact token equality."""

    def wanted(name: str) -> bool:
        return bool(_HTTPX_FILE_RE.fullmatch(name) or _WEB_TEXT_FILE_RE.fullmatch(name))

    found: list[tuple[str, str, str, int | None, str | None]] = []
    for name in candidates(web_fd, stats, options, wanted):
        httpx = _HTTPX_FILE_RE.fullmatch(name)
        port: int | None = None
        scheme: str | None = None
        if httpx is not None:
            kind, raw_host = "httpx", httpx.group("host")
        else:
            text = _WEB_TEXT_FILE_RE.fullmatch(name)
            assert text is not None
            kind, raw_host = text.group("kind"), text.group("host")
            scheme = text.group("scheme")
            port = (_port_number(text.group("port")) if text.group("port") is not None
                    else _DEFAULT_PORTS[scheme])
        token = targets.loot_host(raw_host)
        if token is None or (host is not None and token != host):
            continue
        found.append((name, kind, token, port, scheme))
    order = {kind: index for index, kind in enumerate(TECH_SOURCES)}
    found.sort(key=lambda item: (order[item[1]], item[0]))
    return found


def read_technologies(ws_fd: int, stats: ReadStats, options: Options,
                      host: str | None = None) -> ReadResult:
    """J.3.4: httpx JSON lines, webtech, whatweb summaries and nuclei detections."""
    result = ReadResult()
    table = _TechTable()
    web_fd = _subdir(ws_fd, "web", stats)
    if web_fd is not None:
        try:
            for name, kind, token, port, scheme in _web_files(web_fd, stats, options, host):
                read = _read_source(web_fd, "web", name, kind, stats)
                if read is None:
                    continue
                src, data = read
                if kind == "httpx":
                    result.invisible_removed += _httpx_records(data, token, options, table,
                                                               src, result)
                else:
                    lines, invisible = file_lines(data, options)
                    result.invisible_removed += invisible
                    for line in lines:
                        found = _line_techs(kind, line)
                        location = found[0][2] if found else None
                        line_port, line_scheme = port, scheme
                        if location is not None:
                            # A brief whatweb line names its URL: a redirect chain also
                            # lists other URLs, of this host or of another one.
                            if _url_host(location) != token:
                                result.rejected_lines += 1
                                continue
                            url_port, url_scheme = _url_port_scheme(location)
                            if url_port is not None and url_scheme is not None:
                                line_port, line_scheme = url_port, url_scheme
                        for tech, version, _loc in found:
                            strings = Strings()
                            strings.add_counts(line.counts)
                            if table.add(host=token, port=line_port, scheme=line_scheme,
                                         technology=tech, version=version, source=kind,
                                         strings=strings):
                                src.records += 1
                result.sources.append(src)
        finally:
            os.close(web_fd)
    nmap_fd = _subdir(ws_fd, "nmap", stats)
    if nmap_fd is not None:
        try:
            for name in candidates(nmap_fd, stats, options,
                                   lambda n: bool(_NUCLEI_FILE_RE.fullmatch(n))):
                raw_token = _NUCLEI_FILE_RE.fullmatch(name).group(1)  # type: ignore[union-attr]
                if raw_token.startswith(_NUCLEI_ALLSUBS_PREFIX):
                    continue
                token = targets.loot_host(raw_token)
                if token is None or (host is not None and token != host):
                    continue
                read = _read_source(nmap_fd, "nmap", name, "nuclei", stats)
                if read is None:
                    continue
                src, data = read
                lines, invisible = file_lines(data, options)
                result.invisible_removed += invisible
                for line in lines:
                    for tech, version, location in _line_techs("nuclei", line):
                        port, scheme = _url_port_scheme(location or "")
                        strings = Strings()
                        strings.add_counts(line.counts)
                        if table.add(host=token, port=port, scheme=scheme, technology=tech,
                                     version=version, source="nuclei", strings=strings):
                            src.records += 1
                result.sources.append(src)
        finally:
            os.close(nmap_fd)
    result.records = sorted(table.items.values(),
                            key=lambda t: (t.host, t.port if t.port is not None else -1,
                                           t.technology.lower()))
    return result


# --- grep_loot (J.5) ----------------------------------------------------------------------------

GREP_TIMEOUT_SECONDS = 20.0
# J.5 output bounds. Each match record is kept up to GREP_RECORD_MAX_BYTES (the J.4 line cap
# for the text plus room for the name and line number) while grep's output streams in; the
# rest of an overlong line is read and dropped. GREP_KEPT_MAX_BYTES bounds what is kept
# (and so the memory used), GREP_RAW_MAX_BYTES everything read, the dropped rest of
# overlong lines included, so one huge single-line file (a 3 MB attack-tree.json, V2 D2,
# or the 18-19 MB smbmap progress lines of RC R1) no longer ends the search for the
# matches after it. Reading 512 MiB through the pipe takes about a second; the 20 s
# timeout still bounds the whole search.
GREP_RECORD_MAX_BYTES = LINE_CAP + 8 * 1024
GREP_KEPT_MAX_BYTES = 4 * 1024 * 1024
GREP_RAW_MAX_BYTES = 512 * 1024 * 1024
GREP_TEXT_CAP = 1000
# J.5: the last word of a cut line, dropped when the rest would be shown up to the cut.
_TRAILING_WORD_RE = re.compile(r"\S+\Z")
GREP_VERSION_TIMEOUT_SECONDS = 5.0
_grep_checked: dict[str, bool] = {}
_grep_lock = threading.Lock()


def grep_binary(home: str) -> str | None:
    """GNU grep: ``paths.GREP``, else ``grep`` on PATH, verified once with ``--version``."""
    candidate = paths.GREP if os.path.isfile(paths.GREP) else shutil.which("grep")
    if candidate is None:
        return None
    with _grep_lock:
        known = _grep_checked.get(candidate)
    if known is None:
        try:
            result = proc.run_capture([candidate, "--version"], home=home,
                                      timeout=GREP_VERSION_TIMEOUT_SECONDS)
            known = (not result.timed_out and result.returncode == 0
                     and b"GNU grep" in result.output)
        except proc.LaunchError:
            known = False
        with _grep_lock:
            _grep_checked[candidate] = known
    return candidate if known else None


def has_back_reference(pattern: str) -> bool:
    """``\\1``-``\\9`` in an extended regular expression (an escaped backslash is not)."""
    index = 0
    while index < len(pattern):
        if pattern[index] == "\\" and index + 1 < len(pattern):
            if pattern[index + 1] in "123456789":
                return True
            index += 2
            continue
        index += 1
    return False


def grep_argv(grep: str, pattern: str, *, regex: bool, ignore_case: bool, max_matches: int,
              exclude: bool) -> list[str]:
    """The J.5 argv."""
    argv = [grep, "-r", "-n", "-H", "-Z", "-I", "--devices=skip", "--no-messages",
            "--color=never", "-m", str(max_matches), "-E" if regex else "-F"]
    if ignore_case:
        argv.append("-i")
    if exclude:
        argv += lootfs.grep_exclusion_args()
    argv += ["-e", pattern, "--", "."]
    return argv


@dataclass(frozen=True)
class RawMatch:
    name: bytes
    line: int
    text: bytes
    cut: bool = False  # the line was longer than the record cap and was cut while streaming


def parse_grep_output(data: bytes, limit: int, cut: Iterable[int] = ()) -> list[RawMatch]:
    """Records ``./<path>`` NUL ``<line>:<text>`` newline; an incomplete or malformed
    record ends the parse (the name is read up to the NUL, so a name holding ``:``
    or a newline cannot fake the framing). ``cut`` holds the positions of the records
    that were cut while streaming (:attr:`proc.StreamResult.cut_records`)."""
    cut_positions = frozenset(cut)
    records: list[RawMatch] = []
    position = 0
    while position < len(data) and len(records) < limit:
        nul = data.find(b"\0", position)
        if nul < 0:
            break
        colon = data.find(b":", nul + 1)
        newline = data.find(b"\n", nul + 1)
        if colon < 0 or newline < 0 or colon > newline:
            break
        number = data[nul + 1:colon]
        if not number.isdigit():
            break
        name = data[position:nul]
        if name.startswith(b"./"):
            name = name[2:]
        records.append(RawMatch(name=name, line=int(number), text=data[colon + 1:newline],
                                cut=len(records) in cut_positions))
        position = newline + 1
    return records


def cut_line_text(raw: bytes, options: Options) -> tuple[str, dict[str, int], int]:
    """J.6 steps 1-7 on the text of a line that was cut while it streamed in (J.5).

    The end of such a line was only partly read: a token cut there is no longer
    recognized by redaction, and the J.6 carriage-return rule would pick an unfinished
    update after the cut. So the part after the last carriage return is dropped first
    (the last complete progress update is the one shown), and a line without one loses
    its last word when the cleaned text is short enough to be shown up to the cut. The
    shown text always ends with ``[truncated]`` (:meth:`Strings.cap_cut`).
    """
    carriage_return = raw.rfind(b"\r")
    if carriage_return >= 0:
        return clean_text(raw[:carriage_return], options)
    text, counts, removed = clean_text(raw, options)
    if len(text) <= GREP_TEXT_CAP:
        text = _TRAILING_WORD_RE.sub("", text)
    return text, counts, removed


@dataclass
class GrepMatch:
    path: str
    line: int
    text: str
    strings: Strings

    def to_json(self) -> dict[str, Any]:
        return {"path": self.path, "line": self.line, "text": self.text}


@dataclass
class GrepResult:
    matches: list[GrepMatch]
    stopped_reason: str  # complete, max_matches, max_bytes, timeout
    grep_status_2: bool
    unchecked_dropped: int  # matches dropped: their file could not be checked for key blocks
    invisible_removed: int


_STOPPED = {"complete": "complete", "max_lines": "max_matches", "max_bytes": "max_bytes",
            "timeout": "timeout"}


@dataclass(frozen=True)
class KeyLines:
    """What the J.5 re-read of one matched file found."""

    numbers: set[int]  # lines inside private-key blocks
    checked_through: int | None  # last line checked when the read was cut, else None

    def covers(self, line: int) -> bool:
        return self.checked_through is None or line <= self.checked_through


def _key_lines(dir_fd: int, name: bytes, stats: ReadStats) -> KeyLines | None:
    """Private-key block lines of the matched file, reopened safely relative to the
    searched directory; None when it cannot be reopened or the J.4 per-call caps
    (64 MiB, 5,000 files) are used up. Only the first 8 MiB are read: when the file is
    longer, lines past the last complete line read are not covered."""
    components = os.fsdecode(name).split("/")
    if not components or not all(lootfs.component_ok(c) for c in components):
        return None
    if not stats.can_read():
        return None
    parent = lootfs.open_relative(dir_fd, components[:-1], stats)
    if parent is None:
        return None
    try:
        data = lootfs.read_file(parent, components[-1], stats, allow_hardlinks=True)
    finally:
        os.close(parent)
    if data is None:
        return None
    text = data.data.decode("utf-8", errors="replace")
    return KeyLines(numbers=redact.private_key_line_numbers(text),
                    checked_through=text.count("\n") if data.truncated else None)


def regex_is_valid(grep: str, pattern: str, *, home: str) -> bool:
    """grep -E exits 2 for an invalid expression; check it on empty input first, so the
    search can report ``invalid_pattern`` instead of an empty result (J.5)."""
    try:
        result = proc.run_capture([grep, "-E", "-e", pattern], home=home,
                                  timeout=GREP_VERSION_TIMEOUT_SECONDS, input_bytes=b"")
    except proc.LaunchError:
        return True  # the search itself reports the failure
    return result.timed_out or result.returncode != 2


def run_grep(dir_fd: int, grep: str, pattern: str, *, regex: bool, ignore_case: bool,
             max_matches: int, options: Options, home: str) -> GrepResult:
    """Search the directory open at ``dir_fd`` (J.5) and build the match records."""
    argv = grep_argv(grep, pattern, regex=regex, ignore_case=ignore_case,
                     max_matches=max_matches, exclude=options.exclude)
    cwd = os.path.join(paths.PROC_ROOT, "self", "fd", str(dir_fd))
    streamed = proc.run_streaming(argv, home=home, cwd=cwd, pass_fds=(dir_fd,),
                                  max_lines=max_matches, max_bytes=GREP_KEPT_MAX_BYTES,
                                  timeout=GREP_TIMEOUT_SECONDS, nul_framed=True,
                                  max_record_bytes=GREP_RECORD_MAX_BYTES,
                                  max_raw_bytes=GREP_RAW_MAX_BYTES)
    raw = parse_grep_output(streamed.output, max_matches, streamed.cut_records)
    key_lines: dict[bytes, KeyLines | None] = {}
    if options.redact:
        # One budget for every re-read of this call: the J.4 per-call caps.
        stats = ReadStats()
        for match in raw:
            if match.name not in key_lines:
                key_lines[match.name] = _key_lines(dir_fd, match.name, stats)
    matches: list[GrepMatch] = []
    dropped = 0
    invisible = 0
    for match in raw:
        strings = Strings()
        clean = cut_line_text if match.cut else clean_text
        from_line = True  # the text comes from the matched line, not a redaction token
        if options.redact:
            found = key_lines.get(match.name)
            if found is None or not found.covers(match.line):
                dropped += 1  # J.5: a match that cannot be checked is never returned
                continue
            if match.line in found.numbers:
                text = redact.token("private-key")
                strings.add_counts({"private-key": 1})
                from_line = False
            else:
                text, counts, removed = clean(match.text, options)
                strings.add_counts(counts)
                invisible += removed
        else:
            text, _, removed = clean(match.text, options)
            invisible += removed
        path, path_counts, removed = clean_text(match.name, options)
        invisible += removed
        strings.add_counts(path_counts)
        shown = (strings.cap_cut(text, GREP_TEXT_CAP) if match.cut and from_line
                 else strings.cap(text, GREP_TEXT_CAP) or "")
        matches.append(GrepMatch(path=strings.cap(path, GREP_TEXT_CAP) or "",
                                 line=match.line, text=shown, strings=strings))
    return GrepResult(matches=matches,
                      stopped_reason=_STOPPED.get(streamed.stopped_reason, "complete"),
                      grep_status_2=streamed.returncode == 2,
                      unchecked_dropped=dropped, invisible_removed=invisible)
