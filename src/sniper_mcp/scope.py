# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Scope guard: parsing, matching, the always-deny set and the DNS policy (contract F).

The scope is the union of ``SNIPER_MCP_SCOPE`` and the scope file, re-read on
every ``sniper_scan`` and ``sniper_status`` call (F.1, A-35). Parsing fails
closed: one invalid entry makes the whole scope invalid. Entries are
normalized exactly like targets (E.1 steps 3a and 8, canonical IP forms), so
matching compares the strings the engine will receive.

Every address table is a constant below, copied from the IANA registries
(A-43); nothing depends on ``ipaddress.is_global`` or ``is_private``, whose
tables differ between the Python patch releases this package supports.

``resolver`` and ``is_public`` are module attributes looked up at call time:
the test isolation fixture replaces them (O.2). Code under test never reaches
the system resolver.
"""

from __future__ import annotations

import collections
import functools
import hashlib
import ipaddress
import json
import re
import socket
import stat
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from sniper_mcp import state, targets
from sniper_mcp.settings import Settings

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

MAX_ENTRIES = 10_000
MAX_SOURCE_BYTES = 1024 * 1024
IPV4_PREFIX_FLOOR = 8
IPV6_PREFIX_FLOOR = 32
DIGEST_CHARS = 16
MAX_INVALID_LISTED = 20
MAX_ENTRY_CHARS = 256
RESOLVED_MAX = 64

# F.5: one lookup at a time per worker, two workers per process, 5 seconds each.
DNS_TIMEOUT_SECONDS = 5.0
DNS_WORKERS = 2

SOURCE_ENV = "env"
SOURCE_FILE = "file"
POLICY_STRICT = "strict"
POLICY_LENIENT = "lenient"

DOMAIN = "domain"
WILDCARD = "wildcard"
NETWORK = "network"

_NEVER_RETRY = ("Do not retry with other spellings, encodings, IP forms or wider ranges; "
                "ask the operator.")
# F.1 tokenizing: commas, spaces, tabs and newlines (CR too, for files with CRLF ends).
_SPLIT_RE = re.compile(r"[, \t\r\n]+")


def _v4(*blocks: str) -> tuple[ipaddress.IPv4Network, ...]:
    return tuple(ipaddress.IPv4Network(block) for block in blocks)


def _v6(*blocks: str) -> tuple[ipaddress.IPv6Network, ...]:
    return tuple(ipaddress.IPv6Network(block) for block in blocks)


# --- F.4.1 always-deny set ------------------------------------------------------------
# Applies to literal targets, CIDR targets (overlap) and resolved addresses, in every
# DNS policy and under the lab override. 169.254.0.0/16 includes the cloud metadata
# (169.254.169.254) and container credential (169.254.170.2) endpoints;
# 100.100.100.200 is the Alibaba Cloud metadata address and 168.63.129.16 the Azure
# platform endpoint; 240.0.0.0/4 includes 255.255.255.255; fd00:ec2::/32 is the AWS
# instance metadata, DNS and NTP range over IPv6.
ALWAYS_DENY_V4 = _v4("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "100.100.100.200/32",
                     "168.63.129.16/32", "224.0.0.0/4", "240.0.0.0/4")
ALWAYS_DENY_V6 = _v6("::/96", "fe80::/10", "fec0::/10", "ff00::/8", "fd00:ec2::/32")

# --- F.4.3 non-public table (R3) --------------------------------------------------------
# Copied from the IANA IPv4 and IPv6 Special-Purpose Address Registries as last updated
# 2025-10-09 (re-checked on 2026-10-11): every block whose "Globally Reachable" value is
# False, plus the always-deny set. Blocks marked True inside a False block stay public.
# 64:ff9b::/96 (globally reachable) and 2002::/16 (no registry value) are absent: an
# address there is judged through its embedded IPv4 address (F.5).
REGISTRY_DATE = "2025-10-09"
NON_PUBLIC_V4 = _v4(
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
    "255.255.255.255/32",
    # always-deny additions
    "224.0.0.0/4", "100.100.100.200/32", "168.63.129.16/32",
)
PUBLIC_EXCEPTIONS_V4 = _v4("192.0.0.9/32", "192.0.0.10/32")
NON_PUBLIC_V6 = _v6(
    "::/96", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64", "100:0:0:1::/64", "2001::/23",
    "2001:db8::/32", "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10",
    # always-deny additions
    "fec0::/10", "ff00::/8", "fd00:ec2::/32",
)
PUBLIC_EXCEPTIONS_V6 = _v6("2001:1::1/128", "2001:1::2/128", "2001:1::3/128", "2001:3::/32",
                           "2001:4:112::/48", "2001:20::/28", "2001:30::/28")

# --- F.4.2 IPv6 prefixes that carry an IPv4 address ------------------------------------
_MAPPED = ipaddress.IPv6Network("::ffff:0:0/96")
_COMPATIBLE = ipaddress.IPv6Network("::/96")
_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.IPv6Network("64:ff9b:1::/48")
_SIXTOFOUR = ipaddress.IPv6Network("2002::/16")
_TEREDO = ipaddress.IPv6Network("2001::/32")
_LOW32 = 0xFFFFFFFF


def embedded_ipv4(address: ipaddress.IPv6Address) -> tuple[ipaddress.IPv4Address, ...]:
    """F.4.2: the IPv4 addresses carried inside an IPv6 address (zero, one or two)."""
    value = int(address)
    if address in _MAPPED:
        return (ipaddress.IPv4Address(value & _LOW32),)
    if address in _COMPATIBLE:
        if value in (0, 1):  # "::" and "::1" carry no IPv4 address
            return ()
        return (ipaddress.IPv4Address(value & _LOW32),)
    if address in _NAT64 or address in _NAT64_LOCAL:
        return (ipaddress.IPv4Address(value & _LOW32),)
    if address in _SIXTOFOUR:  # bits 16-47
        return (ipaddress.IPv4Address((value >> 80) & _LOW32),)
    if address in _TEREDO:  # server: bits 32-63; client: the inverse of the low 32 bits
        return (ipaddress.IPv4Address((value >> 64) & _LOW32),
                ipaddress.IPv4Address(~value & _LOW32))
    return ()


def is_public(address: IPAddress | str) -> bool:
    """F.4.3: False for an address inside the non-public table, True otherwise.

    Tests replace this function only to model public answers with RFC 5737
    values (O.2).
    """
    if isinstance(address, str):
        address = ipaddress.ip_address(address)
    if address.version == 4:
        table, exceptions = NON_PUBLIC_V4, PUBLIC_EXCEPTIONS_V4
    else:
        table, exceptions = NON_PUBLIC_V6, PUBLIC_EXCEPTIONS_V6
    if any(address in block for block in exceptions):
        return True
    return not any(address in block for block in table)


def in_always_deny_v4(address: ipaddress.IPv4Address) -> bool:
    return any(address in block for block in ALWAYS_DENY_V4)


def in_always_deny(address: IPAddress) -> bool:
    """F.4.1 for one address: the IPv4 row, the IPv6 row, or an embedded IPv4 in the IPv4 row."""
    if address.version == 4:
        return in_always_deny_v4(address)
    return (any(address in block for block in ALWAYS_DENY_V6)
            or any(in_always_deny_v4(e) for e in embedded_ipv4(address)))


def covered(block: IPNetwork, covers: Iterable[IPNetwork]) -> bool:
    """True when every address of ``block`` lies in the union of ``covers``."""
    remaining = [block]
    for cover in covers:
        if cover.version != block.version:
            continue
        pending: list[IPNetwork] = []
        for part in remaining:
            if part.subnet_of(cover):  # type: ignore[arg-type]
                continue
            if cover.subnet_of(part):  # type: ignore[arg-type]
                pending.extend(part.address_exclude(cover))  # type: ignore[arg-type]
            else:
                pending.append(part)
        remaining = pending
        if not remaining:
            return True
    return not remaining


def inside_always_deny(network: IPNetwork) -> bool:
    """An entry lies entirely inside the always-deny set (explicit listing, F.4.1)."""
    return covered(network, ALWAYS_DENY_V4 if network.version == 4 else ALWAYS_DENY_V6)


# --- entries (F.1) ---------------------------------------------------------------------

class EntryError(ValueError):
    """One scope entry is invalid; ``reason`` is the code shown in ``invalid_entries``."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Entry:
    """One normalized scope entry (positive or exclusion)."""

    text: str  # normalized text, as listed by sniper_status (exclusions without "!")
    kind: str  # DOMAIN, WILDCARD or NETWORK
    domain: str | None = None
    network: IPNetwork | None = None

    def matches_host(self, host: str) -> bool:
        """F.2 label-boundary matching on a normalized hostname."""
        domain = self.domain
        if domain is None:
            return False
        if self.kind == WILDCARD:  # subdomains only, never the apex
            return host.endswith("." + domain)
        # A single-label entry matches only that exact name (A-50).
        return host == domain or ("." in domain and host.endswith("." + domain))


def _entry_hostname(mapped: str, *, exclusion: bool) -> str:
    try:
        return targets.validate_hostname(mapped, deny_names=not exclusion)
    except targets.TargetError as exc:
        if exc.code == "always_denied":
            raise EntryError("always_denied_name") from exc
        raise EntryError(exc.code) from exc


def _network_entry(network: IPNetwork) -> Entry:
    if network.version == 6 and network.prefixlen >= 96 and network.subnet_of(_MAPPED):
        # IPv4-mapped entries become the equivalent IPv4 entry (F.1).
        network = ipaddress.IPv4Network(
            (int(network.network_address) & _LOW32, network.prefixlen - 96))
    floor = IPV4_PREFIX_FLOOR if network.version == 4 else IPV6_PREFIX_FLOOR
    if network.prefixlen < floor:
        raise EntryError("cidr_prefix_too_short")
    if network.prefixlen == network.max_prefixlen:
        text = str(network.network_address)
    else:
        text = str(network)
    return Entry(text=text, kind=NETWORK, network=network)


def parse_entry(body: str, *, exclusion: bool) -> Entry:
    """Normalize one entry (without its ``!``); raises ``EntryError``."""
    wildcard = body.startswith("*.")
    text = body[2:] if wildcard else body
    if not text:
        raise EntryError("invalid_target")
    try:
        mapped = targets.map_entry_text(text)
    except targets.TargetError as exc:
        raise EntryError(exc.code) from exc
    if wildcard:
        name = _entry_hostname(mapped, exclusion=exclusion)
        if "." not in name:  # *.<single label> would cover a whole top-level domain
            raise EntryError("invalid_wildcard")
        return Entry(text=f"*.{name}", kind=WILDCARD, domain=name)
    if "%" in mapped:  # IPv6 zone identifiers are never valid
        raise EntryError("invalid_target")
    if "/" in mapped:
        try:
            ipaddress.ip_network(mapped, strict=False)
        except ValueError as exc:
            raise EntryError("invalid_target") from exc
        try:
            network = ipaddress.ip_network(mapped, strict=True)
        except ValueError as exc:
            raise EntryError("cidr_not_canonical") from exc
        return _network_entry(network)
    try:
        address = ipaddress.ip_address(mapped)
    except ValueError:
        address = None
    if address is not None:
        return _network_entry(ipaddress.ip_network(address))
    if ":" in mapped:  # host:port is not an entry
        raise EntryError("invalid_target")
    if targets.is_alternate_ipv4(mapped):
        raise EntryError("non_canonical_ip")
    name = _entry_hostname(mapped, exclusion=exclusion)
    return Entry(text=name, kind=DOMAIN, domain=name)


def tokenize(text: str, *, comments: bool) -> list[str]:
    """F.1: entries separated by commas, spaces, tabs or newlines; ``#`` comments in files."""
    if comments:
        text = "\n".join(line.split("#", 1)[0] for line in text.split("\n"))
    return [token for token in _SPLIT_RE.split(text) if token]


# --- the snapshot of one read ------------------------------------------------------------

def _mode_text(st: Any) -> str | None:
    return None if st is None else f"{stat.S_IMODE(st.st_mode):04o}"


@dataclass(frozen=True)
class ScopeSnapshot:
    """The scope as read by one ``sniper_scan`` or ``sniper_status`` call."""

    configured: bool
    sources: tuple[str, ...]
    entries: tuple[Entry, ...]
    exclusions: tuple[Entry, ...]
    invalid: tuple[dict[str, str], ...]
    digest: str | None
    file: dict[str, Any] | None
    file_writable_by_server_user: bool

    @property
    def valid(self) -> bool:
        return not self.invalid

    @property
    def source(self) -> str:
        """``scope_source`` vocabulary of the audit log: env, file, env+file, none."""
        return "+".join(self.sources) or "none"

    @property
    def entry_count(self) -> int:
        return len(self.entries) + len(self.exclusions)

    @functools.cached_property
    def domain_entries(self) -> tuple[Entry, ...]:
        return tuple(e for e in self.entries if e.kind != NETWORK)

    @functools.cached_property
    def domain_exclusions(self) -> tuple[Entry, ...]:
        return tuple(e for e in self.exclusions if e.kind != NETWORK)

    @functools.cached_property
    def networks(self) -> tuple[IPNetwork, ...]:
        """Positive IP and CIDR entries."""
        return tuple(e.network for e in self.entries if e.network is not None)

    @functools.cached_property
    def excluded_networks(self) -> tuple[IPNetwork, ...]:
        return tuple(e.network for e in self.exclusions if e.network is not None)

    @functools.cached_property
    def explicit_networks(self) -> tuple[IPNetwork, ...]:
        """Positive entries that lie entirely inside the always-deny set (F.4.1)."""
        return tuple(n for n in self.networks if inside_always_deny(n))

    @property
    def has_ip_entries(self) -> bool:
        return bool(self.networks)

    def warning_codes(self) -> list[str]:
        """F.1 parse-time warnings (``sniper_status``)."""
        codes = []
        if self.file_writable_by_server_user:
            codes.append("scope_file_writable_by_server_user")
        if self.domain_exclusions and self.networks:
            codes.append("domain_exclusions_not_applied_to_ip_targets")
        return codes

    # --- address predicates (F.4, F.5) ----------------------------------------------
    def in_scope_address(self, address: IPAddress) -> bool:
        """Inside a positive IP/CIDR entry. Callers never pass an IPv6 address that
        embeds IPv4: such addresses are judged through their IPv4 form (F.1)."""
        return any(address in network for network in self.networks
                   if network.version == address.version)

    def excluded_address(self, address: IPAddress) -> bool:
        return any(address in network for network in self.excluded_networks
                   if network.version == address.version)

    def explicitly_listed(self, address: IPAddress) -> bool:
        """F.4.1 explicit listing of one always-denied address."""
        return any(address in network for network in self.explicit_networks
                   if network.version == address.version)


def _file_info(path: str, st: Any, euid: int) -> dict[str, Any]:
    writable = st is not None and (st.st_uid == euid or euid == 0)
    return {"path": path, "owner_uid": None if st is None else st.st_uid,
            "mode": _mode_text(st), "writable_by_server_user": writable}


def _digest(entries: Sequence[Entry], exclusions: Sequence[Entry],
            invalid: Sequence[dict[str, str]]) -> str | None:
    """F.1 ``scope_digest``: SHA-256 over the sorted normalized entries, 16 hex characters.

    Invalid entries take part with a ``?`` prefix, so a scope that turns invalid
    never keeps the digest of the valid scope it came from.
    """
    lines = ({e.text for e in entries} | {"!" + e.text for e in exclusions}
             | {"?" + item["_raw"] for item in invalid})
    if not lines:
        return None
    joined = "\n".join(sorted(lines)).encode("utf-8", "surrogatepass")
    return hashlib.sha256(joined).hexdigest()[:DIGEST_CHARS]


def _display(entry: str) -> str:
    """An invalid entry as shown to the operator and the model: ASCII with JSON escapes,
    so control, bidi or undecodable characters can neither hide nor break the payload."""
    return json.dumps(entry[:MAX_ENTRY_CHARS], ensure_ascii=True)[1:-1]


def _invalid(entry: str, reason: str) -> dict[str, str]:
    return {"entry": _display(entry), "reason": reason, "_raw": entry}


def load(settings: Settings) -> ScopeSnapshot:
    """Read and parse both scope sources (F.1). Never raises for bad content."""
    invalid: list[dict[str, str]] = []
    sources: list[str] = []
    env_tokens: list[str] = []
    env_text = settings.scope
    if len(env_text.encode("utf-8", "surrogatepass")) > MAX_SOURCE_BYTES:
        sources.append(SOURCE_ENV)
        invalid.append(_invalid("SNIPER_MCP_SCOPE", "source_too_large"))
    else:
        env_tokens = tokenize(env_text, comments=False)
        if env_tokens:
            sources.append(SOURCE_ENV)

    file_info: dict[str, Any] | None = None
    file_tokens: list[str] = []
    if settings.scope_file is not None:
        path = settings.scope_file
        sources.append(SOURCE_FILE)
        try:
            secure = state.read_secure_file(path, max_bytes=MAX_SOURCE_BYTES,
                                            label="scope file")
        except state.SecureFileError as exc:
            file_info = _file_info(path, exc.st, settings.euid)
            invalid.append(_invalid(path, exc.reason))
        else:
            file_info = _file_info(path, secure.st, settings.euid)
            try:
                text = secure.data.decode("utf-8")
            except UnicodeDecodeError:
                invalid.append(_invalid(path, "file_not_utf8"))
            else:
                file_tokens = tokenize(text, comments=True)

    tokens = env_tokens + file_tokens
    entries: dict[str, Entry] = {}
    exclusions: dict[str, Entry] = {}
    if len(tokens) > MAX_ENTRIES:
        invalid.append(_invalid(f"{len(tokens)} entries", "too_many_entries"))
    else:
        for token in tokens:
            exclusion = token.startswith("!")
            body = token[1:] if exclusion else token
            try:
                entry = parse_entry(body, exclusion=exclusion)
            except EntryError as exc:
                invalid.append(_invalid(token, exc.reason))
                continue
            (exclusions if exclusion else entries).setdefault(entry.text, entry)

    digest = _digest(list(entries.values()), list(exclusions.values()), invalid)
    return ScopeSnapshot(
        configured=bool(tokens) or bool(invalid),
        sources=tuple(sources),
        entries=tuple(entries.values()),
        exclusions=tuple(exclusions.values()),
        invalid=tuple({"entry": item["entry"], "reason": item["reason"]} for item in invalid),
        digest=digest,
        file=file_info,
        file_writable_by_server_user=bool(file_info and file_info["writable_by_server_user"]),
    )


# --- refusals ------------------------------------------------------------------------

class ScopeRefusal(Exception):
    """A scope or DNS refusal (F.7): an H.2 code with message, hint and details."""

    def __init__(self, code: str, message: str, hint: str,
                 details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.hint = hint
        self.details = dict(details or {})


def _details(snapshot: ScopeSnapshot, target: targets.Target, **extra: Any) -> dict[str, Any]:
    details: dict[str, Any] = {"target": target.normalized, "target_type": target.target_type,
                               "scope_entries": snapshot.entry_count,
                               "scope_digest": snapshot.digest}
    details.update(extra)
    return details


def _refuse(code: str, snapshot: ScopeSnapshot, target: targets.Target, **extra: Any
            ) -> ScopeRefusal:
    name = target.normalized
    texts = {
        "out_of_scope": (f"Target {name} is outside the configured scope.",
                         "Ask the operator to add it to SNIPER_MCP_SCOPE (or the scope file) "
                         "if they are authorized to test it. Do not retry with other "
                         "spellings, encodings, IP forms or wider ranges."),
        "excluded": (f"Target {name} is excluded by the configured scope.", _NEVER_RETRY),
        "always_denied": (f"Target {name} is or contains a special-use address that is "
                          "always denied.",
                          "Only an operator can authorize a special-use address, by listing "
                          "it explicitly in the scope. " + _NEVER_RETRY),
        "special_use_address": (f"Target {name} resolves to a special-use address.",
                                _NEVER_RETRY),
        "private_address_not_in_scope": (
            f"Target {name} resolves to a private or special address that no IP or CIDR "
            "entry of the scope covers.",
            "Ask the operator to add that address range to the scope if it is authorized. "
            + _NEVER_RETRY),
        "resolved_out_of_scope": (
            f"Target {name} resolves to addresses outside the IP and CIDR entries of the "
            "scope.",
            "Ask the operator to check the name and the scope ranges. " + _NEVER_RETRY),
        "dns_unresolved": (f"Target {name} does not resolve to any address.",
                           "Check the name with the operator; the strict DNS policy refuses "
                           "names that do not resolve."),
        "dns_timeout": (f"The DNS lookup of {name} did not finish in time.",
                        "Retry later without changing the target."),
    }
    message, hint = texts[code]
    return ScopeRefusal(code, message, hint, _details(snapshot, target, **extra))


def configuration_refusal(snapshot: ScopeSnapshot, *, allow_any: bool) -> ScopeRefusal | None:
    """F.9 step 7 before matching: not configured (unless the lab override) or invalid."""
    if not snapshot.configured:
        if allow_any:
            return None
        return ScopeRefusal(
            "scope_not_configured", "No target scope is configured, so no scan can run.",
            "Ask the operator to set SNIPER_MCP_SCOPE or SNIPER_MCP_SCOPE_FILE to the targets "
            "they are authorized to test (see docs/configuration.md#scope).")
    if snapshot.invalid:
        return ScopeRefusal(
            "scope_invalid", "The configured scope has invalid entries, so no scan can run "
            "until it is fixed.",
            "Ask the operator to fix the entries listed in details (SNIPER_MCP_SCOPE or "
            "SNIPER_MCP_SCOPE_FILE); sniper_status shows them too.",
            {"invalid_entries": [dict(item) for item in snapshot.invalid[:MAX_INVALID_LISTED]],
             "invalid_entries_total": len(snapshot.invalid)})
    return None


def _best_domain_entry(snapshot: ScopeSnapshot, host: str) -> str | None:
    matching = [e for e in snapshot.domain_entries if e.matches_host(host)]
    if not matching:
        return None
    # Most specific first: an exact entry, then the longest domain.
    matching.sort(key=lambda e: (e.domain != host, -len(e.domain or ""), e.text))
    return matching[0].text


def _best_network_entry(snapshot: ScopeSnapshot, block: IPNetwork) -> str | None:
    matching = [e for e in snapshot.entries if e.network is not None
                and e.network.version == block.version
                and block.subnet_of(e.network)]  # type: ignore[arg-type]
    if not matching:
        return None
    matching.sort(key=lambda e: (-e.network.prefixlen, e.text))  # type: ignore[union-attr]
    return matching[0].text


def check_target(snapshot: ScopeSnapshot, target: targets.Target, *,
                 allow_any: bool) -> str | None:
    """F.9 step 7: configuration, exclusions, membership and the literal deny checks.

    Returns the normalized entry that authorized the target (``None`` under
    the lab override when no entry matches). Raises ``ScopeRefusal``.
    """
    refusal = configuration_refusal(snapshot, allow_any=allow_any)
    if refusal is not None:
        raise refusal
    kind = target.target_type
    if kind == targets.HOSTNAME:
        host = target.normalized
        if any(e.matches_host(host) for e in snapshot.domain_exclusions):
            raise _refuse("excluded", snapshot, target)
        matched = _best_domain_entry(snapshot, host)
        if matched is None and not allow_any:
            raise _refuse("out_of_scope", snapshot, target)
        return matched  # the DNS policy follows at F.9 step 13
    if kind == targets.IPV4:
        address = ipaddress.IPv4Address(target.normalized)
        if snapshot.excluded_address(address):
            raise _refuse("excluded", snapshot, target)
        matched = _best_network_entry(snapshot, ipaddress.IPv4Network(address))
        if matched is None and not allow_any:
            raise _refuse("out_of_scope", snapshot, target)
        if in_always_deny_v4(address) and not snapshot.explicitly_listed(address):
            raise _refuse("always_denied", snapshot, target)
        return matched
    if kind == targets.IPV4_CIDR:
        network = ipaddress.IPv4Network(target.normalized)
        # The engine cannot skip addresses inside a range, so any overlap refuses.
        if any(network.overlaps(x) for x in snapshot.excluded_networks if x.version == 4):
            raise _refuse("excluded", snapshot, target)
        matched = _best_network_entry(snapshot, network)
        if matched is None and not allow_any:
            raise _refuse("out_of_scope", snapshot, target)
        explicit = [n for n in snapshot.explicit_networks if n.version == 4]
        for denied in ALWAYS_DENY_V4:
            if network.overlaps(denied):
                part = network if network.subnet_of(denied) else denied
                if not covered(part, explicit):
                    raise _refuse("always_denied", snapshot, target)
        return matched
    raise ValueError(f"unknown target type {kind!r}")


# --- DNS policy (F.5) ----------------------------------------------------------------

class DnsNotFound(Exception):
    """The name has no address (NXDOMAIN or no A/AAAA record)."""


class DnsTimeout(Exception):
    """The lookup did not finish in time, both workers are busy, or it failed transiently."""


_NOT_FOUND_ERRNOS = frozenset(
    code for code in (getattr(socket, "EAI_NONAME", None), getattr(socket, "EAI_NODATA", None))
    if code is not None)


def resolver(host: str) -> list[str]:
    """The system resolver: ``getaddrinfo(host, None, AF_UNSPEC, SOCK_STREAM)`` (F.5).

    Raises ``LookupError`` for a definite negative answer and ``TimeoutError``
    for every other failure (fail closed). Tests replace this function (O.2).
    """
    try:
        infos = socket.getaddrinfo(host.encode("ascii"), None, socket.AF_UNSPEC,
                                   socket.SOCK_STREAM)
    except socket.gaierror as exc:
        if exc.errno in _NOT_FOUND_ERRNOS:
            raise LookupError(f"{host} has no address") from exc
        raise TimeoutError(f"lookup of {host} failed ({exc.strerror})") from exc
    except (OSError, UnicodeError) as exc:
        raise TimeoutError(f"lookup of {host} failed") from exc
    return [str(info[4][0]) for info in infos]


_workers = threading.BoundedSemaphore(DNS_WORKERS)


def lookup(host: str) -> list[str]:
    """Run ``resolver(host)`` in the bounded pool with the F.5 timeout.

    When both workers are busy (for example with lookups that timed out but
    have not returned) the call fails at once with ``DnsTimeout``.
    """
    if not _workers.acquire(blocking=False):
        raise DnsTimeout("both DNS workers are busy")
    outcome: dict[str, Any] = {}
    finished = threading.Event()

    def work() -> None:
        try:
            outcome["value"] = resolver(host)  # module attribute, read at call time
        except BaseException as exc:  # noqa: BLE001 - every failure is reported below
            outcome["error"] = exc
        finally:
            _workers.release()
            finished.set()

    try:
        threading.Thread(target=work, name="sn1per-mcp-dns", daemon=True).start()
    except RuntimeError as exc:
        _workers.release()
        raise DnsTimeout("cannot start a DNS worker") from exc
    if not finished.wait(DNS_TIMEOUT_SECONDS):
        raise DnsTimeout(f"no answer for {host} within {DNS_TIMEOUT_SECONDS} seconds")
    error = outcome.get("error")
    if error is not None:
        if isinstance(error, LookupError):
            raise DnsNotFound(str(error))
        raise DnsTimeout(str(error) or type(error).__name__)
    value = outcome.get("value")
    if not isinstance(value, (list, tuple)):
        raise DnsTimeout("the resolver returned no address list")
    return [str(item) for item in value]


def _address_key(address: IPAddress) -> tuple[int, int]:
    return (address.version, int(address))


def _parse_answers(raw: Iterable[str]) -> list[IPAddress]:
    """Unique answers, IPv4-mapped IPv6 converted to IPv4, sorted (F.5)."""
    unique: dict[str, IPAddress] = {}
    for item in raw:
        text = item.split("%", 1)[0]  # an IPv6 zone index is not part of the address
        try:
            address = ipaddress.ip_address(text)
        except ValueError as exc:
            raise DnsTimeout("the resolver returned an unparseable address") from exc
        if address.version == 6 and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        unique[str(address)] = address
    return sorted(unique.values(), key=_address_key)


def _judged(address: IPAddress) -> tuple[IPAddress, ...]:
    """Addresses judged by the scope rules R3 and R4: the embedded IPv4 when there is one."""
    if address.version == 6:
        embedded = embedded_ipv4(address)
        if embedded:
            return embedded
    return (address,)


def special_use_offends(snapshot: ScopeSnapshot, address: IPAddress) -> bool:
    """R1: the answer, or an IPv4 address embedded in it, is always-denied and not listed."""
    if address.version == 4:
        return in_always_deny_v4(address) and not snapshot.explicitly_listed(address)
    embedded = embedded_ipv4(address)
    if any(in_always_deny_v4(e) and not snapshot.explicitly_listed(e) for e in embedded):
        return True
    if any(address in block for block in ALWAYS_DENY_V6):
        if embedded:
            # An embedded-IPv4 address is explicitly listed only through its IPv4 form.
            return not all(snapshot.explicitly_listed(e) for e in embedded)
        return not snapshot.explicitly_listed(address)
    return False


def excluded_offends(snapshot: ScopeSnapshot, address: IPAddress) -> bool:
    """R2: the answer, or an IPv4 address embedded in it, is inside an IP/CIDR exclusion."""
    if snapshot.excluded_address(address):
        return True
    if address.version == 6:
        return any(snapshot.excluded_address(e) for e in embedded_ipv4(address))
    return False


@dataclass(frozen=True)
class DnsCheck:
    """Outcome of the DNS policy for an accepted hostname target."""

    resolved: tuple[str, ...]  # sorted, at most 64
    total: int
    warnings: tuple[str, ...] = ()


def check_dns(snapshot: ScopeSnapshot, target: targets.Target, *, policy: str,
              allow_any: bool) -> DnsCheck:
    """F.5 for a hostname target (F.9 step 13). Raises ``ScopeRefusal``.

    ``strict``: R0-R4 (the lab override skips R3 and R4). ``lenient``: R1 and R2,
    and a name without addresses passes with warning ``dns_unresolved``. A
    timeout, a full worker pool or an unparseable answer refuses under both
    policies: no answer was checked.
    """
    if target.target_type != targets.HOSTNAME:
        raise ValueError("only hostname targets are resolved")
    try:
        answers = _parse_answers(lookup(target.normalized))
    except DnsTimeout as exc:  # F.7: every DNS refusal lists both address sets
        raise _refuse("dns_timeout", snapshot, target, resolved_addresses=[],
                      offending_addresses=[]) from exc
    except DnsNotFound:
        answers = []
    if not answers:  # R0
        if policy == POLICY_LENIENT:
            return DnsCheck(resolved=(), total=0, warnings=("dns_unresolved",))
        raise _refuse("dns_unresolved", snapshot, target, resolved_addresses=[],
                      offending_addresses=[])
    resolved = [str(a) for a in answers]
    shown = resolved[:RESOLVED_MAX]

    def refuse(code: str, offending: list[IPAddress]) -> ScopeRefusal:
        return _refuse(code, snapshot, target, resolved_addresses=shown,
                       resolved_addresses_total=len(resolved),
                       offending_addresses=[str(a) for a in offending][:RESOLVED_MAX])

    offending = [a for a in answers if special_use_offends(snapshot, a)]  # R1
    if offending:
        raise refuse("special_use_address", offending)
    offending = [a for a in answers if excluded_offends(snapshot, a)]  # R2
    if offending:
        raise refuse("excluded", offending)
    if policy == POLICY_STRICT and not allow_any:
        offending = [a for a in answers  # R3
                     if any(not is_public(j) and not snapshot.in_scope_address(j)
                            for j in _judged(a))]
        if offending:
            raise refuse("private_address_not_in_scope", offending)
        if snapshot.has_ip_entries:  # R4
            offending = [a for a in answers
                         if any(not snapshot.in_scope_address(j) for j in _judged(a))]
            if offending:
                raise refuse("resolved_out_of_scope", offending)
    return DnsCheck(resolved=tuple(shown), total=len(resolved))


# --- change detection (F.1, G.4 scope_changed) ---------------------------------------

class ScopeTracker:
    """The last ``scope_digest`` this process saw (F.1 change detection).

    The first digest seen is the baseline. A later different digest is a
    change that the caller records with a ``scope_changed`` audit line, then
    commits; a change whose line could not be written stays pending, so the
    next read tries again.
    """

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self._seen = False
        self._digest: str | None = None

    @property
    def digest(self) -> str | None:
        return self._digest

    def pending_change(self, digest: str | None) -> tuple[bool, str | None]:
        """``(changed, previous digest)``; the first digest seen becomes the baseline
        and is not a change. Call with ``lock`` held."""
        if not self._seen:
            self._seen = True
            self._digest = digest
            return False, digest
        return digest != self._digest, self._digest

    def commit(self, digest: str | None) -> None:
        """Record ``digest`` as seen. Call with ``lock`` held."""
        self._seen = True
        self._digest = digest


# --- rate limit (F.8, A-44) ------------------------------------------------------------------

RATE_LIMIT_CALLS = 6
RATE_LIMIT_WINDOW_SECONDS = 60.0


class RateLimiter:
    """At most 6 ``sniper_scan`` calls per server process in any 60-second window may
    pass the scope step (F.9 step 8). A fixed constant, not a setting (A-44)."""

    def __init__(self, calls: int = RATE_LIMIT_CALLS,
                 window: float = RATE_LIMIT_WINDOW_SECONDS,
                 clock: Callable[[], float] | None = None) -> None:
        self.calls = calls
        self.window = window
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._passed: collections.deque[float] = collections.deque()

    def allow(self) -> bool:
        """Count one call that passed the scope step; False when the window is full."""
        with self._lock:
            now = self._clock()
            while self._passed and now - self._passed[0] >= self.window:
                self._passed.popleft()
            if len(self._passed) >= self.calls:
                return False
            self._passed.append(now)
            return True
