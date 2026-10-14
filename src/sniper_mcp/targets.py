# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Target grammar, IDNA normalization and workspace names (contract E, H.4).

:func:`normalize_target` runs the E.1 pipeline in its normative order; the
first failing step decides the error code. Only the normalized target it
returns may reach argv, the scope guard, the audit log or workspace
derivation. Every pattern uses ``re.fullmatch`` (a ``$`` anchor accepts a
trailing newline, 01 SEC-16).
"""

from __future__ import annotations

import ipaddress
import re
import socket
import unicodedata
import urllib.parse
from dataclasses import dataclass, field

import idna

MAX_TARGET_CHARS = 2048
MAX_HOSTNAME_CHARS = 253
MAX_HOST_FILTER_CHARS = 253
TARGET_INPUT_AUDIT_CHARS = 256

# Target types reported in results and used by the D.6 compatibility table. One
# spelling on every surface (tool results, refusal details, sniper_status modes, job
# records and the audit log): the G.3 vocabulary, a stable public value (S.5).
HOSTNAME = "hostname"
IPV4 = "ipv4"
IPV4_CIDR = "cidr"

# E.1 step 1: Unicode general categories that are never allowed anywhere.
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zs", "Zl", "Zp"})
# E.1 step 1: ASCII characters forbidden outside a URL query or fragment.
_FORBIDDEN_PUNCTUATION = frozenset("`$;|&<>(){}\"'\\*!^~,")

_URL_SCHEMES = {"http://": 80, "https://": 443}

# E.1 step 8.4.
_ALABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_ENDS_IN_NUMBER_RE = re.compile(r"[0-9]+|0x[0-9a-f]*")
_HAS_LETTER_RE = re.compile(r".*[a-z].*")

# E.1 step 8.5: script groups that may share a label. Every other script word is
# its own group. "CJK" is the first word of the Han ideograph names.
_SHARED_SCRIPT_GROUPS = (
    frozenset({"CJK", "HIRAGANA", "KATAKANA", "KATAKANA-HIRAGANA"}),
    frozenset({"CJK", "HANGUL"}),
)

# E.1 step 8.6 (A-42): never scanned, whatever the scope or the lab override.
ALWAYS_DENIED_NAMES = frozenset({
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback", "metadata",
    "metadata.google.internal", "metadata.goog", "instance-data",
    "instance-data.ec2.internal",
})
# Names denied together with every name under them. example.com, example.net and
# example.org are real IANA-operated hosts; the 2026-10-10 incident scanned one.
ALWAYS_DENIED_SUFFIXES = ("localhost", "example.com", "example.net", "example.org")

# E.3 workspace grammar.
WORKSPACE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_WORKSPACE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_WORKSPACE_UNSAFE_RE = re.compile(r"[^A-Za-z0-9._-]")


class TargetError(ValueError):
    """A target, host filter or workspace failed validation (H.2 code in ``code``)."""

    def __init__(self, code: str, message: str, hint: str,
                 details: dict[str, object] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.hint = hint
        self.details = dict(details or {})


@dataclass(frozen=True)
class Target:
    """A target that passed E.1."""

    normalized: str
    target_type: str  # HOSTNAME, IPV4 or IPV4_CIDR
    raw: str
    from_url: bool = False
    url_port: int | None = None  # the URL's explicit port, if any
    url_default_port: int | None = None  # 80 or 443 for a URL, else None
    warnings: tuple[str, ...] = field(default=())

    @property
    def changed(self) -> bool:
        """True when normalization changed the input (the result then echoes it)."""
        return self.normalized != self.raw


_HINT_ONE_TARGET = ("Pass one hostname, IPv4 address, http(s) URL or IPv4 CIDR range. Do not "
                    "retry with other spellings or encodings.")
_HINT_NEVER = ("Do not retry with other spellings, encodings, IP forms or wider ranges; ask "
               "the operator.")


def _invalid(message: str, hint: str = _HINT_ONE_TARGET) -> TargetError:
    return TargetError("invalid_target", message, hint)


def _forbidden_character(text: str, *, punctuation: bool) -> str | None:
    """E.1 step 1: the first forbidden character, or None."""
    for ch in text:
        code = ord(ch)
        if unicodedata.category(ch) in _FORBIDDEN_CATEGORIES:
            return ch
        if 0xFE00 <= code <= 0xFE0F or 0xE0100 <= code <= 0xE01EF:
            return ch
        if punctuation and ch in _FORBIDDEN_PUNCTUATION:
            return ch
    return None


def _check_characters(text: str, *, url: bool) -> None:
    """E.1 steps 1 and 2."""
    if url:
        # Punctuation is allowed in a URL query or fragment; categories are not.
        cut = min((i for i in (text.find("?"), text.find("#")) if i >= 0), default=len(text))
        bad = (_forbidden_character(text, punctuation=False)
               or _forbidden_character(text[:cut], punctuation=True))
    else:
        bad = _forbidden_character(text, punctuation=True)
    if bad is not None:
        raise _invalid(f"The target contains a forbidden character (U+{ord(bad):04X}).")
    if text.startswith("-"):
        raise _invalid("The target starts with '-'.")


def _url_scheme(text: str) -> str | None:
    lowered = text[:8].lower()
    for scheme in _URL_SCHEMES:
        if lowered.startswith(scheme):
            return scheme
    return None


@dataclass
class _UrlParts:
    host: str
    port: int | None
    default_port: int
    reduced: bool


def _split_url(text: str, scheme: str) -> _UrlParts:
    """E.1 step 3."""
    try:
        parts = urllib.parse.urlsplit(text)
        netloc = parts.netloc
        if "@" in netloc:
            raise _invalid("The URL carries user information (credentials).",
                           "Pass the URL without user information.")
        if netloc.startswith("["):
            raise TargetError("unsupported_target", "IPv6 targets are not supported in this "
                              "version.", "Use an IPv4 address or a hostname.")
        port = parts.port
    except ValueError as exc:
        if isinstance(exc, TargetError):
            raise
        raise _invalid("The URL cannot be parsed.") from exc
    if port == 0:
        raise _invalid("The URL port is not valid.")
    host = netloc.rsplit(":", 1)[0] if ":" in netloc else netloc
    if not host:
        raise _invalid("The URL has no host.")
    reduced = (parts.path not in ("", "/") or bool(parts.query) or bool(parts.fragment)
               or "?" in text or "#" in text)
    return _UrlParts(host=host, port=port, default_port=_URL_SCHEMES[scheme],
                     reduced=reduced)


def _canonical_map(host: str) -> str:
    """E.1 step 3a: UTS-46 map, strip one trailing dot, refuse empty labels."""
    try:
        mapped = idna.uts46_remap(host, std3_rules=False, transitional=False)
    except (idna.IDNAError, ValueError) as exc:
        raise _invalid("The target cannot be mapped to a hostname.") from exc
    if mapped.endswith("."):
        mapped = mapped[:-1]
    if mapped == "" or "" in mapped.split("."):
        raise _invalid("The target has an empty label.")
    _check_characters(mapped, url=False)
    return mapped


def _is_ipv6(value: str) -> bool:
    for parse in (ipaddress.IPv6Address, lambda v: ipaddress.IPv6Network(v, strict=False)):
        try:
            parse(value)
        except ValueError:
            continue
        return True
    return False


def _unsupported_ipv6() -> TargetError:
    return TargetError("unsupported_target", "IPv6 targets are not supported in this version.",
                       "Use an IPv4 address or a hostname.")


def _cidr(value: str, cidr_cap: int) -> str:
    """E.1 step 5."""
    try:
        loose = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise _invalid("The target is not a valid CIDR range.") from exc
    if loose.version == 6:
        raise _unsupported_ipv6()
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise TargetError("cidr_not_canonical", "The CIDR range has host bits set.",
                          f"Use the canonical network {loose}.",
                          {"canonical": str(loose)}) from exc
    if network.prefixlen < cidr_cap:
        raise TargetError("cidr_too_large", f"The range {network} is larger than /{cidr_cap}.",
                          f"Use a range of /{cidr_cap} or smaller.",
                          {"cidr_cap": cidr_cap, "prefixlen": network.prefixlen})
    return str(network)


def _inet_aton_accepts(value: str) -> bool:
    try:
        socket.inet_aton(value)
    except (OSError, ValueError):
        return False
    return True


def _script_word(ch: str) -> str:
    if "a" <= ch <= "z" or "A" <= ch <= "Z":
        return "LATIN"
    try:
        return unicodedata.name(ch).split(" ", 1)[0]
    except ValueError:
        return f"U+{ord(ch):04X}"


def _mixed_script(ulabel: str) -> bool:
    """E.1 step 8.5: letters of one label must come from one script group."""
    words = {_script_word(ch) for ch in ulabel if unicodedata.category(ch).startswith("L")}
    if len(words) <= 1:
        return False
    return not any(words <= group for group in _SHARED_SCRIPT_GROUPS)


def is_always_denied_name(name: str) -> bool:
    """E.1 step 8.6 on a normalized (lowercase A-label) hostname."""
    if name in ALWAYS_DENIED_NAMES:
        return True
    return any(name == suffix or name.endswith("." + suffix)
               for suffix in ALWAYS_DENIED_SUFFIXES)


def _hostname(mapped: str, *, deny_names: bool) -> str:
    """E.1 step 8: the lowercase A-label hostname."""
    alabels: list[str] = []
    for label in mapped.split("."):
        if not label.isascii() or label.startswith("xn--"):
            try:
                alabel = idna.encode(label, uts46=True, transitional=False).decode("ascii")
            except (idna.IDNAError, UnicodeError, ValueError) as exc:
                raise _invalid("The target is not a valid internationalized name.") from exc
        else:
            alabel = label
        alabels.append(alabel)
    name = ".".join(alabels)
    if name != name.lower():
        raise _invalid("The target could not be lowercased.")
    if not all(_ALABEL_RE.fullmatch(label) for label in alabels):
        raise _invalid("A label of the hostname is not valid (1-63 letters, digits or '-', "
                       "no leading or trailing '-').")
    final = alabels[-1]
    if _ENDS_IN_NUMBER_RE.fullmatch(final) or not _HAS_LETTER_RE.fullmatch(final):
        raise _invalid("The last label of the hostname must contain a letter and must not "
                       "look like a number.")
    if len(name) > MAX_HOSTNAME_CHARS:
        raise TargetError("target_too_long", "The hostname is longer than 253 characters.",
                          "Pass a shorter hostname.")
    for alabel in alabels:
        ulabel = alabel
        if alabel.startswith("xn--"):
            try:
                ulabel = idna.decode(alabel)
            except (idna.IDNAError, UnicodeError, ValueError) as exc:
                raise _invalid("The target is not a valid internationalized name.") from exc
        if _mixed_script(ulabel):
            raise TargetError("mixed_script", "A label of the hostname mixes scripts.",
                              _HINT_NEVER)
    if deny_names and is_always_denied_name(name):
        raise TargetError("always_denied", f"Target {name} is always denied.", _HINT_NEVER)
    if alabels[0] == "com":
        raise TargetError("unsupported_target", "Targets whose first label is 'com' are not "
                          "supported (the engine reads them as mobile application ids).",
                          "Pass a different hostname.")
    return name


def normalize_target(raw: str, *, cidr_cap: int) -> Target:
    """Run E.1 on ``raw`` and return the normalized target, or raise ``TargetError``."""
    if not isinstance(raw, str) or not 1 <= len(raw) <= MAX_TARGET_CHARS:
        raise _invalid("The target must be 1-2048 characters.")
    scheme = _url_scheme(raw)
    _check_characters(raw, url=scheme is not None)  # steps 1 and 2
    warnings: list[str] = []
    url: _UrlParts | None = None
    host = raw
    if scheme is not None:  # step 3
        url = _split_url(raw, scheme)
        host = url.host
        if url.reduced:
            warnings.append("url_reduced_to_host")
    mapped = _canonical_map(host)  # step 3a (re-runs steps 1 and 2)

    def made(normalized: str, target_type: str) -> Target:
        return Target(normalized=normalized, target_type=target_type, raw=raw,
                      from_url=url is not None,
                      url_port=url.port if url else None,
                      url_default_port=url.default_port if url else None,
                      warnings=tuple(warnings))

    if ":" in mapped and not _is_ipv6(mapped):  # step 4
        raise _invalid("The target contains ':' but is not an address.",
                       "Use the port parameter or an http(s) URL.")
    if "/" in mapped:  # step 5
        if url is not None:
            raise _invalid("A URL host cannot be a CIDR range.")
        return made(_cidr(mapped, cidr_cap), IPV4_CIDR)
    try:  # step 6
        address = ipaddress.ip_address(mapped)
    except ValueError:
        address = None
    if address is not None:
        if address.version == 6:
            raise _unsupported_ipv6()
        return made(str(address), IPV4)
    if _inet_aton_accepts(mapped):  # step 7
        raise TargetError("non_canonical_ip", "The target is an alternate IPv4 notation.",
                          "Write the address as four decimal octets without leading zeros. "
                          + _HINT_NEVER)
    return made(_hostname(mapped, deny_names=True), HOSTNAME)  # step 8


def map_entry_text(text: str) -> str:
    """E.1 steps 1-2, 3a and 1-2 again, for a scope entry body (F.1 normalization).

    Raises ``TargetError`` (``invalid_target``) on a forbidden character, a
    leading dash, a mapping error or an empty label.
    """
    _check_characters(text, url=False)
    return _canonical_map(text)


def validate_hostname(mapped: str, *, deny_names: bool) -> str:
    """E.1 step 8 on a mapped name (step 3a done); returns the lowercase A-label name.

    With ``deny_names`` the always-denied names of step 8.6 raise
    ``always_denied``; scope exclusions may name them (F.1).
    """
    return _hostname(mapped, deny_names=deny_names)


def is_alternate_ipv4(mapped: str) -> bool:
    """E.1 step 7: ``inet_aton`` accepts a notation that is not a canonical IPv4 address."""
    return _inet_aton_accepts(mapped)


def target_input_for_audit(raw: str) -> str:
    """The raw input as recorded in the audit log (``target_input``, E.1)."""
    return raw[:TARGET_INPUT_AUDIT_CHARS]


def normalize_host_filter(value: str) -> str:
    """H.4 ``host`` filter: a hostname (E.1 steps 3a and 8) or an IPv4 address.

    The always-denied names are allowed here, because nothing is scanned.
    Anything else is ``invalid_argument``.
    """
    hint = "Pass one hostname or IPv4 address as it appears in the results, without wildcards."
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_HOST_FILTER_CHARS:
        raise TargetError("invalid_argument", "host must be 1-253 characters.", hint)
    try:
        mapped = _canonical_map(value)
        try:
            address = ipaddress.ip_address(mapped)
        except ValueError:
            address = None
        if address is not None:
            if address.version != 4:
                raise _invalid("IPv6 is not supported.")
            return str(address)
        if _inet_aton_accepts(mapped):
            raise _invalid("Alternate IPv4 notation.")
        return _hostname(mapped, deny_names=False)
    except TargetError as exc:
        raise TargetError("invalid_argument", "host must be one exact hostname or IPv4 "
                          f"address ({exc.message})", hint) from exc


def loot_host(value: str) -> str | None:
    """A host named by loot (a file-name token, J.3.2): the normalized hostname or
    IPv4 address of :func:`normalize_host_filter`, or None when it is neither."""
    try:
        return normalize_host_filter(value)
    except TargetError:
        return None


def loot_hostname(value: str) -> str | None:
    """J.3.3: a hostname read from loot, as a lowercase A-label name, or None.

    The E.1 step 1 characters and the step 8 rules apply (the always-denied names
    are kept: nothing is scanned). IP addresses, ``host:port`` and wildcards give
    None.
    """
    if not 1 <= len(value) <= MAX_HOST_FILTER_CHARS:
        return None
    try:
        _check_characters(value, url=False)
        mapped = _canonical_map(value)
        try:
            ipaddress.ip_address(mapped)
            return None
        except ValueError:
            pass
        if _inet_aton_accepts(mapped):
            return None
        return _hostname(mapped, deny_names=False)
    except TargetError:
        return None


def is_valid_workspace(name: object) -> bool:
    """E.3 grammar: pattern, no ``..`` substring, no trailing ``.``."""
    return (isinstance(name, str) and _WORKSPACE_RE.fullmatch(name) is not None
            and ".." not in name and not name.endswith("."))


def validate_workspace(name: str) -> str:
    """Return ``name`` or raise ``TargetError("invalid_workspace")`` (E.3)."""
    if not is_valid_workspace(name):
        raise TargetError("invalid_workspace", "Invalid workspace name.",
                          "Use 1-128 letters, digits, '.', '_' and '-', starting with a letter "
                          "or digit, without '..' and without a trailing '.'.")
    return name


def derive_workspace(normalized: str) -> str:
    """E.3 derivation from the normalized target (``192.0.2.0/24`` -> ``192.0.2.0-24``)."""
    candidate = _WORKSPACE_UNSAFE_RE.sub("-", normalized)
    if not is_valid_workspace(candidate):
        raise TargetError("invalid_workspace", "No valid workspace name can be derived from "
                          "this target.", "Pass an explicit workspace.")
    return candidate
