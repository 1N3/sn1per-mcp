# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""The scope guard and the DNS policy (contract F.1-F.6; O.5 P0-08 and GAP-07).

Unit tests of ``sniper_mcp.scope``: parsing and normalization, label-boundary
matching, the pinned F.4 tables, embedded IPv4, explicit special-use listing,
the strict and lenient DNS policies, the lab override, the bounded resolver
pool and the address cap. Every F.2 row also runs end to end through
``sniper_scan`` in tests/test_scan_tools.py.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import json
import os
import threading
import time

import pytest

from sniper_mcp import scope, state, targets
from tests import support

CAP = 16
CYRILLIC_A = "\u0430"
# Values outside RFC 5737 and the F.4 ranges are built at run time, so no such literal
# appears in the repository (P.5 example-value rule): a public address, and the /16
# and /24 around the Azure platform endpoint of the deny table.
PUBLIC_V4 = str(ipaddress.IPv4Address(0x0B000001))
AZURE = str(scope.ALWAYS_DENY_V4[4].network_address)
AZURE_16 = str(ipaddress.ip_network(AZURE + "/16", strict=False))
AZURE_24 = str(ipaddress.ip_network(AZURE + "/24", strict=False))
# The /23 around 192.0.2.0/24 reaches outside RFC 5737, so it is built at run time (P.5).
SUPERNET_23 = str(ipaddress.ip_network("192.0.2.0/24").supernet())
AZURE_OTHER_24 = str(next(ipaddress.ip_network(AZURE_16).subnets(new_prefix=24)))


def snapshot(iso, value: str = "", *, file_text: str | None = None, mode: int = 0o600):
    if value:
        iso.setenv(SNIPER_MCP_SCOPE=value)
    if file_text is not None:
        path = iso.tmp / "scope-file"
        path.write_text(file_text)
        path.chmod(mode)
        iso.setenv(SNIPER_MCP_SCOPE_FILE=str(path))
    return scope.load(support.current_settings())


def target(value: str) -> targets.Target:
    return targets.normalize_target(value, cidr_cap=CAP)


def refusal(snap, value: str, *, allow_any: bool = False) -> str | None:
    try:
        scope.check_target(snap, target(value), allow_any=allow_any)
    except scope.ScopeRefusal as exc:
        return exc.code
    return None


def dns_refusal(snap, value: str, *, policy: str = "strict", allow_any: bool = False):
    try:
        scope.check_dns(snap, target(value), policy=policy, allow_any=allow_any)
    except scope.ScopeRefusal as exc:
        return exc.code
    return None


# --- F.1 tokenizing and entry types ------------------------------------------------------

def test_tokens_are_split_on_commas_spaces_tabs_and_newlines(iso):
    snap = snapshot(iso, "app.example, api.app.example\t192.0.2.0/24\n!dev.app.example,,")
    assert [e.text for e in snap.entries] == ["app.example", "api.app.example", "192.0.2.0/24"]
    assert [e.text for e in snap.exclusions] == ["dev.app.example"]
    assert snap.valid and snap.configured and snap.sources == ("env",)


def test_file_comments_crlf_and_union_with_the_environment(iso):
    snap = snapshot(iso, "app.example",
                    file_text="# engagement SOW-1\r\n192.0.2.0/24 # lab range\r\n"
                              "!192.0.2.13\r\n\r\n#!ignored.example\n")
    assert [e.text for e in snap.entries] == ["app.example", "192.0.2.0/24"]
    assert [e.text for e in snap.exclusions] == ["192.0.2.13"]
    assert snap.sources == ("env", "file") and snap.source == "env+file"
    assert snap.valid


def test_hash_is_not_a_comment_in_the_environment(iso):
    snap = snapshot(iso, "app.example,#comment")
    assert not snap.valid
    assert snap.invalid == ({"entry": "#comment", "reason": "invalid_target"},)


@pytest.mark.parametrize(("entry", "normalized"), [
    ("APP.Example.", "app.example"),
    ("app.example\u3002", "app.example"),
    ("\uff41\uff50\uff50.example", "app.example"),  # full-width letters
    ("m\u00fcnchen.example", "xn--mnchen-3ya.example"),
    ("XN--MNCHEN-3YA.example", "xn--mnchen-3ya.example"),
    ("*.App.Example", "*.app.example"),
    ("corp", "corp"),
    ("192.0.2.10", "192.0.2.10"),
    ("\uff11\uff19\uff12\uff0e\uff10\uff0e\uff12\uff0e\uff11\uff10", "192.0.2.10"),
    ("192.0.2.0/24", "192.0.2.0/24"),
    ("192.0.2.10/32", "192.0.2.10"),
    ("2001:DB8::10", "2001:db8::10"),
    ("2001:db8::/48", "2001:db8::/48"),
    ("::ffff:192.0.2.10", "192.0.2.10"),
    ("::ffff:c000:200/120", "192.0.2.0/24"),
    ("::ffff:c000:20a/128", "192.0.2.10"),
])
def test_entries_are_normalized_like_targets(iso, entry, normalized):
    snap = snapshot(iso, entry)
    assert snap.valid, snap.invalid
    assert [e.text for e in snap.entries] == [normalized]


@pytest.mark.parametrize(("entry", "reason"), [
    ("*.corp", "invalid_wildcard"),
    ("*.", "invalid_target"),
    ("*", "invalid_target"),
    ("**.app.example", "invalid_target"),
    ("*.192.0.2.1", "invalid_target"),
    ("app.*.example", "invalid_target"),
    ("example.com", "always_denied_name"),
    ("www.example.org", "always_denied_name"),
    ("EXAMPLE.NET.", "always_denied_name"),
    ("*.example.com", "always_denied_name"),
    ("localhost", "always_denied_name"),
    ("api.localhost", "always_denied_name"),
    ("metadata.google.internal", "always_denied_name"),
    ("::ffff:0:0/96", "cidr_prefix_too_short"),
    ("0.0.0.0/0", "cidr_prefix_too_short"),
    ("::/0", "cidr_prefix_too_short"),
    ("224.0.0.0/7", "cidr_prefix_too_short"),
    ("2001:db8::/31", "cidr_prefix_too_short"),
    ("::ffff:0:0/100", "cidr_prefix_too_short"),
    ("192.0.2.5/24", "cidr_not_canonical"),
    ("2001:db8::1/48", "cidr_not_canonical"),
    ("bad..app.example", "invalid_target"),
    ("<authorized-targets>", "invalid_target"),
    ("127.1", "non_canonical_ip"),
    ("0x7f000001", "non_canonical_ip"),
    ("192.0.2.010", "non_canonical_ip"),
    ("app.example:443", "invalid_target"),
    ("http://app.example", "invalid_target"),
    ("fe80::1%eth0", "invalid_target"),
    ("-app.example", "invalid_target"),
    ("app.example;id", "invalid_target"),
    ("com.example.app", "unsupported_target"),
    ("a" + CYRILLIC_A + "pp.example", "mixed_script"),
    ("a" * 64 + ".example", "invalid_target"),
    (("a" * 63 + ".") * 4 + "example", "target_too_long"),
    ("!", "invalid_target"),
    ("!*.corp", "invalid_wildcard"),
])
def test_invalid_entries_and_their_reasons(iso, entry, reason):
    snap = snapshot(iso, f"app.example,{entry}")
    assert not snap.valid
    shown = json.dumps(entry[:scope.MAX_ENTRY_CHARS])[1:-1]  # escaped ASCII
    assert snap.invalid == ({"entry": shown, "reason": reason},)
    # The valid entries are still listed (sniper_status shows them).
    assert [e.text for e in snap.entries] == ["app.example"]


def test_one_bad_entry_invalidates_the_whole_scope(iso):
    snap = snapshot(iso, "app.example,192.0.2.0/24,bad..app.example")
    assert refusal(snap, "app.example") == "scope_invalid"
    assert refusal(snap, "192.0.2.10") == "scope_invalid"
    # Even the lab override does not skip an invalid scope (F.6 skips only "not configured").
    assert refusal(snap, "app.example", allow_any=True) == "scope_invalid"


def test_always_denied_names_are_allowed_as_exclusions(iso):
    snap = snapshot(iso, "app.example,!example.com,!localhost,!*.example.org")
    assert snap.valid
    assert [e.text for e in snap.exclusions] == ["example.com", "localhost", "*.example.org"]


def test_duplicates_are_listed_once(iso):
    snap = snapshot(iso, "app.example,APP.example.,app.example\u3002")
    assert [e.text for e in snap.entries] == ["app.example"]


def test_not_configured_and_the_placeholder(iso):
    empty = snapshot(iso)
    assert not empty.configured and empty.digest is None and empty.source == "none"
    assert refusal(empty, "app.example") == "scope_not_configured"
    assert refusal(empty, "app.example", allow_any=True) is None
    placeholder = snapshot(iso, "<authorized-targets>")
    assert placeholder.configured and not placeholder.valid
    assert refusal(placeholder, "app.example") == "scope_invalid"


def test_server_json_placeholder_is_a_valid_scope(iso):
    snap = snapshot(iso, "app.example,192.0.2.0/24")
    assert snap.valid and [e.text for e in snap.entries] == ["app.example", "192.0.2.0/24"]


def test_entry_limit(iso):
    entries = ",".join(f"h{i}.app.example" for i in range(scope.MAX_ENTRIES + 1))
    snap = snapshot(iso, entries)
    assert not snap.valid and snap.invalid[0]["reason"] == "too_many_entries"
    assert snapshot(iso, ",".join(f"h{i}.app.example"
                                  for i in range(scope.MAX_ENTRIES))).valid


def test_environment_source_size_limit(iso):
    big = "app.example," + "x" * scope.MAX_SOURCE_BYTES
    snap = snapshot(iso, big)
    assert not snap.valid
    assert snap.invalid == ({"entry": "SNIPER_MCP_SCOPE", "reason": "source_too_large"},)


# --- F.1 the scope file ------------------------------------------------------------------

def test_scope_file_is_read_without_following_links(iso):
    real = iso.tmp / "real-scope"
    real.write_text("app.example\n")
    real.chmod(0o600)
    link = iso.tmp / "scope-link"
    link.symlink_to(real)
    iso.setenv(SNIPER_MCP_SCOPE_FILE=str(link))
    snap = scope.load(support.current_settings())
    assert not snap.valid and snap.invalid[0] == {"entry": str(link),
                                                  "reason": "file_unreadable"}
    assert refusal(snap, "app.example") == "scope_invalid"


@pytest.mark.parametrize(("mode", "reason"), [(0o620, "file_writable"),
                                              (0o602, "file_writable")])
def test_group_or_world_writable_scope_file_is_invalid(iso, mode, reason):
    snap = snapshot(iso, file_text="app.example\n", mode=mode)
    assert not snap.valid and snap.invalid[0]["reason"] == reason
    assert snap.file["mode"] == f"{mode:04o}"


def test_scope_file_that_is_a_fifo_never_blocks(iso):
    fifo = iso.tmp / "scope-fifo"
    os.mkfifo(fifo, 0o600)
    iso.setenv(SNIPER_MCP_SCOPE_FILE=str(fifo))
    snap = scope.load(support.current_settings())
    assert snap.invalid[0]["reason"] == "file_not_regular"


def test_missing_scope_file_is_invalid_not_ignored(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.example",
               SNIPER_MCP_SCOPE_FILE=str(iso.tmp / "absent-scope"))
    snap = scope.load(support.current_settings())
    assert snap.configured and not snap.valid
    assert snap.invalid[0]["reason"] == "file_unreadable"


def test_scope_file_size_limit_and_encoding(iso):
    snap = snapshot(iso, file_text="a" * (scope.MAX_SOURCE_BYTES + 1))
    assert snap.invalid[0]["reason"] == "file_too_large"
    path = iso.tmp / "scope-latin1"
    path.write_bytes(b"app.example \xff\n")
    path.chmod(0o600)
    iso.setenv(SNIPER_MCP_SCOPE_FILE=str(path))
    assert scope.load(support.current_settings()).invalid[0]["reason"] == "file_not_utf8"


def test_scope_file_info_and_the_writable_warning(iso):
    snap = snapshot(iso, file_text="app.example\n", mode=0o644)
    assert snap.file == {"path": str(iso.tmp / "scope-file"), "owner_uid": os.geteuid(),
                         "mode": "0644", "writable_by_server_user": True}
    assert snap.warning_codes() == ["scope_file_writable_by_server_user"]
    # A file the server user cannot modify (owned by someone else, server not root).
    other = dataclasses.replace(support.current_settings(), euid=os.geteuid() + 1)
    snap = scope.load(other)
    assert snap.file["writable_by_server_user"] is False and snap.warning_codes() == []


def test_domain_exclusions_warning(iso):
    assert snapshot(iso, "app.example,192.0.2.0/24,!dev.app.example").warning_codes() == [
        "domain_exclusions_not_applied_to_ip_targets"]
    assert snapshot(iso, "app.example,!dev.app.example").warning_codes() == []
    assert snapshot(iso, "192.0.2.0/24,!192.0.2.13").warning_codes() == []


def test_scope_file_is_re_read_on_every_load(iso):
    first = snapshot(iso, file_text="app.example\n")
    (iso.tmp / "scope-file").write_text("app.example\napi.app.example\n")
    second = scope.load(support.current_settings())
    assert len(second.entries) == 2 and first.digest != second.digest


# --- F.1 digest ----------------------------------------------------------------------

def test_digest_is_sha256_of_the_sorted_normalized_entries(iso):
    import hashlib

    snap = snapshot(iso, "192.0.2.0/24,APP.example.,!dev.app.example")
    lines = sorted(["app.example", "192.0.2.0/24", "!dev.app.example"])
    expected = hashlib.sha256("\n".join(lines).encode()).hexdigest()[:16]
    assert snap.digest == expected
    # Order and spelling do not matter; content does.
    same = snapshot(iso, "!dev.app.example,app.example,192.0.2.0/24")
    assert same.digest == expected


def test_digest_of_an_invalid_scope_differs_from_its_valid_part(iso):
    valid = snapshot(iso, "app.example")
    invalid = snapshot(iso, "app.example,bad..app.example")
    assert valid.digest != invalid.digest and invalid.digest is not None


# --- F.2 hostname matching -----------------------------------------------------------

@pytest.mark.parametrize(("scope_value", "value", "expected"), [
    ("app.example", "notapp.example", "out_of_scope"),
    ("app.example", "evil-app.example", "out_of_scope"),
    ("app.example", "APP.Example.", None),
    ("app.example", "www.app.example", None),
    ("app.example", "a.b.c.app.example", None),
    ("app.example", "example", "out_of_scope"),
    ("app.example", "app.example.example", "out_of_scope"),
    ("*.app.example", "app.example", "out_of_scope"),
    ("*.app.example", "www.app.example", None),
    ("m\u00fcnchen.example", "xn--mnchen-3ya.example", None),
    ("xn--mnchen-3ya.example", "M\u00fcnchen.example", None),
    ("app.example,!dev.app.example", "api.dev.app.example", "excluded"),
    ("app.example,!dev.app.example", "dev.app.example", "excluded"),
    ("app.example,!dev.app.example", "xdev.app.example", None),
    ("app.example,!*.dev.app.example", "dev.app.example", None),
    ("app.example,!*.dev.app.example", "a.dev.app.example", "excluded"),
    ("corp", "corp", None),
    ("corp", "app.corp", "out_of_scope"),
    ("app.example,!corp", "corp.app.example", None),  # single-label exclusion: exact only
    ("192.0.2.0/24", "app.example", "out_of_scope"),  # IP entries never authorize names
])
def test_hostname_matching_on_label_boundaries(iso, scope_value, value, expected):
    assert refusal(snapshot(iso, scope_value), value) == expected


def test_mixed_script_target_never_reaches_matching(iso):
    with pytest.raises(targets.TargetError) as caught:
        target("a" + CYRILLIC_A + "pp.example")
    assert caught.value.code == "mixed_script"


def test_matched_entry_is_the_most_specific(iso):
    snap = snapshot(iso, "app.example,api.app.example,*.app.example")
    assert scope.check_target(snap, target("v1.api.app.example"), allow_any=False) == \
        "api.app.example"
    assert scope.check_target(snap, target("app.example"), allow_any=False) == "app.example"
    snap = snapshot(iso, "192.0.2.0/24,192.0.2.0/28,192.0.2.5")
    assert scope.check_target(snap, target("192.0.2.5"), allow_any=False) == "192.0.2.5"
    assert scope.check_target(snap, target("192.0.2.9"), allow_any=False) == "192.0.2.0/28"


# --- F.2 IPv4 and CIDR matching ------------------------------------------------------

@pytest.mark.parametrize(("scope_value", "value", "expected"), [
    ("192.0.2.0/24", "192.0.2.77", None),
    ("192.0.2.0/24", "198.51.100.7", "out_of_scope"),
    ("192.0.2.10", "192.0.2.10", None),
    ("192.0.2.10", "192.0.2.11", "out_of_scope"),
    ("app.example", "192.0.2.10", "out_of_scope"),  # domain entries never authorize IPs
    ("192.0.2.0/24,!192.0.2.13", "192.0.2.13", "excluded"),
    ("192.0.2.200,!192.0.2.128/25", "192.0.2.200", "excluded"),
    ("192.0.2.0/24,!app.example", "192.0.2.10", None),  # domain exclusions never apply
    ("::ffff:c000:200/120", "192.0.2.10", None),
    ("192.0.2.0/24,!::ffff:192.0.2.10", "192.0.2.10", "excluded"),
    ("192.0.2.0/24", "192.0.2.0/25", None),
    ("192.0.2.0/24,!192.0.2.64/26", "192.0.2.0/24", "excluded"),
    ("192.0.2.0/24,!192.0.2.10", "192.0.2.0/24", "excluded"),
    ("192.0.2.0/25,!192.0.2.0/24", "192.0.2.0/25", "excluded"),
    ("192.0.2.0/25,!192.0.2.128/25", "192.0.2.0/25", None),
    ("192.0.2.0/24", SUPERNET_23, "out_of_scope"),
    ("192.0.2.0/25,192.0.2.128/25", "192.0.2.0/24", "out_of_scope"),  # one single entry
])
def test_ip_and_cidr_matching(iso, scope_value, value, expected):
    assert refusal(snapshot(iso, scope_value), value) == expected


def test_cidr_cap_boundary_in_the_target_grammar():
    with pytest.raises(targets.TargetError) as caught:
        targets.normalize_target("198.18.0.0/15", cidr_cap=16)
    assert caught.value.code == "cidr_too_large"
    assert targets.normalize_target("198.18.0.0/16", cidr_cap=16).normalized == "198.18.0.0/16"


# --- F.4 tables ----------------------------------------------------------------------------

def test_always_deny_table_is_pinned():
    assert [str(n) for n in scope.ALWAYS_DENY_V4] == [
        "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "100.100.100.200/32",
        "168.63.129.16/32", "224.0.0.0/4", "240.0.0.0/4"]
    assert [str(n) for n in scope.ALWAYS_DENY_V6] == [
        "::/96", "fe80::/10", "fec0::/10", "ff00::/8", "fd00:ec2::/32"]


def test_non_public_table_is_pinned():
    assert scope.REGISTRY_DATE == "2025-10-09"
    assert [str(n) for n in scope.NON_PUBLIC_V4] == [
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
        "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
        "255.255.255.255/32", "224.0.0.0/4", "100.100.100.200/32", "168.63.129.16/32"]
    assert [str(n) for n in scope.PUBLIC_EXCEPTIONS_V4] == ["192.0.0.9/32", "192.0.0.10/32"]
    assert list(scope.NON_PUBLIC_V6) == [ipaddress.IPv6Network(n) for n in (
        "::/96", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64", "100:0:0:1::/64",
        "2001::/23", "2001:db8::/32", "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10",
        "fec0::/10", "ff00::/8", "fd00:ec2::/32")]
    assert list(scope.PUBLIC_EXCEPTIONS_V6) == [ipaddress.IPv6Network(n) for n in (
        "2001:1::1/128", "2001:1::2/128", "2001:1::3/128", "2001:3::/32",
        "2001:4:112::/48", "2001:20::/28", "2001:30::/28")]


@pytest.mark.parametrize(("address", "public"), [
    ("192.0.2.10", False), ("198.51.100.7", False), ("203.0.113.9", False),
    ("10.20.30.40", False), ("172.16.0.1", False), ("192.168.1.1", False),
    ("100.64.0.1", False), ("169.254.169.254", False), ("127.0.0.1", False),
    ("198.18.0.1", False), ("192.88.99.1", False), ("255.255.255.255", False),
    ("224.0.0.1", False), ("100.100.100.200", False), ("168.63.129.16", False),
    ("192.0.0.8", False), ("192.0.0.9", True), ("192.0.0.10", True), (PUBLIC_V4, True),
    ("::1", False), ("::ffff:c000:20a", False), ("64:ff9b:1::1", False), ("fc00::1", False),
    ("fe80::1", False), ("fec0::1", False), ("ff02::1", False), ("fd00:ec2::254", False),
    ("2001:db8::1", False), ("3fff::1", False), ("5f00::1", False), ("100::1", False),
    ("2001:2::1", False), ("2001:1::1", True), ("2001:1::4", False), ("2001:3::1", True),
    ("2001:4:112::1", True), ("2001:20::1", True), ("2001:30::1", True),
    ("64:ff9b::a14:1e28", True),  # judged through its embedded address, not as itself
])
def test_is_public_follows_the_pinned_table(address, public):
    assert scope.is_public(ipaddress.ip_address(address)) is public


def test_is_public_never_uses_the_ipaddress_flags(monkeypatch):
    def boom(self):  # pragma: no cover - must never be called
        raise AssertionError("is_global/is_private must not decide R3")

    for cls in (ipaddress.IPv4Address, ipaddress.IPv6Address):
        monkeypatch.setattr(cls, "is_global", property(boom))
        monkeypatch.setattr(cls, "is_private", property(boom))
    assert scope.is_public(ipaddress.ip_address("10.20.30.40")) is False
    assert scope.is_public(ipaddress.ip_address(PUBLIC_V4)) is True


@pytest.mark.parametrize(("address", "embedded"), [
    ("::ffff:a9fe:a9fe", ["169.254.169.254"]),
    ("::a9fe:a9fe", ["169.254.169.254"]),
    ("::", []),
    ("::1", []),
    ("64:ff9b::a14:1e28", ["10.20.30.40"]),
    ("64:ff9b:1::c000:20a", ["192.0.2.10"]),
    ("2002:a9fe:a9fe::1", ["169.254.169.254"]),
    ("2001:0:c000:20a::3f57:fef5", ["192.0.2.10", "192.168.1.10"]),
    ("2001:db8::1", []),
    ("fe80::1", []),
])
def test_embedded_ipv4(address, embedded):
    found = scope.embedded_ipv4(ipaddress.IPv6Address(address))
    assert [str(a) for a in found] == embedded


def test_embedded_ipv4_matches_the_stdlib_for_6to4_and_teredo():
    six = ipaddress.IPv6Address("2002:a9fe:a9fe::1")
    assert scope.embedded_ipv4(six) == (six.sixtofour,)
    teredo = ipaddress.IPv6Address("2001:0:c000:20a::3f57:fef5")
    assert scope.embedded_ipv4(teredo) == teredo.teredo


# --- F.4 always-deny literals and explicit listing ------------------------------------

@pytest.mark.parametrize("value", ["0.0.0.0", "127.0.0.1", "169.254.169.254", "169.254.170.2",
                                   "100.100.100.200", "168.63.129.16", "224.0.0.1",
                                   "239.255.255.250", "240.0.0.1", "255.255.255.255"])
def test_always_denied_literals_are_refused_unless_explicitly_listed(iso, value):
    broad = snapshot(iso, "0.0.0.0/8,127.0.0.0/8,169.254.0.0/16,100.64.0.0/10,"
                          f"{AZURE_16},224.0.0.0/8,239.0.0.0/8,240.0.0.0/8,255.0.0.0/8")
    expected = None if value.startswith(("0.", "127.", "169.254.", "224.", "239.", "240.",
                                         "255.")) else "always_denied"
    # Entries that lie entirely inside the deny set list the address explicitly; the
    # broad 100.64.0.0/10 and Azure /16 entries only overlap it (F.4.1).
    assert refusal(broad, value) == expected
    assert refusal(snapshot(iso, f"{value}"), value) is None
    assert refusal(snapshot(iso, "app.example"), value, allow_any=True) == "always_denied"
    assert refusal(snapshot(iso, f"app.example,{value}"), value, allow_any=True) is None


def test_explicit_listing_of_a_special_use_cidr(iso):
    snap = snapshot(iso, "169.254.10.0/24")
    assert refusal(snap, "169.254.10.0/24") is None
    assert refusal(snap, "169.254.10.7") is None
    snap = snapshot(iso, AZURE_16)  # overlaps the Azure /32 only
    assert refusal(snap, AZURE_24) == "always_denied"
    assert refusal(snap, AZURE_OTHER_24) is None
    snap = snapshot(iso, f"{AZURE_16},{AZURE}")
    assert refusal(snap, AZURE_24) is None
    snap = snapshot(iso, "100.64.0.0/10")  # 100.100.100.200 lies inside it
    assert refusal(snap, "100.100.100.0/24") == "always_denied"
    assert refusal(snap, "100.100.100.200") == "always_denied"


def test_cidr_overlapping_the_deny_set_under_the_lab_override(iso):
    snap = snapshot(iso)
    assert refusal(snap, "169.254.0.0/16", allow_any=True) == "always_denied"
    assert refusal(snap, "224.0.0.0/16", allow_any=True) == "always_denied"
    assert refusal(snap, "192.0.2.0/24", allow_any=True) is None


# --- F.5 DNS policy (resolver replaced by the dns fixture, O.2) -------------------------

@pytest.mark.parametrize(("answers", "expected"), [
    (["169.254.169.254"], "special_use_address"),
    (["64:ff9b::a9fe:a9fe"], "special_use_address"),
    (["::a9fe:a9fe"], "special_use_address"),
    (["fec0::1"], "special_use_address"),
    (["2002:a9fe:a9fe::1"], "special_use_address"),
    (["2001:0:a9fe:a9fe::1"], "special_use_address"),  # Teredo server address
    (["::ffff:7f00:1"], "special_use_address"),  # mapped answers are converted first
    (["::1"], "special_use_address"),
    (["fe80::1%eth0"], "special_use_address"),
    (["fd00:ec2::254"], "special_use_address"),
    (["::c000:20a"], "special_use_address"),  # IPv4-compatible form of a scope address
    (["10.20.30.40"], "private_address_not_in_scope"),
    (["64:ff9b::a14:1e28"], "private_address_not_in_scope"),
    (["2002:a14:1e28::1"], "private_address_not_in_scope"),
    (["fc00::5"], "private_address_not_in_scope"),
    (["2001:db8::5"], "private_address_not_in_scope"),
    (["203.0.113.10", "10.20.30.40"], "private_address_not_in_scope"),
    ([], "dns_unresolved"),
])
def test_strict_policy_refusals(iso, dns, answers, expected):
    snap = snapshot(iso, "app.example")
    iso.resolve("app.example", *answers, public=False)
    assert dns_refusal(snap, "app.example") == expected


def test_unknown_name_is_unresolved(iso):
    snap = snapshot(iso, "app.example")
    assert dns_refusal(snap, "app.example") == "dns_unresolved"
    check = scope.check_dns(snap, target("app.example"), policy="lenient", allow_any=False)
    assert check.warnings == ("dns_unresolved",) and check.resolved == ()


def test_private_answer_inside_a_scope_cidr_is_accepted(iso):
    snap = snapshot(iso, "app.example,10.20.30.0/24")
    iso.resolve("app.example", "10.20.30.40", public=False)
    check = scope.check_dns(snap, target("app.example"), policy="strict", allow_any=False)
    assert check.resolved == ("10.20.30.40",) and check.total == 1
    iso.resolve("app.example", "64:ff9b::a14:1e28", public=False)  # its NAT64 form
    assert dns_refusal(snap, "app.example") is None


def test_ipv6_entries_never_cover_embedded_ipv4_answers(iso):
    snap = snapshot(iso, "app.example,64:ff9b::/96")
    iso.resolve("app.example", "64:ff9b::a14:1e28", public=False)
    assert dns_refusal(snap, "app.example") == "private_address_not_in_scope"


def test_r4_binds_names_to_the_scope_ip_entries(iso):
    snap = snapshot(iso, "app.example,192.0.2.0/24")
    iso.resolve("app.example", "198.51.100.7")  # modeled as public: R3 passes
    assert dns_refusal(snap, "app.example") == "resolved_out_of_scope"
    iso.resolve("app.example", "192.0.2.10", public=False)
    assert dns_refusal(snap, "app.example") is None
    iso.resolve("app.example", "192.0.2.10", "198.51.100.7")
    assert dns_refusal(snap, "app.example") == "resolved_out_of_scope"


def test_domain_only_scope_trusts_public_answers(iso):
    snap = snapshot(iso, "app.example")
    iso.resolve("app.example", "203.0.113.10", "2001:20::5")
    check = scope.check_dns(snap, target("app.example"), policy="strict", allow_any=False)
    assert check.resolved == ("203.0.113.10", "2001:20::5")


def test_r2_exclusions_judge_both_forms(iso):
    snap = snapshot(iso, "app.example,!192.0.2.13")
    iso.resolve("app.example", "64:ff9b::c000:20d")
    assert dns_refusal(snap, "app.example") == "excluded"
    snap = snapshot(iso, "app.example,!2001:db8::/48")
    iso.resolve("app.example", "2001:db8::7")
    iso.public_addresses.add("2001:db8::7")
    assert dns_refusal(snap, "app.example") == "excluded"
    assert dns_refusal(snap, "app.example", policy="lenient") == "excluded"


def test_explicitly_listed_special_use_answer(iso):
    snap = snapshot(iso, "app.example,127.0.0.1")
    iso.resolve("app.example", "127.0.0.1", public=False)
    assert dns_refusal(snap, "app.example") is None
    iso.resolve("app.example", "64:ff9b::7f00:1", public=False)  # listed through its IPv4
    assert dns_refusal(snap, "app.example") is None
    snap = snapshot(iso, "app.example,::1")
    iso.resolve("app.example", "::1", public=False)
    assert dns_refusal(snap, "app.example") is None


def test_lenient_policy_applies_r1_and_r2_only(iso):
    snap = snapshot(iso, "app.example,192.0.2.0/24")
    iso.resolve("app.example", "10.20.30.40", public=False)
    assert dns_refusal(snap, "app.example", policy="lenient") is None
    iso.resolve("app.example", "198.51.100.7")
    assert dns_refusal(snap, "app.example", policy="lenient") is None
    iso.resolve("app.example", "169.254.169.254")
    assert dns_refusal(snap, "app.example", policy="lenient") == "special_use_address"


def test_lab_override_skips_r3_and_r4_but_not_r0_r1_r2(iso):
    snap = snapshot(iso, "app.example,192.0.2.0/24,!192.0.2.13")
    iso.resolve("app.example", "10.20.30.40", public=False)
    assert dns_refusal(snap, "app.example", allow_any=True) is None
    iso.resolve("app.example", "198.51.100.7")
    assert dns_refusal(snap, "app.example", allow_any=True) is None
    iso.resolve("app.example", "169.254.169.254")
    assert dns_refusal(snap, "app.example", allow_any=True) == "special_use_address"
    iso.resolve("app.example", "192.0.2.13", public=False)
    assert dns_refusal(snap, "app.example", allow_any=True) == "excluded"
    del iso.dns_table["app.example"]
    assert dns_refusal(snap, "app.example", allow_any=True) == "dns_unresolved"


def test_resolved_addresses_are_sorted_unique_capped_and_counted(iso):
    snap = snapshot(iso, "app.example")
    answers = [f"203.0.113.{i}" for i in range(100, 0, -1)] + ["203.0.113.5"]
    answers += [f"::ffff:203.0.113.{i}" for i in (1, 2)]
    iso.resolve("app.example", *answers)
    iso.public_addresses.update(str(ipaddress.ip_address(a).ipv4_mapped or a)
                                for a in answers if a.startswith("::"))
    check = scope.check_dns(snap, target("app.example"), policy="strict", allow_any=False)
    assert check.total == 100
    assert len(check.resolved) == scope.RESOLVED_MAX == 64
    assert list(check.resolved) == [f"203.0.113.{i}" for i in range(1, 65)]


def test_refusal_details_carry_resolved_and_offending_addresses(iso):
    snap = snapshot(iso, "app.example")
    iso.resolve("app.example", "203.0.113.10", "169.254.169.254")
    with pytest.raises(scope.ScopeRefusal) as caught:
        scope.check_dns(snap, target("app.example"), policy="strict", allow_any=False)
    details = caught.value.details
    assert details["resolved_addresses"] == ["169.254.169.254", "203.0.113.10"]
    assert details["offending_addresses"] == ["169.254.169.254"]
    assert details["resolved_addresses_total"] == 2
    assert details["target"] == "app.example" and details["scope_digest"] == snap.digest
    assert caught.value.code == "special_use_address"


def test_unparseable_answer_fails_closed_under_both_policies(iso, monkeypatch):
    snap = snapshot(iso, "app.example")
    monkeypatch.setattr(scope, "resolver", lambda host: ["not-an-address"])
    assert dns_refusal(snap, "app.example") == "dns_timeout"
    assert dns_refusal(snap, "app.example", policy="lenient") == "dns_timeout"


def test_resolver_failure_other_than_not_found_is_a_timeout(iso, monkeypatch):
    snap = snapshot(iso, "app.example")

    def broken(host):
        raise TimeoutError("SERVFAIL")

    monkeypatch.setattr(scope, "resolver", broken)
    assert dns_refusal(snap, "app.example") == "dns_timeout"
    assert dns_refusal(snap, "app.example", policy="lenient") == "dns_timeout"


def test_slow_lookup_times_out_and_a_full_pool_fails_at_once(iso, monkeypatch):
    snap = snapshot(iso, "app.example")
    release = threading.Event()
    calls: list[str] = []

    def slow(host):
        calls.append(host)
        release.wait(30)
        return ["203.0.113.10"]

    monkeypatch.setattr(scope, "resolver", slow)
    monkeypatch.setattr(scope, "DNS_TIMEOUT_SECONDS", 0.2)
    try:
        assert dns_refusal(snap, "app.example") == "dns_timeout"  # worker 1 stays busy
        assert dns_refusal(snap, "app.example") == "dns_timeout"  # worker 2 stays busy
        monkeypatch.setattr(scope, "DNS_TIMEOUT_SECONDS", 30.0)
        started = time.monotonic()
        assert dns_refusal(snap, "app.example") == "dns_timeout"  # pool full: no wait
        assert time.monotonic() - started < 5
        assert len(calls) == 2  # the third call never reached the resolver
    finally:
        release.set()
        for thread in threading.enumerate():
            if thread.name == "sn1per-mcp-dns":
                thread.join(10)
    iso.resolve("app.example", "203.0.113.10")
    monkeypatch.setattr(scope, "resolver", lambda host: ["203.0.113.10"])
    assert dns_refusal(snap, "app.example") is None  # both slots are free again


def test_the_system_resolver_is_replaced_in_tests():
    """O.2: the dns fixture replaced the resolver; the real one would trip Layer 1."""
    assert "fake_resolver" in scope.resolver.__qualname__


# --- F.8 rate limiter -----------------------------------------------------------------

def test_rate_limiter_window():
    now = [1000.0]
    limiter = scope.RateLimiter(clock=lambda: now[0])
    allowed = []
    for _ in range(7):  # one call per second
        allowed.append(limiter.allow())
        now[0] += 1.0
    assert allowed == [True] * 6 + [False]
    now[0] = 1059.9
    assert limiter.allow() is False  # the first call (t=1000) is still in the window
    now[0] = 1060.0
    assert limiter.allow() is True  # it left; one slot freed
    assert limiter.allow() is False  # the second call (t=1001) is still in the window
    assert (limiter.calls, limiter.window) == (6, 60.0)


# --- F.1 change tracking ----------------------------------------------------------------

def test_scope_tracker_baseline_and_changes():
    tracker = scope.ScopeTracker()
    with tracker.lock:
        assert tracker.pending_change("aaaa") == (False, "aaaa")
        assert tracker.pending_change("aaaa") == (False, "aaaa")
        assert tracker.pending_change("bbbb") == (True, "aaaa")
        tracker.commit("bbbb")
        assert tracker.pending_change(None) == (True, "bbbb")


def test_state_secure_file_reasons(iso):
    path = iso.tmp / "cfg"
    path.write_text("x")
    path.chmod(0o666)
    with pytest.raises(state.SecureFileError) as caught:
        state.read_secure_file(str(path), max_bytes=10, label="scope file")
    assert caught.value.reason == "file_writable" and caught.value.st is not None


@pytest.mark.parametrize(("raw", "shown"), [
    ("bad\u202eentry", "bad\\u202eentry"),
    ("x\x1b[31m", "x\\u001b[31m"),
    ("\udcff\udcfe", "\\udcff\\udcfe"),
    ("quo\"te\\", "quo\\\"te\\\\"),
])
def test_invalid_entries_are_shown_escaped(iso, raw, shown):
    snap = snapshot(iso, raw)
    assert snap.invalid[0]["entry"] == shown and snap.invalid[0]["entry"].isascii()
    other = snapshot(iso, raw + "x")
    assert other.digest != snap.digest  # the digest still uses the raw token


async def test_undecodable_scope_bytes_never_break_status(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.example,\udcff")
    payload, is_error = await support.call("sniper_status")
    assert not is_error
    assert payload["scope"]["invalid_entries"] == [{"entry": "\\udcff",
                                                    "reason": "invalid_target"}]
