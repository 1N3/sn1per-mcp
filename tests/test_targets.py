# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Target grammar, host filters and workspace names (contract E, H.4; O.5 P0-07, A-42).

Every row of the E.2 rejection table is a test here, plus the accepted
normalizations, the URL port rules and the discover argument-injection sinks.
"""

from __future__ import annotations

import pytest

from sniper_mcp import jobs, targets
from sniper_mcp.tools import status
from tests import support

CAP = 16

# E.2, row by row: (inputs, expected code).
E2_ROWS = [
    (["-oN/tmp/x", "-iL/etc/shadow", "-osniper", "-", "-d"], "invalid_target"),
    (["/", "/etc/passwd"], "invalid_target"),
    (["http://-o/etc/passwd"], "invalid_target"),
    (["app.example\n"], "invalid_target"),
    ([" app.example"], "invalid_target"),
    (["app.example;id", "$(id)", "`id`", "a&&b", "a|b"], "invalid_target"),
    (["app\u00ad.example", "app.example\U000E0041", "app.example\ufe0f"], "invalid_target"),
    (["*.app.example"], "invalid_target"),
    (["app.example:8443", "app.example\uff1a8443"], "invalid_target"),
    (["http://user:pass@app.example/", "http://@app.example/"], "invalid_target"),
    (["\uff0doN"], "invalid_target"),
    (["2001:db8::1", "2001:db8::/64", "http://[2001:db8::1]/"], "unsupported_target"),
    (["127.1", "1.2.3", "0x7f000001", "2130706433", "0177.0.0.1"], "non_canonical_ip"),
    (["127.0.0.0x1.", "0x7f.0.0.0x1.", "1.0x7f.",
      "\uff11\uff12\uff17\uff0e\uff10\uff0e\uff10\uff0e\uff10\uff58\uff11"],
     "non_canonical_ip"),
    (["app.0x7f", "app.123", "app.0x"], "invalid_target"),
    (["192.0.2.5/24"], "cidr_not_canonical"),
    (["198.18.0.0/15"], "cidr_too_large"),
    (["localhost", "foo.localhost", "metadata.google.internal"], "always_denied"),
    (["example.com", "www.example.org", "EXAMPLE.NET.", "example.com\u3002"], "always_denied"),
    (["a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "e" * 62], "target_too_long"),
    (["x" * 64 + ".example"], "invalid_target"),
    (["xn--zz", "XN--ZZ"], "invalid_target"),
    (["\u0430pp.example"], "mixed_script"),
    (["com.example.app"], "unsupported_target"),
    (["a" * 5000], "invalid_target"),
]
E2_CASES = [(value, code) for values, code in E2_ROWS for value in values]


@pytest.mark.parametrize(("value", "code"), E2_CASES, ids=[repr(v)[:40] for v, _ in E2_CASES])
def test_e2_rejection_rows(value, code):
    with pytest.raises(targets.TargetError) as caught:
        targets.normalize_target(value, cidr_cap=CAP)
    assert caught.value.code == code, (value, caught.value.message)


def test_the_254_character_case_is_exactly_254_and_253_is_accepted():
    long_name = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "e" * 62
    assert len(long_name) == 254
    accepted = targets.normalize_target(long_name[:-1], cidr_cap=CAP)
    assert len(accepted.normalized) == 253


@pytest.mark.parametrize(("value", "normalized", "target_type"), [
    ("APP.Example.", "app.example", targets.HOSTNAME),
    ("app.example\u3002", "app.example", targets.HOSTNAME),
    ("\uff11\uff19\uff12\uff0e\uff10\uff0e\uff12\uff0e\uff11\uff10", "192.0.2.10", targets.IPV4),
    ("M\u00fcnchen.example", "xn--mnchen-3ya.example", targets.HOSTNAME),
    ("xn--mnchen-3ya.example", "xn--mnchen-3ya.example", targets.HOSTNAME),
    ("192.0.2.10", "192.0.2.10", targets.IPV4),
    ("192.0.2.0/24", "192.0.2.0/24", targets.IPV4_CIDR),
    ("198.18.0.0/16", "198.18.0.0/16", targets.IPV4_CIDR),
    ("corp", "corp", targets.HOSTNAME),
    ("\u65e5\u672c\u3054.example", "xn--38jv62nb2a.example", targets.HOSTNAME),
])
def test_accepted_normalizations(value, normalized, target_type):
    result = targets.normalize_target(value, cidr_cap=CAP)
    assert (result.normalized, result.target_type) == (normalized, target_type)
    assert result.changed == (normalized != value)


def test_url_is_reduced_to_its_host_with_a_warning():
    result = targets.normalize_target("https://WWW.App.Example:443/login?x=1", cidr_cap=CAP)
    assert result.normalized == "www.app.example" and result.target_type == targets.HOSTNAME
    assert result.warnings == ("url_reduced_to_host",)
    assert (result.url_port, result.url_default_port) == (443, 443)
    plain = targets.normalize_target("http://app.example/", cidr_cap=CAP)
    assert plain.warnings == () and plain.url_port is None and plain.url_default_port == 80


def test_url_query_may_carry_punctuation_but_not_invisible_characters():
    ok = targets.normalize_target("https://app.example/?q=$(id)&x=1", cidr_cap=CAP)
    assert ok.normalized == "app.example"
    for value in ("https://app.example/?q=a\u200bb", "https://app.example/$(id)",
                  "HTTPS://app.example:0/", "https://app.example:99999/",
                  "https://app.example:x/", "http:///path"):
        with pytest.raises(targets.TargetError) as caught:
            targets.normalize_target(value, cidr_cap=CAP)
        assert caught.value.code == "invalid_target", value


def test_cidr_cap_boundary_and_canonical_hint():
    assert targets.normalize_target("198.18.0.0/16", cidr_cap=16).normalized == "198.18.0.0/16"
    with pytest.raises(targets.TargetError) as caught:
        targets.normalize_target("198.18.0.0/15", cidr_cap=16)
    assert caught.value.code == "cidr_too_large"
    with pytest.raises(targets.TargetError) as caught:
        targets.normalize_target("192.0.2.5/24", cidr_cap=16)
    assert caught.value.details == {"canonical": "192.0.2.0/24"}


def test_mixed_script_allows_one_script_and_the_cjk_groups():
    assert targets.normalize_target("\u0430\u0431\u0432.example", cidr_cap=CAP).normalized \
        .startswith("xn--")
    # Han with Hangul is one group; Hangul with Hiragana is not.
    targets.normalize_target("\u4e00\ud55c.example", cidr_cap=CAP)
    with pytest.raises(targets.TargetError) as caught:
        targets.normalize_target("\ud55c\u3042.example", cidr_cap=CAP)
    assert caught.value.code == "mixed_script"


# --- A-42 and the documentation placeholders (target side) -------------------------

@pytest.mark.parametrize("value", ["example.com", "www.example.org", "EXAMPLE.NET.",
                                   "deep.sub.example.net", "example.com\u3002"])
def test_example_domains_are_always_denied_as_targets(value):
    with pytest.raises(targets.TargetError) as caught:
        targets.normalize_target(value, cidr_cap=CAP)
    assert caught.value.code == "always_denied"


@pytest.mark.parametrize("value", ["notexample.com", "example.community", "app.example"])
def test_label_boundaries_of_the_deny_rule(value):
    assert targets.normalize_target(value, cidr_cap=CAP).normalized == value


def test_docs_placeholder_is_not_a_target_and_the_server_json_values_are():
    with pytest.raises(targets.TargetError) as caught:
        targets.normalize_target("<authorized-targets>", cidr_cap=CAP)
    assert caught.value.code == "invalid_target"
    assert targets.normalize_target("app.example", cidr_cap=CAP).normalized == "app.example"
    assert targets.normalize_target("192.0.2.0/24", cidr_cap=CAP).target_type == "cidr"


# --- H.4 host filters --------------------------------------------------------------

@pytest.mark.parametrize(("value", "normalized"), [
    ("example.com", "example.com"), ("WWW.Example.Org.", "www.example.org"),
    ("localhost", "localhost"), ("APP.Example", "app.example"), ("192.0.2.1", "192.0.2.1"),
    ("M\u00fcnchen.example", "xn--mnchen-3ya.example"),
])
def test_host_filter_accepts_names_and_ipv4(value, normalized):
    assert targets.normalize_host_filter(value) == normalized


@pytest.mark.parametrize("value", ["*.app.example", "app.example:80", "2001:db8::1", "127.1",
                                   "192.0.2.0/24", "http://app.example/", "a b", "",
                                   "x" * 254, "app..example"])
def test_host_filter_rejects_everything_else(value):
    with pytest.raises(targets.TargetError) as caught:
        targets.normalize_host_filter(value)
    assert caught.value.code == "invalid_argument"


async def test_host_filters_accept_example_domains_through_a_reader(iso):
    iso.copy_loot("se-11.x")
    payload, is_error = await support.call("get_findings", {"workspace": "app.example",
                                                            "host": "EXAMPLE.COM"})
    assert not is_error, payload
    assert payload["host"] == "example.com"
    payload, is_error = await support.call("get_findings", {"workspace": "app.example",
                                                            "host": "*.app.example"})
    assert is_error and payload["error"]["code"] == "invalid_argument"


# --- E.3 workspace names -----------------------------------------------------------

@pytest.mark.parametrize("name", ["a", "acme-2026q4", "app.example", "192.0.2.0-24", "A_b.C",
                                  "x" * 128])
def test_valid_workspace_names(name):
    assert targets.validate_workspace(name) == name


@pytest.mark.parametrize("name", ["", "-a", ".a", "_a", "a..b", "a.", "a/b", "a b", "a\n",
                                  "x" * 129, "\u00e4", "..", "a$b"])
def test_invalid_workspace_names(name):
    with pytest.raises(targets.TargetError) as caught:
        targets.validate_workspace(name)
    assert caught.value.code == "invalid_workspace"


@pytest.mark.parametrize(("normalized", "derived"), [
    ("192.0.2.0/24", "192.0.2.0-24"), ("app.example", "app.example"),
    ("192.0.2.10", "192.0.2.10"), ("xn--mnchen-3ya.example", "xn--mnchen-3ya.example"),
])
def test_workspace_derivation(normalized, derived):
    assert targets.derive_workspace(normalized) == derived


def test_workspace_derivation_too_long_asks_for_an_explicit_workspace():
    name = ("a" * 63 + ".") * 3 + "example"
    with pytest.raises(targets.TargetError) as caught:
        targets.derive_workspace(targets.normalize_target(name, cidr_cap=CAP).normalized)
    assert caught.value.code == "invalid_workspace"
    assert "explicit workspace" in caught.value.hint


# --- through sniper_scan: the stub records nothing ---------------------------------

@pytest.fixture(autouse=True)
def _fresh_jobs():
    status.clear_sudo_cache()
    yield
    jobs.terminate_all()
    jobs.JOBS.clear()


@pytest.mark.parametrize("target", ["-iL/etc/shadow", "-oN/tmp/x", "\uff0diL/etc/shadow",
                                    "-sn", "192.0.2.0/24 -iL/etc/shadow",
                                    "192.0.2.0/24;id"])
async def test_discover_sinks_refuse_argument_injection(iso, target):
    iso.setenv(SNIPER_MCP_SCOPE="192.0.2.0/24")
    payload, is_error = await support.call("sniper_scan", {"target": target,
                                                           "mode": "discover"})
    assert is_error and payload["error"]["code"] == "invalid_target", payload
    assert payload["error"]["retry"] == "never"
    assert iso.calls() == []


@pytest.mark.parametrize(("value", "code"), [(v, c) for v, c in E2_CASES if len(v) <= 2048])
async def test_e2_rows_through_sniper_scan_reach_nothing(iso, value, code):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test", SNIPER_MCP_ALLOW_ANY_TARGET="1",
               SNIPER_MCP_ALLOW_INTRUSIVE="1")
    payload, is_error = await support.call("sniper_scan", {"target": value})
    assert is_error and payload["error"]["code"] == code, payload
    assert iso.calls() == []


async def test_workspace_derivation_failure_through_sniper_scan(iso):
    name = ("a" * 63 + ".") * 3 + "scan.test"
    iso.setenv(SNIPER_MCP_SCOPE=name)
    payload, is_error = await support.call("sniper_scan", {"target": name})
    assert is_error and payload["error"]["code"] == "invalid_workspace"
    assert iso.calls() == []


async def test_url_target_is_reduced_and_echoed(iso):
    iso.setenv(SNIPER_MCP_SCOPE="www.app.scan.test")
    iso.resolve("www.app.scan.test", "203.0.113.10")
    payload, is_error = await support.call(
        "sniper_scan", {"target": "https://WWW.App.Scan.Test:443/login?x=1"})
    assert not is_error, payload
    jobs.JOBS[payload["job_id"]].process.wait(timeout=30)
    assert payload["target"] == "www.app.scan.test"
    assert payload["target_input"] == "https://WWW.App.Scan.Test:443/login?x=1"
    assert [w["code"] for w in payload["warnings"]] == ["url_reduced_to_host"]
    assert iso.calls("sniper")[-1] == [str(iso.cli_path), "-t", "www.app.scan.test", "-m",
                                       "stealth", "-w", "www.app.scan.test"]
