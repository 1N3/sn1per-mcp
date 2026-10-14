# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""sniper_scan, scan_status and cancel_scan through the stubs (H.6-H.8, F.9; O.3, O.5).

Every dispatch test runs the stub sudo and stub CLI and asserts the exact argv
they recorded (or that nothing ran). Hostname targets resolve only through the
fake DNS table of the isolation fixture (O.2).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import stat
import threading
import time

import mcp.types as mcp_types
import pytest

from sniper_mcp import edition, jobs, paths, proc, scope
from sniper_mcp.tools import status
from tests import support

CYRILLIC_A = "\u0430"
# The /23 around 192.0.2.0/24 reaches outside RFC 5737, so it is built at run time (P.5).
SUPERNET_23 = str(ipaddress.ip_network("192.0.2.0/24").supernet())


@pytest.fixture(autouse=True)
def _fresh_state(iso):
    status.clear_sudo_cache()
    iso.resolve("app.scan.test", "203.0.113.10")
    yield
    jobs.terminate_all()
    jobs.JOBS.clear()


@pytest.fixture
def fast_cancel(monkeypatch):
    monkeypatch.setattr(jobs, "CANCEL_TERM_GRACE_SECONDS", 1.0)
    monkeypatch.setattr(jobs, "CANCEL_POLL_SECONDS", 3.0)
    monkeypatch.setattr(jobs, "CANCEL_POLL_INTERVAL", 0.05)


@pytest.fixture
def lookups(monkeypatch):
    """Counts resolver calls (the fake DNS stays in charge of the answers)."""
    calls: list[str] = []
    fake = scope.resolver

    def counting(host):
        calls.append(host)
        return fake(host)

    monkeypatch.setattr(scope, "resolver", counting)
    return calls


def wait_for(job_id: str) -> None:
    jobs.JOBS[job_id].process.wait(timeout=30)


async def scan(**arguments) -> tuple[dict, bool]:
    return await support.call("sniper_scan", arguments)


def error_code(payload: dict) -> str:
    return payload["error"]["code"]


def nothing_ran(iso) -> bool:
    """No engine run: at most the sudo preflight (sudo -n -l) was called."""
    return iso.calls("sniper") == [] and all(argv[1:3] == ["-n", "-l"]
                                             for argv in iso.calls("sudo"))


def assert_dispatched(iso, target: str, mode: str, workspace: str | None = None) -> None:
    """O.3: the exact engine argv (normalized target, mode, derived or given workspace),
    run through the stub sudo front-end."""
    ws = workspace if workspace is not None else target.replace("/", "-")  # E.3
    expected = [str(iso.cli_path), "-t", target, "-m", mode, "-w", ws]
    assert iso.calls("sniper")[-1] == expected
    dispatched = [argv for argv in iso.calls("sudo") if argv[1:3] == ["-n", "--"]]
    assert dispatched and dispatched[-1] == [str(iso.sudo_path), "-n", "--", *expected]


def audit_records(iso, event: str | None = None) -> list[dict]:
    found = [json.loads(line) for line in iso.audit_log.read_text().splitlines() if line]
    return [r for r in found if event is None or r["event"] == event]


# --- INCIDENT rows (O.5) --------------------------------------------------------------------

async def test_incident_row_1_pro_edition_scan_reaches_only_the_stub(iso):
    iso.use_install("pro")
    iso.setenv(SNIPER_EDITION="pro", SNIPER_MCP_SCOPE="app.scan.test")
    payload, is_error = await scan(target="APP.Scan.Test")
    assert not is_error, payload
    wait_for(payload["job_id"])
    cli = str(iso.cli_path)
    expected = [cli, "-t", "app.scan.test", "-m", "stealth", "-w", "app.scan.test"]
    assert iso.calls("sudo") == [
        [str(iso.sudo_path), "-n", "-l", cli],
        [str(iso.sudo_path), "-n", "--", *expected],
    ]
    assert iso.calls("sniper") == [expected]
    assert payload["target"] == "app.scan.test" and payload["target_input"] == "APP.Scan.Test"
    assert payload["edition"] == "pro" and payload["status"] in ("launched", "exited_early")
    log = payload["log_path"]
    assert log == f"{iso.state_dir}/jobs/{payload['job_id']}.log"
    assert stat.S_IMODE(os.stat(log).st_mode) == 0o600


@pytest.mark.parametrize("target", ["example.com", "www.example.org", "EXAMPLE.NET.",
                                    "localhost", "metadata.google.internal"])
async def test_incident_row_2_always_denied_whatever_the_flags(iso, target):
    iso.setenv(SNIPER_MCP_SCOPE=f"{target},app.scan.test", SNIPER_MCP_ALLOW_ANY_TARGET="1",
               SNIPER_MCP_ALLOW_INTRUSIVE="1", SNIPER_MCP_ENABLE_DESTRUCTIVE="1",
               SNIPER_EDITION="enterprise", SNIPER_MCP_DNS_POLICY="lenient")
    payload, is_error = await scan(target=target, mode="normal")
    assert is_error and error_code(payload) == "always_denied"
    assert payload["error"]["retry"] == "never"
    assert iso.calls() == []


# --- F.2 rows end to end (O.5 P0-08 + GAP-07) ------------------------------------------

F2_ROWS = [
    # scope, target, mode, DNS answers (name -> addresses), answers public?, expected
    ("app.example", "notapp.example", "stealth", {}, True, "out_of_scope"),
    ("app.example", "evil-app.example", "stealth", {}, True, "out_of_scope"),
    ("app.example", "APP.Example.", "stealth", {"app.example": ["203.0.113.20"]}, True, None),
    ("app.example", "www.app.example", "stealth", {"www.app.example": ["203.0.113.21"]}, True,
     None),
    ("*.app.example", "app.example", "stealth", {"app.example": ["203.0.113.20"]}, True,
     "out_of_scope"),
    ("m\u00fcnchen.example", "xn--mnchen-3ya.example", "stealth",
     {"xn--mnchen-3ya.example": ["203.0.113.22"]}, True, None),
    ("xn--mnchen-3ya.example", "M\u00fcnchen.example", "stealth",
     {"xn--mnchen-3ya.example": ["203.0.113.22"]}, True, None),
    ("app.example", "a" + CYRILLIC_A + "pp.example", "stealth", {}, True, "mixed_script"),
    ("app.example,!dev.app.example", "api.dev.app.example", "stealth",
     {"api.dev.app.example": ["203.0.113.23"]}, True, "excluded"),
    ("corp", "corp", "stealth", {"corp": ["203.0.113.24"]}, True, None),
    ("corp", "app.corp", "stealth", {"app.corp": ["203.0.113.25"]}, True, "out_of_scope"),
    ("*.corp", "app.corp", "stealth", {"app.corp": ["203.0.113.25"]}, True, "scope_invalid"),
    ("example.com", "app.example", "stealth", {"app.example": ["203.0.113.20"]}, True,
     "scope_invalid"),
    ("::ffff:0:0/96", "192.0.2.10", "stealth", {}, True, "scope_invalid"),
    ("192.0.2.0/24", "192.0.2.77", "stealth", {}, True, None),
    ("192.0.2.0/24", "192.0.2.0/25", "discover", {}, True, None),
    ("192.0.2.0/24,!192.0.2.64/26", "192.0.2.0/24", "discover", {}, True, "excluded"),
    ("192.0.2.0/24", SUPERNET_23, "discover", {}, True, "out_of_scope"),
    ("app.example", "app.example", "stealth", {"app.example": ["169.254.169.254"]}, False,
     "special_use_address"),
    ("app.example", "app.example", "stealth", {"app.example": ["64:ff9b::a9fe:a9fe"]}, False,
     "special_use_address"),
    ("app.example", "app.example", "stealth", {"app.example": ["::a9fe:a9fe"]}, False,
     "special_use_address"),
    ("app.example", "app.example", "stealth", {"app.example": ["fec0::1"]}, False,
     "special_use_address"),
    ("app.example", "app.example", "stealth", {"app.example": ["2002:a9fe:a9fe::1"]}, False,
     "special_use_address"),
    ("app.example", "app.example", "stealth", {"app.example": ["10.20.30.40"]}, False,
     "private_address_not_in_scope"),
    ("app.example", "app.example", "stealth", {"app.example": ["64:ff9b::a14:1e28"]}, False,
     "private_address_not_in_scope"),
    ("app.example,10.20.30.0/24", "app.example", "stealth",
     {"app.example": ["10.20.30.40"]}, False, None),
    ("app.example,192.0.2.0/24", "app.example", "stealth",
     {"app.example": ["198.51.100.7"]}, True, "resolved_out_of_scope"),
    ("", "app.example", "stealth", {"app.example": ["203.0.113.20"]}, True,
     "scope_not_configured"),
    ("app.example,bad..app.example", "app.example", "stealth",
     {"app.example": ["203.0.113.20"]}, True, "scope_invalid"),
    ("<authorized-targets>", "app.example", "stealth", {"app.example": ["203.0.113.20"]},
     True, "scope_invalid"),
]


# Accepted F.2 targets whose normalized form differs from the input.
F2_NORMALIZED = {"APP.Example.": "app.example", "M\u00fcnchen.example": "xn--mnchen-3ya.example"}


@pytest.mark.parametrize(("scope_value", "target", "mode", "answers", "public", "expected"),
                         F2_ROWS, ids=[f"{r[0] or 'empty'}->{r[1]}" for r in F2_ROWS])
async def test_f2_rows_through_sniper_scan(iso, scope_value, target, mode, answers, public,
                                           expected):
    if scope_value:
        iso.setenv(SNIPER_MCP_SCOPE=scope_value)
    for name, addresses in answers.items():
        iso.resolve(name, *addresses, public=public)
    payload, is_error = await scan(target=target, mode=mode)
    if expected is None:
        assert not is_error, payload
        wait_for(payload["job_id"])
        normalized = F2_NORMALIZED.get(target, target)
        assert payload["target"] == normalized
        assert_dispatched(iso, normalized, mode)
    else:
        assert is_error and error_code(payload) == expected, payload
        assert payload["error"]["retry"] == "never"
        assert nothing_ran(iso)


async def test_dns_refusal_details_list_resolved_and_offending_addresses(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.example")
    iso.resolve("app.example", "203.0.113.30", "169.254.169.254")
    payload, _ = await scan(target="app.example")
    details = payload["error"]["details"]
    assert details["resolved_addresses"] == ["169.254.169.254", "203.0.113.30"]
    assert details["offending_addresses"] == ["169.254.169.254"]
    assert details["target"] == "app.example" and details["target_type"] == "hostname"
    # F.7: a count and a digest, never the scope entries themselves.
    assert set(details) == {"target", "target_type", "scope_entries", "scope_digest",
                            "resolved_addresses", "resolved_addresses_total",
                            "offending_addresses"}
    assert details["scope_entries"] == 1 and details["resolved_addresses_total"] == 2


async def test_resolved_addresses_are_capped_at_64_in_the_result(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    iso.resolve("app.scan.test", *[f"203.0.113.{i}" for i in range(1, 101)])
    payload, is_error = await scan(target="app.scan.test")
    assert not is_error, payload
    wait_for(payload["job_id"])
    assert len(payload["scope"]["resolved_addresses"]) == 64
    assert payload["scope"]["resolved_addresses_total"] == 100
    request = audit_records(iso, "scan_request")[-1]
    assert len(request["resolved_addresses"]) == 64
    assert request["resolved_addresses_total"] == 100


@pytest.mark.parametrize("target", ["127.0.0.1", "169.254.169.254", "0.0.0.0", "224.0.0.1",
                                    "100.100.100.200", "168.63.129.16"])
async def test_special_use_literals_need_an_explicit_listing(iso, target):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test", SNIPER_MCP_ALLOW_ANY_TARGET="1")
    payload, is_error = await scan(target=target)
    assert is_error and error_code(payload) == "always_denied", payload
    assert iso.calls() == []
    iso.setenv(SNIPER_MCP_SCOPE=target, SNIPER_MCP_ALLOW_ANY_TARGET="0")
    payload, is_error = await scan(target=target)  # explicitly listed (F.4.1)
    assert not is_error, payload
    wait_for(payload["job_id"])
    assert_dispatched(iso, target, "stealth")


# --- F.6 lab override -----------------------------------------------------------------

async def test_lab_override_skips_membership_and_warns(iso):
    iso.setenv(SNIPER_MCP_ALLOW_ANY_TARGET="1")
    iso.resolve("other.scan.test", "10.20.30.41", public=False)  # R3 skipped
    payload, is_error = await scan(target="other.scan.test")
    assert not is_error, payload
    wait_for(payload["job_id"])
    assert payload["scope"]["allow_any_target"] is True
    assert payload["scope"]["matched_entry"] is None
    assert [w["code"] for w in payload["warnings"]] == ["allow_any_target"]
    request = audit_records(iso, "scan_request")[-1]
    assert request["allow_any_target"] is True and request["decision"] == "accepted"


ACTION_EVENTS = ("scan_request", "scan_exit", "cancel_request", "delete_request",
                 "export_request")


async def test_lab_override_is_on_every_action_line(iso, fast_cancel):
    """F.6 + G.3: every action line of a process running with the overrides says so,
    including cancels, finishes, deletes and exports of jobs launched without them."""
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test", SNIPER_MCP_ENABLE_DESTRUCTIVE="1")
    iso.make_workspace("acme-2026q4", {"notes.txt": "keep\n"})
    iso.resolve("other.scan.test", "203.0.113.11")
    iso.set_knobs(sleep=30)
    payload, is_error = await scan(target="app.scan.test")  # launched without the overrides
    assert not is_error, payload
    launched_without = len(audit_records(iso))
    iso.setenv(SNIPER_MCP_ALLOW_ANY_TARGET="1", SNIPER_MCP_ALLOW_INTRUSIVE="1")
    body, is_error = await support.call("cancel_scan", {"job_id": payload["job_id"]})
    assert not is_error and body["state"] == "cancelled", body
    body, is_error = await support.call("cancel_scan", {"job_id": "0123456789abcdef"})
    assert is_error and error_code(body) == "job_not_found"
    iso.set_knobs(files=["scans/stub-output.txt"])  # the next scan succeeds at once
    payload, is_error = await scan(target="other.scan.test")  # membership skipped (F.6)
    assert not is_error, payload
    wait_for(payload["job_id"])
    body, is_error = await support.call("delete_workspace",
                                        {"workspace": "acme-2026q4", "confirm": False})
    assert is_error and error_code(body) == "confirmation_required"
    body, is_error = await support.call("export_workspace", {"workspace": "acme-2026q4"})
    assert is_error and error_code(body) == "elicitation_unsupported"
    body, is_error = await support.call("export_workspace", {"workspace": "acme-2026q4"},
                                        **support.Elicitation("decline").kwargs())
    assert not is_error and body["exported"] is False, body
    body, is_error = await support.call("export_workspace", {"workspace": "acme-2026q4"},
                                        **support.Elicitation("accept", "acme-2026q4").kwargs())
    assert not is_error, body
    body, is_error = await support.call("delete_workspace",
                                        {"workspace": "acme-2026q4", "confirm": True},
                                        **support.Elicitation("accept", "acme-2026q4").kwargs())
    assert not is_error, body

    records = audit_records(iso)
    before = [r for r in records[:launched_without] if r["event"] in ACTION_EVENTS]
    assert [(r["event"], r["allow_any_target"], r["allow_intrusive"]) for r in before] == [
        ("scan_request", False, False)]
    after = [r for r in records[launched_without:] if r["event"] in ACTION_EVENTS]
    seen = {(r["event"], r["decision"]) for r in after}
    assert seen == {("cancel_request", "accepted"), ("cancel_request", "completed"),
                    ("cancel_request", "refused"), ("scan_exit", "failed"),
                    ("scan_request", "accepted"), ("scan_exit", "completed"),
                    ("delete_request", "refused"), ("delete_request", "accepted"),
                    ("delete_request", "completed"), ("export_request", "refused"),
                    ("export_request", "declined"), ("export_request", "accepted"),
                    ("export_request", "completed")}
    for record in after:
        assert record["allow_any_target"] is True, record
        assert record["allow_intrusive"] is True, record


async def test_without_overrides_every_action_line_has_false_not_null(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test", SNIPER_MCP_ENABLE_DESTRUCTIVE="1")
    iso.make_workspace("acme-2026q4", {"notes.txt": "keep\n"})
    payload, is_error = await scan(target="app.scan.test")
    assert not is_error, payload
    wait_for(payload["job_id"])
    await support.call("cancel_scan", {"job_id": payload["job_id"]})
    await support.call("cancel_scan", {"job_id": "0123456789abcdef"})
    await support.call("delete_workspace", {"workspace": "acme-2026q4", "confirm": False})
    await support.call("export_workspace", {"workspace": "acme-2026q4"})
    records = [r for r in audit_records(iso) if r["event"] in ACTION_EVENTS]
    assert {r["event"] for r in records} == set(ACTION_EVENTS)
    for record in records:
        assert record["allow_any_target"] is False and record["allow_intrusive"] is False


async def test_lab_override_keeps_exclusions_and_r0(iso):
    iso.setenv(SNIPER_MCP_ALLOW_ANY_TARGET="1", SNIPER_MCP_SCOPE="app.scan.test,!bad.scan.test")
    payload, _ = await scan(target="bad.scan.test")
    assert error_code(payload) == "excluded"
    payload, _ = await scan(target="nxdomain.scan.test")
    assert error_code(payload) == "dns_unresolved"


async def test_lenient_policy_warns_on_an_unresolved_name(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test", SNIPER_MCP_DNS_POLICY="lenient")
    del iso.dns_table["app.scan.test"]
    payload, is_error = await scan(target="app.scan.test")
    assert not is_error, payload
    wait_for(payload["job_id"])
    assert [w["code"] for w in payload["warnings"]] == ["dns_unresolved"]
    assert payload["scope"]["resolved_addresses"] == []
    assert payload["scope"]["dns_policy"] == "lenient"


async def test_writable_scope_file_warns_in_every_scan_result(iso):
    path = iso.tmp / "scope"
    path.write_text("app.scan.test\n")
    path.chmod(0o600)
    iso.setenv(SNIPER_MCP_SCOPE_FILE=str(path))
    payload, is_error = await scan(target="app.scan.test")
    assert not is_error, payload
    wait_for(payload["job_id"])
    assert "scope_file_writable_by_server_user" in [w["code"] for w in payload["warnings"]]


# --- F.8 rate limit, concurrency, the scan lock ----------------------------------------

async def test_seventh_call_is_rate_limited_without_a_lookup(iso, lookups):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    results = []
    async with support.session() as client:
        for _ in range(7):
            result = await client.call_tool("sniper_scan", {"target": "app.scan.test"})
            results.append(result.structuredContent)
    assert [("error" in r) for r in results] == [False] * 6 + [True]
    assert results[-1]["error"]["code"] == "rate_limited"
    assert results[-1]["error"]["retry"] == "later"
    assert len(lookups) == 6
    refused = audit_records(iso, "scan_request")[-1]
    assert refused["decision"] == "refused" and refused["reason_code"] == "rate_limited"


async def test_calls_refused_after_the_scope_step_still_count(iso):
    iso.setenv(SNIPER_MCP_SCOPE="192.0.2.10", SNIPER_NEEDS_SUDO="false")
    async with support.session() as client:
        codes = []
        for _ in range(7):
            result = await client.call_tool("sniper_scan", {"target": "192.0.2.10"})
            codes.append(result.structuredContent["error"]["code"])
        out = await client.call_tool("sniper_scan", {"target": "198.51.100.7"})
    assert codes == ["not_root"] * 6 + ["rate_limited"]
    assert out.structuredContent["error"]["code"] == "out_of_scope"  # scope comes first


async def test_concurrency_limit_and_target_busy_come_before_any_lookup(iso, lookups):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test,other.scan.test",
               SNIPER_MCP_MAX_CONCURRENT_SCANS="1")
    iso.resolve("other.scan.test", "203.0.113.11")
    iso.set_knobs(sleep=30)
    first, _ = await scan(target="app.scan.test")
    assert first["status"] == "launched"
    payload, _ = await scan(target="other.scan.test")
    assert error_code(payload) == "concurrency_limit" and payload["error"]["retry"] == "later"
    assert payload["error"]["details"] == {"running": 1, "max_concurrent": 1}
    iso.setenv(SNIPER_MCP_MAX_CONCURRENT_SCANS="2")
    payload, _ = await scan(target="APP.scan.test")
    assert error_code(payload) == "target_busy"
    assert payload["error"]["details"]["job_ids"] == [first["job_id"]]
    assert lookups == ["app.scan.test"]  # only the launched scan resolved its name
    assert len(iso.calls("sniper")) == 1


async def test_two_servers_racing_for_the_last_slot_launch_one_scan(iso, monkeypatch):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test,other.scan.test",
               SNIPER_MCP_MAX_CONCURRENT_SCANS="1")
    iso.resolve("other.scan.test", "203.0.113.11")
    iso.set_knobs(sleep=30)
    fake = scope.resolver
    inside = threading.Barrier(2, timeout=2)

    def slow(host):
        try:
            inside.wait()  # never satisfied: only one lookup runs at a time under the lock
        except threading.BrokenBarrierError:
            pass
        return fake(host)

    monkeypatch.setattr(scope, "resolver", slow)
    monkeypatch.setattr(scope, "DNS_TIMEOUT_SECONDS", 10.0)

    async def one(target):
        async with support.session() as client:  # one server process each
            result = await client.call_tool("sniper_scan", {"target": target})
            return result.structuredContent

    first, second = await asyncio.gather(one("app.scan.test"), one("other.scan.test"))
    outcomes = sorted(["launched" if "job_id" in r else r["error"]["code"]
                       for r in (first, second)])
    assert outcomes == ["concurrency_limit", "launched"]
    assert len(iso.calls("sniper")) == 1


async def test_a_held_scan_lock_is_a_concurrency_refusal(iso, monkeypatch):
    import fcntl

    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    monkeypatch.setattr(jobs, "SCAN_LOCK_WAIT_SECONDS", 0.3)
    async with support.session() as client:
        lock_path = iso.state_dir / "scan.lock"
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            result = await client.call_tool("sniper_scan", {"target": "app.scan.test"})
        finally:
            os.close(fd)
    assert result.structuredContent["error"]["code"] == "concurrency_limit"
    assert nothing_ran(iso)


async def test_full_dns_pool_refuses_at_once(iso, monkeypatch):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    release = threading.Event()
    calls: list[str] = []

    def hanging(host):
        calls.append(host)
        release.wait(60)
        return []

    monkeypatch.setattr(scope, "resolver", hanging)
    timeout = 0.3
    monkeypatch.setattr(scope, "DNS_TIMEOUT_SECONDS", timeout)
    try:
        for _ in range(2):  # both workers stay busy
            payload, _ = await scan(target="app.scan.test")
            assert error_code(payload) == "dns_timeout"
        assert len(calls) == 2
        # A full pool must refuse without waiting: a long timeout would show up here.
        monkeypatch.setattr(scope, "DNS_TIMEOUT_SECONDS", 30.0)
        started = time.monotonic()
        payload, _ = await scan(target="app.scan.test")
        assert error_code(payload) == "dns_timeout" and payload["error"]["retry"] == "later"
        assert time.monotonic() - started < 5
        assert len(calls) == 2  # the third lookup never reached the resolver
        details = payload["error"]["details"]
        assert details["resolved_addresses"] == [] and details["offending_addresses"] == []
    finally:
        release.set()
        for thread in threading.enumerate():
            if thread.name == "sn1per-mcp-dns":
                thread.join(10)
    assert nothing_ran(iso)


# --- F.9 order ------------------------------------------------------------------------------

async def test_check_order_disabled_and_detection_come_first(iso):
    iso.setenv(SNIPER_SCAN_ENABLED="false", SNIPER_BIN=str(iso.tmp / "absent"))
    payload, _ = await scan(target="-oN/tmp/x")
    assert error_code(payload) == "scan_disabled"
    iso.setenv(SNIPER_SCAN_ENABLED="true")
    payload, _ = await scan(target="-oN/tmp/x")
    assert error_code(payload) == "cli_not_found"


async def test_check_order_target_mode_workspace_then_scope(iso):
    payload, _ = await scan(target="-oN/tmp/x", mode="discover")
    assert error_code(payload) == "invalid_target"
    payload, _ = await scan(target="app.scan.test", mode="discover")
    assert error_code(payload) == "target_type_not_supported_for_mode"
    payload, _ = await scan(target="app.scan.test", workspace="a..b")
    assert error_code(payload) == "invalid_workspace"
    payload, _ = await scan(target="app.scan.test")
    assert error_code(payload) == "scope_not_configured"


async def test_check_order_state_dir_before_privilege_before_engine_path(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test", SNIPER_BIN=str(iso.cli_path))
    iso.set_knobs(sudo_list_exit=1)
    (iso.bin_dir / "sniper").unlink()  # the engine PATH check would fail too
    async with support.session() as client:
        os.rename(iso.state_dir / "jobs", iso.tmp / "jobs-moved")
        (iso.state_dir / "jobs").symlink_to(iso.tmp)
        first = await client.call_tool("sniper_scan", {"target": "app.scan.test"})
        (iso.state_dir / "jobs").unlink()
        os.rename(iso.tmp / "jobs-moved", iso.state_dir / "jobs")
        second = await client.call_tool("sniper_scan", {"target": "app.scan.test"})
        iso.set_knobs()
        status.clear_sudo_cache()
        third = await client.call_tool("sniper_scan", {"target": "app.scan.test"})
    assert first.structuredContent["error"]["code"] == "state_dir_insecure"
    assert second.structuredContent["error"]["code"] == "sudo_not_configured"
    assert third.structuredContent["error"]["code"] == "engine_path_missing"
    assert nothing_ran(iso)


async def test_engine_path_before_the_concurrency_cap(iso):
    from sniper_mcp import edition

    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test,other.scan.test",
               SNIPER_MCP_MAX_CONCURRENT_SCANS="1", SNIPER_BIN=str(iso.cli_path))
    iso.resolve("other.scan.test", "203.0.113.11")
    iso.set_knobs(sleep=30)
    first, _ = await scan(target="app.scan.test")
    assert first["status"] == "launched"
    (iso.bin_dir / "sniper").unlink()
    edition.clear_cache()  # detection is cached for 30 seconds (C.2)
    payload, _ = await scan(target="other.scan.test")
    assert error_code(payload) == "engine_path_missing"


# --- every outcome is audited (G.2) -----------------------------------------------------------

async def test_refusals_are_audited_with_their_code(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    for target, code in (("-oN/tmp/x", "invalid_target"), ("other.scan.test", "out_of_scope"),
                         ("nx.app.scan.test", "dns_unresolved")):
        payload, _ = await scan(target=target)
        assert error_code(payload) == code
    found = audit_records(iso, "scan_request")
    assert [(r["decision"], r["reason_code"]) for r in found] == [
        ("refused", "invalid_target"), ("refused", "out_of_scope"),
        ("refused", "dns_unresolved")]
    assert found[0]["target"] is None and found[0]["target_input"] == "-oN/tmp/x"
    assert found[2]["resolved_addresses"] == [] and found[2]["argv"] is None


async def test_launch_failure_is_audited_with_a_scan_exit_line(iso, monkeypatch):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")

    def broken(argv, *, log_fd, home):
        raise proc.LaunchError("could not start", cause="PermissionError")

    monkeypatch.setattr(proc, "spawn_detached", broken)
    monkeypatch.setattr(proc, "spawn_with_terminal", broken)  # the non-root launch (L.6)
    payload, is_error = await scan(target="app.scan.test")
    assert is_error and error_code(payload) == "launch_failed"
    assert payload["error"]["details"]["cause"] == "PermissionError"
    job_id = payload["error"]["details"]["job_id"]
    request, = audit_records(iso, "scan_request")
    exit_line, = audit_records(iso, "scan_exit")
    assert request["decision"] == "accepted" and request["job_id"] == job_id
    assert exit_line["job_id"] == job_id and exit_line["reason_code"] == "launch_failed"
    assert exit_line["result"]["state_reason"] == "launch_failed"
    assert exit_line["argv"] is None
    assert not os.path.exists(iso.state_dir / "jobs" / f"{job_id}.log")


# --- F.9 step 16: the early-exit wait ----------------------------------------------------------

async def test_a_scan_that_finishes_at_once_is_exited_early(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    iso.set_knobs(stdout="stub scan done", files=["scans/out.txt"])
    payload, is_error = await scan(target="app.scan.test")
    assert not is_error, payload
    assert payload["status"] == "exited_early"
    early = payload["early_exit"]
    assert (early["state"], early["state_reason"], early["exit_code"]) == ("succeeded", None, 0)
    assert early["untrusted_content"]["notice"].startswith("UNTRUSTED DATA")
    assert early["untrusted_content"]["log_tail"] == "stub scan done"
    assert [r["result"]["state"] for r in audit_records(iso, "scan_exit")] == ["succeeded"]


async def test_an_early_failure_is_scan_failed_early_with_a_redacted_tail(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    key = "AKIA" + "Q" * 16
    iso.set_knobs(stdout=f"\x1b[31mThis script must be run as root\x1b[0m\nkey {key}",
                  files=["scans/out.txt"])
    payload, is_error = await scan(target="app.scan.test")
    assert is_error and error_code(payload) == "scan_failed_early"
    details = payload["error"]["details"]
    assert details["state_reason"] == "not_root" and details["exit_code"] == 0
    tail = details["untrusted_content"]["log_tail"]
    assert "[REDACTED:aws-access-key-id]" in tail and key not in tail and "\x1b" not in tail
    assert payload["error"]["retry"] == "after_change"


async def test_a_running_scan_is_launched(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test", SNIPER_MCP_AUTHORIZATION_REF="SOW-9")
    iso.set_knobs(sleep=30)
    payload, is_error = await scan(target="app.scan.test")
    assert not is_error and payload["status"] == "launched" and "early_exit" not in payload
    assert list(payload)[:5] == ["schema_version", "tool", "status", "job_id", "edition"]
    assert payload["poll"] == {"tool": "scan_status",
                               "arguments": {"job_id": payload["job_id"]}}
    assert payload["authorization_ref"] == "SOW-9"
    assert payload["scope"] == {"matched_entry": "app.scan.test",
                                "resolved_addresses": ["203.0.113.10"],
                                "resolved_addresses_total": 1, "allow_any_target": False,
                                "dns_policy": "strict"}


# --- existing refusal paths -----------------------------------------------------------

async def test_normal_mode_is_not_offered(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    async with support.session() as client:
        result = await client.call_tool("sniper_scan", {"target": "app.scan.test",
                                                        "mode": "normal"})
    assert result.isError and iso.calls() == []


async def test_scope_not_configured_is_the_default(iso):
    payload, is_error = await scan(target="app.scan.test")
    assert is_error and error_code(payload) == "scope_not_configured"
    assert "SNIPER_MCP_SCOPE_FILE" in payload["error"]["hint"]
    assert iso.calls() == []


async def test_out_of_scope_is_refused_before_any_sudo_call(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    for target in ("notapp.scan.test", "scan.test", "app.scan.test.other.test", "192.0.2.10"):
        payload, is_error = await scan(target=target)
        assert is_error and error_code(payload) == "out_of_scope", target
        assert "Do not retry" in payload["error"]["hint"]
    assert iso.calls() == []


@pytest.mark.parametrize("target", ["-oN/tmp/x", "-d", "app.scan.test;id", "$(id)",
                                    "app.scan.test\n", " app.scan.test", "*.app.scan.test",
                                    "a b"])
async def test_invalid_targets(iso, target):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    payload, is_error = await scan(target=target)
    assert is_error and error_code(payload) == "invalid_target", target
    assert iso.calls() == []


async def test_port_is_refused_for_stealth(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    payload, is_error = await scan(target="app.scan.test", port=8443)
    assert is_error and error_code(payload) == "port_not_supported_for_mode"


async def test_scan_disabled(iso):
    iso.setenv(SNIPER_SCAN_ENABLED="false", SNIPER_MCP_SCOPE="app.scan.test")
    payload, is_error = await scan(target="app.scan.test")
    assert is_error and error_code(payload) == "scan_disabled"
    assert iso.calls() == []


async def test_cli_not_found_and_untrusted(iso, monkeypatch):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test", SNIPER_BIN=str(iso.tmp / "no-cli"))
    payload, _ = await scan(target="app.scan.test")
    assert error_code(payload) == "cli_not_found"
    iso.setenv(SNIPER_BIN=str(iso.cli_link))
    monkeypatch.setattr(paths, "TRUSTED_UID", os.geteuid() + 1)
    payload, _ = await scan(target="app.scan.test")
    assert error_code(payload) == "cli_untrusted"
    # Nothing on the way is TRUSTED_UID's now, so the hint names no path (C.2 step 1).
    assert payload["error"]["hint"] == edition.CLI_UNTRUSTED_HINT_NOT_SHOWN
    assert iso.calls() == []


async def test_sudo_not_configured_spawns_nothing(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    iso.set_knobs(sudo_password_required=True)
    payload, is_error = await scan(target="app.scan.test")
    assert is_error and error_code(payload) == "sudo_not_configured"
    assert "NOPASSWD: " + str(iso.cli_path) in payload["error"]["hint"]
    assert iso.calls("sniper") == []
    assert [argv[1:3] for argv in iso.calls("sudo")] == [["-n", "-l"]]


async def test_sudo_missing_and_untrusted(iso, monkeypatch):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    iso.sudo_path.chmod(0o777)
    payload, _ = await scan(target="app.scan.test")
    assert error_code(payload) == "sudo_untrusted"
    monkeypatch.setattr(paths, "SUDO", str(iso.tmp / "no-sudo"))
    iso.sudo_path.unlink()
    payload, is_error = await scan(target="app.scan.test")
    assert is_error and error_code(payload) == "sudo_missing"
    assert iso.calls() == []


async def test_not_root_when_sudo_is_switched_off(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test", SNIPER_NEEDS_SUDO="false")
    payload, _ = await scan(target="app.scan.test")
    assert error_code(payload) == "not_root"
    assert iso.calls() == []


async def test_state_dir_insecure(iso):
    iso.state_dir.mkdir()
    (iso.state_dir / "jobs").symlink_to(iso.tmp)
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    payload, _ = await scan(target="app.scan.test")
    assert error_code(payload) == "state_dir_insecure"
    assert iso.calls() == []


async def test_workspace_derivation_and_explicit_workspace(iso):
    iso.setenv(SNIPER_MCP_SCOPE="192.0.2.10")
    payload, is_error = await scan(target="192.0.2.10", workspace="acme-2026q4")
    assert not is_error, payload
    wait_for(payload["job_id"])
    assert_dispatched(iso, "192.0.2.10", "stealth", workspace="acme-2026q4")
    assert payload["scope"]["resolved_addresses"] == []
    assert payload["scope"]["resolved_addresses_total"] is None
    async with support.session() as client:
        bad = await client.call_tool("sniper_scan", {"target": "192.0.2.10",
                                                     "workspace": "../etc"})
    assert bad.isError


@pytest.mark.parametrize(("scope_value", "target", "mode"), [
    ("192.0.2.0/24,!192.0.2.64/26", "192.0.2.0/24", "discover"),
    ("192.0.2.200,!192.0.2.128/25", "192.0.2.200", "stealth"),
    ("192.0.2.0/24,!192.0.2.10", "192.0.2.0/24", "discover"),
    ("192.0.2.10,!192.0.2.10", "192.0.2.10", "stealth"),
    ("192.0.2.0/25,!192.0.2.0/24", "192.0.2.0/25", "discover"),
    ("127.0.0.1,!127.0.0.0/8", "127.0.0.1", "stealth"),
    ("app.example,!dev.app.example", "api.dev.app.example", "stealth"),
    ("app.scan.test,!scan.test", "app.scan.test", "stealth"),
    ("app.scan.test,!*.scan.test", "app.scan.test", "stealth"),
])
async def test_exclusions_always_win(iso, scope_value, target, mode):
    iso.setenv(SNIPER_MCP_SCOPE=scope_value)
    payload, is_error = await scan(target=target, mode=mode)
    assert is_error and error_code(payload) == "excluded", payload
    assert payload["error"]["retry"] == "never"
    assert iso.calls() == []


@pytest.mark.parametrize(("scope_value", "target", "mode"), [
    ("192.0.2.0/25,!192.0.2.128/25", "192.0.2.0/25", "discover"),
    ("192.0.2.200,!192.0.2.0/25", "192.0.2.200", "stealth"),
    ("192.0.2.10,!scan.test", "192.0.2.10", "stealth"),
    ("app.scan.test,!192.0.2.0/24", "app.scan.test", "stealth"),
])
async def test_non_overlapping_exclusions_do_not_refuse(iso, scope_value, target, mode):
    iso.setenv(SNIPER_MCP_SCOPE=scope_value)
    payload, is_error = await scan(target=target, mode=mode)
    assert not is_error, payload
    wait_for(payload["job_id"])
    assert_dispatched(iso, target, mode)


async def test_cidr_target_is_refused_for_a_single_host_mode(iso):
    iso.setenv(SNIPER_MCP_SCOPE="192.0.2.0/24")
    payload, is_error = await scan(target="192.0.2.0/24")
    assert is_error and error_code(payload) == "target_type_not_supported_for_mode"
    assert iso.calls() == []


@pytest.mark.parametrize("target", ["127.1", "2130706433", "0x7f.1", "0177.0.0.1",
                                    "192.0.2.010"])
async def test_numeric_non_dotted_quad_targets_are_non_canonical(iso, target):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    payload, is_error = await scan(target=target)
    assert is_error and error_code(payload) == "non_canonical_ip", payload
    assert iso.calls() == []


@pytest.mark.parametrize("scope_value", ["<authorized-targets>", "app.scan.test,example.com",
                                         "app.scan.test,bad..app.scan.test"])
async def test_invalid_scope_entries_refuse_every_scan(iso, scope_value):
    iso.setenv(SNIPER_MCP_SCOPE=scope_value)
    payload, is_error = await scan(target="app.scan.test")
    assert is_error and error_code(payload) == "scope_invalid", payload
    assert payload["error"]["details"]["invalid_entries"]
    assert iso.calls() == []


async def test_status_reports_ready_with_the_stub(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test", SNIPER_MCP_AUTHORIZATION_REF="SOW-2026-114")
    payload, is_error = await support.call("sniper_status")
    assert not is_error
    assert payload["scan"]["enabled"] is True and payload["scan"]["sudo"]["status"] == "ok"
    assert payload["paths"]["sniper_bin_realpath"] == str(iso.cli_path)
    assert payload["scope"]["authorization_ref"] == "SOW-2026-114"
    assert payload["notes"][0].startswith("Scope applies to the requested target")


# --- scan_status (H.7, L.4, O.5 P1-03) ------------------------------------------------------

async def test_scan_status_for_a_job_and_its_workspace(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    iso.set_knobs(sleep=30)
    async with support.session() as client:
        launched = await client.call_tool("sniper_scan", {"target": "app.scan.test"})
        job_id = launched.structuredContent["job_id"]
        running = await client.call_tool("scan_status", {"job_id": job_id,
                                                         "workspace": "app.scan.test"})
        jobs.terminate_all()
        finished = await client.call_tool("scan_status", {"job_id": job_id})
    body = running.structuredContent
    job = body["job"]
    assert job["state"] in ("starting", "running") and job["launched_by"] == "this_process"
    assert set(job) == {"job_id", "state", "state_reason", "exit_code", "target", "mode",
                        "port", "workspace", "started_at", "ended_at", "elapsed_seconds",
                        "pid", "launched_by", "log_path", "cancel", "summary"}
    workspace = body["workspace_status"]
    assert workspace["is_running"] is True and workspace["running_processes"] >= 1
    assert workspace["stale_markers"] is False and workspace["process_check"] == "ok"
    assert workspace["recent_jobs"] == [job_id]
    assert body["untrusted_content"]["notice"].startswith("UNTRUSTED DATA")
    assert body["redaction"] == {"enabled": True, "counts": {}}
    done = finished.structuredContent["job"]
    assert (done["state"], done["state_reason"]) == ("failed", "exit_status")
    assert done["exit_code"] == -9 and done["ended_at"] is not None
    assert done["summary"]["files_written"] == 0


async def test_scan_status_after_a_restart_reports_previous_process(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    iso.set_knobs(sleep=30)
    payload, _ = await scan(target="app.scan.test")
    child = jobs.JOBS.pop(payload["job_id"])
    try:
        status_payload, _ = await support.call("scan_status", {"job_id": payload["job_id"]})
        assert status_payload["job"]["launched_by"] == "previous_process"
        assert status_payload["job"]["state"] in ("starting", "running")
    finally:
        os.killpg(child.process.pid, 9)
        child.process.wait(timeout=30)


async def test_scan_status_stale_markers_and_hidden_processes(iso, monkeypatch):
    iso.make_workspace("ws", {"scans/tasks-running.txt": "1\n", "scans/running_a.txt": ""})
    payload, _ = await support.call("scan_status", {"workspace": "ws"})
    assert payload["workspace_status"]["is_running"] is False
    assert payload["workspace_status"]["stale_markers"] is True
    assert payload["workspace_status"]["markers"] == {"tasks_running": 1, "running_files": 1,
                                                      "resume_markers": 0}
    assert "untrusted_content" not in payload and payload["warnings"] == []
    fake = iso.tmp / "hidepid"
    fake.mkdir()
    monkeypatch.setattr(paths, "PROC_ROOT", str(fake))
    payload, _ = await support.call("scan_status", {"workspace": "ws"})
    assert payload["workspace_status"]["process_check"] == "unavailable"
    assert payload["workspace_status"]["is_running"] is True
    assert [w["code"] for w in payload["warnings"]] == ["process_check_unavailable"]


async def test_scan_status_reads_markers_through_the_pinned_descriptor(iso, monkeypatch):
    from sniper_mcp import lootfs

    iso.make_workspace("ws", {"scans/tasks-running.txt": "3\n"})

    def no_path_lookup(*args, **kwargs):
        raise AssertionError("scan_status resolved the workspace by path again")

    seen = []
    real = jobs.read_markers
    monkeypatch.setattr(lootfs, "workspace_path", no_path_lookup)
    monkeypatch.setattr(jobs, "read_markers", lambda where: seen.append(where) or real(where))
    payload, is_error = await support.call("scan_status", {"workspace": "ws"})
    assert not is_error and payload["workspace_status"]["markers"]["tasks_running"] == 3
    assert seen and all(isinstance(where, int) for where in seen)


async def test_scan_status_errors(iso):
    payload, is_error = await support.call("scan_status", {"job_id": "0123456789abcdef"})
    assert is_error and error_code(payload) == "job_not_found"
    payload, _ = await support.call("scan_status", {})
    assert error_code(payload) == "invalid_argument"
    payload, _ = await support.call("scan_status", {"workspace": "missing-ws"})
    assert error_code(payload) == "workspace_not_found"
    payload, _ = await support.call("scan_status", {"workspace": "a..b"})
    assert error_code(payload) == "invalid_workspace"
    iso.make_workspace("real-ws")
    (iso.workspace_dir / "linked-ws").symlink_to(iso.workspace_dir / "real-ws")
    payload, _ = await support.call("scan_status", {"workspace": "linked-ws"})
    assert error_code(payload) == "workspace_not_found"


async def test_scan_status_log_tail_is_redacted_and_stripped(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    token = "ghp_" + "a" * 36
    iso.set_knobs(stdout=f"\x1b[1mstarting\x1b[0m\ntoken {token}", files=["scans/out.txt"])
    payload, _ = await scan(target="app.scan.test")
    status_payload, _ = await support.call("scan_status", {"job_id": payload["job_id"],
                                                          "log_lines": 1})
    assert status_payload["untrusted_content"]["log_tail"] == "token [REDACTED:github-token]"
    assert status_payload["redaction"]["counts"] == {"github-token": 1}
    iso.setenv(SNIPER_MCP_REDACT="false")
    raw, _ = await support.call("scan_status", {"job_id": payload["job_id"]})
    assert token in raw["untrusted_content"]["log_tail"]
    assert [w["code"] for w in raw["warnings"]] == ["redaction_disabled"]


# --- cancel_scan (H.8, L.6, O.5 P1-04) -------------------------------------------------------

async def test_cancel_a_running_scan(iso, fast_cancel):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    iso.set_knobs(sleep=30)
    async with support.session() as client:
        launched = await client.call_tool("sniper_scan", {"target": "app.scan.test"})
        job_id = launched.structuredContent["job_id"]
        cancelled = await client.call_tool("cancel_scan", {"job_id": job_id})
        after = await client.call_tool("scan_status", {"job_id": job_id})
    body = cancelled.structuredContent
    job = after.structuredContent["job"]
    assert not cancelled.isError
    assert body["state"] == "cancelled" and body["previous_state"] in ("starting", "running")
    assert body["remaining_pids"] == [] and body["hint"] is None
    # L.6: a non-root scan runs under the terminal holder (the recorded pid); SIGTERM goes
    # to the sudo process it started, which relays it to the engine's process group.
    record = json.loads((iso.state_dir / "jobs" / f"{job_id}.json").read_text())
    assert record["launcher"] == "terminal" and record["front_pid"] not in (None, job["pid"])
    assert body["signals"] == [{"pid": record["front_pid"], "signal": "SIGTERM"}]
    assert job["state"] == "cancelled" and job["cancel"]["outcome"] == "cancelled"
    requests = audit_records(iso, "cancel_request")
    assert [r["decision"] for r in requests] == ["accepted", "completed"]
    assert requests[0]["result"] == {"state": None, "remaining_pids": None}
    assert requests[1]["result"] == {"state": "cancelled", "remaining_pids": []}
    assert requests[0]["job_id"] == job_id and requests[0]["target"] == "app.scan.test"
    exits = audit_records(iso, "scan_exit")
    assert [e["result"]["state"] for e in exits] == ["cancelled"]
    assert len(iso.calls("sniper")) == 1  # the CLI never ran again (no -dt, L.6)


async def test_cancel_a_finished_scan_and_an_unknown_job(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    payload, _ = await scan(target="app.scan.test")
    body, is_error = await support.call("cancel_scan", {"job_id": payload["job_id"]})
    assert not is_error
    assert body["state"] == "already_finished" and body["previous_state"] == "succeeded"
    assert body["signals"] == []
    body, is_error = await support.call("cancel_scan", {"job_id": "0123456789abcdef"})
    assert is_error and error_code(body) == "job_not_found" and body["error"]["retry"] == "never"
    decisions = [(r["decision"], r["reason_code"]) for r in audit_records(iso, "cancel_request")]
    assert decisions == [("completed", None), ("refused", "job_not_found")]


async def test_cancel_incomplete_names_the_surviving_processes(iso, fast_cancel):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    iso.set_knobs(sleep=30, ignore_term=True, ignore_hup=True)
    payload, _ = await scan(target="app.scan.test")
    body, is_error = await support.call("cancel_scan", {"job_id": payload["job_id"]})
    try:
        assert not is_error and body["state"] == "cancel_incomplete"
        pids = body["remaining_pids"]
        assert pids
        listed = " ".join(map(str, pids))
        sessions = sorted({jobs.read_stat(pid).session for pid in pids})
        assert body["hint"] == (
            f"These processes are owned by root and are still running: {listed}. Stop them "
            f"from a shell with: sudo kill {listed} (or their whole sessions with: sudo pkill "
            f"-TERM -s {','.join(map(str, sessions))})")
        decisions = [r["decision"] for r in audit_records(iso, "cancel_request")]
        assert decisions == ["accepted", "failed"]
        # L.6: while the survivors run, the job is never reported cancelled.
        status_body, _ = await support.call("scan_status", {"job_id": payload["job_id"]})
        job = status_body["job"]
        assert (job["state"], job["state_reason"]) == ("running", "cancel_incomplete")
        assert job["cancel"]["outcome"] == "cancel_incomplete"
        assert job["cancel"]["remaining_pids"] == pids
    finally:
        for pid in body.get("remaining_pids", []):
            os.kill(pid, 9)
    deadline = time.monotonic() + 10
    while True:  # the survivors are gone: now the job is cancelled
        status_body, _ = await support.call("scan_status", {"job_id": payload["job_id"]})
        if status_body["job"]["state"] != "running" or time.monotonic() > deadline:
            break
        await asyncio.sleep(0.05)
    assert status_body["job"]["state"] == "cancelled"


async def test_cancel_failing_after_acceptance_writes_a_failed_line(iso, monkeypatch):
    """G.2: an accepted cancel_request always gets an outcome line, as delete does."""
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    iso.set_knobs(sleep=30)
    payload, _ = await scan(target="app.scan.test")

    def broken(self, job_id):
        raise OSError("disk full")

    monkeypatch.setattr(jobs.JobStore, "request_cancel", broken)
    body, is_error = await support.call("cancel_scan", {"job_id": payload["job_id"]})
    assert is_error and error_code(body) == "internal_error"
    requests = audit_records(iso, "cancel_request")
    assert [(r["decision"], r["reason_code"]) for r in requests] == [
        ("accepted", None), ("failed", "internal_error")]
    assert requests[1]["result"] == {"state": None, "remaining_pids": None}
    assert jobs.JOBS[payload["job_id"]].process.poll() is None  # nothing was signalled


async def test_cancel_with_an_untrusted_recorded_pid_signals_nothing(iso, monkeypatch):
    """L.6 hardening through the tool: a record naming the server's parent is never
    signalled and the hint never tells the operator to kill it."""
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    iso.set_knobs(sleep=30)
    payload, _ = await scan(target="app.scan.test")
    job_id = payload["job_id"]
    record_path = iso.state_dir / "jobs" / f"{job_id}.json"
    record = json.loads(record_path.read_text())
    child = jobs.JOBS.pop(job_id)  # as if a previous process had launched it
    parent = jobs.read_stat(os.getppid())
    record.update(pid=parent.pid, pid_starttime=parent.starttime)
    record_path.write_text(json.dumps(record))
    sent: list[tuple[int, int]] = []
    monkeypatch.setattr(jobs.os, "kill", lambda pid, sig: sent.append((pid, sig)))
    try:
        body, is_error = await support.call("cancel_scan", {"job_id": job_id})
    finally:
        jobs.JOBS[job_id] = child
    assert sent == []
    assert not is_error and body["state"] == "cancel_incomplete"
    assert body["signals"] == [] and body["remaining_pids"] == []
    assert "No signal was sent" in body["hint"] and str(os.getppid()) not in body["hint"]


async def test_cancel_refuses_without_an_audit_log(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    iso.set_knobs(sleep=30)
    async with support.session() as client:
        launched = await client.call_tool("sniper_scan", {"target": "app.scan.test"})
        os.rename(iso.audit_log, iso.tmp / "audit-moved")
        iso.audit_log.mkdir()
        refused = await client.call_tool("cancel_scan",
                                         {"job_id": launched.structuredContent["job_id"]})
    assert refused.structuredContent["error"]["code"] == "audit_unavailable"
    child = jobs.JOBS[launched.structuredContent["job_id"]]
    assert child.process.poll() is None  # nothing was signalled


async def test_client_info_reaches_the_audit_log(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    info = mcp_types.Implementation(name="c" * 80, version="1")
    async with support.session(client_info=info) as client:
        await client.call_tool("sniper_scan", {"target": "other.scan.test"})
    request = audit_records(iso, "scan_request")[-1]
    assert request["client"] == {"name": "c" * 64, "version": "1"}


async def test_cidr_cap_boundary_through_sniper_scan(iso):
    iso.setenv(SNIPER_MCP_SCOPE="198.18.0.0/15")
    payload, is_error = await scan(target="198.18.0.0/15", mode="discover")
    assert is_error and error_code(payload) == "cidr_too_large"
    assert payload["error"]["details"] == {"cidr_cap": 16, "prefixlen": 15}
    payload, is_error = await scan(target="198.18.0.0/16", mode="discover")
    assert not is_error, payload
    wait_for(payload["job_id"])
    assert_dispatched(iso, "198.18.0.0/16", "discover")
    iso.setenv(SNIPER_MCP_CIDR_CAP="24")
    payload, _ = await scan(target="198.18.0.0/23", mode="discover")
    assert error_code(payload) == "cidr_too_large"


async def test_cidr_target_type_has_one_spelling_on_every_surface(iso):
    """S3 review: the audit log said "cidr" (G.3) while results and refusal details said
    "ipv4_cidr". The value is a stable public identifier (S.5): one spelling, "cidr",
    in sniper_status, sniper_scan results and refusals, job records and the audit log."""
    iso.setenv(SNIPER_MCP_SCOPE="192.0.2.0/24")
    status_payload, _ = await support.call("sniper_status")
    discover = next(m for m in status_payload["modes"]["available"]
                    if m["name"] == "discover")
    assert discover["target_types"] == ["ipv4", "cidr"]
    payload, is_error = await scan(target="192.0.2.0/25", mode="discover")
    assert not is_error, payload
    wait_for(payload["job_id"])
    assert payload["target_type"] == "cidr"
    record = json.loads((iso.state_dir / "jobs" / f"{payload['job_id']}.json").read_text())
    assert record["target_type"] == "cidr"
    refused, _ = await scan(target="198.51.100.0/24", mode="discover")
    assert error_code(refused) == "out_of_scope"
    assert refused["error"]["details"]["target_type"] == "cidr"
    wrong_mode, _ = await scan(target="192.0.2.0/25", mode="stealth")
    assert error_code(wrong_mode) == "target_type_not_supported_for_mode"
    assert wrong_mode["error"]["details"]["target_type"] == "cidr"
    await support.call("scan_status", {"job_id": payload["job_id"]})  # writes scan_exit
    lines = [r for r in audit_records(iso) if r["event"] in ("scan_request", "scan_exit")]
    assert {r["event"] for r in lines} == {"scan_request", "scan_exit"}
    assert {r["target_type"] for r in lines} == {"cidr"}
    # A job record written by an earlier development build is read with the same value.
    assert jobs.AUDIT_TARGET_TYPES["ipv4_cidr"] == "cidr"
