# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""The audit log (contract G; O.5 P0-08 audit rows and GAP-25)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import threading

import pytest

from sniper_mcp import audit, jobs
from sniper_mcp.tools import status
from tests import support

TS_RE = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z")


@pytest.fixture(autouse=True)
def _clean():
    status.clear_sudo_cache()
    yield
    jobs.terminate_all()
    jobs.JOBS.clear()


def lines(path) -> list[str]:
    return [line for line in open(path, encoding="ascii").read().split("\n") if line]


def records(path) -> list[dict]:
    return [json.loads(line) for line in lines(path)]


def verify_chain(path, session: str | None = None) -> list[dict]:
    """Recompute every session's seq/prev chain; returns the records."""
    raw = lines(path)
    chains: dict[str, tuple[int, str | None]] = {}
    found = []
    for line in raw:
        record = json.loads(line)
        sid = record["session"]
        seq, prev = chains.get(sid, (0, None))
        assert record["seq"] == seq + 1, (sid, record["seq"], seq)
        assert record["prev"] == prev
        chains[sid] = (record["seq"], hashlib.sha256(line.encode("ascii")).hexdigest())
        if session is None or sid == session:
            found.append(record)
    return found


def scan_fields(**values):
    return audit.action_fields(tool="sniper_scan", **values)


# --- G.3 record format -----------------------------------------------------------------

def test_record_format_order_and_chain(iso):
    iso.state_dir.mkdir(exist_ok=True)
    log = audit.AuditLog(str(iso.audit_log))
    log.client = {"name": "test-client", "version": "1.0"}
    assert log.write(audit.SERVER_START, result={"settings": {}}) == 1
    assert log.write(audit.SCAN_REQUEST, action=scan_fields(decision="refused",
                                                            reason_code="out_of_scope"),
                     result={"status": None}, request_id=7) == 2
    assert log.write(audit.SERVER_STOP, result={}, request_id="abc") == 3
    found = verify_chain(iso.audit_log)
    assert [r["event"] for r in found] == ["server_start", "scan_request", "server_stop"]
    first, second, third = found
    assert list(first) == list(audit.COMMON_FIELDS) + ["result"]
    assert list(second) == list(audit.COMMON_FIELDS) + list(audit.ACTION_FIELDS) + ["result"]
    for record in found:
        assert record["schema_version"] == "1" and record["server_version"] == "0.9.0"
        assert TS_RE.fullmatch(record["ts"]) and record["ts"].endswith("Z")  # GAP-25
        assert record["pid"] == os.getpid()
        assert re.fullmatch(r"[0-9a-f]{8}", record["session"])
        assert record["client"] == {"name": "test-client", "version": "1.0"}
    assert first["prev"] is None and first["request_id"] is None
    assert second["request_id"] == 7 and third["request_id"] == "abc"
    assert second["decision"] == "refused" and second["reason_code"] == "out_of_scope"
    assert second["argv"] is None and second["job_id"] is None


def test_action_lines_always_carry_the_process_overrides(iso):
    """F.6, G.3: the override flags are booleans on every action line, true whenever
    the writing process runs with them, even if the caller left them out."""
    iso.state_dir.mkdir(exist_ok=True)
    plain = audit.AuditLog(str(iso.audit_log))
    plain.write(audit.EXPORT_REQUEST, action=audit.action_fields(tool="export_workspace",
                                                                 decision="refused"),
                result={})
    lab = audit.AuditLog(str(iso.audit_log), allow_any_target=True, allow_intrusive=True)
    for event in (audit.SCAN_EXIT, audit.CANCEL_REQUEST, audit.DELETE_REQUEST,
                  audit.EXPORT_REQUEST):
        lab.write(event, action=audit.action_fields(tool="t", decision="refused",
                                                    allow_any_target=False), result={})
    lab.write(audit.SERVER_STOP, result={})
    found = [json.loads(line) for line in iso.audit_log.read_text().splitlines()]
    first, *rest, stop = found
    assert first["allow_any_target"] is False and first["allow_intrusive"] is False
    assert len(rest) == 4
    assert all(r["allow_any_target"] is True and r["allow_intrusive"] is True for r in rest)
    assert "allow_any_target" not in stop  # not an action event


def test_attacker_controlled_text_is_ascii_escaped(iso):
    iso.state_dir.mkdir(exist_ok=True)
    log = audit.AuditLog(str(iso.audit_log))
    raw = "app.example\u202e\n\x1b[31m\u2028" + "x" * 300
    log.write(audit.SCAN_REQUEST, action=scan_fields(decision="refused", target_input=raw,
                                                     reason="r" * 500),
              result={"status": None})
    text = open(iso.audit_log, "rb").read()
    assert text.count(b"\n") == 1 and text.endswith(b"\n")
    assert all(byte < 0x80 for byte in text)
    record = json.loads(text)
    assert record["target_input"] == raw[:256]
    assert len(record["reason"]) == 200
    assert "\\u202e" in text.decode() and "\\u001b" in text.decode()


def test_client_fields_are_cut_to_64_characters():
    assert audit.client_object("n" * 100, "v" * 100) == {"name": "n" * 64, "version": "v" * 64}
    assert audit.client_object(None, "1") is None


def test_action_fields_reject_typos_and_unknown_decisions():
    with pytest.raises(ValueError):
        audit.action_fields(tool="sniper_scan", targett="x")
    with pytest.raises(ValueError):
        audit.action_fields(tool="sniper_scan", decision="maybe")
    fields = audit.action_fields(resolved_addresses=[str(i) for i in range(100)])
    assert len(fields["resolved_addresses"]) == 64
    assert list(fields) == list(audit.ACTION_FIELDS)


def test_events_and_action_fields_must_agree(iso):
    log = audit.AuditLog(str(iso.audit_log))
    with pytest.raises(ValueError):
        log.write(audit.SCAN_REQUEST, result={})
    with pytest.raises(ValueError):
        log.write(audit.SERVER_STOP, action=scan_fields(), result={})
    with pytest.raises(ValueError):
        log.write("made_up_event", result={})


# --- G.1 location and permissions ------------------------------------------------------

def test_new_log_is_0600_and_a_loose_mode_is_fixed(iso):
    old = os.umask(0)
    try:
        log = audit.AuditLog(str(iso.audit_log))
        iso.state_dir.mkdir(exist_ok=True)
        log.write(audit.SERVER_STOP, result={})
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.stat(iso.audit_log).st_mode) == 0o600
    os.chmod(iso.audit_log, 0o644)
    log.write(audit.SERVER_STOP, result={})
    assert stat.S_IMODE(os.stat(iso.audit_log).st_mode) == 0o600
    assert log.mode_not_fixed is False


def test_eperm_from_fchmod_keeps_the_log_with_a_warning(iso, monkeypatch):
    iso.state_dir.mkdir(exist_ok=True)
    iso.audit_log.write_text("")
    os.chmod(iso.audit_log, 0o644)

    def refuse(fd, mode):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(audit.os, "fchmod", refuse)
    log = audit.AuditLog(str(iso.audit_log))
    log.write(audit.SERVER_STOP, result={})
    assert log.mode_not_fixed is True and log.status().mode_not_fixed is True
    os.chmod(iso.audit_log, 0o666)  # group- and world-writable: unavailable
    with pytest.raises(audit.AuditUnavailable):
        log.write(audit.SERVER_STOP, result={})


async def test_audit_log_mode_not_fixed_warning_in_status(iso, monkeypatch):
    iso.state_dir.mkdir(exist_ok=True)
    iso.audit_log.write_text("")
    os.chmod(iso.audit_log, 0o640)

    def refuse(fd, mode):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(audit.os, "fchmod", refuse)
    payload, _ = await support.call("sniper_status")
    assert "audit_log_mode_not_fixed" in [w["code"] for w in payload["warnings"]]


@pytest.mark.parametrize("kind", ["symlink", "directory", "fifo"])
def test_unsafe_audit_paths_are_unavailable(iso, kind):
    iso.state_dir.mkdir(exist_ok=True)
    target = iso.tmp / "elsewhere.jsonl"
    target.write_text("")
    if kind == "symlink":
        iso.audit_log.symlink_to(target)
    elif kind == "directory":
        iso.audit_log.mkdir()
    else:
        os.mkfifo(iso.audit_log, 0o600)
    log = audit.AuditLog(str(iso.audit_log))
    with pytest.raises(audit.AuditUnavailable):
        log.write(audit.SERVER_STOP, result={})
    with pytest.raises(audit.AuditUnavailable):
        log.check()
    assert log.status().available is False
    assert target.read_text() == ""


def test_missing_parent_directory_is_unavailable(iso):
    log = audit.AuditLog(str(iso.tmp / "no-such-dir" / "audit.jsonl"))
    with pytest.raises(audit.AuditUnavailable):
        log.write(audit.SERVER_STOP, result={})
    assert log.status().available is False


def test_status_does_not_create_the_log(iso):
    iso.state_dir.mkdir(exist_ok=True)
    log = audit.AuditLog(str(iso.audit_log))
    assert log.status().available is True
    assert not iso.audit_log.exists()


def test_failed_write_does_not_consume_a_sequence_number(iso):
    iso.state_dir.mkdir(exist_ok=True)
    log = audit.AuditLog(str(iso.audit_log))
    log.write(audit.SERVER_START, result={})
    os.rename(iso.audit_log, iso.tmp / "moved.jsonl")
    iso.audit_log.mkdir()
    with pytest.raises(audit.AuditUnavailable):
        log.write(audit.SERVER_STOP, result={})
    iso.audit_log.rmdir()
    os.rename(iso.tmp / "moved.jsonl", iso.audit_log)
    assert log.write(audit.SERVER_STOP, result={}) == 2
    assert [r["seq"] for r in verify_chain(iso.audit_log)] == [1, 2]


def test_concurrent_writers_keep_one_chain_per_session(iso):
    iso.state_dir.mkdir(exist_ok=True)
    first = audit.AuditLog(str(iso.audit_log))
    second = audit.AuditLog(str(iso.audit_log))  # another server process sharing the file

    def burst(log):
        for _ in range(50):
            log.write(audit.SERVER_STOP, result={"filler": "x" * 2000})

    threads = [threading.Thread(target=burst, args=(log,)) for log in (first, first, second,
                                                                      second)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    found = verify_chain(iso.audit_log)
    assert len(found) == 200
    assert {r["session"] for r in found} == {first.session, second.session}
    assert first.seq == second.seq == 100


# --- G.4 events through the server --------------------------------------------------------

async def test_server_start_and_stop_lines(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test,192.0.2.0/24,!dev.app.scan.test",
               SNIPER_MCP_ALLOW_INTRUSIVE="1")
    async with support.session() as client:
        await client.call_tool("sniper_status", {})
    found = verify_chain(iso.audit_log)
    events = [r["event"] for r in found]
    assert events[0] == "server_start" and events[-1] == "server_stop"
    start = found[0]["result"]
    assert set(start) == {"settings", "plugins", "warnings"}
    assert start["settings"] == {
        "scan_enabled": True, "needs_sudo": True, "scope_configured": True,
        "scope_digest": start["settings"]["scope_digest"], "scope_source": "env",
        "allow_any_target": False, "allow_intrusive": True, "dns_policy": "strict",
        "cidr_cap": 16, "max_concurrent_scans": 2, "destructive_enabled": False,
        "redact": True, "reveal_secrets": False}
    assert len(start["settings"]["scope_digest"]) == 16
    assert start["plugins"] == []
    assert "domain_exclusions_not_applied_to_ip_targets" in start["warnings"]


@pytest.mark.parametrize("tool", ["list_workspaces", "get_findings", "get_ports",
                                  "get_subdomains", "get_technologies", "grep_loot"])
async def test_a_read_only_session_records_its_client(iso, tool):
    """V2 D4: server_stop of a session that only used read tools had client null."""
    iso.make_workspace("app.example", {"nmap/nmap-app.example.txt": "80/tcp open http\n"})
    arguments = {"pattern": "http", "workspace": "app.example"} if tool == "grep_loot" else (
        {} if tool == "list_workspaces" else {"workspace": "app.example"})
    info = __import__("mcp").types.Implementation(name="reader-client", version="3.1")
    async with support.session(client_info=info) as client:
        result = await client.call_tool(tool, arguments)
        assert not result.isError, result
    stop = [r for r in verify_chain(iso.audit_log) if r["event"] == "server_stop"]
    assert stop and stop[-1]["client"] == {"name": "reader-client", "version": "3.1"}


async def test_scope_change_is_audited_before_it_is_used(iso):
    scope_file = iso.tmp / "scope"
    scope_file.write_text("app.scan.test\n")
    scope_file.chmod(0o600)
    iso.setenv(SNIPER_MCP_SCOPE_FILE=str(scope_file))
    iso.resolve("app.scan.test", "203.0.113.10")
    iso.resolve("api.app.scan.test", "203.0.113.11")
    async with support.session() as client:
        await client.call_tool("sniper_status", {})
        scope_file.write_text("app.scan.test\n!api.app.scan.test\n")
        refused = await client.call_tool("sniper_scan", {"target": "api.app.scan.test"})
        await client.call_tool("sniper_status", {})  # same digest: no second line
    assert refused.structuredContent["error"]["code"] == "excluded"
    found = verify_chain(iso.audit_log)
    events = [r["event"] for r in found]
    assert events.count("scope_changed") == 1
    changed = found[events.index("scope_changed")]
    request = found[events.index("scan_request")]
    assert events.index("scope_changed") < events.index("scan_request")
    assert changed["result"]["source"] == "file"
    assert changed["result"]["old_digest"] == found[0]["result"]["settings"]["scope_digest"]
    assert changed["result"]["new_digest"] == request["scope_digest"]
    assert changed["result"]["old_digest"] != changed["result"]["new_digest"]


async def test_check_never_writes_the_audit_log(iso, capsys):
    from sniper_mcp import server

    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    assert server.run(["--check"]) == 0
    assert not iso.audit_log.exists()


# --- G.2 fail-closed ---------------------------------------------------------------------

def _break_audit_log(iso):
    iso.state_dir.mkdir(exist_ok=True)
    (iso.state_dir / "jobs").mkdir(exist_ok=True)
    (iso.state_dir / "exports").mkdir(exist_ok=True)
    iso.audit_log.mkdir()


async def test_scan_refuses_when_the_audit_log_cannot_be_written(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    iso.resolve("app.scan.test", "203.0.113.10")
    _break_audit_log(iso)
    payload, is_error = await support.call("sniper_scan", {"target": "app.scan.test"})
    assert is_error and payload["error"]["code"] == "audit_unavailable"
    assert payload["error"]["retry"] == "after_change"
    assert iso.calls() == []  # not even the sudo preflight (F.9 step 9 precedes step 10)


async def test_refusals_stay_refusals_when_the_audit_log_is_down(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    _break_audit_log(iso)
    payload, is_error = await support.call("sniper_scan", {"target": "-oN/tmp/x"})
    assert is_error and payload["error"]["code"] == "invalid_target"
    payload, is_error = await support.call("cancel_scan", {"job_id": "0123456789abcdef"})
    assert is_error and payload["error"]["code"] == "job_not_found"


async def test_read_tools_do_not_depend_on_the_audit_log(iso):
    _break_audit_log(iso)
    iso.copy_loot("se-11.x")
    payload, is_error = await support.call("list_workspaces")
    assert not is_error
    payload, is_error = await support.call("sniper_status")
    assert not is_error and payload["scan"]["disabled_reason"] == "scope_not_configured"
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    payload, _ = await support.call("sniper_status")
    assert payload["scan"]["disabled_reason"] == "audit_unavailable"


async def test_accepted_and_refused_scan_lines_carry_every_field(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test", SNIPER_MCP_AUTHORIZATION_REF="SOW-7")
    iso.resolve("app.scan.test", "203.0.113.10")
    info = __import__("mcp").types.Implementation(name="audit-client", version="2.0")
    async with support.session(client_info=info) as client:
        accepted = await client.call_tool("sniper_scan", {"target": "APP.Scan.Test"})
        refused = await client.call_tool("sniper_scan", {"target": "other.scan.test"})
    assert not accepted.isError and refused.isError
    found = [r for r in verify_chain(iso.audit_log) if r["event"] == "scan_request"]
    ok, no = found
    for record in found:
        assert list(record) == (list(audit.COMMON_FIELDS) + list(audit.ACTION_FIELDS)
                                + ["result"])
        assert record["client"] == {"name": "audit-client", "version": "2.0"}
        assert isinstance(record["request_id"], int)
        assert record["tool"] == "sniper_scan" and record["authorization_ref"] == "SOW-7"
        assert record["scope_source"] == "env" and len(record["scope_digest"]) == 16
        assert record["allow_any_target"] is False and record["allow_intrusive"] is False
        assert record["dns_policy"] == "strict" and record["sudo"] is True
        assert record["edition"] == "se" and record["dialect"] == "11.x"
        assert record["elicitation"] == {"requested": False, "action": None}
    job_id = accepted.structuredContent["job_id"]
    assert ok["decision"] == "accepted" and ok["reason_code"] is None
    assert ok["target_input"] == "APP.Scan.Test" and ok["target"] == "app.scan.test"
    assert ok["target_type"] == "hostname" and ok["mode"] == "stealth"
    assert ok["mode_class"] == "active" and ok["workspace"] == "app.scan.test"
    assert ok["job_id"] == job_id and ok["argv"][-6:] == [
        "-t", "app.scan.test", "-m", "stealth", "-w", "app.scan.test"]
    assert ok["resolved_addresses"] == ["203.0.113.10"]
    assert ok["resolved_addresses_total"] == 1
    assert ok["matched_scope_entry"] == "app.scan.test"
    assert ok["result"] == {"status": "launched"}
    assert no["decision"] == "refused" and no["reason_code"] == "out_of_scope"
    assert no["argv"] is None and no["job_id"] is None and no["result"] == {"status": None}
    assert no["target"] == "other.scan.test" and no["resolved_addresses"] is None


async def test_audit_log_never_holds_log_text(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    iso.resolve("app.scan.test", "203.0.113.10")
    iso.set_knobs(stdout="CANARY-LOG-TEXT This script must be run as root")
    payload, is_error = await support.call("sniper_scan", {"target": "app.scan.test"})
    assert is_error and payload["error"]["code"] == "scan_failed_early"
    assert "CANARY-LOG-TEXT" in json.dumps(payload)
    assert "CANARY-LOG-TEXT" not in iso.audit_log.read_text()
    exits = [r for r in records(iso.audit_log) if r["event"] == "scan_exit"]
    assert len(exits) == 1 and exits[0]["result"]["state_reason"] == "not_root"
