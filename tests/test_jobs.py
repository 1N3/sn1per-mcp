# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Jobs: records, liveness, classification, cancel, retention, reaping (contract L).

O.5 P0-13 (every L.3 pattern, CE exit 0 with failure text, no_output), P1-03
(stale markers) and P1-04 (persistence across a restart, SIGKILL after an
ignored SIGTERM, cancel_incomplete, never -dt or a pattern kill). Every job
runs the stub CLI (O.3); no test signals anything it did not start.
"""

from __future__ import annotations

import json
import os
import re
import signal
import stat
import time

import pytest

from sniper_mcp import audit, jobs, paths, proc, state
from tests import support

D = "-" * 5
KEY_BEGIN = D + "BEGIN OPENSSH PRIVATE KEY" + D
KEY_END = D + "END OPENSSH PRIVATE KEY" + D


@pytest.fixture(autouse=True)
def _clean():
    yield
    jobs.terminate_all()
    jobs.JOBS.clear()


@pytest.fixture
def fast_cancel(monkeypatch):
    monkeypatch.setattr(jobs, "CANCEL_TERM_GRACE_SECONDS", 1.0)
    monkeypatch.setattr(jobs, "CANCEL_POLL_SECONDS", 3.0)
    monkeypatch.setattr(jobs, "CANCEL_POLL_INTERVAL", 0.05)


def make_store(iso, *, euid: int | None = None, with_audit: bool = True) -> jobs.JobStore:
    settings = support.current_settings()
    assert state.prepare_state_dir(settings.state_dir).ok
    return jobs.JobStore(state_dir=settings.state_dir, home=settings.home,
                         euid=settings.euid if euid is None else euid,
                         workspace_dir=lambda: str(iso.workspace_dir),
                         audit=audit.AuditLog(settings.audit_log) if with_audit else None)


def cli_argv(iso, workspace: str = "app.scan.test") -> list[str]:
    return [str(iso.cli_path), "-t", "app.scan.test", "-m", "stealth", "-w", workspace]


def start(iso, store: jobs.JobStore, *, workspace: str = "app.scan.test",
          argv: list[str] | None = None, sudo: bool = False,
          engine_files: list[str] | None = None) -> tuple[str, dict]:
    job_id = store.new_job_id()
    record = store.launch(job_id, argv or cli_argv(iso, workspace), {
        "target": "app.scan.test", "target_type": "hostname", "target_input": "app.scan.test",
        "mode": "stealth", "mode_class": "active", "port": None, "workspace": workspace,
        "edition": "se", "dialect": "11.x", "engine_version": "11.0", "sudo": sudo,
        "authorization_ref": "SOW-1", "allow_any_target": False, "scope_digest": "0" * 16,
        "engine_files": engine_files or []})
    return job_id, record


def sudo_argv(iso, workspace: str = "app.scan.test") -> list[str]:
    return [str(iso.sudo_path), "-n", "--", *cli_argv(iso, workspace)]


def wait_exit(job_id: str) -> int:
    return jobs.JOBS[job_id].process.wait(timeout=30)


def finished(iso, store, **knobs) -> jobs.JobView:
    iso.set_knobs(**knobs)
    job_id, record = start(iso, store)
    wait_exit(job_id)
    return store.observe(record)


def wait_for_tree(record: dict, size: int) -> list:
    tree: list = []
    for _ in range(200):
        tree = jobs._snapshot_tree(record["pid"], record["pid_starttime"])
        if len(tree) >= size:
            break
        time.sleep(0.05)
    return tree


def audit_lines(iso) -> list[dict]:
    if not iso.audit_log.exists():
        return []
    return [json.loads(line) for line in iso.audit_log.read_text().splitlines() if line]


# --- L.1 records and files -------------------------------------------------------------

def test_job_ids_are_16_lowercase_hex():
    assert all(re.fullmatch(r"[0-9a-f]{16}", jobs.JobStore.new_job_id()) for _ in range(50))


def test_launch_writes_a_private_record_and_log(iso):
    store = make_store(iso)
    iso.set_knobs(stdout="stub engine output", files=["scans/out.txt"])
    job_id, record = start(iso, store)
    assert wait_exit(job_id) == 0
    jobs_dir = iso.state_dir / "jobs"
    assert stat.S_IMODE(os.stat(jobs_dir).st_mode) == 0o700
    for name in (f"{job_id}.json", f"{job_id}.log"):
        assert stat.S_IMODE(os.stat(jobs_dir / name).st_mode) == 0o600
    on_disk = json.loads((jobs_dir / f"{job_id}.json").read_text())
    assert on_disk == record
    assert set(record) >= {
        "schema_version", "job_id", "created_at", "server_version", "server_pid", "edition",
        "dialect", "engine_version", "target", "target_type", "target_input", "mode",
        "mode_class", "port", "workspace", "argv", "sudo", "pid", "pid_starttime", "pgid",
        "sid", "log_path", "started_at", "ended_at", "exit_code", "state", "state_reason",
        "cancel", "authorization_ref", "allow_any_target", "scope_digest"}
    assert record["schema_version"] == "1" and record["server_pid"] == os.getpid()
    assert record["pgid"] == record["sid"] == record["pid"]  # its own session (D.5)
    assert isinstance(record["pid_starttime"], int)
    assert record["log_path"] == str(jobs_dir / f"{job_id}.log")
    assert record["state"] == "starting" and record["argv"] == cli_argv(iso)
    assert "stub engine output" in (jobs_dir / f"{job_id}.log").read_text()
    assert "PATH=" not in json.dumps(record)  # no environment in the record


def test_spawn_failure_leaves_no_log_and_no_record(iso):
    store = make_store(iso)
    with pytest.raises(proc.LaunchError):
        start(iso, store, argv=[str(iso.tmp / "absent-engine")])
    assert os.listdir(iso.state_dir / "jobs") == []
    assert jobs.JOBS == {}


def test_record_write_failure_stops_the_scan(iso, monkeypatch):
    store = make_store(iso)
    iso.set_knobs(sleep=30)

    def fail(path, obj):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(state, "write_json_atomic", fail)
    with pytest.raises(proc.LaunchError) as caught:
        start(iso, store)
    assert caught.value.cause == "OSError"
    assert jobs.JOBS == {}
    own_stub = str(iso.cli_path).encode()
    for name in os.listdir(paths.PROC_ROOT):  # this test's stub is not running any more
        if name.isdigit():
            st = jobs.read_stat(int(name))
            if st is not None and not st.dead:
                assert own_stub not in (jobs.read_cmdline(int(name)) or [])


def test_records_the_server_did_not_write_are_ignored(iso):
    store = make_store(iso)
    job_id = "0123456789abcdef"
    path = iso.state_dir / "jobs" / f"{job_id}.json"
    for bad in ({"schema_version": "1", "job_id": job_id, "pid": 1},
                {"schema_version": "1", "job_id": "fedcba9876543210", "pid": 4242},
                {"schema_version": "2", "job_id": job_id, "pid": 4242}):
        path.write_text(json.dumps(bad))
        path.chmod(0o600)
        assert store.load(job_id) is None
    link = iso.state_dir / "jobs" / "1111111111111111.json"
    link.symlink_to(path)
    assert store.load("1111111111111111") is None
    assert store.load("../etc") is None


# --- L.3 liveness ------------------------------------------------------------------------

def test_starting_then_running(iso, monkeypatch):
    store = make_store(iso)
    iso.set_knobs(sleep=30)
    job_id, record = start(iso, store)
    assert store.observe(record).state == "starting"
    monkeypatch.setattr(jobs, "STARTING_SECONDS", 0.0)
    view = store.observe(record)
    assert view.state == "running" and view.alive and view.launched_by == "this_process"


def test_pid_reuse_is_detected_by_start_time(iso):
    store = make_store(iso)
    iso.set_knobs(sleep=30)
    job_id, record = start(iso, store)
    assert jobs.process_alive(record["pid"], record["pid_starttime"])
    assert not jobs.process_alive(record["pid"], record["pid_starttime"] + 1)


def test_eperm_counts_as_alive(monkeypatch):
    monkeypatch.setattr(jobs, "read_stat", lambda pid: None)

    def eperm(pid, sig):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(jobs.os, "kill", eperm)
    assert jobs.process_alive(424242, 123) is True


def test_a_zombie_is_not_alive(iso):
    store = make_store(iso)
    job_id, record = start(iso, store)
    child = jobs.JOBS[job_id]
    for _ in range(600):  # until it exited (a zombie: this process has not reaped it)
        st = jobs.read_stat(record["pid"])
        if st is None or st.dead:
            break
        time.sleep(0.05)
    assert not jobs.process_alive(record["pid"], record["pid_starttime"])
    child.process.wait(timeout=30)


# --- L.3 classification (O.5 P0-13) --------------------------------------------------------

@pytest.mark.parametrize(("reason", "text"), [
    (reason, needles[0]) for reason, needles, _ in jobs.FAILURE_PATTERNS
] + [("sudo_terminal_required", "sudo: sorry, you must have a tty"),
     ("sudo_not_allowed", "alice is not in the sudoers file."),
     ("license_limit", "Workspace LIMIT EXCEEDED for this licence")])
def test_every_failure_pattern_fails_a_ce_style_exit_zero(iso, reason, text):
    store = make_store(iso)
    colored = f"\x1b[1;31m[!]\x1b[0m {text}\r\n"
    view = finished(iso, store, stdout=colored, files=["scans/out.txt"], exit_status=0)
    assert (view.state, view.state_reason, view.exit_code) == ("failed", reason, 0)
    assert reason in view.summary["failure_markers"]


def test_non_zero_exit_without_a_pattern_is_exit_status(iso):
    view = finished(iso, make_store(iso), files=["scans/out.txt"], exit_status=3)
    assert (view.state, view.state_reason, view.exit_code) == ("failed", "exit_status", 3)


def test_no_new_workspace_file_is_no_output(iso):
    iso.make_workspace("app.scan.test", {"old/file.txt": "older run"})
    old = iso.workspace_dir / "app.scan.test" / "old" / "file.txt"
    os.utime(old, (time.time() - 3600, time.time() - 3600))
    view = finished(iso, make_store(iso), exit_status=0)
    assert (view.state, view.state_reason) == ("failed", "no_output")
    assert view.summary["files_written"] == 0


def test_scan_complete_is_never_a_success_criterion(iso):
    view = finished(iso, make_store(iso), stdout="SCAN COMPLETE!", exit_status=0)
    assert (view.state, view.state_reason) == ("failed", "no_output")
    assert view.summary["completion_marker_seen"] is True


def test_success_needs_output_and_no_failure(iso):
    view = finished(iso, make_store(iso), files=["nmap/ports.txt", "web/a.txt"])
    assert (view.state, view.state_reason, view.exit_code) == ("succeeded", None, 0)
    assert view.summary == {"completion_marker_seen": False, "failure_markers": [],
                            "files_written": 2}


def test_an_engine_removed_while_it_started_is_failed(iso):
    """V3 D2: the 11.x licence hook deleted the engine during check_update; the engine
    exited 0 after 0.4 s and init's skeleton files defeated no_output."""
    store = make_store(iso)
    victim = iso.tmp / "engine-file"
    victim.write_text("present at launch")
    iso.set_knobs(files=["scans/out.txt"], exit_status=0)
    job_id, record = start(iso, store, engine_files=[str(victim)])
    assert record["engine_files"] == [str(victim)]
    wait_exit(job_id)
    victim.unlink()
    view = store.observe(record)
    assert (view.state, view.state_reason) == ("failed", "engine_removed")


def test_the_engine_files_missing_message_fails_the_scan(iso):
    store = make_store(iso)
    text = (f"functions.sh: line 396: {iso.install_dir}/modes/normal.sh: No such file or "
            "directory")
    view = finished(iso, store, stdout=text, files=["scans/out.txt"], exit_status=0)
    assert (view.state, view.state_reason) == ("failed", "engine_files_missing")


def test_a_cancel_request_classifies_as_cancelled(iso):
    store = make_store(iso)
    iso.set_knobs(exit_status=1)
    job_id, record = start(iso, store)
    wait_exit(job_id)
    store.request_cancel(job_id)
    assert store.observe(store.load(job_id)).state == "cancelled"


def test_unknown_when_proc_is_unreadable_and_nothing_is_known(iso, monkeypatch):
    store = make_store(iso)
    job_id, record = start(iso, store)
    wait_exit(job_id)
    jobs.JOBS.clear()  # the handle, and so the exit code, is gone
    os.unlink(store.log_path(job_id))
    empty_proc = iso.tmp / "empty-proc"
    empty_proc.mkdir()
    monkeypatch.setattr(paths, "PROC_ROOT", str(empty_proc))
    view = store.observe(store.load(job_id))
    assert view.state == "unknown" and view.exit_code is None


def test_large_logs_are_scanned_at_both_ends_only(iso):
    store = make_store(iso)
    iso.set_knobs(files=["scans/out.txt"])
    job_id, record = start(iso, store)
    wait_exit(job_id)
    filler = ("x" * 1023 + "\n").encode() * 4096  # 4 MiB
    log = store.log_path(job_id)
    with open(log, "wb") as handle:
        handle.write(filler + b"Unknown scan option\n" + filler + b"tail\n")
    assert store.classify(store.load(job_id), 0)[0] == "succeeded"  # the middle is skipped
    with open(log, "wb") as handle:
        handle.write(filler + filler + b"Unknown scan option\n")
    assert store.classify(store.load(job_id), 0)[:2] == ("failed", "unknown_option")


# --- L.8 persistence, finishing, reaping --------------------------------------------------

def test_record_survives_a_restart_and_is_finished_by_the_next_process(iso, monkeypatch):
    monkeypatch.setattr(jobs, "STARTING_SECONDS", 0.0)
    first = make_store(iso)
    iso.set_knobs(sleep=30)
    job_id, record = start(iso, first)
    child = jobs.JOBS.pop(job_id)  # the next server process has no handle
    second = make_store(iso)
    try:
        view = second.view(job_id)
        assert view.state == "running" and view.launched_by == "previous_process"
    finally:
        os.killpg(child.process.pid, signal.SIGKILL)
        child.process.wait(timeout=30)
    view = second.view(job_id)
    assert view.state == "failed" and view.exit_code is None  # unknown after a restart
    assert second.load(job_id)["state"] == "failed"
    exits = [r for r in audit_lines(iso) if r["event"] == "scan_exit"]
    assert len(exits) == 1 and exits[0]["job_id"] == job_id
    assert exits[0]["result"]["state"] == "failed" and exits[0]["decision"] == "failed"
    second.view(job_id)
    make_store(iso).view(job_id)
    assert len([r for r in audit_lines(iso) if r["event"] == "scan_exit"]) == 1


def test_another_live_launcher_finishes_its_own_jobs(iso):
    store = make_store(iso)
    job_id, record = start(iso, store)
    wait_exit(job_id)
    iso.set_knobs(sleep=30)
    _, other = start(iso, store)  # any live process of ours stands in for that server
    foreign = dict(store.load(job_id))
    foreign["server_pid"] = other["pid"]
    foreign["server_pid_starttime"] = other["pid_starttime"]
    state.write_json_atomic(store.record_path(job_id), foreign)
    jobs.JOBS.pop(job_id)
    view = store.observe(foreign)
    assert view.state == "succeeded" and store.load(job_id)["state"] == "starting"
    foreign["server_pid_starttime"] = other["pid_starttime"] + 1  # that launcher is gone
    state.write_json_atomic(store.record_path(job_id), foreign)
    store.observe(foreign)
    assert store.load(job_id)["state"] == "succeeded"


def test_poll_children_reaps_and_finishes(iso):
    store = make_store(iso)
    job_id, record = start(iso, store)
    child = jobs.JOBS[job_id]
    for _ in range(600):
        st = jobs.read_stat(record["pid"])
        if st is None or st.dead:
            break
        time.sleep(0.05)
    store.poll_children()
    assert child.process.returncode == 0
    assert jobs.read_stat(record["pid"]) is None  # reaped: no zombie left
    assert store.load(job_id)["state"] == "succeeded"


def test_sweep_finishes_records_of_previous_processes(iso):
    store = make_store(iso)
    job_id, record = start(iso, store)
    wait_exit(job_id)
    jobs.JOBS.clear()
    make_store(iso).sweep()
    assert store.load(job_id)["state"] == "succeeded"


def test_scan_exit_line_comes_before_the_terminal_record(iso):
    store = make_store(iso)
    job_id, record = start(iso, store)
    wait_exit(job_id)
    iso.audit_log.mkdir()  # unavailable: the record must not turn terminal silently
    assert store.observe(store.load(job_id)).state == "succeeded"
    assert store.load(job_id)["state"] == "starting"
    iso.audit_log.rmdir()
    store.observe(store.load(job_id))
    assert store.load(job_id)["state"] == "succeeded"
    assert [r["event"] for r in audit_lines(iso)] == ["scan_exit"]


# --- L.7 retention -------------------------------------------------------------------------

def test_retention_prunes_only_old_finished_jobs(iso):
    store = make_store(iso)
    old_id, _ = start(iso, store)
    wait_exit(old_id)
    store.view(old_id)
    iso.set_knobs(sleep=30)
    running_id, _ = start(iso, store)
    record = store.load(old_id)
    record["ended_at"] = "2020-01-01T00:00:00.000Z"
    state.write_json_atomic(store.record_path(old_id), record)
    stale = store.load(running_id)
    stale["started_at"] = "2020-01-01T00:00:00.000Z"
    state.write_json_atomic(store.record_path(running_id), stale)
    (iso.state_dir / "exports" / "keep.tar.gz").write_bytes(b"x")
    iso.audit_log.write_text("{}\n")
    assert store.prune(0) == 0
    assert store.prune(30) == 1
    assert store.load(old_id) is None and not os.path.exists(store.log_path(old_id))
    assert store.load(running_id) is not None
    assert (iso.state_dir / "exports" / "keep.tar.gz").exists() and iso.audit_log.exists()


def test_retention_runs_at_most_once_per_hour(iso, monkeypatch):
    store = make_store(iso)
    calls = []
    monkeypatch.setattr(store, "prune", lambda days, now=None: calls.append(days) or 0)
    store.prune_if_due(30)
    store.prune_if_due(30)
    assert calls == [30]


# --- L.5 log tails ---------------------------------------------------------------------------

def write_log(store, job_id: str, data: bytes) -> None:
    with open(store.log_path(job_id), "wb") as handle:
        handle.write(data)


def ended(iso) -> tuple[jobs.JobStore, str]:
    store = make_store(iso)
    job_id, _ = start(iso, store)
    wait_exit(job_id)
    return store, job_id


def test_log_tail_lines_ansi_and_progress(iso):
    store, job_id = ended(iso)
    write_log(store, job_id, b"one\n\x1b[32mtwo\x1b[0m\n10%\r50%\r100%\nfour\n")
    assert store.log_tail(job_id, 3, redact_enabled=True).text == "two\n100%\nfour"
    assert store.log_tail(job_id, 0, redact_enabled=True).text == ""
    assert store.log_tail(job_id, 200, redact_enabled=True).text.startswith("one\n")


def test_log_tail_redacts_a_key_whose_begin_line_is_outside_the_selection(iso):
    store, job_id = ended(iso)
    body = "\n".join("QUJD" * 16 for _ in range(10))
    write_log(store, job_id, f"start\n{KEY_BEGIN}\n{body}\n{KEY_END}\nafter\n".encode())
    tail = store.log_tail(job_id, 3, redact_enabled=True)
    assert "QUJD" not in tail.text and tail.text.endswith("after")
    assert tail.counts == {"private-key": 1}
    assert "QUJD" in store.log_tail(job_id, 3, redact_enabled=False).text


def test_log_tail_key_body_across_the_8000_character_cut_is_redacted(iso):
    store, job_id = ended(iso)
    body = "\n".join("S0VZQk9EWQ" * 7 for _ in range(150))  # about 10,600 characters
    filler = "".join(f"line {i:05d} " + "z" * 60 + "\n" for i in range(150))
    write_log(store, job_id, f"{filler}{KEY_BEGIN}\n{body}\n{KEY_END}\ntail\n".encode())
    tail = store.log_tail(job_id, 200, redact_enabled=True)
    assert tail.truncated and len(tail.text) <= jobs.LOG_TAIL_MAX_CHARS
    assert "S0VZ" not in tail.text and "[REDACTED:private-key]" in tail.text
    assert tail.counts == {"private-key": 1}
    raw = store.log_tail(job_id, 200, redact_enabled=False)
    assert "S0VZ" in raw.text and KEY_BEGIN not in raw.text  # the block crosses the cut


def test_log_tail_window_and_cap_keep_the_end(iso):
    store, job_id = ended(iso)
    write_log(store, job_id, b"".join(b"%06d " % i + b"y" * 90 + b"\n" for i in range(2000)))
    tail = store.log_tail(job_id, 200, redact_enabled=True)
    assert len(tail.text) <= jobs.LOG_TAIL_MAX_CHARS and tail.truncated
    assert tail.text.startswith("[truncated]") and tail.text.endswith("y" * 90)
    assert "001999 " in tail.text


def test_log_tail_counts_invisible_characters(iso):
    store, job_id = ended(iso)
    write_log(store, job_id, "a\U000e0041b\ufe0fc\u200bd\n".encode())
    tail = store.log_tail(job_id, 5, redact_enabled=True)
    assert tail.text == "abc<U+200B>d" and tail.invisible_removed == 2


# --- L.4 workspace activity (O.5 P1-03) --------------------------------------------------------

def test_markers_are_counted_without_following_links(iso):
    path = iso.make_workspace("ws", {"scans/tasks-running.txt": "2\n",
                                     "scans/running_app.txt": "",
                                     "scans/running_b.txt": "",
                                     "scans/resume/stealth.running": "",
                                     "scans/resume/other.done": ""})
    assert jobs.read_markers(str(path)) == {"tasks_running": 2, "running_files": 2,
                                            "resume_markers": 1}
    linked = iso.make_workspace("linked")
    (linked / "scans").symlink_to(path / "scans")
    assert jobs.read_markers(str(linked)) == {"tasks_running": 0, "running_files": 0,
                                              "resume_markers": 0}


def test_markers_are_read_relative_to_an_open_descriptor(iso):
    path = iso.make_workspace("ws", {"scans/tasks-running.txt": "4\n",
                                     "scans/running_app.txt": ""})
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        moved = path.with_name("ws-moved")
        path.rename(moved)  # the path is gone; the descriptor still names the directory
        assert jobs.read_markers(fd) == {"tasks_running": 4, "running_files": 1,
                                         "resume_markers": 0}
        assert jobs.workspace_activity("ws", fd).markers["tasks_running"] == 4
        os.fstat(fd)  # not closed by the reader
    finally:
        os.close(fd)


def test_stale_markers_without_a_process(iso):
    path = iso.make_workspace("ws", {"scans/tasks-running.txt": "1\n"})
    activity = jobs.workspace_activity("ws", str(path))
    assert activity.process_check == "ok"
    assert activity.running_processes == 0 and activity.is_running is False
    assert activity.stale_markers is True


def test_a_live_engine_process_matches_its_workspace(iso):
    store = make_store(iso)
    iso.set_knobs(sleep=30)
    path = iso.make_workspace("busy-ws")
    start(iso, store, workspace="busy-ws")
    activity = jobs.workspace_activity("busy-ws", str(path))
    assert activity.running_processes == 1 and activity.is_running is True
    assert activity.stale_markers is False
    assert jobs.workspace_activity("busy", str(path)).running_processes == 0  # exact name


def test_hidden_processes_fall_back_to_markers(iso, monkeypatch):
    path = iso.make_workspace("ws", {"scans/running_x.txt": ""})
    fake = iso.tmp / "hidepid-proc"
    fake.mkdir()
    monkeypatch.setattr(paths, "PROC_ROOT", str(fake))
    activity = jobs.workspace_activity("ws", str(path))
    assert activity.process_check == "unavailable"
    assert activity.is_running is True and activity.stale_markers is False


# --- L.6 cancel (O.5 P1-04) ------------------------------------------------------------------

def test_cancel_as_a_normal_user_signals_the_sudo_front_end(iso, fast_cancel):
    store = make_store(iso)
    iso.set_knobs(sleep=30, sudo_fork=True)
    job_id, record = start(iso, store,
                           argv=[str(iso.sudo_path), "-n", "--", *cli_argv(iso)])
    assert len(wait_for_tree(record, 3)) == 3  # stub sudo, engine stub, its sleep
    outcome = store.signal_job(record)
    assert outcome.state == "cancelled" and outcome.remaining_pids == []
    assert outcome.signals == [{"pid": record["pid"], "signal": "SIGTERM"}]


def test_ignored_sigterm_ends_in_sigkill_when_running_as_root(iso, fast_cancel):
    store = make_store(iso, euid=0)  # the root path: every process of the tree is signalled
    iso.set_knobs(sleep=30, ignore_term=True)
    job_id, record = start(iso, store)
    tree = wait_for_tree(record, 2)
    assert len(tree) == 2 and tree[-1][0] == record["pid"]  # children first
    outcome = store.signal_job(record)
    assert outcome.state == "cancelled" and outcome.remaining_pids == []
    sent = [(s["pid"], s["signal"]) for s in outcome.signals]
    assert [sig for _, sig in sent] == ["SIGTERM", "SIGTERM", "SIGKILL", "SIGKILL"]
    assert sent[1] == (record["pid"], "SIGTERM")


def test_root_owned_survivors_give_cancel_incomplete(iso, fast_cancel):
    store = make_store(iso)  # a normal user: only the recorded pid is signalled
    iso.set_knobs(sleep=30, ignore_term=True)
    job_id, record = start(iso, store)
    assert len(wait_for_tree(record, 2)) == 2
    outcome = store.signal_job(record)
    try:
        assert outcome.state == "cancel_incomplete"
        assert outcome.remaining_pids and record["pid"] not in outcome.remaining_pids
        assert [s["signal"] for s in outcome.signals] == ["SIGTERM", "SIGKILL"]
    finally:
        for pid in outcome.remaining_pids:  # the orphaned stub sleep (ours)
            os.kill(pid, signal.SIGKILL)


# --- the terminal holder (L.6; V2/V3 D1: a non-root cancel did not stop an 11.x scan) ---------

def pipeline_done(iso, workspace: str = "app.scan.test") -> bool:
    return (iso.workspace_dir / workspace / "scans" / "pipeline-done.txt").exists()


def wait_front(record: dict) -> None:
    """Until the holder's sudo has started the 11.x-shaped stub: stub sudo, the stub
    CLI, its pipeline subshell, the subshell's sleep and the pipe reader."""
    for _ in range(200):
        tree = jobs._snapshot_tree(record["front_pid"], record["front_pid_starttime"])
        if len(tree) >= 5:
            return
        time.sleep(0.05)
    raise AssertionError("the stub engine did not start")


def test_a_sudo_scan_runs_under_the_terminal_holder(iso):
    """sudo gets a controlling terminal (the condition for use_pty), and the holder
    reports sudo's pid and ends with its exit status."""
    store = make_store(iso)
    iso.set_knobs(stdout="engine output", files=["scans/out.txt"], exit_status=3)
    job_id, record = start(iso, store, argv=sudo_argv(iso), sudo=True)
    assert record["launcher"] == "terminal"
    assert record["front_pid"] not in (None, record["pid"])
    assert isinstance(record["front_pid_starttime"], int)
    assert record["argv"] == sudo_argv(iso)  # the record and audit argv stay the scan's
    assert wait_exit(job_id) == 3  # the holder ends with sudo's (here the CLI's) status
    view = store.observe(record)
    assert (view.state, view.state_reason, view.exit_code) == ("failed", "exit_status", 3)
    assert "engine output" in (iso.state_dir / "jobs" / f"{job_id}.log").read_text()


def test_the_holder_gives_sudo_a_controlling_terminal(iso):
    store = make_store(iso)
    probe = iso.tmp / "tty-probe.sh"
    marker = iso.tmp / "tty.txt"
    # "true", not ":": a redirection error on a special built-in ends a POSIX shell.
    probe.write_text(f"#!/bin/sh\nif true < /dev/tty; then echo yes > {marker}; "
                     f"else echo no > {marker}; fi\n")
    probe.chmod(0o755)
    iso.set_knobs()
    job_id, _ = start(iso, store, argv=[str(iso.sudo_path), "-n", "--", str(probe)],
                      sudo=True)
    wait_exit(job_id)
    assert marker.read_text().strip() == "yes"
    marker.unlink()
    job_id, _ = start(iso, store, argv=[str(iso.sudo_path), "-n", "--", str(probe)])
    wait_exit(job_id)
    assert marker.read_text().strip() == "no"  # a direct launch has no terminal


def test_a_non_root_cancel_stops_an_11x_shaped_scan(iso, fast_cancel):
    """The 11.x CLI runs its scan body in a subshell piped to tee. With a terminal, sudo
    (here the stub with use_pty) relays SIGTERM to the whole process group: nothing of
    the scan survives and the body never reaches its end."""
    store = make_store(iso)
    iso.set_knobs(sleep=4, use_pty=True, pipeline=True, files=["scans/out.txt"])
    job_id, record = start(iso, store, argv=sudo_argv(iso), sudo=True)
    wait_front(record)
    tree = jobs._snapshot_tree(record["pid"], record["pid_starttime"])
    store.request_cancel(job_id)
    outcome = store.signal_job(store.load(job_id))
    assert outcome.state == "cancelled" and outcome.remaining_pids == []
    assert outcome.signals == [{"pid": record["front_pid"], "signal": "SIGTERM"}]
    assert not any(jobs.process_alive(pid, start) for pid, start in tree)
    time.sleep(5)  # longer than the body's sleep
    assert not pipeline_done(iso)
    assert store.observe(store.load(job_id)).state == "cancelled"


def test_without_the_terminal_the_same_cancel_leaves_the_body_running(iso, fast_cancel,
                                                                       monkeypatch):
    """Negative control: the defect the holder fixes. Launched without a terminal, the
    stub sudo relays SIGTERM to its direct child only, and the pipeline body survives."""
    store = make_store(iso)

    def without_terminal(argv, *, log_fd, home):
        return proc.Launched(proc.spawn_detached(argv, log_fd=log_fd, home=home), None,
                             "test: no terminal holder")

    monkeypatch.setattr(proc, "spawn_with_terminal", without_terminal)
    iso.set_knobs(sleep=30, use_pty=True, pipeline=True, files=["scans/out.txt"])
    job_id, record = start(iso, store, argv=sudo_argv(iso), sudo=True)
    assert record["launcher"] == "direct" and record["front_pid"] is None
    assert len(wait_for_tree(record, 5)) >= 5
    store.request_cancel(job_id)
    outcome = store.signal_job(store.load(job_id))
    try:
        assert outcome.state == "cancel_incomplete" and outcome.remaining_pids
        assert record["pid"] not in outcome.remaining_pids  # sudo itself went away
        store.record_cancel_outcome(job_id, outcome.state, outcome.survivors)
        view = store.observe(store.load(job_id))
        assert (view.state, view.state_reason) == ("running", "cancel_incomplete")
        assert jobs.cancel_survivors(store.load(job_id))
        assert "no terminal holder" in (iso.state_dir / "jobs" / f"{job_id}.log").read_text()
    finally:
        for pid in outcome.remaining_pids:
            os.kill(pid, signal.SIGKILL)


def test_the_hangup_of_the_holder_reaches_an_engine_without_use_pty(iso, fast_cancel):
    """sudo without use_pty (older sudo) relays SIGTERM to its direct child only; when the
    holder then ends, its terminal hangs up and the rest of the scan gets SIGHUP."""
    store = make_store(iso)
    iso.set_knobs(sleep=4, sudo_fork=True, pipeline=True, files=["scans/out.txt"])
    job_id, record = start(iso, store, argv=sudo_argv(iso), sudo=True)
    wait_front(record)
    tree = jobs._snapshot_tree(record["pid"], record["pid_starttime"])
    store.request_cancel(job_id)
    outcome = store.signal_job(store.load(job_id))
    assert outcome.state == "cancelled" and outcome.remaining_pids == []
    assert not any(jobs.process_alive(pid, start) for pid, start in tree)
    time.sleep(5)
    assert not pipeline_done(iso)


def test_a_job_whose_holder_died_stays_alive_through_its_sudo(iso, fast_cancel):
    """If the holder is killed, sudo keeps the scan running (use_pty ignores the hangup):
    the job is still running, and a cancel still reaches sudo."""
    store = make_store(iso)
    iso.set_knobs(sleep=30, use_pty=True, pipeline=True, files=["scans/out.txt"])
    job_id, record = start(iso, store, argv=sudo_argv(iso), sudo=True)
    wait_front(record)
    child = jobs.JOBS.pop(job_id)  # as if another server process had launched it
    try:
        os.kill(record["pid"], signal.SIGSTOP)  # the holder no longer counts...
        os.kill(record["pid"], signal.SIGKILL)  # ...and is gone; sudo is not
        child.process.wait(timeout=10)
        assert jobs.process_alive(record["front_pid"], record["front_pid_starttime"])
        assert store.observe(store.load(job_id)).state in ("starting", "running")
        assert [r["job_id"] for r in store.running()] == [job_id]
        store.request_cancel(job_id)
        outcome = store.signal_job(store.load(job_id))
        assert outcome.state == "cancelled" and outcome.remaining_pids == []
    finally:
        jobs.JOBS[job_id] = child


def test_the_holder_in_process_without_a_terminal_notes_it_and_reports_the_pid(iso, capfd):
    """The holder's no-terminal branch (this test process is no session leader, so it
    cannot take a controlling terminal): a log line, the command still runs."""
    read_fd, write_fd = os.pipe()
    try:
        status = proc._holder_main([proc.HOLDER_FLAG, str(write_fd), "--", str(iso.cli_path),
                                    "-t", "app.scan.test", "-m", "stealth", "-w", "w"])
        report = os.read(read_fd, 64)
    finally:
        os.close(read_fd)
    assert status == 0 and report.strip().isdigit()
    assert "no controlling terminal for sudo" in capfd.readouterr().out
    assert proc._holder_main(["--bogus"]) == 2


def test_the_tree_never_contains_the_server_or_its_ancestors():
    assert jobs._snapshot_tree(os.getpid(), None) == []
    assert jobs._snapshot_tree(os.getppid(), None) == []


class _KillRecorder:
    """Stands in for ``os.kill`` so a hardening test can never signal anything."""

    def __init__(self) -> None:
        self.calls: list[tuple[int, int]] = []

    def __call__(self, pid: int, sig: int) -> None:
        self.calls.append((pid, sig))


@pytest.mark.parametrize("euid", [None, 0])
@pytest.mark.parametrize("which", ["server", "parent", "session"])
def test_signal_job_never_signals_the_server_its_ancestors_or_its_session(
        iso, monkeypatch, euid, which):
    """L.6 step 3 hardening: a record naming the server's own lineage (tampered, or a
    reused pid) gets no signal on either branch, and the pid is never named."""
    store = make_store(iso, euid=euid)
    pid = {"server": os.getpid(), "parent": os.getppid()}.get(which)
    if pid is None:  # another process of the server's session: find one, else skip
        own_session = os.getsid(0)
        candidates = [p for p in jobs._process_table().values()
                      if p.session == own_session and p.pid not in (os.getpid(),)]
        if not candidates:
            pytest.skip("no other process in this session")
        pid = candidates[0].pid
    st = jobs.read_stat(pid)
    record = {"job_id": "0123456789abcdef", "pid": pid,
              "pid_starttime": st.starttime if st else None}
    recorder = _KillRecorder()
    monkeypatch.setattr(jobs.os, "kill", recorder)
    outcome = store.signal_job(record)
    assert recorder.calls == []
    assert outcome.state == "cancel_incomplete" and outcome.signals == []
    assert outcome.remaining_pids == [] and outcome.unverified


@pytest.mark.parametrize("euid", [None, 0])
def test_signal_job_needs_a_start_time_for_a_foreign_pid(iso, fast_cancel, monkeypatch, euid):
    """Without pid_starttime PID reuse cannot be ruled out: only our own unreaped child
    may still be signalled."""
    store = make_store(iso, euid=euid)
    iso.set_knobs(sleep=30)
    job_id, record = start(iso, store)
    foreign = dict(record, pid_starttime=None)
    child = jobs.JOBS.pop(job_id)  # as if another server process had launched it
    recorder = _KillRecorder()
    try:
        with monkeypatch.context() as patch:
            patch.setattr(jobs.os, "kill", recorder)
            outcome = store.signal_job(foreign)
        assert recorder.calls == [] and outcome.state == "cancel_incomplete"
        assert outcome.unverified and outcome.remaining_pids == []
    finally:
        jobs.JOBS[job_id] = child
    outcome = store.signal_job(foreign)  # our own child: the Popen handle is trusted
    assert outcome.state == "cancelled" and outcome.unverified is None


def test_scan_exit_lines_carry_the_writing_process_overrides(iso):
    settings = support.current_settings()
    assert state.prepare_state_dir(settings.state_dir).ok
    store = jobs.JobStore(state_dir=settings.state_dir, home=settings.home,
                          euid=settings.euid, workspace_dir=lambda: str(iso.workspace_dir),
                          audit=audit.AuditLog(settings.audit_log),
                          allow_any_target=True, allow_intrusive=True)
    job_id, record = start(iso, store)  # launched with allow_any_target false
    wait_exit(job_id)
    store.observe(record)
    exits = [r for r in audit_lines(iso) if r["event"] == "scan_exit"]
    assert len(exits) == 1
    assert exits[0]["allow_any_target"] is True and exits[0]["allow_intrusive"] is True


def test_cancel_never_runs_the_cli(iso, fast_cancel):
    store = make_store(iso)
    iso.set_knobs(sleep=30)
    job_id, record = start(iso, store)
    assert len(wait_for_tree(record, 2)) == 2  # the stub logged its argv and is sleeping
    store.request_cancel(job_id)
    assert store.signal_job(record).state == "cancelled"
    assert iso.calls("sniper") == [cli_argv(iso)]
    assert not any("-dt" in argv or "--delete-task" in argv for argv in iso.calls())


def test_a_deep_planted_tree_cannot_break_classification(iso, monkeypatch):
    """The loot tree is world-writable on CE: a local user may plant a very deep tree."""
    store = make_store(iso)
    iso.set_knobs(files=["scans/out.txt"])
    job_id, record = start(iso, store)
    wait_exit(job_id)
    deep = iso.workspace_dir / "app.scan.test"
    fd = os.open(deep, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for _ in range(120):
            os.mkdir("d", dir_fd=fd)
            child = os.open("d", os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = child
    finally:
        os.close(fd)

    def recursive_walk(*args, **kwargs):  # pragma: no cover - must not be used
        raise AssertionError("os.walk recurses on Python 3.11; use the iterative walk")

    with monkeypatch.context() as patched:
        patched.setattr(os, "walk", recursive_walk)
        view = store.observe(store.load(job_id))
    assert view.state == "succeeded" and view.summary["files_written"] >= 1


def test_src_never_builds_a_task_deletion_or_a_pattern_kill():
    """L.6 step 6: no argv element in src/ is ``-dt``, ``--delete-task``, ``pkill``,
    ``killall`` or ``kill`` (cancel signals pids itself; it never runs a program)."""
    import ast
    from pathlib import Path

    src = Path(__file__).resolve().parent.parent / "src" / "sniper_mcp"
    forbidden = {"-dt", "--delete-task", "pkill", "killall", "kill"}
    for path in sorted(src.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert node.value.strip() not in forbidden, (path, node.lineno, node.value)
