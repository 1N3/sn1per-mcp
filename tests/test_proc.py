# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Process creation (contract D.5, J.5, L.2, O.5 GAP-25)."""

from __future__ import annotations

import os
import time

import pytest

from sniper_mcp import paths, proc

SHELL_ADDED = {"PWD", "OLDPWD", "SHLVL", "_"}


def script(iso, name: str, body: str):
    path = iso.tmp / name
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)
    return str(path)


def test_minimal_env_is_fixed(iso):
    assert proc.minimal_env("/h") == {
        "PATH": paths.MINIMAL_ENV_PATH, "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8",
        "HOME": "/h", "TERM": "dumb"}


def test_detached_child_gets_only_the_minimal_env_and_its_own_session(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.example", CLIENT_SECRET_LIKE="must-not-leak")
    out = iso.tmp / "env.txt"
    exe = script(iso, "dump.sh",
                 f'env > "{out}"\npwd >> "{out}"\nread x || echo stdin-empty >> "{out}"\n')
    fd = os.open(str(iso.tmp / "log"), os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        child = proc.spawn_detached([exe], log_fd=fd, home=str(iso.home))
    finally:
        os.close(fd)
    assert os.getsid(child.pid) == child.pid
    assert child.wait(timeout=10) == 0
    lines = out.read_text().splitlines()
    env = dict(line.split("=", 1) for line in lines if "=" in line)
    for key in SHELL_ADDED:
        env.pop(key, None)
    assert env == proc.minimal_env(str(iso.home))
    assert lines[-2:] == ["/", "stdin-empty"]


def test_spawn_errors_are_launch_failed(iso):
    fd = os.open(str(iso.tmp / "log"), os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        with pytest.raises(proc.LaunchError) as raised:
            proc.spawn_detached([str(iso.tmp / "absent")], log_fd=fd, home=str(iso.home))
    finally:
        os.close(fd)
    assert raised.value.code == "launch_failed" and raised.value.cause == "FileNotFoundError"


def test_run_capture_with_input_and_timeout(iso):
    echo = script(iso, "echo.sh", "read line\necho got:$line\necho err >&2\nexit 3\n")
    result = proc.run_capture([echo], home=str(iso.home), timeout=10, input_bytes=b"y\n")
    assert (result.returncode, result.output, result.timed_out) == (3, b"got:y\nerr\n", False)
    slow = script(iso, "slow.sh", "sleep 30 &\nsleep 30\n")
    started = time.monotonic()
    result = proc.run_capture([slow], home=str(iso.home), timeout=0.5)
    assert result.timed_out and result.returncode is None
    assert time.monotonic() - started < 10


def test_run_capture_caps_output(iso):
    noisy = script(iso, "noisy.sh",
                   "i=0\nwhile [ $i -lt 2000 ]; do echo 0123456789; i=$((i+1)); done\n")
    result = proc.run_capture([noisy], home=str(iso.home), timeout=10, max_output=100)
    assert len(result.output) == 100 and result.output_truncated


@pytest.mark.parametrize("limit,expected", [
    ({"max_lines": 5, "max_bytes": 1 << 20, "timeout": 10}, "max_lines"),
    ({"max_lines": 10_000, "max_bytes": 64, "timeout": 10}, "max_bytes"),
])
def test_run_streaming_limits(iso, limit, expected):
    lines = script(iso, "lines.sh",
                   "i=0\nwhile [ $i -lt 5000 ]; do echo line$i; i=$((i+1)); done\n")
    result = proc.run_streaming([lines], home=str(iso.home), cwd=str(iso.tmp), **limit)
    assert result.stopped_reason == expected and result.returncode is None
    if expected == "max_lines":
        assert result.output.splitlines() == [f"line{i}".encode() for i in range(5)]
    else:
        assert len(result.output) == 64


def test_run_streaming_timeout_kills_the_group(iso):
    hang = script(iso, "hang.sh", "echo first\nsleep 30\n")
    started = time.monotonic()
    result = proc.run_streaming([hang], home=str(iso.home), cwd=str(iso.tmp), max_lines=10,
                                max_bytes=1000, timeout=0.5)
    assert result.stopped_reason == "timeout" and result.output == b"first\n"
    assert time.monotonic() - started < 10


def test_run_streaming_complete(iso):
    done = script(iso, "done.sh", "echo a\necho b\nexit 1\n")
    result = proc.run_streaming([done], home=str(iso.home), cwd=str(iso.tmp), max_lines=10,
                                max_bytes=1000, timeout=10)
    assert (result.stopped_reason, result.returncode, result.output) == ("complete", 1, b"a\nb\n")


@pytest.mark.parametrize("limit", [{"max_lines": 2, "max_bytes": 1000},
                                   {"max_lines": 10, "max_bytes": 4}])
def test_run_streaming_output_ending_exactly_at_a_limit_is_complete(iso, limit, monkeypatch):
    # grep exit status 2 (unreadable entries) must survive when the output simply ended
    # at max_lines or max_bytes. A long probe keeps a loaded test host from flaking.
    monkeypatch.setattr(proc, "_EOF_PROBE_SECONDS", 5.0)
    exact = script(iso, "exact.sh", "echo a\necho b\nexit 2\n")
    result = proc.run_streaming([exact], home=str(iso.home), cwd=str(iso.tmp), timeout=10,
                                **limit)
    assert (result.stopped_reason, result.returncode, result.output) == ("complete", 2,
                                                                         b"a\nb\n")


def test_run_streaming_at_a_limit_with_a_live_child_is_truncated(iso):
    held = script(iso, "held.sh", "echo a\necho b\nsleep 30\n")
    started = time.monotonic()
    result = proc.run_streaming([held], home=str(iso.home), cwd=str(iso.tmp), max_lines=2,
                                max_bytes=1000, timeout=10)
    assert (result.stopped_reason, result.returncode) == ("max_lines", None)
    assert time.monotonic() - started < 5


def records_script(iso, body: str) -> str:
    """A command that prints grep -Z style records (name NUL line:text newline)."""
    return script(iso, "records.sh", body)


def test_run_streaming_cuts_each_record_and_keeps_the_framing(iso):
    """V2 D2: a huge record is cut to max_record_bytes while it streams in; the rest of its
    line is dropped, it keeps its newline, and the records after it are still read."""
    printer = records_script(iso, (
        "printf './a.txt\\0001:first\\n'\n"
        "printf './big.txt\\0002:'; head -c 200000 /dev/zero | tr '\\0' x; printf '\\n'\n"
        "printf './c.txt\\0003:last\\n'\n"))
    result = proc.run_streaming([printer], home=str(iso.home), cwd=str(iso.tmp),
                                max_lines=10, max_bytes=1 << 20, timeout=10,
                                nul_framed=True, max_record_bytes=100, max_raw_bytes=1 << 22)
    assert result.stopped_reason == "complete" and result.lines == 3
    records = result.output.split(b"\n")[:-1]
    assert records[0] == b"./a.txt\x001:first" and records[2] == b"./c.txt\x003:last"
    assert len(records[1]) == 100 and records[1].startswith(b"./big.txt\x002:xxx")


def test_run_streaming_counts_only_kept_bytes_and_stops_at_the_raw_cap(iso):
    printer = records_script(iso, (
        "i=0\nwhile [ $i -lt 50 ]; do printf './f\\000%d:' $i; "
        "head -c 5000 /dev/zero | tr '\\0' y; printf '\\n'; i=$((i+1)); done\n"))
    kept = proc.run_streaming([printer], home=str(iso.home), cwd=str(iso.tmp),
                              max_lines=100, max_bytes=1 << 20, timeout=10, nul_framed=True,
                              max_record_bytes=20, max_raw_bytes=1 << 22)
    assert kept.stopped_reason == "complete" and kept.lines == 50
    assert len(kept.output) <= 50 * 21  # 20 kept bytes plus the newline per record
    raw = proc.run_streaming([printer], home=str(iso.home), cwd=str(iso.tmp),
                             max_lines=100, max_bytes=1 << 20, timeout=10, nul_framed=True,
                             max_record_bytes=20, max_raw_bytes=60_000)
    assert raw.stopped_reason == "max_bytes" and 5 <= raw.lines < 50


def test_run_streaming_reports_which_records_were_cut(iso):
    """RC R1: grep_loot marks a line cut while streaming, so the reader must learn which
    kept records lost the rest of their line (and that a line of exactly the cap did not)."""
    printer = records_script(iso, (
        "printf './a.txt\\0001:short\\n'\n"
        "printf './big.txt\\0002:'; head -c 5000 /dev/zero | tr '\\0' x; printf '\\n'\n"
        "printf './c.txt\\0003:also short\\n'\n"
        "printf './d.txt\\0004:'; head -c 5000 /dev/zero | tr '\\0' y; printf '\\n'\n"
        "printf './e.txt\\0005:'; head -c 90 /dev/zero | tr '\\0' z; printf '\\n'\n"))
    result = proc.run_streaming([printer], home=str(iso.home), cwd=str(iso.tmp),
                                max_lines=10, max_bytes=1 << 20, timeout=10,
                                nul_framed=True, max_record_bytes=100, max_raw_bytes=1 << 20)
    assert result.stopped_reason == "complete" and result.lines == 5
    assert result.cut_records == (1, 3)
    records = result.output.split(b"\n")[:-1]
    assert [len(r) for r in records] == [15, 100, 20, 100, 100]  # e.txt fits exactly
    plain = proc.run_streaming([printer], home=str(iso.home), cwd=str(iso.tmp),
                               max_lines=10, max_bytes=1 << 20, timeout=10)
    assert plain.cut_records == ()


def test_run_streaming_drops_a_record_whose_name_is_past_the_cap(iso):
    printer = records_script(iso, (
        "printf './%s\\0001:hit\\n' $(head -c 300 /dev/zero | tr '\\0' n)\n"
        "printf './b.txt\\0002:hit\\n'\n"))
    result = proc.run_streaming([printer], home=str(iso.home), cwd=str(iso.tmp),
                                max_lines=10, max_bytes=1 << 20, timeout=10,
                                nul_framed=True, max_record_bytes=100, max_raw_bytes=1 << 20)
    assert result.lines == 2 and result.output == b"./b.txt\x002:hit\n"


def test_resolve_sudo_ok_missing_untrusted(iso, monkeypatch):
    assert proc.resolve_sudo() == proc.SudoInfo(path=os.path.realpath(iso.sudo_path),
                                                status="ok")
    iso.sudo_path.chmod(0o777)
    assert proc.resolve_sudo().status == "untrusted"
    iso.sudo_path.chmod(0o755)
    monkeypatch.setattr(paths, "TRUSTED_UID", os.geteuid() + 1)
    assert proc.resolve_sudo().status == "untrusted"
    monkeypatch.setattr(paths, "SUDO", str(iso.tmp / "no-sudo-here"))
    iso.setenv(PATH=str(iso.tmp / "empty-path"))
    assert proc.resolve_sudo().status == "missing"


def test_resolve_sudo_returns_the_realpath_of_a_path_symlink(iso, monkeypatch):
    """D.5: the argv names the checked file itself, never a swappable symlink."""
    link_dir = iso.tmp / "link-bin"
    link_dir.mkdir()
    (link_dir / "sudo").symlink_to(iso.sudo_path)
    monkeypatch.setattr(paths, "SUDO", str(iso.tmp / "no-sudo-here"))
    iso.setenv(PATH=str(link_dir))
    info = proc.resolve_sudo()
    assert info == proc.SudoInfo(path=os.path.realpath(iso.sudo_path), status="ok")


def test_resolve_sudo_is_resolved_once(iso, monkeypatch):
    """D.5: resolved once; a sudo that appears on PATH later is not picked up."""
    monkeypatch.setattr(paths, "SUDO", str(iso.tmp / "no-sudo-here"))
    late_dir = iso.tmp / "late-bin"
    late_dir.mkdir()
    iso.setenv(PATH=str(late_dir))
    assert proc.resolve_sudo().status == "missing"
    (late_dir / "sudo").symlink_to(iso.sudo_path)
    assert proc.resolve_sudo().status == "missing"


def test_sudo_preflight(iso):
    assert proc.sudo_preflight(str(iso.sudo_path), str(iso.cli_path), home=str(iso.home))
    iso.set_knobs(sudo_list_exit=1)
    assert not proc.sudo_preflight(str(iso.sudo_path), str(iso.cli_path), home=str(iso.home))
    iso.set_knobs(sudo_password_required=True)
    assert not proc.sudo_preflight(str(iso.sudo_path), str(iso.cli_path), home=str(iso.home))
    assert not proc.sudo_preflight(str(iso.tmp / "absent"), str(iso.cli_path),
                                   home=str(iso.home))
    assert all(argv[1:] == ["-n", "-l", str(iso.cli_path)] for argv in iso.calls("sudo"))


def test_run_capture_keeps_the_tail_when_asked(iso):
    noisy = script(iso, "counting.sh",
                   "i=0\nwhile [ $i -lt 500 ]; do echo line$i; i=$((i+1)); done\n")
    result = proc.run_capture([noisy], home=str(iso.home), timeout=10, max_output=20,
                              keep="tail")
    assert result.output_truncated and result.output == b"497\nline498\nline499\n"
    with pytest.raises(ValueError):
        proc.run_capture([noisy], home=str(iso.home), timeout=10, keep="middle")


def test_run_capture_does_not_wait_for_a_process_outside_the_group(iso, monkeypatch):
    """After the timeout kill, a process the kill cannot reach (a root engine under sudo)
    may hold the pipe open; the call returns after a bounded drain instead of waiting."""
    monkeypatch.setattr(proc, "_DRAIN_SECONDS", 0.5)
    pidfile = iso.tmp / "escaped.pid"
    escaped = script(iso, "escaped.sh",
                     f"echo before\nsetsid sh -c 'echo $$ > {pidfile}; exec sleep 30' &\n"
                     "sleep 30\n")
    started = time.monotonic()
    try:
        result = proc.run_capture([escaped], home=str(iso.home), timeout=0.5)
        elapsed = time.monotonic() - started
    finally:
        for _ in range(50):
            if pidfile.exists() and pidfile.read_text().strip():
                break
            time.sleep(0.05)
        if pidfile.exists() and pidfile.read_text().strip():
            try:
                os.kill(int(pidfile.read_text()), 9)
            except ProcessLookupError:
                pass
    assert result.timed_out and result.returncode is None
    assert result.output == b"before\n"
    assert elapsed < 5
