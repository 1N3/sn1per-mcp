# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""The incident-proof guard (contract O.1-O.3, O.5 INCIDENT rows 3-5, O.2 meta-tests).

This is the only test module allowed to import ``expect_violation`` (meta-test
below). Every blocked call here is made on purpose and consumed.
"""

from __future__ import annotations

import ast
import json
import os
import re
import socket
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from sniper_mcp import proc
from tests import realpaths
from tests.guard import hook
from tests.guard.expect import expect_child_violation, expect_violation

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src" / "sniper_mcp"
TESTS = REPO / "tests"


def _py_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


# --- Layer 1 is installed ----------------------------------------------------

def test_guard_is_installed_for_the_session():
    state = hook.state()
    assert state is not None and state.mode == "pytest"
    assert state.temp_root and state.repo_root == str(REPO)


# --- INCIDENT row (3): each blocked call raises and is recorded ----------------

def test_popen_of_real_sudo_is_blocked():
    with expect_violation("process") as record, pytest.raises(hook.RealExecutionBlocked):
        subprocess.Popen([realpaths.SUDO_BIN, "-n", "true"])
    assert "sudo" in record.violations[0].detail


def test_stale_popen_binding_with_real_engine_argv_is_blocked():
    from subprocess import Popen as StalePopen

    with expect_violation("process"), pytest.raises(hook.RealExecutionBlocked):
        StalePopen([realpaths.SNIPER_SHARE_CLI, "-t", "app.example", "-m", "stealth"])


def test_engine_path_as_any_argument_is_blocked():
    with expect_violation("process"), pytest.raises(hook.RealExecutionBlocked):
        subprocess.Popen([realpaths.TRUE_BIN, realpaths.SNIPER_SHARE_CLI])


def test_os_posix_spawn_is_blocked():
    with expect_violation("process"), pytest.raises(hook.RealExecutionBlocked):
        os.posix_spawn(realpaths.TRUE_BIN, [realpaths.TRUE_BIN], {})


@pytest.mark.parametrize("call", ["fork", "system", "execv"])
def test_other_process_apis_are_blocked(call):
    with expect_violation("process"), pytest.raises(hook.RealExecutionBlocked):
        if call == "fork":
            os.fork()
        elif call == "system":
            os.system("true")
        else:
            os.execv(realpaths.TRUE_BIN, [realpaths.TRUE_BIN])


def test_python_child_without_guard_path_is_blocked():
    with expect_violation("process") as record, pytest.raises(hook.RealExecutionBlocked):
        subprocess.Popen([sys.executable, "-c", "pass"], env={"PATH": "/nonexistent"})
    assert "PYTHONPATH" in record.violations[0].detail


def test_python_child_with_isolation_flag_is_blocked(iso):
    env = iso.child_env()
    with expect_violation("process"), pytest.raises(hook.RealExecutionBlocked):
        subprocess.Popen([sys.executable, "-I", "-c", "pass"], env=env)


@pytest.mark.parametrize("argv", [
    ["--check-hash-based-pycs", "default", "-I", "-c", "pass"],
    ["--check-hash-based-pycs", "default", "-E", "-c", "pass"],
    ["--unknown-long-option", "-c", "pass"],
    ["-X", "dev", "--check-hash-based-pycs", "always", "-S", "-c", "pass"],
])
def test_python_child_flags_behind_a_long_option_are_blocked(iso, argv):
    """Review round 2: --check-hash-based-pycs takes an argument, so the flag scan
    must skip that argument and keep going; an unknown long option fails closed."""
    with expect_violation("process"), pytest.raises(hook.RealExecutionBlocked):
        subprocess.Popen([sys.executable, *argv], env=iso.child_env())


def test_python_child_with_an_allowed_long_option_runs_guarded(iso):
    code = "import sys; print(sys._sn1per_mcp_test_guard_state.mode)"
    result = subprocess.run([sys.executable, "--check-hash-based-pycs", "default", "-c", code],
                            env=iso.child_env(), capture_output=True, text=True, timeout=60,
                            check=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "child"


def test_dns_lookup_is_blocked():
    with expect_violation("network"), pytest.raises(hook.NetworkBlocked):
        socket.getaddrinfo("app.example", None)


def test_inet_connect_is_blocked():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with expect_violation("network"), pytest.raises(hook.NetworkBlocked):
            sock.connect(("192.0.2.10", 80))
    finally:
        sock.close()


def test_open_of_real_engine_file_is_blocked():
    with expect_violation("file"), pytest.raises(hook.RealExecutionBlocked):
        open(realpaths.SNIPER_SHARE_CLI)  # noqa: SIM115


def test_open_of_real_home_file_is_blocked():
    real_home = os.path.realpath(os.path.expanduser("~" + _user_name()))
    if real_home == "/":
        pytest.skip("this account has no home directory")
    with expect_violation("file"), pytest.raises(hook.RealExecutionBlocked):
        os.open(os.path.join(real_home, ".sniper.conf"), os.O_RDONLY)


def test_listing_of_real_loot_is_blocked():
    with expect_violation("file"), pytest.raises(hook.RealExecutionBlocked):
        os.listdir(realpaths.SNIPER_SHARE_WORKSPACE)


def test_proc_spawn_of_real_engine_is_launch_failed_and_still_fails_the_session(iso):
    fd = os.open(str(iso.tmp / "job.log"), os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        with expect_violation("process") as record:
            with pytest.raises(proc.LaunchError) as raised:
                proc.spawn_detached([realpaths.SNIPER_SHARE_CLI, "-t", "app.example"],
                                    log_fd=fd, home=str(iso.home))
            assert raised.value.code == "launch_failed"
            assert raised.value.cause == "RealExecutionBlocked"
            # Caught by production code, yet still recorded: outside this block the
            # session would fail (contract O.2).
            pending = record.pending()
            assert pending and "sniper" in pending[0].detail
    finally:
        os.close(fd)


def test_allowed_spawns_still_work(iso):
    script = iso.tmp / "hello.sh"
    script.write_text("#!/bin/sh\necho hello\n")
    script.chmod(0o755)
    result = proc.run_capture([str(script)], home=str(iso.home), timeout=10)
    assert result.output == b"hello\n"
    assert subprocess.run([realpaths.TRUE_BIN], check=False).returncode == 0


# --- process creation without an audit event -----------------

def test_direct_fork_exec_is_blocked():
    import _posixsubprocess

    true_bin = os.fsencode(realpaths.TRUE_BIN)
    with expect_violation("process") as record, pytest.raises(hook.RealExecutionBlocked):
        _posixsubprocess.fork_exec([true_bin], [true_bin])
    assert record.violations[0].event == "_posixsubprocess.fork_exec"


def test_subprocess_private_fork_exec_binding_is_blocked():
    fork_exec = getattr(subprocess, "_fork_exec", None)
    if fork_exec is None:
        pytest.skip("this Python's subprocess has no _fork_exec binding")
    true_bin = os.fsencode(realpaths.TRUE_BIN)
    with expect_violation("process"), pytest.raises(hook.RealExecutionBlocked):
        fork_exec([true_bin], [true_bin])


@pytest.mark.parametrize("method", [None, "spawn", "forkserver", "fork"])
def test_multiprocessing_process_is_blocked(method):
    import multiprocessing

    if method is not None and method not in multiprocessing.get_all_start_methods():
        pytest.skip(f"start method {method} is not available")
    process = multiprocessing.get_context(method).Process(target=int)
    with expect_violation("process") as record, pytest.raises(hook.RealExecutionBlocked):
        process.start()
    assert record.violations[0].event == "multiprocessing.Process.start"


def test_multiprocessing_spawn_helper_is_blocked_below_process_start():
    """The spawn and forkserver start methods reach fork_exec through this helper."""
    from multiprocessing import util

    with expect_violation("process") as record, pytest.raises(hook.RealExecutionBlocked):
        util.spawnv_passfds(sys.executable, [sys.executable, "-c", "pass"], ())
    assert record.violations[0].event == "_posixsubprocess.fork_exec"


def test_popen_on_the_with_cwd_still_works(iso):
    """cwd and start_new_session make subprocess use fork_exec instead of posix_spawn."""
    child = subprocess.Popen([realpaths.TRUE_BIN], cwd=str(iso.tmp), start_new_session=True)
    assert child.wait(timeout=30) == 0
    child = subprocess.Popen([sys.executable, "-c", "pass"], cwd=str(iso.tmp),
                             start_new_session=True, env=iso.child_env())
    assert child.wait(timeout=60) == 0


@pytest.mark.parametrize("broken", ["no-shebang", "missing-interpreter", "not-executable"])
@pytest.mark.parametrize("with_cwd", [False, True])
def test_approved_stub_that_fails_to_exec_never_falls_through_the_path(iso, broken,
                                                                        with_cwd):
    """Review round 2: _posixsubprocess tries every executable_list entry and goes on
    after ENOEXEC, ENOENT or EACCES. The approved temp-root stub must be the only
    candidate, so a later PATH entry (a real sudo or sniper on a host) never runs.
    Here the later entry is a harmless marker script inside the temp root."""
    first, second = iso.tmp / "a", iso.tmp / "b"
    first.mkdir()
    second.mkdir()
    marker = iso.tmp / "fell-through"
    later = second / "tool"
    later.write_text(f"#!/bin/sh\necho ran > '{marker}'\n")
    later.chmod(0o755)
    stub = first / "tool"
    if broken == "no-shebang":
        stub.write_text("this is not a program\n")
    elif broken == "missing-interpreter":
        stub.write_text("#!/nonexistent/interpreter\n")
    else:
        stub.write_text("#!/bin/sh\nexit 0\n")
    stub.chmod(0o644 if broken == "not-executable" else 0o755)
    env = {"PATH": f"{first}:{second}"}
    kwargs = {"cwd": str(iso.tmp), "start_new_session": True} if with_cwd else {}
    if broken == "not-executable":
        # which() skips the non-executable stub and approves b/tool; the call runs
        # exactly the approved file.
        subprocess.run(["tool"], env=env, check=True, timeout=60, **kwargs)
        assert marker.read_text() == "ran\n"
        return
    with pytest.raises(OSError):
        subprocess.run(["tool"], env=env, check=False, timeout=60, **kwargs)
    assert not marker.exists()


def _relative_path_trap(iso, monkeypatch):
    """Two directories with a bin/tool each: A's is harmless, C's leaves a marker.

    The parent runs in A; the child is asked to run in C. An earlier guard
    judged relative names against A while the child
    resolved them against C (or wherever a preexec_fn moved it).
    """
    marker = iso.tmp / "wrong-file-ran"
    for name, body in (("A", "#!/bin/sh\nexit 0\n"),
                       ("C", f"#!/bin/sh\necho ran > '{marker}'\n")):
        tool = iso.tmp / name / "bin" / "tool"
        tool.parent.mkdir(parents=True)
        tool.write_text(body)
        tool.chmod(0o755)
    monkeypatch.chdir(iso.tmp / "A")
    return iso.tmp / "A", iso.tmp / "C", marker


def test_relative_path_entry_is_blocked(iso, monkeypatch):
    _, c_dir, marker = _relative_path_trap(iso, monkeypatch)
    with expect_violation("process") as record, pytest.raises(hook.RealExecutionBlocked):
        subprocess.Popen(["tool"], env={"PATH": "bin"}, cwd=str(c_dir),
                         start_new_session=True)
    assert "relative entry" in record.violations[0].detail
    with expect_violation("process"), pytest.raises(hook.RealExecutionBlocked):
        subprocess.Popen(["tool"], env={"PATH": f"{iso.tmp / 'A' / 'bin'}:"},
                         cwd=str(c_dir), start_new_session=True)
    assert not marker.exists()


def test_preexec_fn_is_blocked(iso, monkeypatch):
    a_dir, c_dir, marker = _relative_path_trap(iso, monkeypatch)
    with expect_violation("process") as record, pytest.raises(hook.RealExecutionBlocked):
        subprocess.Popen(["bin/tool"], cwd=str(a_dir), preexec_fn=lambda: os.chdir(c_dir))
    assert record.violations[0].event == "_posixsubprocess.fork_exec"
    assert not marker.exists()


def test_relative_executable_with_cwd_runs_exactly_the_approved_file(iso, monkeypatch):
    _, c_dir, marker = _relative_path_trap(iso, monkeypatch)
    # The guard resolves bin/tool against cwd (C), approves C's tool and execs that
    # absolute path, which is what the child would have run.
    subprocess.run(["bin/tool"], cwd=str(c_dir), check=True, timeout=60,
                   start_new_session=True)
    assert marker.read_text() == "ran\n"


# Run in a guarded child whose temp root is a sub-directory of this test's directory, so
# the marker scripts can sit outside the child's temp root (standing in for a real
# binary) while every write stays inside this test's own directory (O.1).
#
# The pinned grep reaches a probe through its environment (PROBE_GREP_ENV), never as an
# argument: the guard allows an existing path as an argument only inside the temp root,
# the repository or the interpreter's prefixes, and only an interpreter installed under
# /usr (a distribution Python) has the grep binary inside its base prefix. A Python from
# actions/setup-python or uv lives elsewhere (E1 of the 0.9.0 readiness report).
PROBE_GREP_ENV = "PROBE_GREP"


def _probe_env(child_root: Path) -> dict[str, str]:
    """The environment of a guarded probe child: the guard, its own temp root, a minimal
    PATH and the pinned grep (by name, so no argument names a system binary)."""
    return hook.child_env(str(child_root), str(REPO),
                          {"PATH": realpaths.MINIMAL_ENV_PATH,
                           PROBE_GREP_ENV: realpaths.GREP_BIN})


_OUTSIDE_PROBE = textwrap.dedent("""
    import functools
    import os
    import subprocess
    import sys

    outside, mirror = sys.argv[1], sys.argv[2]
    grep = os.environ["PROBE_GREP"]
    # Harmless stubs inside this child's temp root: one at the same relative path from
    # its working directory as the marker directory has from "/", one under bin/. An
    # earlier guard judged relative names against this process's directory and approved
    # these stubs, while the child process resolved them elsewhere.
    relative = os.path.relpath(os.path.join(outside, "bin"), "/")
    for directory in (os.path.join(mirror, relative), os.path.join(mirror, "bin")):
        os.makedirs(directory, exist_ok=True)
        for name in ("tool", "sudo"):
            stub = os.path.join(directory, name)
            with open(stub, "w") as handle:
                handle.write("#!/bin/sh\\nexit 0\\n")
            os.chmod(stub, 0o755)
    os.chdir(mirror)
    # /proc/self/cwd names this process's directory (the mirror) when the guard looks,
    # and the child's ("/") once it has changed to cwd.
    through_cwd = "/proc/self/cwd/" + relative
    link = os.path.join(mirror, "link-tool")
    os.symlink(through_cwd + "/tool", link)
    # The kernel applies ".." to the target of the link before it; the lexical form of
    # "<link>/.." (or of "/proc/self/cwd/..") has lost the link.
    link_dir = os.path.join(mirror, "link-dir")
    os.symlink(through_cwd + "/sub", link_dir)
    stub_tool = os.path.join(mirror, "bin", "tool")
    outside_bin = os.path.join(outside, "bin")


    def with_fd(path, call):
        fd = os.open(path, os.O_RDONLY)
        try:
            return call(fd)
        finally:
            os.close(fd)


    def own_stdin(path, call):
        # This process's own fd 0 is a temp-root file or directory, so the guard sees a
        # temp-root path in /proc/self/fd/0 where the child sees the stdin= it is given.
        saved = os.dup(0)
        fd = os.open(path, os.O_RDONLY)
        os.dup2(fd, 0)
        os.close(fd)
        try:
            return call()
        finally:
            os.dup2(saved, 0)
            os.close(saved)


    attempts = {
        "relative-entry": lambda: subprocess.run(
            ["tool"], cwd="/", env={"PATH": relative}, timeout=30),
        "dot-relative-entry": lambda: subprocess.run(
            ["tool"], cwd="/", env={"PATH": "./" + relative}, timeout=30),
        "empty-entry": lambda: subprocess.run(
            ["tool"], cwd="/", env={"PATH": ":" + os.path.join(mirror, "bin")}, timeout=30),
        "preexec-chdir-sudo": lambda: subprocess.run(
            ["bin/sudo", "-n", "true"], preexec_fn=lambda: os.chdir(outside), timeout=30),
        "preexec-partial": lambda: subprocess.run(
            ["bin/tool"], preexec_fn=functools.partial(os.chdir, outside), timeout=30),
        "preexec-with-cwd": lambda: subprocess.run(
            ["bin/tool"], cwd=mirror, preexec_fn=lambda: os.chdir(outside), timeout=30),
        "proc-self-cwd-executable": lambda: subprocess.run(
            [through_cwd + "/tool"], cwd="/", timeout=30),
        "proc-thread-self-cwd-executable": lambda: subprocess.run(
            ["/proc/thread-self/cwd/" + relative + "/tool"], cwd="/", timeout=30),
        "proc-self-cwd-path-entry": lambda: subprocess.run(
            ["tool"], cwd="/", env={"PATH": through_cwd}, timeout=30),
        "link-through-proc-self-cwd": lambda: subprocess.run([link], cwd="/", timeout=30),
        "grep-reads-through-proc-self-cwd": lambda: subprocess.run(
            [grep, "-c", "ran", through_cwd + "/tool"], cwd="/", capture_output=True,
            timeout=30),
        "grep-reads-through-proc-self-cwd-dotdot": lambda: subprocess.run(
            [grep, "-c", "ran", "/proc/self/cwd/../" + relative + "/tool"], cwd="/",
            capture_output=True, timeout=30),
        "grep-reads-through-thread-self-cwd-dotdot": lambda: subprocess.run(
            [grep, "-c", "ran", "/proc/thread-self/cwd/../" + relative + "/tool"], cwd="/",
            capture_output=True, timeout=30),
        "grep-reads-through-a-link-then-dotdot": lambda: subprocess.run(
            [grep, "-c", "ran", os.path.join(link_dir, "..", "tool")], cwd="/",
            capture_output=True, timeout=30),
        "grep-reads-through-a-redirected-stdin": lambda: with_fd("/", lambda fd: (
            subprocess.run([grep, "-c", "ran", "/proc/self/fd/0/" + relative + "/tool"],
                           stdin=fd, capture_output=True, timeout=30))),
        "exec-through-a-redirected-stdin": lambda: own_stdin(stub_tool, lambda: with_fd(
            os.path.join(outside_bin, "tool"),
            lambda fd: subprocess.run(["/proc/self/fd/0"], stdin=fd, timeout=30))),
        "cwd-through-a-redirected-stdin": lambda: own_stdin(os.path.dirname(stub_tool), (
            lambda: with_fd(outside_bin, lambda fd: subprocess.run(
                ["./tool"], cwd="/proc/self/fd/0", stdin=fd, timeout=30)))),
    }
    for name, call in attempts.items():
        try:
            done = call()
        except Exception as exc:
            print(name, type(exc).__name__)
        else:
            # A grep that ran prints how many marker lines it read outside the roots.
            out = (getattr(done, "stdout", None) or b"").decode().strip()
            print(name, "read:" + out if out else "ran")
""")


def test_no_exec_escapes_the_temp_root_through_cwd_tricks(iso):
    """S1 review round 2, as reported: (A) a relative or empty PATH entry with cwd "/"
    and a temp-root stub at the same relative path, and (B) a preexec_fn that changes
    directory before a relative executable is run. Fix phase, same class: an
    executable, a PATH entry, a temp-root link or a grep argument that goes through
    /proc/self/cwd or /proc/thread-self/cwd. Fix round 2, as reported: grep arguments
    with ".." right after such a link, or after a temp-root link that points through
    it (the guard had normalized the ".." away before it looked), and through a
    standard-descriptor link (/proc/self/fd/0 names the child's redirected stdin),
    which also ran an outside file as the executable and as cwd. The marker scripts
    outside the child's temp root stand in for /usr/bin/<name> and a real sudo; none
    may run or be read, and every attempt must raise RealExecutionBlocked and be
    recorded."""
    outside = iso.tmp / "outside"
    (outside / "bin" / "sub").mkdir(parents=True)
    for name in ("tool", "sudo"):
        script = outside / "bin" / name
        script.write_text(f"#!/bin/sh\necho ran > '{outside / ('ran-' + name)}'\n")
        script.chmod(0o755)
    child_root = iso.tmp / "child-root"
    child_root.mkdir(mode=0o700)
    mirror = child_root / "mirror"
    mirror.mkdir()
    with expect_child_violation(str(child_root), "process") as children:
        result = subprocess.run([sys.executable, "-c", _OUTSIDE_PROBE, str(outside),
                                 str(mirror)],
                                env=_probe_env(child_root), capture_output=True, text=True,
                                timeout=120, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    outcomes = dict(line.split() for line in result.stdout.splitlines())
    assert outcomes == dict.fromkeys(
        ("relative-entry", "dot-relative-entry", "empty-entry", "preexec-chdir-sudo",
         "preexec-partial", "preexec-with-cwd", "proc-self-cwd-executable",
         "proc-thread-self-cwd-executable", "proc-self-cwd-path-entry",
         "link-through-proc-self-cwd", "grep-reads-through-proc-self-cwd",
         "grep-reads-through-proc-self-cwd-dotdot",
         "grep-reads-through-thread-self-cwd-dotdot",
         "grep-reads-through-a-link-then-dotdot", "grep-reads-through-a-redirected-stdin",
         "exec-through-a-redirected-stdin", "cwd-through-a-redirected-stdin"),
        "RealExecutionBlocked"), outcomes
    assert sorted(path.name for path in outside.iterdir()) == ["bin"]  # no marker ran
    details = [str(item.get("detail")) for item in children]
    assert len(children) == len(outcomes), details  # one recorded violation per attempt
    assert sum("relative entry" in detail for detail in details) == 3, details
    assert sum(item.get("event") == "_posixsubprocess.fork_exec" for item in children) == 3
    assert sum("through a process's cwd, root or standard-descriptor link" in detail
               for detail in details) == 11, details


# FR2 (fix-review-2-0.9.0.md), the same S1 class: the guard judged env through env.get()
# and a path-like argument through its first answers, while the child got env.items() and
# CPython's C conversion. Each attempt below would start an unguarded (or widened) Python
# child that runs the outside marker, or make grep read the outside file.
_DIVERGENCE_PROBE = textwrap.dedent("""
    import json
    import os
    import subprocess
    import sys

    outside, mirror, wider = sys.argv[1], sys.argv[2], sys.argv[3]
    grep = os.environ["PROBE_GREP"]
    state = sys._sn1per_mcp_test_guard_state
    guard = os.environ["PYTHONPATH"].split(os.pathsep)[0]
    variable = "SN1PER_MCP_TEST_GUARD"
    mark = os.path.join(outside, "bin", "mark")
    secret = os.path.join(outside, "bin", "secret.txt")
    inside = os.path.join(mirror, "inside.txt")
    with open(inside, "w") as handle:
        handle.write("inside\\n")
    empty = os.path.join(mirror, "empty")
    os.makedirs(empty, exist_ok=True)
    valid = json.dumps({"temp_root": state.temp_root, "repo_root": state.repo_root})
    # Names the parent of this child's temp root: valid for a child of its own, but a
    # parent may only forward its own temp root or a directory inside it.
    widened = json.dumps({"temp_root": wider, "repo_root": state.repo_root})
    base = {"PATH": os.environ["PATH"], "PYTHONPATH": guard, variable: valid}


    def grandchild(name, flag=None, **kwargs):
        # The marker path travels inside the code text: as an argument of its own the
        # guard would refuse it (a path outside this child's roots).
        code = ("import subprocess, sys\\n"
                f"run = subprocess.run([{mark!r}, {name!r}], timeout=30).returncode\\n"
                "print('guard', hasattr(sys, '_sn1per_mcp_test_guard_state'), 'run', run)\\n")
        flags = [] if flag is None else [flag]
        return subprocess.run([sys.executable, *flags, "-c", code], capture_output=True,
                              timeout=60, **kwargs)


    class Lying(dict):
        # get() names the guard; items(), which the child gets, the empty directory.
        def get(self, key, default=None):
            if key in ("PYTHONPATH", b"PYTHONPATH"):
                return guard
            return dict.get(self, key, default)


    class Flip:
        # Answers "used" on the conversions numbered first..last (1-based), "judged" on
        # every other one. The numbers follow the reviewed guard (41f2db4): it converted
        # an argument at the Popen check (1) and for its approval (2); the fork_exec
        # wrapper compared it (3) before the C conversion (4), while os.posix_spawn
        # converts in C (3) before its audit event compares it (4).
        def __init__(self, judged, used, first, last=None):
            self.judged, self.used, self.first, self.last = judged, used, first, last
            self.calls = 0

        def __fspath__(self):
            self.calls += 1
            late = self.calls >= self.first and (self.last is None or self.calls <= self.last)
            return self.used if late else self.judged


    # A str and a bytes key for one name: the child's getenv takes the first entry.
    shadowed = {b"PYTHONPATH": empty.encode(), **base}
    # close_fds=False and no cwd: the shape in which subprocess takes os.posix_spawn on
    # Python 3.11 to 3.14 (3.11 and 3.12 only without close_fds) unless the guard turned
    # that off, which it now does (fix review 3); a cwd forces fork_exec.
    attempts = {
        "n1-str-and-bytes-pythonpath-fork-exec": lambda: grandchild(
            "n1", cwd=mirror, env=shadowed),
        "n1b-str-and-bytes-pythonpath-posix-spawn": lambda: grandchild(
            "n1b", env=shadowed, close_fds=False),
        "n2-mapping-whose-get-disagrees-with-items": lambda: grandchild(
            "n2", cwd=mirror, env=Lying({**base, "PYTHONPATH": empty})),
        "n11-str-and-bytes-guard-variable": lambda: grandchild(
            "n11", cwd=mirror, env={variable.encode(): widened.encode(), **base}),
        "n3c-path-like-argument-fork-exec": lambda: subprocess.run(
            [grep, "-c", "ran", Flip(inside, secret, 4)], cwd="/", capture_output=True,
            timeout=30),
        "n3s-path-like-argument-posix-spawn": lambda: subprocess.run(
            [grep, "-c", "ran", Flip(inside, secret, 3, 3)], capture_output=True,
            timeout=30, close_fds=False),
        "n3p-path-like-python-flag": lambda: grandchild(
            "n3p", Flip("-u", "-I", 4), cwd=mirror, env=base),
    }
    for name, call in attempts.items():
        before = state.recorded_count()
        try:
            done = call()
        except Exception as exc:
            outcome = type(exc).__name__
        else:
            out = (done.stdout or b"").decode().strip()
            outcome = "read:" + out if out.isdigit() else "ran:" + out.replace(" ", "_")
        print(name, outcome, state.recorded_count() - before)
""")


def test_no_child_gets_an_environment_or_argv_other_than_the_one_judged(iso):
    """FR2 (the review of fix round 2) found the S1 class open: an approved Popen whose
    child received a different environment or argv than the guard judged. N1/N1b: a str
    and a bytes PYTHONPATH key (fork_exec and posix_spawn paths) start a Python child
    without the guard; N2: an env mapping whose get() disagrees with items(); N11: a str
    and a bytes SN1PER_MCP_TEST_GUARD key give the child a wider temp root; N3c/N3s: a
    path-like grep argument names a temp-root file to the guard and an outside file to
    the C conversion; N3p: a path-like flag reads -u to the guard and -I to the child.
    Each attempt must raise RealExecutionBlocked with exactly one recorded violation, and
    no outside marker may run or be read."""
    outside = iso.tmp / "outside"
    (outside / "bin").mkdir(parents=True)
    mark = outside / "bin" / "mark"
    mark.write_text(f"#!/bin/sh\necho ran > '{outside}/ran-'\"$1\"\n")
    mark.chmod(0o755)
    (outside / "bin" / "secret.txt").write_text("ran\n")
    child_root = iso.tmp / "child-root"
    child_root.mkdir(mode=0o700)
    mirror = child_root / "mirror"
    mirror.mkdir()
    with expect_child_violation(str(child_root), "process") as children:
        result = subprocess.run([sys.executable, "-c", _DIVERGENCE_PROBE, str(outside),
                                 str(mirror), str(iso.tmp)],
                                env=_probe_env(child_root), capture_output=True, text=True,
                                timeout=180, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    outcomes = {name: (outcome, int(count)) for name, outcome, count
                in (line.split() for line in result.stdout.splitlines())}
    assert outcomes == dict.fromkeys(
        ("n1-str-and-bytes-pythonpath-fork-exec", "n1b-str-and-bytes-pythonpath-posix-spawn",
         "n2-mapping-whose-get-disagrees-with-items", "n11-str-and-bytes-guard-variable",
         "n3c-path-like-argument-fork-exec", "n3s-path-like-argument-posix-spawn",
         "n3p-path-like-python-flag"),
        ("RealExecutionBlocked", 1)), outcomes
    assert sorted(path.name for path in outside.iterdir()) == ["bin"]  # no marker ran
    details = [str(item.get("detail")) for item in children]
    assert len(children) == len(outcomes), details
    assert all(item.get("event") == "subprocess.Popen" for item in children), children
    assert sum("twice (a str and a bytes key)" in detail for detail in details) == 3, details
    assert sum("not a dict or os.environ" in detail for detail in details) == 1, details
    assert sum("argv elements must be str, bytes or pathlib paths" in detail
               for detail in details) == 3, details


class _PathLike:
    """A path-like object that is not a standard pathlib path."""

    def __init__(self, path: str) -> None:
        self.path = path

    def __fspath__(self) -> str:
        return self.path


class _Flip:
    """A path-like object that answers ``used`` on the conversions numbered ``first`` to
    ``last`` (1-based; ``last`` None: every later one) and ``judged`` on all others."""

    def __init__(self, judged: str, used: str, first: int, last: int | None = None) -> None:
        self.judged, self.used, self.first, self.last = judged, used, first, last
        self.calls = 0

    def __fspath__(self) -> str:
        self.calls += 1
        late = self.calls >= self.first and (self.last is None or self.calls <= self.last)
        return self.used if late else self.judged


class _Str(str):
    """A str subclass: its methods may answer differently from the C conversion."""


@pytest.mark.parametrize("case", ["dict-subclass", "environb", "str-and-bytes-path",
                                  "int-value", "path-like-argument", "str-subclass-argument",
                                  "bytes-subclass-argument", "path-like-executable",
                                  "path-like-cwd"])
def test_only_a_plain_env_and_exact_path_types_are_judged(iso, case):
    """FR2 fix: env must be exactly a dict (or os.environ) with str or bytes entries and no
    name twice; argv elements, the executable and cwd must be str, bytes or a standard
    pathlib path. Every other form is refused with one violation (the command here is
    /bin/true, harmless if the guard let it through)."""
    true_bin = realpaths.TRUE_BIN
    path = {"PATH": realpaths.MINIMAL_ENV_PATH}
    calls = {
        "dict-subclass": lambda: subprocess.Popen(
            [true_bin], env=type("Env", (dict,), {})(path)),
        "environb": lambda: subprocess.Popen([true_bin], env=os.environb),
        "str-and-bytes-path": lambda: subprocess.Popen(
            [true_bin], env={**path, b"PATH": os.fsencode(realpaths.MINIMAL_ENV_PATH)}),
        "int-value": lambda: subprocess.Popen([true_bin], env={**path, "X": 1}),
        "path-like-argument": lambda: subprocess.Popen([true_bin, _PathLike(str(iso.tmp))]),
        "str-subclass-argument": lambda: subprocess.Popen([true_bin, _Str("x")]),
        "bytes-subclass-argument": lambda: subprocess.Popen(
            [true_bin, type("Bytes", (bytes,), {})(b"x")]),
        "path-like-executable": lambda: subprocess.Popen(
            ["true"], executable=_PathLike(true_bin)),
        "path-like-cwd": lambda: subprocess.Popen([true_bin], cwd=_PathLike(str(iso.tmp))),
    }
    with expect_violation("process") as record, pytest.raises(hook.RealExecutionBlocked):
        calls[case]()
    assert len(record.violations) == 1, [v.describe() for v in record.violations]


def test_plain_env_and_exact_path_types_still_run(iso):
    """The controls of the FR2 fix: pathlib, bytes and os.environ are still accepted, a
    call in the shape that would take os.posix_spawn runs (through fork_exec, fix review
    3), and a Python child whose environment has only bytes keys is read from the encoded
    entries and runs guarded."""
    marker = iso.tmp / "ran"
    stub = iso.tmp / "stub.sh"
    stub.write_text(f"#!/bin/sh\necho \"$1\" >> '{marker}'\n")
    stub.chmod(0o755)
    subprocess.run([stub, "pathlib"], cwd=iso.tmp, check=True, timeout=60)
    subprocess.run([os.fsencode(str(stub)), b"bytes"], env=os.environ, check=True, timeout=60)
    subprocess.run([str(stub), "posix-spawn-shape"], close_fds=False, check=True, timeout=60)
    assert marker.read_text().split() == ["pathlib", "bytes", "posix-spawn-shape"]
    code = "import sys; print(sys._sn1per_mcp_test_guard_state.mode)"
    env = {os.fsencode(key): os.fsencode(value) for key, value in iso.child_env().items()}
    result = subprocess.run([sys.executable, "-c", code], cwd=iso.tmp, env=env,
                            capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "child"


def test_file_rules_judge_only_exact_path_types(iso):
    """The FR2 class in the file rules. The os functions and the builtin open() hand the
    converted path to their audit event, but io.FileIO converts a path-like object in C
    and then raises "open" with the object itself, and shutil raises its events with the
    caller's object: a path-like object could name a protected file to the kernel and a
    temp-root file to the guard. Only str and bytes are judged (and pathlib paths in the
    shutil events, whose follow-up calls raise their own events); any other path type is
    refused. The protected name does not exist, so nothing could be read or removed even
    if the guard let a call through."""
    import io
    import shutil

    missing = os.path.join(realpaths.ROOT_HOME, "missing-" + os.urandom(8).hex())
    harmless = str(iso.tmp / "harmless")
    calls = [
        # FileIO converts in C (1), then raises "open" with the object (2).
        lambda: io.FileIO(_Flip(harmless, missing, 1, 1)),
        # shutil raises its event with the object (1), then converts in C (2 and later).
        lambda: shutil.rmtree(_Flip(harmless, missing, 2)),
    ]
    for call in calls:
        with expect_violation("file") as record, pytest.raises(hook.RealExecutionBlocked):
            call()
        assert len(record.violations) == 1, [v.describe() for v in record.violations]
        assert "a path of type _Flip" in record.violations[0].detail
    plain = iso.tmp / "plain"
    plain.write_text("x")
    with open(plain) as by_path, open(os.fsencode(str(plain))) as by_bytes:
        assert by_path.read() == by_bytes.read() == "x"


# Fix review 3 (rc-closeout-fixes.md, round 2), the same class once more: the guard judged a
# value that the child or the kernel did not use, or ran test code with itself switched off.
# One attack per guarded probe child, because most attacks patch the standard library, the
# hook module or os.environ for the rest of the process. Markers and the outside secret sit
# outside the probe's temp root; HOME names a directory outside it too, which the probe's
# guard protects like the developer's home (a stand-in: no real home file is ever named).
_SUBVERSION_PROBE = textwrap.dedent("""
    import builtins
    import io
    import json
    import os
    import pathlib
    import signal
    import socket
    import stat
    import subprocess
    import sys
    import threading

    attack, outside, wider = sys.argv[1], sys.argv[2], sys.argv[3]
    state = sys._sn1per_mcp_test_guard_state
    hook = sys.modules["_sn1per_mcp_guard_hook"]
    grep, true, sleep = (os.environ[n] for n in ("PROBE_GREP", "PROBE_TRUE", "PROBE_SLEEP"))
    guard = os.environ["PYTHONPATH"].split(os.pathsep)[0]
    variable = "SN1PER_MCP_TEST_GUARD"
    mark = os.path.join(outside, "bin", "mark")
    secret = os.path.join(outside, "bin", "secret.txt")
    home = os.environ["HOME"]
    home_secret = os.path.join(home, "secret.txt")
    root = state.temp_root
    inside = os.path.join(root, "inside.txt")
    empty = os.path.join(root, "empty")
    os.makedirs(empty, exist_ok=True)
    valid = json.dumps({"temp_root": root, "repo_root": state.repo_root})
    # Names the parent of this probe's temp root: valid for a child of its own, but a
    # parent may only forward its own temp root or a directory inside it.
    widened = json.dumps({"temp_root": wider, "repo_root": state.repo_root})
    base = {"PATH": os.environ["PATH"], "PYTHONPATH": guard, variable: valid}


    def grandchild(tag, *flags, **kwargs):
        # The marker path travels inside the code text: as an argument the guard would
        # refuse it (a path outside the probe's roots).
        code = ("import subprocess, sys\\n"
                "state = getattr(sys, '_sn1per_mcp_test_guard_state', None)\\n"
                "try:\\n"
                f"    run = subprocess.run([{mark!r}, {tag!r}], timeout=30).returncode\\n"
                "except Exception as exc:\\n"
                "    run = type(exc).__name__\\n"
                "print(state.temp_root if state else '-', run)\\n")
        done = subprocess.run([sys.executable, *flags, "-c", code], capture_output=True,
                              timeout=60, **kwargs)
        where, _, run = (done.stdout or b"- ?").decode().strip().partition(" ")
        kind = "unguarded" if where == "-" else "guarded" if where == root else "widened"
        return Grandchild(kind + ":" + run)


    class Grandchild(str):
        # How a Python grandchild ran: guarded (with this probe's temp root), widened
        # (guarded with another root) or unguarded, and what its marker run gave.
        pass


    class Outcome(str):
        # An outcome the attack states itself, such as "read:<what a read returned>".
        pass


    class BigFd(int):
        # An int subclass whose value does not fit a C int: io.FileIO takes it as a path,
        # converts it with __fspath__ (the protected stand-in secret) and raises "open"
        # with the object itself.
        def __fspath__(self):
            return home_secret


    def judged_secret():
        # A file named like the stand-in secret, inside this probe's temp root: what the
        # guard judges a relative "secret.txt", or a link to it, to be.
        path = os.path.join(root, "secret.txt")
        with open(path, "w") as handle:
            handle.write("judged\\n")
        return path


    class Evil(str):
        judged = ""

        def encode(self, *args, **kwargs):
            return type(self).judged.encode()


    def poisoned(judged, used):
        # An exact pathlib path whose cached string is a str subclass: its encode() gives
        # the judged path, while CPython's C conversion encodes its characters (used).
        path = pathlib.PosixPath(judged)
        path._str = type("Evil", (Evil,), {"judged": judged})(used)
        return path


    def patch_fspath_of_pathlib(first_used):
        # Class-level: every pathlib path converts to "used" on the odd (first_used) or the
        # even conversions. io.FileIO converts in C (1) before the guard (2); a Popen check
        # converts (1) before anything else does (2).
        real, calls = pathlib.PurePath.__fspath__, []

        def flip(self):
            calls.append(1)
            text = real(self)
            if text == inside and (len(calls) % 2 == 1) == first_used:
                return home_secret if first_used else secret
            return text
        pathlib.PurePath.__fspath__ = flip


    def patch_fspath(target):
        # os.fspath answers a temp-root file for target; os.fsencode, os.path.realpath and
        # pathlib call os.fspath, the kernel and C conversions never do.
        real = os.fspath
        os.fspath = lambda value: inside if real(value) == target else real(value)


    def patch_environ_values(name, value):
        env = os.environ
        env.values = lambda: [value if key == name else env[key] for key in env.keys()]


    def patch_environ_decodevalue(callback):
        env, real = os.environ, os.environ.decodevalue

        def decodevalue(data):
            text = real(data)
            return callback(text)
        env.decodevalue = decodevalue


    def judged_then_empty():
        # The guard's read gets the guard directory; the next read (os.posix_spawn's C
        # values() on 4dc2d55, subprocess's env list here) the empty directory.
        calls = []

        def answer(text):
            if text != guard:
                return text
            calls.append(1)
            return empty if len(calls) == 2 else text
        return answer


    def once(action):
        fired = []

        def answer(text):
            if not fired:
                fired.append(1)
                action()
            return text
        return answer


    def read(path):
        with open(path) as handle:
            return handle.read()


    def run_attack():
        if attack == "p1-poisoned-pathlib-argument":
            return subprocess.run([grep, "-c", "ran", poisoned(inside, secret)],
                                  close_fds=False, capture_output=True, timeout=30)
        if attack == "p1c-poisoned-pathlib-argument-with-cwd":
            return subprocess.run([grep, "-c", "ran", poisoned(inside, secret)], cwd=root,
                                  capture_output=True, timeout=30)
        if attack == "p2-poisoned-pathlib-python-flag":
            return grandchild("p2", poisoned("-u", "-I"), env=base, close_fds=False)
        if attack == "p4-poisoned-pathlib-in-fileio":
            return io.FileIO(poisoned(inside, home_secret)).read()
        if attack == "p5-class-patched-pathlib-argument":
            patch_fspath_of_pathlib(first_used=False)
            return subprocess.run([grep, "-c", "ran", pathlib.PosixPath(inside)],
                                  close_fds=False, capture_output=True, timeout=30)
        if attack == "p6-class-patched-pathlib-in-fileio":
            patch_fspath_of_pathlib(first_used=True)
            return io.FileIO(pathlib.PosixPath(inside)).read()
        if attack == "e1-environ-values-replaced":
            patch_environ_values("PYTHONPATH", empty)
            return grandchild("e1", env=os.environ, close_fds=False)
        if attack == "e1w-environ-values-widen-the-guard-variable":
            patch_environ_values(variable, widened)
            return grandchild("e1w", env=os.environ, close_fds=False)
        if attack == "e2-environ-decodevalue-counts-calls":
            patch_environ_decodevalue(judged_then_empty())
            return grandchild("e2", env=os.environ, close_fds=False)
        if attack == "f1-fspath-replaced-argument":
            patch_fspath(secret)
            return subprocess.run([grep, "-c", "ran", secret], close_fds=False,
                                  capture_output=True, timeout=30)
        if attack == "f1c-fspath-replaced-argument-with-cwd":
            patch_fspath(secret)
            return subprocess.run([grep, "-c", "ran", secret], cwd=root,
                                  capture_output=True, timeout=30)
        if attack == "f2-fspath-replaced-open":
            patch_fspath(home_secret)
            return read(home_secret)
        if attack == "f3-fspath-replaced-os-open":
            patch_fspath(home_secret)
            fd = os.open(home_secret, os.O_RDONLY)
            try:
                return os.read(fd, 100)
            finally:
                os.close(fd)
        if attack == "f4-lstat-and-readlink-replaced-open":
            real_lstat, real_readlink = os.lstat, os.readlink

            def lstat(path, *args, **kwargs):
                if os.fspath(path) == home_secret:  # presented as a link to a temp-root file
                    return os.stat_result((stat.S_IFLNK | 0o777,) + (0,) * 9)
                return real_lstat(path, *args, **kwargs)

            def readlink(path, *args, **kwargs):
                if os.fspath(path) == home_secret:
                    return inside
                return real_readlink(path, *args, **kwargs)
            os.lstat, os.readlink = lstat, readlink
            return read(home_secret)
        if attack == "x1-hook-table-cleared":
            hook._ALWAYS_BLOCKED_EVENTS.clear()
            return os.system(mark + " x1")
        if attack == "x1r-hook-table-rebound":
            hook._ALWAYS_BLOCKED_EVENTS = {}
            return os.system(mark + " x1r")
        if attack == "x2-builtin-any-replaced":
            builtins.any = lambda iterable: False
            return read(home_secret)
        if attack == "x3-json-loads-replaced":
            real_loads = json.loads
            json.loads = lambda text, *a, **k: real_loads(valid if text == widened else text,
                                                          *a, **k)
            return grandchild("x3", env={**base, variable: widened}, cwd=root)
        if attack == "x4-socket-family-property":
            class Claims(socket.socket):
                @property
                def family(self):
                    return socket.AF_UNIX
            sock = Claims(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            try:
                return sock.connect(("192.0.2.10", 80))
            finally:
                sock.close()
        if attack == "x5-class-attribute-claims-int":
            class Liar:
                __class__ = property(lambda self: int)

                def __fspath__(self):
                    return home_secret
            return io.FileIO(Liar()).read()
        if attack == "x6-environ-callback-runs-a-command":
            patch_environ_decodevalue(once(lambda: os.system(mark + " x6")))
            return subprocess.run([true], env=os.environ, cwd=root, timeout=30)
        if attack == "x6o-environ-callback-reads-a-file":
            got = []
            patch_environ_decodevalue(once(lambda: got.append(read(home_secret))))
            subprocess.run([true], env=os.environ, cwd=root, timeout=30)
            return "read:" + "".join(got).strip()
        if attack == "x7-repr-callback-runs-a-command":
            class Shown(str):
                def __repr__(self):
                    os.system(mark + " x7")
                    return "shown"
            return os.posix_spawn(true, [Shown("x")], {})
        if attack == "x8-repr-raises":
            class Hidden(str):
                def __repr__(self):
                    raise ValueError("no repr")
            return os.posix_spawn(true, [Hidden("x")], {})
        if attack in ("x9-second-audit-hook-during-a-proc-read",
                      "x10-second-audit-hook-during-a-violation-write"):
            fired = []

            def second(event, args):
                if fired or event != "open" or not args or type(args[0]) is not str:
                    return
                if args[0].startswith("/proc/") or args[0].endswith(".jsonl"):
                    fired.append(1)
                    os.system(mark + " " + attack[:3].rstrip("-"))
            sys.addaudithook(second)
            if attack.startswith("x10"):
                return read(home_secret)
            child = subprocess.Popen([sleep, "30"], cwd=root)
            try:
                return os.kill(child.pid, signal.SIGCONT)
            finally:
                child.kill()
                child.wait()
        if "-int-subclass-in-" in attack:
            fd = BigFd(-2**40 if "negative" in attack else 2**31)
            call = attack.rsplit("-in-", 1)[1]
            if call == "open":
                return read(fd)
            if call == "fileio":
                return io.FileIO(fd).read()
            if call == "io-open":
                with io.open(fd) as handle:
                    return handle.read()
            with os.fdopen(fd) as handle:
                return handle.read()
        if attack == "d1-second-audit-hook-changes-the-cwd":
            judged_secret()
            fired = []

            def second(event, args):
                # Runs after the guard judged "secret.txt" against the temp root.
                if not fired and event == "open" and args and args[0] == "secret.txt":
                    fired.append(1)
                    os.chdir(home)
            sys.addaudithook(second)
            os.chdir(root)
            return Outcome("read:" + read("secret.txt").strip())
        if attack == "d2-second-audit-hook-re-points-a-link":
            link = os.path.join(root, "link.txt")
            os.symlink(judged_secret(), link)
            fired = []

            def second(event, args):
                # Runs after the guard resolved the link to the temp-root file.
                if not fired and event == "open" and args and args[0] == link:
                    fired.append(1)
                    os.remove(link)
                    os.symlink(home_secret, link)
            sys.addaudithook(second)
            return Outcome("read:" + read(link).strip())
        if attack == "b1-another-thread-changes-the-cwd-after-the-approval":
            judged_secret()
            go, done = threading.Event(), threading.Event()

            def flip():
                go.wait(30)
                os.chdir(home)
                done.set()
            worker = threading.Thread(target=flip)
            worker.start()
            count, calls = len(os.environ), []

            def after_the_check(text):
                # The guard reads every value of os.environ once while it judges the Popen;
                # subprocess reads them again for the child after the approval, and on the
                # first of those reads the other thread changes this process's directory
                # (an event in another thread does not clear this thread's approval).
                calls.append(1)
                if len(calls) == count + 1:
                    go.set()
                    done.wait(30)
                return text
            patch_environ_decodevalue(after_the_check)
            os.chdir(root)
            try:
                done_run = subprocess.run([grep, "", "secret.txt"], env=os.environ,
                                          capture_output=True, timeout=30)
            finally:
                go.set()
                worker.join()
            return Outcome("read:" + done_run.stdout.decode().strip())
        if attack == "v0-trip":
            return read(home_secret)
        if attack == "v1-link-at-the-violation-file":
            os.symlink(os.path.join(home, "target.txt"),
                       os.path.join(root, hook.CHILD_VIOLATIONS_FILE))
            return read(home_secret)
        if attack == "v3-temp-root-moved-and-linked":
            os.chdir("/")
            os.rename(root, root + "-moved")
            os.symlink(home, root)
            return read(home_secret)
        if attack == "v4-fifo-at-the-violation-file":
            os.mkfifo(os.path.join(root, hook.CHILD_VIOLATIONS_FILE))
            return read(home_secret)
        raise SystemExit("unknown attack " + attack)


    before = state.recorded_count()
    try:
        done = run_attack()
    except Exception as exc:
        outcome = type(exc).__name__
    else:
        if type(done) is Grandchild or type(done) is Outcome:
            outcome = str(done)
        elif type(done) is subprocess.CompletedProcess:
            out = (done.stdout or b"").decode().strip()
            outcome = "read:" + out if out.isdigit() else "exit:" + str(done.returncode)
        elif type(done) in (bytes, str) and "ran" in str(done):
            outcome = "read:secret"
        else:
            outcome = "returned:" + str(done).replace(" ", "_")[:60]
    print(attack, outcome, state.recorded_count() - before)
""")

_BLOCKED = "RealExecutionBlocked"
_HOOK_REFUSED = "adding an audit hook is never allowed in tests"
_INT_SUBCLASS = "open of a path of type BigFd"
# attack: (outcome in the probe, violations in the probe's own ledger, the details that the
# recorded child violations must contain: one text, a tuple of texts, or None for "no child
# violation at all"). E1 and E1w start a grandchild that must run guarded with the probe's
# own temp root; its marker run is the recorded violation. Since fix review 4 an audit hook
# added after the guard is refused (CPython then returns None and drops it), so X9 and X10
# never install their second hook, and D1 and D2 read the file the guard judged.
_SUBVERSIONS = {
    "p1-poisoned-pathlib-argument": (_BLOCKED, 1, "argv elements must be str, bytes"),
    "p1c-poisoned-pathlib-argument-with-cwd": (_BLOCKED, 1, "argv elements must be str"),
    "p2-poisoned-pathlib-python-flag": (_BLOCKED, 1, "argv elements must be str, bytes"),
    "p4-poisoned-pathlib-in-fileio": (_BLOCKED, 1, "open of a path of type PosixPath"),
    "p5-class-patched-pathlib-argument": (_BLOCKED, 1, "fork_exec outside an approved"),
    "p6-class-patched-pathlib-in-fileio": (_BLOCKED, 1, "open of a path of type PosixPath"),
    "e1-environ-values-replaced": ("guarded:" + _BLOCKED, 0, "outside the test temp root"),
    "e1w-environ-values-widen-the-guard-variable": (
        "guarded:" + _BLOCKED, 0, "outside the test temp root"),
    "e2-environ-decodevalue-counts-calls": (_BLOCKED, 1, "fork_exec outside an approved"),
    "f1-fspath-replaced-argument": (_BLOCKED, 1, "names a path outside the test roots"),
    "f1c-fspath-replaced-argument-with-cwd": (
        _BLOCKED, 1, "names a path outside the test roots"),
    "f2-fspath-replaced-open": (_BLOCKED, 1, "open of real path"),
    "f3-fspath-replaced-os-open": (_BLOCKED, 1, "open of real path"),
    "f4-lstat-and-readlink-replaced-open": (_BLOCKED, 1, "open of real path"),
    "x1-hook-table-cleared": (_BLOCKED, 1, "os.system is never allowed"),
    "x1r-hook-table-rebound": (_BLOCKED, 1, "os.system is never allowed"),
    "x2-builtin-any-replaced": (_BLOCKED, 1, "open of real path"),
    "x3-json-loads-replaced": (_BLOCKED, 1, "is outside this session's temp root"),
    "x4-socket-family-property": ("NetworkBlocked", 1, "network I/O to"),
    "x5-class-attribute-claims-int": (_BLOCKED, 1, "open of a path of type Liar"),
    "x6-environ-callback-runs-a-command": (_BLOCKED, 1, "os.system is never allowed"),
    "x6o-environ-callback-reads-a-file": (_BLOCKED, 1, "open of real path"),
    "x7-repr-callback-runs-a-command": (_BLOCKED, 1, "os.posix_spawn is never allowed"),
    "x8-repr-raises": (_BLOCKED, 1, "os.posix_spawn is never allowed"),
    "x9-second-audit-hook-during-a-proc-read": ("returned:None", 1, _HOOK_REFUSED),
    "x10-second-audit-hook-during-a-violation-write": (
        _BLOCKED, 2, (_HOOK_REFUSED, "open of real path")),
    # Fix review 4: an int subclass is not a descriptor (io.FileIO takes a value that does
    # not fit a C int as a path), in each of the four calls that reach io.FileIO.
    "i1-int-subclass-in-open": (_BLOCKED, 1, _INT_SUBCLASS),
    "i2-int-subclass-in-fileio": (_BLOCKED, 1, _INT_SUBCLASS),
    "i3-int-subclass-in-io-open": (_BLOCKED, 1, _INT_SUBCLASS),
    "i4-int-subclass-in-fdopen": (_BLOCKED, 1, _INT_SUBCLASS),
    "i5-negative-int-subclass-in-open": (_BLOCKED, 1, _INT_SUBCLASS),
    "i6-negative-int-subclass-in-fileio": (_BLOCKED, 1, _INT_SUBCLASS),
    "i7-negative-int-subclass-in-io-open": (_BLOCKED, 1, _INT_SUBCLASS),
    "i8-negative-int-subclass-in-fdopen": (_BLOCKED, 1, _INT_SUBCLASS),
    # Fix review 4: a judgment that goes stale before the kernel or the child acts on it.
    "d1-second-audit-hook-changes-the-cwd": ("read:judged", 1, _HOOK_REFUSED),
    "d2-second-audit-hook-re-points-a-link": ("read:judged", 1, _HOOK_REFUSED),
    "b1-another-thread-changes-the-cwd-after-the-approval": ("read:judged", 0, None),
}


def _subversion_probe(iso) -> tuple[dict[str, str], Path, Path, Path]:
    """(env, outside, home, child_root) of a guarded subversion probe child: markers and an
    outside secret in ``outside``, a stand-in home (protected by the probe's guard) with a
    secret, and the probe's own temp root."""
    outside = iso.tmp / "outside"
    (outside / "bin").mkdir(parents=True)
    mark = outside / "bin" / "mark"
    mark.write_text(f"#!/bin/sh\necho ran > '{outside}/ran-'\"$1\"\n")
    mark.chmod(0o755)
    (outside / "bin" / "secret.txt").write_text("ran\n")
    home = iso.tmp / "probe-home"
    home.mkdir()
    (home / "secret.txt").write_text("ran\n")
    child_root = iso.tmp / "child-root"
    child_root.mkdir(mode=0o700)
    (child_root / "inside.txt").write_text("inside\n")
    env = _probe_env(child_root)
    env.update({"HOME": str(home), "PROBE_TRUE": realpaths.TRUE_BIN,
                "PROBE_SLEEP": realpaths.SLEEP_BIN})
    return env, outside, home, child_root


def _run_subversion_probe(iso, attack: str, env: dict[str, str], outside: Path,
                          child_root: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-c", _SUBVERSION_PROBE, attack, str(outside),
                           str(iso.tmp)],
                          env=env, cwd=str(child_root), capture_output=True, text=True,
                          timeout=120, check=False)


@pytest.mark.parametrize("attack", list(_SUBVERSIONS))
def test_no_test_code_changes_what_the_guard_judges(iso, attack):
    """Fix review 3 (round 2 of the release-candidate close-out). P1-P6: an exact pathlib
    path whose cached string is a str subclass, or whose class conversion was patched, was
    judged as one path and used as another (os.posix_spawn argv and io.FileIO). E1, E1w,
    E2: os.environ on the os.posix_spawn path was judged through items() while the child
    got keys() and values(). F1-F4: patching os.fspath, os.lstat or os.readlink changed the
    path the guard's Python-level helpers judged. X1-X10, the same class found while fixing
    those: a cleared or rebound table of the hook module, a replaced builtin or json.loads,
    a socket subclass whose family property claims AF_UNIX, an object whose __class__
    claims int, and test code that ran while the guard was switched off (os.environ
    callbacks and a caller's __repr__ during a check, another audit hook during the
    guard's own /proc read or violation write), or a __repr__ that raised before the
    violation was recorded. Each attack must be refused and recorded (E1 and E1w: the
    grandchild runs guarded with the probe's own temp root), and no marker may run and no
    secret be read.

    Fix review 4 (round 3). I1-I8: an int subclass that defines __fspath__ was taken for a
    descriptor, while io.FileIO (open(), io.open(), os.fdopen()) opened the path it names
    when its value does not fit a C int; it is refused like any other path type. D1, D2: a
    second audit hook ran after the guard and changed the working directory, or re-pointed
    a link, between the guard's judgment and the open; adding an audit hook is refused
    (recorded, and CPython drops the hook), so the open reads the file the guard judged.
    B1: another thread changed this process's directory after an approved Popen with
    cwd=None, and the child inherited it; the child now starts in the directory the guard
    judged, reads the judged file and nothing is recorded."""
    env, outside, _home, child_root = _subversion_probe(iso)
    expected_outcome, expected_count, expected_details = _SUBVERSIONS[attack]
    if expected_details is None:
        result = _run_subversion_probe(iso, attack, env, outside, child_root)
        children = hook.read_child_violations(str(iso.tmp), recursive=True)
        assert children == [], children
    else:
        with expect_child_violation(str(child_root)) as children:
            result = _run_subversion_probe(iso, attack, env, outside, child_root)
    assert result.returncode == 0, result.stdout + result.stderr
    name, outcome, count = result.stdout.split()
    assert (name, outcome, int(count)) == (attack, expected_outcome, expected_count), \
        result.stdout + result.stderr
    assert sorted(path.name for path in outside.iterdir()) == ["bin"]  # no marker ran
    details = [str(item.get("detail")) for item in children]
    if isinstance(expected_details, str):
        expected_details = (expected_details,)
    for expected in expected_details or ():
        assert any(expected in detail for detail in details), (expected, details)


# Fix review 4, finding 3: the guard's own write of its violation file. case: (attack in
# the probe, what this test plants at the probe's violation-file name before the probe runs,
# and a phrase the reader must report for the entry, or None when the guard's line must land
# in a usable file of the probe's moved temp root).
_VIOLATION_FILE_CASES = {
    "link-planted-by-the-child": ("v1-link-at-the-violation-file", None, "a symbolic link"),
    "link-planted-by-the-parent": ("v0-trip", "link", "a symbolic link"),
    "hard-link-planted-by-the-parent": ("v0-trip", "hard-link", "hard-linked (2 links)"),
    "fifo-planted-by-the-child": ("v4-fifo-at-the-violation-file", None, "a FIFO"),
    "temp-root-moved-and-replaced-by-a-link": ("v3-temp-root-moved-and-linked", None, None),
}


@pytest.mark.parametrize("case", list(_VIOLATION_FILE_CASES))
def test_the_guard_never_writes_its_violation_file_through_a_planted_entry(iso, case):
    """Fix review 4, finding 3: in a guarded child the guard wrote each violation through
    os.open(O_WRONLY|O_APPEND|O_CREAT) on the temp root's path, so a link planted at the
    file's name (by the child or by its parent) sent the line into the file it names (a
    protected one here), and the parent's reader skipped links, so the trip never reached
    the session. Same class, found while fixing it: a hard link at the name put the line
    into another file; a FIFO there hung the child, and the reader skipped it; and a child
    that renamed its temp root and put a link to a protected directory in its place made
    the guard create a file there. The guard now opens the file relative to a descriptor
    of its temp root taken at install, with O_NOFOLLOW and O_NONBLOCK, and writes only to a
    regular file of this user with one link, else to stderr; the reader reports an entry a
    child cannot have written to as a violation of its own, and expect_child_violation()
    never consumes it. The trip still fails the probe's call in every case, and no target
    changes."""
    attack, planted, reported = _VIOLATION_FILE_CASES[case]
    env, outside, home, child_root = _subversion_probe(iso)
    (home / "target.txt").write_text("original\n")
    other = iso.tmp / "other.txt"  # outside the probe's temp root, not protected
    other.write_text("original\n")
    entry = child_root / hook.CHILD_VIOLATIONS_FILE
    if planted == "link":
        entry.symlink_to(home / "target.txt")
    elif planted == "hard-link":
        os.link(other, entry)
    if reported is None:
        with expect_child_violation(str(iso.tmp)) as children:
            result = _run_subversion_probe(iso, attack, env, outside, child_root)
        moved = str(child_root) + "-moved/"
        # The line went into the renamed temp root (by its descriptor), where the session
        # reader finds it; the link now at the old name was never followed.
        assert [item["source"].startswith(moved) for item in children] == [True], children
        assert "open of real path" in str(children[0].get("detail"))
    else:
        result = _run_subversion_probe(iso, attack, env, outside, child_root)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.split() == [attack, _BLOCKED, "1"], result.stdout + result.stderr
    assert (home / "target.txt").read_text() == "original\n"
    assert other.read_text() == "original\n"
    assert sorted(path.name for path in home.iterdir()) == ["secret.txt", "target.txt"]
    if reported is None:
        return
    # Reported where the child could: its stderr, with the trip itself.
    assert "reported here only" in result.stderr and "open of real path" in result.stderr, \
        result.stderr
    items = hook.read_child_violations(str(iso.tmp), recursive=True)
    assert [(item.get("unusable"), item.get("path")) for item in items] == \
        [(True, str(entry))], items
    assert reported in items[0]["detail"], items
    with pytest.raises(AssertionError, match="never consumed"), \
            expect_child_violation(str(child_root)):
        pass
    assert os.path.lexists(entry)  # left in place: the test and the session would fail
    entry.unlink()  # this test planted it (or let the probe plant it) on purpose


def test_the_child_violation_readers_report_every_entry_a_child_cannot_write(iso):
    """Fix review 4, finding 3, the reader's half: child_violation_files() skipped links
    and anything that was not a regular file, so a guarded child's trips behind a planted
    link never reached the session. Every entry named like a child violation file is now
    found, links are never followed, and the ones a child cannot have written to are
    reported as violations of their own (marked unusable). The readers run in each test's
    teardown while its monkeypatch changes are still in place (tests patch os.lstat,
    os.walk and os.geteuid), so they decide only with values captured when the hook module
    was imported: the same patches, and patched json.loads and open(), change nothing."""
    import builtins

    name = hook.CHILD_VIOLATIONS_FILE
    root = iso.tmp / "readers"
    line = json.dumps({"kind": "process", "event": "subprocess.Popen", "detail": "x",
                       "pid": 1}) + "\n"
    elsewhere = iso.tmp / "elsewhere.txt"
    elsewhere.write_text(line)
    makers = {
        "a-link": lambda path: path.symlink_to(elsewhere),
        "b-dangling-link": lambda path: path.symlink_to(iso.tmp / "missing"),
        "c-fifo": lambda path: os.mkfifo(path, 0o600),
        "d-directory": lambda path: path.mkdir(),
        "e-hard-link": lambda path: os.link(elsewhere, path),
        "f-regular": lambda path: path.write_text(line),
    }
    for directory, make in makers.items():
        (root / directory).mkdir(parents=True)
        make(root / directory / name)
    entries = [str(root / directory / name) for directory in makers]
    expected = [(entries[0], True, "a symbolic link"), (entries[1], True, "a symbolic link"),
                (entries[2], True, "a FIFO"), (entries[3], True, "a directory"),
                (entries[4], True, "hard-linked (2 links)"), (entries[5] + ":1", None, "x")]

    def summary() -> list[tuple]:
        return sorted((item.get("path") or item["source"], item.get("unusable"),
                       item["detail"]) for item in hook.read_child_violations(
                           str(root), recursive=True))

    found = summary()
    assert [(path, mark) for path, mark, _ in found] == \
        [(path, mark) for path, mark, _ in expected], found
    assert all(want in got for (_, _, got), (_, _, want) in zip(found, expected, strict=True)), \
        found
    assert hook.child_violation_files(str(root), recursive=True) == entries
    assert hook.child_violation_files(str(root / "a-link")) == [entries[0]]

    def broken(*args, **kwargs):
        raise OSError("patched by a test")

    with pytest.MonkeyPatch.context() as patched:
        for owner, attribute in ((os, "lstat"), (os, "stat"), (os, "scandir"), (os, "walk"),
                                 (os, "open"), (os, "fstat"), (os, "read"), (os.path, "isfile"),
                                 (os.path, "islink"), (os.path, "join"), (json, "loads"),
                                 (builtins, "open")):
            patched.setattr(owner, attribute, broken)
        patched.setattr(os, "geteuid", lambda: os.getuid() + 1)
        found_patched = summary()
        files_patched = hook.child_violation_files(str(root), recursive=True)
    assert found_patched == found
    assert files_patched == entries
    # The usable file is consumed; every unusable entry fails the block and stays.
    with pytest.raises(AssertionError, match="never consumed"), \
            expect_child_violation(str(root)):
        pass
    assert hook.child_violation_files(str(root), recursive=True) == entries[:5]
    for path in entries[:5]:
        if os.path.isdir(path) and not os.path.islink(path):
            os.rmdir(path)
        else:
            os.remove(path)


def test_a_link_at_a_child_violation_file_fails_the_test_and_the_session(iso):
    """Fix review 4, finding 3, in a real guarded pytest session: a test that plants a link
    at its guarded child's violation-file name (or whose child plants one) and lets the
    child trip used to pass, with the guard's line written into the link's target. Now the
    target stays unchanged, the test errors at teardown and the session fails. The links
    are left for this outer test, which consumes them on purpose."""
    name = hook.CHILD_VIOLATIONS_FILE
    work = iso.tmp / "planted-link-session"
    work.mkdir()
    (work / "conftest.py").write_text(textwrap.dedent("""
        from tests.conftest import pytest_configure, pytest_sessionfinish  # noqa: F401
        from tests.conftest import _isolation_fixture, iso  # noqa: F401
    """))
    (work / "test_planted.py").write_text(textwrap.dedent("""
        import os
        import subprocess
        import sys

        import pytest

        from tests import realpaths
        from tests.guard import hook

        NAME = @NAME@
        CODE = (
            "import os, sys\\n"
            "root = sys._sn1per_mcp_test_guard_state.temp_root\\n"
            "home = os.environ['HOME']\\n"
            "if sys.argv[1] == 'child':\\n"
            "    os.symlink(os.path.join(home, 'target.txt'), os.path.join(root, "
            + repr(NAME) + "))\\n"
            "try:\\n"
            "    open(os.path.join(home, 'secret.txt')).read()\\n"
            "except Exception as exc:\\n"
            "    print(type(exc).__name__)\\n"
        )

        @pytest.mark.parametrize("planter", ["parent", "child"])
        def test_a_child_trip_behind_a_planted_link(iso, planter):
            sub = iso.tmp / "grandchild-root"
            sub.mkdir(mode=0o700)
            home = iso.tmp / "stand-in-home"
            home.mkdir()
            (home / "secret.txt").write_text("secret\\n")
            (home / "target.txt").write_text("original\\n")
            if planter == "parent":
                os.symlink(home / "target.txt", sub / NAME)
            env = hook.child_env(str(sub), hook.state().repo_root,
                                 {"PATH": realpaths.MINIMAL_ENV_PATH, "HOME": str(home)})
            result = subprocess.run([sys.executable, "-c", CODE, planter], env=env,
                                    cwd=str(sub), capture_output=True, text=True, timeout=60,
                                    check=False)
            assert result.returncode == 0, result.stderr
            assert result.stdout.strip() == "RealExecutionBlocked", result.stdout
    """).replace("@NAME@", repr(name)))
    child_root = iso.tmp / "child-root"
    child_root.mkdir(mode=0o700)
    env = hook.child_env(str(child_root), str(REPO),
                         {"PATH": realpaths.MINIMAL_ENV_PATH, "HOME": str(iso.home)},
                         extra_pythonpath=[str(REPO), str(REPO / "src")])
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
         "--basetemp", str(child_root / "basetemp"), "--rootdir", str(work), str(work)],
        cwd=str(work), env=env, capture_output=True, text=True, timeout=120, check=False)
    output = result.stdout + result.stderr
    targets = sorted(directory / "stand-in-home" / "target.txt"
                     for directory in (child_root / "basetemp").iterdir()
                     if not directory.is_symlink())  # pytest's "<prefix>current" link
    assert [path.read_text() for path in targets] == ["original\n", "original\n"], output
    assert "2 passed" in output, output
    assert output.count("ERROR at teardown of test_a_child_trip_behind_a_planted_link") == 2, \
        output
    assert "TEST GUARD VIOLATIONS" in output and "child violation file" in output, output
    assert result.returncode == 1, output
    planted = hook.read_child_violations(str(child_root), recursive=True)
    assert [(item.get("unusable"), os.path.basename(item.get("path", ""))) for item in planted] \
        == [(True, name), (True, name)], planted
    for item in planted:
        os.remove(item["path"])


def test_a_child_started_without_env_gets_exactly_the_judged_environment(iso):
    """Fix review 3, same class: with env=None the child inherited the process environment,
    which os.putenv changes without os.environ (what the guard reads). The child now gets
    the judged os.environ entries explicitly."""
    stub = iso.tmp / "show.sh"
    stub.write_text('#!/bin/sh\necho "[$PROBE_PUTENV_ONLY]"\n')
    stub.chmod(0o755)
    os.putenv("PROBE_PUTENV_ONLY", "inherited")
    try:
        unseen = subprocess.run([str(stub)], cwd=str(iso.tmp), capture_output=True, text=True,
                                timeout=60, check=True)
    finally:
        os.unsetenv("PROBE_PUTENV_ONLY")
    assert unseen.stdout.strip() == "[]"
    iso.setenv(PROBE_PUTENV_ONLY="judged")
    seen = subprocess.run([str(stub)], cwd=str(iso.tmp), capture_output=True, text=True,
                          timeout=60, check=True)
    assert seen.stdout.strip() == "[judged]"


def test_guard_code_looks_up_no_global_name():
    """Fix review 3, same class: the hook and its wrappers decide only from values captured
    at install time. A name looked up in the hook module's globals or in builtins when the
    hook runs (a table, os.path.realpath, any(), json.loads) could be patched by a test, and
    so could an attribute of a module object the hook kept. Every function nested in
    install() is checked: no global lookup, and no module among its free variables. Fix
    review 4: the same for the readers of the child violation files, which run in each
    test's teardown while its monkeypatch changes are still in place."""
    import dis
    import types

    modules = {"os", "sys", "io", "json", "shutil", "socket", "stat", "pathlib", "subprocess",
               "_posixsubprocess", "_socket", "builtins", "multiprocessing", "realpaths",
               "threading", "importlib", "posixpath"}

    def nested(code):
        for const in code.co_consts:
            if isinstance(const, types.CodeType):
                yield const
                yield from nested(const)

    problems = []
    readers = list(nested(hook._build_child_file_readers.__code__))
    assert {code.co_name for code in readers} >= {"child_violation_files",
                                                  "read_child_violations"}, readers
    functions = list(nested(hook.install.__code__)) + readers
    assert len(functions) > 40, len(functions)  # the hook, its wrappers and helpers
    for code in functions:
        for instruction in dis.get_instructions(code):
            if instruction.opname in ("LOAD_GLOBAL", "LOAD_NAME", "STORE_GLOBAL",
                                      "DELETE_GLOBAL"):
                problems.append(f"{code.co_name}: {instruction.opname} {instruction.argval}")
        for name in sorted(set(code.co_freevars) & modules):
            problems.append(f"{code.co_name}: uses the module {name}")
    assert not problems, "\n".join(problems)


def test_paths_through_a_process_cwd_link_are_refused_in_the_session(iso):
    """The same rule in the pytest session itself: the executable, a PATH entry, an
    argument and cwd are judged as the child would see them, so a cwd, root or
    standard-descriptor link under /proc is refused even when it currently names a
    temp-root file, also with ".." right after it or after a temp-root link that
    points through it (fix round 2: those spellings were normalized before the
    check, and /proc/self/cwd/../<top-level install>/loot was approved)."""
    stub = iso.tmp / "tool"
    stub.write_text("#!/bin/sh\nexit 0\n")
    stub.chmod(0o755)
    proc = realpaths.PROC_ROOT
    via_cwd = os.path.join(proc, "self", "cwd")
    via_stdin = os.path.join(proc, "self", "fd", "0")
    link_dir = iso.tmp / "link-dir"
    link_dir.symlink_to(os.path.join(via_cwd, "sub"))
    top_level_loot = os.path.join(via_cwd, "..", realpaths.SNIPER_TOP.lstrip("/"), "loot")
    calls = [
        lambda: subprocess.Popen([os.path.join(via_cwd, "tool")], cwd=str(iso.tmp)),
        lambda: subprocess.Popen(["tool"], cwd=str(iso.tmp), env={"PATH": via_cwd}),
        lambda: subprocess.Popen([realpaths.TRUE_BIN, os.path.join(via_cwd, "tool")]),
        lambda: subprocess.Popen([os.path.join(proc, "self", "root", str(stub).lstrip("/"))]),
        lambda: subprocess.Popen([realpaths.TRUE_BIN, "-r", "-c", "x", top_level_loot],
                                 cwd="/"),
        lambda: subprocess.Popen([realpaths.TRUE_BIN,
                                  os.path.join(proc, "thread-self", "cwd", "..", "tool")]),
        lambda: subprocess.Popen([realpaths.TRUE_BIN, os.path.join(str(link_dir), "..", "x")]),
        lambda: subprocess.Popen([realpaths.TRUE_BIN, os.path.join(via_stdin, "tool")]),
        lambda: subprocess.Popen([realpaths.TRUE_BIN,
                                  os.path.join(proc, "thread-self", "fd", "2")]),
        lambda: subprocess.Popen([via_stdin]),
        lambda: subprocess.Popen(["tool"], cwd=str(iso.tmp),
                                 env={"PATH": os.path.join(proc, "self", "fd", "1")}),
        lambda: subprocess.Popen([str(stub)], cwd=via_stdin),
        lambda: subprocess.Popen([str(stub)], cwd=os.path.join(via_cwd, "..")),
    ]
    for call in calls:
        with expect_violation("process") as record, \
                pytest.raises(hook.RealExecutionBlocked):
            call()
        assert "cwd, root or standard-descriptor link" in record.violations[0].detail


def test_a_link_then_dotdot_is_judged_where_the_kernel_resolves_it(iso):
    """Fix round 2, same class: the always-blocked rules resolved only the lexical form
    of a path, which drops a link followed by "..". A temp-root link then ".." named a
    real file while both lexical readings stayed in the temp root: under the
    interpreter's base prefix (an argv root) that let a child read the live loot. The
    plain spellings were always refused."""
    to_golden = iso.tmp / "to-golden"
    to_golden.symlink_to(REPO / "tests" / "fixtures" / "golden")
    to_share = iso.tmp / "to-share"
    to_share.symlink_to(os.path.join(realpaths.SNIPER_SHARE, "conf"))
    for argument in (os.path.join(str(to_golden), "..", "cli", "sudo"),
                     os.path.join(str(to_share), "..", "loot")):
        with expect_violation("process") as record, \
                pytest.raises(hook.RealExecutionBlocked):
            subprocess.Popen([realpaths.TRUE_BIN, argument])
        assert "names a real Sn1per or sudo binary" in record.violations[0].detail


def test_a_change_through_a_link_then_dotdot_is_judged_at_the_link_target(iso):
    """Fix round 2, same class: a remove, rename, mkdir or symlink resolved the parent
    of the name in its lexical form, so "<temp-root link>/../name" was judged as a
    name in the temp root while the kernel changes "name" in the parent of the link's
    target (a protected root here). The names do not exist, so neither call could
    change anything even if the guard let it through."""
    link = iso.tmp / "to-root-home"
    link.symlink_to(os.path.join(realpaths.ROOT_HOME, "sub"))
    target = os.path.join(str(link), "..", "missing-" + os.urandom(8).hex())
    with expect_violation("file") as record, pytest.raises(hook.RealExecutionBlocked):
        os.rmdir(target)
    assert realpaths.ROOT_HOME + "/missing-" in record.violations[0].detail
    with expect_violation("file"), pytest.raises(hook.RealExecutionBlocked):
        os.rename(str(iso.tmp / ("missing-" + os.urandom(8).hex())), target)


def test_python_child_pythonpath_is_judged_in_the_spelling_the_child_uses(iso, monkeypatch):
    """Fix round 2, same class: a Python child makes each PYTHONPATH entry absolute from
    its own cwd and normalizes it before it imports sitecustomize (the guard). A
    relative entry, one through /proc/self/cwd, or "<link>/../guard" named the guard
    here but an absent directory in the child, which then ran with no guard at all.
    PYTHONHOME would bring another site module. Only the absolute, normalized spelling
    is accepted, and the control child runs guarded."""
    guard = str(hook.GUARD_DIR)
    relative = os.path.relpath(guard, str(REPO))
    monkeypatch.chdir(REPO)  # the relative spelling names the guard from here
    to_fixtures = iso.tmp / "to-fixtures"
    to_fixtures.symlink_to(hook.GUARD_DIR.parent / "fixtures")
    code = "import sys; print(hasattr(sys, '_sn1per_mcp_test_guard_state'))"
    for env in ({"PYTHONPATH": relative},
                {"PYTHONPATH": os.path.join(realpaths.PROC_ROOT, "self", "cwd", relative)},
                {"PYTHONPATH": os.path.join(str(to_fixtures), "..", "guard")},
                {"PYTHONPATH": guard, "PYTHONHOME": sys.base_prefix}):
        with expect_violation("process") as record, \
                pytest.raises(hook.RealExecutionBlocked):
            subprocess.Popen([sys.executable, "-c", code], cwd=str(iso.tmp), env=env)
        assert "PYTHON" in record.violations[0].detail
    control = subprocess.run([sys.executable, "-c", code], cwd=str(iso.tmp),
                             env={"PYTHONPATH": guard}, capture_output=True, text=True,
                             timeout=60, check=False)
    assert control.stdout.strip() == "True", control.stderr


def test_posix_spawn_after_an_approved_fork_exec_popen_is_blocked(iso):
    """The approval of a Popen that took the fork_exec path does not linger."""
    argv = [sys.executable, "-c", "pass"]
    child = subprocess.Popen(argv, cwd=str(iso.tmp), start_new_session=True,
                             env=iso.child_env())
    assert child.wait(timeout=60) == 0
    with expect_violation("process"), pytest.raises(hook.RealExecutionBlocked):
        os.posix_spawn(sys.executable, argv, {"PATH": realpaths.MINIMAL_ENV_PATH})


def test_posix_spawn_is_never_approved(iso):
    """Fix review 3: os.posix_spawn converts its arguments in C before its audit event,
    from objects whose methods a test can replace (os.environ's keys() and values()), so
    an approved Popen no longer allows it, not even with the same executable, argv and
    environment, and subprocess never takes it under the guard: a call in the shape that
    would (no cwd, close_fds=False) runs through the fork_exec wrapper, guarded."""
    assert subprocess._USE_POSIX_SPAWN is False
    argv = [sys.executable, "-c", "import sys; print(sys._sn1per_mcp_test_guard_state.mode)"]
    env = iso.child_env()
    result = subprocess.run(argv, env=env, close_fds=False, capture_output=True, text=True,
                            timeout=60, check=False)
    assert result.stdout.strip() == "child", result.stderr
    sys.audit("subprocess.Popen", sys.executable, argv, None, env)
    with expect_violation("process") as record, pytest.raises(hook.RealExecutionBlocked):
        os.posix_spawn(sys.executable, argv, env)
    assert record.violations[0].event == "os.posix_spawn"


# --- SN1PER_MCP_TEST_GUARD only restricts ----------------------

def _forged(iso, name: str) -> dict:
    session = {"temp_root": iso.temp_root, "repo_root": str(REPO)}
    outside = os.path.join(os.path.dirname(iso.temp_root), "not-the-session")
    return {
        "system-dir": {**session, "temp_root": "/usr"},
        "filesystem-root": {**session, "temp_root": "/"},
        "temp-parent": {**session, "temp_root": os.path.dirname(iso.temp_root)},
        "temp-sibling": {**session, "temp_root": outside},
        "repo-elsewhere": {**session, "repo_root": "/usr"},
        "relative": {**session, "temp_root": "relative/dir"},
        "extra-key": {**session, "allow": True},
    }[name]


_FORGERIES = ["system-dir", "filesystem-root", "temp-parent", "temp-sibling", "repo-elsewhere",
              "relative", "extra-key"]


@pytest.mark.parametrize("name", _FORGERIES)
def test_parent_refuses_to_forward_a_widening_guard_variable(iso, name):
    env = {"PATH": realpaths.MINIMAL_ENV_PATH, "PYTHONPATH": str(hook.GUARD_DIR),
           hook.ENV_VAR: json.dumps(_forged(iso, name))}
    with expect_violation("process") as record, pytest.raises(hook.RealExecutionBlocked):
        subprocess.Popen([sys.executable, "-c", "pass"], env=env)
    assert hook.ENV_VAR in record.violations[0].detail


def test_parent_refuses_a_guard_variable_on_a_non_python_child(iso):
    env = {"PATH": realpaths.MINIMAL_ENV_PATH,
           hook.ENV_VAR: json.dumps(_forged(iso, "system-dir"))}
    with expect_violation("process"), pytest.raises(hook.RealExecutionBlocked):
        subprocess.Popen([realpaths.TRUE_BIN], env=env)


@pytest.mark.parametrize("name", [n for n in _FORGERIES if n != "temp-parent"])
def test_child_goes_strict_on_implausible_roots(iso, name):
    # A child cannot know its parent's temp root, so "temp-parent" (a private
    # directory of this user) is plausible there; the parent refuses it (above).
    assert hook.validated_roots(_forged(iso, name)) is None


def test_child_goes_strict_on_a_root_above_a_protected_root_or_the_interpreter(iso):
    real_home = os.path.realpath(os.path.expanduser("~" + _user_name()))
    for temp_root in {os.path.dirname(real_home), real_home, sys.prefix,
                      os.path.dirname(os.path.realpath(sys.prefix)), str(REPO)}:
        if temp_root == "/":
            continue
        roots = {"temp_root": temp_root, "repo_root": str(REPO)}
        assert hook.validated_roots(roots) is None, temp_root


def test_child_goes_strict_on_a_temp_root_inside_a_protected_root(iso, monkeypatch):
    """Review round 2: child mode exempts its temp root from the open rule, so a temp
    root inside a protected root (for example ~/.ssh) would widen strict mode."""
    protected = iso.tmp / "protected"
    inside = protected / "inner"
    inside.mkdir(parents=True, mode=0o700)
    protected.chmod(0o700)
    sibling = iso.tmp / "sibling"
    sibling.mkdir(mode=0o700)
    real_protected_roots = hook._protected_roots

    def with_test_root(realpaths_module, temp_root=None):
        return sorted({*real_protected_roots(realpaths_module, temp_root), str(protected)})

    monkeypatch.setattr(hook, "_protected_roots", with_test_root)
    assert hook.validated_roots({"temp_root": str(inside), "repo_root": str(REPO)}) is None
    assert hook.validated_roots({"temp_root": str(sibling), "repo_root": str(REPO)}) \
        == (str(sibling), str(REPO))


def test_child_goes_strict_on_a_shared_temp_root(iso):
    shared = iso.tmp / "shared-root"
    shared.mkdir(mode=0o700)
    shared.chmod(0o775)
    assert hook.validated_roots({"temp_root": str(shared), "repo_root": str(REPO)}) is None


def test_child_accepts_the_session_roots(iso):
    roots = {"temp_root": iso.temp_root, "repo_root": str(REPO)}
    assert hook.validated_roots(roots) == (iso.temp_root, str(REPO))


def _child_mode(iso, guard_value: str | None) -> str:
    code = ("import sys; s = sys._sn1per_mcp_test_guard_state; "
            "print(s.mode, s.temp_root)")
    env = {"PATH": realpaths.MINIMAL_ENV_PATH, "PYTHONPATH": str(hook.GUARD_DIR)}
    if guard_value is not None:
        env[hook.ENV_VAR] = guard_value
    result = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True,
                            text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def test_guarded_children_run_in_child_or_strict_mode(iso):
    sub = iso.tmp / "child-root"
    sub.mkdir(mode=0o700)
    assert _child_mode(iso, json.dumps({"temp_root": str(sub), "repo_root": str(REPO)})) \
        == f"child {sub}"
    assert _child_mode(iso, json.dumps({"temp_root": iso.temp_root, "repo_root": str(REPO)})) \
        == f"child {iso.temp_root}"
    assert _child_mode(iso, None) == "strict None"


def test_temp_root_link_to_a_real_binary_is_always_blocked(iso):
    """The always-blocked rules apply to the realpath too, never waived by the root."""
    link = iso.tmp / "helper"
    link.symlink_to(realpaths.SUDO_BIN)
    with expect_violation("process") as record, pytest.raises(hook.RealExecutionBlocked):
        subprocess.Popen([realpaths.TRUE_BIN, str(link)])
    assert "sudo" in record.violations[0].detail
    named_sudo = iso.tmp / "sudo"
    named_sudo.symlink_to(realpaths.TRUE_BIN)
    with expect_violation("process"), pytest.raises(hook.RealExecutionBlocked):
        subprocess.Popen([str(named_sudo)])


# --- the suite refuses to run without its conftest -------------

@pytest.mark.parametrize("flags", [
    ["--noconftest"],
    ["--confcutdir", str(TESTS / "fixtures")],
    ["--noconftest", "--import-mode=importlib"],
])
def test_suite_refuses_to_run_without_its_conftest(iso, flags):
    child_root = iso.tmp / "child-root"
    child_root.mkdir(mode=0o700)
    env = hook.child_env(str(child_root), str(REPO),
                         {"PATH": realpaths.MINIMAL_ENV_PATH, "HOME": str(iso.home)},
                         extra_pythonpath=[str(REPO / "src")])
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *flags,
         "--rootdir", str(REPO), "-c", str(REPO / "pyproject.toml"),
         "--basetemp", str(child_root / "basetemp"),
         str(TESTS / "test_settings.py"), str(TESTS / "test_protocol.py")],
        cwd=str(child_root), env=env, capture_output=True, text=True, timeout=120, check=False)
    output = result.stdout + result.stderr
    assert "test isolation guard (tests/conftest.py) is not active" in output, output
    assert " passed" not in output and " failed" not in output, output
    assert result.returncode == pytest.ExitCode.INTERRUPTED, output


def test_support_refuses_to_build_a_server_without_the_fixture(iso, monkeypatch):
    from sniper_mcp import paths
    from tests import support

    support.assert_isolated()
    monkeypatch.setattr(paths, "SUDO", realpaths.SUDO_BIN)
    with pytest.raises(AssertionError, match="paths.SUDO"):
        support.current_settings()


# --- writes, signals and dir_fd escapes ----------

def _real_home() -> str:
    home = os.path.realpath(os.path.expanduser("~" + _user_name()))
    if home == "/":
        pytest.skip("this account has no home directory")
    return home


@pytest.mark.parametrize("call", ["remove", "rmdir", "rename", "mkdir", "chmod", "rmtree"])
def test_changes_to_real_home_are_blocked(call):
    # Every target is a name that does not exist, so a guard failure changes nothing.
    missing = os.path.join(_real_home(), ".sn1per-mcp-guard-probe-missing")
    with expect_violation("file"), pytest.raises(hook.RealExecutionBlocked):
        if call == "remove":
            os.remove(missing)
        elif call == "rmdir":
            os.rmdir(missing)
        elif call == "rename":
            os.rename(missing, missing + "-2")
        elif call == "mkdir":
            os.mkdir(os.path.join(missing, "sub"))
        elif call == "chmod":
            os.chmod(missing, 0o700)
        else:
            import shutil

            shutil.rmtree(missing)


def test_removing_a_temp_link_to_a_real_file_is_allowed(iso):
    link = iso.tmp / "link-to-engine"
    link.symlink_to(realpaths.SNIPER_SHARE_CLI)
    os.remove(link)
    assert not os.path.lexists(link)


def test_signal_to_a_foreign_process_is_blocked():
    import signal

    # SIGCONT to pid 1 is harmless even if the guard failed.
    with expect_violation("process"), pytest.raises(hook.RealExecutionBlocked):
        os.kill(1, signal.SIGCONT)
    with expect_violation("process"), pytest.raises(hook.RealExecutionBlocked):
        os.killpg(1, signal.SIGCONT)
    with expect_violation("process"), pytest.raises(hook.RealExecutionBlocked):
        os.kill(0, signal.SIGCONT)


def test_signal_to_own_children_is_allowed(iso):
    import signal

    child = subprocess.Popen([realpaths.SLEEP_BIN, "30"], start_new_session=True)
    try:
        os.kill(child.pid, 0)
        os.killpg(child.pid, signal.SIGTERM)
        assert child.wait(timeout=30) == -signal.SIGTERM
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()


def test_opening_a_directory_above_the_real_home_is_blocked():
    parent = os.path.dirname(_real_home())
    state = hook.state()
    assert state is not None
    if parent == "/" or any(root == parent or root.startswith(parent + "/")
                            for root in state.exempt_roots):
        pytest.skip("the home's parent also leads to the checkout or the interpreter here")
    with expect_violation("file"), pytest.raises(hook.RealExecutionBlocked):
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        os.close(fd)


# --- the ledger is private -----------------------

def test_clearing_the_public_violation_list_hides_nothing():
    state = hook.state()
    assert state is not None
    with expect_violation("network"):
        with pytest.raises(hook.NetworkBlocked):
            socket.gethostbyname("app.example")
        before = len(state.unconsumed())
        hidden = list(state.violations)
        state.violations.clear()
        for violation in hidden:
            violation.consumed = True
        assert len(state.unconsumed()) == before
        state.violations.extend(hidden)


# --- INCIDENT row (4): stub sudo and stub CLIs exit 97 outside the temp root ------

def _run_stub(path: Path, *args: str) -> subprocess.CompletedProcess:
    env = {"PATH": realpaths.MINIMAL_ENV_PATH, "LC_ALL": "C.UTF-8"}
    return subprocess.run([str(path), *args], env=env, cwd="/", capture_output=True,
                          timeout=30, check=False)


def test_stub_sudo_refuses_a_command_outside_the_temp_root(iso):
    outside = os.path.join(os.path.dirname(iso.temp_root), "not-in-temp-root", "sniper-x")
    assert _run_stub(iso.sudo_path, "-n", "--", outside, "-t", "app.example").returncode == 97
    assert _run_stub(iso.sudo_path, "-n", "-l", outside).returncode == 97
    assert _run_stub(iso.sudo_path, "-n", "--", sys.executable, "-c", "pass").returncode == 97
    # In the temp root the stub works: it runs the stub CLI.
    ok = _run_stub(iso.sudo_path, "-n", "--", str(iso.cli_path), "-t", "app.example")
    assert ok.returncode == 0, ok.stdout + ok.stderr


@pytest.mark.parametrize("cli", ["sniper-9.2", "sniper-11.0"])
def test_stub_cli_refuses_an_install_dir_outside_the_temp_root(iso, cli):
    outside = os.path.dirname(iso.temp_root)
    text = (TESTS / "fixtures" / "cli" / cli).read_text()
    for placeholder, value in {"@INSTALL_DIR@": outside, "@TEMP_ROOT@": iso.temp_root,
                               "@KNOBS@": str(iso.knobs_path),
                               "@ARGV_LOG@": str(iso.argv_log_path),
                               "@PYTHON@": sys.executable}.items():
        text = text.replace(placeholder, value)
    stub = iso.tmp / f"outside-{cli}"
    stub.write_text(text)
    stub.chmod(0o755)
    result = _run_stub(stub, "-w", "anything", "-d")
    assert result.returncode == 97
    assert iso.calls() == []  # exited before logging or doing anything


@pytest.mark.parametrize("stub_name", ["sniper-9.2", "sniper-11.0", "sudo"])
def test_unreplaced_stub_refuses_to_run(iso, stub_name):
    stub = iso.tmp / f"raw-{stub_name}"
    stub.write_text((TESTS / "fixtures" / "cli" / stub_name).read_text())
    stub.chmod(0o755)
    assert _run_stub(stub, "-n", "--", str(iso.cli_path)).returncode == 97


# --- INCIDENT row (5): the hook cannot be removed by monkeypatch or a fixture ------

def test_monkeypatch_cannot_remove_the_hook(monkeypatch):
    for name in ("install", "state", "is_installed", "read_child_violations", "child_env"):
        monkeypatch.setattr(hook, name, lambda *a, **k: None)
    monkeypatch.setattr(sys, "addaudithook", lambda *a, **k: None)
    monkeypatch.setattr(hook, "GuardViolation", Exception)
    monkeypatch.setattr(subprocess, "Popen", subprocess.Popen)
    with expect_violation("process"), pytest.raises(Exception) as raised:
        subprocess.Popen([realpaths.SUDO_BIN, "-n", "true"])
    assert type(raised.value).__name__ == "RealExecutionBlocked"


def test_same_named_fixture_cannot_remove_the_hook(iso):
    """A test session whose autouse isolation fixture is overridden by name still
    has Layer 1: the blocked call raises and the child session fails."""
    work = iso.tmp / "override-session"
    work.mkdir()
    (work / "conftest.py").write_text(textwrap.dedent("""
        from tests.conftest import pytest_configure, pytest_sessionfinish  # noqa: F401
        from tests.conftest import _isolation_fixture  # noqa: F401
    """))
    fixture_name = hook.ISOLATION_FIXTURE_NAME
    (work / "test_override.py").write_text(textwrap.dedent(f"""
        import subprocess
        import pytest

        @pytest.fixture(autouse=True)
        def {fixture_name}():
            yield None

        def test_blocked_even_without_layer_two():
            with pytest.raises(Exception) as raised:
                subprocess.Popen([{realpaths.SUDO_BIN!r}, "-n", "true"])
            assert type(raised.value).__name__ == "RealExecutionBlocked"
    """))
    child_root = iso.tmp / "child-root"
    child_root.mkdir(mode=0o700)
    env = hook.child_env(str(child_root), str(REPO),
                         {"PATH": realpaths.MINIMAL_ENV_PATH, "HOME": str(iso.home)},
                         extra_pythonpath=[str(REPO), str(REPO / "src")])
    # The inner session's blocked sudo is also written to the child file below
    # child_root, which the outer test must consume or it fails too.
    with expect_child_violation(str(child_root), "process") as children:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
             "--basetemp", str(child_root / "basetemp"), "--rootdir", str(work), str(work)],
            cwd=str(work), env=env, capture_output=True, text=True, timeout=120, check=False)
    output = result.stdout + result.stderr
    assert "1 passed" in output, output
    assert "TEST GUARD VIOLATIONS" in output, output
    assert result.returncode == 1, output
    assert any("sudo" in str(item.get("detail")) for item in children), children


# --- O.2 item 5: meta-tests ---------------------------------------------------

_FORBIDDEN_MODULES = {"pty", "ctypes", "_ctypes", "_posixsubprocess", "multiprocessing",
                      "_multiprocessing", "concurrent.futures.process", "_imp"}
# Calls that load a module by name. A fresh instance of _posixsubprocess built
# with find_spec + module_from_spec has an unwrapped fork_exec.
_DYNAMIC_IMPORT_CALLS = {"__import__", "importlib.import_module", "import_module",
                         "importlib.util.find_spec", "util.find_spec", "find_spec",
                         "importlib.reload", "reload", "importlib.__import__"}
_FORBIDDEN_NAMES = {"ProcessPoolExecutor"}
_FORBIDDEN_OS_CALLS = re.compile(
    r"(system|popen|exec[lv]p?e?|spawn[lv]p?e?|posix_spawnp?|fork|forkpty)")
_SPAWN_MODULES = {"subprocess", "asyncio.subprocess"}


def _imports(tree: ast.AST) -> list[tuple[str, int]]:
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [(alias.name, node.lineno) for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.append((node.module, node.lineno))
            found += [(f"{node.module}.{alias.name}", node.lineno) for alias in node.names]
    return found


def _module_aliases(tree: ast.AST) -> dict[str, str]:
    """Local name -> module, for ``import os as o`` and ``from asyncio import subprocess``."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    aliases[alias.name.split(".")[0]] = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _process_api_uses(tree: ast.AST, *, allow_subprocess: bool) -> list[tuple[int, str]]:
    """Process-creation APIs named in ``tree``, however they are spelled.

    Catches aliases (``import os as o; o.system``), ``getattr(os, "system")``,
    ``from asyncio import create_subprocess_exec``, star imports from ``os`` and
    dynamic imports of the spawning modules.
    """
    aliases = _module_aliases(tree)
    os_names = {name for name, module in aliases.items() if module == "os"}
    asyncio_names = {name for name, module in aliases.items() if module == "asyncio"}
    found: list[tuple[int, str]] = []

    def forbidden_attr(owner: str, attr: str) -> str | None:
        if owner in os_names and _FORBIDDEN_OS_CALLS.fullmatch(attr):
            return f"os.{attr}"
        if owner in asyncio_names and attr.startswith("create_subprocess"):
            return f"asyncio.{attr}"
        if owner in asyncio_names and attr == "subprocess" and not allow_subprocess:
            return "asyncio.subprocess"
        return None

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for name, line in _imports(node):
                root = name.split(".")[0]
                if name in _FORBIDDEN_MODULES or root in _FORBIDDEN_MODULES \
                        or name.split(".")[-1] in _FORBIDDEN_NAMES:
                    found.append((line, f"imports {name}"))
                if not allow_subprocess and (root == "subprocess"
                                             or name.startswith("asyncio.subprocess")):
                    found.append((line, f"imports {name} (only proc.py may)"))
            if isinstance(node, ast.ImportFrom) and node.module in ("os", "posix"):
                for alias in node.names:
                    if alias.name == "*" or _FORBIDDEN_OS_CALLS.fullmatch(alias.name):
                        found.append((node.lineno, f"imports os.{alias.name}"))
            if isinstance(node, ast.ImportFrom) and node.module == "asyncio":
                for alias in node.names:
                    if alias.name.startswith("create_subprocess") or (
                            alias.name == "subprocess" and not allow_subprocess):
                        found.append((node.lineno, f"imports asyncio.{alias.name}"))
            if isinstance(node, ast.ImportFrom) and node.module == "subprocess":
                found.append((node.lineno, "'from subprocess import' is not allowed"))
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            what = forbidden_attr(node.value.id, node.attr)
            if what:
                found.append((node.lineno, f"uses {what}"))
        elif isinstance(node, ast.Call):
            func = ast.unparse(node.func)
            args = node.args
            if func in ("getattr", "builtins.getattr") and len(args) >= 2 \
                    and isinstance(args[0], ast.Name) and isinstance(args[1], ast.Constant) \
                    and isinstance(args[1].value, str):
                what = forbidden_attr(args[0].id, args[1].value)
                if what:
                    found.append((node.lineno, f"uses getattr for {what}"))
            if func in _DYNAMIC_IMPORT_CALLS and args \
                    and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str):
                module = args[0].value
                if module.split(".")[0] in _FORBIDDEN_MODULES or (
                        not allow_subprocess and module in _SPAWN_MODULES):
                    found.append((node.lineno, f"imports {module} dynamically"))
    return found


def test_meta_only_proc_creates_processes():
    problems = []
    for path in _py_files(SRC):
        tree = ast.parse(path.read_text(), str(path))
        rel = path.relative_to(SRC.parent)
        is_proc = path.name == "proc.py" and path.parent == SRC
        for line, what in _process_api_uses(tree, allow_subprocess=is_proc):
            problems.append(f"{rel}:{line}: {what}")
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize("snippet", [
    "import os as o\no.system('x')",
    "import os\ngetattr(os, 'system')('x')",
    "from asyncio import create_subprocess_exec",
    "import asyncio as a\na.create_subprocess_shell('x')",
    "from os import *",
    "from os import posix_spawn",
    "import multiprocessing.pool",
    "from concurrent.futures import ProcessPoolExecutor",
    "import concurrent.futures.process",
    "__import__('subprocess')",
    "import importlib\nimportlib.import_module('ctypes')",
    "from asyncio import subprocess",
    "import pty",
    "import importlib.util\nimportlib.util.find_spec('_posixsubprocess')",
    "from importlib.util import find_spec\nfind_spec('_posixsubprocess')",
    "from importlib import util\nutil.find_spec('multiprocessing')",
    "import _imp",
    "from _imp import create_builtin",
])
def test_meta_process_api_detector_catches_spellings(snippet):
    assert _process_api_uses(ast.parse(snippet), allow_subprocess=False)


def test_meta_tests_never_use_multiprocessing_ctypes_or_pty():
    """O.2 extended to tests/: these create processes or call C without an audit event.

    Only the guard (which wraps them) and this module (which proves they are
    blocked) may name them; other tests use ``subprocess`` only.
    """
    allowed = {TESTS / "test_guard.py"}
    problems = []
    for path in _py_files(TESTS):
        if path in allowed or TESTS / "guard" in path.parents:
            continue
        tree = ast.parse(path.read_text(), str(path))
        for line, what in _process_api_uses(tree, allow_subprocess=True):
            if "subprocess" not in what:
                problems.append(f"{path.relative_to(REPO)}:{line}: {what}")
    assert not problems, "\n".join(problems)


def test_meta_proc_uses_attribute_access_on_subprocess():
    tree = ast.parse((SRC / "proc.py").read_text())
    names = [n for n, _ in _imports(tree)]
    assert "subprocess" in names
    assert not any(n.startswith("subprocess.") for n in names)


def test_meta_no_real_path_literals_under_tests():
    allowed = TESTS / "realpaths.py"
    home_re = re.compile(realpaths.HOME_PATH_PATTERN)
    problems = []
    for path in sorted(TESTS.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts or path == allowed:
            continue
        try:
            text = path.read_text()
        except UnicodeDecodeError:
            continue
        for literal in realpaths.FORBIDDEN_LITERALS:
            if literal in text:
                problems.append(f"{path.relative_to(REPO)}: contains {literal!r}")
        match = home_re.search(text)
        if match:
            problems.append(f"{path.relative_to(REPO)}: contains home path {match.group(0)!r}")
    assert not problems, "\n".join(problems)


def _fixture_name(node: ast.FunctionDef) -> str | None:
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        dotted = ast.unparse(target)
        if dotted.endswith("fixture"):
            if isinstance(decorator, ast.Call):
                for keyword in decorator.keywords:
                    if keyword.arg == "name":
                        return ast.unparse(keyword.value)
            return node.name
    return None


def test_meta_guard_integrity():
    problems = []
    guard_dir = TESTS / "guard"
    for path in _py_files(TESTS):
        rel = path.relative_to(REPO)
        privileged = path == TESTS / "conftest.py" or guard_dir in path.parents
        tree = ast.parse(path.read_text(), str(path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not privileged:
                name = _fixture_name(node)
                if name is not None and hook.ISOLATION_FIXTURE_NAME in (name, name.strip("'\"")):
                    problems.append(f"{rel}:{node.lineno}: overrides the isolation fixture")
                if node.name == hook.ISOLATION_FIXTURE_NAME:
                    problems.append(f"{rel}:{node.lineno}: defines the isolation fixture name")
            if isinstance(node, ast.Call) and not privileged:
                if ast.unparse(node.func).endswith("addaudithook"):
                    problems.append(f"{rel}:{node.lineno}: calls addaudithook")
        if path.name != "test_guard.py" and not privileged:
            for name, line in _imports(tree):
                if name.endswith("expect_violation") or name.endswith("guard.expect"):
                    problems.append(f"{rel}:{line}: imports expect_violation")
            # Removing a child's violation file is how a child trip is consumed.
            text = path.read_text()
            for token in ("CHILD_VIOLATIONS_FILE", "child_violation_files",
                          hook.CHILD_VIOLATIONS_FILE, "expect_child_violation"):
                if token in text:
                    problems.append(f"{rel}: names {token!r} (child violation files)")
    assert not problems, "\n".join(problems)


# Reaching the guard's own objects is outside the hook's model (tests/guard/hook.py
# docstring): the wrappers' closure cells hold the real fork_exec, and gc reaches the ledger.
_GUARD_INTERNALS = frozenset({"__closure__", "cell_contents", "__globals__", "__code__"})


def _guard_internals_uses(tree: ast.AST) -> list[tuple[int, str]]:
    """Spellings that take a function or the garbage collector apart."""
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in _GUARD_INTERNALS:
            found.append((node.lineno, f"uses .{node.attr}"))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for name, line in _imports(node):
                if name.split(".")[0] == "gc":
                    found.append((line, f"imports {name}"))
        elif isinstance(node, ast.Call):
            func = ast.unparse(node.func)
            args = node.args
            if func in ("getattr", "setattr", "delattr", "builtins.getattr") \
                    and len(args) >= 2 and isinstance(args[1], ast.Constant) \
                    and args[1].value in _GUARD_INTERNALS:
                found.append((node.lineno, f"uses {func} for {args[1].value}"))
            if func in _DYNAMIC_IMPORT_CALLS and args and isinstance(args[0], ast.Constant) \
                    and args[0].value == "gc":
                found.append((node.lineno, "imports gc dynamically"))
    return found


@pytest.mark.parametrize("snippet", [
    "import gc\ngc.get_objects()",
    "from gc import get_referents",
    "import importlib\nimportlib.import_module('gc')",
    "fork_exec.__closure__[0].cell_contents",
    "getattr(fork_exec, '__closure__')",
    "audit.__globals__['x'] = 1",
    "check.__code__ = other.__code__",
])
def test_meta_guard_internals_detector_catches_spellings(snippet):
    assert _guard_internals_uses(ast.parse(snippet))


def test_meta_tests_never_take_the_guard_apart():
    """Fix review 3: what the hook's model leaves out (code that takes the guard itself
    apart through closure cells, function globals or code objects, or gc) is kept out of
    every test file except this one, which only reads the hook's code objects."""
    problems = []
    for path in _py_files(TESTS):
        if path == TESTS / "test_guard.py" or TESTS / "guard" in path.parents:
            continue
        tree = ast.parse(path.read_text(), str(path))
        for line, what in _guard_internals_uses(tree):
            problems.append(f"{path.relative_to(REPO)}:{line}: {what}")
    assert not problems, "\n".join(problems)


_SYSTEM_PATH_RE = re.compile(r"^/(usr|bin|sbin|etc|proc|sys|root|home|opt|var|tmp|dev|sniper)(/|$)")


def test_meta_src_names_system_paths_only_in_paths_module():
    problems = []
    for path in _py_files(SRC):
        if path == SRC / "paths.py":
            continue
        tree = ast.parse(path.read_text(), str(path))
        docstrings = {id(node.body[0].value) for node in ast.walk(tree)
                      if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                                           ast.ClassDef))
                      and node.body and isinstance(node.body[0], ast.Expr)
                      and isinstance(node.body[0].value, ast.Constant)}
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and id(node) not in docstrings and _SYSTEM_PATH_RE.match(node.value)):
                problems.append(f"{path.relative_to(SRC.parent)}:{node.lineno}: {node.value!r}")
            if isinstance(node, ast.ImportFrom) and node.module == "sniper_mcp.paths":
                problems.append(f"{path.relative_to(SRC.parent)}:{node.lineno}: "
                                "import paths as a module so tests can patch it")
    assert not problems, "\n".join(problems)


def test_meta_no_real_execution_switch():
    """O.7: nothing under tests/ reads a variable or marker that enables real execution."""
    pattern = re.compile(r"(REAL_EXEC|ALLOW_REAL|LIVE_SCAN|RUN_REAL|--real|--live)", re.I)
    problems = []
    for path in _py_files(TESTS):
        if path == Path(__file__).resolve():
            continue
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            if pattern.search(line):
                problems.append(f"{path.relative_to(REPO)}:{number}: {line.strip()}")
    assert not problems, "\n".join(problems)


def test_child_violation_files_are_read_recursively_with_stable_sources(iso):
    root = iso.tmp / "probe"
    (root / "nested").mkdir(parents=True)
    line = json.dumps({"kind": "process", "event": "subprocess.Popen", "detail": "x",
                       "pid": 1}) + "\n"
    with expect_child_violation(str(root), "process") as found:
        (root / "nested" / hook.CHILD_VIOLATIONS_FILE).write_text(line)
        assert hook.read_child_violations(str(root)) == []
        items = hook.read_child_violations(str(root), recursive=True)
        assert [item["kind"] for item in items] == ["process"]
        assert items[0]["source"].endswith(f"{hook.CHILD_VIOLATIONS_FILE}:1")
    assert found and not hook.child_violation_files(str(root), recursive=True)


def test_hidden_trip_of_a_child_in_a_sub_root_fails_the_test_and_the_session(iso):
    """Review round 2: a guarded child given a sub-root of the temp root writes its
    violations there. When the child's own code catches the guard exception (a
    production broad except), the per-test fixture and pytest_sessionfinish still
    fail. Proven in a child pytest session, whose output is checked here."""
    work = iso.tmp / "hidden-trip-session"
    work.mkdir()
    (work / "conftest.py").write_text(textwrap.dedent("""
        from tests.conftest import pytest_configure, pytest_sessionfinish  # noqa: F401
        from tests.conftest import _isolation_fixture, iso  # noqa: F401
    """))
    (work / "test_hidden.py").write_text(textwrap.dedent("""
        import subprocess
        import sys

        from tests import realpaths
        from tests.guard import hook

        def test_grandchild_hides_its_trip(iso):
            sub = iso.tmp / "grandchild-root"
            sub.mkdir(mode=0o700)
            repo = hook.state().repo_root
            env = hook.child_env(str(sub), repo, {"PATH": realpaths.MINIMAL_ENV_PATH})
            code = ("import subprocess\\n"
                    "try:\\n"
                    f"    subprocess.Popen([{realpaths.SUDO_BIN!r}, '-n', 'true'])\\n"
                    "except Exception:\\n"
                    "    pass\\n")
            result = subprocess.run([sys.executable, "-c", code], env=env,
                                    capture_output=True, text=True, timeout=60, check=False)
            assert result.returncode == 0, result.stderr
    """))
    child_root = iso.tmp / "child-root"
    child_root.mkdir(mode=0o700)
    env = hook.child_env(str(child_root), str(REPO),
                         {"PATH": realpaths.MINIMAL_ENV_PATH, "HOME": str(iso.home)},
                         extra_pythonpath=[str(REPO), str(REPO / "src")])
    with expect_child_violation(str(child_root), "process") as children:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
             "--basetemp", str(child_root / "basetemp"), "--rootdir", str(work), str(work)],
            cwd=str(work), env=env, capture_output=True, text=True, timeout=120, check=False)
    output = result.stdout + result.stderr
    assert "1 passed" in output, output
    assert "ERROR at teardown of test_grandchild_hides_its_trip" in output, output
    assert "TEST GUARD VIOLATIONS" in output, output
    assert result.returncode == 1, output
    assert any("sudo" in str(item.get("detail")) for item in children), children


def _user_name() -> str:
    import pwd

    return pwd.getpwuid(os.getuid()).pw_name
