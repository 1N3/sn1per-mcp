# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""The only module that creates processes (contract D.5, J.5, L.2, L.6, O.2).

Every child gets a minimal environment (never ``os.environ``), stdin from
``/dev/null`` unless input is given, ``close_fds=True`` and its own session.
A meta-test enforces that no other module imports ``subprocess`` or calls any
other process-creation API.

A scan that runs through sudo is started by the terminal holder (D.5, L.6): this
module run as ``python -m sniper_mcp.proc``, which gives sudo a controlling
pseudo-terminal. Without a terminal sudo does not apply ``use_pty`` and relays a
signal only to its direct child, so a non-root ``cancel_scan`` could not stop an
11.x scan (whose body runs in a subshell piped to ``tee``). With one, sudo runs the
engine in a process group of its own and relays the signal to the whole group.
"""

from __future__ import annotations

import fcntl
import os
import select
import shutil
import signal
import stat
import subprocess
import sys
import termios
import time
from collections.abc import Sequence
from dataclasses import dataclass

from sniper_mcp import paths

Process = subprocess.Popen

_KILL_GRACE_SECONDS = 2.0

# The terminal holder (L.6): module, command-line flag, and how long the launcher waits
# for the holder to report the pid of the sudo process it started.
HOLDER_MODULE = "sniper_mcp.proc"
HOLDER_FLAG = "--sudo-terminal"
HOLDER_REPORT_SECONDS = 10.0
_HOLDER_POLL_SECONDS = 0.5
# The directory this package was imported from: the holder imports the same code.
_PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class LaunchError(Exception):
    """A child process could not be created (``launch_failed``)."""

    code = "launch_failed"

    def __init__(self, message: str, *, cause: str) -> None:
        super().__init__(message)
        self.cause = cause


@dataclass(frozen=True)
class SudoInfo:
    """Result of resolving the sudo binary (D.5)."""

    path: str | None
    status: str  # "ok", "missing" or "untrusted"
    detail: str | None = None


@dataclass(frozen=True)
class CaptureResult:
    """Output of :func:`run_capture`."""

    returncode: int | None
    output: bytes
    timed_out: bool
    output_truncated: bool


@dataclass(frozen=True)
class StreamResult:
    """Output of :func:`run_streaming`."""

    returncode: int | None
    output: bytes
    lines: int
    stopped_reason: str  # "complete", "max_lines", "max_bytes" or "timeout"
    # With max_record_bytes: the positions, in output order, of the kept records whose
    # line was longer than the per-record cap and was cut while it streamed in.
    cut_records: tuple[int, ...] = ()


def minimal_env(home: str) -> dict[str, str]:
    """The fixed child environment of D.5; nothing is inherited."""
    return {
        "PATH": paths.MINIMAL_ENV_PATH,
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
        "HOME": home,
        "TERM": "dumb",
    }


_sudo_candidates: dict[tuple[str, str], str | None] = {}


def _sudo_candidate() -> str | None:
    """``paths.SUDO`` if it exists, else ``shutil.which("sudo")``, resolved once (D.5).

    The result is the realpath, so the argv never names a user-owned symlink
    whose target could be swapped after the ownership check.
    """
    key = (paths.SUDO, os.environ.get("PATH", ""))
    if key not in _sudo_candidates:
        candidate = paths.SUDO if os.path.lexists(paths.SUDO) else shutil.which("sudo")
        _sudo_candidates[key] = os.path.realpath(candidate) if candidate else None
    return _sudo_candidates[key]


def resolve_sudo() -> SudoInfo:
    """Check the sudo binary: a root-owned regular file, not group- or world-writable.

    The path is resolved once per process (D.5) and returned as its realpath,
    which is what callers put in argv; the file checks run on every call.
    """
    candidate = _sudo_candidate()
    if candidate is None:
        return SudoInfo(path=None, status="missing", detail="no sudo binary found")
    try:
        st = os.stat(candidate, follow_symlinks=False)
    except OSError as exc:
        return SudoInfo(path=None, status="missing", detail=f"{candidate}: {exc.strerror}")
    if not stat.S_ISREG(st.st_mode):
        return SudoInfo(path=candidate, status="untrusted", detail="not a regular file")
    if st.st_uid != paths.TRUSTED_UID:
        return SudoInfo(path=candidate, status="untrusted",
                        detail=f"owned by uid {st.st_uid}, not by root")
    if stat.S_IMODE(st.st_mode) & 0o022:
        return SudoInfo(path=candidate, status="untrusted",
                        detail="group- or world-writable")
    return SudoInfo(path=candidate, status="ok")


def _kill_group(proc: Process) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def spawn_detached(argv: Sequence[str], *, log_fd: int, home: str) -> Process:
    """Start a long-running child in its own session with output to ``log_fd`` (D.5).

    Raises :class:`LaunchError` for any failure to create the process.
    """
    try:
        return subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=log_fd,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
            cwd=paths.SPAWN_CWD,
            env=minimal_env(home),
        )
    except Exception as exc:  # any spawn failure is launch_failed (F.9 step 15)
        raise LaunchError(f"could not start {argv[0]!r}", cause=type(exc).__name__) from exc


# --- the terminal holder (D.5, L.6) ---------------------------------------------------------

def holder_env(home: str) -> dict[str, str]:
    """Environment of the terminal holder: the minimal environment plus ``PYTHONPATH``
    naming the directory this package was imported from, so the holder runs this same
    code. The holder gives sudo the plain minimal environment."""
    env = minimal_env(home)
    env["PYTHONPATH"] = _PACKAGE_ROOT
    return env


def holder_argv(argv: Sequence[str], report_fd: int) -> list[str]:
    """``python -s -P -m sniper_mcp.proc --sudo-terminal <fd> -- <sudo argv>``."""
    return [sys.executable, "-s", "-P", "-m", HOLDER_MODULE, HOLDER_FLAG, str(report_fd),
            "--", *argv]


@dataclass(frozen=True)
class Launched:
    """A scan started by :func:`spawn_with_terminal`."""

    process: Process  # the terminal holder (or sudo itself when no holder could run)
    front_pid: int | None  # the sudo process the holder started, when it reported it
    note: str | None = None  # why the scan runs without a terminal, else None


def _read_report(fd: int, timeout: float) -> int | None:
    """The pid line the holder writes to its report pipe, or None (EOF, junk, timeout)."""
    deadline = time.monotonic() + timeout
    data = b""
    while len(data) < 32:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        try:
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                return None
            chunk = os.read(fd, 32)
        except OSError:
            return None
        if not chunk:
            break
        data += chunk
        if b"\n" in data:
            break
    line = data.split(b"\n", 1)[0].strip()
    return int(line) if line.isdigit() and 1 < int(line) < 2 ** 31 else None


def spawn_with_terminal(argv: Sequence[str], *, log_fd: int, home: str) -> Launched:
    """Start a sudo command line under the terminal holder, detached, output to ``log_fd``.

    The holder is a session leader that takes a new pseudo-terminal as its controlling
    terminal and starts ``argv`` (``sudo -n -- <cli> ...``) in its session, so sudo
    has a terminal and applies ``use_pty`` (L.6). It reports the pid of that sudo
    process on a pipe and then waits for it: its exit status is sudo's. Without a
    Python interpreter to run the holder, ``argv`` is started directly (the old,
    terminal-less launch) and ``note`` says so. Raises :class:`LaunchError`.
    """
    if not sys.executable:
        note = "no Python interpreter to run the terminal holder"
        return Launched(spawn_detached(argv, log_fd=log_fd, home=home), None, note)
    read_fd, write_fd = os.pipe()
    try:
        try:
            process = subprocess.Popen(
                holder_argv(argv, write_fd),
                stdin=subprocess.DEVNULL,
                stdout=log_fd,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                close_fds=True,
                pass_fds=(write_fd,),
                cwd=paths.SPAWN_CWD,
                env=holder_env(home),
            )
        except Exception as exc:  # any spawn failure is launch_failed (F.9 step 15)
            raise LaunchError(f"could not start the terminal holder for {argv[0]!r}",
                              cause=type(exc).__name__) from exc
        os.close(write_fd)
        write_fd = -1
        front = _read_report(read_fd, HOLDER_REPORT_SECONDS)
    finally:
        if write_fd >= 0:
            os.close(write_fd)
        os.close(read_fd)
    return Launched(process, front)


def _holder_note(text: str) -> None:
    """One line into the job log (the holder's stdout is the log)."""
    try:
        os.write(1, f"sn1per-mcp: {text}\n".encode("utf-8", "replace"))
    except OSError:
        pass


def _copy_out(master: int) -> None:
    """Anything written to the terminal goes into the job log, so no writer ever blocks
    on a full terminal buffer."""
    try:
        data = os.read(master, 65536)
    except OSError:
        time.sleep(_HOLDER_POLL_SECONDS)
        return
    view = memoryview(data)
    while view:
        try:
            written = os.write(1, view)
        except OSError:
            return
        view = view[written:]


def _holder_main(args: Sequence[str]) -> int:
    """The terminal holder: ``--sudo-terminal <report fd> -- <sudo argv>`` (L.6).

    Runs as a session leader without a controlling terminal (the launcher starts it
    with ``start_new_session``), takes a new pseudo-terminal as its controlling
    terminal, starts the command in the holder's session and process group (so sudo is
    in the terminal's foreground process group and has the terminal), writes its pid
    to the report fd, copies terminal output into the log, and exits with the command's
    status (a command killed by a signal ends the holder with the same signal). A
    terminal that cannot be set up is noted in the log, and the command runs without it.
    """
    if len(args) < 4 or args[0] != HOLDER_FLAG or not args[1].isdigit() or args[2] != "--":
        _holder_note("terminal holder: bad arguments")
        return 2
    report_fd = int(args[1])
    command = list(args[3:])
    master = slave = -1
    try:
        master, slave = os.openpty()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    except OSError as exc:
        _holder_note(f"no controlling terminal for sudo ({exc.strerror or exc}); "
                     "cancel_scan may not stop every process of this scan")
        for fd in (master, slave):
            if fd >= 0:
                os.close(fd)
        master = slave = -1
    try:
        # cwd: inherited; the launcher started the holder in paths.SPAWN_CWD (D.5).
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, close_fds=True,
                                 env=minimal_env(os.environ.get("HOME") or "/"))
    except Exception as exc:  # noqa: BLE001 - reported in the log; the launcher sees EOF
        _holder_note(f"could not start {command[0]!r} ({type(exc).__name__})")
        os.close(report_fd)
        return 127
    try:
        os.write(report_fd, f"{child.pid}\n".encode("ascii"))
    except OSError:
        pass
    os.close(report_fd)
    try:
        while child.poll() is None:
            if master < 0:
                try:
                    child.wait(timeout=_HOLDER_POLL_SECONDS)
                except subprocess.TimeoutExpired:
                    pass
                continue
            try:
                ready, _, _ = select.select([master], [], [], _HOLDER_POLL_SECONDS)
            except OSError:
                ready = []
            if ready:
                _copy_out(master)
    finally:
        # The slave stays open until here: while the holder lives, the terminal is
        # never hung up, so the master never reads as end of file in a busy loop.
        # Closing the master hangs the terminal up, which sends SIGHUP to the holder
        # (its controlling process): the holder ends with the command's status instead.
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        for fd in (master, slave):
            if fd >= 0:
                os.close(fd)
    status = child.returncode
    if status < 0:
        number = -status
        if number not in (signal.SIGKILL, signal.SIGSTOP):
            signal.signal(number, signal.SIG_DFL)
        os.kill(os.getpid(), number)
        return 128 + number
    return status


# After a timeout kill, how long run_capture keeps reading for the rest of the output. A
# process outside the killed group (a root engine under sudo, which an unprivileged
# killpg cannot reach) may hold the pipe open for much longer; the call does not wait.
_DRAIN_SECONDS = 10.0


def _close_pipes(proc: Process) -> None:
    for pipe in (proc.stdin, proc.stdout):
        if pipe is not None:
            try:
                pipe.close()
            except OSError:
                pass


def run_capture(argv: Sequence[str], *, home: str, timeout: float,
                input_bytes: bytes | None = None,
                max_output: int = 1024 * 1024, keep: str = "head") -> CaptureResult:
    """Run a short command to completion, capturing stdout and stderr together.

    The child runs in its own session; on timeout the whole group is killed and the
    remaining output is read for at most ``_DRAIN_SECONDS``. Only ``max_output`` bytes
    are kept: the first ones (``keep="head"``) or the last ones (``keep="tail"``, for
    callers that report the end of the output).
    """
    if keep not in ("head", "tail"):
        raise ValueError(f"keep must be 'head' or 'tail', not {keep!r}")
    try:
        proc = subprocess.Popen(
            list(argv),
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
            cwd=paths.SPAWN_CWD,
            env=minimal_env(home),
        )
    except Exception as exc:
        raise LaunchError(f"could not start {argv[0]!r}", cause=type(exc).__name__) from exc
    try:
        out, _ = proc.communicate(input=input_bytes, timeout=timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        try:
            out, _ = proc.communicate(timeout=_DRAIN_SECONDS)
        except subprocess.TimeoutExpired as exc:
            out = exc.output or b""  # everything read so far, both communicate calls
            _close_pipes(proc)
        timed_out = True
    truncated = len(out) > max_output
    kept = out[len(out) - max_output:] if keep == "tail" and truncated else out[:max_output]
    return CaptureResult(
        returncode=None if timed_out else proc.returncode,
        output=kept,
        timed_out=timed_out,
        output_truncated=truncated,
    )


# How long run_streaming waits, at a limit, to learn whether the output simply ended there.
_EOF_PROBE_SECONDS = 0.25


def _at_eof(fd: int, deadline: float) -> bool:
    """True when the pipe reaches end of file within a short wait: the child wrote
    nothing past the limit, so the result is complete and its exit status counts."""
    wait = min(_EOF_PROBE_SECONDS, max(0.0, deadline - time.monotonic()))
    try:
        ready, _, _ = select.select([fd], [], [], wait)
        return bool(ready) and os.read(fd, 1) == b""
    except OSError:
        return False


def run_streaming(argv: Sequence[str], *, home: str, cwd: str,
                  pass_fds: Sequence[int] = (), max_lines: int, max_bytes: int,
                  timeout: float, nul_framed: bool = False,
                  max_record_bytes: int | None = None,
                  max_raw_bytes: int | None = None) -> StreamResult:
    """Run a command and read its stdout incrementally (J.5).

    Stops at ``max_lines`` newline-terminated lines, ``max_bytes`` bytes or
    ``timeout`` seconds, whichever comes first, then kills the child's process
    group. The output is never buffered beyond ``max_bytes``. Output that ends
    exactly at a limit (end of file follows within a short wait) is ``complete``,
    with the child's exit status.

    With ``nul_framed`` (``grep -Z`` output, ``<name> NUL <line>:<text> newline``) a
    line ends only at the first newline after a NUL, so newlines inside file names
    cannot use up ``max_lines`` and hide matches. With ``max_record_bytes`` as well,
    each record is kept up to that many bytes (the rest of an overlong line is read
    and dropped, and the record keeps its newline; ``cut_records`` says which records
    were cut), ``max_bytes`` counts only the bytes kept, and ``max_raw_bytes`` bounds
    everything read from the child, the dropped rest of overlong lines included: one
    huge line can no longer use up the budget of the whole search (V2 D2), as long as
    ``max_raw_bytes`` is far above the longest line (RC R1).
    """
    if max_record_bytes is not None and not nul_framed:
        raise ValueError("max_record_bytes needs nul_framed")
    try:
        proc = subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
            pass_fds=tuple(pass_fds),
            cwd=cwd,
            env=minimal_env(home),
        )
    except Exception as exc:
        raise LaunchError(f"could not start {argv[0]!r}", cause=type(exc).__name__) from exc
    assert proc.stdout is not None
    fd = proc.stdout.fileno()
    deadline = time.monotonic() + timeout
    reason = "timeout"  # until a reader returns (an exception also kills the group)
    cut: list[int] = []
    try:
        if max_record_bytes is not None:
            chunks, lines, reason, cut = _read_records(
                fd, deadline, max_records=max_lines, max_kept=max_bytes,
                max_raw=max_raw_bytes if max_raw_bytes is not None else max_bytes,
                cap=max_record_bytes)
        else:
            chunks, lines, reason = _read_lines(fd, deadline, max_lines=max_lines,
                                                max_bytes=max_bytes, nul_framed=nul_framed)
    finally:
        if reason != "complete" and proc.poll() is None:
            _kill_group(proc)
        proc.stdout.close()
        try:
            proc.wait(timeout=_KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            proc.wait()
    returncode = proc.returncode if reason == "complete" else None
    return StreamResult(returncode=returncode, output=b"".join(chunks), lines=lines,
                        stopped_reason=reason, cut_records=tuple(cut))


def _read_lines(fd: int, deadline: float, *, max_lines: int, max_bytes: int,
                nul_framed: bool) -> tuple[list[bytes], int, str]:
    """The plain reader of :func:`run_streaming`: (chunks, lines, stopped reason)."""
    chunks: list[bytes] = []
    size = 0
    lines = 0
    seen_nul = False  # nul_framed: a NUL was read since the last counted line end
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return chunks, lines, "timeout"
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            return chunks, lines, "timeout"
        chunk = os.read(fd, 65536)
        if not chunk:
            return chunks, lines, "complete"
        room = max_bytes - size
        dropped = len(chunk) > room  # bytes past max_bytes in this chunk
        if len(chunk) >= room:
            chunk = chunk[:room]
        # Count complete lines and stop exactly after the max_lines-th one.
        cut = None
        start = 0
        while True:
            if nul_framed and not seen_nul:
                nul = chunk.find(b"\0", start)
                if nul < 0:
                    break
                seen_nul = True
                start = nul + 1
            idx = chunk.find(b"\n", start)
            if idx < 0:
                break
            seen_nul = False
            lines += 1
            start = idx + 1
            if lines >= max_lines:
                cut = start
                break
        if cut is not None:
            chunks.append(chunk[:cut])
            if not dropped and cut == len(chunk) and _at_eof(fd, deadline):
                return chunks, lines, "complete"  # the output ended exactly at the limit
            return chunks, lines, "max_lines"
        chunks.append(chunk)
        size += len(chunk)
        if size >= max_bytes:
            if not dropped and _at_eof(fd, deadline):
                return chunks, lines, "complete"
            return chunks, lines, "max_bytes"


def _read_records(fd: int, deadline: float, *, max_records: int, max_kept: int,
                  max_raw: int, cap: int) -> tuple[list[bytes], int, str, list[int]]:
    """The record reader of :func:`run_streaming` (``grep -Z`` with a per-record cap).

    A record is ``<name> NUL <rest> newline``; it ends at the first newline after its
    NUL. At most ``cap`` bytes of each are kept; a kept record always ends with its
    newline, and one whose NUL fell past the cap is dropped whole (it could not be
    framed). Returns (kept records, records seen, stopped reason, positions of the
    kept records that were cut at ``cap``).
    """
    records: list[bytes] = []
    cut: list[int] = []
    kept = 0
    raw = 0
    seen = 0
    current = bytearray()
    in_rest = False  # this record's NUL was read
    nul_kept = False  # ... and is inside the kept bytes
    overflow = False  # ... and bytes of its line were dropped at the cap
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return records, seen, "timeout", cut
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            return records, seen, "timeout", cut
        chunk = os.read(fd, 65536)
        if not chunk:
            return records, seen, "complete", cut  # an unterminated last record is dropped
        raw += len(chunk)
        position = 0
        while position < len(chunk):
            if not in_rest:
                nul = chunk.find(b"\0", position)
                end = len(chunk) if nul < 0 else nul + 1
                piece = chunk[position:end]
                room = cap - len(current)
                current += piece[:max(room, 0)]
                if nul >= 0:
                    in_rest = True
                    nul_kept = room >= len(piece)
                position = end
                continue
            newline = chunk.find(b"\n", position)
            end = len(chunk) if newline < 0 else newline
            room = cap - len(current)
            if end - position > room:
                overflow = True
            current += chunk[position:end][:max(room, 0)]
            if newline < 0:
                position = end
                continue
            position = newline + 1
            seen += 1
            if nul_kept:
                current += b"\n"
                if overflow:
                    cut.append(len(records))
                records.append(bytes(current))
                kept += len(current)
            current = bytearray()
            in_rest = nul_kept = overflow = False
            at_end = position == len(chunk)
            if seen >= max_records or kept >= max_kept:
                if at_end and raw < max_raw and _at_eof(fd, deadline):
                    return records, seen, "complete", cut  # the output ended at the limit
                return (records, seen, "max_lines" if seen >= max_records else "max_bytes",
                        cut)
        if raw >= max_raw:
            if _at_eof(fd, deadline) and not current:
                return records, seen, "complete", cut
            return records, seen, "max_bytes", cut


def sudo_preflight(sudo_path: str, cli_realpath: str, *, home: str,
                   timeout: float = 10.0) -> bool:
    """``sudo -n -l <cli>``: True when the passwordless rule allows the CLI (L.2)."""
    try:
        result = run_capture([sudo_path, "-n", "-l", cli_realpath], home=home, timeout=timeout)
    except LaunchError:
        return False
    return not result.timed_out and result.returncode == 0


if __name__ == "__main__":
    raise SystemExit(_holder_main(sys.argv[1:]))
