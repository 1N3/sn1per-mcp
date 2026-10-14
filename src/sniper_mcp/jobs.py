# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Scan jobs: records, liveness, classification, cancel, retention, reaping (contract L).

The job record in ``<state_dir>/jobs/<job_id>.json`` is the source of truth;
any server process of the same user can report, cancel and finish a job from
it, including jobs launched by an earlier process (``start_new_session`` lets
scans outlive the server by design). This process also keeps the ``Popen``
handles of the scans it launched (:data:`JOBS`), polls them on every tool call
and every 30 seconds (reaping zombies) and so knows their exit codes.

A job is alive when a process with the recorded ``pid`` exists and its
``/proc/<pid>/stat`` start time equals ``pid_starttime`` (guards against PID
reuse). A finished job is classified from its sanitized log and its workspace
files, never from ``SCAN COMPLETE!`` and never from a zero exit code alone
(CE exits 0 on almost every failure). The first observer of a finished job
writes one ``scan_exit`` audit line and then the terminal state into the
record; the record's ``state`` field is the guard.

Cancel signals the job's process tree and sessions, never by pattern and never
through the CLI (``-dt`` would match this server, L.6).
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import re
import secrets
import signal
import stat
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from sniper_mcp import __version__, paths, proc, redact, sanitize, state, targets
from sniper_mcp import audit as audit_mod

RECORD_SCHEMA_VERSION = "1"
JOB_ID_RE = re.compile(r"[0-9a-f]{16}")
_RECORD_NAME_RE = re.compile(r"([0-9a-f]{16})\.json")

STARTING = "starting"
RUNNING = "running"
SUCCEEDED = "succeeded"
FAILED = "failed"
CANCELLED = "cancelled"
UNKNOWN = "unknown"
LIVE_STATES = frozenset({STARTING, RUNNING})
TERMINAL_STATES = frozenset({SUCCEEDED, FAILED, CANCELLED, UNKNOWN})
ALL_STATES = LIVE_STATES | TERMINAL_STATES

STARTING_SECONDS = 2.0
RECORD_MAX_BYTES = 256 * 1024
LOG_SCAN_FULL_BYTES = 8 * 1024 * 1024
LOG_SCAN_PART_BYTES = 1024 * 1024
LOG_TAIL_WINDOW_BYTES = 64 * 1024
LOG_TAIL_MAX_CHARS = 8000
NO_OUTPUT_SLACK_SECONDS = 2.0
WORKSPACE_WALK_LIMIT = 100_000
STARTUP_RECORDS = 1000  # L.8: the newest records loaded by the startup sweep
MAX_RECORDS_SCANNED = 10_000
SCAN_LOCK_WAIT_SECONDS = 10.0  # F.8
RECORD_LOCK_WAIT_SECONDS = 2.0
CANCEL_TERM_GRACE_SECONDS = 10.0  # L.6 step 4
CANCEL_POLL_SECONDS = 15.0  # L.6 step 5
CANCEL_POLL_INTERVAL = 0.5
RETENTION_INTERVAL_SECONDS = 3600.0  # L.7
REAPER_INTERVAL_SECONDS = 30.0  # L.8
RECENT_JOBS_LISTED = 20
_CMDLINE_MAX_BYTES = 64 * 1024
_STAT_MAX_BYTES = 4096
_MARKER_MAX_BYTES = 64

COMPLETION_MARKER = "SCAN COMPLETE!"
# L.3 failure patterns: (state_reason, substrings, case-insensitive). Versioned with
# the contract; the first pattern in this order that occurs gives the reason.
FAILURE_PATTERNS: tuple[tuple[str, tuple[str, ...], bool], ...] = (
    ("sudo_password_required", ("sudo: a password is required",), False),
    ("sudo_terminal_required", ("sudo: a terminal is required",
                                "sudo: sorry, you must have a tty"), False),
    ("sudo_not_allowed", ("is not allowed to execute", "is not in the sudoers file"), False),
    ("not_root", ("This script must be run as root",), False),
    ("missing_target_file", ("You need to specify a list of targets",), False),
    ("missing_target", ("You need to specify a target or workspace to use",), False),
    ("unknown_option", ("Unknown scan option",), False),
    ("engine_not_on_path", ("sniper: command not found",), False),
    # The engine's files were removed while it started (an 11.x licence hook deletes the
    # install when the host fingerprint changes, for example after a container restart).
    ("engine_files_missing", ("/modes/normal.sh: No such file or directory",
                              "/modes/functions.sh: No such file or directory"), False),
    ("invalid_port", ("Your port specifications are illegal",), False),
    ("missing_port", ("$PORT not set. Exiting!",), False),
    ("target_unresolvable", ("does not appear to be resolvable... Skipping",), False),
    ("engine_out_of_scope", ("is out of scope. Skipping!",), False),
    ("unsupported_target", ("Target appears to be a mobile application",), False),
    ("license_limit", ("limit exceeded",), True),
)

# G.3 target_type vocabulary of the audit log, which tool results and job records now
# share. "ipv4_cidr" is the spelling of job records written by earlier 0.9.0
# development builds; it is still read as "cidr".
AUDIT_TARGET_TYPES = {targets.HOSTNAME: "hostname", targets.IPV4: "ipv4",
                      targets.IPV4_CIDR: "cidr", "ipv4_cidr": "cidr"}

log = logging.getLogger("sn1per-mcp")


# --- time --------------------------------------------------------------------------------

def parse_timestamp(text: object) -> float | None:
    """Epoch seconds of a G.3 timestamp (``2026-10-21T14:03:07.412Z``), or None."""
    if not isinstance(text, str):
        return None
    try:
        moment = datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return None
    return moment.replace(tzinfo=datetime.UTC).timestamp()


# --- the process table ---------------------------------------------------------------

@dataclass(frozen=True)
class ProcStat:
    """The fields of ``/proc/<pid>/stat`` the server uses."""

    pid: int
    state: str
    ppid: int
    pgrp: int
    session: int
    starttime: int

    @property
    def dead(self) -> bool:
        return self.state in ("Z", "X", "x")


def _read_proc_file(pid: int, name: str, limit: int) -> bytes | None:
    try:
        fd = os.open(os.path.join(paths.PROC_ROOT, str(pid), name), os.O_RDONLY | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        return os.read(fd, limit)
    except OSError:
        return None
    finally:
        os.close(fd)


def read_stat(pid: int) -> ProcStat | None:
    """``/proc/<pid>/stat``, or None when it is missing or unreadable."""
    data = _read_proc_file(pid, "stat", _STAT_MAX_BYTES)
    if not data:
        return None
    close = data.rfind(b")")
    if close < 0:
        return None
    fields = data[close + 2:].split()
    try:
        return ProcStat(pid=pid, state=fields[0].decode("ascii", "replace"),
                        ppid=int(fields[1]), pgrp=int(fields[2]), session=int(fields[3]),
                        starttime=int(fields[19]))
    except (IndexError, ValueError):
        return None


def read_cmdline(pid: int) -> list[bytes] | None:
    data = _read_proc_file(pid, "cmdline", _CMDLINE_MAX_BYTES)
    if data is None:
        return None
    parts = data.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    return parts


def proc_available() -> bool:
    """True when this process can read its own ``/proc`` entry."""
    return read_stat(os.getpid()) is not None


def _pid_exists(pid: int) -> bool:
    """``kill(pid, 0)``: an ``EPERM`` answer counts as alive (L.3)."""
    if pid <= 1:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def process_alive(pid: int, starttime: int | None) -> bool:
    """L.3 liveness of one recorded process."""
    if pid <= 1 or pid == os.getpid():
        return False
    st = read_stat(pid)
    if st is not None:
        if starttime is not None and st.starttime != starttime:
            return False  # the pid was reused
        return not st.dead
    # Not visible in /proc: gone, or hidden from this user (hidepid).
    return _pid_exists(pid)


def _process_table() -> dict[int, ProcStat]:
    table: dict[int, ProcStat] = {}
    try:
        names = os.listdir(paths.PROC_ROOT)
    except OSError:
        return table
    for name in names:
        if name.isdigit():
            st = read_stat(int(name))
            if st is not None:
                table[st.pid] = st
    return table


def _ancestors(pid: int, table: Mapping[int, ProcStat]) -> set[int]:
    found: set[int] = set()
    current = pid
    for _ in range(4096):
        st = table.get(current)
        if st is None or st.ppid <= 0 or st.ppid in found:
            break
        found.add(st.ppid)
        current = st.ppid
    return found


def server_lineage_problem(pid: int) -> str | None:
    """Why ``pid`` must never be signalled: this server, an ancestor or its session (L.6)."""
    own = os.getpid()
    if pid == own:
        return "it is this server process"
    current = own
    for _ in range(4096):
        st = read_stat(current)
        if st is None or st.ppid <= 0:
            break
        if st.ppid == pid:
            return "it is an ancestor of this server process"
        current = st.ppid
    target = read_stat(pid)
    try:
        own_session = os.getsid(0)
        session = target.session if target is not None else os.getsid(pid)
    except OSError:
        return None
    if session == own_session:
        return "it is in this server's session"
    return None


# --- this process's children (L.8) ------------------------------------------------------

@dataclass
class Child:
    """A scan launched by this process."""

    job_id: str
    process: proc.Process = field(repr=False)
    workspace: str
    target: str


JOBS: dict[str, Child] = {}
_jobs_lock = threading.Lock()


def own_child(job_id: str) -> Child | None:
    with _jobs_lock:
        return JOBS.get(job_id)


def terminate_all() -> None:
    """Kill every scan of this process (the test suite's cleanup; never called by tools)."""
    with _jobs_lock:
        children = list(JOBS.values())
    for child in children:
        if child.process.poll() is None:
            try:
                os.killpg(child.process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            child.process.wait()


# --- views and outcomes ------------------------------------------------------------------

@dataclass
class JobView:
    """What one observation of a job found (H.7 ``job`` object)."""

    record: dict[str, Any]
    state: str
    state_reason: str | None
    exit_code: int | None
    alive: bool
    ended_at: str | None
    summary: dict[str, Any] | None
    launched_by: str

    @property
    def job_id(self) -> str:
        return str(self.record["job_id"])

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    def status_object(self, log_path: str) -> dict[str, Any]:
        """The H.7 ``job`` object."""
        record = self.record
        started = parse_timestamp(record.get("started_at"))
        ended = parse_timestamp(self.ended_at)
        reference = ended if ended is not None else time.time()
        elapsed = round(max(reference - started, 0.0), 1) if started is not None else None
        return {
            "job_id": record["job_id"],
            "state": self.state,
            "state_reason": self.state_reason,
            "exit_code": self.exit_code,
            "target": record.get("target"),
            "mode": record.get("mode"),
            "port": record.get("port"),
            "workspace": record.get("workspace"),
            "started_at": record.get("started_at"),
            "ended_at": self.ended_at,
            "elapsed_seconds": elapsed,
            "pid": record.get("pid"),
            "launched_by": self.launched_by,
            "log_path": log_path,
            "cancel": record.get("cancel"),
            "summary": self.summary if self.terminal else None,
        }


@dataclass(frozen=True)
class Tail:
    """A sanitized, redacted log tail (L.5)."""

    text: str
    counts: dict[str, int]
    invisible_removed: int
    truncated: bool


@dataclass
class CancelResult:
    """Outcome of :meth:`JobStore.signal_job` (H.8)."""

    state: str  # cancelled or cancel_incomplete
    signals: list[dict[str, Any]]
    remaining_pids: list[int]
    # Set when no signal was sent because the recorded process could not be trusted
    # to be the scan (L.6 step 3 hardening); the state is then cancel_incomplete.
    unverified: str | None = None
    # cancel_incomplete: (pid, start time) of every process still running, and their
    # session ids (the hint names them, so a human can stop whole sessions).
    survivors: list[tuple[int, int | None]] = field(default_factory=list)
    sessions: list[int] = field(default_factory=list)


@dataclass(frozen=True)
class Activity:
    """L.4 workspace activity."""

    running_processes: int
    process_check: str  # "ok" or "unavailable"
    markers: dict[str, int]

    @property
    def markers_running(self) -> bool:
        return any(self.markers.values())

    @property
    def is_running(self) -> bool:
        if self.process_check == "ok":
            return self.running_processes > 0
        return self.markers_running

    @property
    def stale_markers(self) -> bool:
        return (self.process_check == "ok" and self.markers_running
                and self.running_processes == 0)


# --- record validation -----------------------------------------------------------------

def _valid_record(record: object, job_id: str) -> bool:
    """A record this server wrote: anything else is ignored (never signalled)."""
    if not isinstance(record, dict):
        return False
    pid = record.get("pid")
    starttime = record.get("pid_starttime")
    argv = record.get("argv")
    cancel = record.get("cancel")
    return (record.get("schema_version") == RECORD_SCHEMA_VERSION
            and record.get("job_id") == job_id
            and isinstance(pid, int) and not isinstance(pid, bool) and pid > 1
            and (starttime is None or (isinstance(starttime, int)
                                       and not isinstance(starttime, bool)))
            and targets.is_valid_workspace(record.get("workspace"))
            and isinstance(record.get("target"), str)
            and record.get("state") in ALL_STATES
            and parse_timestamp(record.get("started_at")) is not None
            and isinstance(argv, list) and all(isinstance(a, str) for a in argv)
            and (cancel is None or isinstance(cancel, dict))
            and _optional_pid(record.get("front_pid"))
            and _optional_int(record.get("front_pid_starttime"))
            and _valid_survivors(record.get("cancel_survivors"))
            and _valid_paths(record.get("engine_files")))


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _optional_int(value: object) -> bool:
    return value is None or _is_int(value)


def _optional_pid(value: object) -> bool:
    return value is None or (_is_int(value) and value > 1)  # type: ignore[operator]


def _valid_survivors(value: object) -> bool:
    """``cancel_survivors``: absent, or a list of ``[pid, start time]`` pairs (L.6)."""
    if value is None:
        return True
    return isinstance(value, list) and len(value) <= 4096 and all(
        isinstance(item, list) and len(item) == 2 and _optional_pid(item[0])
        and item[0] is not None and _optional_int(item[1]) for item in value)


def _valid_paths(value: object) -> bool:
    return value is None or (isinstance(value, list) and len(value) <= 64 and all(
        isinstance(item, str) and os.path.isabs(item) for item in value))


def _front(record: Mapping[str, Any]) -> tuple[int, int] | None:
    """The sudo process the terminal holder started (L.6), when its start time is known
    and it is not this server, an ancestor or a member of its session."""
    pid, start = record.get("front_pid"), record.get("front_pid_starttime")
    if not _is_int(pid) or not _is_int(start) or pid <= 1:
        return None
    if server_lineage_problem(pid) is not None:
        return None
    return pid, start


def _front_alive(record: Mapping[str, Any]) -> bool:
    front = _front(record)
    return front is not None and process_alive(*front)


def cancel_survivors(record: Mapping[str, Any]) -> list[tuple[int, int | None]]:
    """Processes a cancel left running (L.6, recorded in ``cancel_survivors``) that are
    still alive. While any is, the job is reported running, never cancelled."""
    found = []
    for item in record.get("cancel_survivors") or ():
        pid, start = int(item[0]), item[1]
        if start is not None and process_alive(pid, start):
            found.append((pid, start))
    return found


def _engine_files_gone(record: Mapping[str, Any]) -> bool:
    """L.3: an engine file that existed at launch is gone (the engine was removed while
    the scan started, for example by an 11.x licence hook)."""
    return any(not os.path.lexists(path) for path in record.get("engine_files") or ())


# --- classification (L.3) ------------------------------------------------------------------

def failure_markers(text: str) -> list[str]:
    """Every L.3 failure pattern that occurs in a sanitized log, in table order."""
    found = []
    lowered: str | None = None
    for reason, needles, insensitive in FAILURE_PATTERNS:
        if insensitive:
            lowered = text.lower() if lowered is None else lowered
            hit = any(n.lower() in lowered for n in needles)
        else:
            hit = any(n in text for n in needles)
        if hit:
            found.append(reason)
    return found


def files_written(workspace_path: str, since: float) -> int:
    """Regular files under the workspace with ``mtime >= since``.

    An iterative ``scandir`` walk: links are never followed, at most
    ``WORKSPACE_WALK_LIMIT`` entries are looked at, and a tree planted in the
    world-writable loot cannot exhaust the recursion limit.
    """
    try:
        top = os.lstat(workspace_path)
    except OSError:
        return 0
    if not stat.S_ISDIR(top.st_mode):
        return 0
    count = 0
    seen = 0
    pending = [workspace_path]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    seen += 1
                    if seen > WORKSPACE_WALK_LIMIT:
                        return count
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(entry.path)
                        elif (entry.is_file(follow_symlinks=False)
                              and entry.stat(follow_symlinks=False).st_mtime >= since):
                            count += 1
                    except OSError:
                        continue
        except OSError:
            continue
    return count


# --- the store ---------------------------------------------------------------------------

class JobStore:
    """Job records of one state directory, as seen by this server process."""

    def __init__(self, *, state_dir: str, home: str, euid: int,
                 workspace_dir: Callable[[], str],
                 audit: audit_mod.AuditLog | None = None,
                 allow_any_target: bool = False, allow_intrusive: bool = False) -> None:
        self.state_dir = state_dir
        self.home = home
        self.euid = euid
        # This process's lab overrides, for the scan_exit lines it writes (F.6, G.3).
        self.allow_any_target = allow_any_target
        self.allow_intrusive = allow_intrusive
        self._workspace_dir = workspace_dir
        self.audit = audit
        self._last_retention: float | None = None
        self._retention_lock = threading.Lock()

    # --- paths -------------------------------------------------------------------------
    @property
    def jobs_dir(self) -> str:
        return os.path.join(self.state_dir, state.JOBS_SUBDIR)

    def record_path(self, job_id: str) -> str:
        return os.path.join(self.jobs_dir, f"{job_id}.json")

    def log_path(self, job_id: str) -> str:
        return os.path.join(self.jobs_dir, f"{job_id}.log")

    @property
    def scan_lock_path(self) -> str:
        return os.path.join(self.state_dir, state.SCAN_LOCK_NAME)

    # --- locks -------------------------------------------------------------------------
    @contextmanager
    def scan_lock(self) -> Iterator[None]:
        """F.8: the exclusive ``flock`` on ``scan.lock``, waited for at most 10 seconds.

        Raises ``state.LockTimeout`` (``concurrency_limit``) or
        ``state.StateDirInsecure``.
        """
        fd = state.open_lock_file(self.scan_lock_path)
        try:
            state.flock_exclusive(fd, timeout=SCAN_LOCK_WAIT_SECONDS)
            yield
        finally:
            os.close(fd)  # releases the lock

    @contextmanager
    def _record_lock(self, timeout: float = RECORD_LOCK_WAIT_SECONDS) -> Iterator[None]:
        """Serializes read-modify-write of existing records across processes."""
        fd = state.open_dir_lock(self.jobs_dir)
        try:
            state.flock_exclusive(fd, timeout=timeout)
            yield
        finally:
            os.close(fd)

    # --- records -----------------------------------------------------------------------
    @staticmethod
    def new_job_id() -> str:
        """16 lowercase hex characters (L.1, A-25)."""
        return secrets.token_hex(8)

    def load(self, job_id: str) -> dict[str, Any] | None:
        if not isinstance(job_id, str) or not JOB_ID_RE.fullmatch(job_id):
            return None
        try:
            data = state.read_private_file(self.record_path(job_id), max_bytes=RECORD_MAX_BYTES)
        except (OSError, state.SecureFileError):
            return None
        try:
            record = json.loads(data)
        except ValueError:
            return None
        return record if _valid_record(record, job_id) else None

    def _write(self, record: Mapping[str, Any]) -> None:
        state.write_json_atomic(self.record_path(str(record["job_id"])), dict(record))

    def record_ids(self, limit: int | None = MAX_RECORDS_SCANNED) -> list[str]:
        """Job ids of the records in ``jobs/``, newest first (``None``: all of them)."""
        found: list[tuple[float, str]] = []
        try:
            with os.scandir(self.jobs_dir) as entries:
                for entry in entries:
                    match = _RECORD_NAME_RE.fullmatch(entry.name)
                    if match is None or not entry.is_file(follow_symlinks=False):
                        continue
                    try:
                        mtime = entry.stat(follow_symlinks=False).st_mtime
                    except OSError:
                        continue
                    found.append((mtime, match.group(1)))
        except OSError:
            return []
        found.sort(reverse=True)
        chosen = found if limit is None else found[:limit]
        return [job_id for _, job_id in chosen]

    def records(self, limit: int | None = MAX_RECORDS_SCANNED) -> Iterator[dict[str, Any]]:
        for job_id in self.record_ids(limit):
            record = self.load(job_id)
            if record is not None:
                yield record

    # --- launch (F.9 step 15) ------------------------------------------------------------
    def launch(self, job_id: str, argv: list[str], fields: Mapping[str, Any]) -> dict[str, Any]:
        """Spawn the scan detached with its log, register it and write its record.

        Raises ``proc.LaunchError``. When the record cannot be written the scan
        is stopped first, so no untracked root scan survives.
        """
        log_path = self.log_path(job_id)
        try:
            log_fd = state.create_exclusive(log_path)
        except OSError as exc:
            raise proc.LaunchError("could not create the job log",
                                   cause=type(exc).__name__) from exc
        created_at = audit_mod.utc_timestamp()
        terminal = bool(fields.get("sudo"))
        front_pid: int | None = None
        try:
            if terminal:
                # L.6: sudo gets a controlling terminal from the terminal holder, so a
                # non-root cancel can stop the whole engine process group.
                launched = proc.spawn_with_terminal(argv, log_fd=log_fd, home=self.home)
                process, front_pid = launched.process, launched.front_pid
                if launched.note is not None:
                    _note_in_log(log_fd, f"{launched.note}; cancel_scan may not stop every "
                                         "process of this scan")
                    terminal = False
            else:
                process = proc.spawn_detached(argv, log_fd=log_fd, home=self.home)
        except proc.LaunchError:
            os.close(log_fd)
            _unlink_quietly(log_path)
            raise
        os.close(log_fd)
        started = time.time()
        front_stat = read_stat(front_pid) if front_pid is not None else None
        if front_stat is None or front_stat.dead:
            front_pid = None  # gone already, or never reported: only the holder is known
        child = Child(job_id=job_id, process=process, workspace=str(fields["workspace"]),
                      target=str(fields["target"]))
        with _jobs_lock:
            JOBS[job_id] = child
        st = read_stat(process.pid)
        try:
            pgid, sid = os.getpgid(process.pid), os.getsid(process.pid)
        except OSError:
            pgid = sid = process.pid
        own = read_stat(os.getpid())
        record: dict[str, Any] = {
            "schema_version": RECORD_SCHEMA_VERSION,
            "job_id": job_id,
            "created_at": created_at,
            "server_version": __version__,
            "server_pid": os.getpid(),
            "server_pid_starttime": own.starttime if own else None,
            "edition": fields.get("edition"),
            "dialect": fields.get("dialect"),
            "engine_version": fields.get("engine_version"),
            "target": fields["target"],
            "target_type": fields.get("target_type"),
            "target_input": fields.get("target_input"),
            "mode": fields.get("mode"),
            "mode_class": fields.get("mode_class"),
            "port": fields.get("port"),
            "workspace": fields["workspace"],
            "argv": list(argv),
            "sudo": bool(fields.get("sudo")),
            "pid": process.pid,
            "pid_starttime": st.starttime if st else None,
            "pgid": pgid,
            "sid": sid,
            # L.6: "terminal" when pid is the terminal holder and front_pid the sudo
            # process it started; "direct" when pid is the scan's own first process.
            "launcher": "terminal" if terminal else "direct",
            "front_pid": front_pid,
            "front_pid_starttime": front_stat.starttime if front_stat is not None
            and front_pid is not None else None,
            # L.3: engine files present at launch; a scan that ends after any of them is
            # gone is failed (engine_removed), whatever its exit code.
            "engine_files": [str(p) for p in fields.get("engine_files") or ()],
            "log_path": log_path,
            "started_at": audit_mod.utc_timestamp(started),
            "ended_at": None,
            "exit_code": None,
            "state": STARTING,
            "state_reason": None,
            "cancel": None,
            "authorization_ref": fields.get("authorization_ref"),
            "allow_any_target": bool(fields.get("allow_any_target")),
            "scope_digest": fields.get("scope_digest"),
        }
        try:
            self._write(record)
        except OSError as exc:
            log.error("job record %s could not be written (%s); stopping the scan", job_id,
                      exc.strerror)
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                process.wait(timeout=10)
            except Exception:  # noqa: BLE001 - best effort; the launch already failed
                pass
            with _jobs_lock:
                JOBS.pop(job_id, None)
            raise proc.LaunchError("could not write the job record",
                                   cause=type(exc).__name__) from exc
        return record

    # --- observation (L.3) ---------------------------------------------------------------
    def workspace_path(self, record: Mapping[str, Any]) -> str:
        return os.path.join(self._workspace_dir(), str(record["workspace"]))

    def _read_log_for_classification(self, job_id: str) -> str | None:
        """The sanitized log: all of it up to 8 MiB, else the first and last 1 MiB."""
        try:
            fd = os.open(self.log_path(job_id),
                         os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        except OSError:
            return None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid():
                return None
            if st.st_size <= LOG_SCAN_FULL_BYTES:
                parts = [_read_exactly(fd, LOG_SCAN_FULL_BYTES)]
            else:
                parts = [_read_exactly(fd, LOG_SCAN_PART_BYTES)]
                os.lseek(fd, max(st.st_size - LOG_SCAN_PART_BYTES, 0), os.SEEK_SET)
                parts.append(_read_exactly(fd, LOG_SCAN_PART_BYTES))
        except OSError:
            return None
        finally:
            os.close(fd)
        return "\n".join(sanitize.sanitize(part).text for part in parts)

    def classify(self, record: Mapping[str, Any], exit_code: int | None
                 ) -> tuple[str, str | None, dict[str, Any]]:
        """L.3 for a job that is not alive: (state, state_reason, summary)."""
        job_id = str(record["job_id"])
        text = self._read_log_for_classification(job_id)
        markers = failure_markers(text) if text is not None else []
        started = parse_timestamp(record.get("started_at")) or 0.0
        files = files_written(self.workspace_path(record), started - NO_OUTPUT_SLACK_SECONDS)
        summary = {"completion_marker_seen": bool(text and COMPLETION_MARKER in text),
                   "failure_markers": markers, "files_written": files}
        if record.get("cancel"):
            return CANCELLED, None, summary
        if text is None and exit_code is None and not proc_available():
            return UNKNOWN, None, summary
        if markers:
            return FAILED, markers[0], summary
        if _engine_files_gone(record):
            return FAILED, "engine_removed", summary
        if exit_code is not None and exit_code != 0:
            return FAILED, "exit_status", summary
        if files == 0:
            return FAILED, "no_output", summary
        return SUCCEEDED, None, summary

    def _launched_by(self, record: Mapping[str, Any]) -> str:
        if own_child(str(record["job_id"])) is not None:
            return "this_process"
        return "previous_process"

    def _may_finish(self, record: Mapping[str, Any]) -> bool:
        """Whether this process may write the terminal state: the launcher first.

        The launcher knows the exit code; another process writes it only after
        the launching process is gone.
        """
        if own_child(str(record["job_id"])) is not None or \
                record.get("server_pid") == os.getpid():
            return True
        server_pid = record.get("server_pid")
        server_start = record.get("server_pid_starttime")
        if not isinstance(server_pid, int) or not isinstance(server_start, int):
            return True
        st = read_stat(server_pid)
        return st is None or st.dead or st.starttime != server_start

    def observe(self, record: dict[str, Any], *, finish: bool = True) -> JobView:
        """The current state of one job; finishes the record when it newly ended (L.8)."""
        job_id = str(record["job_id"])
        launched_by = self._launched_by(record)
        stored_exit = record.get("exit_code")
        exit_code = stored_exit if isinstance(stored_exit, int) else None
        if record.get("state") in TERMINAL_STATES:
            return JobView(record=record, state=str(record["state"]),
                           state_reason=record.get("state_reason"), exit_code=exit_code,
                           alive=False, ended_at=record.get("ended_at"),
                           summary=record.get("summary"), launched_by=launched_by)
        child = own_child(job_id)
        if child is not None:
            returncode = child.process.poll()  # reaps the zombie
            alive = returncode is None
            exit_code = returncode
        else:
            alive = process_alive(int(record["pid"]), record.get("pid_starttime"))
        if not alive and _front_alive(record):
            alive = True  # the terminal holder is gone but sudo still runs the scan (L.6)
            exit_code = None
        if alive:
            started = parse_timestamp(record.get("started_at")) or 0.0
            live = STARTING if time.time() - started < STARTING_SECONDS else RUNNING
            return JobView(record=record, state=live, state_reason=None, exit_code=None,
                           alive=True, ended_at=None, summary=None, launched_by=launched_by)
        if cancel_survivors(record):
            # L.6: a cancel left processes of the scan running. Never report the job
            # cancelled (or finished at all) while they run.
            return JobView(record=record, state=RUNNING, state_reason="cancel_incomplete",
                           exit_code=None, alive=True, ended_at=None, summary=None,
                           launched_by=launched_by)
        state_now, reason, summary = self.classify(record, exit_code)
        view = JobView(record=record, state=state_now, state_reason=reason,
                       exit_code=exit_code, alive=False,
                       ended_at=self._ended_at(job_id, record, child), summary=summary,
                       launched_by=launched_by)
        if finish and self._may_finish(record):
            self._finish(view)
        return view

    def _ended_at(self, job_id: str, record: Mapping[str, Any], child: Child | None) -> str:
        if child is None:
            # Another process launched it: the log's last write is the best estimate.
            try:
                mtime = os.stat(self.log_path(job_id), follow_symlinks=False).st_mtime
            except OSError:
                mtime = None
            started = parse_timestamp(record.get("started_at"))
            if mtime is not None and (started is None or mtime >= started):
                return audit_mod.utc_timestamp(mtime)
        return audit_mod.utc_timestamp()

    def _finish(self, view: JobView) -> bool:
        """First observer only: one ``scan_exit`` audit line, then the terminal record."""
        job_id = view.job_id
        try:
            with self._record_lock():
                current = self.load(job_id)
                if current is None or current.get("state") in TERMINAL_STATES:
                    return False
                if current.get("cancel") and view.state != CANCELLED:
                    # A cancel recorded after the caller read its copy still wins (L.3).
                    view.state, view.state_reason = CANCELLED, None
                result = {"state": view.state, "state_reason": view.state_reason,
                          "exit_code": view.exit_code, "ended_at": view.ended_at}
                if self.audit is not None:
                    # Audit first: a record never turns terminal without its scan_exit line.
                    self.audit.write(audit_mod.SCAN_EXIT,
                                     action=scan_exit_fields(
                                         current, view, allow_any_target=self.allow_any_target,
                                         allow_intrusive=self.allow_intrusive),
                                     result=result)
                current.update(state=view.state, state_reason=view.state_reason,
                               exit_code=view.exit_code, ended_at=view.ended_at,
                               summary=view.summary)
                self._write(current)
                view.record = current
                return True
        except (state.LockTimeout, state.StateDirInsecure, audit_mod.AuditUnavailable,
                OSError) as exc:
            log.warning("job %s ended but its terminal state is not recorded yet: %s", job_id,
                        exc)
            return False

    def view(self, job_id: str) -> JobView | None:
        record = self.load(job_id)
        return None if record is None else self.observe(record)

    # --- concurrency (F.8) ---------------------------------------------------------------
    def running(self) -> list[dict[str, Any]]:
        """Records of jobs in ``starting``/``running`` whose process is verified alive."""
        found = []
        for record in self.records():
            if record.get("state") in TERMINAL_STATES:
                continue
            child = own_child(str(record["job_id"]))
            if child is not None:
                alive = child.process.poll() is None
            else:
                alive = process_alive(int(record["pid"]), record.get("pid_starttime"))
            if alive or _front_alive(record) or cancel_survivors(record):
                found.append(record)
        return found

    # --- log tail (L.5) ------------------------------------------------------------------
    def log_tail(self, job_id: str, lines: int, *, redact_enabled: bool,
                 max_chars: int = LOG_TAIL_MAX_CHARS) -> Tail:
        """The last ``lines`` lines of the job log, sanitized and redacted over the whole
        64 KiB window before they are selected and cut."""
        if lines <= 0:
            return Tail("", {}, 0, False)
        try:
            fd = os.open(self.log_path(job_id),
                         os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        except OSError:
            return Tail("", {}, 0, False)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid():
                return Tail("", {}, 0, False)
            start = max(st.st_size - LOG_TAIL_WINDOW_BYTES, 0)
            os.lseek(fd, start, os.SEEK_SET)
            window = _read_exactly(fd, LOG_TAIL_WINDOW_BYTES)
        except OSError:
            return Tail("", {}, 0, False)
        finally:
            os.close(fd)
        if start > 0:  # the window starts inside a line: drop the partial line
            cut = window.find(b"\n")
            window = window[cut + 1:] if cut >= 0 else b""
        cleaned = sanitize.sanitize(window)
        text = cleaned.text
        counts: dict[str, int] = {}
        if redact_enabled:
            text, counts = redact.redact(text)
        selected = text.split("\n")
        if selected and selected[-1] == "":
            selected.pop()
        tail, truncated = sanitize.truncate_tail("\n".join(selected[-lines:]), max_chars)
        return Tail(tail, counts, cleaned.invisible_removed, truncated)

    # --- cancel (L.6) ----------------------------------------------------------------------
    def request_cancel(self, job_id: str) -> dict[str, Any] | None:
        """L.6 step 2: record the cancel request in the job record; returns it."""
        with self._record_lock(timeout=SCAN_LOCK_WAIT_SECONDS):
            record = self.load(job_id)
            if record is None:
                return None
            record["cancel"] = {"requested_at": audit_mod.utc_timestamp(),
                                "requested_by_pid": os.getpid(), "outcome": None}
            self._write(record)
            return record

    def record_cancel_outcome(self, job_id: str, outcome: str,
                              survivors: list[tuple[int, int | None]] | None = None) -> None:
        """Store the outcome and, for ``cancel_incomplete``, the processes still running
        (``cancel.remaining_pids`` for the reader, ``cancel_survivors`` with start times
        for the liveness check of L.6)."""
        try:
            with self._record_lock():
                record = self.load(job_id)
                if record is None or not isinstance(record.get("cancel"), dict):
                    return
                record["cancel"]["outcome"] = outcome
                kept = [[pid, start] for pid, start in survivors or () if start is not None]
                record["cancel"]["remaining_pids"] = [pid for pid, _ in kept]
                record["cancel_survivors"] = kept[:4096]
                self._write(record)
        except (state.LockTimeout, state.StateDirInsecure, OSError) as exc:
            log.warning("job %s: the cancel outcome was not recorded: %s", job_id, exc)

    def signal_job(self, record: Mapping[str, Any]) -> CancelResult:
        """L.6 steps 3-5: snapshot the tree, signal it, wait for every member to exit."""
        root_pid = int(record["pid"])
        stored_start = record.get("pid_starttime")
        root_start = stored_start if isinstance(stored_start, int) else None
        child = own_child(str(record["job_id"]))
        # Never signal this server, its ancestors or its session (a tampered record), and
        # never a pid whose start time is unknown unless it is our own unreaped child
        # (PID reuse could not be ruled out). Nothing is sent and nothing is named.
        unverified = server_lineage_problem(root_pid)
        if unverified is None and root_start is None and \
                (child is None or child.process.pid != root_pid):
            unverified = "its start time was not recorded, so PID reuse cannot be ruled out"
        if unverified is not None:
            log.warning("job %s: no signal sent to recorded pid %d: %s", record["job_id"],
                        root_pid, unverified)
            return CancelResult(state="cancel_incomplete", signals=[], remaining_pids=[],
                                unverified=unverified)
        front = _front(record)
        # The recorded process, the sudo process the terminal holder started (it outlives
        # the holder if the holder is killed) and the survivors of an earlier cancel.
        tree = _merge_trees(_snapshot_tree(root_pid, root_start),
                            *(_snapshot_tree(pid, start) for pid, start
                              in ([front] if front is not None else [])
                              + cancel_survivors(record)))
        signals: list[dict[str, Any]] = []

        def alive(pid: int, starttime: int | None) -> bool:
            if child is not None and pid == child.process.pid:
                return child.process.poll() is None  # reaps our own child
            return process_alive(pid, starttime)

        def send(pid: int, starttime: int | None, sig: signal.Signals) -> None:
            if not alive(pid, starttime):  # also re-checks the start time (PID reuse)
                return
            try:
                os.kill(pid, sig)
            except (ProcessLookupError, PermissionError):
                return
            signals.append({"pid": pid, "signal": sig.name})

        def wait_gone(members: list[tuple[int, int | None]], seconds: float) -> None:
            deadline = time.monotonic() + seconds
            while any(alive(pid, start) for pid, start in members):
                if time.monotonic() >= deadline:
                    return
                time.sleep(CANCEL_POLL_INTERVAL)

        root = (root_pid, root_start)
        members = tree if tree else [root]
        if self.euid == 0:
            # Children first; survivors of SIGTERM get SIGKILL after the grace period.
            for pid, start in tree:
                send(pid, start, signal.SIGTERM)
            wait_gone(tree, CANCEL_TERM_GRACE_SECONDS)
            for pid, start in tree:
                send(pid, start, signal.SIGKILL)
        elif record.get("launcher") == "terminal":
            # sudo has a controlling terminal (the terminal holder, L.6). It keeps this
            # user's real UID, so it can be signalled; with use_pty it relays SIGTERM to
            # the engine's whole process group. Survivors after the grace period: SIGKILL
            # sudo (with use_pty the engine's terminal then hangs up) and the holder (its
            # terminal hangs up, which reaches the engine when sudo runs without use_pty).
            fronts = ([front] if front is not None and alive(*front)
                      else _children_of(root_pid, tree))
            for pid, start in fronts:
                send(pid, start, signal.SIGTERM)
            if signals:
                wait_gone(members, CANCEL_TERM_GRACE_SECONDS)
            if any(alive(pid, start) for pid, start in members):
                for pid, start in fronts:
                    send(pid, start, signal.SIGKILL)
                send(*root, signal.SIGKILL)
        else:
            # A scan started without the terminal holder: SIGTERM reaches the sudo
            # front-end, which relays it to its direct child only.
            send(*root, signal.SIGTERM)
            wait_gone([root], CANCEL_TERM_GRACE_SECONDS)
            send(*root, signal.SIGKILL)
        if signals:
            wait_gone(members, CANCEL_POLL_SECONDS)
        survivors = [(pid, start) for pid, start in members if alive(pid, start)]
        sessions = sorted({st.session for st in (read_stat(pid) for pid, _ in survivors)
                           if st is not None and st.session > 1})
        return CancelResult(state="cancel_incomplete" if survivors else "cancelled",
                            signals=signals, remaining_pids=sorted(p for p, _ in survivors),
                            survivors=survivors, sessions=sessions)

    # --- retention (L.7) -------------------------------------------------------------------
    def prune(self, days: int, *, now: float | None = None) -> int:
        """Delete records and logs of finished jobs older than ``days`` days (0 keeps all)."""
        if days <= 0:
            return 0
        cutoff = (time.time() if now is None else now) - days * 86400
        removed = 0
        for job_id in self.record_ids(None):
            record = self.load(job_id)
            if record is None or record.get("state") not in TERMINAL_STATES:
                continue
            moment = (parse_timestamp(record.get("ended_at"))
                      or parse_timestamp(record.get("started_at")))
            if moment is None or moment >= cutoff:
                continue
            try:
                with self._record_lock():
                    current = self.load(job_id)
                    if current is None or current.get("state") not in TERMINAL_STATES:
                        continue
                    _unlink_quietly(self.record_path(job_id))
                    _unlink_quietly(self.log_path(job_id))
                    removed += 1
            except (state.LockTimeout, state.StateDirInsecure, OSError) as exc:
                log.warning("retention: job %s was not removed: %s", job_id, exc)
        return removed

    def prune_if_due(self, days: int) -> None:
        """L.7: at most once per hour during tool calls (after the startup sweep)."""
        now = time.monotonic()
        with self._retention_lock:
            if self._last_retention is not None and \
                    now - self._last_retention < RETENTION_INTERVAL_SECONDS:
                return
            self._last_retention = now
        self.prune(days)

    # --- reaping (L.8) -------------------------------------------------------------------
    def poll_children(self) -> None:
        """Every tool call: reap this process's finished scans and finish their records."""
        with _jobs_lock:
            children = list(JOBS.values())
        for child in children:
            if child.process.poll() is None:
                continue
            record = self.load(child.job_id)
            if record is not None and record.get("state") not in TERMINAL_STATES:
                self.observe(record)

    def sweep(self, limit: int = STARTUP_RECORDS) -> None:
        """The background task: this process's children, then every unfinished record."""
        self.poll_children()
        for record in self.records(limit):
            if record.get("state") not in TERMINAL_STATES:
                self.observe(record)

    def recent_jobs(self, workspace: str, limit: int = RECENT_JOBS_LISTED) -> list[str]:
        """Job ids of this workspace, newest first."""
        found = []
        for record in self.records():
            if record.get("workspace") == workspace:
                found.append(str(record["job_id"]))
                if len(found) >= limit:
                    break
        return found

    def running_in_workspace(self, workspace: str) -> list[str]:
        return [str(r["job_id"]) for r in self.running() if r.get("workspace") == workspace]


def scan_exit_fields(record: Mapping[str, Any], view: JobView, *,
                     allow_any_target: bool = False,
                     allow_intrusive: bool = False) -> dict[str, Any]:
    """The G.3 action fields of a ``scan_exit`` line, from the job record.

    ``allow_any_target`` is true when the job was launched under the override or
    the process writing the line runs with it; ``allow_intrusive`` is the
    writing process's setting (the job record does not keep it).
    """
    target_type = record.get("target_type")
    return audit_mod.action_fields(
        tool="sniper_scan",
        decision="completed" if view.state == SUCCEEDED else "failed",
        reason=f"scan ended: {view.state}"
        + (f" ({view.state_reason})" if view.state_reason else ""),
        target_input=record.get("target_input"),
        target=record.get("target"),
        target_type=AUDIT_TARGET_TYPES.get(str(target_type), target_type),
        mode=record.get("mode"),
        mode_class=record.get("mode_class"),
        port=record.get("port"),
        workspace=record.get("workspace"),
        job_id=record.get("job_id"),
        sudo=record.get("sudo"),
        edition=record.get("edition"),
        dialect=record.get("dialect"),
        engine_version=record.get("engine_version"),
        scope_digest=record.get("scope_digest"),
        allow_any_target=bool(record.get("allow_any_target")) or allow_any_target,
        allow_intrusive=allow_intrusive,
        authorization_ref=record.get("authorization_ref"),
        elicitation={"requested": False, "action": None},
    )


# --- the process tree of a job (L.6 step 3) ----------------------------------------------

def _snapshot_tree(root_pid: int, root_start: int | None) -> list[tuple[int, int | None]]:
    """Descendants of the recorded pid plus every process in their sessions.

    The server's own pid, its ancestors and its own session are always
    excluded. The deepest processes come first (children before parents).
    """
    table = _process_table()
    own = os.getpid()
    excluded = {own} | _ancestors(own, table)
    try:
        own_session = os.getsid(0)
    except OSError:
        own_session = -1
    if root_pid in excluded:
        return []  # never this server, its ancestors or anything below them
    root = table.get(root_pid)
    if root is None or root.dead or (root_start is not None and root.starttime != root_start):
        return []
    if root.session == own_session:
        return []
    selected = {root_pid}
    while True:
        sessions = {table[p].session for p in selected if p in table}
        sessions -= {0, 1, own_session}
        grown = {pid for pid, st in table.items()
                 if pid not in selected and pid not in excluded and st.session != own_session
                 and (st.ppid in selected or st.session in sessions)}
        if not grown:
            break
        selected |= grown
    selected -= excluded

    def depth(pid: int) -> int:
        steps = 0
        current = pid
        while current != root_pid and steps < 4096:
            st = table.get(current)
            if st is None or st.ppid not in selected:
                return 4096  # reparented into one of the sessions: treat as deepest
            current = st.ppid
            steps += 1
        return steps

    ordered = sorted(selected, key=lambda p: (-depth(p), -p))
    return [(pid, table[pid].starttime) for pid in ordered if pid in table]


def _merge_trees(*trees: list[tuple[int, int | None]]) -> list[tuple[int, int | None]]:
    """Several snapshots as one list, each pid once, in the order first seen."""
    merged: list[tuple[int, int | None]] = []
    seen: set[int] = set()
    for tree in trees:
        for pid, start in tree:
            if pid not in seen:
                seen.add(pid)
                merged.append((pid, start))
    return merged


def _children_of(pid: int, tree: list[tuple[int, int | None]]) -> list[tuple[int, int | None]]:
    """Members of ``tree`` whose parent is ``pid`` (the terminal holder's sudo)."""
    found = []
    for member, start in tree:
        st = read_stat(member)
        if st is not None and st.ppid == pid:
            found.append((member, start))
    return found


# --- workspace activity (L.4) -------------------------------------------------------------

def process_check_available() -> bool:
    """``/proc`` shows other users' processes (no ``hidepid``): init's cmdline is readable."""
    return _read_proc_file(1, "cmdline", 16) is not None


def matching_processes(workspace: str) -> int:
    """Processes whose cmdline has a ``sniper`` element and the pair ``-w <workspace>``."""
    wanted = workspace.encode()
    own = os.getpid()
    count = 0
    try:
        names = os.listdir(paths.PROC_ROOT)
    except OSError:
        return 0
    for name in names:
        if not name.isdigit() or int(name) == own:
            continue
        argv = read_cmdline(int(name))
        if not argv:
            continue
        if not any(os.path.basename(arg) == b"sniper" for arg in argv):
            continue
        if any(argv[i] == b"-w" and argv[i + 1] == wanted for i in range(len(argv) - 1)):
            count += 1
    return count


_MARKER_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def read_markers(workspace: str | int) -> dict[str, int]:
    """J.3.5 marker counts, read without following symbolic links.

    ``workspace`` is the workspace path, or a directory descriptor already opened with
    the safe opener (J.1); a descriptor is read relative to, and not closed, so the
    counts come from the directory that was validated, not from a path that may since
    have been swapped."""
    if isinstance(workspace, int):
        return _read_markers_at(workspace)
    try:
        ws_fd = os.open(workspace, _MARKER_DIR_FLAGS)
    except OSError:
        return {"tasks_running": 0, "running_files": 0, "resume_markers": 0}
    try:
        return _read_markers_at(ws_fd)
    finally:
        os.close(ws_fd)


def _read_markers_at(ws_fd: int) -> dict[str, int]:
    markers = {"tasks_running": 0, "running_files": 0, "resume_markers": 0}
    dir_flags = _MARKER_DIR_FLAGS
    try:
        scans_fd = os.open("scans", dir_flags, dir_fd=ws_fd)
    except OSError:
        return markers
    try:
        markers["tasks_running"] = _read_counter(scans_fd, "tasks-running.txt")
        markers["running_files"] = _count_entries(
            scans_fd, lambda n: n.startswith("running_") and n.endswith(".txt"))
        try:
            resume_fd = os.open("resume", dir_flags, dir_fd=scans_fd)
        except OSError:
            resume_fd = None
        if resume_fd is not None:
            try:
                markers["resume_markers"] = _count_entries(
                    resume_fd, lambda n: n.endswith(".running"))
            finally:
                os.close(resume_fd)
    finally:
        os.close(scans_fd)
    return markers


def _read_counter(dir_fd: int, name: str) -> int:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=dir_fd)
    except OSError:
        return 0
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return 0
        text = os.read(fd, _MARKER_MAX_BYTES).decode("ascii", "replace").strip()
    except OSError:
        return 0
    finally:
        os.close(fd)
    return int(text) if text.isdecimal() and len(text) <= 9 else 0


def _count_entries(dir_fd: int, wanted: Callable[[str], bool]) -> int:
    count = 0
    try:
        with os.scandir(dir_fd) as entries:
            for entry in entries:
                if wanted(entry.name) and entry.is_file(follow_symlinks=False):
                    count += 1
    except OSError:
        return count
    return count


def workspace_activity(workspace: str, location: str | int) -> Activity:
    """L.4 for ``scan_status(workspace=...)`` and the delete/export busy checks;
    ``location`` is the workspace path or an open directory descriptor (see
    :func:`read_markers`)."""
    markers = read_markers(location)
    if not process_check_available():
        return Activity(running_processes=0, process_check="unavailable", markers=markers)
    return Activity(running_processes=matching_processes(workspace), process_check="ok",
                    markers=markers)


# --- helpers -------------------------------------------------------------------------------

def _read_exactly(fd: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit
    while remaining > 0:
        chunk = os.read(fd, min(remaining, 65536))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _unlink_quietly(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def _note_in_log(fd: int, text: str) -> None:
    """One ``sn1per-mcp:`` line in a job log the server still has open."""
    try:
        os.write(fd, f"sn1per-mcp: {text}\n".encode("utf-8", "replace"))
    except OSError:
        pass
