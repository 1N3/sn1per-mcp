# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""JSONL audit log (contract G).

One :class:`AuditLog` per server process. Every record is one line, written
with a single ``os.write`` under an exclusive ``flock`` (several server
processes may share the file) and under this process's write lock, which also
assigns ``seq`` and ``prev``: ``seq`` counts this session's successful writes
and ``prev`` is the SHA-256 of the previous line this session wrote. The log
is never read back, rotated, truncated or deleted (G.1, G.5).

The file is opened for every record with ``O_NOFOLLOW`` and checked with
``fstat`` on the descriptor: a regular file owned by the effective UID. A
looser mode is fixed with ``fchmod``; if that fails with ``EPERM`` (an
append-only file, ``chattr +a``) the log stays usable with warning
``audit_log_mode_not_fixed`` unless group or others can write it (G.1).
"""

from __future__ import annotations

import datetime
import errno
import fcntl
import hashlib
import json
import logging
import os
import re
import secrets
import stat
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from sniper_mcp import __version__

SCHEMA_VERSION = "1"

# G.4 events.
SERVER_START = "server_start"
SERVER_STOP = "server_stop"
SCAN_REQUEST = "scan_request"
SCAN_EXIT = "scan_exit"
CANCEL_REQUEST = "cancel_request"
DELETE_REQUEST = "delete_request"
EXPORT_REQUEST = "export_request"
PLUGIN_LOADED = "plugin_loaded"
PLUGIN_ERROR = "plugin_error"
SCOPE_CHANGED = "scope_changed"
EVENTS = frozenset({SERVER_START, SERVER_STOP, SCAN_REQUEST, SCAN_EXIT, CANCEL_REQUEST,
                    DELETE_REQUEST, EXPORT_REQUEST, PLUGIN_LOADED, PLUGIN_ERROR,
                    SCOPE_CHANGED})
# Events that carry the action fields (G.3).
ACTION_EVENTS = frozenset({SCAN_REQUEST, SCAN_EXIT, CANCEL_REQUEST, DELETE_REQUEST,
                           EXPORT_REQUEST})
DECISIONS = frozenset({"accepted", "refused", "declined", "completed", "failed"})
# Plugin events (M.2): ``plugin:<entry-point-name>:<event>``, never action events.
PLUGIN_EVENT_RE = re.compile(r"plugin:[a-z0-9][a-z0-9._-]{0,63}:[a-z][a-z0-9_]{0,63}")

# G.3 field order.
COMMON_FIELDS = ("schema_version", "ts", "event", "server_version", "pid", "session", "seq",
                 "prev", "client", "request_id")
ACTION_FIELDS = ("tool", "decision", "reason_code", "reason", "target_input", "target",
                 "target_type", "resolved_addresses", "resolved_addresses_total", "mode",
                 "mode_class", "port", "workspace", "job_id", "argv", "sudo", "edition",
                 "dialect", "engine_version", "scope_source", "scope_digest",
                 "matched_scope_entry", "allow_any_target", "allow_intrusive", "dns_policy",
                 "authorization_ref", "elicitation")

REASON_MAX_CHARS = 200
TARGET_INPUT_MAX_CHARS = 256
CLIENT_FIELD_MAX_CHARS = 64
RESOLVED_MAX = 64
LOCK_WAIT_SECONDS = 5.0
_LOCK_POLL_SECONDS = 0.02
# O_NONBLOCK: a FIFO planted at the audit path fails the open (or the fstat check)
# instead of blocking the tool call; regular files ignore the flag.
_OPEN_FLAGS = (os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
               | os.O_NONBLOCK)
_PROBE_FLAGS = _OPEN_FLAGS & ~os.O_CREAT

log = logging.getLogger("sn1per-mcp")


class AuditUnavailable(Exception):
    """The audit log cannot be opened or written (``audit_unavailable``, G.2)."""


def utc_timestamp(epoch: float | None = None) -> str:
    """ISO 8601 UTC with milliseconds and ``Z`` (G.3, 09 GAP-25)."""
    moment = datetime.datetime.fromtimestamp(time.time() if epoch is None else epoch,
                                             tz=datetime.UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def client_object(name: object, version: object) -> dict[str, str] | None:
    """The ``client`` field: initialize clientInfo, each value cut to 64 characters."""
    if not isinstance(name, str) or not isinstance(version, str):
        return None
    return {"name": name[:CLIENT_FIELD_MAX_CHARS], "version": version[:CLIENT_FIELD_MAX_CHARS]}


def action_fields(**values: Any) -> dict[str, Any]:
    """Every G.3 action field in order; fields not given are ``null``.

    Raises ``ValueError`` for an unknown field name or decision, so a typo can
    never drop a field silently.
    """
    unknown = set(values) - set(ACTION_FIELDS)
    if unknown:
        raise ValueError(f"unknown audit action fields: {sorted(unknown)}")
    decision = values.get("decision")
    if decision is not None and decision not in DECISIONS:
        raise ValueError(f"unknown audit decision {decision!r}")
    fields = {name: values.get(name) for name in ACTION_FIELDS}
    if isinstance(fields["reason"], str):
        fields["reason"] = fields["reason"][:REASON_MAX_CHARS]
    if isinstance(fields["target_input"], str):
        fields["target_input"] = fields["target_input"][:TARGET_INPUT_MAX_CHARS]
    if isinstance(fields["resolved_addresses"], list):
        fields["resolved_addresses"] = fields["resolved_addresses"][:RESOLVED_MAX]
    return fields


@dataclass(frozen=True)
class AuditStatus:
    """Outcome of :meth:`AuditLog.status` (``sniper_status``, ``--check``)."""

    available: bool
    problem: str | None
    mode_not_fixed: bool


class AuditLog:
    """The audit writer of one server process (one ``session``)."""

    def __init__(self, path: str, *, session: str | None = None,
                 allow_any_target: bool = False, allow_intrusive: bool = False) -> None:
        self.path = path
        self.session = session or secrets.token_hex(4)
        # The lab overrides of this process (F.6, G.3): every action line carries them,
        # whatever the caller passed, so an action taken under an override is always
        # identifiable from its own line.
        self.allow_any_target = allow_any_target
        self.allow_intrusive = allow_intrusive
        self.client: dict[str, str] | None = None
        self.mode_not_fixed = False
        self._lock = threading.Lock()
        self._seq = 0
        self._prev: str | None = None

    @property
    def seq(self) -> int:
        """Number of records this session has written."""
        return self._seq

    # --- opening ---------------------------------------------------------------
    def _check_fd(self, fd: int) -> None:
        """G.1 checks on an opened descriptor; raises ``AuditUnavailable``."""
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise AuditUnavailable(f"{self.path} is not a regular file")
        if st.st_uid != os.geteuid():
            raise AuditUnavailable(f"{self.path} is owned by uid {st.st_uid}, not by uid "
                                   f"{os.geteuid()}")
        mode = stat.S_IMODE(st.st_mode)
        if not mode & 0o077:
            self.mode_not_fixed = False
            return
        try:
            os.fchmod(fd, 0o600)
        except PermissionError as exc:
            if mode & 0o022:
                raise AuditUnavailable(f"{self.path} is group- or world-writable and its "
                                       "mode cannot be changed") from exc
            self.mode_not_fixed = True
            return
        self.mode_not_fixed = False

    def _open(self, flags: int = _OPEN_FLAGS) -> int:
        try:
            fd = os.open(self.path, flags, 0o600)
        except OSError as exc:
            raise AuditUnavailable(f"{self.path} cannot be opened ({exc.strerror})") from exc
        try:
            self._check_fd(fd)
        except BaseException:
            os.close(fd)
            raise
        return fd

    def check(self) -> None:
        """Open the log as a write would (creating it); raises ``AuditUnavailable``."""
        with self._lock:
            os.close(self._open())

    def status(self) -> AuditStatus:
        """Whether a write would succeed, without creating the file (read tools, ``--check``)."""
        with self._lock:
            try:
                fd = self._open(_PROBE_FLAGS)
            except AuditUnavailable as exc:
                cause = exc.__cause__
                if isinstance(cause, FileNotFoundError):
                    # Not created yet: the first write creates it if the directory allows.
                    parent = os.path.dirname(self.path) or "."
                    if os.path.isdir(parent) and os.access(parent, os.W_OK | os.X_OK):
                        return AuditStatus(True, None, False)
                return AuditStatus(False, str(exc), False)
            os.close(fd)
            return AuditStatus(True, None, self.mode_not_fixed)

    @staticmethod
    def _flock(fd: int) -> None:
        deadline = time.monotonic() + LOCK_WAIT_SECONDS
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except OSError as exc:
                if exc.errno not in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES):
                    raise AuditUnavailable(f"cannot lock the audit log ({exc.strerror})") \
                        from exc
            if time.monotonic() >= deadline:
                raise AuditUnavailable("the audit log stayed locked by another process")
            time.sleep(_LOCK_POLL_SECONDS)

    # --- writing ---------------------------------------------------------------
    def write(self, event: str, *, action: Mapping[str, Any] | None = None,
              result: Mapping[str, Any] | None = None, request_id: object = None,
              client: dict[str, str] | None = None) -> int:
        """Write one record; returns its ``seq``. Raises ``AuditUnavailable``.

        ``action`` comes from :func:`action_fields` and is required exactly for
        the action events. On those, ``allow_any_target`` and ``allow_intrusive``
        are always booleans: the value given, or true when this process runs with
        the override (F.6). A failed write does not consume a ``seq`` number.
        """
        if event not in EVENTS and not PLUGIN_EVENT_RE.fullmatch(event):
            raise ValueError(f"unknown audit event {event!r}")
        if (event in ACTION_EVENTS) != (action is not None):
            raise ValueError(f"event {event} {'needs' if event in ACTION_EVENTS else 'takes no'}"
                             " action fields")
        if not isinstance(request_id, (str, int)) or isinstance(request_id, bool):
            request_id = None
        with self._lock:
            fd = self._open()
            try:
                self._flock(fd)
                record: dict[str, Any] = {
                    "schema_version": SCHEMA_VERSION,
                    "ts": utc_timestamp(),
                    "event": event,
                    "server_version": __version__,
                    "pid": os.getpid(),
                    "session": self.session,
                    "seq": self._seq + 1,
                    "prev": self._prev,
                    "client": client if client is not None else self.client,
                    "request_id": request_id,
                }
                if action is not None:
                    for name in ACTION_FIELDS:
                        record[name] = action.get(name)
                    record["allow_any_target"] = (bool(record["allow_any_target"])
                                                  or self.allow_any_target)
                    record["allow_intrusive"] = (bool(record["allow_intrusive"])
                                                 or self.allow_intrusive)
                record["result"] = dict(result) if result is not None else {}
                line = json.dumps(record, ensure_ascii=True, separators=(",", ":"))
                data = line.encode("ascii") + b"\n"
                try:
                    written = os.write(fd, data)
                except OSError as exc:
                    raise AuditUnavailable(f"cannot write the audit log ({exc.strerror})") \
                        from exc
                if written != len(data):
                    raise AuditUnavailable("short write to the audit log")
                self._seq += 1
                self._prev = hashlib.sha256(data[:-1]).hexdigest()
                return self._seq
            finally:
                os.close(fd)  # closing the descriptor releases the flock

    def write_best_effort(self, event: str, **kwargs: Any) -> bool:
        """:meth:`write` for refusals and notices: failures go to stderr only (G.2)."""
        try:
            self.write(event, **kwargs)
        except AuditUnavailable as exc:
            log.warning("audit log unavailable, %s record not written: %s", event, exc)
            return False
        return True
