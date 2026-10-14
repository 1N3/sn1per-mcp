# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Secure directory and file helpers (contract L.1, B.5, F.1).

Everything here opens with ``O_NOFOLLOW`` and checks the opened descriptor with
``fstat``, never stat-then-open, so a symbolic link swapped in between cannot
redirect a read or a write.
"""

from __future__ import annotations

import errno
import fcntl
import json
import os
import secrets
import stat
import time
from dataclasses import dataclass, field
from typing import Any

from sniper_mcp import paths

JOBS_SUBDIR = "jobs"
EXPORTS_SUBDIR = "exports"
SCAN_LOCK_NAME = "scan.lock"

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_LOCK_FLAGS = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_LOCK_POLL_SECONDS = 0.05


class StateDirInsecure(Exception):
    """The state directory is a symlink, not a directory, or owned by another user."""


class SecureFileError(Exception):
    """A configuration file failed the open or ``fstat`` checks.

    ``reason`` is a short stable code (``file_unreadable``, ``file_not_regular``,
    ``file_owner``, ``file_writable``, ``file_too_large``) and ``st`` the
    ``fstat`` result when the file could be opened.
    """

    def __init__(self, message: str, *, reason: str = "file_unreadable",
                 st: os.stat_result | None = None) -> None:
        super().__init__(message)
        self.reason = reason
        self.st = st


@dataclass(frozen=True)
class StateDirStatus:
    """Outcome of preparing the state directory (L.1)."""

    path: str
    ok: bool
    problem: str | None = None
    warnings: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class SecureFile:
    """Content and ``fstat`` result of a file read through :func:`read_secure_file`."""

    data: bytes
    st: os.stat_result


def _chmod_private(name: str, *, dir_fd: int | None = None) -> None:
    """Make a directory this process just created ``0700``, whatever the umask.

    ``chmod(follow_symlinks=False)`` raises ``NotImplementedError`` (not an
    ``OSError``) where ``fchmodat`` lacks ``AT_SYMLINK_NOFOLLOW``; there the
    entry is checked to be a real directory first. The caller then opens it with
    ``O_NOFOLLOW`` and checks the descriptor, so a swapped-in link is refused
    either way.
    """
    try:
        os.chmod(name, 0o700, dir_fd=dir_fd, follow_symlinks=False)
    except NotImplementedError:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            os.chmod(name, 0o700, dir_fd=dir_fd)


def _create_missing_dirs(path: str) -> None:
    """Create ``path`` and its missing parents, each ``0700`` regardless of umask."""
    missing: list[str] = []
    current = path
    while not os.path.lexists(current):
        missing.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    for directory in reversed(missing):
        try:
            os.mkdir(directory, 0o700)
        except FileExistsError:
            continue
        _chmod_private(directory)


def _check_private_fd(fd: int, label: str) -> bool:
    """Check an opened directory fd; fix loose modes. Returns True if fixed."""
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode):
        raise StateDirInsecure(f"{label} is not a directory")
    if st.st_uid != os.geteuid():
        raise StateDirInsecure(f"{label} is owned by uid {st.st_uid}, not by uid {os.geteuid()}")
    if stat.S_IMODE(st.st_mode) & 0o077:
        os.fchmod(fd, 0o700)
        return True
    return False


def _open_dir_nofollow(path: str, *, dir_fd: int | None = None) -> int:
    try:
        return os.open(path, _DIR_FLAGS, dir_fd=dir_fd)
    except OSError as exc:
        raise StateDirInsecure(
            f"{path} cannot be opened as a real directory ({exc.strerror})"
        ) from exc


def prepare_state_dir(path: str) -> StateDirStatus:
    """Create or check ``<state_dir>`` with its ``jobs/`` and ``exports/`` (L.1).

    Never raises for an insecure directory: the problem is returned so that only
    the tools that write state refuse (``state_dir_insecure``) while read tools
    keep working.
    """
    warnings: list[str] = []
    try:
        _create_missing_dirs(path)
        fd = _open_dir_nofollow(path)
        try:
            fixed = _check_private_fd(fd, path)
            for sub in (JOBS_SUBDIR, EXPORTS_SUBDIR):
                try:
                    os.mkdir(sub, 0o700, dir_fd=fd)
                    _chmod_private(sub, dir_fd=fd)
                except FileExistsError:
                    pass
                sub_fd = _open_dir_nofollow(sub, dir_fd=fd)
                try:
                    fixed = _check_private_fd(sub_fd, os.path.join(path, sub)) or fixed
                finally:
                    os.close(sub_fd)
        finally:
            os.close(fd)
    except StateDirInsecure as exc:
        return StateDirStatus(path=path, ok=False, problem=str(exc))
    except OSError as exc:
        return StateDirStatus(
            path=path, ok=False, problem=f"{path} cannot be prepared ({exc.strerror})"
        )
    if fixed:
        warnings.append("state_dir_permissions_fixed")
    return StateDirStatus(path=path, ok=True, warnings=tuple(warnings))


def read_secure_file(path: str, *, max_bytes: int, label: str) -> SecureFile:
    """Read a configuration file the agent must not be able to swap (B.5, F.1).

    Opens with ``O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`` and checks the
    descriptor: a regular file owned by the effective UID or by
    ``paths.TRUSTED_UID``, not group- or world-writable, at most ``max_bytes``.
    """
    if not os.path.isabs(path):
        raise SecureFileError(f"{label} must be an absolute path")
    try:
        fd = os.open(path, _READ_FLAGS)
    except OSError as exc:
        raise SecureFileError(f"{label} {path} cannot be opened ({exc.strerror})") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SecureFileError(f"{label} {path} is not a regular file",
                                  reason="file_not_regular", st=st)
        if st.st_uid not in (os.geteuid(), paths.TRUSTED_UID):
            # V1: name the actual owner (a file copied with "docker cp" keeps the host
            # user's uid), and do not repeat root when the server itself runs as root.
            allowed = (f"uid {paths.TRUSTED_UID} (root)" if os.geteuid() == paths.TRUSTED_UID
                       else f"uid {os.geteuid()} (the server's user) or uid "
                            f"{paths.TRUSTED_UID} (root)")
            raise SecureFileError(
                f"{label} {path} is owned by uid {st.st_uid}; it must be owned by {allowed}",
                reason="file_owner", st=st,
            )
        if stat.S_IMODE(st.st_mode) & 0o022:
            raise SecureFileError(f"{label} {path} must not be group- or world-writable",
                                  reason="file_writable", st=st)
        if st.st_size > max_bytes:
            raise SecureFileError(f"{label} {path} is larger than {max_bytes} bytes",
                                  reason="file_too_large", st=st)
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise SecureFileError(f"{label} {path} is larger than {max_bytes} bytes",
                                  reason="file_too_large", st=st)
        return SecureFile(data=data, st=st)
    finally:
        os.close(fd)


def create_exclusive(path: str) -> int:
    """Create a new ``0600`` file for writing; fails if it exists or is a link (L.5)."""
    return os.open(path, _CREATE_FLAGS, 0o600)


def write_json_atomic(path: str, obj: Any) -> None:
    """Write ``obj`` as JSON to ``path``: temp file, fsync, rename (L.1)."""
    directory = os.path.dirname(path)
    tmp = os.path.join(directory, f".{os.path.basename(path)}.{secrets.token_hex(4)}.tmp")
    data = json.dumps(obj, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    fd = create_exclusive(tmp)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        os.unlink(tmp)
        raise
    os.close(fd)
    os.replace(tmp, path)
    dir_fd = os.open(directory, _DIR_FLAGS)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def read_private_file(path: str, *, max_bytes: int, dir_fd: int | None = None) -> bytes:
    """Read a file of the private state directory (job records, job logs).

    ``O_NOFOLLOW`` and ``fstat`` on the descriptor: a regular file owned by the
    effective UID, at most ``max_bytes``. Raises ``OSError`` when the file
    cannot be opened and ``SecureFileError`` when a check fails.
    """
    fd = os.open(path, _READ_FLAGS, dir_fd=dir_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SecureFileError(f"{path} is not a regular file", reason="file_not_regular",
                                  st=st)
        if st.st_uid != os.geteuid():
            raise SecureFileError(f"{path} is not owned by uid {os.geteuid()}",
                                  reason="file_owner", st=st)
        if st.st_size > max_bytes:
            raise SecureFileError(f"{path} is larger than {max_bytes} bytes",
                                  reason="file_too_large", st=st)
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise SecureFileError(f"{path} is larger than {max_bytes} bytes",
                                  reason="file_too_large", st=st)
        return data
    finally:
        os.close(fd)


class LockTimeout(Exception):
    """An exclusive ``flock`` was not granted within the wait limit."""


def open_lock_file(path: str) -> int:
    """Open (creating ``0600``) a lock file of the state directory (``scan.lock``, L.1).

    Raises ``StateDirInsecure`` unless it is a regular file owned by the effective
    UID; a symbolic link fails the open.
    """
    try:
        fd = os.open(path, _LOCK_FLAGS, 0o600)
    except OSError as exc:
        raise StateDirInsecure(f"{path} cannot be opened ({exc.strerror})") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid():
            raise StateDirInsecure(f"{path} is not a regular file owned by uid {os.geteuid()}")
    except BaseException:
        os.close(fd)
        raise
    return fd


def open_dir_lock(path: str) -> int:
    """Open a directory of the state dir for ``flock`` (record updates, L.8)."""
    try:
        fd = os.open(path, _DIR_FLAGS)
    except OSError as exc:
        raise StateDirInsecure(f"{path} cannot be opened ({exc.strerror})") from exc
    try:
        st = os.fstat(fd)
        if st.st_uid != os.geteuid():
            raise StateDirInsecure(f"{path} is not owned by uid {os.geteuid()}")
    except BaseException:
        os.close(fd)
        raise
    return fd


def flock_exclusive(fd: int, *, timeout: float) -> None:
    """``LOCK_EX | LOCK_NB``, retried until ``timeout`` seconds; raises ``LockTimeout``."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except OSError as exc:
            if exc.errno not in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES):
                raise
        if time.monotonic() >= deadline:
            raise LockTimeout("lock not granted in time")
        time.sleep(_LOCK_POLL_SECONDS)


def open_private_subdir(state_dir: str, name: str) -> int:
    """Open ``<state_dir>/<name>`` (``exports/``) for creating files in it (L.1, I.4).

    Both levels are opened with ``O_NOFOLLOW`` and checked on the descriptor: a real
    directory owned by the effective UID with no group or other access. Raises
    ``StateDirInsecure``.
    """
    parent = _open_dir_nofollow(state_dir)
    try:
        fd = _open_dir_nofollow(name, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        st = os.fstat(fd)
        label = os.path.join(state_dir, name)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
            raise StateDirInsecure(f"{label} is not a directory owned by uid {os.geteuid()}")
        if stat.S_IMODE(st.st_mode) & 0o077:
            raise StateDirInsecure(f"{label} is group- or world-accessible")
    except BaseException:
        os.close(fd)
        raise
    return fd
