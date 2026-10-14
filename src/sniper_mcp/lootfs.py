# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Safe loot filesystem access (contract J.1, J.2).

The loot tree is world-writable on Community Edition after a scan and 0777 on
the live Enterprise host, so every name in it is attacker-influenced. This
module therefore never follows a symbolic link and never resolves a path
string twice:

- The loot base (operator configuration) is ``realpath``-resolved once and its
  ``(st_dev, st_ino)`` is pinned at startup, or at the first successful open
  when it did not exist yet (A-47). Every later open compares; a mismatch is
  ``loot_dir_changed``.
- Every component below it is opened relative to its parent's descriptor with
  ``O_NOFOLLOW``; a symbolic link fails the open and counts as absent.
- Files are opened ``O_NONBLOCK`` (a FIFO never blocks), checked with
  ``fstat`` (only regular files are read) and skipped when they have more than
  one hard link.
- Listings come from ``os.scandir(<dir fd>)`` with ``follow_symlinks=False``.

The J.2 exclusions (``credentials/``, ``bloodhound/`` and the credential-file
denylist, all case-insensitive) live here too, together with the matching
``grep`` arguments (J.5).
"""

from __future__ import annotations

import os
import re
import stat
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field

from sniper_mcp import paths, targets

BASE_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC

# J.4 caps.
FILE_READ_CAP = 8 * 1024 * 1024
CALL_READ_CAP = 64 * 1024 * 1024
CALL_FILE_CAP = 5000
LINE_CAP = 64 * 1024
FIELD_CAP = 2000
# Directory depth the walker descends to (real loot is three or four levels deep).
WALK_MAX_DEPTH = 32

# H.1: a reader skips a source whose relative path has a component outside this set.
SOURCE_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,128}")

# J.2 exclusions (case-insensitive).
EXCLUDED_DIRS: tuple[str, ...] = ("credentials", "bloodhound")
EXCLUDED_SUFFIXES: tuple[str, ...] = (
    ".pfx", ".p12", ".ccache", ".kirbi", ".keytab", ".key", ".pem", ".pot", ".potfile",
    ".hccapx", ".22000", ".dit",
)
EXCLUDED_SUBSTRINGS: tuple[str, ...] = (
    "kerberoast", "asrep", "as_rep", "timeroast", "hash_cracking", "hashcat", "secretsdump",
    "potfile", "gpp_laps", "credential_harvest", "lsass", "ntds",
)


class LootError(Exception):
    """A loot lookup failed (H.2 code in ``code``)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# --- J.2 exclusions ----------------------------------------------------------------------

def is_excluded_dir(name: str) -> bool:
    """``credentials`` or ``bloodhound`` in any letter case, at any depth."""
    return name.lower() in EXCLUDED_DIRS


def is_excluded_file(name: str) -> bool:
    """A known credential file name (suffix or substring rule), in any letter case."""
    lowered = name.lower()
    return lowered.endswith(EXCLUDED_SUFFIXES) or any(
        part in lowered for part in EXCLUDED_SUBSTRINGS)


def case_glob(text: str) -> str:
    """A shell glob matching ``text`` in every letter case (``[Cc][Rr]...``).

    grep's ``--exclude`` and ``--exclude-dir`` match case-sensitively, and a local
    user can rename the world-writable ``credentials/`` to ``CrEdentials``.
    """
    out = []
    for ch in text:
        if ch.isalpha():
            out.append(f"[{ch.lower()}{ch.upper()}]")
        elif ch in "*?[]\\":
            out.append(f"[{ch}]")
        else:
            out.append(ch)
    return "".join(out)


def grep_exclusion_args() -> list[str]:
    """The J.5 exclusion arguments: every J.2 rule, written for every letter case."""
    args = [f"--exclude-dir={case_glob(name)}" for name in EXCLUDED_DIRS]
    args += [f"--exclude=*{case_glob(suffix)}" for suffix in EXCLUDED_SUFFIXES]
    args += [f"--exclude=*{case_glob(part)}*" for part in EXCLUDED_SUBSTRINGS]
    return args


# --- statistics of one call ---------------------------------------------------------------

@dataclass
class ReadStats:
    """What a reader call skipped and how much it read (J.1, J.4, H.1)."""

    hardlinks_skipped: int = 0
    unreadable: int = 0
    source_names_skipped: int = 0
    symlinks_skipped: int = 0
    special_skipped: int = 0
    excluded_dirs: int = 0
    excluded_files: int = 0
    bytes_read: int = 0
    files_read: int = 0
    call_cap_reached: bool = False

    def can_read(self) -> bool:
        """False once the per-call caps (64 MiB, 5,000 files) are used up."""
        if self.files_read >= CALL_FILE_CAP or self.bytes_read >= CALL_READ_CAP:
            self.call_cap_reached = True
            return False
        return True


@dataclass(frozen=True)
class Entry:
    """One directory entry, typed without following symbolic links."""

    name: str
    kind: str  # "dir", "file", "symlink" or "other"


@dataclass(frozen=True)
class FileData:
    """The bytes read from one regular file (at most the cap) and whether it was cut."""

    data: bytes
    truncated: bool


def component_ok(name: str) -> bool:
    """A single path component: not empty, no ``/`` or NUL, not ``.`` or ``..``."""
    return bool(name) and "/" not in name and "\x00" not in name and name not in (".", "..")


def open_dir(parent_fd: int, name: str, stats: ReadStats | None = None) -> int | None:
    """Open the directory ``name`` below ``parent_fd`` without following a link.

    A symbolic link, a missing entry or a non-directory is absent (``None``); a
    permission problem is absent too and counted in ``stats.unreadable``.
    """
    if not component_ok(name):
        return None
    try:
        return os.open(name, DIR_FLAGS, dir_fd=parent_fd)
    except PermissionError:
        if stats is not None:
            stats.unreadable += 1
        return None
    except OSError:
        return None


def list_dir(dir_fd: int, stats: ReadStats | None = None) -> list[Entry]:
    """Entries of the directory open at ``dir_fd``, sorted by name, typed with
    ``follow_symlinks=False``."""
    entries: list[Entry] = []
    try:
        with os.scandir(dir_fd) as iterator:
            for item in iterator:
                name = item.name
                if not component_ok(name):
                    continue
                try:
                    if item.is_symlink():
                        kind = "symlink"
                    elif item.is_dir(follow_symlinks=False):
                        kind = "dir"
                    elif item.is_file(follow_symlinks=False):
                        kind = "file"
                    else:
                        kind = "other"
                except OSError:
                    if stats is not None:
                        stats.unreadable += 1
                    continue
                entries.append(Entry(name=name, kind=kind))
    except PermissionError:
        if stats is not None:
            stats.unreadable += 1
        return []
    except OSError:
        return []
    entries.sort(key=lambda e: e.name)
    return entries


def _read_up_to(fd: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit
    while remaining > 0:
        chunk = os.read(fd, min(remaining, 1024 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_file(dir_fd: int, name: str, stats: ReadStats, *, cap: int = FILE_READ_CAP,
              allow_hardlinks: bool = False, count: bool = True) -> FileData | None:
    """Read at most ``cap`` bytes of the regular file ``name`` below ``dir_fd`` (J.1).

    Returns ``None`` for anything that is not a regular file reached without a
    link (FIFOs and devices are never read), for files with more than one hard
    link (unless ``allow_hardlinks``; counted in ``stats.hardlinks_skipped``) and
    for files that cannot be opened (``stats.unreadable`` on a permission
    problem). With ``count`` the bytes are charged to the per-call caps (J.4).
    """
    if not component_ok(name):
        return None
    try:
        fd = os.open(name, FILE_FLAGS, dir_fd=dir_fd)
    except PermissionError:
        stats.unreadable += 1
        return None
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            stats.special_skipped += 1
            return None
        if st.st_nlink > 1 and not allow_hardlinks:
            stats.hardlinks_skipped += 1
            return None
        limit = cap
        if count:
            limit = max(min(cap, CALL_READ_CAP - stats.bytes_read), 0)
        data = _read_up_to(fd, limit + 1)
    except OSError:
        stats.unreadable += 1
        return None
    finally:
        os.close(fd)
    truncated = len(data) > limit
    data = data[:limit]
    if count:
        stats.bytes_read += len(data)
        stats.files_read += 1
    return FileData(data=data, truncated=truncated)


def open_relative(root_fd: int, components: list[str] | tuple[str, ...],
                  stats: ReadStats | None = None) -> int | None:
    """Open the directory ``<root>/<components...>`` one component at a time."""
    current = os.dup(root_fd)
    for name in components:
        nxt = open_dir(current, name, stats)
        os.close(current)
        if nxt is None:
            return None
        current = nxt
    return current


# --- the walker (J.1) ----------------------------------------------------------------------

@dataclass(frozen=True)
class WalkItem:
    """A regular-file entry met by :func:`walk`; ``dir_fd`` is valid during the yield."""

    components: tuple[str, ...]
    dir_fd: int

    @property
    def name(self) -> str:
        return self.components[-1]

    @property
    def relpath(self) -> str:
        return "/".join(self.components)


def walk(dir_fd: int, stats: ReadStats, *, exclude: bool,
         _prefix: tuple[str, ...] = (), _depth: int = 0) -> Iterator[WalkItem]:
    """Depth-first walk below ``dir_fd`` that never follows a symbolic link.

    Yields regular-file entries; the caller reads them with :func:`read_file`
    on ``item.dir_fd``, which checks the type again on the open descriptor.
    Symbolic links and special files are counted and skipped; with ``exclude``
    the J.2 directories and files are skipped too.
    """
    for entry in list_dir(dir_fd, stats):
        if entry.kind == "symlink":
            stats.symlinks_skipped += 1
        elif entry.kind == "other":
            stats.special_skipped += 1
        elif entry.kind == "dir":
            if exclude and is_excluded_dir(entry.name):
                stats.excluded_dirs += 1
                continue
            if _depth + 1 > WALK_MAX_DEPTH:
                stats.unreadable += 1
                continue
            child = open_dir(dir_fd, entry.name, stats)
            if child is None:
                continue
            try:
                yield from walk(child, stats, exclude=exclude,
                                _prefix=(*_prefix, entry.name), _depth=_depth + 1)
            finally:
                os.close(child)
        else:
            if exclude and is_excluded_file(entry.name):
                stats.excluded_files += 1
                continue
            yield WalkItem(components=(*_prefix, entry.name), dir_fd=dir_fd)


# --- the loot base and workspaces ----------------------------------------------------------

@dataclass
class LootBase:
    """The configured loot base, resolved once, with its pinned identity (J.1)."""

    configured: str
    path: str = field(init=False)
    _identity: tuple[int, int] | None = field(default=None, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        self.path = os.path.realpath(self.configured)

    @property
    def identity(self) -> tuple[int, int] | None:
        return self._identity

    @property
    def workspace_dir(self) -> str:
        """``<loot_base>/workspace`` as configured (shown to the operator)."""
        return os.path.join(self.configured, paths.WORKSPACE_SUBDIR)

    def record_if_exists(self) -> None:
        """P.4 step 5: pin the identity when the loot base exists at startup."""
        try:
            fd = self.open()
        except LootError:
            return
        if fd is not None:
            os.close(fd)

    def open(self, stats: ReadStats | None = None) -> int | None:
        """Open the loot base; ``None`` when it does not exist (or cannot be opened).

        Raises ``LootError("loot_dir_changed")`` when it is not the directory
        pinned at startup or at the first successful open.
        """
        try:
            fd = os.open(self.path, BASE_FLAGS)
        except PermissionError:
            if stats is not None:
                stats.unreadable += 1
            return None
        except OSError:
            return None
        try:
            st = os.fstat(fd)
        except OSError:
            os.close(fd)
            return None
        identity = (st.st_dev, st.st_ino)
        with self._lock:
            if self._identity is None:
                self._identity = identity
            elif self._identity != identity:
                os.close(fd)
                raise LootError("loot_dir_changed", "The loot directory is no longer the "
                                "directory identified when the server started.")
        return fd

    def check(self) -> None:
        """Raise ``loot_dir_changed`` if the loot base was swapped (no-op when missing)."""
        fd = self.open()
        if fd is not None:
            os.close(fd)

    def open_workspace_root(self, stats: ReadStats | None = None) -> int | None:
        """``<loot_base>/workspace``; ``None`` when it does not exist."""
        base = self.open(stats)
        if base is None:
            return None
        try:
            return open_dir(base, paths.WORKSPACE_SUBDIR, stats)
        finally:
            os.close(base)

    def open_workspace(self, name: str, stats: ReadStats | None = None) -> int:
        """The workspace directory ``name`` (E.3 grammar, a real directory, no link)."""
        fd = self.open_workspace_if_root(name, stats)
        if fd is None:
            raise LootError("workspace_not_found",
                            f"Workspace {name} does not exist (no workspace directory yet).")
        return fd

    def open_workspace_if_root(self, name: str, stats: ReadStats | None = None) -> int | None:
        """Like :meth:`open_workspace`, but ``None`` when ``<loot_base>/workspace`` itself
        does not exist (C.3: read tools then return empty results with
        ``loot_dir_missing``). A missing workspace inside an existing directory is
        still ``workspace_not_found``."""
        if not targets.is_valid_workspace(name):
            raise LootError("invalid_workspace", "Invalid workspace name.")
        root = self.open_workspace_root(stats)
        if root is None:
            return None
        try:
            fd = open_dir(root, name, stats)
        finally:
            os.close(root)
        if fd is None:
            raise LootError("workspace_not_found", f"Workspace {name} does not exist.")
        return fd


def _open_path_dir(workspace_dir: str) -> int | None:
    try:
        return os.open(workspace_dir, DIR_FLAGS)
    except OSError:
        return None


def workspace_names(workspace_dir: str) -> list[str]:
    """Names of real (non-symlink) directories in ``workspace_dir`` (sorted)."""
    fd = _open_path_dir(workspace_dir)
    if fd is None:
        return []
    try:
        return [e.name for e in list_dir(fd) if e.kind == "dir"]
    finally:
        os.close(fd)


def workspace_path(workspace_dir: str, name: str) -> str:
    """Resolve ``<workspace_dir>/<name>``: a real directory directly inside the base.

    Raises ``LootError`` with ``invalid_workspace`` (E.3 grammar) or
    ``workspace_not_found`` (missing, a symbolic link, or not a directory).
    """
    if not targets.is_valid_workspace(name):
        raise LootError("invalid_workspace", "Invalid workspace name.")
    base = _open_path_dir(workspace_dir)
    if base is None:
        raise LootError("workspace_not_found", f"Workspace {name} does not exist.")
    try:
        fd = open_dir(base, name)
    finally:
        os.close(base)
    if fd is None:
        raise LootError("workspace_not_found", f"Workspace {name} does not exist.")
    os.close(fd)
    return os.path.join(os.path.realpath(workspace_dir), name)
