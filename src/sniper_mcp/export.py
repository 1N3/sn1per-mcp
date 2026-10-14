# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Native tar.gz export of one workspace (contract I.4) and the bounded walk behind the
confirmation message (I.2).

The loot tree is attacker-influenced, so the archive is built only from descriptors
opened below the validated workspace descriptor with ``O_NOFOLLOW`` (J.1): a link
swapped in during the export can neither redirect a read nor add a member.

- Regular files and directories only. Symbolic links, files with more than one hard
  link, FIFOs, sockets and devices are skipped and counted; so are entries that
  cannot be opened.
- Unless ``include_credentials``: every ``credentials/`` and ``bloodhound/``
  directory and the J.2 credential-file denylist are left out (counted).
- Members are ``<workspace>/<relative path>``, pax format, gzip level 6, with
  normalized metadata (files ``0600``, directories ``0700``, uid and gid 0, empty
  owner names) and the original mtime.
- At most 4 GiB of file data and 200,000 members; the partial archive is removed on
  any failure.

The Sn1per CLI ``--export`` path is never used (I.4 step 7).
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import tarfile
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from sniper_mcp import lootfs

EXPORT_MAX_BYTES = 4 * 1024 ** 3
EXPORT_MAX_MEMBERS = 200_000
SUMMARY_MAX_ENTRIES = 200_000  # I.2: stop counting and show "200000+"
GZIP_LEVEL = 6
FILE_MODE = 0o600
DIR_MODE = 0o700
_CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_CHUNK = 1024 * 1024


class ExportTooLarge(Exception):
    """Over 4 GiB of data or 200,000 members (``export_too_large``)."""


class ExportFailed(Exception):
    """An I/O failure while writing the archive (``export_failed``)."""


class ArchiveExists(ExportFailed):
    """The archive name is taken (two exports of one workspace in the same second)."""


# --- what is skipped ------------------------------------------------------------------------

@dataclass
class Skipped:
    """The ``skipped`` object of the ``export_workspace`` payload (H.16)."""

    symlinks: int = 0
    hardlinks: int = 0
    special_files: int = 0
    unreadable: int = 0
    credentials_excluded: int = 0
    denylisted_excluded: int = 0

    def to_json(self) -> dict[str, int]:
        return {"symlinks": self.symlinks, "hardlinks": self.hardlinks,
                "special_files": self.special_files, "unreadable": self.unreadable,
                "credentials_excluded": self.credentials_excluded,
                "denylisted_excluded": self.denylisted_excluded}


@dataclass
class _Node:
    """One entry met by :func:`_walk`. ``fd`` is an open descriptor of the entry (the
    caller must not close it), valid during the yield; ``st`` its ``fstat``."""

    components: tuple[str, ...]
    kind: str  # "dir" or "file"
    fd: int
    st: os.stat_result


@dataclass
class _Budget:
    """Directory entries looked at, for the I.2 summary cap."""

    limit: int | None
    seen: int = 0

    def take(self) -> bool:
        self.seen += 1
        return self.limit is None or self.seen <= self.limit


def _count_files(dir_fd: int, budget: _Budget, depth: int) -> int:
    """Regular files below ``dir_fd`` (an excluded subtree); nothing is read."""
    count = 0
    for entry in lootfs.list_dir(dir_fd):
        if not budget.take():
            return count
        if entry.kind == "file":
            count += 1
        elif entry.kind == "dir" and depth < lootfs.WALK_MAX_DEPTH:
            child = lootfs.open_dir(dir_fd, entry.name)
            if child is None:
                continue
            try:
                count += _count_files(child, budget, depth + 1)
            finally:
                os.close(child)
    return count


def _walk(dir_fd: int, skipped: Skipped, budget: _Budget, *, include_credentials: bool,
          prefix: tuple[str, ...] = (), depth: int = 0) -> Iterator[_Node]:
    """Depth-first, sorted, never following a link; yields directories before their
    contents. Stops quietly once the budget is spent (summaries only)."""
    for entry in lootfs.list_dir(dir_fd):
        if not budget.take():
            return
        name = entry.name
        if entry.kind == "symlink":
            skipped.symlinks += 1
            continue
        if entry.kind == "other":
            skipped.special_files += 1
            continue
        if entry.kind == "dir":
            excluded = not include_credentials and lootfs.is_excluded_dir(name)
            if depth + 1 > lootfs.WALK_MAX_DEPTH:
                skipped.unreadable += 1
                continue
            child = _open(dir_fd, name, lootfs.DIR_FLAGS, skipped)
            if child is None:
                continue
            try:
                if excluded:
                    files = _count_files(child, budget, depth + 1)
                    if name.lower() == "credentials":
                        skipped.credentials_excluded += files
                    else:
                        skipped.denylisted_excluded += files
                    continue
                st = os.fstat(child)
                yield _Node(components=(*prefix, name), kind="dir", fd=child, st=st)
                yield from _walk(child, skipped, budget, include_credentials=include_credentials,
                                 prefix=(*prefix, name), depth=depth + 1)
            except OSError:
                skipped.unreadable += 1
            finally:
                os.close(child)
            continue
        if not include_credentials and lootfs.is_excluded_file(name):
            skipped.denylisted_excluded += 1
            continue
        fd = _open(dir_fd, name, lootfs.FILE_FLAGS, skipped)
        if fd is None:
            continue
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                skipped.special_files += 1
                continue
            if st.st_nlink > 1:
                skipped.hardlinks += 1
                continue
            yield _Node(components=(*prefix, name), kind="file", fd=fd, st=st)
        except OSError:
            skipped.unreadable += 1
        finally:
            os.close(fd)


def _open(dir_fd: int, name: str, flags: int, skipped: Skipped) -> int | None:
    """Open ``name`` below ``dir_fd`` without following a link. A link or a vanished
    entry is skipped quietly; a permission or other I/O error counts as unreadable."""
    if not lootfs.component_ok(name):
        skipped.unreadable += 1
        return None
    try:
        return os.open(name, flags, dir_fd=dir_fd)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as exc:
        if exc.errno == errno.ELOOP:  # replaced by a link after the listing
            skipped.symlinks += 1
        else:
            skipped.unreadable += 1
        return None


# --- the I.2 summary ------------------------------------------------------------------------

@dataclass(frozen=True)
class Summary:
    """Files and bytes of a workspace for the confirmation message (I.2)."""

    files: int
    bytes: int
    capped: bool

    def files_text(self) -> str:
        """``1 file``, ``<n> files`` or ``200000+ files`` (I.2)."""
        if self.capped:
            return f"{SUMMARY_MAX_ENTRIES}+ files"
        return "1 file" if self.files == 1 else f"{self.files} files"

    def size_text(self) -> str:
        """I.2 marks only ``<files>`` as capped ("200000+"); the size stays a plain
        number (the bytes counted so far)."""
        return format_size(self.bytes)


def format_size(size: int) -> str:
    """Bytes below 1 KiB, else KiB, MiB or GiB with one decimal (I.2)."""
    if size < 1024:
        return f"{size} B"
    if size < 1024 ** 2:
        return f"{size / 1024:.1f} KiB"
    if size < 1024 ** 3:
        return f"{size / 1024 ** 2:.1f} MiB"
    return f"{size / 1024 ** 3:.1f} GiB"


def summarize(ws_fd: int, *, include_credentials: bool | None) -> Summary:
    """Count a workspace with a bounded walk (at most 200,000 entries).

    ``include_credentials=None`` counts every regular file (the delete removes them
    all); a boolean counts what an export with that switch would archive.
    """
    budget = _Budget(limit=SUMMARY_MAX_ENTRIES)
    if include_credentials is None:
        return _summarize_all(ws_fd, budget)
    skipped = Skipped()
    files = size = 0
    for node in _walk(ws_fd, skipped, budget, include_credentials=include_credentials):
        if node.kind == "file":
            files += 1
            size += node.st.st_size
    return Summary(files=files, bytes=size, capped=budget.seen > SUMMARY_MAX_ENTRIES)


def _summarize_all(ws_fd: int, budget: _Budget) -> Summary:
    files = size = 0
    pending: list[tuple[int, int]] = [(os.dup(ws_fd), 0)]
    try:
        while pending:
            dir_fd, depth = pending.pop()
            try:
                for entry in lootfs.list_dir(dir_fd):
                    if not budget.take():
                        return Summary(files=files, bytes=size, capped=True)
                    if entry.kind == "file":
                        try:
                            st = os.stat(entry.name, dir_fd=dir_fd, follow_symlinks=False)
                        except OSError:
                            continue
                        files += 1
                        size += st.st_size
                    elif entry.kind == "dir" and depth < lootfs.WALK_MAX_DEPTH:
                        child = lootfs.open_dir(dir_fd, entry.name)
                        if child is not None:
                            pending.append((child, depth + 1))
            finally:
                os.close(dir_fd)
    finally:
        for dir_fd, _ in pending:
            os.close(dir_fd)
    return Summary(files=files, bytes=size, capped=False)


# --- the archive ---------------------------------------------------------------------------

@dataclass
class ExportResult:
    """What ``export_workspace`` reports about a finished archive (H.16)."""

    name: str
    bytes: int
    sha256: str
    files: int
    directories: int
    skipped: Skipped = field(default_factory=Skipped)


class _HashingWriter:
    """A write-only file object over a descriptor that hashes and counts every byte."""

    def __init__(self, fd: int) -> None:
        self.fd = fd
        self.size = 0
        self._hash = hashlib.sha256()

    def write(self, data: Any) -> int:
        view = memoryview(data).cast("B")
        total = len(view)
        while view:
            written = os.write(self.fd, view)
            self._hash.update(view[:written])
            view = view[written:]
        self.size += total
        return total

    def flush(self) -> None:
        return None

    def hexdigest(self) -> str:
        return self._hash.hexdigest()


class _ExactReader:
    """Reads exactly ``size`` bytes from ``fd`` (the size the tar header declared).

    ``tarfile`` treats any short read as a fatal "unexpected end of data", so every
    ``read(n)`` returns exactly ``min(n, remaining)`` bytes: a file that grows during
    the export is cut at the declared size, and one that shrinks is padded with zero
    bytes, so the archive stays well-formed either way.
    """

    def __init__(self, fd: int, size: int) -> None:
        self.fd = fd
        self.remaining = size

    def read(self, n: int = -1) -> bytes:
        if self.remaining <= 0:
            return b""
        want = self.remaining if n is None or n < 0 else min(n, self.remaining)
        chunks: list[bytes] = []
        got = 0
        while got < want:
            data = os.read(self.fd, min(want - got, _READ_CHUNK))
            if not data:
                chunks.append(b"\x00" * (want - got))
                got = want
                break
            chunks.append(data)
            got += len(data)
        self.remaining -= want
        return b"".join(chunks)


def _member(name: str, kind: str, st: os.stat_result) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    if kind == "dir":
        info.type = tarfile.DIRTYPE
        info.mode = DIR_MODE
        info.size = 0
    else:
        info.type = tarfile.REGTYPE
        info.mode = FILE_MODE
        info.size = st.st_size
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = st.st_mtime
    return info


def archive_name(workspace: str, epoch: float) -> str:
    """``<workspace>-<YYYYmmddTHHMMSSZ>.tar.gz`` (I.4 step 2)."""
    return f"{workspace}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(epoch))}.tar.gz"


def write_archive(ws_fd: int, workspace: str, exports_fd: int, name: str, *,
                  include_credentials: bool) -> ExportResult:
    """Write the archive ``name`` in the directory open at ``exports_fd`` (I.4 steps 2-5).

    Raises ``ExportTooLarge`` or ``ExportFailed`` (the partial file is removed first), or
    ``ArchiveExists`` when ``name`` is taken (nothing was written).
    """
    try:
        out_fd = os.open(name, _CREATE_FLAGS, 0o600, dir_fd=exports_fd)
    except FileExistsError as exc:
        raise ArchiveExists(name) from exc
    except OSError as exc:
        raise ExportFailed(f"cannot create the archive ({exc.strerror})") from exc
    writer = _HashingWriter(out_fd)
    skipped = Skipped()
    files = directories = 0
    try:
        os.fchmod(out_fd, 0o600)
        root_st = os.fstat(ws_fd)
        data_bytes = 0
        members = 0
        with tarfile.open(fileobj=writer, mode="w:gz", compresslevel=GZIP_LEVEL,  # type: ignore[call-overload]
                          format=tarfile.PAX_FORMAT) as tar:
            tar.addfile(_member(workspace, "dir", root_st))
            members = directories = 1
            for node in _walk(ws_fd, skipped, _Budget(limit=None),
                              include_credentials=include_credentials):
                members += 1
                if members > EXPORT_MAX_MEMBERS:
                    raise ExportTooLarge(f"more than {EXPORT_MAX_MEMBERS} entries")
                member_name = "/".join((workspace, *node.components))
                if node.kind == "dir":
                    tar.addfile(_member(member_name, "dir", node.st))
                    directories += 1
                    continue
                data_bytes += node.st.st_size
                if data_bytes > EXPORT_MAX_BYTES:
                    raise ExportTooLarge("more than 4 GiB of file data")
                tar.addfile(_member(member_name, "file", node.st),
                            _ExactReader(node.fd, node.st.st_size))
                files += 1
        os.fsync(out_fd)
    except ExportTooLarge:
        _discard(out_fd, exports_fd, name)
        raise
    except Exception as exc:  # noqa: BLE001 - every failure removes the partial archive
        _discard(out_fd, exports_fd, name)
        raise ExportFailed(f"writing the archive failed ({type(exc).__name__})") from exc
    os.close(out_fd)
    return ExportResult(name=name, bytes=writer.size, sha256=writer.hexdigest(), files=files,
                        directories=directories, skipped=skipped)


def _discard(out_fd: int, exports_fd: int, name: str) -> None:
    try:
        os.close(out_fd)
    except OSError:
        pass
    try:
        os.unlink(name, dir_fd=exports_fd)
    except OSError:
        pass
