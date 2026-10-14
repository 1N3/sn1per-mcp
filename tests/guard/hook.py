# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Layer 1 of the test isolation guard: an interpreter audit hook (contract O.2).

``sys.addaudithook`` hooks cannot be removed, so no fixture override or
``monkeypatch`` can switch this off, and the hook also sees calls made through
stale bindings (``from subprocess import Popen``), because CPython raises the
``subprocess.Popen`` audit event inside ``Popen._execute_child`` before it forks.

Two process-creation paths raise no audit event at all: a direct call of
``_posixsubprocess.fork_exec`` (which ``multiprocessing`` uses for its spawn and
forkserver start methods) and ``multiprocessing.Process.start``. ``install``
replaces both with wrappers: ``fork_exec`` runs only as the immediate follow-up
of an approved ``subprocess.Popen`` with the same argv, cwd and environment
(any other audit event in the thread first clears the approval), and
``Process.start`` always raises. ``os.posix_spawn`` is never allowed: ``install``
turns off ``subprocess``'s use of it, so every approved ``Popen`` starts its child
through the ``fork_exec`` wrapper. ``os.posix_spawn`` converts its arguments in C
before its audit event, from objects whose methods a test can replace (the
``keys()`` and ``values()`` of ``os.environ``), so nothing there could be judged.

The child changes to ``cwd`` before it runs anything, so every path is judged as
the child will see it: relative and empty PATH entries and ``preexec_fn`` are
refused, the approved executable is run by its absolute path, and an
executable, PATH entry, argument or ``cwd`` whose resolution passes the ``cwd``
or ``root`` link, or the ``fd/0``, ``fd/1`` or ``fd/2`` link, of a process under
the proc root (``self/cwd``, also through a symbolic link) is refused, because
that link names this process's directory or descriptor here and the child's
there (the child's standard descriptors are the redirected ones). Paths are
never normalized before they are resolved: the kernel applies ``..`` to the
target of the link before it, so ``/proc/self/cwd/..`` and ``<link>/..`` are
walked as written, by the Popen rules and by the file rules (the parent of a
name that a remove, rename or mkdir changes). The first ``PYTHONPATH`` entry of a
Python child is judged in the spelling the child uses (absolute and normalized),
and ``PYTHONHOME`` is refused.

The guard judges exactly the values the child receives, converted once. ``env``
must be a plain ``dict`` (or ``os.environ`` itself) whose keys and values are
``str`` or ``bytes``; it is encoded once into the list of names and values that
``subprocess`` gives the child, a name that occurs twice after encoding (a
``str`` and a ``bytes`` key) is refused, and ``PATH``, ``PYTHONPATH``,
``PYTHONHOME`` and ``SN1PER_MCP_TEST_GUARD`` are read from that list. With
``env=None`` the list is read from ``os.environ``, and the child gets it
explicitly instead of inheriting the process environment, which ``os.putenv``
can change without ``os.environ``. Argv elements, the executable and ``cwd`` must
be exactly ``str`` or ``bytes``, or a standard ``pathlib`` path whose string is
exactly ``str``; each is converted once with the file-system codec, and the
``fork_exec`` wrapper passes the judged bytes (argv, the one approved
executable, the start directory, environment) to the real ``fork_exec``. The
start directory is the absolute directory every relative path was judged
against (this process's directory for ``cwd=None``, joined with a relative
``cwd``), read once by the check, so the child never starts in a directory that
another thread chose after the check. The file rules judge exact ``str`` and
``bytes``, which is what the ``os`` functions and the builtin ``open()`` pass to
their events; a ``shutil`` event may also carry a standard ``pathlib`` path (the
calls that follow it raise their own events with the converted path); a
descriptor is an exact ``int`` (or ``bool``), because ``io.FileIO`` takes an
``int`` subclass that does not fit a C int as a path and converts it with its
``__fspath__``; any other path type is refused, including any path object in an
``open`` event (``io.FileIO`` converts it in C before it raises the event).

The hook and the wrappers decide only from values captured at install time,
before any test module is imported: C functions (``os.lstat``, ``os.stat``,
``os.readlink``, ``os.access``, ``os.getcwd``, ``os.fspath`` and the like), the
builtins, this module's tables, the file-system codec and a private JSON
scanner. Their path helpers (``realpath``, ``join``, ``split``, ``normpath``,
the PATH search, ``lexists``, ``isfile``) are implemented in ``install`` on
those primitives, so replacing ``os.fspath``, ``os.lstat``, an ``os.path`` or
``shutil`` function, ``json.loads``, a builtin or an attribute of this module
afterwards changes nothing in how the hook judges a value (a meta-test checks
that the hook's code looks up no global name). The same holds for the readers of
the child violation files, built when this module is imported. A socket's family
is read from its C object, never through a property a subclass can override, and
an argument's type is read with ``type``, never through its ``__class__``. Code
of a caller's object that the hook runs while it judges a call (the methods of
``os.environ``, the conversion of a ``pathlib`` path) is judged like any other
code, and an audit hook added after the guard is refused (it would run after the
guard for every event and could change what the guard judged, such as the
working directory or a link, before the call acts): the hook skips only the one
event of each of its own ``/proc`` reads and violation-file writes, matched by
name and path (so not an event that a hook installed before it raises
meanwhile), and it never calls the ``repr()`` or ``str()`` of a caller's object
to describe a call. A guarded child opens its violation file relative to a
descriptor of its temp root taken at install, without following a link at the
name and without blocking on a FIFO, and writes to it only when it is a regular
file of this user with one link (otherwise the line goes to stderr); a parent
reports every entry of that name that a child cannot have written to as a
violation of its own.

Every violation is recorded in a private ledger that ``tests/conftest.py`` checks
at the end of each test and of the session; the public ``violations`` list is a
diagnostic copy, so clearing it or flipping ``consumed`` on an entry hides
nothing. Outside this model: code that takes the guard itself apart (the
wrappers' closure cells, the ledger reached through ``gc``, a second instance of
``_posixsubprocess`` or ``ctypes``, or this module's classes and functions
changed in place). The meta-tests keep those spellings (``_posixsubprocess``,
``ctypes``, ``_imp``, ``gc``, closure cells, function globals and code objects)
out of every test file except ``tests/test_guard.py``. Also outside, because an
audit hook sees a call only at its event and cannot hold the file system still
until the kernel or the child acts: changes made meanwhile by code that runs
concurrently with the call. That is another thread (a link re-pointed or the
working directory changed between an event and its system call, or after an
approved ``Popen``), a signal handler that runs while an interrupted system call
is retried (an open that waits for a FIFO peer or a lease break, which resolves
the path again), and whatever this process does after an approved ``Popen`` has
returned and before the child uses its arguments. Within that limit the guard
closes the windows in which code runs synchronously, in the calling thread,
between a judgment and its use: audit hooks added after it are refused, any
other event in the thread clears an approval before its ``fork_exec``, and the
child starts in the judged directory.

There is deliberately no switch here that enables real execution, real
network access or real loot (O.7). ``SN1PER_MCP_TEST_GUARD`` only restricts:
a parent refuses to forward a value that names roots other than its own, and a
child goes strict on a value whose roots are implausible. Allowances needed by
a dependency at import time (none is known) would go here, each with a comment
naming the dependency.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import pathlib
import socket
import stat
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

ENV_VAR = "SN1PER_MCP_TEST_GUARD"
STATE_ATTR = "_sn1per_mcp_test_guard_state"
CHILD_VIOLATIONS_FILE = "guard-child-violations.jsonl"
ISOLATION_FIXTURE_NAME = "_sn1per_isolation"
GUARD_DIR = Path(__file__).resolve().parent

_ALWAYS_BLOCKED_EVENTS = {
    "os.system": "os.system",
    "os.exec": "os.exec*",
    "os.posix_spawn": "os.posix_spawn",
    "os.spawn": "os.spawn*",
    "os.fork": "os.fork",
    "os.forkpty": "os.forkpty",
    "ctypes.dlopen": "ctypes.dlopen",
}
_DNS_EVENTS = (
    "socket.getaddrinfo",
    "socket.gethostbyname",
    "socket.gethostbyname_ex",
    "socket.gethostbyaddr",
    "socket.getnameinfo",
)
_SOCKET_SEND_EVENTS = ("socket.connect", "socket.sendto", "socket.sendmsg")
_LISTING_EVENTS = ("os.listdir", "os.scandir")
_KILL_EVENTS = ("os.kill", "os.killpg")
# Mutation events: (path argument index, follow a symlink in the final
# component, index of the matching dir_fd argument or None). Operations on a
# link itself (remove, rename, symlink, rmdir) resolve only the parent
# directory, so removing a temp-root symlink that points at a real file is not
# mistaken for a change to that file. A relative path with a dir_fd cannot be
# resolved here; the descriptor came from an ``open`` this hook checked.
# CPython reports a missing dir_fd as -1.
_MUTATION_EVENTS: dict[str, tuple[tuple[int, bool, int | None], ...]] = {
    "os.remove": ((0, False, 1),),
    "os.rmdir": ((0, False, 1),),
    "os.rename": ((0, False, 2), (1, False, 3)),
    "os.link": ((0, True, 2), (1, False, 3)),
    "os.symlink": ((1, False, 2),),
    "os.mkdir": ((0, False, 2),),
    "os.chmod": ((0, True, 2),),
    "os.chown": ((0, True, 3),),
    "os.chflags": ((0, True, None),),
    "os.truncate": ((0, True, None),),
    "os.utime": ((0, True, 3),),
    "os.setxattr": ((0, True, None),),
    "os.removexattr": ((0, True, None),),
    "shutil.rmtree": ((0, False, 1),),
    "shutil.move": ((0, False, None), (1, False, None)),
    "shutil.chown": ((0, True, None),),
}
_PYTHON_FORBIDDEN_FLAGS = frozenset("ISE")
_PYTHON_FLAGS_WITH_ARGUMENT = frozenset("WX")
_PYTHON_FLAGS_ENDING_OPTIONS = frozenset("cm")
_PYTHON_LONG_OPTIONS = frozenset({"--help", "--version", "--help-env", "--help-xoptions",
                                  "--help-all"})
_PYTHON_LONG_OPTIONS_WITH_ARGUMENT = frozenset({"--check-hash-based-pycs"})
# The only path objects the guard converts besides exact str and bytes (exact types, never
# subclasses), and only when their string is an exact str: the guard converts it once and
# passes the bytes on (fork_exec), or the calls that follow the event raise their own events
# with the converted path (shutil). Any other path-like object, and any str or bytes
# subclass, may answer differently each time it is converted, and CPython converts argv,
# cwd and file names again in C.
_PATHLIB_TYPES = (pathlib.PurePath, pathlib.PurePosixPath, pathlib.Path, pathlib.PosixPath)


def _load_realpaths():
    """Load tests/realpaths.py by file path (works in guarded child processes too)."""
    spec = importlib.util.spec_from_file_location(
        "_sn1per_mcp_guard_realpaths", GUARD_DIR.parent / "realpaths.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GuardViolation(RuntimeError):
    """Base class of every guard trip."""


class RealExecutionBlocked(GuardViolation):
    """A real process creation, or access to a real Sn1per or home file."""


class NetworkBlocked(GuardViolation):
    """A network connection or a DNS lookup."""


@dataclass
class Violation:
    """One recorded guard trip."""

    kind: str
    event: str
    detail: str
    consumed: bool = False

    def describe(self) -> str:
        return f"{self.kind}: {self.event}: {self.detail}"


def _no_violations() -> list[Violation]:
    return []


def _zero() -> int:
    return 0


def _since_nothing(start: int) -> list[Violation]:
    return []


def _consume_nothing(violation: Violation) -> None:
    return None


@dataclass
class GuardState:
    """Shared by every copy of this module in one interpreter (stored on ``sys``).

    ``violations`` is a public copy for diagnostics. The authoritative ledger
    lives in the hook's closure and is reached through the callables below,
    which ``tests/conftest.py`` and ``tests/guard/expect.py`` capture once.
    """

    mode: str
    temp_root: str | None
    repo_root: str | None
    violations: list[Violation] = field(default_factory=list)
    classes: dict[str, type] = field(default_factory=dict)
    child_file: str | None = None
    protected_roots: tuple[str, ...] = ()
    exempt_roots: tuple[str, ...] = ()
    recorded_count: Callable[[], int] = _zero
    recorded_since: Callable[[int], list[Violation]] = _since_nothing
    consume: Callable[[Violation], None] = _consume_nothing
    unconsumed_ledger: Callable[[], list[Violation]] = _no_violations

    def unconsumed(self) -> list[Violation]:
        return self.unconsumed_ledger()


# Reuse the classes of an already installed copy, so `except RealExecutionBlocked`
# works whichever copy of this module raised it.
_existing = getattr(sys, STATE_ATTR, None)
if _existing is not None:
    GuardViolation = _existing.classes["GuardViolation"]  # type: ignore[misc]
    RealExecutionBlocked = _existing.classes["RealExecutionBlocked"]  # type: ignore[misc]
    NetworkBlocked = _existing.classes["NetworkBlocked"]  # type: ignore[misc]


def state() -> GuardState | None:
    """The installed guard state, or None."""
    return getattr(sys, STATE_ATTR, None)


def is_installed() -> bool:
    return state() is not None


def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def _passwd_home() -> str | None:
    try:
        import pwd

        home = pwd.getpwuid(os.getuid()).pw_dir
    except (ImportError, KeyError):
        return None
    if not home or not os.path.isabs(home) or os.path.realpath(home) == "/":
        return None
    return os.path.realpath(home)


def _protected_roots(realpaths, temp_root: str | None = None) -> list[str]:
    """The real Sn1per trees, root's home and the home directories of this user.

    ``$HOME`` is skipped when it lies strictly inside ``temp_root``: a guarded
    child runs with the test's fake home, which is not the developer's. The
    passwd home is never skipped.
    """
    roots = [os.path.realpath(p) for p in realpaths.PROTECTED_ROOTS]
    passwd_home = _passwd_home()
    if passwd_home:
        roots.append(passwd_home)
    env_home = os.environ.get("HOME", "")
    if env_home and os.path.isabs(env_home):
        real = os.path.realpath(env_home)
        fake = bool(temp_root) and real != temp_root and _within(real, temp_root or "")
        if real != "/" and not fake:
            roots.append(real)
    return sorted(set(roots))


def validated_roots(data: object) -> tuple[str, str] | None:
    """The (temp_root, repo_root) of a decoded ``SN1PER_MCP_TEST_GUARD``, or None.

    None means the value is implausible and the child must go strict: not a
    two-key object of absolute paths; a root that is ``/``, missing, or equal to
    or above a standard system directory or a protected root; a temp root
    equal to or above the repository or an interpreter prefix, inside a system
    tree, an interpreter prefix or a protected root, or not an unshared
    directory of this user.
    """
    if not isinstance(data, dict) or set(data) != {"temp_root", "repo_root"}:
        return None
    raw_temp, raw_repo = data["temp_root"], data["repo_root"]
    if not isinstance(raw_temp, str) or not isinstance(raw_repo, str):
        return None
    if "\x00" in raw_temp + raw_repo or not (os.path.isabs(raw_temp) and os.path.isabs(raw_repo)):
        return None
    temp = os.path.realpath(raw_temp)
    repo = os.path.realpath(raw_repo)
    if temp == "/" or repo == "/":
        return None
    realpaths = _load_realpaths()
    protected = _protected_roots(realpaths, temp)
    for root in (temp, repo):
        if any(_within(item, root) for item in (*realpaths.SYSTEM_DIRS, *protected)):
            return None
        if not os.path.isdir(root):
            return None
    prefixes = {os.path.realpath(p) for p in (sys.prefix, sys.base_prefix, sys.exec_prefix)}
    if any(_within(item, temp) for item in (*prefixes, repo)):
        return None
    # Child mode exempts its temp root from the open rule, so a temp root inside a
    # protected root (for example ~/.ssh) would widen strict mode (O.7).
    if any(_within(temp, root) for root in protected):
        return None
    if any(_within(temp, tree) for tree in (*realpaths.SYSTEM_TREES, *prefixes)):
        return None
    try:
        st = os.stat(temp)
    except OSError:
        return None
    if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o022:
        return None
    return temp, repo


def install(*, temp_root: str | None, repo_root: str | None, mode: str) -> GuardState:
    """Install the audit hook once per interpreter and return the shared state.

    ``mode`` is ``pytest`` (the test session), ``child`` (a guarded child with
    a valid ``SN1PER_MCP_TEST_GUARD``) or ``strict`` (a child without it: every
    process creation and network call is blocked).
    """
    existing = state()
    if existing is not None:
        return existing

    # Imported before the hook exists, so the wrappers below can replace them.
    import _posixsubprocess
    import _socket
    import builtins
    import json.decoder
    import json.encoder
    import multiprocessing.process
    import subprocess

    # --- everything the hook decides from, captured now ------------------------
    # The builtins are names of this scope from here on, so the hook and the wrappers
    # never look them up in builtins (or in this module's globals) when they run; the
    # meta-test test_guard_code_looks_up_no_global_name checks that for every function
    # below.
    (type, len, any, all, list, tuple, set, frozenset, dict, str, bytes, int, bool, float,
     getattr, callable, sorted, repr, id, range, object) = (
        builtins.type, builtins.len, builtins.any, builtins.all, builtins.list,
        builtins.tuple, builtins.set, builtins.frozenset, builtins.dict, builtins.str,
        builtins.bytes, builtins.int, builtins.bool, builtins.float, builtins.getattr,
        builtins.callable, builtins.sorted, builtins.repr, builtins.id, builtins.range,
        builtins.object)
    Exception, OSError, ValueError = builtins.Exception, builtins.OSError, builtins.ValueError
    # C functions and values, never the Python-level helpers built on them
    # (os.fsencode, os.path.*, shutil.which, json.loads), which look up os.fspath,
    # os.lstat and the rest at call time.
    os_fspath = os.fspath
    lstat = os.lstat
    stat_path = os.stat
    readlink = os.readlink
    access = os.access
    getcwd = os.getcwd
    getpid = os.getpid
    getpgrp = os.getpgrp
    listdir = os.listdir
    os_open = os.open
    os_write = os.write
    os_close = os.close
    fstat = os.fstat
    euid = os.geteuid()
    io_open = io.open
    environ = os.environ
    x_ok = os.X_OK
    # The violation file is never reached through a link at its name, never blocks on a
    # FIFO planted there, and never becomes a controlling terminal (record()).
    child_file_flags = (os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
                        | os.O_NOCTTY | os.O_CLOEXEC)
    pathsep = os.pathsep
    fs_encoding = sys.getfilesystemencoding()
    fs_errors = sys.getfilesystemencodeerrors()
    str_encode = str.encode
    bytes_decode = bytes.decode
    str_copy = str.__str__  # an exact str with the characters of a str subclass
    type_name = type.__dict__["__name__"].__get__  # never a metaclass's __name__
    object_new = object.__new__
    object_setattr = object.__setattr__
    socket_family = _socket.socket.__dict__["family"].__get__  # the C field, never a property
    af_unix = socket.AF_UNIX
    json_scan = json.decoder.JSONDecoder().scan_once  # a private C scanner
    json_string = json.encoder.encode_basestring_ascii
    s_ifmt, s_iflnk, s_ifreg, s_ifdir = 0o170000, 0o120000, 0o100000, 0o040000
    pure_path, pure_posix_path, path_type, posix_path = _PATHLIB_TYPES
    # This module's tables and classes, copied (rebinding or mutating the module
    # attributes later changes nothing here).
    always_blocked = dict(_ALWAYS_BLOCKED_EVENTS)
    dns_events = frozenset(_DNS_EVENTS)
    socket_send_events = frozenset(_SOCKET_SEND_EVENTS)
    listing_events = frozenset(_LISTING_EVENTS)
    kill_events = frozenset(_KILL_EVENTS)
    mutation_events = {name: tuple(rules) for name, rules in _MUTATION_EVENTS.items()}
    python_forbidden_flags = frozenset(_PYTHON_FORBIDDEN_FLAGS)
    python_flags_with_argument = frozenset(_PYTHON_FLAGS_WITH_ARGUMENT)
    python_flags_ending_options = frozenset(_PYTHON_FLAGS_ENDING_OPTIONS)
    python_long_options = frozenset(_PYTHON_LONG_OPTIONS)
    python_long_options_with_argument = frozenset(_PYTHON_LONG_OPTIONS_WITH_ARGUMENT)
    env_var = ENV_VAR
    violation_base = GuardViolation
    exc_exec = RealExecutionBlocked
    exc_net = NetworkBlocked
    violation_cls = Violation
    local = threading.local()

    # --- path helpers on exact str, from the primitives above --------------------
    def isabs(path: str) -> bool:
        return path.startswith("/")

    def join(path: str, *parts: str) -> str:
        """``posixpath.join``."""
        for part in parts:
            if part.startswith("/"):
                path = part
            elif not path or path.endswith("/"):
                path = path + part
            else:
                path = path + "/" + part
        return path

    def split(path: str) -> tuple[str, str]:
        """``posixpath.split``."""
        index = path.rfind("/") + 1
        head, tail = path[:index], path[index:]
        if head and head != "/" * len(head):
            head = head.rstrip("/")
        return head, tail

    def normpath(path: str) -> str:
        """``posixpath.normpath`` (lexical: only for the text forms of the always-blocked
        rules and the spelling of PYTHONPATH, never before a path is resolved)."""
        if not path:
            return "."
        initial = ""
        if path.startswith("/"):
            initial = "//" if path.startswith("//") and not path.startswith("///") else "/"
        parts: list[str] = []
        for part in path.split("/"):
            if part == "" or part == ".":
                continue
            if part != ".." or (not initial and not parts) or (parts and parts[-1] == ".."):
                parts.append(part)
            elif parts:
                parts.pop()
        return (initial + "/".join(parts)) or "."

    def file_mode(path: str, follow: bool) -> int | None:
        try:
            return (stat_path(path) if follow else lstat(path)).st_mode
        except (OSError, ValueError):
            return None

    def lexists(path: str) -> bool:
        return file_mode(path, False) is not None

    def isfile(path: str) -> bool:
        mode = file_mode(path, True)
        return mode is not None and (mode & s_ifmt) == s_ifreg

    def realpath(path: str) -> str:
        """``os.path.realpath`` (not strict): symbolic links are followed component by
        component, ``..`` applies to what has been resolved so far, and a missing
        component or a link loop is kept as written."""
        rest: list[str | None] = path.split("/")[::-1]
        count = len(rest)
        current = "/" if path.startswith("/") else getcwd()
        seen: dict[str, str | None] = {}
        while count:
            name = rest.pop()
            if name is None:  # the target of the link below it is resolved
                seen[rest.pop()] = current
                continue
            count -= 1
            if name == "" or name == ".":
                continue
            if name == "..":
                current = current[:current.rindex("/")] or "/"
                continue
            candidate = current + name if current == "/" else current + "/" + name
            mode = file_mode(candidate, False)
            if mode is None or (mode & s_ifmt) != s_iflnk:
                current = candidate
                continue
            if candidate in seen:
                resolved = seen[candidate]
                current = candidate if resolved is None else resolved
                continue
            try:
                target = readlink(candidate)
            except (OSError, ValueError):
                current = candidate
                continue
            if target.startswith("/"):
                current = "/"
            seen[candidate] = None
            rest.append(candidate)
            rest.append(None)
            parts = target.split("/")[::-1]
            rest.extend(parts)
            count += len(parts)
        return current

    def which(command: str, search: str) -> str | None:
        """``shutil.which`` for a name without a slash (the entries are absolute here)."""
        if not search:
            return None
        seen: set[str] = set()
        for directory in search.split(pathsep):
            if directory in seen:
                continue
            seen.add(directory)
            name = join(directory, command)
            mode = file_mode(name, True)
            if mode is not None and (mode & s_ifmt) != s_ifdir and access(name, x_ok):
                return name
        return None

    def within(path: str, root: str) -> bool:
        return path == root or path.startswith(root.rstrip("/") + "/")

    def within_any(path: str, roots) -> bool:
        return any(within(path, root) for root in roots)

    # --- conversions -------------------------------------------------------------
    def is_pathlib(kind) -> bool:
        return (kind is pure_path or kind is pure_posix_path or kind is path_type
                or kind is posix_path)

    def exact_bytes(value) -> bytes | None:
        """``value`` converted once, the way CPython's C code converts it, or None.

        Exact ``bytes`` are used as they are and an exact ``str`` is encoded with the
        file-system codec. A standard ``pathlib`` path is converted through its
        ``__fspath__`` and accepted only when that gives an exact ``str`` (a ``str``
        subclass in its cached string could encode one way here and another in C).
        Anything else, including any ``str`` or ``bytes`` subclass, is None."""
        kind = type(value)
        if kind is bytes:
            return value
        if kind is str:
            text = value
        elif is_pathlib(kind):
            try:
                text = os_fspath(value)
            except Exception:
                return None
            if type(text) is not str:
                return None
        else:
            return None
        try:
            return str_encode(text, fs_encoding, fs_errors)
        except Exception:  # UnicodeEncodeError: a lone surrogate the codec cannot encode
            return None

    def decode(data: bytes) -> str:
        return bytes_decode(data, fs_encoding, fs_errors)

    def exact_text(value) -> str | None:
        encoded = exact_bytes(value)
        return None if encoded is None else decode(encoded)

    def exact_argv(value) -> tuple[bytes, ...] | None:
        """Every element of an argv list (or a single element) as bytes, or None."""
        kind = type(value)
        items = list(value) if kind is list or kind is tuple else [value]
        converted = []
        for item in items:
            encoded = exact_bytes(item)
            if encoded is None:
                return None
            converted.append(encoded)
        return tuple(converted)

    def name_of(value) -> str:
        """The name of ``value``'s type, read without running any of its code."""
        return str_copy(type_name(type(value)))

    def describe(value, depth: int = 0) -> str:
        """A short text of an event argument that runs none of the caller's code: exact
        ``str``, ``bytes``, ``int``, ``float``, ``bool`` and None by their builtin repr,
        exact lists and tuples item by item, anything else by its type name."""
        kind = type(value)
        if (value is None or kind is str or kind is bytes or kind is int or kind is bool
                or kind is float):
            return repr(value)[:200]
        if (kind is list or kind is tuple) and depth < 3:
            inner = ", ".join([describe(item, depth + 1) for item in value[:8]])
            if len(value) > 8:
                inner += ", ..."
            if kind is list:
                return "[" + inner + "]"
            return "(" + inner + ("," if len(value) == 1 else "") + ")"
        return "<" + name_of(value) + ">"

    def parse_json(raw: str):
        """The JSON value of ``raw`` (no surrounding white space), or None."""
        try:
            value, end = json_scan(raw, 0)
        except Exception:  # StopIteration or JSONDecodeError
            return None
        return value if end == len(raw) else None

    # --- state ---------------------------------------------------------------------
    realpaths = _load_realpaths()
    gstate = GuardState(
        mode=mode,
        temp_root=realpath(temp_root) if temp_root else None,
        repo_root=realpath(repo_root) if repo_root else None,
        classes={
            "GuardViolation": GuardViolation,
            "RealExecutionBlocked": RealExecutionBlocked,
            "NetworkBlocked": NetworkBlocked,
        },
    )
    child_name = CHILD_VIOLATIONS_FILE
    child_root_fd = None
    if mode == "child" and gstate.temp_root:
        gstate.child_file = join(gstate.temp_root, child_name)
        # The violation file is opened relative to this descriptor of the temp root, never
        # through its path: a test that renames the temp root and puts a link in its place
        # cannot send the guard's own write into another directory. (The hook is not
        # installed yet, so this open is not an audit event the guard judges.)
        try:
            child_root_fd = os_open(gstate.temp_root, os.O_RDONLY | os.O_DIRECTORY
                                    | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            child_root_fd = None  # record() falls back to the path, still O_NOFOLLOW
    public_violations = gstate.violations
    ledger: list[Violation] = []
    consumed_ids: set[int] = set()
    lock = threading.Lock()

    # --- protected and exempt roots (open, listing, mutation) -----------------
    protected = _protected_roots(realpaths, gstate.temp_root if mode == "child" else None)

    exempt_candidates = [gstate.temp_root, gstate.repo_root, sys.prefix, sys.base_prefix,
                         sys.exec_prefix]
    exempt_candidates += [p if p else getcwd() for p in sys.path]
    exempt_list: list[str] = []
    for candidate in exempt_candidates:
        text = exact_text(candidate) if candidate else None
        if not text:
            continue
        real = realpath(text)
        # An exemption that would cover a whole protected root (for example a
        # sys.path entry equal to $HOME) is dropped.
        if any(within(root, real) for root in protected):
            continue
        exempt_list.append(real)
    exempt = tuple(sorted(set(exempt_list)))
    gstate.protected_roots = tuple(protected)
    gstate.exempt_roots = exempt
    protected = tuple(protected)
    # The dir_fd rule below looks only at the fixed roots and the passwd home: a
    # child's $HOME may be the test's fake home under the system temp directory.
    passwd_home = _passwd_home()
    anchored = tuple(sorted({realpath(p) for p in realpaths.PROTECTED_ROOTS}
                            | ({passwd_home} if passwd_home else set())))

    # --- Popen rules ------------------------------------------------------
    python_real = realpath(sys.executable)
    allowed_exes = frozenset({python_real} | {
        realpath(p) for p in (realpaths.TRUE_BIN, realpaths.FALSE_BIN, realpaths.SLEEP_BIN,
                              realpaths.GREP_BIN)
    })
    argv_roots = tuple(r for r in (gstate.temp_root, gstate.repo_root, realpath(sys.prefix),
                                   realpath(sys.base_prefix)) if r)
    guard_dir_real = realpath(str(GUARD_DIR))
    blocked_suffixes = tuple(realpaths.BLOCKED_ARGV_SUFFIXES)
    blocked_substrings = tuple(realpaths.BLOCKED_ARGV_SUBSTRINGS)
    blocked_prefixes = tuple(realpaths.BLOCKED_ARGV_PREFIXES)
    blocked_exact = tuple(p.rstrip("/") for p in blocked_prefixes)
    proc_root = realpaths.PROC_ROOT
    temp_root_real = gstate.temp_root
    repo_root_real = gstate.repo_root
    child_file = gstate.child_file

    def in_temp(path: str) -> bool:
        return bool(temp_root_real) and (
            path == temp_root_real or path.startswith(temp_root_real + "/"))

    proc_prefix = proc_root.rstrip("/") + "/"
    # Links of a process (or thread) that name something else in the child: its working
    # directory and root, and its standard descriptors, which the child gets redirected
    # (stdin=, stdout=, stderr=) before it changes to cwd and runs anything. A passed
    # descriptor >= 3 names the same open file in both processes, and the child closes
    # every other one (close_fds), so those links are left to the other rules.
    child_relative_links = (("cwd",), ("root",), ("fd", "0"), ("fd", "1"), ("fd", "2"))
    link_text = "a process's cwd, root or standard-descriptor link"

    def child_base(cwd_text: str | None) -> str:
        """The absolute directory a child started with ``cwd`` resolves relative paths
        from (a relative cwd is taken from this process's directory), joined and never
        normalized: ``..`` after a link means the link target's parent there."""
        here = getcwd()
        if cwd_text is None:
            return here
        return cwd_text if isabs(cwd_text) else join(here, cwd_text)

    def is_child_relative_link(path: str) -> bool:
        """``path`` is one of ``child_relative_links`` of a process or thread under the
        proc root (``<pid>``, ``self`` or ``thread-self``, optionally ``task/<tid>``)."""
        if not path.startswith(proc_prefix):
            return False
        parts = path[len(proc_prefix):].split("/")
        if len(parts) >= 3 and parts[1] == "task":
            parts = [parts[0], *parts[3:]]  # <pid>/task/<tid>/x is the thread's x
        return tuple(parts[1:]) in child_relative_links

    def through_proc_link(path: str) -> bool:
        """Resolving ``path`` passes a link in ``child_relative_links``.

        Such a link names the calling process's directory or descriptor when this hook
        resolves it, but the child's once the child has redirected its standard
        descriptors and changed to ``cwd`` (or root), so the file the child would run or
        read cannot be judged here (fail closed). The walk follows symbolic links
        component by component, like ``realpath``, and applies ``..`` to what it has
        resolved so far, never to the text, so ``/proc/self/cwd/..`` is caught, and so is
        ``<link>/..`` when the link points through ``/proc/self/cwd``. Callers pass the
        path as the child will resolve it: absolute, and never normalized.
        """
        if not isabs(path):
            return True
        todo = [part for part in path.split("/") if part][::-1]
        current = ""
        hops = 0
        while todo:
            part = todo.pop()
            if part == ".":
                continue
            if part == "..":
                current = current.rsplit("/", 1)[0]
                continue
            candidate = current + "/" + part
            if is_child_relative_link(candidate):
                return True
            mode = file_mode(candidate, False)
            if mode is None:
                current = candidate  # missing: the rest stays literal
                continue
            if (mode & s_ifmt) != s_iflnk:
                current = candidate
                continue
            hops += 1
            if hops > 40:
                return True  # a link loop, or deeper than the kernel follows
            try:
                target = readlink(candidate)
            except (OSError, ValueError):
                return True
            if target.startswith("/"):
                current = ""
            todo.extend([part for part in target.split("/") if part][::-1])
        return False

    def quietly(event: str, path: str, call, *args, **kwargs):
        """Run one of the hook's own audited operations (a /proc read, the violation-file
        write) on ``path``: the one ``event`` it raises for that path is not judged. Every
        other event is, also one raised meanwhile by an audit hook installed before this
        one (audit hooks added after it are refused), so no code of a test ever runs
        unjudged."""
        saved = getattr(local, "quiet", None)
        local.quiet = (event, path)
        try:
            return call(*args, **kwargs)
        finally:
            local.quiet = saved

    def write_child_line(data: bytes) -> bool:
        """Append ``data`` to this child's violation file; False if it cannot be done safely.

        The file is opened relative to the temp root's descriptor taken at install, with
        O_NOFOLLOW (a link planted at the name, by the child or by its parent, fails the
        open instead of sending the line into the file it names) and O_NONBLOCK (a FIFO
        there cannot hang the child), and written only when it is a regular file of this
        user with exactly one link (a hard link would put the line into another file).
        A parent reports such an entry as a violation of its own (``read_child_violations``),
        so refusing to write through it hides nothing."""
        try:
            if child_root_fd is not None:
                fd = quietly("open", child_name, os_open, child_name, child_file_flags, 0o600,
                             dir_fd=child_root_fd)
            else:
                fd = quietly("open", child_file, os_open, child_file, child_file_flags, 0o600)
        except OSError:
            return False
        try:
            info = fstat(fd)
            if ((info.st_mode & s_ifmt) != s_ifreg or info.st_uid != euid
                    or info.st_nlink != 1):
                return False
            os_write(fd, data)
            return True
        except OSError:
            return False
        finally:
            os_close(fd)

    def record(kind: str, event: str, detail: str, exc_type: type) -> None:
        detail = detail[:500]
        # Built without running this module's (replaceable) Violation.__init__.
        violation = object_new(violation_cls)
        object_setattr(violation, "kind", kind)
        object_setattr(violation, "event", event)
        object_setattr(violation, "detail", detail)
        object_setattr(violation, "consumed", False)
        with lock:
            ledger.append(violation)
            public_violations.append(violation)
        line = ('{"kind": ' + json_string(kind) + ', "event": ' + json_string(event)
                + ', "detail": ' + json_string(detail) + ', "pid": ' + str(getpid()) + "}\n")
        if child_file:
            if not write_child_line(line.encode()):
                # Still fails the call (below); the parent sees the unusable file itself.
                try:
                    os_write(2, ("sn1per-mcp test guard (child): could not record this "
                                 "violation in " + child_name + " (the temp root is gone, or "
                                 "the name is not a regular file of this user with one link); "
                                 "reported here only: " + line).encode())
                except OSError:
                    pass
        elif mode == "strict":
            # No parent file to report to: at least say it on stderr.
            try:
                os_write(2, ("sn1per-mcp test guard (strict child): " + line).encode())
            except OSError:
                pass
        raise exc_type("test guard blocked " + event + ": " + detail[:300])

    def recorded_count() -> int:
        with lock:
            return len(ledger)

    def recorded_since(start: int) -> list[Violation]:
        with lock:
            return list(ledger[start:])

    def consume(violation: Violation) -> None:
        with lock:
            if any(v is violation for v in ledger):
                consumed_ids.add(id(violation))
                violation.consumed = True

    def unconsumed_ledger() -> list[Violation]:
        with lock:
            return [v for v in ledger if id(v) not in consumed_ids]

    gstate.recorded_count = recorded_count
    gstate.recorded_since = recorded_since
    gstate.consume = consume
    gstate.unconsumed_ledger = unconsumed_ledger

    def event_path(value, allow_pathlib: bool) -> tuple[str | None, str | None]:
        """(path, problem) of a path argument of a file event. A descriptor (an exact int
        or bool) or no argument is not a path. An int subclass is not a descriptor here:
        io.FileIO takes a value that does not fit a C int (2**31, -2**40) as a path and
        converts it with its __fspath__, and raises "open" with the object itself. The os
        functions and the builtin open() hand their events the converted path (an exact
        str or bytes); io.FileIO converts a path object in C and then raises "open" with the
        object, and the shutil events carry the caller's object before the calls that
        follow (which raise their own events with the converted path), so only those may
        carry a pathlib path."""
        kind = type(value)
        if value is None or kind is int or kind is bool:
            return None, None
        if kind is str or kind is bytes or (allow_pathlib and is_pathlib(kind)):
            path = exact_text(value)
            if path is not None:
                return path, None
        allowed = "str, bytes and pathlib paths" if allow_pathlib else "str and bytes"
        return None, f"a path of type {name_of(value)} (only {allowed} can be judged)"

    def is_text(value) -> bool:
        kind = type(value)
        return kind is str or kind is bytes

    def env_entries(env) -> tuple[tuple[tuple[bytes, bytes], ...] | None, str | None]:
        """(entries, problem): the environment the child gets, encoded once.

        ``subprocess`` builds the child's environment from ``env.items()`` and keeps a
        ``str`` and a ``bytes`` key for the same name, of which the child's ``getenv``
        sees only one. So ``env`` must be a plain ``dict`` (or ``os.environ``) with ``str``
        or ``bytes`` keys and values, and a name may occur once after encoding. The
        ``fork_exec`` wrapper gives the child exactly these entries.
        """
        if type(env) is not dict and env is not environ:
            return None, (f"env is a {name_of(env)}, not a dict or os.environ: its get() "
                          "and items() could disagree, and the child gets items()")
        entries: list[tuple[bytes, bytes]] = []
        names: set[bytes] = set()
        for key, value in list(env.items()):
            if not is_text(key) or not is_text(value):
                return None, (f"env entry of type {name_of(key)}: {name_of(value)} "
                              "(keys and values must be str or bytes)")
            name, data = exact_bytes(key), exact_bytes(value)
            if name is None or data is None:
                return None, "env entry that cannot be encoded"
            if not name or b"=" in name or b"\x00" in name or b"\x00" in data:
                return None, f"env name {decode(name)!r} is empty or holds '=' or NUL"
            if name in names:
                return None, (f"env names {decode(name)!r} twice (a str and a bytes key): "
                              "the child sees only one of the two values")
            names.add(name)
            entries.append((name, data))
        return tuple(entries), None

    def env_value(entries, name: str) -> str | None:
        wanted = str_encode(name, fs_encoding, fs_errors)
        for key, value in entries:
            if key == wanted:
                return decode(value)
        return None

    def blocked_text(value: str) -> bool:
        if any(s in value for s in blocked_substrings):
            return True
        return value.startswith(blocked_prefixes) or value in blocked_exact

    def always_blocked_arg(element: str, base: str) -> bool:
        """The O.2 always-blocked rules, applied to the text and to its realpaths.

        ``base`` is absolute. The path is resolved as written (the kernel applies
        ``..`` to the target of the link before it) and in its lexical form, and the
        suffix rule is waived only when the absolute text and both realpaths lie
        inside the (validated) temp root. Resolving only the lexical form missed
        ``<temp-root link>/../sudo`` that names a real binary.
        """
        candidates = [element]
        absolute = None
        reals: list[str] = []
        if "/" in element or lexists(join(base, element)):
            joined = join(base, element)
            absolute = normpath(joined)
            reals = [realpath(joined), realpath(absolute)]
            candidates += [absolute, *reals]
        if any(blocked_text(c) for c in candidates):
            return True
        if any(c.endswith(blocked_suffixes) for c in candidates):
            return not (absolute is not None and in_temp(absolute)
                        and all(in_temp(real) for real in reals))
        return False

    def python_flags_ok(argv: list[str]) -> bool:
        skip_next = False
        for element in argv[1:]:
            if skip_next:
                skip_next = False
                continue
            if element == "--" or not element.startswith("-") or element == "-":
                return True
            if element.startswith("--"):
                # CPython's long options, matched by exact name. One takes the next
                # element as its argument; an unknown one is refused (fail closed).
                if element in python_long_options_with_argument:
                    skip_next = True
                    continue
                if element in python_long_options:
                    continue
                return False
            cluster = element[1:]
            for index in range(len(cluster)):
                ch = cluster[index]
                if ch in python_forbidden_flags:
                    return False
                if ch in python_flags_ending_options:
                    return True
                if ch in python_flags_with_argument:
                    if index == len(cluster) - 1:
                        skip_next = True
                    break
        return True

    def forwarded_guard_problem(entries) -> str | None:
        """SN1PER_MCP_TEST_GUARD may only restrict (O.2, O.7).

        Absent: the child goes strict. Present: it must name this session's own
        repository root, and this session's temp root or a directory inside it. Read
        from the encoded entries the child receives (``env_entries``) with the JSON
        scanner captured at install time.
        """
        raw = env_value(entries, env_var)
        if raw is None:
            return None
        data = parse_json(raw)
        if data is None:
            return f"{env_var} is not valid JSON"
        if type(data) is not dict or set(data) != {"temp_root", "repo_root"}:
            return f"{env_var} must carry exactly temp_root and repo_root"
        child_temp, child_repo = data["temp_root"], data["repo_root"]
        if type(child_temp) is not str or type(child_repo) is not str \
                or not isabs(child_temp) or not isabs(child_repo):
            return f"{env_var} roots must be absolute paths"
        if not temp_root_real or not repo_root_real:
            return f"{env_var} forwarded by a session without roots"
        if not in_temp(realpath(child_temp)):
            return f"{env_var} temp_root {child_temp!r} is outside this session's temp root"
        if realpath(child_repo) != repo_root_real:
            return f"{env_var} repo_root {child_repo!r} is not this session's repository"
        return None

    def check_popen(executable, args, cwd, env) -> tuple[str | None, tuple | None]:
        """(problem, approval).

        The approval is ``(executable realpath, argv bytes, env entries, cwd bytes,
        inherited, start directory bytes)``: every value converted exactly once and judged
        in that form, which is what the follow-up ``fork_exec`` call must use and what the
        wrapper passes on (see ``fork_exec_matches``). ``inherited`` is true for
        ``env=None``, whose entries are read from ``os.environ``. The start directory is
        the absolute directory every relative path was judged against (this process's
        directory for ``cwd=None``, joined with a relative ``cwd``), read once here; the
        wrapper gives it to the child as its ``cwd``, so another thread that changes this
        process's directory after the check changes nothing for the child.
        """
        argv_bytes = exact_argv(args)
        if not argv_bytes:
            return ("argv elements must be str, bytes or pathlib paths (another path-like "
                    "object, or a str or bytes subclass, can answer differently when the "
                    "child is started)"), None
        exe_bytes = argv_bytes[0] if executable is None else exact_bytes(executable)
        if exe_bytes is None:
            return (f"executable of type {name_of(executable)} (only str, bytes and "
                    "pathlib paths)"), None
        cwd_bytes = None
        if cwd is not None:
            cwd_bytes = exact_bytes(cwd)
            if cwd_bytes is None:
                return f"cwd of type {name_of(cwd)} (only str, bytes and pathlib paths)", None
        inherited = env is None
        entries, env_problem = env_entries(environ if inherited else env)
        if env_problem:
            return ("os.environ: " if inherited else "") + env_problem, None
        argv = [decode(item) for item in argv_bytes]
        exe = decode(exe_bytes)
        cwd_text = decode(cwd_bytes) if cwd_bytes is not None else None
        # The directory the child resolves relative paths from: cwd (a relative cwd is
        # taken from this process's directory), joined but never normalized. Read once:
        # every relative path below is judged against it, and the child starts in it.
        base = child_base(cwd_text)
        base_bytes = str_encode(base, fs_encoding, fs_errors)

        for element in [exe, *argv]:
            if "\x00" in element:
                return "argv element contains NUL", None
            if always_blocked_arg(element, base):
                return f"argv element {element!r} names a real Sn1per or sudo binary", None

        if "/" in exe:
            exe_path = exe if isabs(exe) else join(base, exe)
        else:
            search = env_value(entries, "PATH") or ""
            path_entries = search.split(pathsep) if search else []
            if any(not isabs(entry) for entry in path_entries):
                # The child resolves a relative entry after its chdir to cwd, this
                # process before it: the two can name different files.
                return f"the child's PATH has a relative entry ({search!r})", None
            if any(through_proc_link(entry) for entry in path_entries):
                return (f"the child's PATH has an entry through {link_text} "
                        f"({search!r})", None)
            found = which(exe, search)
            if found is None:
                return f"executable {exe!r} is not on the child's PATH", None
            exe_path = found
        if through_proc_link(exe_path):
            # /proc/self/cwd/... (directly, after "..", or through a link) names this
            # process's directory here but the child's after its chdir to cwd, and
            # /proc/self/fd/0 names the child's redirected stdin.
            return f"executable {exe_path!r} resolves through {link_text}", None
        if cwd_text is not None and through_proc_link(base):
            return f"cwd {cwd_text!r} resolves through {link_text}", None
        exe_real = realpath(exe_path)
        if always_blocked_arg(exe_path, base):
            return f"executable {exe_path!r} names a real Sn1per or sudo binary", None
        is_python = exe_real == python_real
        if not (in_temp(exe_real) or exe_real in allowed_exes):
            return (f"executable {exe_real!r} is outside the test temp root and the allowlist",
                    None)

        for element in argv[1:]:
            candidate = element if isabs(element) else join(base, element)
            if through_proc_link(candidate):
                # Checked whether or not the path exists here: it may exist only in the
                # child's view of its cwd or of a redirected descriptor.
                return f"argv element {element!r} resolves through {link_text}", None
            if lexists(candidate) and not within_any(realpath(candidate), argv_roots):
                return f"argv element {element!r} names a path outside the test roots", None

        if cwd_text is not None and cwd_text != "/" and not in_temp(realpath(base)):
            return f"cwd {cwd_text!r} is not / and not inside the test temp root", None

        problem = forwarded_guard_problem(entries)
        if problem:
            return problem, None

        if is_python:
            if inherited:
                return ("python child without an explicit env (needs the guard on PYTHONPATH)",
                        None)
            pythonpath = env_value(entries, "PYTHONPATH") or ""
            first = pythonpath.split(pathsep)[0] if pythonpath else ""
            # The child makes each entry absolute from its own cwd and normalizes it
            # lexically before it imports sitecustomize, so only an absolute, normalized
            # spelling that no proc link changes names the same directory there as here.
            if (not first or not isabs(first) or normpath(first) != first
                    or through_proc_link(first) or realpath(first) != guard_dir_real):
                return "python child without tests/guard first on PYTHONPATH", None
            if env_value(entries, "PYTHONHOME") is not None:
                # Another standard library brings another site module, which decides
                # whether sitecustomize (the guard) is imported at all.
                return "python child with PYTHONHOME set", None
            if not python_flags_ok(argv):
                return ("python child started with -I, -S, -E or an unknown long option",
                        None)
        return None, (exe_real, argv_bytes, env_key(entries), cwd_bytes, inherited,
                      base_bytes)

    # --- approval of the one follow-up call of an approved Popen ---------------
    def env_key(entries) -> tuple[bytes, ...]:
        """The ``NAME=value`` byte strings of the child's environment, in order."""
        return tuple([name + b"=" + value for name, value in entries])

    def fork_exec_matches(approved: tuple | None, args: tuple) -> tuple | None:
        """The arguments the approved call runs with, or None to block it.

        The result is ``(argv, executable list, cwd, environment)``, all as the bytes
        ``check_popen`` judged: the real ``fork_exec`` converts what it is given once
        more in C, and a caller's object could answer differently then. The child always
        gets the judged environment explicitly, also when ``env`` was None (``subprocess``
        then passes None, and the child would inherit the process environment, which
        ``os.putenv`` can change without ``os.environ``), and always the judged start
        directory as its ``cwd``, also when ``cwd`` was None or relative (the child would
        inherit, or resolve the relative ``cwd`` from, this process's directory, which
        another thread can change between the check and the fork).

        ``_posixsubprocess`` tries every entry of ``executable_list`` and goes on
        after ENOENT, ENOEXEC or EACCES, so an approved temp-root stub that fails
        to exec (a missing interpreter, no shebang) would fall through to the
        next PATH entry, which may be a real binary. The returned list therefore
        holds only the candidates whose realpath is the approved executable.
        """
        if approved is None or len(args) < 6:
            return None
        exe_real, approved_argv, approved_env, approved_cwd, inherited, start = approved
        if exact_argv(args[0]) != approved_argv:
            return None
        cwd_value = args[4]
        cwd_bytes = exact_bytes(cwd_value) if cwd_value is not None else None
        if (cwd_value is not None and cwd_bytes is None) or cwd_bytes != approved_cwd:
            return None
        env_list = args[5]
        if inherited:
            if env_list is not None:
                return None
        elif ((type(env_list) is not list and type(env_list) is not tuple)
              or any(type(item) is not bytes for item in env_list)
              or tuple(env_list) != approved_env):
            return None
        if any(callable(item) for item in args[6:]):
            # preexec_fn runs arbitrary code in the child before the exec (for example a
            # chdir that changes what a relative path names). Never needed in tests.
            return None
        # The child chdirs to the start directory before it execs, so a relative candidate
        # (from a relative PATH entry or a relative executable) names a file relative to
        # it, not to this process's directory now. Judge and exec the absolute path
        # instead, joined but not normalized, so the file judged is the file the child runs.
        base = decode(start)
        if through_proc_link(base):
            return None
        candidates = args[1]
        if type(candidates) is not list and type(candidates) is not tuple:
            return None
        narrowed = []
        first_runnable_seen = False
        for candidate in candidates:
            path = exact_text(candidate)
            if path is None or "\x00" in path:
                return None
            absolute = path if isabs(path) else join(base, path)
            if through_proc_link(absolute):
                return None  # names a different file once the child is in cwd
            matches = realpath(absolute) == exe_real
            if not first_runnable_seen and isfile(absolute) and access(absolute, x_ok):
                # The executable subprocess would have run must be the approved one.
                if not matches:
                    return None
                first_runnable_seen = True
            if matches:
                narrowed.append(str_encode(absolute, fs_encoding, fs_errors))
        if not narrowed:
            return None
        return approved_argv, tuple(narrowed[:1]), start, approved_env

    real_fork_exec = _posixsubprocess.fork_exec

    def gated_fork_exec(*args, **kwargs):
        approved = getattr(local, "approved", None)
        local.approved = None
        try:
            judged = None if kwargs else fork_exec_matches(approved, args)
        except violation_base:
            raise
        except Exception:  # a guard bug must fail closed
            judged = None
        if judged is None:
            record("process", "_posixsubprocess.fork_exec",
                   "fork_exec outside an approved subprocess.Popen (multiprocessing, a direct "
                   f"call or a stale approval): {describe(args[:1])}", exc_exec)
        argv_bytes, narrowed, start, env_items = judged
        # Run exactly what was judged: the argv, environment and start directory bytes
        # check_popen converted (the C code would convert the caller's objects once more,
        # and a cwd of None would inherit this process's directory at fork time) and only
        # the approved file (no fall-through to a later PATH entry).
        return real_fork_exec(argv_bytes, narrowed, args[2], args[3], start,
                              list(env_items), *args[6:])

    def blocked_process_start(self, *args, **kwargs):
        record("process", "multiprocessing.Process.start",
               f"multiprocessing is never allowed in tests ({name_of(self)})", exc_exec)

    _posixsubprocess.fork_exec = gated_fork_exec
    if getattr(subprocess, "_fork_exec", None) is real_fork_exec:
        subprocess._fork_exec = gated_fork_exec
    # os.posix_spawn converts its arguments in C before its audit event, from objects whose
    # methods a test can replace, so it is never approved; without this subprocess would
    # call it (and fail closed) for every Popen without cwd, preexec_fn or a new session.
    subprocess._USE_POSIX_SPAWN = False
    multiprocessing.process.BaseProcess.start = blocked_process_start

    # --- files ------------------------------------------------------------
    def resolve(path: str | None, follow: bool) -> str | None:
        """The realpath of ``path`` (from ``event_path``), or of its parent with the last
        name joined when ``follow`` is false."""
        if path is None or path == "" or "\x00" in path:
            return None
        try:
            if follow:
                return realpath(path)
            # Joined, never normalized: in "<link>/../name" the kernel changes the
            # entry "name" in the parent of the link's TARGET, which the lexical form
            # ("name" next to the link) hides.
            parent, name = split(path if isabs(path) else join(getcwd(), path))
            if not name or name == "." or name == "..":
                return realpath(path)
            return join(realpath(parent), name)
        except (OSError, ValueError):
            return None

    def is_protected(real: str) -> bool:
        return within_any(real, protected) and not within_any(real, exempt)

    def above_protected(real: str) -> bool:
        """A directory above a protected root, through which a ``dir_fd`` open could
        reach it; allowed only when it also leads to an exempt root (``/`` always does)."""
        if real == "/":
            return False
        if not any(root != real and within(root, real) for root in anchored):
            return False
        return not any(within(root, real) for root in exempt)

    # --- signals ------------------------------------------------------------
    def read_proc(pid: int, name: str) -> bytes | None:
        path = proc_root + "/" + str(pid) + "/" + name
        try:
            handle = quietly("open", path, io_open, path, "rb")
        except OSError:
            return None
        try:
            return handle.read(1 << 16)
        except OSError:
            return None
        finally:
            handle.close()

    def stat_fields(pid: int) -> list[bytes] | None:
        data = read_proc(pid, "stat")
        if not data or b")" not in data:
            return None
        return data[data.rfind(b")") + 2:].split()

    def is_descendant(pid: int) -> bool:
        me = getpid()
        current = pid
        for _ in range(64):
            fields = stat_fields(current)
            if fields is None or len(fields) < 2:
                return False
            parent = int(fields[1])
            if parent == me:
                return True
            if parent <= 1:
                return False
            current = parent
        return False

    def carries_temp_root(pid: int) -> bool:
        """A stub reparented after its parent exited still names the temp root."""
        if not temp_root_real:
            return False
        for name in ("cmdline", "environ"):
            data = read_proc(pid, name)
            for item in (data or b"").split(b"\0"):
                value = item.decode("utf-8", "replace")
                if name == "environ":
                    value = value.partition("=")[2]
                if value and in_temp(value):
                    return True
        return False

    def is_ours(pid: int) -> bool:
        return pid == getpid() or is_descendant(pid) or carries_temp_root(pid)

    def group_ok(pgid: int) -> bool:
        if pgid <= 0 or pgid == getpgrp():
            return False
        if lexists(proc_root + "/" + str(pgid)):
            return is_ours(pgid)
        members = []
        for entry in quietly("os.listdir", proc_root, listdir, proc_root):
            if entry.isdigit():
                fields = stat_fields(int(entry))
                if fields is not None and len(fields) > 2 and int(fields[2]) == pgid:
                    members.append(int(entry))
        return all(is_ours(member) for member in members)

    def kill_problem(event: str, args: tuple) -> str | None:
        if len(args) < 2 or type(args[0]) is not int or type(args[1]) is not int \
                or args[1] == 0:
            return None
        target = args[0]
        if event == "os.killpg":
            return None if group_ok(target) else f"signal to process group {target}"
        if target == 0 or target == -1:
            return f"signal to pid {target} (own process group or every process)"
        if target < -1:
            return None if group_ok(-target) else f"signal to process group {-target}"
        if target == getpid() or not lexists(proc_root + "/" + str(target)):
            return None
        return None if is_ours(target) else f"signal to pid {target}, not started by the tests"

    def is_dir_fd(value) -> bool:
        """A descriptor in a dir_fd argument (CPython reports none as -1; -100 is
        AT_FDCWD). Read by its real type: anything else counts as no descriptor, so the
        path is judged."""
        return type(value) is int and value != -1 and value != -100

    def mutation_problem(event: str, args: tuple) -> str | None:
        allow_pathlib = event.startswith("shutil.")
        for index, follow, dir_fd_index in mutation_events[event]:
            if len(args) <= index:
                continue
            value, problem = event_path(args[index], allow_pathlib)
            if problem:
                return f"change of {problem}"
            if value is None:
                continue
            if dir_fd_index is not None and len(args) > dir_fd_index \
                    and is_dir_fd(args[dir_fd_index]) and not isabs(value):
                continue
            real = resolve(value, follow)
            if real and is_protected(real):
                return f"change to real path {real!r}"
        return None

    def is_unix_socket(sock) -> bool:
        try:
            return socket_family(sock) == af_unix
        except Exception:  # not a socket object: judged as a network socket
            return False

    def judge(event: str, args: tuple) -> None:
        if event == "subprocess.Popen":
            if mode == "strict":
                record("process", event, "unguarded child: no process creation allowed",
                       exc_exec)
            approval = None
            try:
                problem, approval = check_popen(*args)
            except violation_base:
                raise  # a trip in code of the caller's objects, already recorded
            except Exception as exc:  # a guard bug must fail closed
                problem = f"guard could not check the call ({name_of(exc)})"
            if problem:
                record("process", event, problem, exc_exec)
            # subprocess implements an approved Popen with _posixsubprocess.fork_exec;
            # allow exactly that one follow-up call.
            local.approved = approval
        elif event in always_blocked:
            record("process", event, f"{always_blocked[event]} is never allowed in tests: "
                   f"{describe(args)}", exc_exec)
        elif event == "sys.addaudithook":
            # A hook added now would run after this one for every event, after the guard has
            # judged it and before the call acts, and could change what was judged (chdir,
            # re-point a link). CPython drops a new hook when an existing one raises an
            # Exception subclass, so the call returns None without adding it; the violation
            # is recorded.
            record("guard", event, "adding an audit hook is never allowed in tests: it would "
                   "run after the guard and could change what the guard judged (the working "
                   "directory, a link) before the call acts", exc_exec)
        elif event in dns_events:
            record("network", event, f"DNS lookup {describe(args)}", exc_net)
        elif event in socket_send_events:
            if mode == "strict" or not is_unix_socket(args[0] if args else None):
                record("network", event, f"network I/O to {describe(args[1:])}", exc_net)
        elif event == "open":
            path, problem = event_path(args[0] if args else None, False)
            if problem:
                record("file", event, f"open of {problem}", exc_exec)
            real = resolve(path, True)
            if real and is_protected(real):
                record("file", event, f"open of real path {real!r}", exc_exec)
            if real and above_protected(real):
                record("file", event, f"open of {real!r}, a directory above a protected "
                       "root (a dir_fd open could reach it)", exc_exec)
        elif event in listing_events:
            path, problem = event_path(args[0] if args else None, False)
            if problem:
                record("file", event, f"listing of {problem}", exc_exec)
            real = resolve(path, True)
            if real and is_protected(real):
                record("file", event, f"listing of real path {real!r}", exc_exec)
        elif event in mutation_events:
            problem = mutation_problem(event, args)
            if problem:
                record("file", event, problem, exc_exec)
        elif event in kill_events:
            problem = kill_problem(event, args)
            if problem:
                record("process", event, problem, exc_exec)

    def audit(event: str, args: tuple) -> None:
        quiet = getattr(local, "quiet", None)
        if quiet is not None and event == quiet[0] and args and type(args[0]) is str \
                and args[0] == quiet[1]:
            local.quiet = None
            return  # the event of the hook's own /proc read or violation-file write
        # An approval covers only the immediately following event in this thread.
        local.approved = None
        try:
            judge(event, args)
        except violation_base:
            raise
        except Exception as exc:  # a guard bug, or a caller's object that failed, fails closed
            local.approved = None
            record("guard", event, f"guard could not check the event ({name_of(exc)})",
                   exc_exec)

    sys.addaudithook(audit)
    setattr(sys, STATE_ATTR, gstate)
    return gstate


def install_from_environment() -> GuardState:
    """Install in a child process: ``child`` mode with a valid variable, else ``strict``."""
    raw = os.environ.get(ENV_VAR)
    roots = None
    if raw:
        try:
            roots = validated_roots(json.loads(raw))
        except ValueError:
            roots = None
    if roots is not None:
        return install(temp_root=roots[0], repo_root=roots[1], mode="child")
    return install(temp_root=None, repo_root=None, mode="strict")


def child_env(temp_root: str, repo_root: str, base: dict[str, str] | None = None,
              extra_pythonpath: list[str] | None = None) -> dict[str, str]:
    """Environment for a guarded ``sys.executable`` child (O.2)."""
    env = dict(base or {})
    entries = [str(GUARD_DIR)] + list(extra_pythonpath or [])
    env["PYTHONPATH"] = os.pathsep.join(entries)
    env[ENV_VAR] = json.dumps({"temp_root": temp_root, "repo_root": repo_root})
    return env


def _build_child_file_readers():
    """Build ``child_violation_files`` and ``read_child_violations`` (bound below).

    They run in the test session: at the end of every test (``tests/conftest.py``), while
    that test's ``monkeypatch`` changes are still in place (tests patch ``os.lstat``,
    ``os.walk`` and ``os.geteuid``), at the end of the session and in
    ``expect_child_violation``. So, like the hook, they decide only with values captured
    here, when this module is first imported (before any test module): C functions of
    ``os``, this user's uid, the builtins they use and a private JSON scanner
    (``test_guard_code_looks_up_no_global_name`` checks their bytecode). They never follow
    a symbolic link, and a directory that cannot be listed is skipped (as ``os.walk``
    does). Every entry named like a child violation file that a guarded child cannot have
    written to (a link, a directory, a FIFO or other special file, a file of another user
    or with more than one link, one that cannot be opened) is reported as a violation of
    its own, marked ``"unusable": True``: the guard refuses to write through such an entry,
    so the trips it would have recorded there are not in it.
    """
    import builtins
    import json.decoder

    type, len, sorted, str, dict, enumerate = (
        builtins.type, builtins.len, builtins.sorted, builtins.str, builtins.dict,
        builtins.enumerate)
    Exception, OSError, FileNotFoundError = (
        builtins.Exception, builtins.OSError, builtins.FileNotFoundError)
    lstat, scandir, os_open, fstat, os_read, os_close = (
        os.lstat, os.scandir, os.open, os.fstat, os.read, os.close)
    euid = os.geteuid()
    read_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
    scan = json.decoder.JSONDecoder().scan_once  # a private C scanner
    bytes_decode = builtins.bytes.decode
    bytes_join = b"".join
    name = CHILD_VIOLATIONS_FILE
    s_ifmt, s_ifreg = 0o170000, 0o100000
    kinds = {0o120000: "a symbolic link", 0o040000: "a directory", 0o010000: "a FIFO",
             0o140000: "a socket", 0o020000: "a character device",
             0o060000: "a block device"}

    def is_directory(entry) -> bool:
        try:
            return entry.is_dir(follow_symlinks=False)
        except OSError:
            return False

    def child_violation_files(root: str, *, recursive: bool = False) -> list[str]:
        """Every entry named like a child violation file directly in ``root`` or,
        recursively, below it, whatever its type (``read_child_violations`` reports the
        ones a child cannot have written to).

        A guarded child may be given a directory inside the session temp root as its own
        temp root (pytest-in-pytest tests do), and writes its file there, so the session
        looks below the temp root too. Symbolic links are never followed."""
        top = root.rstrip("/")
        if not recursive:
            path = top + "/" + name
            try:
                lstat(path)
            except OSError:
                return []
            return [path]
        found: list[str] = []
        pending = [top or "/"]
        while pending:
            directory = pending.pop()
            try:
                with scandir(directory) as listing:
                    entries = [(entry.name, is_directory(entry)) for entry in listing]
            except OSError:
                continue
            prefix = directory.rstrip("/") + "/"
            for entry_name, is_dir in entries:
                if entry_name == name:
                    found.append(prefix + entry_name)
                if is_dir:
                    pending.append(prefix + entry_name)
        return sorted(found)

    def unusable(path: str, what: str) -> dict:
        return {"kind": "guard", "event": "child violation file", "pid": "-",
                "detail": (path + " is " + what + ": a guarded child cannot record its trips "
                           "there (the guard refuses to write through it), so any it had "
                           "are not in it"),
                "unusable": True, "path": path, "source": path + ":0"}

    def lines_of(path: str, data: bytes) -> list[dict]:
        items: list[dict] = []
        for number, raw in enumerate(data.splitlines(), start=1):
            text = bytes_decode(raw, "utf-8", "replace").strip()
            if not text:
                continue
            try:
                value, end = scan(text, 0)
            except Exception:  # StopIteration or JSONDecodeError
                value, end = None, -1
            if end != len(text) or type(value) is not dict:
                value = {"kind": "unknown", "event": "unreadable child violation line",
                         "detail": text[:200]}
            value["source"] = path + ":" + str(number)
            items.append(value)
        return items

    def read_child_violations(root: str, *, recursive: bool = False) -> list[dict]:
        """Violations that guarded children wrote into ``root`` (or below it), and one
        item marked ``"unusable": True`` for every entry named like a child violation file
        that a child cannot have written to.

        Each item carries a ``source`` key (``<file>:<line>``; ``<file>:0`` for an unusable
        entry) that identifies it across calls, so a caller can tell new violations from
        old ones."""
        items: list[dict] = []
        for path in child_violation_files(root, recursive=recursive):
            try:
                mode = lstat(path).st_mode
            except FileNotFoundError:
                continue
            except OSError:
                items.append(unusable(path, "an entry that cannot be examined"))
                continue
            if (mode & s_ifmt) != s_ifreg:
                items.append(unusable(path, kinds.get(mode & s_ifmt, "a special file")))
                continue
            try:
                fd = os_open(path, read_flags)
            except FileNotFoundError:
                continue
            except OSError:
                items.append(unusable(path, "a file that cannot be opened"))
                continue
            problem = None
            chunks: list[bytes] = []
            try:
                info = fstat(fd)
                if (info.st_mode & s_ifmt) != s_ifreg:
                    problem = kinds.get(info.st_mode & s_ifmt, "a special file")
                elif info.st_uid != euid:
                    problem = "owned by uid " + str(info.st_uid)
                elif info.st_nlink != 1:
                    problem = "hard-linked (" + str(info.st_nlink) + " links)"
                while problem is None:
                    chunk = os_read(fd, 1 << 16)
                    if not chunk:
                        break
                    chunks.append(chunk)
            except OSError:
                problem = "a file that cannot be read"
            finally:
                os_close(fd)
            if problem is not None:
                items.append(unusable(path, problem))
                continue
            items.extend(lines_of(path, bytes_join(chunks)))
        return items

    return child_violation_files, read_child_violations


child_violation_files, read_child_violations = _build_child_file_readers()
