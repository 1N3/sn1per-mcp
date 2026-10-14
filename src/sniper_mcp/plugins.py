# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Allowlisted plugin loader and the plugin API, version 1 (contract M).

Only the ``<distribution>:<entry-point-name>`` pairs listed in
``SNIPER_MCP_PLUGINS`` are considered (B.2, A-48). An installed entry point
that is not listed is never imported, not even ``.load()``-ed, and another
distribution that declares the same entry-point name is ignored, so it can
neither replace the listed plugin nor make it ambiguous.

Plugins are fully trusted code that runs in this process (M.4). The checks
below catch accidents, not attacks:

- an exception in ``load()`` or ``register()`` is isolated: the plugin gets
  status ``error`` and the tools it added are removed;
- a plugin tool whose name collides with an existing tool is an ``error``;
- a plugin that removes or replaces a tool that existed before it ran (a core
  tool, or a tool of an earlier plugin) makes the server exit with status 3,
  after a ``plugin_error`` audit line and a stderr message (A-39).
"""

from __future__ import annotations

import contextlib
import importlib.metadata
import logging
import os
import re
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult

from sniper_mcp import __version__, lootfs, redact, results, sanitize
from sniper_mcp import audit as audit_mod
from sniper_mcp.edition import Detection
from sniper_mcp.settings import Settings

GROUP = "sn1per_mcp.plugins"
API_VERSION = 1
ERROR_MAX_CHARS = 200
EXIT_PLUGIN_INTEGRITY = 3
PRIVILEGE_WARNING = (
    "Plugins run inside the Sn1per MCP Server process with the same user, the same sudo "
    "rights and access to its memory and environment. Enable only plugins you trust."
)
_EVENT_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_NORMALIZE_RE = re.compile(r"[-_.]+")

log = logging.getLogger("sn1per-mcp")

# Read at call time, so tests can replace the entry-point source.
entry_points: Callable[..., Any] = importlib.metadata.entry_points


class PluginIntegrityError(Exception):
    """A plugin removed or replaced an existing tool; the server exits with status 3."""


def normalize(name: str) -> str:
    """PEP 503 normalization: lowercase, runs of ``-``, ``_`` and ``.`` become ``-``."""
    return _NORMALIZE_RE.sub("-", name).lower()


# --- discovery (never imports anything) ------------------------------------------------------

def _dist_name(ep: Any) -> str | None:
    dist = getattr(ep, "dist", None)
    name = getattr(dist, "name", None) if dist is not None else None
    return name if isinstance(name, str) else None


def matching(distribution: str, entry_point: str) -> list[Any]:
    """Entry points of the group named ``entry_point`` whose distribution is
    ``distribution`` (PEP 503 normalized), in discovery order."""
    wanted = normalize(distribution)
    found = []
    for ep in entry_points(group=GROUP, name=entry_point):
        dist = _dist_name(ep)
        if dist is not None and normalize(dist) == wanted:
            found.append(ep)
    return found


def installed() -> list[tuple[str, str]]:
    """Every installed ``(distribution, entry-point name)`` of the group (``--check``)."""
    pairs = set()
    for ep in entry_points(group=GROUP):
        dist = _dist_name(ep)
        if dist is not None:
            pairs.add((normalize(dist), ep.name))
    return sorted(pairs)


def not_allowlisted(allowlist: Iterable[tuple[str, str]]) -> list[str]:
    """Installed but not allowlisted entry points as ``<distribution>:<entry-point>``."""
    listed = {(normalize(dist), name) for dist, name in allowlist}
    return [f"{dist}:{name}" for dist, name in installed() if (dist, name) not in listed]


# --- records (M.3) ------------------------------------------------------------------------------

@dataclass
class PluginRecord:
    """One allowlisted plugin and what happened to it."""

    distribution: str
    entry_point: str
    version: str | None = None
    path: str | None = None
    status: str = "not_found"  # loaded, error, not_found
    tools: list[str] = field(default_factory=list)
    error: str | None = None
    annotations_missing: list[str] = field(default_factory=list)

    def status_object(self) -> dict[str, Any]:
        """The ``sniper_status.plugins`` entry (M.3)."""
        return {"distribution": self.distribution, "entry_point": self.entry_point,
                "version": self.version, "path": self.path, "status": self.status,
                "tools": list(self.tools), "error": self.error}

    def start_object(self) -> dict[str, Any]:
        """The ``server_start`` entry (G.4)."""
        return {"distribution": self.distribution, "entry_point": self.entry_point,
                "version": self.version, "status": self.status}

    def audit_result(self) -> dict[str, Any]:
        """The ``plugin_loaded`` / ``plugin_error`` result object (G.4)."""
        base = {"distribution": self.distribution, "entry_point": self.entry_point,
                "version": self.version, "path": self.path}
        if self.status == "loaded":
            return {**base, "tools": list(self.tools)}
        return {**base, "error": self.error}


def status_warnings(records: Sequence[PluginRecord]) -> list[dict[str, str]]:
    """``plugins_loaded`` and ``plugin_tool_annotations_missing`` (M.2, M.3)."""
    warnings = []
    if any(r.status == "loaded" for r in records):
        warnings.append(results.warning("plugins_loaded", PRIVILEGE_WARNING))
    missing = [f"{r.distribution}:{r.entry_point} ({', '.join(r.annotations_missing)})"
               for r in records if r.annotations_missing]
    if missing:
        warnings.append(results.warning(
            "plugin_tool_annotations_missing",
            "Plugin tools without a title or without all four annotation hints: "
            + "; ".join(missing) + "."))
    return warnings


# --- the plugin API (M.2) -----------------------------------------------------------------------

class PluginContext:
    """What a plugin's ``register(mcp, ctx)`` receives (API version 1)."""

    api_version = API_VERSION
    server_version = __version__

    def __init__(self, *, distribution: str, entry_point: str, settings: Settings,
                 edition: Detection | None, audit_log: audit_mod.AuditLog | None,
                 loot: lootfs.LootBase | None) -> None:
        self.distribution = distribution
        self.entry_point = entry_point
        self.settings = settings  # frozen; no environment dump
        self.edition = edition
        self.logger = logging.getLogger(f"sn1per-mcp.plugin.{entry_point}")
        self._audit_log = audit_log
        self._loot = loot

    # --- audit ---------------------------------------------------------------------------
    def audit(self, event: str, **fields: Any) -> None:
        """Write ``plugin:<entry-point>:<event>`` with ``fields`` as its result object;
        the loader adds ``distribution``. Raises ``audit.AuditUnavailable``."""
        if not _EVENT_RE.fullmatch(event):
            raise ValueError(f"invalid plugin audit event {event!r}")
        if self._audit_log is None:
            raise audit_mod.AuditUnavailable("no audit log in this context")
        result = {**fields, "distribution": self.distribution}
        self._audit_log.write(f"plugin:{self.entry_point}:{event}", result=result)

    # --- untrusted strings (J.6, K) ----------------------------------------------------------
    @staticmethod
    def sanitize(text: str | bytes) -> str:
        """J.6 steps 1-6."""
        return sanitize.sanitize(text).text

    def redact(self, text: str) -> tuple[str, dict[str, int]]:
        """K.2 redaction, unless the operator disabled it (``SNIPER_MCP_REDACT=false``)."""
        if not self.settings.redact:
            return text, {}
        return redact.redact(text)

    @staticmethod
    def untrusted(**fields: Any) -> dict[str, Any]:
        """The ``untrusted_content`` object with its fixed notice (H.1)."""
        return results.untrusted(**fields)

    # --- loot (J.1, J.2) ---------------------------------------------------------------------
    def open_loot_file(self, workspace: str, relpath: str, max_bytes: int) -> bytes:
        """Read at most ``max_bytes`` (and at most 8 MiB) of one loot file through the safe
        opener. Raises ``lootfs.LootError`` (``invalid_workspace``, ``workspace_not_found``,
        ``loot_dir_changed``, ``invalid_argument``, ``excluded``, ``file_not_found``)."""
        if self._loot is None:
            raise lootfs.LootError("workspace_not_found", "No loot directory.")
        parts = relpath.split("/")
        if not relpath or not all(lootfs.component_ok(p) for p in parts):
            raise lootfs.LootError("invalid_argument", "Invalid relative path.")
        exclude = not self.settings.reveal_secrets
        if exclude and (any(lootfs.is_excluded_dir(p) for p in parts[:-1])
                        or lootfs.is_excluded_file(parts[-1])):
            raise lootfs.LootError("excluded", "The file is excluded from loot reads.")
        cap = max(0, min(int(max_bytes), lootfs.FILE_READ_CAP))
        stats = lootfs.ReadStats()
        ws_fd = self._loot.open_workspace(workspace, stats)
        try:
            dir_fd = lootfs.open_relative(ws_fd, parts[:-1], stats)
        finally:
            os.close(ws_fd)
        if dir_fd is None:
            raise lootfs.LootError("file_not_found", "No such loot file.")
        try:
            data = lootfs.read_file(dir_fd, parts[-1], stats, cap=cap, count=False)
        finally:
            os.close(dir_fd)
        if data is None:
            raise lootfs.LootError("file_not_found", "No such regular, singly linked loot "
                                   "file.")
        return data.data

    # --- result envelopes (H.1, H.2) -----------------------------------------------------------
    def result(self, payload: Mapping[str, Any], *, tool: str | None = None,
               warnings: Sequence[Mapping[str, str]] = ()) -> CallToolResult:
        """A success result; ``tool`` defaults to ``payload["tool"]``."""
        name = tool or payload.get("tool")
        if not isinstance(name, str) or not name:
            raise ValueError("result() needs the tool name (payload['tool'] or tool=)")
        return results.success(name, payload, warnings)

    def error(self, code: str, message: str, hint: str, retry: str = "after_change",
              details: Mapping[str, Any] | None = None, *,
              tool: str | None = None) -> CallToolResult:
        """An error result; plugin-defined codes are allowed (M.2)."""
        return results.plugin_failure(tool or self.entry_point, code, message, hint,
                                      retry=retry, details=details)


# --- the loader (M.1) ---------------------------------------------------------------------------

def _tools(mcp: FastMCP) -> dict[str, Any]:
    return {tool.name: tool for tool in mcp._tool_manager.list_tools()}


def _remove(mcp: FastMCP, names: Iterable[str]) -> None:
    manager = mcp._tool_manager
    for name in names:
        try:
            manager.remove_tool(name)
        except Exception:  # noqa: BLE001 - older SDKs: fall back to the table
            getattr(manager, "_tools", {}).pop(name, None)


def _annotated(tool: Any) -> bool:
    annotations = getattr(tool, "annotations", None)
    if not getattr(tool, "title", None) or annotations is None:
        return False
    return all(getattr(annotations, hint, None) is not None for hint in (
        "readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"))


def _error_text(exc: BaseException) -> str:
    message = sanitize.sanitize(str(exc)).text.replace("\n", " ")
    return f"{type(exc).__name__}: {message}"[:ERROR_MAX_CHARS]


def _describe(dist: Any) -> tuple[str | None, str | None]:
    version = getattr(dist, "version", None)
    try:
        path = str(dist.locate_file(""))
    except Exception:  # noqa: BLE001 - a distribution without a location
        path = None
    return (version if isinstance(version, str) else None), path


class _Recorder:
    """Watches ``add_tool`` while one plugin registers (name collisions)."""

    def __init__(self, mcp: FastMCP) -> None:
        self.manager = mcp._tool_manager
        self.collisions: list[str] = []
        self._original = self.manager.add_tool

    def __enter__(self) -> _Recorder:
        manager, original, collisions = self.manager, self._original, self.collisions

        def add_tool(fn: Any, *args: Any, **kwargs: Any) -> Any:
            name = kwargs.get("name") or (args[0] if args else None) or getattr(
                fn, "__name__", None)
            if isinstance(name, str) and manager.get_tool(name) is not None:
                collisions.append(name)
            return original(fn, *args, **kwargs)

        self.manager.add_tool = add_tool  # type: ignore[method-assign]
        return self

    def __exit__(self, *exc: object) -> None:
        self.manager.__dict__.pop("add_tool", None)


def load_plugins(mcp: FastMCP, *, settings: Settings, detection: Detection | None,
                 audit_log: audit_mod.AuditLog | None,
                 loot: lootfs.LootBase | None) -> list[PluginRecord]:
    """P.4 step 9: load every allowlisted plugin in order; returns their records.

    Raises ``PluginIntegrityError`` (exit status 3) when a plugin removed or replaced
    a tool that existed before it ran.
    """
    records: list[PluginRecord] = []
    for distribution, entry_point in settings.plugins:
        record = PluginRecord(distribution=distribution, entry_point=entry_point)
        records.append(record)
        found = matching(distribution, entry_point)
        if not found:
            _audit(audit_log, audit_mod.PLUGIN_ERROR, record, "not installed")
            continue
        record.version, record.path = _describe(found[0].dist)
        if len(found) > 1:
            record.status, record.error = "error", "ambiguous entry point"
            _audit(audit_log, audit_mod.PLUGIN_ERROR, record)
            continue
        context = PluginContext(distribution=distribution, entry_point=entry_point,
                                settings=settings, edition=detection, audit_log=audit_log,
                                loot=loot)
        before = _tools(mcp)
        failure: BaseException | None = None
        # stdout carries JSON-RPC frames only (B.4): anything a plugin prints while it is
        # imported or registers goes to stderr instead.
        with _Recorder(mcp) as recorder, contextlib.redirect_stdout(sys.stderr):
            try:
                register = found[0].load()
                register(mcp, context)
            except (Exception, SystemExit) as exc:  # noqa: BLE001 - isolate the plugin
                failure = exc
                log.error("plugin %s:%s failed", distribution, entry_point,
                          exc_info=(type(exc), exc, exc.__traceback__))
        after = _tools(mcp)
        broken = sorted(name for name, tool in before.items() if after.get(name) is not tool)
        if broken:
            record.status = "error"
            record.error = ("removed or replaced existing tools: " + ", ".join(broken))[
                :ERROR_MAX_CHARS]
            _audit(audit_log, audit_mod.PLUGIN_ERROR, record)
            sys.stderr.write(f"sn1per-mcp: plugin {distribution}:{entry_point} "
                             f"{record.error}; exiting\n")
            raise PluginIntegrityError(record.error)
        added = sorted(set(after) - set(before))
        if failure is None and recorder.collisions:
            failure = ValueError("tool name collides with an existing tool: "
                                 + ", ".join(sorted(set(recorder.collisions))))
        if failure is not None:
            _remove(mcp, added)
            record.status, record.error = "error", _error_text(failure)
            _audit(audit_log, audit_mod.PLUGIN_ERROR, record)
            continue
        record.status, record.tools = "loaded", added
        record.annotations_missing = [name for name in added if not _annotated(after[name])]
        _audit(audit_log, audit_mod.PLUGIN_LOADED, record)
    return records


def _audit(audit_log: audit_mod.AuditLog | None, event: str, record: PluginRecord,
           error: str | None = None) -> None:
    """``plugin_loaded`` / ``plugin_error`` (best effort; P.4 step 9 comes before the
    ``server_start`` line). ``error`` overrides the audited reason only."""
    if audit_log is None:
        return
    result = record.audit_result()
    if error is not None:
        result["error"] = error
    audit_log.write_best_effort(event, result=result)
