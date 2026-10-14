# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""``sniper_status`` (contract H.5) and the shared readiness checks of ``--check``.

The scope fields come from ``sniper_mcp.scope``: the scope file is re-read on
every call, and a changed digest is written as a ``scope_changed`` audit line
(F.1) except by ``--check``, which never writes the audit log.
"""

from __future__ import annotations

import asyncio
import importlib.metadata
import os
import platform
import pwd
import time
from dataclasses import dataclass
from typing import Any

from mcp.server.fastmcp import Context, FastMCP
from mcp.types import CallToolResult, ToolAnnotations

from sniper_mcp import (
    __version__,
    edition,
    lootfs,
    modes,
    paths,
    plugins,
    proc,
    results,
    scope,
    targets,
)
from sniper_mcp.edition import CliInfo, Detection
from sniper_mcp.results import ToolError
from sniper_mcp.settings import Settings
from sniper_mcp.tools import CallInfo, ToolContext

TOOL = "sniper_status"
TITLE = "Sn1per status"
DESCRIPTION = (
    "Report what this server can do on this host: the detected Sn1per edition and engine "
    "version, whether scanning is enabled and why not, the scan modes available here with "
    "their activity class, the configured target scope, concurrency, redaction and audit "
    "settings, and loaded plugins. Call this first, and again whenever a scan is refused. "
    "Read-only; sends no network traffic."
)
SUDO_CACHE_SECONDS = 60.0
SUDOERS_HINT = (
    'Add a sudoers drop-in with "sudo visudo -f /etc/sudoers.d/sn1per-mcp" containing this '
    "line:\n{user} ALL=(root) NOPASSWD: {cli}\nThis rule is equivalent to full root access "
    "for {user}; see docs/security-model.md."
)
# The same advice when root did not choose every name on the CLI realpath (C.2 step 1,
# H.5): the path is never put in front of the model.
SUDOERS_HINT_NOT_SHOWN = (
    'Add a sudoers drop-in with "sudo visudo -f /etc/sudoers.d/sn1per-mcp" containing this '
    "line, with the CLI realpath that sn1per-mcp --check prints on the host:\n{user} "
    "ALL=(root) NOPASSWD: <CLI realpath>\nThis rule is equivalent to full root access for "
    "{user}, and other local users could have chosen or replaced that file; see "
    "docs/security-model.md."
)
NOTES = [
    "Scope applies to the requested target at launch time; Sn1per may contact third-party "
    "services and hosts it discovers.",
    "Every Sn1per launch runs the engine's update and licence checks.",
    "Mode classes describe Sn1per's default profiles; edited profiles change what a mode does.",
]
RATE_LIMIT = {"calls": scope.RATE_LIMIT_CALLS,
              "window_seconds": int(scope.RATE_LIMIT_WINDOW_SECONDS)}
MAX_LISTED_SCOPE_ENTRIES = 100
MAX_LISTED_INVALID_ENTRIES = 20
SCOPE_FILE_WRITABLE_TEXT = (
    "The user this server runs as can modify the scope file, so an agent with file access "
    f"could widen the scope; keep it at {paths.HARDENED_SCOPE_FILE}, owned by root.")
ALLOW_ANY_TARGET_TEXT = (
    "Scope membership was not enforced because SNIPER_MCP_ALLOW_ANY_TARGET is set; the "
    "operator is responsible for authorization")
AUDIT_MODE_TEXT = (
    "The audit log is readable by other users and its mode could not be set to 0600 (for "
    "example an append-only file); keep it private.")
# The payload's sudo.status values (H.5). H.5 reserves not_needed for running as root,
# so the not_root refusal (SNIPER_NEEDS_SUDO=false, not root) shows not_checked: sudo
# was not consulted, and disabled_reason carries not_root.
_SUDO_STATUS_SHOWN = {"not_root": "not_checked"}


# --- detection refusals (C.3) ------------------------------------------------------

def detection_error(detection: Detection, code: str) -> ToolError:
    """The H.2 error for a C.3 detection refusal (``sniper_scan`` and delete)."""
    if code == "cli_not_found":
        return ToolError("cli_not_found", "No Sn1per CLI was found.",
                         "Install Sn1per or set SNIPER_BIN.")
    if code == "cli_untrusted":
        # The chown hint names the path only when root placed the file (C.2 step 1).
        return ToolError("cli_untrusted", "The Sn1per CLI is not owned by root, so a sudo "
                         "rule would run a user-owned file as root.",
                         detection.cli.untrusted_hint())
    return ToolError("edition_unsupported", "The Sn1per engine version could not be "
                     "identified as a supported engine.",
                     "Supported engines are Sn1per Community Edition 9.x and the 11.x engine "
                     "(SE, Professional, Enterprise); set SNIPER_EDITION only if the CLI is a "
                     "wrapper.",
                     details={"engine_version": detection.engine_version})


def engine_path_error(detection: Detection) -> ToolError:
    """C.2 step 12 refusal."""
    return ToolError("engine_path_missing", "The engine re-invokes 'sniper' by name as root, "
                     "but no 'sniper' on root's PATH is this CLI.",
                     detection.engine_path_hint())


# --- privilege preflight (L.2) ------------------------------------------------------

@dataclass(frozen=True)
class Privilege:
    """Outcome of the privilege preflight (L.2)."""

    status: str  # ok, not_needed, missing, untrusted, not_configured, not_checked, not_root
    code: str | None  # the H.2 refusal code, or None when scans may proceed
    hint: str | None
    sudo_path: str | None


_sudo_cache: dict[tuple[str, str], tuple[float, bool]] = {}


def _user_name(euid: int) -> str:
    try:
        return pwd.getpwuid(euid).pw_name
    except KeyError:
        return str(euid)


def privilege(ctx: ToolContext, *, cli: CliInfo | None) -> Privilege:
    """Root, or a trusted sudo whose passwordless rule allows the CLI (L.2, D.5).

    The sudo check always uses the CLI realpath; the hint names it only when root
    chose it (``CliInfo.chosen_by_root``).
    """
    cli_realpath = cli.realpath if cli is not None else None
    settings = ctx.settings
    if settings.euid == 0:
        return Privilege("not_needed", None, None, None)
    if not settings.needs_sudo:
        return Privilege("not_root", "not_root",
                         "Run the server as root or unset SNIPER_NEEDS_SUDO.", None)
    sudo = proc.resolve_sudo()
    if sudo.status == "missing":
        return Privilege("missing", "sudo_missing",
                         "Install sudo or run the server as root.", None)
    if sudo.status == "untrusted":
        return Privilege("untrusted", "sudo_untrusted",
                         f"The sudo binary at {sudo.path} must be a root-owned file that is "
                         f"not group- or world-writable ({sudo.detail}).", sudo.path)
    assert sudo.path is not None
    if cli_realpath is None:
        return Privilege("not_checked", None, None, sudo.path)
    key = (sudo.path, cli_realpath)
    now = time.monotonic()
    cached = _sudo_cache.get(key)
    if cached is not None and now - cached[0] < SUDO_CACHE_SECONDS:
        allowed = cached[1]
    else:
        allowed = proc.sudo_preflight(sudo.path, cli_realpath, home=settings.home)
        _sudo_cache[key] = (now, allowed)
    if allowed:
        return Privilege("ok", None, None, sudo.path)
    assert cli is not None
    template = SUDOERS_HINT if cli.chosen_by_root else SUDOERS_HINT_NOT_SHOWN
    hint = template.format(user=_user_name(settings.euid), cli=cli_realpath)
    return Privilege("not_configured", "sudo_not_configured", hint, sudo.path)


def clear_sudo_cache() -> None:
    _sudo_cache.clear()


# --- scope (F.1, H.5) ------------------------------------------------------------------

def scope_object(snapshot: scope.ScopeSnapshot, settings: Settings) -> dict[str, Any]:
    """The ``scope`` object of ``sniper_status`` (H.5)."""
    return {
        "configured": snapshot.configured,
        "valid": snapshot.valid if snapshot.configured else None,
        "sources": list(snapshot.sources),
        "file": dict(snapshot.file) if snapshot.file is not None else None,
        "entries": [e.text for e in snapshot.entries[:MAX_LISTED_SCOPE_ENTRIES]],
        "entries_total": len(snapshot.entries),
        "exclusions": [e.text for e in snapshot.exclusions[:MAX_LISTED_SCOPE_ENTRIES]],
        "exclusions_total": len(snapshot.exclusions),
        "invalid_entries": [dict(item)
                            for item in snapshot.invalid[:MAX_LISTED_INVALID_ENTRIES]],
        "digest": snapshot.digest,
        "allow_any_target": settings.allow_any_target,
        "dns_policy": settings.dns_policy,
        "cidr_cap": settings.cidr_cap,
        "authorization_ref": settings.authorization_ref,
    }


def scope_warnings(snapshot: scope.ScopeSnapshot) -> list[dict[str, str]]:
    """F.1 parse-time warnings, in the order of H.2.1."""
    found = []
    for code in snapshot.warning_codes():
        if code == "scope_file_writable_by_server_user":
            found.append(results.warning(code, SCOPE_FILE_WRITABLE_TEXT))
        else:
            example = snapshot.domain_exclusions[0].text
            found.append(results.warning(
                code, f"Domain exclusions such as {example} do not apply to IP or CIDR "
                      "targets."))
    return found


# --- the status payload ---------------------------------------------------------------

def _mcp_sdk_version() -> str | None:
    try:
        return importlib.metadata.version("mcp")
    except importlib.metadata.PackageNotFoundError:
        return None


def elicitation_form_supported(capabilities: Any) -> bool:
    """I.2: ``capabilities.elicitation`` present, with ``form``, or with neither ``form``
    nor ``url`` (the 2025-06-18 shape ``{}`` means form). URL-only clients cannot answer
    the confirmation form, so they do not count."""
    elicitation = getattr(capabilities, "elicitation", None)
    if elicitation is None:
        return False
    return getattr(elicitation, "form", None) is not None or getattr(
        elicitation, "url", None) is None


def client_info(context: Context | None) -> dict[str, Any] | None:
    """The ``client`` object (H.5) from the session's initialize parameters."""
    if context is None:
        return None
    try:
        params = context.request_context.session.client_params
    except (AttributeError, ValueError, LookupError):
        return None
    if params is None:
        return None
    capabilities = getattr(params, "capabilities", None)
    return {
        "name": params.clientInfo.name,
        "version": params.clientInfo.version,
        # The same predicate the destructive tools use (I.2): form mode only.
        "elicitation": elicitation_form_supported(capabilities),
    }


def modes_object(settings: Settings, detection: Detection) -> dict[str, Any]:
    """The ``modes`` object of ``sniper_status`` (H.5, D)."""
    available: list[dict[str, object]] = []
    unavailable: list[dict[str, object]] = []
    if detection.dialect is not None:
        for mode in modes.table(detection.dialect):
            if not modes.mode_allowed(mode, settings.allow_intrusive):
                unavailable.append(modes.unavailable_entry(mode, "mode_not_allowed"))
            elif not detection.modes_present.get(mode.name, False):
                unavailable.append(modes.unavailable_entry(mode, "engine_file_missing"))
            else:
                available.append(modes.status_entry(mode))
    names = [str(entry["name"]) for entry in available]
    return {"default": modes.schema_default(names), "allow_intrusive": settings.allow_intrusive,
            "available": available, "unavailable": unavailable}


def _workspace_count(workspace_dir: str) -> int:
    return sum(1 for name in lootfs.workspace_names(workspace_dir)
               if targets.is_valid_workspace(name))


def build_status(ctx: ToolContext, client: dict[str, Any] | None = None, *,
                 call: CallInfo | None = None, record_scope_change: bool = True
                 ) -> tuple[dict[str, Any], list[dict[str, str]], list[str]]:
    """The status payload, its warnings, and the reasons scanning is unavailable.

    ``reasons`` follows the ``sniper_scan`` check order (F.9); the first one is
    ``scan.disabled_reason``. ``--check`` passes ``record_scope_change=False``:
    it never writes the audit log.
    """
    settings = ctx.settings
    detection = edition.detect(settings)
    snapshot = ctx.read_scope(call, record_change=record_scope_change)
    state_status = ctx.refresh_state_dir()
    audit_status = ctx.audit.status()
    reasons: list[str] = []
    warnings: list[dict[str, str]] = []

    if not settings.scan_enabled:  # F.9 step 1
        reasons.append("scan_disabled")
    if detection.scan_refusal:  # step 2
        reasons.append(detection.scan_refusal)
    refusal = scope.configuration_refusal(snapshot, allow_any=settings.allow_any_target)
    if refusal is not None:  # step 7
        reasons.append(refusal.code)
    if not state_status.ok:  # step 9
        reasons.append("state_dir_insecure")
    elif not audit_status.available:
        reasons.append("audit_unavailable")

    cli_ok = detection.cli.status == "ok"
    if settings.scan_enabled and cli_ok:  # step 10
        priv = privilege(ctx, cli=detection.cli)
    elif settings.euid == 0:
        priv = Privilege("not_needed", None, None, None)
    else:
        priv = Privilege("not_checked", None, None, None)
    if priv.code:
        reasons.append(priv.code)
    if cli_ok and detection.engine_path_ok is False:  # step 11
        reasons.append("engine_path_missing")

    for code, message in detection.warnings:
        warnings.append(results.warning(code, message))
    for code in state_status.warnings:
        warnings.append(results.warning(code, "The state directory was group- or "
                                              "world-accessible; its mode was set to 0700."))
    warnings += scope_warnings(snapshot)
    if settings.allow_any_target:
        warnings.append(results.warning("allow_any_target", ALLOW_ANY_TARGET_TEXT))
    if audit_status.mode_not_fixed:
        warnings.append(results.warning("audit_log_mode_not_fixed", AUDIT_MODE_TEXT))
    warnings += plugins.status_warnings(ctx.plugins)  # M.2, M.3

    running = len(ctx.jobs.running())
    workspace_dir = detection.workspace_dir
    payload: dict[str, Any] = {
        "server": {
            "name": "sn1per-mcp",
            "version": __version__,
            "python": platform.python_version(),
            "mcp_sdk": _mcp_sdk_version(),
            "transport": "stdio",
            "pid": os.getpid(),
        },
        "client": client,
        "edition": detection.edition_object(),
        "paths": {
            "sniper_bin": detection.cli.configured,
            # Shown only when root chose every name on it (C.2 step 1, H.5).
            "sniper_bin_realpath": detection.cli.shown_realpath,
            "install_dir": detection.install_dir,
            # Only when root chose the CLI file (C.2 step 3, H.5).
            "cli_install_dir": detection.shown_cli_install_dir,
            "loot_base": detection.loot_base,
            "workspace_dir": workspace_dir,
            "workspace_dir_exists": os.path.isdir(workspace_dir),
            "state_dir": settings.state_dir,
            "audit_log": settings.audit_log,
        },
        "scan": {
            "enabled": not reasons,
            "disabled_reason": reasons[0] if reasons else None,
            "needs_sudo": settings.needs_sudo and settings.euid != 0,
            "sudo": {"status": _SUDO_STATUS_SHOWN.get(priv.status, priv.status),
                     "hint": priv.hint},
            "engine_path_ok": detection.engine_path_ok,
            "max_concurrent": settings.max_concurrent_scans,
            "running_jobs": running,
            "rate_limit": dict(RATE_LIMIT),
        },
        "modes": modes_object(settings, detection),
        "scope": scope_object(snapshot, settings),
        "destructive": {"enabled": settings.enable_destructive,
                        "tools": list(ctx.destructive_tools),
                        "client_elicitation": client["elicitation"] if client else None},
        "redaction": {"enabled": settings.redact, "reveal_secrets": settings.reveal_secrets},
        "plugins": [record.status_object() for record in ctx.plugins],
        "workspaces": {"count": _workspace_count(workspace_dir)},
        "notes": list(NOTES),
    }
    return payload, warnings, reasons


def register(mcp: FastMCP, ctx: ToolContext) -> None:
    @mcp.tool(name=TOOL, title=TITLE, description=DESCRIPTION,
              annotations=ToolAnnotations(title=TITLE, readOnlyHint=True, destructiveHint=False,
                                          idempotentHint=True, openWorldHint=False))
    @results.guarded(TOOL)
    async def sniper_status(context: Context) -> CallToolResult:
        call = ctx.begin_call(context)
        client = client_info(context)

        def run() -> tuple[dict[str, Any], list[dict[str, str]], list[str]]:
            ctx.maintain()
            return build_status(ctx, client, call=call)

        payload, warnings, _ = await asyncio.to_thread(run)
        return results.success(TOOL, payload, warnings)
