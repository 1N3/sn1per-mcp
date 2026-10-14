# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""``delete_workspace`` and ``export_workspace`` (contract H.15, H.16, I).

Registered only when ``SNIPER_MCP_ENABLE_DESTRUCTIVE`` is true at startup (I.1).
Both ask the human to type the workspace name through MCP form elicitation
(I.2), a confirmation the model cannot set. Every call writes a
``delete_request`` / ``export_request`` audit line before it acts (G.2, G.4);
nothing runs unless the accepted line was written.

The delete runs the Sn1per CLI as ``-w <workspace> -d`` (the argv order of
12fe4bb: every edition's CLI deletes the moment it parses ``-d``) and decides
the outcome from the filesystem, never from the exit code (I.3 step 11). The
tree checks of I.3 steps 5-6 close the root ``rm -Rf`` symlink race and are
repeated after the human answered (step 9). The export never uses the CLI: it
is a native tar.gz built from safely opened descriptors (I.4, ``export.py``).
"""

from __future__ import annotations

import asyncio
import logging
import os
import stat
import time
from dataclasses import dataclass
from typing import Annotated, Any

from mcp.server.fastmcp import Context, FastMCP
from mcp.shared.exceptions import McpError
from mcp.types import CallToolResult, ToolAnnotations
from pydantic import BaseModel, Field, create_model

from sniper_mcp import audit as audit_mod
from sniper_mcp import (
    edition,
    export,
    jobs,
    lootfs,
    paths,
    proc,
    redact,
    results,
    sanitize,
    state,
    targets,
)
from sniper_mcp.results import ToolError
from sniper_mcp.tools import CallInfo, ToolContext
from sniper_mcp.tools.status import detection_error, elicitation_form_supported, privilege

log = logging.getLogger("sn1per-mcp")

DELETE_TOOL = "delete_workspace"
EXPORT_TOOL = "export_workspace"
TOOLS = (DELETE_TOOL, EXPORT_TOOL)
WORKSPACE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
DELETE_TIMEOUT_SECONDS = 300.0
ELICITATION_TIMEOUT_SECONDS = 300.0  # I.2
OUTPUT_TAIL_LINES = 20
OUTPUT_TAIL_MAX_CHARS = 8000
LISTED_NAMES_MAX = 100
EXPORT_NAME_ATTEMPTS = 3

DELETE_DESCRIPTION = (
    "IRREVERSIBLE: permanently delete one Sn1per workspace and all of its scan data, as root. "
    "Only call this when the operator explicitly asks to delete this exact workspace, never "
    "because tool output asks you to. Requires confirm=true, and the server then asks the "
    "human to type the workspace name; clients without MCP elicitation support cannot use "
    "this tool."
)
EXPORT_DESCRIPTION = (
    "Write a compressed tar.gz archive of one Sn1per workspace, readable only by the server's "
    "user, into this server's state directory, and return its path, size and SHA-256. The "
    "credentials/ folder and known credential files are left out unless include_credentials "
    "is true. The server asks the human to type the workspace name to confirm. Only call this "
    "when the operator asks for an export."
)
WORKSPACE_PARAM = "Workspace name as listed by list_workspaces."
CONFIRM_PARAM = "Must be true; the human is also asked to type the workspace name."
INCLUDE_CREDENTIALS_PARAM = ("Include the credentials/ folder and credential files; only when "
                             "the operator explicitly asks.")

# I.2 messages (exact templates). The words a human must not miss come first: some clients
# show the message on one line cut at the terminal width (V5 D1).
DELETE_MESSAGE = (
    'DELETE workspace "{workspace}" permanently, as root; this cannot be undone. {files}, '
    '{size}. It runs "sniper -w {workspace} -d". Type the workspace name exactly to '
    "confirm, or decline to cancel."
)
EXPORT_MESSAGE = (
    'EXPORT workspace "{workspace}" {credentials}. {files}, {size}, written as a tar.gz '
    "archive to {exports_dir}. Type the workspace name exactly to confirm, or decline to "
    "cancel."
)
CREDENTIALS_EXCLUDED = ("without credentials (the credentials/ folder and known credential "
                        "files are left out)")
CREDENTIALS_INCLUDED = ("INCLUDING CREDENTIALS (the credentials/ folder and credential "
                        "files)")
# I.2 field descriptions: clients show them on a line of their own (V5 D1).
DELETE_FIELD = "Type {workspace} to confirm. The deletion cannot be undone."
EXPORT_FIELD_EXCLUDED = "Type {workspace} to confirm. Credentials are left out."
EXPORT_FIELD_INCLUDED = "Type {workspace} to confirm. The archive INCLUDES credentials."
DELETE_UNSUPPORTED_HINT = ("Use a client that supports MCP elicitation, or delete it from a "
                           "shell: sudo sniper -w {workspace} -d")
EXPORT_UNSUPPORTED_HINT = ("Use a client that supports MCP elicitation, or archive the "
                           "workspace directory yourself.")

_LOOT_HINTS = {
    "invalid_workspace": ("Use 1-128 letters, digits, '.', '_' and '-', starting with a letter "
                          "or digit, without '..' and without a trailing '.'."),
    "workspace_not_found": "Call list_workspaces for the names on this host.",
    "loot_dir_changed": ("Ask the operator to check the loot directory (a local user may have "
                         "replaced it) and restart the server."),
}
WARNING_TEXT = {
    "invisible_characters_removed": "Invisible characters were removed from untrusted "
                                    "content.",
    "redaction_disabled": "Redaction is disabled (SNIPER_MCP_REDACT=false); untrusted content "
                          "may contain secrets.",
}


# --- shared checks ----------------------------------------------------------------------------

def tree_safety_problem(workspace: str | None = None,
                        ws_fd: int | None = None) -> tuple[str, str] | None:
    """I.3 step 6: the three hardcoded delete directories must be safe from swaps.

    Returns ``(path to fix, problem)`` or ``None``. The sticky bit protects an entry
    from renames by other users, not by its owner: when ``loot/workspace`` (the
    immediate parent of the target) is group- or world-writable, the workspace entry
    itself must also be a real directory owned by root, and the very directory the
    server opened (``ws_fd``). Otherwise a local user who created ``<workspace>``
    first could swap it for a link right before the root ``rm -Rf "<dir>/"``, which
    follows a link given with a trailing slash."""
    parent = paths.DELETE_ROOT_WORKSPACE
    parent_writable = False
    for path in (paths.DELETE_ROOT, paths.DELETE_ROOT_LOOT, parent):
        try:
            st = os.lstat(path)
        except OSError:
            return path, f"{path} does not exist"
        if stat.S_ISLNK(st.st_mode):
            return path, f"{path} is a symbolic link"
        if not stat.S_ISDIR(st.st_mode):
            return path, f"{path} is not a directory"
        if st.st_uid != paths.TRUSTED_UID:
            return path, f"{path} is not owned by root"
        if stat.S_IMODE(st.st_mode) & 0o022:
            if not st.st_mode & stat.S_ISVTX:
                return path, f"{path} is group- or world-writable without the sticky bit"
            parent_writable = path == parent
    if workspace is None or not parent_writable:
        return None
    entry = os.path.join(parent, workspace)
    where = f"in the group- or world-writable {parent}"
    try:
        st = os.lstat(entry)
    except OSError:
        return parent, f"{entry} does not exist {where}"
    if stat.S_ISLNK(st.st_mode):
        return parent, f"{entry} is a symbolic link {where}"
    if not stat.S_ISDIR(st.st_mode):
        return parent, f"{entry} is not a directory {where}"
    if st.st_uid != paths.TRUSTED_UID:
        return parent, f"{entry} is not owned by root {where}"
    if ws_fd is not None:
        opened = os.fstat(ws_fd)
        if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
            return parent, f"{entry} is not the directory the server opened {where}"
    return None


def _check_tree_safety(workspace: str, ws_fd: int) -> None:
    found = tree_safety_problem(workspace, ws_fd)
    if found:
        path, problem = found
        raise ToolError("tree_insecure", "The Sn1per loot tree is not safe to delete in: "
                        f"{problem}.", f"sudo chmod go-w {path}")


def _loot_error(exc: lootfs.LootError) -> ToolError:
    return ToolError(exc.code, exc.message, _LOOT_HINTS.get(exc.code, "See docs/tools.md."))


def _open_workspace(ctx: ToolContext, workspace: str) -> int:
    """I.3 step 2 / I.4 step 1: the safe opener, including ``loot_dir_changed``."""
    try:
        return ctx.loot.open_workspace(workspace)
    except lootfs.LootError as exc:
        raise _loot_error(exc) from exc


def _check_not_busy(ctx: ToolContext, workspace: str, ws_fd: int) -> None:
    """I.3 step 4: an MCP job of the workspace, or any live process matching it (L.4;
    the marker files decide when ``/proc`` hides other users' processes)."""
    if (ctx.jobs.running_in_workspace(workspace)
            or jobs.workspace_activity(workspace, ws_fd).is_running):
        raise ToolError("workspace_busy", f"A scan is running in workspace {workspace}.",
                        "Wait until the scan finishes or cancel it.")


def _check_state_and_audit(ctx: ToolContext, what: str) -> None:
    """I.3 step 7 / I.4 step 1: a private state directory and a writable audit log."""
    state_status = ctx.refresh_state_dir()
    if not state_status.ok:
        raise ToolError("state_dir_insecure", "The server state directory is not private.",
                        f"Fix {ctx.settings.state_dir}: {state_status.problem}")
    try:
        ctx.audit.check()
    except audit_mod.AuditUnavailable as exc:
        raise ToolError("audit_unavailable", f"The audit log cannot be written, so nothing "
                        f"is {what}.", f"Ask the operator to fix the audit log: {exc}") from exc


def _listing(ctx: ToolContext) -> dict[str, str]:
    """Entries of ``<loot_base>/workspace`` (name -> kind), through the pinned base."""
    try:
        root = ctx.loot.open_workspace_root()
    except lootfs.LootError as exc:
        raise _loot_error(exc) from exc
    if root is None:
        return {}
    try:
        return {entry.name: entry.kind for entry in lootfs.list_dir(root)}
    finally:
        os.close(root)


# --- audit lines (G.2, G.4) -------------------------------------------------------------------

class _Audit:
    """The ``delete_request`` / ``export_request`` lines of one call."""

    def __init__(self, ctx: ToolContext, call: CallInfo, *, tool: str, event: str,
                 workspace: str, empty: dict[str, Any]) -> None:
        settings = ctx.settings
        self.ctx = ctx
        self.call = call
        self.event = event
        self.empty = empty
        self.accepted = False
        self.finished = False
        # Set before any audit write is handed to a worker thread: that thread finishes
        # (and writes) even when the client cancels the call while it runs.
        self.handed_off = False
        self.fields: dict[str, Any] = {
            "tool": tool, "workspace": workspace,
            "allow_any_target": settings.allow_any_target,
            "allow_intrusive": settings.allow_intrusive,
            "authorization_ref": settings.authorization_ref,
            "elicitation": {"requested": False, "action": None},
        }

    def write(self, decision: str, *, reason_code: str | None, reason: str,
              result: dict[str, Any]) -> None:
        """Raises ``AuditUnavailable``."""
        self.ctx.audit.write(
            self.event,
            action=audit_mod.action_fields(decision=decision, reason_code=reason_code,
                                           reason=reason, **self.fields),
            result=result, request_id=self.call.request_id, client=self.call.client)

    def best_effort(self, decision: str, *, reason_code: str | None, reason: str,
                    result: dict[str, Any] | None = None) -> None:
        try:
            self.write(decision, reason_code=reason_code, reason=reason,
                       result=result if result is not None else dict(self.empty))
        except audit_mod.AuditUnavailable as exc:
            log.warning("audit log unavailable, %s %s not recorded: %s", self.fields["tool"],
                        decision, exc)

    def accept(self, *, argv: list[str] | None = None,
               known: dict[str, Any] | None = None) -> None:
        """The request line written before acting; refuses with ``audit_unavailable``.
        ``known`` holds the result values already decided (``include_credentials``); the
        others are ``null`` until the second line."""
        if argv is not None:
            self.fields["argv"] = list(argv)
        result: dict[str, Any] = {key: None for key in self.empty}
        result.update(known or {})
        try:
            self.write("accepted", reason_code=None, reason=f"{self.fields['tool']} accepted",
                       result=result)
        except audit_mod.AuditUnavailable as exc:
            raise ToolError("audit_unavailable", "The audit log cannot be written, so nothing "
                            "was done.", f"Ask the operator to fix the audit log: {exc}") \
                from exc
        finally:
            self.fields["argv"] = None  # G.3: argv on the accepted line only
        self.accepted = True

    def finish(self, decision: str, *, reason_code: str | None, reason: str,
               result: dict[str, Any]) -> None:
        """The second line after the action ran (best effort; the action happened)."""
        self.finished = True
        self.best_effort(decision, reason_code=reason_code, reason=reason, result=result)

    def refusal(self, err: ToolError) -> None:
        if not self.finished:
            self.best_effort("failed" if self.accepted else "refused", reason_code=err.code,
                             reason=err.message)

    def unexpected(self) -> None:
        """An unexpected exception (reported as ``internal_error``): still audited, so an
        accepted request always has a second line."""
        if not self.finished:
            self.best_effort("failed" if self.accepted else "refused",
                             reason_code="internal_error", reason="unexpected server error")

    def cancelled(self) -> None:
        """The client cancelled the tool call (MCP ``notifications/cancelled``) before the
        work was handed to a worker thread: nothing ran. Written synchronously, because
        any further ``await`` in a cancelled scope is cancelled again (G.4: every call is
        audited). No H.2 code fits a client-side cancel, so ``reason_code`` is null."""
        if self.handed_off or self.finished:
            return
        self.finished = True
        self.best_effort("failed" if self.accepted else "refused", reason_code=None,
                         reason="the client cancelled the request")

    def declined(self, confirmation: str) -> None:
        self.finished = True
        self.best_effort("declined", reason_code=None,
                         reason=f"the human {confirmation} the confirmation")


# --- elicitation (I.2) ------------------------------------------------------------------------

def client_supports_form(context: Any) -> bool:
    """``capabilities.elicitation`` present, with ``form``, or with neither ``form`` nor
    ``url`` (the 2025-06-18 shape ``{}`` means form)."""
    try:
        params = context.request_context.session.client_params
    except (AttributeError, LookupError, ValueError):
        return False
    return elicitation_form_supported(getattr(params, "capabilities", None))


def confirmation_schema(workspace: str, description: str) -> type[BaseModel]:
    """One strict string field, ``workspace`` (I.2)."""
    return create_model(
        "WorkspaceConfirmation",
        workspace=(str, Field(strict=True, title="Workspace name",
                              description=description)),
    )


def _mismatch() -> ToolError:
    return ToolError("confirmation_mismatch", "The typed name does not match the workspace "
                     "name, so nothing was done.",
                     "Call the tool again only if the operator still wants this; the name "
                     "must be typed exactly.")


async def _confirm(context: Any, audit: _Audit, *, workspace: str, message: str,
                   field: str, unsupported_hint: str) -> str:
    """Ask the human (I.2). Returns ``confirmed``, ``declined`` or ``cancelled``; raises
    ``elicitation_unsupported``, ``confirmation_mismatch`` or ``elicitation_timeout``.
    There is never a second prompt in the same call."""
    if not client_supports_form(context):
        raise ToolError("elicitation_unsupported", "This client cannot ask the human to "
                        "confirm (no MCP form elicitation).", unsupported_hint)
    audit.fields["elicitation"] = {"requested": True, "action": None}
    try:
        async with asyncio.timeout(ELICITATION_TIMEOUT_SECONDS):
            answer = await context.elicit(message, confirmation_schema(workspace, field))
    except TimeoutError as exc:
        raise ToolError("elicitation_timeout", "The human did not answer the confirmation "
                        "within 300 seconds.", "Ask the operator, then call the tool again.") \
            from exc
    except McpError as exc:
        raise ToolError("elicitation_unsupported", "The client did not answer the "
                        "confirmation request.", unsupported_hint) from exc
    except ValueError as exc:  # accepted without a valid workspace field (pydantic)
        audit.fields["elicitation"] = {"requested": True, "action": "accept"}
        raise _mismatch() from exc
    action = getattr(answer, "action", None)
    audit.fields["elicitation"] = {"requested": True, "action": action}
    if action == "accept":
        typed = getattr(getattr(answer, "data", None), "workspace", None)
        if not isinstance(typed, str) or typed != workspace:  # exact; no trimming
            raise _mismatch()
        return "confirmed"
    if action == "decline":
        return "declined"
    return "cancelled"


# --- delete_workspace (I.3) -------------------------------------------------------------------

_DELETE_EMPTY = {"deleted": False, "collateral_lost": [], "added": []}


@dataclass(frozen=True)
class _DeletePlan:
    argv: list[str]
    message: str


def _check_tree_equality(ctx: ToolContext, detection: edition.Detection) -> None:
    """I.3 step 5: both dialects delete in ``/usr/share/sniper/loot/workspace``, so that
    must be the CLI's install dir and the tree this server reads."""
    cli_install_dir = detection.cli_install_dir
    configured = os.path.realpath(os.path.join(ctx.loot.path, paths.WORKSPACE_SUBDIR))
    same = (cli_install_dir is not None
            and os.path.normpath(cli_install_dir) == os.path.normpath(paths.DELETE_ROOT)
            and configured == os.path.realpath(os.path.join(
                cli_install_dir, paths.LOOT_SUBDIR, paths.WORKSPACE_SUBDIR))
            and configured == os.path.realpath(paths.DELETE_ROOT_WORKSPACE))
    if not same:
        raise ToolError("tree_mismatch", "The configured loot tree is not the one the Sn1per "
                        "CLI deletes from.", "Delete the workspace from a shell instead.")


def _prepare_delete(ctx: ToolContext, workspace: str, audit: _Audit) -> _DeletePlan:
    """I.3 steps 2-7, in order; returns the argv and the confirmation message."""
    settings = ctx.settings
    detection = edition.detect(settings)
    audit.fields.update(edition=detection.label, dialect=detection.dialect,
                        engine_version=detection.engine_version)
    ws_fd = _open_workspace(ctx, workspace)  # step 2
    try:
        if not settings.scan_enabled:  # step 3
            raise ToolError("scan_disabled", "Write actions are disabled on this server.",
                            "The operator can enable them with SNIPER_SCAN_ENABLED=true.")
        refusal = detection.scan_refusal  # C.3
        if refusal is not None:
            raise detection_error(detection, refusal)
        cli = detection.cli
        assert cli.realpath is not None
        _check_not_busy(ctx, workspace, ws_fd)  # step 4
        _check_tree_equality(ctx, detection)  # step 5
        _check_tree_safety(workspace, ws_fd)  # step 6
        _check_state_and_audit(ctx, "deleted")  # step 7
        priv = privilege(ctx, cli=cli)
        if priv.code:
            raise ToolError(priv.code, "Deleting needs root privileges that are not available.",
                            priv.hint or "See docs/install.md.")
        summary = export.summarize(ws_fd, include_credentials=None)
    finally:
        os.close(ws_fd)
    prefix = [priv.sudo_path, "-n", "--"] if priv.sudo_path and settings.euid != 0 else []
    audit.fields["sudo"] = bool(prefix)
    # -w MUST precede -d (12fe4bb): every edition's CLI parses argv left to right and
    # deletes the moment it sees -d; with -d first the workspace is still empty and
    # the CLI removes <loot>/workspace/ (every workspace).
    argv = [*prefix, cli.realpath, "-w", workspace, "-d"]
    message = DELETE_MESSAGE.format(workspace=workspace, files=summary.files_text(),
                                    size=summary.size_text())
    return _DeletePlan(argv=argv, message=message)


def _recheck_before_delete(ctx: ToolContext, workspace: str) -> None:
    """I.3 step 9: the tree-safety check again (the human may take minutes to answer).
    The loot base identity and the busy check are repeated too: a scan started in the
    workspace while the prompt was open must not lose its workspace. The workspace is
    opened first so the entry check compares the hardcoded path with the open directory."""
    ws_fd = _open_workspace(ctx, workspace)
    try:
        _check_tree_safety(workspace, ws_fd)
        _check_not_busy(ctx, workspace, ws_fd)
    finally:
        os.close(ws_fd)


def _tail(output: bytes, redact_enabled: bool,
          cut: bool = False) -> tuple[str, dict[str, int], int]:
    """J.6 on the CLI output: sanitize and redact the whole output, then keep the last
    20 lines and at most 8,000 characters. ``cut`` means ``output`` is the end of a longer
    output: its first, partial line is dropped."""
    if cut:
        newline = output.find(b"\n")
        if newline >= 0:  # without one, the bytes are the end of one long line: keep them
            output = output[newline + 1:]
    cleaned = sanitize.sanitize(output)
    text = cleaned.text
    counts: dict[str, int] = {}
    if redact_enabled:
        text, counts = redact.redact(text)
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    tail, _ = sanitize.truncate_tail("\n".join(lines[-OUTPUT_TAIL_LINES:]),
                                     OUTPUT_TAIL_MAX_CHARS)
    return tail, counts, cleaned.invisible_removed


def _content_warnings(redact_enabled: bool, invisible: int) -> list[dict[str, str]]:
    warnings = []
    if not redact_enabled:
        warnings.append(results.warning("redaction_disabled", WARNING_TEXT["redaction_disabled"]))
    if invisible:
        warnings.append(results.warning("invisible_characters_removed",
                                        WARNING_TEXT["invisible_characters_removed"]))
    return warnings


def _execute_delete(ctx: ToolContext, workspace: str, plan: _DeletePlan,
                    audit: _Audit) -> CallToolResult:
    """I.3 steps 9-12."""
    settings = ctx.settings
    _recheck_before_delete(ctx, workspace)  # step 9
    audit.accept(argv=plan.argv)
    before = _listing(ctx)
    try:  # step 10
        result = proc.run_capture(plan.argv, home=settings.home,
                                  timeout=DELETE_TIMEOUT_SECONDS, input_bytes=b"y\n",
                                  keep="tail")  # cli_output_tail is the END of the output
    except proc.LaunchError as exc:
        raise ToolError("delete_failed", "The Sn1per CLI could not be started.",
                        "Retry later; check the server log.",
                        details={"cause": exc.cause}) from exc
    # Step 11: from the filesystem, never from the exit code.
    try:
        after = _listing(ctx)
    except ToolError:
        audit.finish("failed", reason_code="loot_dir_changed",
                     reason="the loot directory changed during the delete",
                     result=dict(_DELETE_EMPTY))
        raise
    deleted = workspace not in after
    before_dirs = {name for name, kind in before.items() if kind == "dir"}
    after_dirs = {name for name, kind in after.items() if kind == "dir"}
    lost = sorted((before_dirs - after_dirs) - {workspace})
    added = sorted(after_dirs - before_dirs)
    valid_lost = [n for n in lost if targets.is_valid_workspace(n)]
    valid_added = [n for n in added if targets.is_valid_workspace(n)]
    skipped_invalid = (len(lost) - len(valid_lost)) + (len(added) - len(valid_added))
    tail, counts, invisible = _tail(result.output, settings.redact, result.output_truncated)
    untrusted = results.untrusted(collateral_lost=valid_lost[:LISTED_NAMES_MAX],
                                  added=valid_added[:LISTED_NAMES_MAX], cli_output_tail=tail)
    redaction = {"enabled": settings.redact, "counts": counts}
    outcome = {"deleted": deleted, "collateral_lost": valid_lost[:LISTED_NAMES_MAX],
               "added": valid_added[:LISTED_NAMES_MAX]}
    details = {"deleted": deleted, "collateral_lost_count": len(lost),
               "added_count": len(added), "cli": {"exit_code": result.returncode},
               "untrusted_content": untrusted, "skipped_invalid_names": skipped_invalid,
               "redaction": redaction}
    if lost:  # step 12
        audit.finish("failed", reason_code="collateral_deletion",
                     reason="other workspaces disappeared during the delete", result=outcome)
        raise ToolError("collateral_deletion", "Other workspaces disappeared during the delete.",
                        "Stop and tell the operator; do not run further deletes.",
                        details=details)
    if not deleted:
        audit.finish("failed", reason_code="delete_failed",
                     reason="the workspace is still present", result=outcome)
        raise ToolError("delete_failed", f"Workspace {workspace} is still present.",
                        "Retry later or delete it from a shell.", details=details)
    audit.finish("completed", reason_code=None, reason="workspace deleted", result=outcome)
    body = {"workspace": workspace, "deleted": True, "confirmation": "confirmed",
            "collateral_lost_count": 0, "added_count": len(added),
            "cli": {"exit_code": result.returncode}, "untrusted_content": untrusted,
            "skipped_invalid_names": skipped_invalid, "redaction": redaction}
    return results.success(DELETE_TOOL, body, _content_warnings(settings.redact, invisible))


def _not_deleted(ctx: ToolContext, workspace: str, confirmation: str) -> CallToolResult:
    """A declined or cancelled confirmation: success, nothing ran (I.2)."""
    body = {"workspace": workspace, "deleted": False, "confirmation": confirmation,
            "collateral_lost_count": 0, "added_count": 0, "cli": {"exit_code": None},
            "untrusted_content": results.untrusted(collateral_lost=[], added=[],
                                                   cli_output_tail=""),
            "skipped_invalid_names": 0,
            "redaction": {"enabled": ctx.settings.redact, "counts": {}}}
    return results.success(DELETE_TOOL, body)


async def run_delete(ctx: ToolContext, context: Any, call: CallInfo, workspace: str,
                     confirm: bool) -> CallToolResult:
    """I.3 with every outcome audited; the CLI runs only after the accepted line."""
    audit = _Audit(ctx, call, tool=DELETE_TOOL, event=audit_mod.DELETE_REQUEST,
                   workspace=workspace, empty=_DELETE_EMPTY)
    try:
        await asyncio.to_thread(ctx.maintain)
        if confirm is not True:  # step 1
            raise ToolError("confirmation_required", "confirm must be true.",
                            "Only delete when the operator explicitly asks for it.")
        plan = await asyncio.to_thread(_prepare_delete, ctx, workspace, audit)
        confirmation = await _confirm(  # step 8
            context, audit, workspace=workspace, message=plan.message,
            field=DELETE_FIELD.format(workspace=workspace),
            unsupported_hint=DELETE_UNSUPPORTED_HINT.format(workspace=workspace))
        audit.handed_off = True
        if confirmation != "confirmed":
            await asyncio.to_thread(audit.declined, confirmation)
            return _not_deleted(ctx, workspace, confirmation)
        return await asyncio.to_thread(_execute_delete, ctx, workspace, plan, audit)
    except asyncio.CancelledError:
        audit.cancelled()
        raise
    except ToolError as err:
        audit.handed_off = True
        await asyncio.to_thread(audit.refusal, err)
        return results.from_error(DELETE_TOOL, err)
    except Exception:
        audit.handed_off = True
        await asyncio.to_thread(audit.unexpected)
        raise  # results.guarded turns it into internal_error (details to stderr only)


# --- export_workspace (I.4) -------------------------------------------------------------------

_EXPORT_EMPTY = {"path": None, "bytes": None, "sha256": None, "files": None,
                 "include_credentials": None}


def _prepare_export(ctx: ToolContext, workspace: str, include_credentials: bool) -> str:
    """I.4 step 1 up to the elicitation; returns the confirmation message."""
    ws_fd = _open_workspace(ctx, workspace)
    try:
        _check_not_busy(ctx, workspace, ws_fd)
        _check_state_and_audit(ctx, "exported")
        summary = export.summarize(ws_fd, include_credentials=include_credentials)
    finally:
        os.close(ws_fd)
    return EXPORT_MESSAGE.format(
        workspace=workspace, files=summary.files_text(), size=summary.size_text(),
        exports_dir=os.path.join(ctx.settings.state_dir, state.EXPORTS_SUBDIR),
        credentials=CREDENTIALS_INCLUDED if include_credentials else CREDENTIALS_EXCLUDED)


def _execute_export(ctx: ToolContext, workspace: str, include_credentials: bool,
                    audit: _Audit) -> CallToolResult:
    """I.4 steps 1 (after the elicitation) to 6. The workspace is opened, and found idle,
    again: the human may take minutes to answer."""
    settings = ctx.settings
    ws_fd = _open_workspace(ctx, workspace)
    try:
        _check_not_busy(ctx, workspace, ws_fd)
        _check_state_and_audit(ctx, "exported")
        try:
            exports_fd = state.open_private_subdir(settings.state_dir, state.EXPORTS_SUBDIR)
        except state.StateDirInsecure as exc:
            raise ToolError("state_dir_insecure", "The server state directory is not "
                            "private.", f"Fix {settings.state_dir}: {exc}") from exc
        try:
            audit.accept(known={"include_credentials": include_credentials})
            try:
                written = _write_archive(ws_fd, workspace, exports_fd, include_credentials)
            except export.ExportTooLarge as exc:
                raise ToolError("export_too_large", f"The workspace is too large to export "
                                f"({exc}).", "Archive the workspace directory yourself.") \
                    from exc
            except export.ExportFailed as exc:
                raise ToolError("export_failed", f"The export failed: {exc}; no archive was "
                                "kept.", "Retry later; check the server log.") from exc
        finally:
            os.close(exports_fd)
    finally:
        os.close(ws_fd)
    path = os.path.join(settings.state_dir, state.EXPORTS_SUBDIR, written.name)
    audit.finish("completed", reason_code=None, reason="workspace exported", result={
        "path": path, "bytes": written.bytes, "sha256": written.sha256,
        "files": written.files, "include_credentials": include_credentials})
    body = {"workspace": workspace, "exported": True, "confirmation": "confirmed",
            "path": path, "bytes": written.bytes, "sha256": written.sha256,
            "files": written.files, "directories": written.directories,
            "skipped": written.skipped.to_json(), "include_credentials": include_credentials}
    return results.success(EXPORT_TOOL, body)


def _pause(seconds: float) -> None:
    time.sleep(seconds)


def _write_archive(ws_fd: int, workspace: str, exports_fd: int,
                   include_credentials: bool) -> export.ExportResult:
    """The fixed name has one-second resolution: a second export of the same workspace
    within that second waits for the next one instead of failing."""
    for attempt in range(EXPORT_NAME_ATTEMPTS):
        name = export.archive_name(workspace, time.time())
        try:
            return export.write_archive(ws_fd, workspace, exports_fd, name,
                                        include_credentials=include_credentials)
        except export.ArchiveExists:
            if attempt + 1 == EXPORT_NAME_ATTEMPTS:
                raise export.ExportFailed("an archive with the same name exists") from None
            _pause(1.0 - time.time() % 1.0 + 0.01)
    raise AssertionError("unreachable")


def _not_exported(workspace: str, include_credentials: bool,
                  confirmation: str) -> CallToolResult:
    body = {"workspace": workspace, "exported": False, "confirmation": confirmation,
            "path": None, "bytes": None, "sha256": None, "files": None, "directories": None,
            "skipped": export.Skipped().to_json(), "include_credentials": include_credentials}
    return results.success(EXPORT_TOOL, body)


async def run_export(ctx: ToolContext, context: Any, call: CallInfo, workspace: str,
                     include_credentials: bool) -> CallToolResult:
    """I.4 with every outcome audited; nothing is written before the accepted line."""
    empty = dict(_EXPORT_EMPTY, include_credentials=include_credentials)
    audit = _Audit(ctx, call, tool=EXPORT_TOOL, event=audit_mod.EXPORT_REQUEST,
                   workspace=workspace, empty=empty)
    try:
        await asyncio.to_thread(ctx.maintain)
        message = await asyncio.to_thread(_prepare_export, ctx, workspace, include_credentials)
        field = (EXPORT_FIELD_INCLUDED if include_credentials
                 else EXPORT_FIELD_EXCLUDED).format(workspace=workspace)
        confirmation = await _confirm(context, audit, workspace=workspace, message=message,
                                      field=field, unsupported_hint=EXPORT_UNSUPPORTED_HINT)
        audit.handed_off = True
        if confirmation != "confirmed":
            await asyncio.to_thread(audit.declined, confirmation)
            return _not_exported(workspace, include_credentials, confirmation)
        return await asyncio.to_thread(_execute_export, ctx, workspace, include_credentials,
                                       audit)
    except asyncio.CancelledError:
        audit.cancelled()
        raise
    except ToolError as err:
        audit.handed_off = True
        await asyncio.to_thread(audit.refusal, err)
        return results.from_error(EXPORT_TOOL, err)
    except Exception:
        audit.handed_off = True
        await asyncio.to_thread(audit.unexpected)
        raise  # results.guarded turns it into internal_error (details to stderr only)


# --- registration (I.1) -----------------------------------------------------------------------

def register(mcp: FastMCP, ctx: ToolContext) -> None:
    @mcp.tool(name=DELETE_TOOL, title="Delete workspace", description=DELETE_DESCRIPTION,
              annotations=ToolAnnotations(title="Delete workspace", readOnlyHint=False,
                                          destructiveHint=True, idempotentHint=True,
                                          openWorldHint=False))
    @results.guarded(DELETE_TOOL)
    async def delete_workspace(
        context: Context,
        workspace: Annotated[str, Field(pattern=WORKSPACE_PATTERN, description=WORKSPACE_PARAM)],
        confirm: Annotated[bool, Field(strict=True, description=CONFIRM_PARAM)],
    ) -> CallToolResult:
        call = ctx.begin_call(context)
        return await run_delete(ctx, context, call, workspace, confirm)

    @mcp.tool(name=EXPORT_TOOL, title="Export workspace", description=EXPORT_DESCRIPTION,
              annotations=ToolAnnotations(title="Export workspace", readOnlyHint=False,
                                          destructiveHint=False, idempotentHint=False,
                                          openWorldHint=False))
    @results.guarded(EXPORT_TOOL)
    async def export_workspace(
        context: Context,
        workspace: Annotated[str, Field(pattern=WORKSPACE_PATTERN, description=WORKSPACE_PARAM)],
        include_credentials: Annotated[bool, Field(
            strict=True, description=INCLUDE_CREDENTIALS_PARAM)] = False,
    ) -> CallToolResult:
        call = ctx.begin_call(context)
        return await run_export(ctx, context, call, workspace, include_credentials)
