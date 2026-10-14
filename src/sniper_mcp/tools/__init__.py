# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""MCP tool groups and the state they share. Each module exposes ``register(mcp, ctx)``."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from sniper_mcp import audit as audit_mod
from sniper_mcp import edition, jobs, lootfs, scope, state
from sniper_mcp import plugins as plugins_mod
from sniper_mcp.edition import Detection
from sniper_mcp.settings import Settings
from sniper_mcp.state import StateDirStatus

log = logging.getLogger("sn1per-mcp")

_REAPER_JOIN_SECONDS = 2.0


@dataclass(frozen=True)
class CallInfo:
    """The JSON-RPC id and client of one tool call (audit ``request_id`` and ``client``)."""

    request_id: str | int | None = None
    client: dict[str, str] | None = None


def call_info(context: Any) -> CallInfo:
    """Read the request id and the initialize clientInfo from a FastMCP ``Context``."""
    if context is None:
        return CallInfo()
    try:
        request_context = context.request_context
    except (AttributeError, LookupError, ValueError):
        return CallInfo()
    request_id = getattr(request_context, "request_id", None)
    if not isinstance(request_id, (str, int)) or isinstance(request_id, bool):
        request_id = None
    client = None
    params = getattr(getattr(request_context, "session", None), "client_params", None)
    info = getattr(params, "clientInfo", None)
    if info is not None:
        client = audit_mod.client_object(getattr(info, "name", None),
                                         getattr(info, "version", None))
    return CallInfo(request_id=request_id, client=client)


@dataclass
class ToolContext:
    """What the tools of one server process share.

    ``detection`` is the startup detection (P.4 step 5); it fixes the ``mode``
    enum of ``sniper_scan`` (D.1). Tools re-run detection at call time (C.2).
    ``audit`` is this process's audit writer (one ``session``), ``jobs`` the
    job records of the state directory, ``scope_tracker`` the last scope
    digest seen (F.1), ``rate_limiter`` the F.8 window and ``loot`` the loot base
    with its identity pinned at startup (J.1).
    """

    settings: Settings
    state_dir: StateDirStatus
    detection: Detection
    started_monotonic: float = field(default_factory=time.monotonic)
    destructive_tools: tuple[str, ...] = ()
    audit: audit_mod.AuditLog = field(init=False)
    jobs: jobs.JobStore = field(init=False)
    scope_tracker: scope.ScopeTracker = field(init=False)
    rate_limiter: scope.RateLimiter = field(init=False)
    loot: lootfs.LootBase = field(init=False)
    plugins: list[plugins_mod.PluginRecord] = field(default_factory=list)

    def __post_init__(self) -> None:
        settings = self.settings
        self.audit = audit_mod.AuditLog(settings.audit_log,
                                        allow_any_target=settings.allow_any_target,
                                        allow_intrusive=settings.allow_intrusive)
        self.jobs = jobs.JobStore(state_dir=settings.state_dir, home=settings.home,
                                  euid=settings.euid,
                                  workspace_dir=lambda: edition.workspace_dir(settings),
                                  audit=self.audit,
                                  allow_any_target=settings.allow_any_target,
                                  allow_intrusive=settings.allow_intrusive)
        self.scope_tracker = scope.ScopeTracker()
        self.rate_limiter = scope.RateLimiter()
        # J.1: the loot base is resolved once and its identity pinned at startup (P.4 step 5).
        self.loot = lootfs.LootBase(self.detection.loot_base)
        self.loot.record_if_exists()
        self._stop = threading.Event()
        self._reaper: threading.Thread | None = None

    # --- per call ------------------------------------------------------------------------
    def begin_call(self, context: Any) -> CallInfo:
        """The request id and client of this call; the client is kept for audit lines
        that no call owns (``scan_exit`` written by the reaper)."""
        call = call_info(context)
        if call.client is not None:
            self.audit.client = call.client
        return call

    def maintain(self) -> None:
        """Reap this process's finished scans; prune old jobs at most once per hour."""
        try:
            self.jobs.poll_children()
            self.jobs.prune_if_due(self.settings.log_retention_days)
        except Exception:  # noqa: BLE001 - maintenance never fails a tool call
            log.exception("job maintenance failed")

    def refresh_state_dir(self) -> StateDirStatus:
        """L.1 checks again at call time (the directory may have been replaced)."""
        self.state_dir = state.prepare_state_dir(self.settings.state_dir)
        return self.state_dir

    def read_scope(self, call: CallInfo | None = None, *,
                   record_change: bool = True) -> scope.ScopeSnapshot:
        """Re-read the scope (F.1); a changed digest is audited before it is acted on."""
        snapshot = scope.load(self.settings)
        if record_change:
            self.note_scope(snapshot, call)
        return snapshot

    def note_scope(self, snapshot: scope.ScopeSnapshot, call: CallInfo | None = None) -> bool:
        """Write ``scope_changed`` when the digest differs from the last one seen (G.4).

        Returns False while a change could not be recorded; it stays pending and
        the next call tries again.
        """
        call = call or CallInfo()
        with self.scope_tracker.lock:
            changed, previous = self.scope_tracker.pending_change(snapshot.digest)
            if not changed:
                return True
            written = self.audit.write_best_effort(
                audit_mod.SCOPE_CHANGED,
                result={"old_digest": previous, "new_digest": snapshot.digest,
                        "source": snapshot.source},
                request_id=call.request_id, client=call.client)
            if written:
                self.scope_tracker.commit(snapshot.digest)
            return written

    # --- lifecycle (P.4 steps 10-11, G.4, L.7, L.8) --------------------------------------------
    def warning_codes(self, snapshot: scope.ScopeSnapshot | None = None) -> list[str]:
        """Warning codes for the ``server_start`` line."""
        codes = [code for code, _ in self.detection.warnings]
        codes += list(self.state_dir.warnings)
        if snapshot is not None:
            codes += snapshot.warning_codes()
        if self.settings.allow_any_target:
            codes.append("allow_any_target")
        if self.audit.status().mode_not_fixed:
            codes.append("audit_log_mode_not_fixed")
        if not self.settings.redact:
            codes.append("redaction_disabled")
        codes += [w["code"] for w in plugins_mod.status_warnings(self.plugins)]
        return codes

    def start(self) -> None:
        """Write ``server_start``, run the retention sweep and start the reaper."""
        settings = self.settings
        snapshot = scope.load(settings)
        with self.scope_tracker.lock:
            self.scope_tracker.pending_change(snapshot.digest)  # the baseline
        self.audit.write_best_effort(audit_mod.SERVER_START, result={
            "settings": {
                "scan_enabled": settings.scan_enabled,
                "needs_sudo": settings.needs_sudo and settings.euid != 0,
                "scope_configured": snapshot.configured,
                "scope_digest": snapshot.digest,
                "scope_source": snapshot.source,
                "allow_any_target": settings.allow_any_target,
                "allow_intrusive": settings.allow_intrusive,
                "dns_policy": settings.dns_policy,
                "cidr_cap": settings.cidr_cap,
                "max_concurrent_scans": settings.max_concurrent_scans,
                "destructive_enabled": settings.enable_destructive,
                "redact": settings.redact,
                "reveal_secrets": settings.reveal_secrets,
            },
            "plugins": [record.start_object() for record in self.plugins],
            "warnings": self.warning_codes(snapshot),
        })
        try:
            self.jobs.prune_if_due(settings.log_retention_days)
        except Exception:  # noqa: BLE001 - retention never stops the server
            log.exception("retention sweep failed")
        if self._reaper is None:
            self._stop.clear()
            self._reaper = threading.Thread(target=self._reap_loop, name="sn1per-mcp-reaper",
                                            daemon=True)
            self._reaper.start()

    def _reap_loop(self) -> None:
        while True:
            try:
                self.jobs.sweep()
            except Exception:  # noqa: BLE001 - the reaper keeps running
                log.exception("job reaper failed")
            if self._stop.wait(jobs.REAPER_INTERVAL_SECONDS):
                return

    def stop(self) -> None:
        """Stop the reaper and write ``server_stop`` (clean shutdown, best effort)."""
        self._stop.set()
        reaper = self._reaper
        self._reaper = None
        if reaper is not None and reaper is not threading.current_thread():
            reaper.join(_REAPER_JOIN_SECONDS)
        self.audit.write_best_effort(audit_mod.SERVER_STOP, result={})
