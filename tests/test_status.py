# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""``sniper_status`` (contract H.5, C.4, D; O.5 P0-15 for this tool, A-42, docs placeholders).

The scope object comes from ``sniper_mcp.scope``; its parsing and matching rules
are tested in tests/test_scope.py.
"""

from __future__ import annotations

import json
import os

import mcp.types as mcp_types
import pytest

from sniper_mcp import edition, jobs
from sniper_mcp.tools import status
from tests import support

DESCRIPTION = (
    "Report what this server can do on this host: the detected Sn1per edition and engine "
    "version, whether scanning is enabled and why not, the scan modes available here with "
    "their activity class, the configured target scope, concurrency, redaction and audit "
    "settings, and loaded plugins. Call this first, and again whenever a scan is refused. "
    "Read-only; sends no network traffic."
)
TOP_KEYS = ["schema_version", "tool", "server", "client", "edition", "paths", "scan", "modes",
            "scope", "destructive", "redaction", "plugins", "workspaces", "notes", "warnings"]


@pytest.fixture(autouse=True)
def _fresh():
    edition.clear_cache()
    status.clear_sudo_cache()
    yield
    jobs.terminate_all()
    jobs.JOBS.clear()


async def test_description_title_and_no_parameters():
    async with support.session() as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    tool = tools["sniper_status"]
    assert tool.description == DESCRIPTION
    assert tool.inputSchema.get("properties", {}) == {}
    assert not tool.inputSchema.get("required")


async def test_payload_shape(iso):
    iso.use_install("enterprise")
    iso.copy_loot("se-11.x")
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test,192.0.2.0/24,!dev.app.scan.test",
               SNIPER_MCP_AUTHORIZATION_REF="SOW-2026-114")
    payload, is_error = await support.call("sniper_status")
    assert not is_error
    assert list(payload) == TOP_KEYS
    assert set(payload["server"]) == {"name", "version", "python", "mcp_sdk", "transport",
                                      "pid"}
    assert payload["server"]["name"] == "sn1per-mcp" and payload["server"]["pid"] == os.getpid()
    assert payload["server"]["transport"] == "stdio"
    assert payload["edition"] == {
        "label": "enterprise", "display_name": "Sn1per Enterprise", "source": "detected",
        "dialect": "11.x", "engine_version": "11.0",
        "engine_changelog_version": "11.3 [Unreleased]",
        "markers": ["VER=11.0", "pro/index.php:Sn1per Enterprise"], "supported": True}
    assert payload["paths"] == {
        "sniper_bin": str(iso.cli_link), "sniper_bin_realpath": str(iso.cli_path),
        "install_dir": str(iso.install_dir), "cli_install_dir": str(iso.install_dir),
        "loot_base": str(iso.loot_base), "workspace_dir": str(iso.workspace_dir),
        "workspace_dir_exists": True, "state_dir": str(iso.state_dir),
        "audit_log": str(iso.audit_log)}
    assert payload["scan"] == {
        "enabled": True, "disabled_reason": None, "needs_sudo": True,
        "sudo": {"status": "ok", "hint": None}, "engine_path_ok": True, "max_concurrent": 2,
        "running_jobs": 0, "rate_limit": {"calls": 6, "window_seconds": 60}}
    assert set(payload["scope"]) == {
        "configured", "valid", "sources", "file", "entries", "entries_total", "exclusions",
        "exclusions_total", "invalid_entries", "digest", "allow_any_target", "dns_policy",
        "cidr_cap", "authorization_ref"}
    assert payload["scope"]["entries"] == ["app.scan.test", "192.0.2.0/24"]
    assert payload["scope"]["exclusions"] == ["dev.app.scan.test"]
    assert payload["scope"]["authorization_ref"] == "SOW-2026-114"
    assert len(payload["scope"]["digest"]) == 16
    assert payload["destructive"] == {"enabled": False, "tools": [], "client_elicitation": False}
    assert payload["redaction"] == {"enabled": True, "reveal_secrets": False}
    assert payload["plugins"] == [] and payload["workspaces"] == {"count": 2}
    assert payload["notes"] == status.NOTES
    assert payload["scope"]["file"] is None and payload["scope"]["sources"] == ["env"]
    assert payload["scope"]["valid"] is True and payload["scope"]["entries_total"] == 2
    assert payload["warnings"] == [{
        "code": "domain_exclusions_not_applied_to_ip_targets",
        "message": "Domain exclusions such as dev.app.scan.test do not apply to IP or CIDR "
                   "targets."}]
    assert iso.calls("sniper") == []


async def test_modes_object_with_the_gate_off(iso):
    payload, _ = await support.call("sniper_status")
    modes = payload["modes"]
    assert modes["default"] == "stealth" and modes["allow_intrusive"] is False
    assert [m["name"] for m in modes["available"]] == ["stealth", "recon_passive", "discover"]
    stealth = modes["available"][0]
    assert stealth == {
        "name": "stealth", "class": "active",
        "flags": ["port_scan", "web_probe", "vuln_templates", "third_party_osint"],
        "requires_port": False, "target_types": ["hostname", "ipv4"],
        "description": stealth["description"]}
    assert stealth["description"].startswith("Lightest scan (profile conf/flyover)")
    unavailable = {m["name"]: m for m in modes["unavailable"]}
    assert list(unavailable) == ["fullportscan", "normal", "web", "port", "vulnscan",
                                 "full_scan"]
    assert unavailable["normal"] == {
        "name": "normal", "class": "intrusive", "reason_code": "mode_not_allowed",
        "reason": "Intrusive modes are disabled. The operator can enable them with "
                  "SNIPER_MCP_ALLOW_INTRUSIVE=1."}


async def test_modes_object_with_the_gate_on_and_a_missing_file(iso):
    iso.use_install("ce-9.2")
    (iso.install_dir / "modes" / "webscan.sh").unlink()
    iso.setenv(SNIPER_MCP_ALLOW_INTRUSIVE="1")
    payload, _ = await support.call("sniper_status")
    modes = payload["modes"]
    assert modes["allow_intrusive"] is True
    assert [m["name"] for m in modes["available"]] == [
        "stealth", "discover", "fullportonly", "vulnscan", "normal", "web", "port",
        "webporthttp", "webporthttps"]
    assert [m["requires_port"] for m in modes["available"]][-3:] == [True, True, True]
    assert modes["unavailable"] == [{
        "name": "webscan", "class": "intrusive", "reason_code": "engine_file_missing",
        "reason": "The engine files of this mode are missing on this host: modes/webscan.sh."}]


async def test_default_is_null_when_stealth_is_unavailable(iso):
    (iso.install_dir / "conf" / "flyover").unlink()
    payload, _ = await support.call("sniper_status")
    assert payload["modes"]["default"] is None
    assert [m["name"] for m in payload["modes"]["available"]] == ["recon_passive"]


async def test_detection_warnings_surface_in_status(iso):
    keys = iso.install_dir / "conf" / ".GLOBAL_API_KEYS"
    keys.write_text("")
    keys.chmod(0o777)
    iso.setenv(SNIPER_EDITION="ce")
    payload, _ = await support.call("sniper_status")
    codes = [w["code"] for w in payload["warnings"]]
    assert codes == ["edition_override_conflict", "install_world_writable"]
    assert payload["edition"]["label"] == "ce" and payload["edition"]["source"] == "override"


async def test_scan_disabled_skips_the_sudo_preflight(iso):
    iso.setenv(SNIPER_SCAN_ENABLED="false", SNIPER_MCP_SCOPE="app.scan.test")
    payload, _ = await support.call("sniper_status")
    assert payload["scan"]["enabled"] is False
    assert payload["scan"]["disabled_reason"] == "scan_disabled"
    assert payload["scan"]["sudo"] == {"status": "not_checked", "hint": None}
    assert iso.calls() == []


async def test_disabled_reason_follows_the_scan_check_order(iso):
    iso.setenv(SNIPER_BIN=str(iso.tmp / "no-such-cli"))
    payload, _ = await support.call("sniper_status")
    # cli_not_found (F.9 step 2) comes before scope_not_configured (step 7).
    assert payload["scan"]["disabled_reason"] == "cli_not_found"
    iso.setenv(SNIPER_BIN=str(iso.cli_link))
    payload, _ = await support.call("sniper_status")
    assert payload["scan"]["disabled_reason"] == "scope_not_configured"


async def test_not_root_reports_sudo_not_checked(iso):
    """H.5: not_needed means running as root; a non-root no-sudo server is not_checked."""
    iso.setenv(SNIPER_NEEDS_SUDO="false", SNIPER_MCP_SCOPE="app.scan.test")
    payload, _ = await support.call("sniper_status")
    assert payload["scan"]["disabled_reason"] == "not_root"
    assert payload["scan"]["needs_sudo"] is False
    assert payload["scan"]["sudo"]["status"] == "not_checked"


async def test_client_object_from_the_session(iso):
    async def elicit(context, params):  # pragma: no cover - never called here
        return mcp_types.ElicitResult(action="decline")

    info = mcp_types.Implementation(name="test-client", version="9.9.9")
    async with support.session(client_info=info, elicitation_callback=elicit) as client:
        result = await client.call_tool("sniper_status", {})
    payload = result.structuredContent
    assert payload["client"] == {"name": "test-client", "version": "9.9.9",
                                 "elicitation": True}
    assert payload["destructive"]["client_elicitation"] is True


async def test_check_json_has_no_client(iso, capsys):
    from sniper_mcp import server

    assert server.run(["--check", "--json"]) == 1
    import json

    document = json.loads(capsys.readouterr().out)
    assert list(document) == TOP_KEYS
    assert document["client"] is None and document["destructive"]["client_elicitation"] is None


# --- scope: A-42, the docs placeholders, the scope file and its warnings -------------

@pytest.mark.parametrize("scope", ["example.com", "app.scan.test,www.example.org",
                                   "EXAMPLE.NET.", "<authorized-targets>",
                                   "app.scan.test,bad..app.scan.test", "*.corp",
                                   "192.0.2.5/24", "0.0.0.0/0"])
async def test_invalid_scope_entries_are_listed(iso, scope):
    iso.setenv(SNIPER_MCP_SCOPE=scope)
    payload, _ = await support.call("sniper_status")
    assert payload["scope"]["valid"] is False and payload["scope"]["invalid_entries"]
    assert payload["scan"]["disabled_reason"] == "scope_invalid"
    reasons = {e["entry"]: e["reason"] for e in payload["scope"]["invalid_entries"]}
    for entry in reasons:
        if "example." in entry.lower():
            assert reasons[entry] == "always_denied_name"


async def test_server_json_placeholder_is_a_valid_scope(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.example,192.0.2.0/24")
    payload, _ = await support.call("sniper_status")
    assert payload["scope"]["valid"] is True and payload["scope"]["invalid_entries"] == []
    assert payload["scope"]["entries"] == ["app.example", "192.0.2.0/24"]
    assert payload["scan"]["enabled"] is True


async def test_always_denied_names_are_allowed_as_exclusions(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test,!example.com")
    payload, _ = await support.call("sniper_status")
    assert payload["scope"]["valid"] is True
    assert payload["scope"]["exclusions"] == ["example.com"]


async def test_scope_file_fields_and_writable_warning(iso):
    path = iso.tmp / "scope"
    path.write_text("app.scan.test # engagement\n!dev.app.scan.test\n")
    path.chmod(0o640)
    iso.setenv(SNIPER_MCP_SCOPE_FILE=str(path), SNIPER_MCP_SCOPE="192.0.2.0/24")
    payload, _ = await support.call("sniper_status")
    scope = payload["scope"]
    assert scope["sources"] == ["env", "file"]
    assert scope["file"] == {"path": str(path), "owner_uid": os.geteuid(), "mode": "0640",
                             "writable_by_server_user": True}
    assert scope["entries"] == ["192.0.2.0/24", "app.scan.test"]
    assert scope["exclusions"] == ["dev.app.scan.test"]
    codes = [w["code"] for w in payload["warnings"]]
    assert codes == ["scope_file_writable_by_server_user",
                     "domain_exclusions_not_applied_to_ip_targets"]


async def test_lab_override_without_scope_is_not_a_refusal(iso):
    iso.setenv(SNIPER_MCP_ALLOW_ANY_TARGET="1")
    payload, _ = await support.call("sniper_status")
    assert payload["scope"]["configured"] is False and payload["scope"]["valid"] is None
    assert payload["scope"]["allow_any_target"] is True
    assert payload["scan"]["enabled"] is True
    assert [w["code"] for w in payload["warnings"]] == ["allow_any_target"]


async def test_status_lists_at_most_100_entries_and_20_invalid(iso):
    good = ",".join(f"h{i}.app.scan.test" for i in range(150))
    bad = ",".join(f"bad{i}..app.scan.test" for i in range(30))
    iso.setenv(SNIPER_MCP_SCOPE=f"{good},{bad}")
    payload, _ = await support.call("sniper_status")
    scope = payload["scope"]
    assert len(scope["entries"]) == 100 and scope["entries_total"] == 150
    assert len(scope["invalid_entries"]) == 20 and scope["valid"] is False


async def test_running_jobs_counts_scans_that_are_alive(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    iso.resolve("app.scan.test", "203.0.113.10")
    iso.set_knobs(sleep=30)
    launched, _ = await support.call("sniper_scan", {"target": "app.scan.test"})
    assert launched["status"] == "launched"
    payload, _ = await support.call("sniper_status")
    assert payload["scan"]["running_jobs"] == 1


async def test_status_writes_scope_changed_but_check_does_not(iso, capsys):
    from sniper_mcp import server

    path = iso.tmp / "scope"
    path.write_text("app.scan.test\n")
    path.chmod(0o600)
    iso.setenv(SNIPER_MCP_SCOPE_FILE=str(path))
    async with support.session() as client:
        await client.call_tool("sniper_status", {})
        path.write_text("app.scan.test\napi.app.scan.test\n")
        await client.call_tool("sniper_status", {})
    events = [json.loads(line)["event"] for line in iso.audit_log.read_text().splitlines()]
    assert events.count("scope_changed") == 1
    size = iso.audit_log.stat().st_size
    path.write_text("app.scan.test\n")
    assert server.run(["--check"]) == 0
    assert iso.audit_log.stat().st_size == size


def test_client_elicitation_uses_the_form_predicate():
    """H.5 reports what the destructive tools can use (I.2): a URL-only client cannot
    answer the confirmation form, so it reports false in both places."""
    from types import SimpleNamespace

    from sniper_mcp.tools import destructive

    def context(elicitation):
        caps = SimpleNamespace(elicitation=elicitation)
        params = SimpleNamespace(capabilities=caps,
                                 clientInfo=SimpleNamespace(name="c", version="1"))
        session = SimpleNamespace(client_params=params)
        return SimpleNamespace(request_context=SimpleNamespace(session=session))

    shape = SimpleNamespace
    for elicitation, expected in [(shape(form=None, url={}), False),
                                  (shape(form=None, url=None), True),
                                  (shape(form={}, url={}), True), (None, False)]:
        ctx = context(elicitation)
        assert status.client_info(ctx)["elicitation"] is expected
        assert destructive.client_supports_form(ctx) is expected
