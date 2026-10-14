# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Model-facing text and the result envelope (contract H.1-H.16, N; O.5 P0-15, P1-01).

``tests/fixtures/golden/model_facing.json`` is a byte-for-byte copy of the contract's
tool titles and hints (H.3), descriptions (H.5-H.16), parameter descriptions (H.4,
H.6), per-tool error lists, the H.2 and H.2.1 code tables and both N instruction
variants. Its ``input_schema`` entries pin the reviewed listing for the default test
install (SE 11.0, intrusive modes off), so a removed or renamed parameter, a changed
bound or a changed default fails here (S.1).

Every tool call made through ``support.session`` is checked by
``support.check_result`` (P1-01); the tests below cover the refusal paths that no
other test reaches and prove the checker rejects a malformed envelope.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from mcp import types

from sniper_mcp import __version__, results
from sniper_mcp.tools import ToolContext, status
from tests import support

SRC = Path(__file__).resolve().parent.parent / "src" / "sniper_mcp"
GOLDEN = support.golden()
WS = "acme-2026q4"
HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")


async def _surface(iso, destructive: bool) -> tuple[types.InitializeResult, dict]:
    if destructive:
        iso.setenv(SNIPER_MCP_ENABLE_DESTRUCTIVE="1")
    async with support.session() as client:
        init = await client.initialize()
        listed = await client.list_tools()
    return init, {tool.name: tool for tool in listed.tools}


# --- N: server instructions -------------------------------------------------------------------

@pytest.mark.parametrize("destructive", [False, True])
async def test_instructions_match_n_byte_for_byte(iso, destructive):
    init, _ = await _surface(iso, destructive)
    expected = GOLDEN["instructions"]["base"]
    if destructive:
        expected += " " + GOLDEN["instructions"]["destructive_sentence"]
    assert init.instructions == expected
    assert init.serverInfo.name == "sn1per-mcp" and init.serverInfo.version == __version__


# --- H.3-H.16: tools/list ---------------------------------------------------------------------

@pytest.mark.parametrize("destructive", [False, True])
async def test_registered_tools_follow_h3(iso, destructive):
    _, tools = await _surface(iso, destructive)
    expected = {name for name, spec in GOLDEN["tools"].items()
                if destructive or spec["registered"] == "always"}
    assert set(tools) == expected


async def test_titles_hints_descriptions_and_parameters_are_golden(iso):
    _, tools = await _surface(iso, destructive=True)
    for name, spec in GOLDEN["tools"].items():
        tool = tools[name]
        assert tool.title == spec["title"], name
        assert tool.description == spec["description"], name
        # All four hints and the title are set explicitly (H.3), not left to defaults.
        sent = tool.annotations.model_dump(exclude_unset=True)
        assert sent == {"title": spec["title"], **{hint: spec[hint] for hint in HINTS}}, name
        properties = tool.inputSchema.get("properties", {})
        assert {p: s.get("description") for p, s in properties.items()} == spec["parameters"]
        assert tool.outputSchema is None, name  # H.1: no outputSchema in 0.9.0


async def test_input_schemas_are_golden(iso):
    _, tools = await _surface(iso, destructive=True)
    for name, spec in GOLDEN["tools"].items():
        assert tools[name].inputSchema == spec["input_schema"], name


def test_sniper_scan_description_keeps_authorization_and_polling_sentences():
    text = GOLDEN["tools"]["sniper_scan"]["description"]
    assert ("Only call this for targets the operator has explicitly authorized." in text)
    assert ("poll with scan_status(job_id) every few minutes, not in a loop." in text)
    assert "do not retry with alternate spellings, encodings, IP forms or wider ranges" in text


def test_error_and_warning_tables_match_h2():
    assert results.ERROR_CODES == GOLDEN["error_codes"]
    assert list(results.ERROR_CODES) == list(GOLDEN["error_codes"])  # table order
    assert results.WARNING_CODES == frozenset(GOLDEN["warning_codes"])
    for name, spec in GOLDEN["tools"].items():
        assert set(spec["errors"]) <= set(results.ERROR_CODES), name
    assert GOLDEN["tools"]["sniper_status"]["errors"] == ["internal_error"]  # H.5


# --- P1-01: the envelope checker itself -------------------------------------------------------

def _result(payload: dict | None, is_error: bool) -> types.CallToolResult:
    text = results.encode(payload) if payload is not None else "Input validation error"
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)],
                                structuredContent=payload, isError=is_error)


@pytest.mark.parametrize(("payload", "is_error"), [
    ({"tool": "get_ports", "schema_version": "1", "warnings": []}, False),
    ({"schema_version": "1", "tool": "get_ports", "warnings": []}, True),
    ({"schema_version": "1", "tool": "get_ports", "x": 1}, False),
    ({"schema_version": "1", "tool": "get_ports",
      "error": {"code": "out_of_scope", "message": "m", "hint": "h", "retry": "never",
                "details": {}}}, True),
    ({"schema_version": "1", "tool": "get_ports",
      "error": {"code": "workspace_not_found", "message": "m", "hint": "h", "retry": "never",
                "details": {}}}, True),
    ({"schema_version": "1", "tool": "get_ports",
      "error": {"code": "workspace_not_found", "message": "m", "hint": "h",
                "retry": "after_change", "details": {}}}, False),
    ({"schema_version": "1", "tool": "get_ports",
      "error": {"code": "workspace_not_found", "message": "m", "hint": "h",
                "retry": "after_change", "details": {}}, "warnings": []}, True),
    ({"schema_version": "1", "tool": "get_ports",
      "warnings": [{"code": "made_up", "message": "m"}]}, False),
    ({"schema_version": "1", "tool": "sniper_scan", "warnings": []}, False),
    (None, False),
])
def test_check_result_rejects_malformed_envelopes(payload, is_error):
    with pytest.raises(AssertionError):
        support.check_result("get_ports", _result(payload, is_error))


def test_check_result_accepts_the_two_shapes():
    support.check_result("get_ports", results.success("get_ports", {"x": 1}))
    support.check_result("get_ports", results.failure("get_ports", "workspace_not_found",
                                                      "No such workspace.", "List them."))
    support.check_result("get_ports", _result(None, True))  # SDK schema rejection (H.1)


async def test_every_session_call_is_checked(iso, monkeypatch):
    def broken(tool, body, warnings=()):
        return _result({"tool": tool, "schema_version": "1", "warnings": []}, False)

    monkeypatch.setattr(results, "success", broken)
    with pytest.raises(BaseException) as caught:  # anyio wraps it in an exception group
        await support.call("sniper_status")
    assert _contains(caught.value, AssertionError)


def _contains(exc: BaseException, kind: type[BaseException]) -> bool:
    if isinstance(exc, kind):
        return True
    return isinstance(exc, BaseExceptionGroup) and any(_contains(e, kind)
                                                       for e in exc.exceptions)


def test_only_results_builds_call_tool_results():
    """One helper builds every result (H.1, A-11): no other module constructs a
    ``CallToolResult`` or a ``TextContent``."""
    for path in sorted(SRC.rglob("*.py")):
        if path.name == "results.py":
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Call):
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                assert name not in ("CallToolResult", "TextContent"), (path, node.lineno)


# --- P1-01: refusal paths no other test reaches -----------------------------------------------

MINIMAL_ARGUMENTS = {
    "sniper_status": {},
    "list_workspaces": {},
    "scan_status": {"job_id": "0" * 16},
    "cancel_scan": {"job_id": "0" * 16},
    "get_findings": {"workspace": WS},
    "get_ports": {"workspace": WS},
    "get_subdomains": {"workspace": WS},
    "get_technologies": {"workspace": WS},
    "grep_loot": {"pattern": "x", "workspace": WS},
    "sniper_scan": {"target": "app.scan.test"},
    "delete_workspace": {"workspace": WS, "confirm": True},
    "export_workspace": {"workspace": WS},
}


async def test_every_tool_turns_an_unexpected_exception_into_internal_error(iso, monkeypatch,
                                                                            caplog):
    secret = "internal detail that must stay on stderr"

    def explode(self):
        raise RuntimeError(secret)

    iso.setenv(SNIPER_MCP_ENABLE_DESTRUCTIVE="1", SNIPER_MCP_SCOPE="app.scan.test")
    iso.make_workspace(WS)
    monkeypatch.setattr(ToolContext, "maintain", explode)
    status.clear_sudo_cache()
    answer = support.Elicitation("accept", WS)
    async with support.session(**answer.kwargs()) as client:
        names = [tool.name for tool in (await client.list_tools()).tools]
        assert set(names) == set(MINIMAL_ARGUMENTS)  # a new tool needs an entry here
        for name in names:
            result = await client.call_tool(name, MINIMAL_ARGUMENTS[name])
            payload = result.structuredContent
            assert result.isError and payload["error"]["code"] == "internal_error", name
            assert payload["error"]["retry"] == "later"
            assert secret not in json.dumps(payload) and secret not in result.content[0].text
    assert iso.calls() == []
    assert secret in caplog.text  # the details go to the server log (stderr) only


# Arguments outside the input schema never reach a handler: the SDK rejects them with
# isError and a text message, without structuredContent (the H.1 exception). For
# list_workspaces, get_subdomains, cancel_scan, delete_workspace and export_workspace this
# is the only way to get invalid_argument-like refusals: every argument is schema-bounded.
SCHEMA_VIOLATIONS = {
    "list_workspaces": {"limit": 0},
    "scan_status": {"job_id": "0" * 16, "log_lines": 201},
    "cancel_scan": {"job_id": "XYZ"},
    "get_findings": {"workspace": WS, "min_severity": "severe"},
    "get_ports": {"workspace": "-" + WS},
    "get_subdomains": {"workspace": WS, "limit": 1001},
    "get_technologies": {"workspace": WS, "host": ""},
    "grep_loot": {"pattern": "", "workspace": WS},
    "sniper_scan": {"target": "app.scan.test", "port": 65536},
    "delete_workspace": {"workspace": WS, "confirm": "yes"},
    "export_workspace": {"workspace": WS, "include_credentials": "yes"},
}


async def test_schema_violations_never_reach_a_handler(iso):
    iso.setenv(SNIPER_MCP_ENABLE_DESTRUCTIVE="1", SNIPER_MCP_SCOPE="app.scan.test")
    iso.make_workspace(WS)
    answer = support.Elicitation("accept", WS)
    async with support.session(**answer.kwargs()) as client:
        for name, arguments in SCHEMA_VIOLATIONS.items():
            result = await client.call_tool(name, arguments)
            assert result.isError is True and result.structuredContent is None, name
    assert answer.requests == [] and iso.calls() == []
    events = ([json.loads(line)["event"] for line in iso.audit_log.read_text().splitlines()]
              if iso.audit_log.exists() else [])
    assert not [event for event in events if event.endswith("_request")], events


async def test_get_technologies_rejects_an_invalid_host_filter(iso):
    iso.copy_loot()
    payload, is_error = await support.call("get_technologies",
                                           {"workspace": "app.example", "host": "*.app.example"})
    assert is_error and payload["error"]["code"] == "invalid_argument"
    assert payload["error"]["retry"] == "after_change"


async def test_cancel_scan_refuses_an_insecure_state_dir(iso):
    iso.state_dir.mkdir()
    (iso.state_dir / "jobs").symlink_to(iso.tmp)
    payload, is_error = await support.call("cancel_scan", {"job_id": "0" * 16})
    assert is_error and payload["error"]["code"] == "state_dir_insecure"
    assert payload["error"]["retry"] == "after_change"


@pytest.fixture
def destructive_ws(iso):
    status.clear_sudo_cache()
    iso.setenv(SNIPER_MCP_ENABLE_DESTRUCTIVE="1")
    iso.make_workspace(WS, {"notes.txt": "x\n"})
    return iso


async def _destructive_call(tool: str, arguments: dict, typed: str = WS,
                            **answer_kwargs) -> tuple[dict, bool, support.Elicitation]:
    answer = support.Elicitation("accept", typed, **answer_kwargs)
    payload, is_error = await support.call(tool, arguments, **answer.kwargs())
    return payload, is_error, answer


@pytest.mark.parametrize("tool", ["delete_workspace", "export_workspace"])
@pytest.mark.parametrize("workspace", ["acme..2026", "acme-2026."])
async def test_destructive_tools_apply_the_e3_checks_beyond_the_pattern(destructive_ws, tool,
                                                                        workspace):
    arguments = {"workspace": workspace}
    if tool == "delete_workspace":
        arguments["confirm"] = True
    payload, is_error, answer = await _destructive_call(tool, arguments, typed=workspace)
    assert is_error and payload["error"]["code"] == "invalid_workspace"
    assert answer.requests == [] and destructive_ws.calls() == []


@pytest.mark.parametrize("tool", ["delete_workspace", "export_workspace"])
async def test_destructive_tools_refuse_an_insecure_state_dir(destructive_ws, tool):
    destructive_ws.state_dir.mkdir()
    (destructive_ws.state_dir / "jobs").symlink_to(destructive_ws.tmp)
    arguments = {"workspace": WS, **({"confirm": True} if tool == "delete_workspace" else {})}
    payload, is_error, answer = await _destructive_call(tool, arguments)
    assert is_error and payload["error"]["code"] == "state_dir_insecure"
    assert answer.requests == [] and destructive_ws.calls() == []
    assert (destructive_ws.workspace_dir / WS).is_dir()


async def test_delete_not_root_when_sudo_is_switched_off(destructive_ws):
    destructive_ws.setenv(SNIPER_NEEDS_SUDO="false")
    payload, is_error, answer = await _destructive_call(
        "delete_workspace", {"workspace": WS, "confirm": True})
    assert is_error and payload["error"]["code"] == "not_root"
    assert answer.requests == [] and destructive_ws.calls() == []


async def test_delete_sudo_missing_is_a_refusal_not_an_exception(destructive_ws):
    destructive_ws.sudo_path.unlink()
    payload, is_error, answer = await _destructive_call(
        "delete_workspace", {"workspace": WS, "confirm": True})
    assert is_error and payload["error"]["code"] == "sudo_missing"
    assert answer.requests == [] and destructive_ws.calls() == []
    assert (destructive_ws.workspace_dir / WS).is_dir()


async def test_export_swapped_loot_base_is_loot_dir_changed(destructive_ws):
    iso = destructive_ws

    def swap() -> None:
        iso.loot_base.rename(iso.tmp / "loot-moved")
        (iso.loot_base / "workspace" / WS).mkdir(parents=True)

    async with support.session() as client:
        swap()
        result = await client.call_tool("export_workspace", {"workspace": WS})
    assert result.isError
    assert result.structuredContent["error"]["code"] == "loot_dir_changed"
    assert not (iso.state_dir / "exports").exists() or not any(
        (iso.state_dir / "exports").iterdir())


async def test_export_elicitation_timeout(destructive_ws, monkeypatch):
    import anyio

    from sniper_mcp.tools import destructive

    monkeypatch.setattr(destructive, "ELICITATION_TIMEOUT_SECONDS", 0.2)
    answer = support.Elicitation("accept", WS, delay=1.0)
    async with support.session(**answer.kwargs()) as client:
        result = await client.call_tool("export_workspace", {"workspace": WS})
        await anyio.sleep(1.5)  # let the late answer arrive while the session is open
    payload = result.structuredContent
    assert result.isError and payload["error"]["code"] == "elicitation_timeout"
    assert payload["error"]["retry"] == "later"
    exports = destructive_ws.state_dir / "exports"
    assert not exports.exists() or not any(exports.iterdir())
