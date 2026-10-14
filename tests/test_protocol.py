# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Protocol surface over an in-memory session (contract A.1, H.1, O.5 P0-02/03/14)."""

from __future__ import annotations

import ast
import json
from pathlib import Path

from sniper_mcp import __version__
from tests import support

SRC = Path(__file__).resolve().parent.parent / "src" / "sniper_mcp"


async def test_server_info():
    async with support.session() as client:
        init = await client.initialize()
    assert init.serverInfo.name == "sn1per-mcp"
    assert init.serverInfo.version == __version__ == "0.9.0"
    assert init.serverInfo.websiteUrl == "https://github.com/1N3/sn1per-mcp#readme"


# Instructions, titles, hints, descriptions and schemas: tests/test_conformance.py.


async def test_strict_booleans_reject_strings(iso):
    iso.setenv(SNIPER_MCP_ENABLE_DESTRUCTIVE="1")
    iso.make_workspace("acme-2026q4")
    async with support.session() as client:
        result = await client.call_tool("delete_workspace",
                                        {"workspace": "acme-2026q4", "confirm": "yes"})
    assert result.isError is True
    assert result.structuredContent is None
    assert iso.calls() == []
    assert (iso.workspace_dir / "acme-2026q4").is_dir()


async def test_result_envelope_shape():
    async with support.session() as client:
        result = await client.call_tool("sniper_status", {})
    payload = result.structuredContent
    assert result.isError is False
    assert list(payload)[:2] == ["schema_version", "tool"] and list(payload)[-1] == "warnings"
    assert payload["schema_version"] == "1" and payload["tool"] == "sniper_status"
    assert len(result.content) == 1 and result.content[0].type == "text"
    assert result.content[0].text == json.dumps(payload, ensure_ascii=False,
                                                separators=(",", ":"))


async def test_error_envelope_shape():
    async with support.session() as client:
        result = await client.call_tool("scan_status", {})
    payload = result.structuredContent
    assert result.isError is True
    assert set(payload) == {"schema_version", "tool", "error"}
    assert set(payload["error"]) == {"code", "message", "hint", "retry", "details"}
    assert payload["error"]["code"] == "invalid_argument"
    assert payload["error"]["retry"] == "after_change"


# P.3 module map, exactly.
MODULES = {
    "__init__.py", "__main__.py", "server.py", "settings.py", "paths.py", "edition.py",
    "state.py", "proc.py", "jobs.py", "results.py",
    "tools/__init__.py", "tools/status.py", "tools/scan.py", "tools/loot_tools.py",
    "tools/destructive.py", "modes.py", "targets.py", "scope.py", "audit.py", "lootfs.py",
    "parsers.py", "sanitize.py", "redact.py", "export.py", "plugins.py",
}


def test_only_module_map_modules_exist():
    present = {str(p.relative_to(SRC)) for p in SRC.rglob("*.py") if "__pycache__" not in p.parts}
    assert present == MODULES, present ^ MODULES


def test_no_network_transport_strings_or_http_client_in_src():
    for path in sorted(SRC.rglob("*.py")):
        text = path.read_text()
        assert "sse" not in [t.strip("'\"") for t in _strings(text)], path
        assert "streamable-http" not in text, path
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(a.name.split(".")[0] != "httpx" for a in node.names), path
            if isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] != "httpx", path


def _strings(text: str) -> list[str]:
    return [node.value for node in ast.walk(ast.parse(text))
            if isinstance(node, ast.Constant) and isinstance(node.value, str)]


async def test_in_memory_session_initialize_list_and_refusal(iso):
    """One client session over mcp.shared.memory: initialize, tools/list, a refusal."""
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    async with support.session() as client:
        init = await client.initialize()
        listed = await client.list_tools()
        refused = await client.call_tool("sniper_scan", {"target": "example.com",
                                                         "mode": "stealth"})
    assert init.serverInfo.name == "sn1per-mcp" and init.serverInfo.version == __version__
    assert init.capabilities.tools is not None
    assert {t.name for t in listed.tools} == {
        name for name, spec in support.golden()["tools"].items()
        if spec["registered"] == "always"}
    assert refused.isError is True
    error = refused.structuredContent["error"]
    assert (error["code"], error["retry"]) == ("always_denied", "never")
    assert refused.content[0].text == json.dumps(refused.structuredContent,
                                                 ensure_ascii=False, separators=(",", ":"))
    assert iso.calls() == []
