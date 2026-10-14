# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Command line and startup (contract A.1, A.3, B.4, B.5, P.4, O.5 P0-02, P0-03)."""

from __future__ import annotations

import importlib.metadata
import json
import subprocess
import sys

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from sniper_mcp import __version__, server


def run(capsys, *argv: str) -> tuple[int, str, str]:
    code = server.run(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_version(capsys):
    assert run(capsys, "--version") == (0, "sn1per-mcp 0.9.0\n", "")


def test_help(capsys):
    code, out, err = run(capsys, "--help")
    assert code == 0 and out.startswith("usage: sn1per-mcp") and err == ""


@pytest.mark.parametrize("argv", [["--bogus"], ["serve"], ["--json"], ["--env-file"],
                                  ["--ver"], ["--transport", "sse"], ["--port", "8090"],
                                  ["--env-file", "/a", "--env-file", "/b"]])
def test_usage_errors_exit_2(capsys, argv):
    code, out, err = run(capsys, *argv)
    assert code == 2 and out == "" and "usage: sn1per-mcp" in err


@pytest.mark.parametrize("transport", ["sse", "streamable-http", "http"])
def test_non_stdio_transport_exits_2_before_serving(iso, capsys, transport):
    iso.setenv(MCP_TRANSPORT=transport)
    code, out, err = run(capsys)
    assert code == 2 and out == ""
    assert err == "sn1per-mcp: config error: MCP_TRANSPORT: only stdio is supported; unset it\n"


def test_config_error_exits_2(iso, capsys):
    iso.setenv(SNIPER_MCP_CIDR_CAP="99", SNIPER_SCAN_ENABLED="perhaps")
    code, _, err = run(capsys, "--check")
    assert code == 2
    assert err.splitlines() == [
        "sn1per-mcp: config error: SNIPER_SCAN_ENABLED: expected one of 1, true, yes, on, "
        "0, false, no, off",
        "sn1per-mcp: config error: SNIPER_MCP_CIDR_CAP: expected a base-10 integer from 8 to 32",
    ]


def test_oversized_integer_exits_2_with_a_config_error(iso, capsys):
    iso.setenv(SNIPER_MCP_CIDR_CAP="9" * 5000)
    code, out, err = run(capsys, "--check")
    assert code == 2 and out == ""
    assert err == ("sn1per-mcp: config error: SNIPER_MCP_CIDR_CAP: expected a base-10 integer "
                   "from 8 to 32\n")


def test_oversized_integer_in_the_env_file_exits_2(iso, capsys):
    env_file = iso.tmp / "env"
    env_file.write_text("SNIPER_MCP_LOG_RETENTION_DAYS=" + "9" * 5000 + "\n")
    env_file.chmod(0o600)
    code, out, err = run(capsys, "--env-file", str(env_file), "--check")
    assert code == 2 and out == ""
    assert err == ("sn1per-mcp: config error: SNIPER_MCP_LOG_RETENTION_DAYS: expected a "
                   "base-10 integer from 0 to 3650\n")


def test_removed_variables_warn_on_stderr(iso, capsys):
    iso.setenv(RAG_TIMEOUT="30", SNIPER_SCAN_ENABLED="false")
    code, _, err = run(capsys, "--check")
    assert code == 1
    assert "sn1per-mcp: warning: RAG_TIMEOUT is no longer supported and is ignored" in err


def test_removed_variable_warning_precedes_a_config_error(iso, capsys):
    """P.4 step 3 runs before step 4: the warning is printed even when step 4 fails."""
    iso.setenv(MCP_PORT="9000", SNIPER_MCP_CIDR_CAP="99")
    code, out, err = run(capsys, "--check")
    assert code == 2 and out == ""
    assert err.splitlines() == [
        "sn1per-mcp: warning: MCP_PORT is no longer supported and is ignored",
        "sn1per-mcp: config error: SNIPER_MCP_CIDR_CAP: expected a base-10 integer from 8 to 32",
    ]


def test_check_reports_unconfigured_scope(iso, capsys):
    code, out, _ = run(capsys, "--check")
    assert code == 1
    assert "scanning: unavailable (scope_not_configured)" in out
    assert f"CLI realpath (the path a sudoers rule must name): {iso.cli_path}" in out


def test_check_ready_with_scope_and_sudo(iso, capsys):
    iso.setenv(SNIPER_MCP_SCOPE="app.example")
    code, out, _ = run(capsys, "--check")
    assert code == 0, out
    assert "scanning: ready" in out
    assert iso.calls("sudo") == [[str(iso.sudo_path), "-n", "-l", str(iso.cli_path)]]
    assert iso.calls("sniper") == []  # --check never runs the CLI


def test_check_reports_sudo_not_configured_with_the_sudoers_line(iso, capsys):
    import os
    import pwd

    iso.setenv(SNIPER_MCP_SCOPE="app.example")
    iso.set_knobs(sudo_list_exit=1)
    from sniper_mcp.tools import status

    status.clear_sudo_cache()
    code, out, _ = run(capsys, "--check")
    assert code == 1
    user = pwd.getpwuid(os.geteuid()).pw_name
    assert f"\n{user} ALL=(root) NOPASSWD: {iso.cli_path}\n" in out
    assert "sudo_not_configured" in out


def test_check_without_scanning_never_calls_sudo(iso, capsys):
    iso.setenv(SNIPER_SCAN_ENABLED="false", SNIPER_MCP_SCOPE="app.example")
    code, out, _ = run(capsys, "--check")
    assert code == 1 and "scan_disabled" in out
    assert iso.calls() == []


def test_check_json(iso, capsys):
    iso.setenv(SNIPER_SCAN_ENABLED="false")
    code, out, _ = run(capsys, "--check", "--json")
    data = json.loads(out)
    assert code == 1
    assert data["schema_version"] == "1" and data["tool"] == "sniper_status"
    assert data["server"]["version"] == __version__
    assert data["scan"]["disabled_reason"] == "scan_disabled"


def test_check_sees_the_env_file(iso, capsys):
    env_file = iso.tmp / "env"
    env_file.write_text('SNIPER_MCP_SCOPE="app.example"\n')
    env_file.chmod(0o600)
    code, out, _ = run(capsys, "--env-file", str(env_file), "--check")
    assert code == 0, out
    assert "scope: configured" in out


def test_env_file_errors_exit_2(iso, capsys):
    env_file = iso.tmp / "env"
    env_file.write_text("SNIPER_MCP_SCOPPE=app.example\n")
    env_file.chmod(0o600)
    code, _, err = run(capsys, "--env-file", str(env_file), "--check")
    assert code == 2
    assert err.startswith("sn1per-mcp: config error: SNIPER_MCP_SCOPPE: unknown key")


def test_check_prepares_a_private_state_dir(iso, capsys):
    run(capsys, "--check")
    assert (iso.state_dir / "jobs").is_dir() and (iso.state_dir / "exports").is_dir()
    assert iso.state_dir.stat().st_mode & 0o777 == 0o700


def test_console_scripts_point_at_main():
    scripts = {ep.name: ep.value for ep in importlib.metadata.entry_points(
        group="console_scripts") if ep.value.startswith("sniper_mcp")}
    assert scripts == {"sn1per-mcp": "sniper_mcp.server:main",
                       "sniper-mcp-server": "sniper_mcp.server:main"}


# --- guarded child processes (stdio smoke, P.5 step 3 isolation) --------------
# Each child runs in the test's temporary directory: an inherited working
# directory under $HOME would be protected in the child, whose imports list it.

def _smoke_env(iso) -> dict[str, str]:
    return iso.child_env(SNIPER_SCAN_ENABLED="false", SNIPER_BIN="/nonexistent/sniper",
                         SNIPER_MCP_SCOPE="", SNIPER_INSTALL_DIR=str(iso.install_dir),
                         SNIPER_LOOT_BASE=str(iso.loot_base),
                         HOME=str(iso.home), XDG_STATE_HOME=str(iso.tmp / "xdg-state"))


def test_python_m_version_in_a_guarded_child(iso):
    result = subprocess.run([sys.executable, "-m", "sniper_mcp", "--version"],
                            env=_smoke_env(iso), cwd=str(iso.tmp), capture_output=True,
                            text=True, timeout=60, check=False)
    assert (result.returncode, result.stdout) == (0, "sn1per-mcp 0.9.0\n"), result.stderr


def test_python_m_transport_refusal_in_a_guarded_child(iso):
    env = _smoke_env(iso)
    env["MCP_TRANSPORT"] = "sse"
    result = subprocess.run([sys.executable, "-m", "sniper_mcp"], env=env, input="",
                            cwd=str(iso.tmp), capture_output=True, text=True, timeout=60,
                            check=False)
    assert result.returncode == 2 and result.stdout == ""


async def test_stdio_initialize_and_tools_list(iso):
    params = StdioServerParameters(command=sys.executable, args=["-m", "sniper_mcp"],
                                   env=_smoke_env(iso), cwd=str(iso.tmp))
    async with stdio_client(params) as (read, write), ClientSession(read, write) as client:
        init = await client.initialize()
        tools = await client.list_tools()
        status = await client.call_tool("sniper_status", {})
    assert init.serverInfo.name == "sn1per-mcp"
    assert init.serverInfo.version == __version__
    assert {t.name for t in tools.tools} == {
        "sniper_status", "sniper_scan", "scan_status", "cancel_scan", "list_workspaces",
        "get_findings", "get_ports", "get_subdomains", "get_technologies", "grep_loot"}
    assert status.isError is False
    assert status.structuredContent["scan"]["disabled_reason"] == "scan_disabled"


def test_check_is_not_ready_with_the_placeholder_scope(iso, capsys):
    iso.setenv(SNIPER_MCP_SCOPE="<authorized-targets>")
    code, out, _ = run(capsys, "--check")
    assert code == 1, out
    assert "scope_invalid" in out and "scanning: ready" not in out
    assert 'invalid entries: "<authorized-targets>"' in out
    assert iso.calls("sniper") == []
