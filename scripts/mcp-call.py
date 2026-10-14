#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Small stdio MCP client: run initialize, then list tools or call one tool.

Used for stdio smoke tests in CI and by hand. It starts the server, sends
`initialize`, `notifications/initialized` and one request, prints the answer and
stops the server. It keeps the server's stdin open until the answer arrives.

Usage:
    scripts/mcp-call.py tools                       list the server's tools
    scripts/mcp-call.py <tool> ['<json-arguments>'] call one tool
    scripts/mcp-call.py --allow-state-changing <tool> ['<json-arguments>']

Examples:
    scripts/mcp-call.py sniper_status
    scripts/mcp-call.py list_workspaces
    scripts/mcp-call.py get_findings '{"workspace":"app.example"}'
    scripts/mcp-call.py get_ports '{"workspace":"192.0.2.10"}'

The tools that start, stop or change something (sniper_scan, cancel_scan,
delete_workspace, export_workspace) are refused unless --allow-state-changing is
given. For smoke runs, keep scanning off and the scope empty:
    SNIPER_SCAN_ENABLED=false SNIPER_BIN=/nonexistent/sniper SNIPER_MCP_SCOPE= \\
        HOME="$(mktemp -d)" scripts/mcp-call.py tools

Environment:
    SERVER            server command line (default: sn1per-mcp); split like a shell
                      command, so "docker run -i --rm sn1per-mcp:0.9.0" works
    MCP_CALL_TIMEOUT  seconds to wait for the answer (default: 120)
    The rest of the environment is passed to the server unchanged.

Exit status: 0 on success, 1 on a protocol error, a timeout or a tool result with
isError set, 2 on a usage error, 127 when the server command cannot be started.
"""

from __future__ import annotations

import json
import os
import select
import shlex
import shutil
import subprocess
import sys
import time

DEFAULT_SERVER = "sn1per-mcp"
PROTOCOL_VERSION = "2025-06-18"
STATE_CHANGING_TOOLS = frozenset(
    {"sniper_scan", "cancel_scan", "delete_workspace", "export_workspace"})
LIST_COMMANDS = frozenset({"tools", "tools/list", "list"})


def _server_command() -> list[str]:
    """The server argv: $SERVER split like a shell command, else sn1per-mcp."""
    raw = os.environ.get("SERVER", "").strip()
    if raw:
        return shlex.split(raw)
    found = shutil.which(DEFAULT_SERVER)
    if found:
        return [found]
    # pipx puts console scripts in ~/.local/bin, which is not on PATH until
    # `pipx ensurepath` and a new login shell.
    fallback = os.path.join(os.path.expanduser("~"), ".local", "bin", DEFAULT_SERVER)
    return [fallback if os.path.exists(fallback) else DEFAULT_SERVER]


def _usage(stream=None) -> None:
    print(__doc__, file=stream or sys.stdout)


def _parse(argv: list[str]) -> tuple[str, dict, bool] | int:
    allow = False
    rest: list[str] = []
    for arg in argv:
        if arg == "--allow-state-changing":
            allow = True
        elif arg in ("-h", "--help"):
            _usage()
            return 0
        else:
            rest.append(arg)
    if not rest or len(rest) > 2:
        _usage(sys.stderr)
        return 2
    tool = rest[0]
    try:
        arguments = json.loads(rest[1]) if len(rest) == 2 else {}
    except json.JSONDecodeError as exc:
        print(f"bad JSON arguments: {exc}", file=sys.stderr)
        return 2
    if not isinstance(arguments, dict):
        print("JSON arguments must be an object", file=sys.stderr)
        return 2
    if tool in STATE_CHANGING_TOOLS and not allow:
        print(f"refusing to call {tool}: it starts, stops or changes something on the "
              "host; pass --allow-state-changing if that is intended", file=sys.stderr)
        return 2
    return tool, arguments, allow


def _read_answer(fd: int, deadline: float) -> dict | None:
    """The message with id 2 from the server's stdout, or None at the deadline or EOF.

    Reads raw chunks with os.read into its own buffer and splits lines itself. A
    buffered readline() after select() would leave a second message that arrived in
    the same chunk inside Python's buffer, where select() cannot see it.
    """
    buffer = b""
    while True:
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            try:
                message = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            # The response to request 2; a server-initiated request (a ping or an
            # elicitation) can carry the same id but has a method.
            if (isinstance(message, dict) and message.get("id") == 2
                    and "method" not in message):
                return message
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            return None
        chunk = os.read(fd, 65536)
        if not chunk:
            return None
        buffer += chunk


def main(argv: list[str] | None = None) -> int:
    parsed = _parse(sys.argv[1:] if argv is None else argv)
    if isinstance(parsed, int):
        return parsed
    tool, arguments, _ = parsed
    timeout = float(os.environ.get("MCP_CALL_TIMEOUT", "120"))

    listing = tool in LIST_COMMANDS
    request = ({"jsonrpc": "2.0", "id": 2, "method": "tools/list"} if listing else
               {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": tool, "arguments": arguments}})
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name": "mcp-call", "version": "0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        request,
    ]

    command = _server_command()
    try:
        proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env=dict(os.environ))
    except OSError as exc:
        print(f"cannot start the server {command[0]!r}: {exc}\n"
              "Install the package (pipx install sn1per-mcp) or set SERVER to the "
              "absolute path of sn1per-mcp.", file=sys.stderr)
        return 127
    assert proc.stdin is not None and proc.stdout is not None
    try:
        proc.stdin.write("".join(json.dumps(m) + "\n" for m in messages).encode("utf-8"))
        proc.stdin.flush()  # stdin stays open: the server stops at end of input
    except BrokenPipeError:
        # The server exited before it read the requests. Never let this reach the
        # BrokenPipeError handler of __main__, which exits 0 for a closed stdout.
        answer = None
    else:
        answer = _read_answer(proc.stdout.fileno(), time.monotonic() + timeout)

    try:
        proc.stdin.close()
    except OSError:  # BrokenPipeError when the server is gone
        pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    if answer is None:
        print("no answer from the server (timeout or early exit)", file=sys.stderr)
        return 1
    if "error" in answer:
        print(json.dumps(answer["error"], indent=2))
        return 1

    result = answer.get("result") or {}
    if listing:
        for entry in result.get("tools", []):
            lines = (entry.get("description") or "").strip().splitlines()
            print(f"{entry['name']:18} {lines[0] if lines else ''}")
        return 0
    for chunk in result.get("content", []):
        print(chunk.get("text", ""))
    return 1 if result.get("isError") else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        # The reader closed the pipe (for example `| head`); exit quietly.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        raise SystemExit(0) from None
