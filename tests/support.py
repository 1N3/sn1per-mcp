# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""In-memory MCP client helpers (contract O.6: never the SDK's private tool manager)."""

from __future__ import annotations

import functools
import json
import os
import signal
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any

import anyio
from mcp import ClientSession, types
from mcp.shared.memory import create_connected_server_and_client_session

from sniper_mcp import paths, results, server, settings
from tests.guard import hook

GOLDEN = Path(__file__).resolve().parent / "fixtures" / "golden" / "model_facing.json"


@functools.cache
def golden() -> dict[str, Any]:
    """The model-facing surface copied byte for byte from the contract (H, N)."""
    return json.loads(GOLDEN.read_text(encoding="utf-8"))


def assert_isolated() -> None:
    """Refuse to build a server unless the Layer 2 fixture is active (O.2).

    The fixture points HOME, the state directory, the CLI and ``paths.SUDO`` into
    the session temp root; if any of them is elsewhere the server would read the
    real host.
    """
    state = hook.state()
    if state is None or not state.temp_root:
        raise AssertionError("the test isolation guard is not installed")
    root = state.temp_root.rstrip("/") + "/"
    required = {
        "paths.SUDO": paths.SUDO,
        "paths.DEFAULT_INSTALL_DIR": paths.DEFAULT_INSTALL_DIR,
        "paths.DELETE_ROOT": paths.DELETE_ROOT,
        "HOME": os.environ.get("HOME", ""),
    }
    optional = {name: os.environ.get(name, "") for name in (
        "XDG_STATE_HOME", "SNIPER_MCP_STATE_DIR", "SNIPER_MCP_AUDIT_LOG", "SNIPER_BIN",
        "SNIPER_INSTALL_DIR", "SNIPER_LOOT_BASE")}
    checked = dict(required)
    checked.update({k: v for k, v in optional.items() if os.path.isabs(v)})
    for name, value in checked.items():
        if not os.path.realpath(value or "/").startswith(root):
            raise AssertionError(f"the isolation fixture is not active: {name} is outside "
                                 "the test temp root")


def current_settings() -> settings.Settings:
    assert_isolated()
    return settings.load_settings(os.environ)


def check_result(name: str, result: types.CallToolResult) -> None:
    """Assert the H.1/H.2 envelope of one tool result (O.5 P1-01).

    Runs on every tool call made through :func:`session`, so every refusal path that
    any test reaches is checked: ``isError`` is true exactly when the payload holds the
    H.2 error object, the error code is one the tool documents (H.5-H.16) with its H.2
    retry value, and every payload starts with ``schema_version`` and ``tool``.
    """
    payload = result.structuredContent
    assert len(result.content) == 1 and result.content[0].type == "text", name
    if payload is None:
        # H.1 exception: the SDK rejects arguments that violate the input schema.
        assert result.isError is True, name
        return
    assert result.content[0].text == results.encode(payload), name
    assert list(payload)[:2] == ["schema_version", "tool"], (name, list(payload)[:2])
    assert payload["schema_version"] == results.SCHEMA_VERSION
    assert payload["tool"] == name
    assert results.encoded_size(payload) <= results.MAX_STRUCTURED_BYTES, name
    core = golden()["tools"].get(name)
    if "error" in payload:
        assert result.isError is True, name
        assert list(payload) == ["schema_version", "tool", "error"], (name, list(payload))
        error = payload["error"]
        assert list(error) == ["code", "message", "hint", "retry", "details"], name
        assert all(isinstance(error[k], str) and error[k] for k in ("message", "hint")), error
        assert isinstance(error["details"], dict), error
        code = error["code"]
        if core is None:  # plugin tool (M.2): plugin-defined codes are allowed
            assert results.PLUGIN_CODE_RE.fullmatch(code), code
            assert error["retry"] == results.ERROR_CODES.get(code, error["retry"])
            assert error["retry"] in results.RETRY_VALUES
        else:
            assert code in core["errors"], f"{name} returned undocumented error code {code}"
            assert error["retry"] == golden()["error_codes"][code], (name, code)
    else:
        assert result.isError is False, (name, payload)
        assert list(payload)[-1] == "warnings", (name, list(payload)[-1])
        for item in payload["warnings"]:
            assert list(item) == ["code", "message"], item
            assert item["code"] in golden()["warning_codes"], item


def _checked(client: ClientSession) -> ClientSession:
    call_tool = client.call_tool

    @functools.wraps(call_tool)
    async def checked_call(name: str, arguments: dict[str, Any] | None = None,
                           *args: Any, **kwargs: Any) -> types.CallToolResult:
        result = await call_tool(name, arguments, *args, **kwargs)
        check_result(name, result)
        return result

    client.call_tool = checked_call  # type: ignore[method-assign]
    return client


@asynccontextmanager
async def session(**kwargs: Any) -> AsyncIterator[ClientSession]:
    """A client session connected to a freshly built server (current environment).

    Every ``call_tool`` result is checked by :func:`check_result`.
    """
    mcp = server.build_server(current_settings())
    async with create_connected_server_and_client_session(mcp._mcp_server, **kwargs) as client:
        yield _checked(client)


async def call(name: str, arguments: dict[str, Any] | None = None,
               **session_kwargs: Any) -> tuple[dict, bool]:
    """Call one tool on a fresh server; returns (structuredContent, isError)."""
    async with session(**session_kwargs) as client:
        result = await client.call_tool(name, arguments or {})
    return result.structuredContent or {}, bool(result.isError)


class Elicitation:
    """A client-side elicitation callback (I.2) that records every request.

    ``action`` is ``accept``, ``decline`` or ``cancel``; with ``accept`` the form
    content is ``{"workspace": typed}`` (or ``content`` when given). ``before`` runs
    first (for example to change the host while the prompt is open).
    """

    def __init__(self, action: str = "accept", typed: str | None = None, *,
                 content: dict[str, Any] | None = None,
                 before: Any = None, delay: float = 0.0) -> None:
        self.action = action
        self.typed = typed
        self.content = content
        self.before = before
        self.delay = delay
        self.requests: list[types.ElicitRequestParams] = []

    async def __call__(self, context: Any, params: types.ElicitRequestParams) -> types.ElicitResult:
        self.requests.append(params)
        if self.before is not None:
            self.before()
        if self.delay:
            await anyio.sleep(self.delay)
        if self.action != "accept":
            return types.ElicitResult(action=self.action)
        content = self.content if self.content is not None else {"workspace": self.typed}
        return types.ElicitResult(action="accept", content=content)

    def kwargs(self) -> dict[str, Any]:
        return {"elicitation_callback": self}


class DeadlineExceeded(AssertionError):
    """Raised inside a :func:`deadline` block that ran too long."""


@contextmanager
def deadline(seconds: float, what: str = "") -> Iterator[None]:
    """Fail a CPU-bound block that runs longer than ``seconds`` (main thread only).

    A super-linear regular expression on 8 MiB would run for hours; SIGALRM interrupts
    the scan (CPython checks signals while matching), so the test fails in time.
    """
    def expired(signum: int, frame: Any) -> None:
        raise DeadlineExceeded(f"{what or 'block'} ran longer than {seconds} s")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
