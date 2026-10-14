# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Root test configuration: the two-layer isolation guard (contract O.2).

Layer 1 is the interpreter audit hook in tests/guard/hook.py, installed in
``pytest_configure`` before any test module is imported. Layer 2 is the
autouse fixture below, which runs for every test: it empties the Sn1per, MCP
and RAG environment, points HOME, the state directory and every system path
of ``sniper_mcp.paths`` at a fake install inside the test's temporary
directory, and puts the stub ``sudo`` in place.

Nothing here (or anywhere under tests/) enables real execution, real network
access or real loot (O.7).
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

from tests.guard import hook

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
CLI_FIXTURES = FIXTURES / "cli"
INSTALL_FIXTURES = FIXTURES / "install"
LOOT_FIXTURES = FIXTURES / "loot"

INSTALLS = {
    "ce-9.2": ("ce-9.2", "sniper-9.2"),
    "se-11.0": ("se-11.0", "sniper-11.0"),
    "pro": ("pro", "sniper-11.0"),
    "enterprise": ("enterprise", "sniper-11.0"),
}
DEFAULT_INSTALL = "se-11.0"
ENV_PREFIXES_REMOVED = ("SNIPER_", "MCP_", "RAG_")
# By default the stub CLI behaves like a scan that wrote output (L.3 classifies a run
# without new workspace files as failed: no_output). set_knobs() replaces these.
DEFAULT_KNOBS = {"files": ["scans/stub-output.txt"]}
# L.6: the engine's task deletion matches the MCP server process itself (04 CE-16).
FORBIDDEN_ENGINE_ARGS = frozenset({"-dt", "--delete-task"})

_GUARD_STATE: hook.GuardState | None = None
# The ledger accessor, captured once at configure time (O.2): replacing them on
# the state object later changes nothing here.
_UNCONSUMED = None
_READ_CHILD_VIOLATIONS = hook.read_child_violations


@pytest.hookimpl(trylast=True)
def pytest_configure(config: pytest.Config) -> None:
    """Install Layer 1 before collection imports any test module."""
    global _GUARD_STATE, _UNCONSUMED
    factory = getattr(config, "_tmp_path_factory", None)
    if factory is None:
        factory = pytest.TempPathFactory.from_config(config, _ispytest=True)
    temp_root = os.path.realpath(str(factory.getbasetemp()))
    state = hook.install(temp_root=temp_root, repo_root=str(REPO_ROOT), mode="pytest")
    _UNCONSUMED = state.unconsumed_ledger
    _GUARD_STATE = state


def _all_unconsumed() -> list[str]:
    state = _GUARD_STATE
    if state is None or _UNCONSUMED is None:
        return ["the test guard was never installed"]
    problems = [v.describe() for v in _UNCONSUMED()]
    if state.temp_root:
        # Recursive: a child may run with a directory inside the temp root as its own.
        for item in _READ_CHILD_VIOLATIONS(state.temp_root, recursive=True):
            problems.append(f"child pid {item.get('pid')}: {item.get('kind')}: "
                            f"{item.get('event')}: {item.get('detail')}")
    return problems


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Fail the run if any guard violation was not consumed by ``expect_violation()``."""
    problems = _all_unconsumed()
    if not problems:
        return
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    lines = ["", "TEST GUARD VIOLATIONS (contract O.2): the session fails."]
    lines += [f"  {p}" for p in problems]
    for line in lines:
        if reporter is not None:
            reporter.write_line(line, red=True)
        else:
            sys.stderr.write(line + "\n")
    session.exitstatus = pytest.ExitCode.TESTS_FAILED


class Isolation:
    """The per-test fake host: install tree, stub CLI and sudo, state dir, env."""

    def __init__(self, tmp: Path, monkeypatch: pytest.MonkeyPatch, temp_root: str) -> None:
        self.tmp = tmp
        self.monkeypatch = monkeypatch
        self.temp_root = temp_root
        self.bin_dir = tmp / "bin"
        self.home = tmp / "home"
        self.state_dir = tmp / "state"
        self.audit_log = self.state_dir / "audit.jsonl"
        self.install_dir = tmp / "install"
        self.loot_base = self.install_dir / "loot"
        self.workspace_dir = self.loot_base / "workspace"
        self.cli_path = self.install_dir / "sniper"
        self.cli_link = self.bin_dir / "sniper"
        self.sudo_path = self.bin_dir / "sudo"
        self.knobs_path = tmp / "stub-knobs.json"
        self.argv_log_path = tmp / "stub-argv.jsonl"
        self.install_name = ""
        self.dns_table: dict[str, list[str]] = {}
        self.public_addresses: set[str] = set()

    # --- setup -------------------------------------------------------------
    def setup(self) -> None:
        mp = self.monkeypatch
        for key in list(os.environ):
            if key.startswith(ENV_PREFIXES_REMOVED):
                mp.delenv(key, raising=False)
        for directory in (self.bin_dir, self.home):
            directory.mkdir(parents=True, exist_ok=True)
        self.knobs_path.write_text(json.dumps(DEFAULT_KNOBS))
        self.argv_log_path.write_text("")
        mp.setenv("HOME", str(self.home))
        mp.setenv("XDG_STATE_HOME", str(self.home / ".local" / "state"))
        mp.setenv("SNIPER_MCP_STATE_DIR", str(self.state_dir))
        mp.setenv("SNIPER_MCP_AUDIT_LOG", str(self.audit_log))
        mp.setenv("SNIPER_BIN", str(self.cli_link))
        mp.setenv("SNIPER_INSTALL_DIR", str(self.install_dir))
        mp.setenv("SNIPER_LOOT_BASE", str(self.loot_base))
        mp.setenv("PATH", str(self.bin_dir))

        from sniper_mcp import paths

        install = str(self.install_dir)
        mp.setattr(paths, "CLI_FALLBACK", str(self.cli_path))
        mp.setattr(paths, "DEFAULT_INSTALL_DIR", install)
        mp.setattr(paths, "DEFAULT_LOOT_BASE", str(self.loot_base))
        mp.setattr(paths, "DELETE_ROOT", install)
        mp.setattr(paths, "DELETE_ROOT_LOOT", str(self.loot_base))
        mp.setattr(paths, "DELETE_ROOT_WORKSPACE", str(self.workspace_dir))
        mp.setattr(paths, "ENGINE_PATH_DIRS", (str(self.bin_dir),))
        mp.setattr(paths, "SUDO", str(self.sudo_path))
        mp.setattr(paths, "TRUSTED_UID", os.geteuid())
        # The test's own directory (0700, this uid's) stands in for "/" in the walk that
        # decides whether root chose the CLI realpath (C.2 step 1, H.5).
        mp.setattr(paths, "FILESYSTEM_ROOT", str(self.tmp))

        self._install_stub(CLI_FIXTURES / "sudo", self.sudo_path, install_dir=None)
        self.use_install(DEFAULT_INSTALL)
        self._patch_dns()
        # The terminal holder (L.6) is a sys.executable child: it must load the guard.
        from sniper_mcp import proc

        mp.setattr(proc, "holder_env", self.holder_env)

    def holder_env(self, home: str) -> dict[str, str]:
        """``proc.holder_env`` under the guard: the real minimal environment, with the guard
        first on PYTHONPATH and this checkout's ``src`` after it (O.2)."""
        from sniper_mcp import proc

        base = proc.minimal_env(home)
        return hook.child_env(self.temp_root, str(REPO_ROOT), base,
                              extra_pythonpath=[str(REPO_ROOT / "src")])

    def _patch_dns(self) -> None:
        """Replace the scope resolver with the fake mapping of the ``dns`` fixture (O.2).

        The scope guard module must expose ``resolver`` (host -> list of
        addresses) and ``is_public`` (address -> bool). Until that module exists
        there is nothing to patch; Layer 1 blocks real lookups either way.
        """
        try:
            from sniper_mcp import scope  # type: ignore[attr-defined]
        except ImportError:
            return
        if not hasattr(scope, "resolver") or not hasattr(scope, "is_public"):
            raise AssertionError("sniper_mcp.scope must expose resolver and is_public (O.2)")

        def fake_resolver(host: str) -> list[str]:
            if host in self.dns_table:
                return list(self.dns_table[host])
            raise LookupError(f"fake DNS: {host} not found")

        real_is_public = scope.is_public
        self.monkeypatch.setattr(scope, "resolver", fake_resolver)
        self.monkeypatch.setattr(
            scope, "is_public",
            lambda address: str(address) in self.public_addresses or real_is_public(address))

    def _install_stub(self, source: Path, dest: Path, *, install_dir: Path | None) -> None:
        text = source.read_text()
        replacements = {
            "@TEMP_ROOT@": self.temp_root,
            "@KNOBS@": str(self.knobs_path),
            "@ARGV_LOG@": str(self.argv_log_path),
            "@PYTHON@": sys.executable,
        }
        if install_dir is not None:
            replacements["@INSTALL_DIR@"] = str(install_dir)
        for placeholder, value in replacements.items():
            text = text.replace(placeholder, value)
        if dest.exists() or dest.is_symlink():
            dest.unlink()
        dest.write_text(text)
        dest.chmod(0o755)

    # --- helpers for tests --------------------------------------------------
    def use_install(self, name: str) -> None:
        """Switch the fake install to ``ce-9.2``, ``se-11.0``, ``pro`` or ``enterprise``."""
        tree, cli = INSTALLS[name]
        keep_loot = None
        if self.loot_base.exists():
            keep_loot = self.tmp / ".loot-keep"
            shutil.move(str(self.loot_base), str(keep_loot))
        if self.install_dir.exists():
            shutil.rmtree(self.install_dir)
        shutil.copytree(INSTALL_FIXTURES / tree, self.install_dir)
        if keep_loot is not None:
            shutil.move(str(keep_loot), str(self.loot_base))
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        # Like a root-owned install, whatever the checkout umask: nothing in the tree
        # is group- or world-writable (C.2 step 11 must not differ by host).
        for directory, dirnames, filenames in os.walk(self.install_dir):
            for name in dirnames + filenames:
                entry = Path(directory) / name
                if not entry.is_symlink():
                    entry.chmod(entry.stat().st_mode & ~0o022)
        for directory in (self.install_dir, self.loot_base, self.workspace_dir):
            directory.chmod(0o755)
        self._install_stub(CLI_FIXTURES / cli, self.cli_path, install_dir=self.install_dir)
        if self.cli_link.exists() or self.cli_link.is_symlink():
            self.cli_link.unlink()
        self.cli_link.symlink_to(self.cli_path)
        self.install_name = name
        from sniper_mcp import edition

        edition.clear_cache()  # detection is cached for 30 seconds (C.2)

    def set_knobs(self, **knobs: object) -> None:
        """Behaviour knobs read by the stub CLI and stub sudo (O.3); replaces the defaults."""
        self.knobs_path.write_text(json.dumps(knobs))

    def resolve(self, name: str, *addresses: str, public: bool = True) -> None:
        """A fake DNS answer for ``name`` (O.2). RFC 5737 answers are marked public by
        default, so the R3 non-public rule does not refuse them; ``public=False`` keeps
        them non-public."""
        self.dns_table[name] = list(addresses)
        if public:
            self.public_addresses.update(addresses)

    def calls(self, prog: str | None = None) -> list[list[str]]:
        """Argv lists recorded by the stubs, oldest first (``prog``: sniper or sudo)."""
        return [item["argv"] for item in self.recorded()
                if prog is None or item["prog"] == prog]

    def recorded(self) -> list[dict]:
        """Every ``{"prog", "argv"}`` record the stubs wrote, oldest first."""
        if not self.argv_log_path.is_file():
            return []
        return [json.loads(line) for line in self.argv_log_path.read_text().splitlines()
                if line.strip()]

    def copy_loot(self, dialect: str = "se-11.x") -> None:
        """Copy ``tests/fixtures/loot/<dialect>/workspace`` into the fake install."""
        source = LOOT_FIXTURES / dialect / "workspace"
        shutil.copytree(source, self.workspace_dir, dirs_exist_ok=True)

    def make_workspace(self, name: str, files: dict[str, str] | None = None) -> Path:
        path = self.workspace_dir / name
        path.mkdir(parents=True, exist_ok=True)
        for relative, content in (files or {}).items():
            target = path / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        return path

    def setenv(self, **values: str) -> None:
        for key, value in values.items():
            self.monkeypatch.setenv(key, value)

    def delenv(self, *keys: str) -> None:
        for key in keys:
            self.monkeypatch.delenv(key, raising=False)

    def child_env(self, **extra: str) -> dict[str, str]:
        """Environment for a guarded ``sys.executable`` child (stdio smoke tests)."""
        base = {k: v for k, v in os.environ.items() if k in ("HOME", "XDG_STATE_HOME")}
        base["PATH"] = str(self.bin_dir)
        base.update(extra)
        return hook.child_env(self.temp_root, str(REPO_ROOT), base,
                              extra_pythonpath=[str(REPO_ROOT / "src")])


@pytest.fixture(autouse=True, name=hook.ISOLATION_FIXTURE_NAME)
def _isolation_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Layer 2 of the guard (O.2): runs for every test, no opt-out."""
    state = _GUARD_STATE
    assert state is not None and state.temp_root, "test guard not installed"
    assert _UNCONSUMED is not None
    before = {id(v) for v in _UNCONSUMED()}

    def child_items() -> list[dict]:
        # The session temp root's own file, plus any file below this test's
        # directory (children given a sub-root write there).
        return (_READ_CHILD_VIOLATIONS(state.temp_root)
                + _READ_CHILD_VIOLATIONS(str(tmp_path), recursive=True))

    children_before = {item["source"] for item in child_items()}
    isolation = Isolation(tmp_path, monkeypatch, state.temp_root)
    isolation.setup()
    yield isolation
    fresh = [v.describe() for v in _UNCONSUMED() if id(v) not in before]
    fresh += [f"child pid {item.get('pid')}: {item.get('kind')}: {item.get('event')}: "
              f"{item.get('detail')}"
              for item in child_items() if item["source"] not in children_before]
    if fresh:
        pytest.fail("test guard violation(s) (contract O.2):\n"
                    + "\n".join(f"  {line}" for line in fresh), pytrace=False)
    # O.5 P1-04 / L.6: no test ever runs the engine's task deletion (-dt) or a kill
    # through sudo; pattern kills (pkill, killall) are already blocked by Layer 1.
    forbidden = [record for record in isolation.recorded()
                 if FORBIDDEN_ENGINE_ARGS & set(record["argv"])
                 or (record["prog"] == "sudo"
                     and "kill" in {os.path.basename(arg) for arg in record["argv"]})]
    if forbidden:
        pytest.fail(f"a stub recorded a forbidden command (contract L.6): {forbidden}",
                    pytrace=False)


@pytest.fixture
def iso(request: pytest.FixtureRequest) -> Isolation:
    """The isolation object of the current test (fake install, stubs, env helpers)."""
    return request.getfixturevalue(hook.ISOLATION_FIXTURE_NAME)


@pytest.fixture
def dns(iso: Isolation) -> dict[str, list[str]]:
    """Fake DNS table used by the scope resolver (name -> addresses)."""
    return iso.dns_table
