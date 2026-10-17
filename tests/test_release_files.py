# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Release files and the release checks (contract A.3, P.1, P.5-P.9, O.5 P0-03, P0-04).

The sdist ships tests/ and scripts/ (A.4) but not .github/, plugins/, the Dockerfile or
the icon, so the tests that read the whole repository tree skip outside a checkout.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import time
import zipfile
from pathlib import Path

import pytest

import sniper_mcp
from sniper_mcp import scope, settings
from tests import realpaths

REPO = Path(__file__).resolve().parent.parent
VERSION = sniper_mcp.__version__
SCRIPTS = (REPO / "scripts" / "check_release_consistency.py", REPO / "scripts" / "mcp-call.py")
if not all(path.is_file() for path in SCRIPTS):
    pytest.skip("scripts/ is not present (an sdist built before 0.9.0 or a partial copy)",
                allow_module_level=True)
# Files of a repository checkout that the sdist does not carry.
FULL_CHECKOUT = all((REPO / rel).exists() for rel in (
    ".github/workflows/ci.yml", "plugins/sn1per/.mcp.json", ".claude-plugin/marketplace.json",
    "Dockerfile", "assets/sn1per-mcp-256.png"))
requires_checkout = pytest.mark.skipif(
    not FULL_CHECKOUT, reason="needs a repository checkout; the sdist does not ship .github/, "
                              "plugins/, the Dockerfile or assets/")


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


checks = _load("check_release_consistency", SCRIPTS[0])
mcp_call = _load("mcp_call", SCRIPTS[1])


def _args(root: Path, **overrides) -> argparse.Namespace:
    values = {"root": str(root), "allow_pending_docs": False, "export": False,
              "private_branch": False, "decisions": None, "surfaces": None, "dist": None,
              "only": None}
    values.update(overrides)
    return argparse.Namespace(**values)


def _issues(root: Path, **overrides) -> list:
    issues, _ = checks.run(_args(root, **overrides))
    return issues


# --- the repository itself ---------------------------------------------------------------

@requires_checkout
def test_repository_passes_every_check():
    # This tree is the private release branch: it carries the never-exported files.
    # The documentation is complete, so nothing is pending either (O.5 P0-04).
    issues, _ = checks.run(_args(REPO, private_branch=True))
    assert [f"{i.category}: {i.path}: {i.message}" for i in issues] == []
    assert checks.main(["--root", str(REPO), "--private-branch"]) == 0


def test_print_version_matches_the_single_source(capsys):
    assert checks.main(["--root", str(REPO), "--print-version"]) == 0
    assert capsys.readouterr().out == f"{VERSION}\n"


def test_server_json_matches_the_contract():
    data = json.loads((REPO / "server.json").read_text())
    # The whole P.8 object: descriptions, defaults, placeholders and _meta included.
    expected = json.loads(json.dumps(EXPECTED_SERVER_JSON).replace("0.9.0", VERSION))
    assert data == expected
    assert data["icons"][0]["src"] == (
        f"https://raw.githubusercontent.com/1N3/sn1per-mcp/v{VERSION}/assets/sn1per-mcp-256.png")
    names = [e["name"] for e in data["packages"][0]["environmentVariables"]]
    assert names == list(checks.SERVER_JSON_ENV)
    # Never the lab override, reveal-secrets, plugins or paths of the state directory.
    assert set(names) <= set(settings.ENV_VARS)
    assert not {"SNIPER_MCP_ALLOW_ANY_TARGET", "SNIPER_MCP_REVEAL_SECRETS",
                "SNIPER_MCP_PLUGINS"} & set(names)
    meta = data["_meta"]["io.modelcontextprotocol.registry/publisher-provided"]
    assert meta["com.sn1persecurity"]["editions"] == ["ce", "se", "pro", "enterprise"]


def test_server_json_scope_placeholder_is_a_valid_scope():
    env = json.loads((REPO / "server.json").read_text())["packages"][0]["environmentVariables"]
    placeholder = next(e["placeholder"] for e in env if e["name"] == "SNIPER_MCP_SCOPE")
    entries = scope.tokenize(placeholder, comments=False)
    assert entries == ["app.example", "192.0.2.0/24"]
    for entry in entries:
        scope.parse_entry(entry, exclusion=False)  # raises EntryError when invalid


@requires_checkout
def test_plugin_files_pin_the_version():
    market = json.loads((REPO / ".claude-plugin" / "marketplace.json").read_text())
    plugin = json.loads((REPO / "plugins/sn1per/.claude-plugin/plugin.json").read_text())
    mcp = json.loads((REPO / "plugins/sn1per/.mcp.json").read_text())
    assert market["plugins"][0]["version"] == plugin["version"] == VERSION
    assert mcp["mcpServers"]["sn1per"]["args"] == ["--from", f"sn1per-mcp=={VERSION}",
                                                   "sn1per-mcp"]


def test_spdx_header_in_every_script():
    for path in sorted((REPO / "scripts").glob("*.py")):
        lines = path.read_text().splitlines()
        if lines and lines[0].startswith("#!"):
            lines = lines[1:]
        assert lines[:2] == checks.SPDX_HEADER, path


def test_check_script_reproduces_the_scrub_pattern_of_the_test_suite():
    from tests import test_packaging

    assert checks.SCRUB.pattern == test_packaging.SCRUB.pattern


# --- the checks on synthetic trees ------------------------------------------------------

def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "repo"
    (root / "src" / "sniper_mcp").mkdir(parents=True)
    (root / "src" / "sniper_mcp" / "__init__.py").write_text(f'__version__ = "{VERSION}"\n')
    (root / "src" / "sniper_mcp" / "settings.py").write_text(
        "ENV_VARS = " + repr(tuple(settings.ENV_VARS)) + "\n")
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def _categories(issues) -> set[tuple[str, str]]:
    return {(i.category, i.path.split(":")[0]) for i in issues}


CLEAN_README = f"""# Sn1per MCP Server

{checks.MCP_NAME_TOKEN}

Install with `pipx install sn1per-mcp=={VERSION}` and set `SNIPER_MCP_SCOPE` to
`{checks.SCOPE_PLACEHOLDER}`. Read the
[install guide](https://github.com/1N3/sn1per-mcp/blob/main/docs/install.md).
"""


def _release_tree(tmp_path: Path, docs: bool = False) -> Path:
    """A copy of this checkout's published files with a clean README.

    It passes every check except the missing documentation pages; with docs=True it
    also carries a CHANGELOG and a docs/configuration.md that pass.
    """
    if not FULL_CHECKOUT:
        pytest.skip("needs a repository checkout")
    root = tmp_path / "release"
    for rel in checks.LAYOUT_FILES:
        if (REPO / rel).is_file():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / rel, root / rel)
    shutil.copytree(REPO / "src" / "sniper_mcp", root / "src" / "sniper_mcp",
                    dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "rag" + "_client.py", "query.py"))
    (root / "README.md").write_text(CLEAN_README)
    if docs:
        (root / "CHANGELOG.md").write_text(
            f"# Changelog\n\n## [Unreleased]\n\n## [{VERSION}] - 2026-10-20\n\n- First release.\n")
        rows = "".join(f"| `{name}` | a setting |\n" for name in settings.ENV_VARS)
        (root / "docs").mkdir()
        (root / "docs" / "configuration.md").write_text(
            "# Configuration\n\n| Variable | Meaning |\n|---|---|\n" + rows)
    return root


def _edit_json(root: Path, rel: str, change) -> None:
    path = root / rel
    data = json.loads(path.read_text())
    change(data)
    path.write_text(json.dumps(data, indent=2) + "\n")


def _edit_text(root: Path, rel: str, old: str, new: str) -> None:
    path = root / rel
    text = path.read_text()
    assert old in text, (rel, old)
    path.write_text(text.replace(old, new, 1))


OTHER_VERSION = "0.0.1"
SKILL = "plugins/sn1per/skills/authorized-scan/SKILL.md"
ICON_TAG = f"/v{VERSION}/"
CONSISTENCY_MUTATIONS = {
    "server.json version": ("server.json", lambda r: _edit_json(
        r, "server.json", lambda d: d.update(version=OTHER_VERSION))),
    "server.json package version": ("server.json", lambda r: _edit_json(
        r, "server.json", lambda d: d["packages"][0].update(version=OTHER_VERSION))),
    "server.json icon tag": ("server.json", lambda r: _edit_json(
        r, "server.json", lambda d: d["icons"][0].update(
            src=d["icons"][0]["src"].replace(ICON_TAG, "/main/")))),
    "server.json name": ("server.json", lambda r: _edit_json(
        r, "server.json", lambda d: d.update(name="com.sn1persecurity/sn1per-mcp"))),
    "server.json scope placeholder": ("server.json", lambda r: _edit_json(
        r, "server.json", lambda d: d["packages"][0]["environmentVariables"][0].update(
            placeholder="app.example"))),
    "pyproject description": ("pyproject.toml", lambda r: _edit_text(
        r, "pyproject.toml", "read findings.", "read results.")),
    "Dockerfile version label": ("Dockerfile", lambda r: _edit_text(
        r, "Dockerfile", f'image.version="{VERSION}"', f'image.version="{OTHER_VERSION}"')),
    "Dockerfile registry name label": ("Dockerfile", lambda r: _edit_text(
        r, "Dockerfile", 'server.name="io.github.1N3/sn1per-mcp"',
        'server.name="com.sn1persecurity/sn1per-mcp"')),
    "marketplace plugin version": (".claude-plugin/marketplace.json", lambda r: _edit_json(
        r, ".claude-plugin/marketplace.json",
        lambda d: d["plugins"][0].update(version=OTHER_VERSION))),
    "plugin.json version": ("plugins/sn1per/.claude-plugin/plugin.json", lambda r: _edit_json(
        r, "plugins/sn1per/.claude-plugin/plugin.json",
        lambda d: d.update(version=OTHER_VERSION))),
    ".mcp.json pin": ("plugins/sn1per/.mcp.json", lambda r: _edit_json(
        r, "plugins/sn1per/.mcp.json", lambda d: d["mcpServers"]["sn1per"].update(
            args=["--from", f"sn1per-mcp=={OTHER_VERSION}", "sn1per-mcp"]))),
    "CHANGELOG top entry": ("CHANGELOG.md", lambda r: _edit_text(
        r, "CHANGELOG.md", f"## [{VERSION}]", f"## [{OTHER_VERSION}]")),
    "configuration.md environment table": ("docs/configuration.md", lambda r: _edit_text(
        r, "docs/configuration.md", "| `SNIPER_BIN` | a setting |\n", "")),
    "README pin": ("README.md", lambda r: _edit_text(
        r, "README.md", f"sn1per-mcp=={VERSION}", f"sn1per-mcp=={OTHER_VERSION}")),
    "README mcp-name token": ("README.md", lambda r: _edit_text(
        r, "README.md", checks.MCP_NAME_TOKEN + "\n", "")),
    "README scope placeholder": ("README.md", lambda r: _edit_text(
        r, "README.md", checks.SCOPE_PLACEHOLDER, "app.example")),
    "docs version pin": ("docs/configuration.md", lambda r: _append(
        r, "docs/configuration.md", f"Install `pipx install sn1per-mcp=={OTHER_VERSION}`.\n")),
    "pyproject dynamic version": ("pyproject.toml", lambda r: _edit_text(
        r, "pyproject.toml", 'dynamic = ["version"]', f'version = "{VERSION}"')),
    "Development Status for 0.x": ("pyproject.toml", lambda r: _edit_text(
        r, "pyproject.toml", '"Development Status :: 4 - Beta"',
        '"Development Status :: 5 - Production/Stable"')),
    "invalid classifier": ("pyproject.toml", lambda r: _edit_text(
        r, "pyproject.toml", '"Topic :: Security",',
        '"Topic :: Security",\n    "Topic :: Not A Classifier",')),
    "License classifier": ("pyproject.toml", lambda r: _edit_text(
        r, "pyproject.toml", '"Topic :: Security",',
        '"Topic :: Security",\n    "License :: OSI Approved :: Apache Software License",')),
    "server.json description length": ("server.json", lambda r: _edit_json(
        r, "server.json", lambda d: d.update(description=d["description"] + " " + "x" * 100))),
    "server.json transport": ("server.json", lambda r: _edit_json(
        r, "server.json", lambda d: d["packages"][0].update(transport={"type": "sse"}))),
    "server.json isRequired": ("server.json", lambda r: _edit_json(
        r, "server.json", lambda d: d["packages"][0]["environmentVariables"][1].update(
            isRequired=True))),
    "server.json isSecret": ("server.json", lambda r: _edit_json(
        r, "server.json", lambda d: d["packages"][0]["environmentVariables"][2].update(
            isSecret=True))),
    "Dockerfile base digest": ("Dockerfile", lambda r: _edit_text(
        r, "Dockerfile", "python:3.13-slim@sha256:", "python:3.13-slim@sha256:x")),
    "Dockerfile user": ("Dockerfile", lambda r: _edit_text(
        r, "Dockerfile", "USER 10001:10001", "USER root")),
    "Dockerfile entrypoint": ("Dockerfile", lambda r: _edit_text(
        r, "Dockerfile", 'ENTRYPOINT ["sn1per-mcp"]', 'ENTRYPOINT ["sh"]')),
    "Dockerfile scanning off": ("Dockerfile", lambda r: _edit_text(
        r, "Dockerfile", "SNIPER_SCAN_ENABLED=false", "SNIPER_SCAN_ENABLED=true")),
    "Dockerfile editable install": ("Dockerfile", lambda r: _edit_text(
        r, "Dockerfile", "pip install --no-cache-dir /build",
        "pip install --no-cache-dir -e /build")),
    "SKILL.md frontmatter": (SKILL, lambda r: _edit_text(
        r, SKILL, "name: authorized-scan", "name: scan")),
    ".mcp.json env": ("plugins/sn1per/.mcp.json", lambda r: _edit_json(
        r, "plugins/sn1per/.mcp.json", lambda d: d["mcpServers"]["sn1per"]["env"].update(
            SNIPER_MCP_ALLOW_INTRUSIVE="true"))),
    "marketplace owner": (".claude-plugin/marketplace.json", lambda r: _edit_json(
        r, ".claude-plugin/marketplace.json", lambda d: d["owner"].update(name="Someone"))),
    # V5 D6: "claude plugin validate" warns about a marketplace without a description.
    "marketplace description": (".claude-plugin/marketplace.json", lambda r: _edit_json(
        r, ".claude-plugin/marketplace.json", lambda d: d.pop("metadata"))),
    "plugin.json author": ("plugins/sn1per/.claude-plugin/plugin.json", lambda r: _edit_json(
        r, "plugins/sn1per/.claude-plugin/plugin.json",
        lambda d: d["author"].update(email="someone@app.example"))),
    "SPDX header": ("scripts/mcp-call.py", lambda r: _edit_text(
        r, "scripts/mcp-call.py", checks.SPDX_HEADER[0] + "\n", "")),
    "icon size": ("assets/sn1per-mcp-256.png", lambda r: (r / "assets/sn1per-mcp-256.png")
                  .write_bytes(checks.PNG_SIGNATURE + b"\0\0\0\rIHDR"
                               + struct.pack(">II", 128, 128) + b"\0" * 16)),
    "LICENSE text": ("LICENSE", lambda r: (r / "LICENSE").write_text("MIT License\n")),
    "NOTICE first lines": ("NOTICE", lambda r: _edit_text(
        r, "NOTICE", "Sn1per MCP Server\n", "Some Server\n")),
    "pull_request_target": (".github/workflows/ci.yml", lambda r: _edit_text(
        r, ".github/workflows/ci.yml", "  pull_request:\n", "  pull_request_target:\n")),
}


def _append(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.write_text(path.read_text() + text)


def _consistency_paths(root: Path) -> set[str]:
    return {i.path.split(":")[0] for i in _issues(root)
            if i.category == "consistency" or i.message.startswith("[consistency]")}


def test_release_tree_baseline_is_consistent(tmp_path):
    assert _consistency_paths(_release_tree(tmp_path, docs=True)) == set()


@pytest.mark.parametrize("name", sorted(CONSISTENCY_MUTATIONS))
def test_each_consistency_rule_fires(tmp_path, name):
    expected_path, mutate = CONSISTENCY_MUTATIONS[name]
    root = _release_tree(tmp_path, docs=True)
    mutate(root)
    assert expected_path in _consistency_paths(root)


PRIVATE_PATH = "/pen" + "test/tools"
INTERNAL = "CLAUDE" + ".md"


def test_scrub_and_em_dash_are_found_in_any_text_file(tmp_path):
    root = _tree(tmp_path, {
        "a.txt": f"see {PRIVATE_PATH}\n",
        "b.md": "one " + chr(0x2014) + " two\n",
    })
    found = _categories(_issues(root, only="scrub,em-dash"))
    assert found == {("scrub", "a.txt"), ("em-dash", "b.md")}


def test_em_dash_in_a_file_with_nul_bytes_and_in_names(tmp_path):
    root = _tree(tmp_path, {})
    (root / "notes.txt").write_bytes(b"a\0b " + chr(0x2014).encode() + b" c\n")
    (root / "icon.bin").write_bytes(bytes(range(256)))
    (root / ("odd" + chr(0x2014) + "name.md")).write_text("clean\n")
    assert _categories(_issues(root, only="em-dash")) == {
        ("em-dash", "notes.txt"), ("em-dash", "odd" + chr(0x2014) + "name.md")}


@pytest.mark.parametrize("spelling", [
    chr(0x2014), "&" + "mdash;", "&" + "MDASH;", "&#" + "8212;", "&#" + "08212;",
    "&#" + "x2014;", "&#" + "X2014;", "&#" + "x02014;"])
def test_each_em_dash_spelling_is_found_on_its_own(tmp_path, spelling):
    root = _tree(tmp_path, {"page.html": f"one {spelling} two\n", "clean.html": "a - b\n"})
    assert _categories(_issues(root, only="em-dash")) == {("em-dash", "page.html")}


def test_internal_notes_file_is_read_unless_the_tree_is_private(tmp_path):
    root = _tree(tmp_path, {INTERNAL: f"notes kept in {PRIVATE_PATH}\n"})
    # Default (a CI checkout) and --export: present means it would be published.
    for mode in ({}, {"export": True}):
        found = _categories(_issues(root, only="not-exported,scrub", **mode))
        assert ("not-exported", INTERNAL) in found
        assert ("scrub", INTERNAL) in found  # its contents are scrubbed too
    # --private-branch: the release branch carries it on purpose; noted, never read.
    issues, notes = checks.run(_args(root, only="not-exported,scrub", private_branch=True))
    assert issues == []
    assert notes == [f"not scanned (never exported): {INTERNAL}"]


def test_default_invocation_fails_on_a_committed_internal_notes_file(tmp_path):
    """The CI lint and release verify jobs run the script without any mode flag."""
    root = _release_tree(tmp_path)
    assert checks.main(["--root", str(root), "--allow-pending-docs"]) == 0
    (root / INTERNAL).write_text("internal notes\n")
    assert checks.main(["--root", str(root), "--allow-pending-docs"]) == 1
    assert checks.main(["--root", str(root), "--allow-pending-docs", "--export"]) == 1
    assert checks.main(["--root", str(root), "--allow-pending-docs", "--private-branch"]) == 0
    with pytest.raises(SystemExit):  # the two modes exclude each other
        checks.main(["--root", str(root), "--export", "--private-branch"])


def test_git_directory_is_never_read_or_reported(tmp_path):
    root = _release_tree(tmp_path)
    (root / ".git" / "objects").mkdir(parents=True)
    (root / ".git" / "config").write_text(f"[remote]\n\turl = {PRIVATE_PATH}\n")
    assert checks.main(["--root", str(root), "--allow-pending-docs", "--export"]) == 0
    assert checks.main(["--root", str(root), "--allow-pending-docs"]) == 0


GENERATED_SAMPLES = ("build/lib/x.py", "src/sniper_mcp/__pycache__/x.pyc", ".venv/bin/python",
                     "src/sn1per_mcp.egg-info/PKG-INFO")


def _git_index(paths, version: int = 2, hash_size: int = 20) -> bytes:
    """A git index file listing paths (format version 2, 3 or 4), as git writes it."""
    body, previous = b"", b""
    for rel in sorted(paths):
        name = rel.encode()
        flags = min(len(name), 0x0FFF) | (0x4000 if version == 3 else 0)
        entry = bytes(40) + bytes(hash_size) + struct.pack(">H", flags)
        if version == 3:
            entry += struct.pack(">H", 0)
        if version == 4:
            common = 0
            while common < min(len(name), len(previous)) and name[common] == previous[common]:
                common += 1
            strip = len(previous) - common
            assert strip < 0x80  # one varint byte is enough for these tests
            body += entry + bytes([strip]) + name[common:] + b"\0"
        else:
            entry += name
            body += entry + bytes(8 - len(entry) % 8)
        previous = name
    data = b"DIRC" + struct.pack(">II", version, len(paths)) + body
    return data + hashlib.sha1(data).digest()


def _track(root: Path, paths) -> None:
    (root / ".git").mkdir(exist_ok=True)
    (root / ".git" / "index").write_bytes(_git_index(paths))


@pytest.mark.parametrize("version", [2, 3, 4])
@pytest.mark.parametrize("hash_size", [20, 32])
def test_git_index_is_read_without_running_git(tmp_path, version, hash_size):
    long_name = "tests/fixtures/" + "n" * 5000 + ".txt"  # longer than the 12-bit length
    paths = ["README.md", "dist/x.txt", "docs/__pycache__/x.txt", "docs/a.md", long_name]
    if version == 4:
        paths.remove(long_name)
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    (root / ".git" / "index").write_bytes(_git_index(paths, version, hash_size))
    assert checks.git_index_paths(root) == sorted(paths)
    # A worktree: .git is a file naming the git directory.
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    (worktree / ".git").write_text(f"gitdir: {root / '.git'}\n")
    assert checks.git_index_paths(worktree) == sorted(paths)
    # No index yet, no .git, or a damaged index.
    (root / ".git" / "index").unlink()
    assert checks.git_index_paths(root) == []
    assert checks.git_index_paths(tmp_path) is None
    (root / ".git" / "index").write_bytes(b"DIRC" + struct.pack(">II", 2, 3) + b"x" * 40)
    assert checks.git_index_paths(root) is None


def test_default_mode_reads_committed_files_in_generated_directories(tmp_path):
    """A committed file is checked wherever it sits (P.2, P.5): build output, caches and
    virtual environments that git ignores are skipped, tracked files inside them fail."""
    root = _release_tree(tmp_path)
    token = f"{PRIVATE_PATH} " + "xer0" + "dayz@"
    tracked = ["dist/x.txt", "docs/__pycache__/x.txt", "build/notes.txt", "venv/notes.txt",
               "node_modules/notes.txt", "htmlcov/notes.txt", "tests/fixtures/x.egg-info/notes.txt"]
    for rel in tracked + ["src/sniper_mcp/__pycache__/ignored.pyc", ".venv/ignored.txt"]:
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(token + "\n")
    published = [p.relative_to(root).as_posix() for p in root.rglob("*")
                 if p.is_file() and not checks.generated_part(p.relative_to(root).as_posix())]
    _track(root, published)
    # Only ignored generated directories: they are skipped, the tree passes.
    assert checks.main(["--root", str(root), "--allow-pending-docs"]) == 0
    _track(root, published + tracked)
    assert checks.main(["--root", str(root), "--allow-pending-docs"]) == 1
    issues = _issues(root, only="scrub,not-exported")
    assert {p for c, p in _categories(issues) if c == "not-exported"} == set(tracked)
    assert {p for c, p in _categories(issues) if c == "scrub"} == set(tracked)
    # The release branch itself is never failed for its layout; the scrub still reads them.
    private = _issues(root, only="scrub,not-exported", private_branch=True)
    assert {p for _, p in _categories(private)} == set(tracked)
    assert {c for c, _ in _categories(private)} == {"scrub"}


def test_generated_directories_without_a_git_index(tmp_path):
    root = _release_tree(tmp_path)
    for rel in GENERATED_SAMPLES:
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(PRIVATE_PATH)
    expected = {"build", "src/sniper_mcp/__pycache__", ".venv", "src/sn1per_mcp.egg-info"}
    # Nothing tells a committed directory apart: the default mode and --export fail.
    assert checks.main(["--root", str(root), "--allow-pending-docs"]) == 1
    for mode in ({}, {"export": True}):
        assert {i.path for i in _issues(root, only="not-exported", **mode)} == expected
    # The private branch or a developer clone without .git: skipped.
    assert checks.main(["--root", str(root), "--allow-pending-docs", "--private-branch"]) == 0
    # --export fails on them even when a git index says they are untracked.
    _track(root, [])
    assert checks.main(["--root", str(root), "--allow-pending-docs"]) == 0
    assert {i.path for i in _issues(root, export=True, only="not-exported")} == expected


def test_files_outside_the_published_layout_fail(tmp_path):
    root = _release_tree(tmp_path)
    (root / "notes.txt").write_text("scratch\n")
    (root / "assets" / "draft.svg").write_text("<svg/>\n")
    (root / "tests" / "test_new.py").write_text("\n".join(checks.SPDX_HEADER) + "\n")
    found = {i.path for i in _issues(root, only="not-exported")}
    assert found == {"notes.txt", "assets/draft.svg"}
    assert _issues(root, only="not-exported", private_branch=True) == []


def test_scrub_covers_nested_generated_names_binary_files_names_and_symlinks(tmp_path):
    lab = "test" + "fire"
    root = _tree(tmp_path, {
        # Directory names that are skipped only at the root are read deeper down.
        "tests/fixtures/build/notes.txt": f"{PRIVATE_PATH}\n",
        "tests/fixtures/dist/notes.txt": f"{PRIVATE_PATH}\n",
        f"tests/fixtures/{lab}-page.txt": "clean\n",
    })
    (root / "blob.bin").write_bytes(b"\x00\x01" + PRIVATE_PATH.encode() + b"\xff\x00")
    (root / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + PRIVATE_PATH.encode("latin-1"))
    os.symlink(PRIVATE_PATH + "/wordlist.txt", root / "wordlist.txt")
    os.symlink("tests", root / "tests-link")
    found = _categories(_issues(root, only="scrub,not-exported"))
    assert {("scrub", "tests/fixtures/build/notes.txt"), ("scrub", "tests/fixtures/dist/notes.txt"),
            ("scrub", f"tests/fixtures/{lab}-page.txt"), ("scrub", "blob.bin"),
            ("scrub", "image.png"), ("scrub", "wordlist.txt"),
            ("not-exported", "wordlist.txt"), ("not-exported", "tests-link")} <= found
    # A symlinked directory is reported, never followed (no second copy of tests/).
    assert not any(path.startswith("tests-link/") for _, path in found)


def test_example_values_in_docs(tmp_path):
    public_v4 = ".".join(["8"] * 4)
    denied = "example" + ".com"
    root = _tree(tmp_path, {
        "docs/install.md": (
            f"Reach 192.0.2.10 but not {public_v4}.\n"
            f"Never {denied} here.\n"
            "```bash\n"
            "SNIPER_MCP_SCOPE=app.example\n"
            "SNIPER_MCP_SCOPE=<authorized-targets>\n"
            "sniper -t app.example -m stealth\n"
            "sniper -t public-name.io -m stealth\n"
            "```\n"),
        "docs/tools.md": f"Refused: `{denied}` is always denied.\n",
        "docs/security-model.md": "Denied: 169.254.0.0/16 and 10.0.0.0/8.\n",
    })
    issues = _issues(root, only="examples")
    messages = [f"{i.path} {i.message}" for i in issues]
    assert any(public_v4 in m for m in messages)
    assert any(denied in m and "install.md:2" in m for m in messages)
    assert any("SNIPER_MCP_SCOPE snippet value 'app.example'" in m for m in messages)
    assert any("public-name.io" in m for m in messages)
    assert not any("tools.md" in m or "security-model.md" in m for m in messages)
    assert not any("192.0.2.10" in m for m in messages)
    # The placeholder line (5) and the example target (6) pass.
    assert not any(m.startswith(("docs/install.md:5 ", "docs/install.md:6 ")) for m in messages)


# Values that would send a reader's scan to a real host (P.5, the 2026-10-10 incident).
UNSAFE_SNIPPETS = {
    "quoted scope with a space": 'export SNIPER_MCP_SCOPE="portal.acme.ch, 192.0.2.0/24"\n',
    "JSON scope default": '{"env": {"SNIPER_MCP_SCOPE": "${SNIPER_MCP_SCOPE:-shop.acme.com}"}}\n',
    "shell scope default": "SNIPER_MCP_SCOPE=${SNIPER_MCP_SCOPE:-shop.acme.com}\n",
    "target default": '{"target": "${T:-shop.acme.com}"}\n',
    "scope-file line, ccTLD": "shop.acme.ch\n",
    "scope-file wildcard": "*.acme.app\n",
    "scope-file exclusion": "!admin.acme.nl\n",
    "YAML scope": "env:\n  SNIPER_MCP_SCOPE: portal.acme.it\n",
    "dotted placeholder": '{"target": "<shop.acme.in>"}\n',
    "public address in scope": "SNIPER_MCP_SCOPE=" + ".".join(["8"] * 4) + "\n",
    "-t argument": "sniper -t portal.acme.ca -m stealth\n",
}


@pytest.mark.parametrize("name", sorted(UNSAFE_SNIPPETS))
def test_unsafe_snippet_values_fail_and_are_never_deferred(tmp_path, name):
    root = _tree(tmp_path, {"docs/clients.md": "```\n" + UNSAFE_SNIPPETS[name] + "```\n"})
    assert any(i.category == "examples" for i in _issues(root, only="examples")), name
    assert checks.main(["--root", str(root), "--allow-pending-docs", "--only", "examples"]) == 1


@pytest.mark.parametrize("snippet", [
    # An inline code span in prose is a snippet too.
    "Set `SNIPER_MCP_SCOPE=inline.acme.io` first.\n",
    # A program-language block: string literals are read.
    '```python\nos.environ["SNIPER_MCP_SCOPE"] = "py.acme.ch"\n```\n',
    # A ``` line inside a four-backtick block, or ~~~ inside ```, does not close it.
    "````markdown\n```\nnested\n```\nSNIPER_MCP_SCOPE=still.acme.ch\n````\n",
    "```bash\n~~~\nsniper -t tilde.acme.ch\n```\n",
])
def test_snippets_found_wherever_they_sit(tmp_path, snippet):
    root = _tree(tmp_path, {"docs/clients.md": snippet})
    assert any(i.category == "examples" for i in _issues(root, only="examples")), snippet


SAFE_SNIPPETS = """\
```bash
SNIPER_MCP_SCOPE=<authorized-targets>
SNIPER_MCP_SCOPE="${SNIPER_MCP_SCOPE:-}"
SNIPER_MCP_SCOPE= HOME="$(mktemp -d)" sn1per-mcp --check
export SNIPER_MCP_SCOPE="${SNIPER_MCP_SCOPE:-<authorized-targets>}"
sniper -t app.example -m stealth
sniper -t "$TARGET" -m web
sn1per-mcp --env-file ~/.config/sn1per-mcp/env
cat server.json sniper.conf nmap-192.0.2.10.txt audit.jsonl
docker run -i --rm sn1per-mcp:0.9.0
pipx install sn1per-mcp && uvx --from sn1per-mcp sn1per-mcp --version
mcp-publisher login dns --domain sn1persecurity.com
```

```json
{"env": {"SNIPER_MCP_SCOPE": "${SNIPER_MCP_SCOPE:-}"}, "target": "https://app.example/login"}
{"io.modelcontextprotocol.registry/publisher-provided": {"com.sn1persecurity": {}}}
{"target": "<target>", "workspace": "app.example"}
```

```toml
[tool.setuptools.dynamic]
[mcp_servers.sn1per]
```

```python
value = os.environ.get("X")
ctx.audit("x")
```

```text
app.example
*.app.example
!admin.app.example
192.0.2.0/24
2001:db8::/32
scan.app.invalid
dev.app.localhost
ip daddr @block_v4 counter reject
```

```bash
ssh -T -i <key> <user>@<host> sn1per-mcp && ssh kali@scanner.test && ssh root@localhost
curl https://localhost:1337/ https://app.invalid/ http://192.0.2.10:8080/ https://[2001:db8::1]:8443/
uvx sn1per-mcp@0.9.0 --version
git clone git@github.com:1N3/sn1per-mcp.git
bash install.sh && cat README.md setup.py sn1per-mcp-0.9.0.tar.gz
docker pull python:3.13-slim@sha256:70729b46c69b
curl "https://${HOST:-app.example}/" && TARGET=${TARGET:-shop.app.test}
```

```python
value = os.environ.get("X")  # reads the environment of app.example
```

```yaml
env: {SNIPER_MCP_SCOPE: <authorized-targets>, SNIPER_MCP_REDACT: "true"}
```

Read `server.json` and `sniper.conf`; `SNIPER_MCP_SCOPE=app.example` is a valid value.
Use the sniper CLI with -t and -m flags. Write to `support@sn1persecurity.com` or run
`ssh <user>@<host>`; the UI is at `https://localhost:1337/`.
"""


# S7 review: a real host must not slip through an exemption meant for something else.
REAL_HOSTS_IN_CODE = {
    "app. prefix (canonical example prefix on a real TLD)": "app.acme.com\n",
    "dev. prefix": "!dev.acme.io\n",
    "ai. prefix": "ai.acme.ch\n",
    "com. first label": "com.acme.ch\n",
    "user@host": "ssh -T -i key user@scan.acme.ch sn1per-mcp\n",
    "git@host": "git clone git@gitlab.acme.ch:team/repo.git\n",
}


@pytest.mark.parametrize("name", sorted(REAL_HOSTS_IN_CODE))
def test_real_hosts_in_code_blocks_fail(tmp_path, name):
    root = _tree(tmp_path, {"docs/remote.md": "```text\n" + REAL_HOSTS_IN_CODE[name] + "```\n"})
    messages = [i.message for i in _issues(root, only="examples")]
    assert any("in a code block is not an example value" in m for m in messages), name


# Fix phase, S7 residual: the host check fails closed. Only reserved example names
# (.example, .test, .invalid, .localhost), placeholders and allowlisted link hosts pass;
# user@host and URL hosts are parsed, and every exemption that let a real host through
# is closed. (info string, body, expected message start)
FAIL_CLOSED_HOSTS = {
    "dot-free user@host": ("bash", "ssh kali@scanner sn1per-mcp\n",
                           "user@host host 'scanner' in a code block"),
    "user@host in JSON args": ("json", '{"args": ["-T", "kali@scanner.acme.com"]}\n',
                               "user@host host 'scanner.acme.com' in a code block"),
    "URL host in a shell block": ("bash", "curl https://shop.acme.com/\n",
                                  "URL host 'shop.acme.com' in a code block"),
    "URL with userinfo and port": ("bash", "git clone ssh://git@scm.acme.ch:2222/team/x\n",
                                   "URL host 'scm.acme.ch' in a code block"),
    "URL in JSON": ("json", '{"url": "https://shop.acme.com/login"}\n',
                    "URL host 'shop.acme.com' in a code block"),
    "URL host from a reference default": ("bash", 'curl "https://${HOST:-shop.acme.ch}/"\n',
                                          "URL host 'shop.acme.ch' in a code block"),
    "variable default": ("bash", "TARGET=${TARGET:-shop.acme.ch}\n",
                         "host name 'shop.acme.ch' in a code block"),
    "quoted table header outside toml": ("text", '["shop.acme.com"]\n',
                                         "host name 'shop.acme.com' in a code block"),
    "table header outside toml": ("text", "[shop.acme.com]\n",
                                  "host name 'shop.acme.com' in a code block"),
    "internationalized name": ("text", "portal.münchen.de\n",
                               "host name 'portal.münchen.de' in a code block"),
    "internationalized, two labels": ("text", "münchen.de\n",
                                      "host name 'münchen.de' in a code block"),
    "punycode top-level domain": ("text", "shop.acme.xn--p1ai\n",
                                  "host name 'shop.acme.xn--p1ai' in a code block"),
    "file extension that is a TLD (.sh)": ("text", "portal.acme.sh\n",
                                           "host name 'portal.acme.sh' in a code block"),
    "file extension that is a TLD (.zip)": ("text", "files.acme.zip\n",
                                            "host name 'files.acme.zip' in a code block"),
    "python comment": ("python", "x = 1  # scan scanner.acme.com first\n",
                       "host name 'scanner.acme.com' in a code block"),
    "go comment": ("go", "x := 1 // see scanner.acme.com\n",
                   "host name 'scanner.acme.com' in a code block"),
    "scope in a flow mapping": ("yaml", "env: {SNIPER_MCP_SCOPE: shop.acme.com}\n",
                                "SNIPER_MCP_SCOPE entry 'shop.acme.com'"),
    "leading-zero address": ("text", "8.8.8" + ".08\n",
                             "address 8.8.8.08 outside the example ranges"),
}


@pytest.mark.parametrize("name", sorted(FAIL_CLOSED_HOSTS))
def test_host_check_fails_closed_and_is_never_deferred(tmp_path, name):
    info, body, expected = FAIL_CLOSED_HOSTS[name]
    root = _tree(tmp_path, {"docs/remote.md": f"```{info}\n{body}```\n"})
    issues = _issues(root, only="examples")
    assert any(i.category == "examples" and i.message.startswith(expected)
               for i in issues), (name, [i.message for i in issues])
    assert checks.main(["--root", str(root), "--allow-pending-docs", "--only", "examples"]) == 1


@pytest.mark.parametrize(("text", "expected"), [
    ("Run `ssh kali@scanner.acme.com` first.\n",
     "user@host host 'scanner.acme.com' in inline code"),
    ("Open `https://shop.acme.com/` first.\n", "URL host 'shop.acme.com' in inline code"),
])
def test_explicit_hosts_in_inline_code_fail(tmp_path, text, expected):
    root = _tree(tmp_path, {"docs/remote.md": text})
    issues = _issues(root, only="examples")
    assert any(i.category == "examples" and i.message.startswith(expected) for i in issues)


def test_fenced_scope_in_a_flow_mapping_must_be_the_placeholder(tmp_path):
    root = _tree(tmp_path, {"docs/clients.md": (
        "```yaml\nenv: {SNIPER_MCP_SCOPE: app.example, SNIPER_MCP_REDACT: true}\n```\n")})
    messages = [i.message for i in _issues(root, only="examples")]
    assert any("SNIPER_MCP_SCOPE snippet value 'app.example' must be <authorized-targets>"
               in m for m in messages), messages


def test_example_rule_covers_the_skill_and_the_github_templates(tmp_path):
    public_v4 = ".".join(["8"] * 4)
    root = _tree(tmp_path, {
        "plugins/sn1per/skills/authorized-scan/SKILL.md": (
            "Use `app.example`.\n```text\nportal.acme.ch\n```\nThen `ssh kali@scan.acme.ch`.\n"),
        ".github/pull_request_template.md": f"Tested against {public_v4}.\n",
        ".github/ISSUE_TEMPLATE/bug.yml": f"placeholder: sniper -t {public_v4}\n",
    })
    found = {(i.path, i.message.split(" '")[0]) for i in _issues(root, only="examples")}
    assert found == {
        ("plugins/sn1per/skills/authorized-scan/SKILL.md:3", "host name"),
        ("plugins/sn1per/skills/authorized-scan/SKILL.md:5", "user@host host"),
        (".github/pull_request_template.md:1", f"address {public_v4} outside the example "
                                               "ranges"),
        (".github/ISSUE_TEMPLATE/bug.yml:1", f"address {public_v4} outside the example "
                                             "ranges"),
    }


def test_reverse_dns_identifiers_and_program_names_pass(tmp_path):
    root = _tree(tmp_path, {"docs/remote.md": (
        "```text\n"
        "LABEL org.opencontainers.image.version and io.modelcontextprotocol.server.name\n"
        "io.github.1N3/sn1per-mcp com.sn1persecurity/sn1per-mcp\n"
        "docker network create -o com.docker.network.bridge.name=<bridge-interface> <network>\n"
        "C:\\Windows\\System32\\OpenSSH\\ssh.exe and wsl.exe -d kali-linux\n"
        "sudo nft -f /etc/nftables.d/sn1per-egress.nft\n"
        "ssh -T -i <dedicated key> <user>@<host> sn1per-mcp\n"
        "ssh -T user@scan.app.example sn1per-mcp\n"
        "```\n")})
    assert [i.message for i in _issues(root, only="examples")] == []


def test_example_hosts_in_code_are_not_links(tmp_path):
    root = _tree(tmp_path, {"docs/tools.md": (
        '```json\n{"location":"https://www.app.example/.git/config"}\n```\n'
        "`https://WWW.App.Example:443/login?x=1` becomes `www.app.example`.\n"
        "Read [this](https://www.app.example/guide) and `https://real.acme.ch/x`.\n"
        '```json\n{"see":"https://other.acme.ch/"}\n```\n')})
    hosts = [i.message for i in _issues(root, only="links")]
    assert len(hosts) == 3, hosts
    assert any("'www.app.example'" in m for m in hosts)  # a prose link is still checked
    assert any("'real.acme.ch'" in m for m in hosts)
    assert any("'other.acme.ch'" in m for m in hosts)


def test_url_host_follows_whatwg_authority_rules():
    assert checks._url_host("https://real.acme.ch\\@app.example/") == "real.acme.ch"
    assert checks._url_host("https://user@app.example:8443/x") == "app.example"
    assert checks._url_host("https:///x") == ""


def test_backslash_userinfo_and_empty_hosts_are_no_example_urls(tmp_path):
    root = _tree(tmp_path, {"docs/tools.md": (
        "```text\nhttps://real.acme.ch\\@app.example/\n```\n"
        "`https:///x` and `https://\\@app.example/`\n")})
    hosts = [i.message for i in _issues(root, only="links")]
    assert len(hosts) == 3, hosts
    assert any("'real.acme.ch'" in m for m in hosts)
    assert sum("host ''" in m for m in hosts) == 2, hosts


VERIFY_MARKER = "<!" + "-- " + "VERIFY" + ": fill from the verification run -->"


def test_verification_placeholders_fail_outside_the_private_branch(tmp_path):
    root = _tree(tmp_path, {"docs/editions.md": f"# Editions\n\n{VERIFY_MARKER}\n"})
    issues, notes = checks.run(_args(root, private_branch=True, only="consistency"))
    assert not [i for i in issues if "verification placeholder" in i.message]
    assert any("docs/editions.md:3" in note for note in notes)
    for mode in ({}, {"export": True}):
        issues, _ = checks.run(_args(root, only="consistency", **mode))
        found = [i for i in issues if "verification placeholder" in i.message]
        assert [i.path for i in found] == ["docs/editions.md:3"], mode
        assert checks.main(["--root", str(root), "--only", "consistency",
                            *(["--export"] if mode else [])]) == 1


@pytest.mark.parametrize("marker", [
    "<!" + "--" + "VERIFY" + ": no space -->",
    "<!" + "-- " + "verify" + ": lower case -->",
    "<!" + "-- " + "VERIFY" + " - no colon -->",
    "<!" + "-- " + "Verify" + " -->",
    "<!" + "-- " + "see the live run; VERIFY" + " later -->",
    "<!" + "-- " + "VERIFY" + "_LATER: underscore -->",
    "<!" + "-- " + "VERIFIED" + " on the lab VM -->",
    "<!" + "-- " + "Verification" + " pending -->",
])
def test_misspelt_verification_placeholders_are_found(tmp_path, marker):
    root = _tree(tmp_path, {"docs/editions.md": f"# Editions\n\n{marker}\n"})
    issues, _ = checks.run(_args(root, export=True, only="consistency"))
    assert [i.path for i in issues if "verification placeholder" in i.message] == \
        ["docs/editions.md:3"]


def test_placeholders_in_comments_that_span_lines_are_found(tmp_path):
    text = ("# Editions\n\n<!" + "--\n  " + "VERIFY" + ": on its own line\n-->\n"
            "Prose.\n<!" + "-- a note,\nthen " + "verified" + " later -->\n")
    root = _tree(tmp_path, {"docs/editions.md": text})
    issues, _ = checks.run(_args(root, export=True, only="consistency"))
    assert [i.path for i in issues if "verification placeholder" in i.message] == \
        ["docs/editions.md:3", "docs/editions.md:7"]


def test_comments_and_words_that_are_no_placeholders_pass(tmp_path):
    root = _tree(tmp_path, {"docs/editions.md": (
        "# Editions\n\nVerify the results on a lab target first.\n"
        "<!" + "-- " + "unverified wording kept on purpose -->\n"
        "<!" + "-- " + "a note --> then verify the output.\n"
        "<!" + "-- " + "a note\nover two lines -->\nVerified by hand.\n")})
    issues, _ = checks.run(_args(root, export=True, only="consistency"))
    assert not [i for i in issues if "verification placeholder" in i.message]


def test_safe_snippet_values_pass(tmp_path):
    root = _tree(tmp_path, {"docs/clients.md": SAFE_SNIPPETS})
    assert [f"{i.path} {i.message}" for i in _issues(root, only="examples")
            if i.category == "examples"] == []


def test_example_values_in_tests_and_scripts(tmp_path):
    public_v4 = ".".join(["8"] * 4)
    root = _tree(tmp_path, {
        "tests/test_x.py": (f'A = "192.0.2.1"\nB = "127.0.0.1"\nC = "10.0.0.0/8"\n'
                            f'D = "0.0.0.0/0"\nE = "{public_v4}"\nF = "1.28.1"\n'
                            # non-canonical target-grammar inputs stay allowed in tests
                            'G = "0177.0.0.1"\nH = "192.0.2.010"\n'),
    })
    messages = [i.message for i in _issues(root, only="examples")]
    assert messages == [f"address {public_v4} is not an example value"]


@pytest.mark.parametrize(("literal", "ok"), [
    ("192.0.2.010", True),  # 192.0.2.10 or, read as octal, 192.0.2.8: both RFC 5737
    ("198.51.100.07/32", True),
    ("8.8.8" + ".08", False),  # its decimal reading is a public address
    ("0177.0.0.1", False),  # a public address read as decimal, loopback as octal
    ("192.0.2.0999", False),  # no address at all
])
def test_non_canonical_addresses_in_docs_pass_only_when_every_reading_does(tmp_path,
                                                                           literal, ok):
    root = _tree(tmp_path, {"docs/tools.md": f"Refused: `{literal}`.\n"})
    messages = [i.message for i in _issues(root, only="examples")]
    assert (messages == []) is ok, messages


def test_links(tmp_path):
    future = "https://sn1persecurity.com/" + "wordpress/" + "documentation/mcp/"
    root = _tree(tmp_path, {
        "README.md": ("[docs](docs/install.md) [ok](https://github.com/1N3/sn1per-mcp)\n"
                      "[x](https://unlisted.example/page)\n"
                      "[home](https://sn1persecurity.com/?utm_source=github&utm_medium=readme"
                      "&utm_campaign=sn1per-mcp)\n"
                      "[bad](https://sn1persecurity.com/pricing)\n"),
        "notes.txt": f"{future}\n",
    })
    messages = [f"{i.path} {i.message}" for i in _issues(root, only="links")]
    assert any("relative link 'docs/install.md'" in m for m in messages)
    assert any("unlisted.example" in m for m in messages)
    assert any("/pricing" in m and "/wordpress/<slug>/" in m for m in messages)
    assert any("/pricing" in m and "utm_source" in m for m in messages)
    assert any(m.startswith("notes.txt") for m in messages)
    assert not any("github.com/1N3" in m for m in messages)


def test_link_scheme_case_and_footnotes(tmp_path):
    root = _tree(tmp_path, {
        "docs/tools.md": "[a](HTTPS://unlisted.invalid/x) and Http://other.invalid/y\n",
        "README.md": "Text[^1].\n\n[^1]: a footnote, not a link\n",
    })
    messages = [i.message for i in _issues(root, only="links")]
    assert any("'unlisted.invalid'" in m for m in messages)
    assert any("'other.invalid'" in m for m in messages)
    assert not any("footnote" in m or "relative link" in m for m in messages)


def _relative_readme_links(tmp_path, readme: str) -> list[str]:
    root = _tree(tmp_path, {"README.md": readme})
    prefix = "[links] relative link "  # README.md is a doc: deferred as docs-pending
    return [i.message[len(prefix):].split(" (")[0].strip("'")
            for i in _issues(root, only="links") if i.message.startswith(prefix)]


def test_readme_badge_with_a_relative_outer_link_fails(tmp_path):
    badge = ("[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)]"
             "(LICENSE)\n")
    assert _relative_readme_links(tmp_path, badge) == ["LICENSE"]


def test_readme_badge_with_a_relative_image_fails(tmp_path):
    badge = "[![logo](assets/sn1per-mcp-256.png)](https://github.com/1N3/sn1per-mcp)\n"
    assert _relative_readme_links(tmp_path, badge) == ["assets/sn1per-mcp-256.png"]


def test_readme_html_images_and_anchors_must_be_absolute(tmp_path):
    readme = ('<p align="center"><img src="assets/sn1per-mcp-256.png" alt="logo"></p>\n'
              "<a href='docs/install.md'>Install</a>\n"
              '<img alt="x" srcset="assets/a.png 1x, https://raw.githubusercontent.com/b.png 2x">\n'
              "<IMG SRC=assets/c.png>\n"
              '<img src="https://raw.githubusercontent.com/1N3/sn1per-mcp/main/assets/ok.png">\n'
              '<a href="mailto:support@sn1persecurity.com">mail</a>\n'
              "[docs]: docs/install.md\n")
    assert sorted(_relative_readme_links(tmp_path, readme)) == sorted([
        "assets/sn1per-mcp-256.png", "docs/install.md", "assets/a.png", "assets/c.png",
        "docs/install.md"])


def test_readme_links_inside_code_blocks_are_not_links(tmp_path):
    readme = ("```markdown\n[x](docs/install.md)\n<img src=\"a.png\">\n```\n"
              "[ok](https://github.com/1N3/sn1per-mcp)\n")
    assert _relative_readme_links(tmp_path, readme) == []


def test_readme_fences_close_only_on_a_matching_fence(tmp_path):
    readme = ("````markdown\n```\n[x](inside.md)\n````\n[y](after.md)\n"
              "~~~\n```\n[z](tilde.md)\n~~~\n")
    assert _relative_readme_links(tmp_path, readme) == ["after.md"]


def test_scrub_em_dash_and_examples_in_docs_are_never_deferred(tmp_path):
    public_v4 = ".".join(["8"] * 4)
    root = _tree(tmp_path, {
        "README.md": f"Install from {PRIVATE_PATH}.\n",
        "docs/install.md": "One " + chr(0x2014) + f" two. Reach {public_v4}.\n",
        "docs/tools.md": "[x](https://unlisted.example/page)\n",
    })
    issues = _issues(root, only="scrub,em-dash,examples,links")
    assert _categories(issues) == {("scrub", "README.md"), ("em-dash", "docs/install.md"),
                                   ("examples", "docs/install.md"),
                                   ("docs-pending", "docs/tools.md")}
    argv = ["--root", str(root), "--allow-pending-docs"]
    assert checks.main([*argv, "--only", "scrub"]) == 1
    assert checks.main([*argv, "--only", "em-dash"]) == 1
    assert checks.main([*argv, "--only", "examples"]) == 1
    assert checks.main([*argv, "--only", "links"]) == 0  # a docs problem: deferred


def test_unpinned_actions_are_refused(tmp_path):
    sha = "a" * 40
    root = _tree(tmp_path, {".github/workflows/x.yml": (
        "jobs:\n  a:\n    steps:\n"
        f"      - uses: actions/checkout@{sha} # v7\n"
        "      - uses: actions/setup-python@v6\n")})
    messages = [i.message for i in _issues(root, only="consistency")
                if i.path.startswith(".github")]
    assert messages == ["action actions/setup-python@v6 is not pinned to a full commit SHA"]


def test_missing_docs_are_their_own_category(tmp_path):
    root = _tree(tmp_path, {})
    issues = _issues(root, only="missing,docs-pending")
    categories = {i.path: i.category for i in issues}
    assert categories["docs/tools.md"] == "docs-pending"
    assert categories["server.json"] == "missing"
    assert checks.main(["--root", str(root), "--only", "docs-pending",
                        "--allow-pending-docs"]) == 0
    assert checks.main(["--root", str(root), "--only", "docs-pending"]) == 1


def test_decisions_file_comparison(tmp_path):
    good = tmp_path / "decisions.env"
    lines = [f"VERSION={VERSION}", f"TAG=v{VERSION}",
             f"REGISTRY_NAME={checks.REGISTRY_NAME}",
             f'REGISTRY_TITLE="{checks.REGISTRY_TITLE}"',
             f'REGISTRY_DESCRIPTION="{checks.DESCRIPTION}"',
             f'PYPI_SUMMARY="{checks.DESCRIPTION}"',
             f"REGISTRY_SCHEMA={checks.SERVER_JSON_SCHEMA}",
             f"MCP_NAME_TOKEN='{checks.MCP_NAME_TOKEN}'",
             f'TAGLINE="{checks.TAGLINE}"',
             f"SCOPE_PLACEHOLDER='{checks.SCOPE_PLACEHOLDER}'",
             f"SERVER_JSON_SCOPE_PLACEHOLDER={checks.SERVER_JSON_SCOPE_PLACEHOLDER}",
             f"FUTURE_DOCS_URL={checks.FUTURE_DOCS_URL}",
             f'LINK_HOST_ALLOWLIST="{" ".join(checks.LINK_HOST_ALLOWLIST)}"',
             f"SCRUB_REGEX='{checks.SCRUB_PATTERN}'",
             f'UTM_GITHUB="{checks.UTM_GITHUB}"',
             f"SUPPORT_EMAIL={checks.SUPPORT_EMAIL}",
             f"REPO_URL={checks.REPO_URL}",
             f'DEVELOPMENT_STATUS="{checks.BETA}"',
             f'DENIED_EXAMPLE_NAMES="{" ".join(checks.DENIED_EXAMPLE_NAMES)}"',
             f'SPDX_HEADER_LINE_1="{checks.SPDX_HEADER[0]}"',
             f'SPDX_HEADER_LINE_2="{checks.SPDX_HEADER[1]}"']
    good.write_text("# comment\n" + "\n".join(lines) + "\n")
    assert checks.check_decisions(good, VERSION) == []
    bad = tmp_path / "bad.env"
    bad.write_text(good.read_text().replace(f"VERSION={VERSION}", "VERSION=9.9.9"))
    assert [i.path for i in checks.check_decisions(bad, VERSION)] == ["VERSION"]


def test_drift_on_other_surfaces(tmp_path):
    surface = tmp_path / "website"
    surface.mkdir()
    files = {
        "page.md": "Install with pipx install sn1per-mcp==0.9.0\n",
        "uvx.md": "uvx --from sn1per-mcp==0.9.0 sn1per-mcp\n",
        "at.md": "uvx sn1per-mcp@0.9.0\n",
        "table.html": "<td><code>SNIPER_MCP_SCOPE</code></td>\n",
        "table.md": "| Setting | Variable |\n|---|---|\n| Scope | `SNIPER_MCP_SCOPE` |\n",
        # Q.1 bans pins and environment tables, not a version-agnostic command.
        "clean.md": "Install with `pipx install sn1per-mcp`, or run `uvx sn1per-mcp`.\n"
                    "Set SNIPER_MCP_SCOPE as the repository docs describe.\n",
        "tools.html": "<TD><code>sniper_scan</code>, <code>scan_status</code></TD>\n",
        # A staged site's build output is what gets published: never skipped.
        "dist/index.html": "pipx install sn1per-mcp==0.9.0\n",
        "build/env.html": "<td>SNIPER_MCP_SCOPE</td>\n",
        "node_modules/x/README.md": "uvx sn1per-mcp@0.9.0\n",
        "__pycache__/x.txt": "uvx sn1per-mcp@0.9.0\n",
    }
    for name, text in files.items():
        (surface / name).parent.mkdir(parents=True, exist_ok=True)
        (surface / name).write_text(text)
    paths = {Path(i.path.split(":")[0]).relative_to(surface).as_posix()
             for i in checks.check_drift([surface])}
    assert paths == {"page.md", "uvx.md", "at.md", "table.html", "table.md", "dist/index.html",
                     "build/env.html", "node_modules/x/README.md", "__pycache__/x.txt"}


def _wheel(path: Path, members: dict[str, str]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, text in members.items():
            archive.writestr(name, text)


def _sdist(path: Path, members: dict[str, str]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, text in members.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))


def test_dist_contents(tmp_path):
    stem = f"sn1per_mcp-{VERSION}"
    info = f"{stem}.dist-info/"
    metadata = (f"Name: sn1per-mcp\nVersion: {VERSION}\nLicense-Expression: Apache-2.0\n\n"
                f"{checks.MCP_NAME_TOKEN}\n")
    entry_points = ("[console_scripts]\nsn1per-mcp = sniper_mcp.server:main\n"
                    "sniper-mcp-server = sniper_mcp.server:main\n")
    good = {"sniper_mcp/__init__.py": "", info + "METADATA": metadata,
            info + "entry_points.txt": entry_points, info + "licenses/LICENSE": "x",
            info + "licenses/NOTICE": "x"}
    sdist = {f"{stem}/{name}": "x" for name in (
        "LICENSE", "NOTICE", "TRADEMARKS.md", "server.json", "README.md", "pyproject.toml",
        "tests/conftest.py", "tests/fixtures/a.txt", "SECURITY.md", "CHANGELOG.md",
        "docs/install.md", "scripts/check_release_consistency.py", "scripts/mcp-call.py")}
    dist = tmp_path / "dist"
    dist.mkdir()
    _wheel(dist / f"{stem}-py3-none-any.whl", good)
    _sdist(dist / f"{stem}.tar.gz", sdist)
    assert checks.check_dist(dist, VERSION) == []

    bad = dict(good)
    del bad[info + "licenses/NOTICE"]
    bad["tests/test_x.py"] = ""
    bad[info + "METADATA"] = metadata.replace(checks.MCP_NAME_TOKEN, "")
    _wheel(dist / f"{stem}-py3-none-any.whl", bad)
    internal = "CLAUDE" + ".md"
    without_script = {k: v for k, v in sdist.items() if not k.endswith("mcp-call.py")}
    _sdist(dist / f"{stem}.tar.gz", {**without_script, f"{stem}/{internal}": "x"})
    found = {(i.category, i.message) for i in checks.check_dist(dist, VERSION)}
    messages = {m for _, m in found}
    assert f"missing {info}licenses/NOTICE" in messages
    assert "tests must not be in the wheel: tests/test_x.py" in messages
    assert f"must not ship {internal}" in messages
    assert "missing scripts/mcp-call.py" in messages
    assert any(c == "docs-pending" and "METADATA lacks" in m for c, m in found)


# --- scripts/mcp-call.py ------------------------------------------------------------------

@pytest.mark.parametrize("tool", ["sniper_scan", "cancel_scan", "delete_workspace",
                                  "export_workspace"])
def test_mcp_call_refuses_state_changing_tools(tool, capsys):
    # Refused before any process starts (the guard would fail the test otherwise).
    assert mcp_call.main([tool, '{"target":"app.example"}']) == 2
    assert "--allow-state-changing" in capsys.readouterr().err


def test_mcp_call_usage_errors(capsys):
    assert mcp_call.main([]) == 2
    assert mcp_call.main(["get_findings", "not json"]) == 2
    assert mcp_call.main(["get_findings", "[1]"]) == 2
    assert mcp_call.main(["--help"]) == 0
    assert "192.0.2.10" in capsys.readouterr().out


def test_mcp_call_answer_is_a_response_not_a_server_request():
    read_fd, write_fd = os.pipe()
    try:
        lines = [{"jsonrpc": "2.0", "id": 2, "method": "ping"},
                 {"jsonrpc": "2.0", "id": 2, "method": "elicitation/create", "params": {}},
                 {"jsonrpc": "2.0", "id": 2, "result": {"tools": []}}]
        os.write(write_fd, "".join(json.dumps(m) + "\n" for m in lines).encode())
        os.close(write_fd)
        write_fd = -1
        answer = mcp_call._read_answer(read_fd, time.monotonic() + 30)
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)
    assert answer == {"jsonrpc": "2.0", "id": 2, "result": {"tools": []}}


def test_mcp_call_fails_when_the_server_exits_before_reading(monkeypatch, capsys):
    class Pipe:
        def write(self, data):
            raise BrokenPipeError(32, "Broken pipe")

        def flush(self):
            raise BrokenPipeError(32, "Broken pipe")

        def close(self):
            raise BrokenPipeError(32, "Broken pipe")

        def fileno(self):
            raise AssertionError("nothing to read from a server that is gone")

    class GoneServer:
        def __init__(self, *args, **kwargs):
            self.stdin, self.stdout = Pipe(), Pipe()

        def wait(self, timeout=None):
            return 1

    monkeypatch.setattr(mcp_call.subprocess, "Popen", GoneServer)
    monkeypatch.setenv("SERVER", "sn1per-mcp")
    assert mcp_call.main(["sniper_status"]) == 1
    assert "no answer from the server" in capsys.readouterr().err


def test_mcp_call_server_command_is_split_like_a_shell(monkeypatch):
    monkeypatch.setenv("SERVER", "docker run -i --rm 'sn1per-mcp:0.9.0'")
    assert mcp_call._server_command() == ["docker", "run", "-i", "--rm", "sn1per-mcp:0.9.0"]


FAKE_SERVER = """\
import json, sys
for _ in range(3):
    sys.stdin.readline()
# Both replies in one write, so they reach the client in a single read.
replies = [{"jsonrpc": "2.0", "id": 1, "result": {"capabilities": {}}},
           {"jsonrpc": "2.0", "id": 2,
            "result": {"content": [{"type": "text", "text": "answer-two"}]}}]
sys.stdout.write("".join(json.dumps(r) + "\\n" for r in replies))
sys.stdout.flush()
sys.stdin.read()
"""


def test_mcp_call_reads_a_reply_that_arrives_with_the_previous_one(iso, tmp_path):
    fake = tmp_path / "fake_server.py"
    fake.write_text(FAKE_SERVER)
    env = iso.child_env(SERVER=f"{sys.executable} {fake}", MCP_CALL_TIMEOUT="30",
                        HOME=str(iso.home))
    script = str(REPO / "scripts" / "mcp-call.py")
    started = time.monotonic()
    result = subprocess.run([sys.executable, script, "sniper_status"], env=env,
                            cwd=str(iso.tmp), capture_output=True, text=True, timeout=60,
                            check=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "answer-two"
    # The answer was already in hand: no wait for the timeout.
    assert time.monotonic() - started < 20


def test_mcp_call_lists_tools_over_stdio(iso):
    env = iso.child_env(SNIPER_SCAN_ENABLED="false", SNIPER_BIN="/nonexistent/sniper",
                        SNIPER_MCP_SCOPE="", SNIPER_INSTALL_DIR=str(iso.install_dir),
                        SNIPER_LOOT_BASE=str(iso.loot_base), HOME=str(iso.home),
                        XDG_STATE_HOME=str(iso.tmp / "xdg-state"),
                        SERVER=f"{sys.executable} -m sniper_mcp", MCP_CALL_TIMEOUT="60")
    script = str(REPO / "scripts" / "mcp-call.py")
    result = subprocess.run([sys.executable, script, "tools"], env=env, cwd=str(iso.tmp),
                            capture_output=True, text=True, timeout=90, check=False)
    assert result.returncode == 0, result.stderr
    names = [line.split()[0] for line in result.stdout.splitlines()]
    assert sorted(names) == sorted([
        "sniper_status", "sniper_scan", "scan_status", "cancel_scan", "list_workspaces",
        "get_findings", "get_ports", "get_subdomains", "get_technologies", "grep_loot"])
    assert len(names) == checks.TOOL_COUNT_DEFAULT

    status = subprocess.run([sys.executable, script, "sniper_status"], env=env,
                            cwd=str(iso.tmp), capture_output=True, text=True, timeout=90,
                            check=False)
    assert status.returncode == 0, status.stderr
    assert json.loads(status.stdout)["tool"] == "sniper_status"


# The P.8 server.json block of the contract (host paths from tests/realpaths.py, O.2).
EXPECTED_SERVER_JSON = {
    "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
    "name": "io.github.1N3/sn1per-mcp",
    "title": "Sn1per MCP Server: pentest, recon and attack surface scanning",
    "description": (
        "Run scoped, authorized Sn1per pentest, recon and attack surface scans from AI agents; "
        "read findings."
    ),
    "version": "0.9.0",
    "websiteUrl": "https://github.com/1N3/sn1per-mcp#readme",
    "repository": {"url": "https://github.com/1N3/sn1per-mcp", "source": "github"},
    "icons": [
        {
            "src": (
                "https://raw.githubusercontent.com/1N3/sn1per-mcp/v0.9.0/assets/sn1per-mcp-256.png"
            ),
            "mimeType": "image/png",
            "sizes": ["256x256"],
        },
    ],
    "packages": [
        {
            "registryType": "pypi",
            "registryBaseUrl": "https://pypi.org",
            "identifier": "sn1per-mcp",
            "version": "0.9.0",
            "runtimeHint": "uvx",
            "transport": {"type": "stdio"},
            "environmentVariables": [
                {
                    "name": "SNIPER_MCP_SCOPE",
                    "description": (
                        "Comma-separated domains, IPs and CIDR ranges you are authorized to test "
                        "(prefix ! to exclude). Scans outside it are refused."
                    ),
                    "isRequired": False,
                    "isSecret": False,
                    "format": "string",
                    "placeholder": "app.example,192.0.2.0/24",
                },
                {
                    "name": "SNIPER_MCP_SCOPE_FILE",
                    "description": (
                        "Optional absolute path to a scope file with one or more entries per line "
                        "and # comments."
                    ),
                    "isRequired": False,
                    "isSecret": False,
                    "format": "filepath",
                },
                {
                    "name": "SNIPER_MCP_AUTHORIZATION_REF",
                    "description": (
                        "Optional authorization reference, such as a statement-of-work or ticket "
                        "id, recorded in the audit log."
                    ),
                    "isRequired": False,
                    "isSecret": False,
                    "format": "string",
                },
                {
                    "name": "SNIPER_MCP_ALLOW_INTRUSIVE",
                    "description": (
                        "Set to true to offer scan modes that run brute force, exploitation or "
                        "injection testing. Off by default."
                    ),
                    "isRequired": False,
                    "isSecret": False,
                    "format": "boolean",
                    "default": "false",
                },
                {
                    "name": "SNIPER_MCP_ENABLE_DESTRUCTIVE",
                    "description": (
                        "Set to true to add the workspace delete and export tools; they ask the "
                        "human to confirm. Off by default."
                    ),
                    "isRequired": False,
                    "isSecret": False,
                    "format": "boolean",
                    "default": "false",
                },
                {
                    "name": "SNIPER_MCP_REDACT",
                    "description": (
                        "Redaction of secrets in results. On by default; turn off only with a "
                        "local model when raw values are required."
                    ),
                    "isRequired": False,
                    "isSecret": False,
                    "format": "boolean",
                    "default": "true",
                },
                {
                    "name": "SNIPER_EDITION",
                    "description": "Optional override of the auto-detected Sn1per edition.",
                    "isRequired": False,
                    "isSecret": False,
                    "format": "string",
                    "choices": ["auto", "ce", "se", "pro", "enterprise"],
                    "default": "auto",
                },
                {
                    "name": "SNIPER_BIN",
                    "description": (
                        "Optional absolute path to the sniper CLI. Detected automatically on "
                        "standard installs."
                    ),
                    "isRequired": False,
                    "isSecret": False,
                    "format": "filepath",
                    "placeholder": realpaths.SNIPER_SHARE_CLI,
                },
                {
                    "name": "SNIPER_INSTALL_DIR",
                    "description": (
                        "Optional Sn1per install directory. Read from the CLI or /usr/share/"
                        "sniper by default."
                    ),
                    "isRequired": False,
                    "isSecret": False,
                    "format": "filepath",
                    "placeholder": realpaths.SNIPER_SHARE,
                },
                {
                    "name": "SNIPER_LOOT_BASE",
                    "description": (
                        "Optional directory that contains the loot workspace tree. Defaults to "
                        "the install directory's loot folder."
                    ),
                    "isRequired": False,
                    "isSecret": False,
                    "format": "filepath",
                    "placeholder": realpaths.SNIPER_SHARE_LOOT,
                },
                {
                    "name": "SNIPER_SCAN_ENABLED",
                    "description": (
                        "Set to false for a read-only deployment that never launches scans."
                    ),
                    "isRequired": False,
                    "isSecret": False,
                    "format": "boolean",
                    "default": "true",
                },
            ],
        },
    ],
    "_meta": {
        "io.modelcontextprotocol.registry/publisher-provided": {
            "com.sn1persecurity": {
                "editions": ["ce", "se", "pro", "enterprise"],
                "platform": "linux",
                "transport": "stdio only",
                "hostRequirements": (
                    "Runs beside a local Sn1per install (CE 9.x or the 11.x engine). Scan and "
                    "delete tools need root through a passwordless sudo rule for the Sn1per CLI; "
                    "read tools run unprivileged."
                ),
                "intendedUse": (
                    "Authorized security testing only: systems you own or are explicitly "
                    "permitted in writing to test."
                ),
                "controls": (
                    "Mandatory target scope, local JSONL audit log, secrets redaction; intrusive "
                    "modes and destructive tools are off by default."
                ),
                "documentation": "https://github.com/1N3/sn1per-mcp#readme",
                "securityPolicy": "https://github.com/1N3/sn1per-mcp/security/policy",
            },
        },
    },
}
