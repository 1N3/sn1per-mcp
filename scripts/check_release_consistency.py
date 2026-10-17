#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Release checks for the Sn1per MCP Server repository.

Runs over the repository tree (default: the parent of this script) and fails on:

  missing       a file of the published layout is absent
  docs-pending  a documentation file is absent or fails a check (README.md, docs/,
                SECURITY.md, SUPPORT.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md,
                CHANGELOG.md); a separate category so a tree whose documentation is
                still being written can be checked with --allow-pending-docs. Scrub,
                em-dash and example-value problems are never moved into it.
  not-exported  a file that never ships is present, a file outside the published
                layout, a symlink, or a file inside a build, cache or
                virtual-environment directory (see "Which files are read"). Not
                checked with --private-branch.
  scrub         a private path, address, host or internal name in any file (binary
                files are read as latin-1), in a file or directory name, or in the
                target of a symlink
  em-dash       the em-dash character or one of its HTML entities in any text file
  examples      an IP literal or target value outside the example ranges and names
  links         a relative link in README.md, a link host outside the allowlist, a
                link to the documentation page that is not live yet, or a
                sn1persecurity.com link in the wrong form
  consistency   version pins, names, descriptions, placeholders, classifiers, the
                documented environment variables, server.json, plugin files,
                Dockerfile labels, SPDX headers, workflow action pins, the icon, and
                verification placeholders (an HTML comment that opens with VERIFY and a
                colon) outside the private branch
  decisions     an embedded constant differs from the decisions file (--decisions)
  drift         a version pin or environment table on a non-repository surface
                (--surfaces)
  dist          wheel or sdist contents (--dist)

Usage:
  check_release_consistency.py [--root DIR] [--allow-pending-docs]
                               [--export | --private-branch]
                               [--decisions FILE] [--surfaces DIR ...]
                               [--dist DIR] [--only CATEGORY[,CATEGORY...]] [--json]
  check_release_consistency.py --print-version

Tree modes:
  (default)         a repository checkout, as in CI: a never-exported file that is
                    present fails and is scrubbed like every other file
  --export          the exported public tree: also fails on build, cache and
                    virtual-environment directories at any depth
  --private-branch  the private release branch or a developer clone, which may carry
                    the never-exported files: they are listed in a note and not read

Which files are read: every file of the tree, except that generated directories
(__pycache__, .pytest_cache, .ruff_cache, .mypy_cache and *.egg-info at any depth;
.venv, venv, build, dist, .eggs, node_modules and htmlcov at the root) are not
entered, because pip and ruff create them in CI before the check runs. A committed
file is never skipped: when <root>/.git exists the git index is read (without
running git), and a tracked file inside a generated directory is read, scrubbed and
fails as not-exported. Without a readable index a generated directory fails in the
default mode and with --export (nothing tells it apart from a committed one) and is
skipped with --private-branch. Only .git itself is never read.

Exit status: 0 when nothing fails, 1 when a check fails, 2 on a usage error.
Only the standard library is needed for --print-version and --dist; the tree checks
also import trove-classifiers and the package's scope tables (install '.[dev]').
"""

from __future__ import annotations

import argparse
import ast
import ipaddress
import json
import os
import re
import struct
import sys
import tarfile
import zipfile
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

# --- identity and canonical values ------------------------------------------------------

REPO_URL = "https://github.com/1N3/sn1per-mcp"
REGISTRY_NAME = "io.github.1N3/sn1per-mcp"
REGISTRY_TITLE = "Sn1per MCP Server: pentest, recon and attack surface scanning"
DESCRIPTION = ("Run scoped, authorized Sn1per pentest, recon and attack surface scans "
               "from AI agents; read findings.")
TAGLINE = ("Drive your self-hosted Sn1per from your AI assistant: scoped, audited, "
           "for authorized testing.")
MCP_NAME_TOKEN = "<!-- mcp-name: " + REGISTRY_NAME + " -->"
SCOPE_PLACEHOLDER = "<authorized-targets>"
SERVER_JSON_SCOPE_PLACEHOLDER = "app.example,192.0.2.0/24"
SERVER_JSON_SCHEMA = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
SUPPORT_EMAIL = "support@sn1persecurity.com"
OWNER = {"name": "Sn1perSecurity LLC", "email": SUPPORT_EMAIL}
SPDX_HEADER = ["# SPDX-License-Identifier: Apache-2.0", "# Copyright 2026 Sn1perSecurity LLC"]
BETA = "Development Status :: 4 - Beta"
UTM_GITHUB = "utm_source=github&utm_medium=readme&utm_campaign=sn1per-mcp"
# Built from parts so that this file never contains the address it searches for.
FUTURE_DOCS_URL = "https://sn1persecurity.com/" + "wordpress/" + "documentation/mcp/"
LINK_HOST_ALLOWLIST = (
    "github.com raw.githubusercontent.com pypi.org img.shields.io docs.astral.sh "
    "pipx.pypa.io sn1persecurity.com .modelcontextprotocol.io keepachangelog.com "
    "semver.org www.contributor-covenant.org developercertificate.org www.apache.org "
    "code.claude.com code.visualstudio.com vscode.dev insiders.vscode.dev cursor.com "
    "docs.github.com www.iana.org www.rfc-editor.org").split()
DENIED_EXAMPLE_NAMES = ("example.com", "example.net", "example.org")
# The environment variables that server.json exposes (all optional).
SERVER_JSON_ENV = (
    "SNIPER_MCP_SCOPE", "SNIPER_MCP_SCOPE_FILE", "SNIPER_MCP_AUTHORIZATION_REF",
    "SNIPER_MCP_ALLOW_INTRUSIVE", "SNIPER_MCP_ENABLE_DESTRUCTIVE", "SNIPER_MCP_REDACT",
    "SNIPER_EDITION", "SNIPER_BIN", "SNIPER_INSTALL_DIR", "SNIPER_LOOT_BASE",
    "SNIPER_SCAN_ENABLED")
TOOL_COUNT_DEFAULT = 10

# --- scrub pattern ----------------------------------------------------------------------
# Every alternative is stored reversed so that this file, which the scrub also covers,
# never contains a token it searches for. --decisions compares the assembled pattern
# with SCRUB_REGEX in the decisions file.
_SCRUB_REVERSED = (
    ')<!?(/emoh/', '/tsetnep/', '/repins/)]-._9-0z-aZ-A[!<?(', '@zyad0rex', 'liamnotorp',
    'liamhsuh', 'E413x0', 'ytilibisaef', '#? evitceriD', 'pcm-deifinu', 'enigne?] _-[gar',
    'tneilc_gar', 'ENIGNE_GAR', 'tool_yreuq', 'enigne egdelwonk', '0008:tsohlacol',
    'revres-ytiruces-pcm', 'niahctnelis', ')8/0!?(.\\0.\\0.\\01', '.\\85.\\861.\\291',
    '.\\0.\\71.\\271', '.\\232.\\561', '.\\842.\\401', 'eriftset', 'bewnluv', 'itcivnitset',
    'dnuorg-tsetnep', 'gfum', 'yapellez', 'elbatiolpsatem', 'dm.\\EDUALC',
)
SCRUB_PATTERN = "(" + "|".join(a[::-1] for a in _SCRUB_REVERSED) + ")"
SCRUB = re.compile(SCRUB_PATTERN, re.IGNORECASE)

# The em-dash and its three HTML entity spellings, built from code points.
EM_DASH_PATTERNS = (
    re.compile(re.escape(chr(0x2014))),
    re.compile(re.escape("&" + "mdash;"), re.IGNORECASE),
    re.compile("&#0*" + "8212;"),
    re.compile("&#[xX]0*" + "2014;"),
)

# --- layout -----------------------------------------------------------------------------

DOC_FILES = (
    "README.md", "SECURITY.md", "SUPPORT.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md",
    "CHANGELOG.md", "docs/install.md", "docs/configuration.md", "docs/editions.md",
    "docs/tools.md", "docs/security-model.md", "docs/remote.md", "docs/clients.md",
    "docs/troubleshooting.md",
)
LAYOUT_FILES = (
    "LICENSE", "NOTICE", "TRADEMARKS.md", "pyproject.toml", "MANIFEST.in", "server.json",
    "Dockerfile", ".dockerignore", ".gitignore", "Makefile", "assets/sn1per-mcp-256.png",
    "scripts/mcp-call.py", "scripts/check_release_consistency.py",
    "src/sniper_mcp/__init__.py", "tests/conftest.py",
    ".github/workflows/ci.yml", ".github/workflows/release.yml", ".github/dependabot.yml",
    ".github/CODEOWNERS", ".github/pull_request_template.md",
    ".github/ISSUE_TEMPLATE/bug.yml", ".github/ISSUE_TEMPLATE/edition-compat.yml",
    ".github/ISSUE_TEMPLATE/feature.yml", ".github/ISSUE_TEMPLATE/config.yml",
    ".claude-plugin/marketplace.json", "plugins/sn1per/.claude-plugin/plugin.json",
    "plugins/sn1per/.mcp.json", "plugins/sn1per/skills/authorized-scan/SKILL.md",
)
# Published files outside DOC_FILES that readers or agents copy examples from; the
# example-value rule of the docs applies to them as well (P.5).
EXAMPLE_CHECKED_FILES = frozenset({
    "TRADEMARKS.md", ".github/pull_request_template.md",
    ".github/ISSUE_TEMPLATE/bug.yml", ".github/ISSUE_TEMPLATE/edition-compat.yml",
    ".github/ISSUE_TEMPLATE/feature.yml", ".github/ISSUE_TEMPLATE/config.yml",
    "plugins/sn1per/skills/authorized-scan/SKILL.md",
})
# Files that exist on the release branch but are never exported. Names are built from
# parts where the scrub pattern would otherwise match them.
NOT_EXPORTED_FILES = (
    "CLAUDE" + ".md", ".gitleaks.toml",
    "src/sniper_mcp/" + "rag" + "_client.py", "src/sniper_mcp/tools/query.py",
    "tests/test_query.py",
)
# Generated directories. Caches can appear at any depth; the others only at the root,
# so a directory with one of their names deeper in the tree (tests/fixtures/build/) is
# read like any other. `.git` is git's own data (a directory, or the pointer file of a
# worktree) and is never read or reported.
GIT_DIR = ".git"
CACHE_DIRS = frozenset({"__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache"})
ROOT_ONLY_DIRS = frozenset({".venv", "venv", "build", "dist", ".eggs", "node_modules",
                            "htmlcov"})
SKIPPED_DIRS = CACHE_DIRS | ROOT_ONLY_DIRS | {GIT_DIR}
# P.1: the top level of the published tree. Below src/sniper_mcp/ and tests/ any file
# may exist; everywhere else only the files of LAYOUT_FILES and DOC_FILES.
OPEN_LAYOUT_PREFIXES = ("src/sniper_mcp/", "tests/")
# Pages that may show the always-denied names, in refusal examples only.
DENIED_NAMES_ALLOWED_IN = frozenset(
    {"docs/security-model.md", "docs/tools.md", "docs/troubleshooting.md"})
LINK_CHECKED_FILES = ("README.md", "SECURITY.md", "SUPPORT.md", "CONTRIBUTING.md",
                      "CHANGELOG.md")

CATEGORIES = ("missing", "docs-pending", "not-exported", "scrub", "em-dash", "examples",
              "links", "consistency", "decisions", "drift", "dist")
# Categories that are never moved into docs-pending, even inside a documentation file:
# a leak or an unsafe example value fails whatever --allow-pending-docs says.
NEVER_DEFERRED = frozenset({"scrub", "em-dash", "examples"})
NOT_RELABELLED = frozenset({"docs-pending", "drift", "dist"}) | NEVER_DEFERRED
MODES = ("checkout", "export", "private")


@dataclass(frozen=True)
class Issue:
    category: str
    path: str
    message: str

    def render(self) -> str:
        return f"  {self.path}: {self.message}" if self.path else f"  {self.message}"


def is_doc(rel: str) -> bool:
    return rel in DOC_FILES or (rel.startswith("docs/") and rel.endswith(".md"))


# --- file access ------------------------------------------------------------------------

class Tree:
    """Every file of the repository tree, read once.

    mode is "checkout" (the default: a CI checkout or any tree of unknown origin),
    "export" (the exported public tree) or "private" (the private release branch or a
    developer clone, where the never-exported files may legitimately exist).

    The tree is walked; generated directories (caches and *.egg-info at any depth, the
    build, dist and virtual-environment directories at the root) are not entered. In
    "checkout" and "private" mode the git index tells which files are committed: a
    tracked file inside a generated directory is read and fails like any other file
    outside the published layout. Without a readable index a generated directory
    fails (except in "private" mode), because nothing tells it apart from a committed
    one.
    """

    def __init__(self, root: Path, mode: str = "checkout") -> None:
        if mode not in MODES:
            raise ValueError(f"unknown tree mode {mode!r}")
        self.root = root
        self.mode = mode
        self._text: dict[str, str] = {}
        # Binary files as latin-1, for the scrub only.
        self._binary: dict[str, str] = {}
        # Binary files that are UTF-8 text apart from NUL bytes, for the em-dash check.
        self._nul_text: dict[str, str] = {}
        self.paths: list[str] = []          # every walked file, symlink and directory
        self.symlinks: dict[str, str] = {}  # relative path -> link target
        self.generated_dirs: list[str] = []  # skipped generated directories
        # Tracked files inside a generated directory (committed build output or caches).
        self.generated_files: list[str] = []
        self.skipped_internal: list[str] = []
        self.notes: list[str] = []
        self.tracked: list[str] | None = None
        if mode != "export":
            self.tracked = git_index_paths(root)
            if self.tracked is None and (root / GIT_DIR).exists():
                self.notes.append("the git index could not be read; generated directories "
                                  "are treated as possibly committed")
        self._load()

    @property
    def export(self) -> bool:
        return self.mode == "export"

    @property
    def private(self) -> bool:
        return self.mode == "private"

    @property
    def generated_dirs_fail(self) -> bool:
        return self.export or (self.tracked is None and not self.private)

    def _load(self) -> None:
        entries = [(kind, path.relative_to(self.root).as_posix())
                   for kind, path in self._walk(self.root)]
        if self.tracked is not None:
            # Committed files that the walk does not enter.
            skipped = tuple(rel + "/" for kind, rel in entries if kind == "generated")
            for rel in self.tracked:
                if rel.startswith(skipped):
                    path = self.root / rel
                    if path.is_symlink():
                        entries.append(("symlink", rel))
                    elif path.is_file():
                        entries.append(("file", rel))
                    else:
                        continue
                    self.generated_files.append(rel)
        for kind, rel in entries:
            if self.private and rel in NOT_EXPORTED_FILES:
                self.skipped_internal.append(rel)
                continue
            path = self.root / rel
            self.paths.append(rel)
            if kind == "generated":
                self.generated_dirs.append(rel)
            elif kind == "symlink":
                try:
                    self.symlinks[rel] = os.readlink(path)
                except OSError:
                    self.symlinks[rel] = ""
            elif kind == "file":
                try:
                    data = path.read_bytes()
                except OSError:
                    continue
                try:
                    if b"\0" in data:
                        raise UnicodeDecodeError("utf-8", data, 0, 1, "NUL byte")
                    self._text[rel] = data.decode("utf-8")
                except UnicodeDecodeError:
                    self._binary[rel] = data.decode("latin-1")
                    try:
                        self._nul_text[rel] = data.replace(b"\0", b"").decode("utf-8")
                    except UnicodeDecodeError:
                        pass

    @staticmethod
    def _walk(root: Path) -> Iterator[tuple[str, Path]]:
        """(kind, path) with kind "file", "dir", "symlink" or "generated".

        Symlinks are never followed. Generated directories are reported, not entered.
        """
        for dirpath, dirnames, filenames in os.walk(root):
            here = Path(dirpath)
            at_root = here == root
            keep = []
            for name in sorted(dirnames):
                path = here / name
                if name == GIT_DIR and at_root:
                    continue
                if path.is_symlink():
                    yield "symlink", path
                elif name in CACHE_DIRS or name.endswith(".egg-info") or (
                        at_root and name in ROOT_ONLY_DIRS):
                    yield "generated", path
                else:
                    yield "dir", path
                    keep.append(name)
            dirnames[:] = keep
            for name in sorted(filenames):
                if name == GIT_DIR and at_root:  # a worktree's pointer file
                    continue
                path = here / name
                if path.is_symlink():
                    yield "symlink", path
                elif path.is_file():
                    yield "file", path

    def text(self, rel: str) -> str | None:
        return self._text.get(rel)

    def items(self) -> Iterable[tuple[str, str]]:
        return self._text.items()

    def binary_items(self) -> Iterable[tuple[str, str]]:
        return self._binary.items()

    def nul_text_items(self) -> Iterable[tuple[str, str]]:
        return self._nul_text.items()

    def exists(self, rel: str) -> bool:
        return (self.root / rel).is_file()


def generated_part(rel: str) -> str | None:
    """The generated directory that contains rel (a cache or *.egg-info directory at
    any depth, or a build, dist or virtual-environment directory at the root)."""
    parts = rel.split("/")[:-1]
    for depth, name in enumerate(parts):
        if name in CACHE_DIRS or name.endswith(".egg-info") or (
                depth == 0 and name in ROOT_ONLY_DIRS):
            return "/".join(parts[:depth + 1])
    return None


def _git_dir(root: Path) -> Path | None:
    """The git directory of the work tree at root: .git itself, or the directory named
    by the `gitdir:` line of a worktree's .git file."""
    dot_git = root / GIT_DIR
    if dot_git.is_dir():
        return dot_git
    if dot_git.is_file():
        try:
            first = dot_git.read_text(encoding="utf-8").splitlines()[0]
        except (OSError, UnicodeDecodeError, IndexError):
            return None
        if first.startswith("gitdir:"):
            target = Path(first[len("gitdir:"):].strip())
            return target if target.is_absolute() else root / target
    return None


def _parse_git_index(data: bytes, hash_size: int) -> list[str]:
    """The paths of a git index file (format versions 2, 3 and 4); ValueError when the
    data is not an index with entries of hash_size bytes."""
    if data[:4] != b"DIRC" or len(data) < 12:
        raise ValueError("not a git index")
    version, count = struct.unpack(">II", data[4:12])
    if version not in (2, 3, 4):
        raise ValueError(f"index version {version}")
    offset, previous, paths = 12, b"", []
    for _ in range(count):
        start = offset
        offset += 40 + hash_size
        (flags,) = struct.unpack(">H", data[offset:offset + 2])
        offset += 2
        if flags & 0x4000:
            if version < 3:
                raise ValueError("extended flag in a version 2 index")
            offset += 2
        if version == 4:
            byte = data[offset]
            offset += 1
            strip = byte & 0x7F
            while byte & 0x80:
                byte = data[offset]
                offset += 1
                strip = ((strip + 1) << 7) | (byte & 0x7F)
            if strip > len(previous):
                raise ValueError("bad path prefix")
            end = data.index(b"\0", offset)
            path = previous[:len(previous) - strip] + data[offset:end]
            offset = end + 1
        else:
            end = data.index(b"\0", offset)
            path = data[offset:end]
            offset = start + ((end - start + 8) & ~7)
            if data[end:offset].strip(b"\0"):
                raise ValueError("bad entry padding")
        length = flags & 0x0FFF
        if length != 0x0FFF and length != len(path):
            raise ValueError("entry name length differs")
        if offset > len(data):
            raise ValueError("truncated index")
        previous = path
        paths.append(os.fsdecode(path))
    return paths


def git_index_paths(root: Path) -> list[str] | None:
    """The files of the git index of the work tree at root (tracked files), [] for a
    repository without an index yet, or None when there is no readable index.

    Read without running git, so it works in any container, as any user and under the
    test suite's process guard."""
    git_dir = _git_dir(root)
    if git_dir is None or not git_dir.is_dir():
        return None
    index = git_dir / "index"
    if not index.exists():
        return []
    try:
        data = index.read_bytes()
    except OSError:
        return None
    for hash_size in (20, 32):  # SHA-1 and SHA-256 repositories
        try:
            return sorted(set(_parse_git_index(data, hash_size)))
        except (ValueError, IndexError, struct.error):
            continue
    return None


def walk_all(root: Path) -> Iterator[Path]:
    """Every regular file below root, symlinks not followed, only .git skipped."""
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        dirnames[:] = sorted(n for n in dirnames
                             if n != GIT_DIR and not (here / n).is_symlink())
        for name in sorted(filenames):
            path = here / name
            if not path.is_symlink() and path.is_file():
                yield path


def read_version(root: Path) -> str:
    """`__version__` from src/sniper_mcp/__init__.py, without importing the package."""
    source = (root / "src" / "sniper_mcp" / "__init__.py").read_text(encoding="utf-8")
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets):
            value = ast.literal_eval(node.value)
            if isinstance(value, str):
                return value
    raise SystemExit("__version__ not found in src/sniper_mcp/__init__.py")


def read_settings_env_vars(root: Path) -> tuple[str, ...]:
    source = (root / "src" / "sniper_mcp" / "settings.py").read_text(encoding="utf-8")
    for node in ast.parse(source).body:
        target = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
        elif isinstance(node, ast.AnnAssign):
            target = node.target
        if isinstance(target, ast.Name) and target.id == "ENV_VARS" and node.value:
            return tuple(ast.literal_eval(node.value))
    raise SystemExit("ENV_VARS not found in src/sniper_mcp/settings.py")


def load_json(tree: Tree, rel: str, issues: list[Issue]) -> object | None:
    text = tree.text(rel)
    if text is None:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        issues.append(Issue("consistency", rel, f"invalid JSON: {exc}"))
        return None


# --- checks: layout ---------------------------------------------------------------------

def check_layout(tree: Tree) -> list[Issue]:
    issues = []
    for rel in DOC_FILES:
        if not tree.exists(rel):
            issues.append(Issue("docs-pending", rel, "missing"))
    for rel in LAYOUT_FILES:
        if not tree.exists(rel):
            issues.append(Issue("missing", rel, "missing"))
    if tree.private:
        return issues
    published = set(LAYOUT_FILES) | set(DOC_FILES)
    generated = set(tree.generated_files)
    files = {rel for rel, _ in tree.items()} | {rel for rel, _ in tree.binary_items()}
    for rel in sorted(files):
        if rel in NOT_EXPORTED_FILES:
            issues.append(Issue("not-exported", rel, "never exported (P.2); keep it out of "
                                                     "git with .git/info/exclude"))
        elif rel in generated:
            issues.append(Issue("not-exported", rel,
                                f"inside the build, cache or virtual-environment directory "
                                f"{generated_part(rel)}/ (P.2); never commit it"))
        elif rel not in published and not rel.startswith(OPEN_LAYOUT_PREFIXES):
            issues.append(Issue("not-exported", rel, "not part of the published layout (P.1)"))
    for rel, target in sorted(tree.symlinks.items()):
        issues.append(Issue("not-exported", rel, f"a symlink (to {target!r}); the published "
                                                 "tree has none"))
    if tree.generated_dirs_fail:
        reason = ("must not be exported" if tree.export else
                  "is present and, without git, cannot be told apart from a committed one")
        for rel in tree.generated_dirs:
            issues.append(Issue("not-exported", rel,
                                f"a build, cache or virtual-environment directory {reason}"))
    return issues


# --- checks: scrub and em-dash ----------------------------------------------------------

def check_scrub(tree: Tree) -> list[Issue]:
    issues = []
    for rel, text in tree.items():
        for number, line in enumerate(text.splitlines(), 1):
            for match in SCRUB.finditer(line):
                issues.append(Issue("scrub", f"{rel}:{number}",
                                    f"matches the scrub pattern: {match.group(0)!r}"))
    for rel, text in tree.binary_items():
        for match in SCRUB.finditer(text):
            issues.append(Issue("scrub", rel, f"binary file matches the scrub pattern: "
                                              f"{match.group(0)!r}"))
    for rel in tree.paths:
        for match in SCRUB.finditer(rel):
            issues.append(Issue("scrub", rel,
                                f"the path name matches the scrub pattern: {match.group(0)!r}"))
    for rel, target in tree.symlinks.items():
        for match in SCRUB.finditer(target):
            issues.append(Issue("scrub", rel, f"the symlink target matches the scrub pattern: "
                                              f"{match.group(0)!r}"))
    return issues


def check_em_dash(tree: Tree) -> list[Issue]:
    issues = []
    for rel, text in tree.items():
        for number, line in enumerate(text.splitlines(), 1):
            if any(p.search(line) for p in EM_DASH_PATTERNS):
                issues.append(Issue("em-dash", f"{rel}:{number}",
                                    "em-dash or an em-dash HTML entity"))
    # A text file with NUL bytes is read as binary; it is still text.
    for rel, text in tree.nul_text_items():
        if any(p.search(text) for p in EM_DASH_PATTERNS):
            issues.append(Issue("em-dash", rel, "em-dash or an em-dash HTML entity in a "
                                                "file with NUL bytes"))
    for rel in tree.paths:
        if any(p.search(rel) for p in EM_DASH_PATTERNS):
            issues.append(Issue("em-dash", rel, "em-dash in a file or directory name"))
    return issues


# --- checks: example values -------------------------------------------------------------

# Four dot-separated digit runs of any length: 0177.0.0.1 and 8.8.8.08 are read too
# (_ipv4_readings decides what they can mean).
IPV4_RE = re.compile(r"(?<![\w.])((?:\d+\.){3}\d+)(?:/(\d{1,2}))?(?![\w]|\.\d)")
IPV6_RE = re.compile(
    r"(?<![\w:.])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?:/(\d{1,3}))?(?![\w:])")
# A fence line: up to any indentation (fences inside list items are indented), three or
# more backticks or tildes, then the info string.
FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})(.*)$")
DENIED_NAME_RE = re.compile(
    r"(?<![\w.-])(?:[A-Za-z0-9-]+\.)*example\.(?:com|net|org)\.?(?![\w-])", re.IGNORECASE)
# A dotted token, also after "@" (the host of user@host is a host name). Labels may be
# internationalized (portal.münchen.de) and the last label may be a punycode TLD. A
# token that continues a path (/etc/sn1per-mcp, https://github.com/...) is not matched
# here: URL hosts are read by CODE_URL_RE.
HOST_TOKEN_RE = re.compile(
    r"(?<![\w./-])((?:[^\W_](?:[^\W_]|-){0,62}\.)+([^\W\d_]{2,63}|xn--[a-z0-9-]{1,59}))"
    r"\.?(?![\w-])", re.IGNORECASE)
# A dotted token in a code block is a host name unless its last label is one of these
# file extensions (server.json, sniper.conf, nmap-192.0.2.10.txt, ssh.exe) or it is
# one of the reverse-DNS identifiers below.
FILE_EXTENSIONS = frozenset(
    "json jsonl conf cfg ini txt md rst py pyc sh bash zsh ps1 bat toml yml yaml png jpg "
    "jpeg gif svg ico gz tgz tar zip whl xz bz2 log env lock xml html htm csv tsv db "
    "sqlite pem key crt csr pub service socket timer js mjs ts css nmap gnmap pdf out "
    "err tmp bak orig diff patch exe nft".split())
# The file extensions above that are also delegated top-level domains (the IANA list,
# version 2026101001): a name ending in one of them is a file name only as a single
# name.ext (install.sh, README.md, setup.py); portal.acme.sh is a host.
TLD_FILE_EXTENSIONS = frozenset({"md", "pub", "py", "sh", "zip"})
# Reserved names that can never be a real host (RFC 2606, RFC 6761): the only host names
# a target-like value in a snippet may use, besides the placeholders.
EXAMPLE_SUFFIXES = (".example", ".test", ".invalid", ".localhost")
EXAMPLE_NAMES = frozenset({"example", "test", "invalid", "localhost"})
# The authority of a URL with any scheme (https://, ssh://, git+https://): the host is
# what follows the last "@" in it.
CODE_URL_RE = re.compile(
    r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*://([^\s/?#\\\"'`]*)")
# user@host: the user part is a word or a placeholder; the host part ends at white space,
# a path, a port or a quote. A version after "@" (sn1per-mcp@0.9.0) starts with a digit
# and is left to the address check.
USER_AT_HOST_RE = re.compile(
    r"(?<![\w.%+/:<>-])(?:[\w.%+-]+|<[A-Za-z0-9_ -]+>)@"
    r"(\[[0-9A-Fa-f:.]+\]|<[A-Za-z0-9_ -]+>|[^\s@/:,;'\"`<>()\[\]{}|\\]+)")
# Where a comment starts in a program-language block (hosts in comments are read too).
COMMENT_MARKERS = {**dict.fromkeys(("python", "py", "python3", "pycon", "ruby"), "#"),
                   **dict.fromkeys(("javascript", "js", "typescript", "ts", "go", "rust",
                                    "java", "c", "cpp"), "//")}
# The reverse-DNS identifiers the published files use (OCI labels, the MCP registry
# namespaces and _meta keys, Docker network driver options). Only these exact names and
# names under them are exempt:
# a generic first-label rule (app., dev., com. ...) would let a real host such as
# app.<company>.<tld> through, because app. and dev. are the canonical example prefixes.
REVERSE_DNS_IDENTIFIERS = ("io.modelcontextprotocol", "org.opencontainers",
                           "com.sn1persecurity", "io.github", "com.docker.network")
# Info strings of program-language code blocks: there only string literals and comments
# are read for host names (os.environ is no host).
PROGRAM_LANGUAGES = frozenset(COMMENT_MARKERS)
STRING_LITERAL_RE = re.compile(r""""([^"\\]*)"|'([^'\\]*)'""")
# A table header line, skipped only inside a ```toml block ([tool.ruff] is no host).
TOML_HEADER_RE = re.compile(r"""^\s*\[{1,2}[\w."' -]+\]{1,2}\s*(?:#.*)?$""")
INLINE_CODE_RE = re.compile(r"(`+)(.+?)\1")
TARGET_JSON_RE = re.compile(r'"target"\s*:\s*"([^"]*)"')
SNIPER_T_RE = re.compile(r"\bsniper\b.*?\s-t\s+(\"[^\"]*\"|'[^']*'|\S+)")
# A SNIPER_MCP_SCOPE key (never SNIPER_MCP_SCOPE_FILE, never a ${SNIPER_MCP_SCOPE...}
# reference) followed by = or :. The value is read by _scope_value.
SCOPE_KEY_RE = re.compile(
    r"""(?:(?P<q>["'])SNIPER_MCP_SCOPE(?P=q)|(?<![\w$])(?<!\$\{)SNIPER_MCP_SCOPE(?!\w))"""
    r"""\s*(?P<sep>[:=])""")
# Shell parameter references: ${NAME}, ${NAME:-default}, ${NAME-default},
# ${NAME:=default}, ${NAME=default} and $NAME. The default is what a reader who copies
# the snippet ends up with, so it is checked like a literal value.
VAR_REF_RE = re.compile(
    r"\$\{[A-Za-z_][A-Za-z0-9_]*(?:(?::?[-=])(?P<default>[^{}]*))?\}|\$[A-Za-z_][A-Za-z0-9_]*")
# An explicit placeholder: <authorized-targets>, <target>; never a dotted name.
PLACEHOLDER_RE = re.compile(r"<[A-Za-z0-9_ -]+>")
SCOPE_REFERENCE_RE = re.compile(
    r"\$\{[A-Za-z_][A-Za-z0-9_]*(?::?-(?:" + re.escape(SCOPE_PLACEHOLDER) + r")?)?\}"
    r"|\$[A-Za-z_][A-Za-z0-9_]*")
ENTRY_SPLIT_RE = re.compile(r"[\s,]+")
SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
RFC5737 = tuple(ipaddress.ip_network(n) for n in
                ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
DOC_V6 = (ipaddress.ip_network("2001:db8::/32"),)
CATCH_ALL_V4 = ipaddress.ip_network("0.0.0.0/0")


Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _networks(text: str) -> Iterator[tuple[int, str, Network | None]]:
    """(line number, literal, network) for every IPv4 and IPv6 literal. The network is
    None for an IPv4-shaped literal that ipaddress refuses, such as one with a leading
    zero (8.8.8.08), which some resolvers read as octal."""
    for number, line in enumerate(text.splitlines(), 1):
        for regex in (IPV4_RE, IPV6_RE):
            for match in regex.finditer(line):
                literal = match.group(0)
                if regex is IPV6_RE and "::" not in literal and literal.count(":") < 7:
                    continue
                try:
                    network = ipaddress.ip_network(literal, strict=False)
                except ValueError:
                    if regex is IPV6_RE:
                        continue
                    network = None
                yield number, literal, network


def _ipv4_readings(literal: str) -> list[Network]:
    """The networks a non-canonical IPv4 literal can name: every part read as decimal,
    and every part with a leading zero read as octal (inet_aton). A reading with a part
    over 255 is no address."""
    address, _, prefix = literal.partition("/")
    parts = address.split(".")
    if any(len(part) > 12 for part in parts):
        return []  # no reading is an address (and int() stays far from its digit limit)
    decimal = [int(part, 10) for part in parts]
    readings = [decimal]
    if all(set(part) <= set("01234567") for part in parts if part.startswith("0")):
        readings.append([int(part, 8) if part.startswith("0") else int(part, 10)
                         for part in parts])
    networks = []
    for values in readings:
        if all(value <= 255 for value in values):
            text = ".".join(map(str, values)) + (f"/{prefix}" if prefix else "")
            try:
                networks.append(ipaddress.ip_network(text, strict=False))
            except ValueError:
                continue
    return networks


def _inside(network, ranges) -> bool:
    if network is None:
        return False
    return any(network.version == r.version and network.subnet_of(r) for r in ranges)


def _address_ok(literal: str, network: Network | None, ranges) -> bool:
    """An address literal of a published page is inside ``ranges``; a non-canonical one
    only when every way of reading it is."""
    if network is not None:
        return _inside(network, ranges)
    readings = _ipv4_readings(literal)
    return bool(readings) and all(_inside(reading, ranges) for reading in readings)


SCOPE_TABLE_NAMES = ("ALWAYS_DENY_V4", "ALWAYS_DENY_V6", "NON_PUBLIC_V4", "NON_PUBLIC_V6")


def _scope_tables(root: Path) -> tuple[tuple, tuple]:
    """The always-deny (F.4.1) and non-public (F.4.3) tables of the checked tree.

    Read from the tree's own src/sniper_mcp/scope.py (the `NAME = _v4("...", ...)`
    assignments), so a run with --root never compares against whatever version of
    the package happens to be installed. A tree without that file (a synthetic test
    tree) falls back to the installed package.
    """
    path = root / "src" / "sniper_mcp" / "scope.py"
    if not path.is_file():
        from sniper_mcp import scope  # imported lazily: needs the package installed

        tables = {name: tuple(getattr(scope, name)) for name in SCOPE_TABLE_NAMES}
    else:
        tables = {}
        for node in ast.parse(path.read_text(encoding="utf-8")).body:
            if not (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id in SCOPE_TABLE_NAMES
                    and isinstance(node.value, ast.Call)):
                continue
            values = [ast.literal_eval(arg) for arg in node.value.args]
            tables[node.targets[0].id] = tuple(ipaddress.ip_network(v) for v in values)
        missing = [name for name in SCOPE_TABLE_NAMES if name not in tables]
        if missing:
            raise SystemExit(f"{path}: scope tables not found: {', '.join(missing)}")
    deny = tables["ALWAYS_DENY_V4"] + tables["ALWAYS_DENY_V6"]
    non_public = tables["NON_PUBLIC_V4"] + tables["NON_PUBLIC_V6"]
    return deny, non_public


def _fenced_lines(text: str) -> Iterator[tuple[int, str, str | None]]:
    """(number, line, info) for every line; info is None outside a fenced code block,
    else the block's info string (lower case, first word). Fence lines themselves are
    not yielded. Fences follow CommonMark: a block closes only on a fence of the same
    character at least as long as the opening one, with nothing after it."""
    opening: str | None = None
    info = ""
    for number, line in enumerate(text.splitlines(), 1):
        match = FENCE_RE.match(line)
        if opening is None:
            if match and not (match.group(1)[0] == "`" and "`" in match.group(2)):
                opening = match.group(1)
                words = match.group(2).strip().split()
                info = words[0].lower() if words else ""
                continue
            yield number, line, None
        else:
            if (match and match.group(1)[0] == opening[0]
                    and len(match.group(1)) >= len(opening) and not match.group(2).strip()):
                opening = None
                continue
            yield number, line, info


def _expand_references(value: str) -> str:
    """value with every shell parameter reference replaced by its default (or nothing)."""
    return VAR_REF_RE.sub(lambda m: m.group("default") or "", value)


def _entry_ok(entry: str) -> bool:
    """One target or scope entry: a reserved example name (.example, .test, .invalid,
    .localhost), an RFC 5737 or 2001:db8::/32 address or network, or an explicit
    placeholder."""
    entry = entry.strip().strip("\"'`").rstrip(".")
    if not entry or PLACEHOLDER_RE.fullmatch(entry):
        return True
    entry = entry.lstrip("!").strip()
    entry = SCHEME_RE.sub("", entry)
    if entry.startswith("*."):
        entry = entry[2:]
    try:
        return _inside(ipaddress.ip_network(entry, strict=False), RFC5737 + DOC_V6)
    except ValueError:
        pass
    host = entry.split("/")[0].split("?")[0].split("#")[0]
    if host.startswith("["):
        host = host[1:].split("]")[0]
    elif host.count(":") == 1:
        host = host.split(":")[0]
    try:
        return _inside(ipaddress.ip_network(host, strict=False), RFC5737 + DOC_V6)
    except ValueError:
        pass
    host = host.lower().rstrip(".")
    return bool(host) and (host.endswith(EXAMPLE_SUFFIXES) or host in EXAMPLE_NAMES)


def _bad_entries(value: str) -> list[str]:
    """The entries of a target, scope or scope-file value that are no example values.

    References are replaced by their defaults (${SNIPER_MCP_SCOPE:-shop.acme.test} is
    shop.acme.test); the value is then split on commas and white space."""
    expanded = _expand_references(value)
    return [entry for entry in ENTRY_SPLIT_RE.split(expanded)
            if entry and not _entry_ok(entry)]


def _scope_values(line: str, fenced: bool) -> Iterator[str]:
    """The values assigned to SNIPER_MCP_SCOPE on a line: a quoted value whole, an
    unquoted shell value up to white space, and (in fenced code only) an unquoted YAML
    value at the start of a line up to a comment."""
    for match in SCOPE_KEY_RE.finditer(line):
        after = line[match.end():]
        rest = after.lstrip()
        if rest[:1] in ("\"", "'"):
            quote = rest[0]
            closing = rest.find(quote, 1)
            yield rest[1:closing] if closing > 0 else rest[1:]
        elif match.group("sep") == "=":
            # `SNIPER_MCP_SCOPE= cmd` assigns the empty value in a shell.
            if not after[:1].isspace():
                yield re.match(r"[^\s;&|]*", after).group(0)
        elif (fenced and match.group("q") is None
              and re.fullmatch(r"\s*(?:-\s+)?", line[:match.start()])):
            yield rest.split(" #")[0].strip().rstrip(",")
        elif fenced and re.search(r"[{,]\s*$", line[:match.start()]):
            # A YAML or JSON flow mapping: env: {SNIPER_MCP_SCOPE: app.example}
            yield re.match(r"[^,}#]*", rest).group(0).strip()


def _allowed_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    for entry in LINK_HOST_ALLOWLIST:
        if entry.startswith("."):
            if host == entry[1:] or host.endswith(entry):
                return True
        elif host == entry:
            return True
    return host.endswith(".sn1persecurity.com") or host == "users.noreply.github.com"


def example_checked(rel: str) -> bool:
    """Published text held to the docs example-value rule: the documentation files and
    the other public files a reader or an agent copies examples from."""
    return is_doc(rel) or rel in EXAMPLE_CHECKED_FILES


def check_examples(tree: Tree) -> list[Issue]:
    issues: list[Issue] = []
    deny, non_public = _scope_tables(tree.root)
    everything = deny + non_public
    for rel, text in tree.items():
        if example_checked(rel):
            allowed = RFC5737 + DOC_V6
            if rel == "docs/security-model.md":
                allowed = allowed + everything
            for number, literal, network in _networks(text):
                if not _address_ok(literal, network, allowed):
                    issues.append(Issue("examples", f"{rel}:{number}",
                                        f"address {literal} outside the example ranges"))
            if rel not in DENIED_NAMES_ALLOWED_IN:
                for number, line in enumerate(text.splitlines(), 1):
                    for match in DENIED_NAME_RE.finditer(line):
                        issues.append(Issue(
                            "examples", f"{rel}:{number}",
                            f"always-denied name {match.group(0)!r} outside refusal examples"))
            issues.extend(_check_snippets(rel, text))
        elif rel.startswith(("tests/", "scripts/")):
            for number, literal, network in _networks(text):
                # Non-canonical literals (0177.0.0.1) are target-grammar test inputs.
                if network is None or network.version != 4:
                    continue
                if network.prefixlen == 0:
                    if network != CATCH_ALL_V4:
                        issues.append(Issue("examples", f"{rel}:{number}",
                                            f"address {literal} is not an example value"))
                    continue
                if not _inside(network, RFC5737 + everything):
                    issues.append(Issue("examples", f"{rel}:{number}",
                                        f"address {literal} is not an example value"))
    return issues


def _snippets(text: str) -> Iterator[tuple[int, str, str | None]]:
    """(number, code, info) for every line of a fenced code block and every inline code
    span outside one; info is the block's info string, None for an inline span."""
    for number, line, info in _fenced_lines(text):
        if info is not None:
            yield number, line, info
        else:
            for match in INLINE_CODE_RE.finditer(line):
                yield number, match.group(2), None


def _check_snippets(rel: str, text: str) -> list[Issue]:
    issues = []
    denied_ok = rel in DENIED_NAMES_ALLOWED_IN

    def denied(value: str) -> bool:
        return denied_ok and value.strip().strip("\"'").lower().rstrip(".") in \
            DENIED_EXAMPLE_NAMES

    for number, line, info in _snippets(text):
        fenced = info is not None
        where = f"{rel}:{number}"
        reported: set[str] = set()  # reported once, not again as a host name
        values = [m.group(1) for m in TARGET_JSON_RE.finditer(line)]
        values += [m.group(1) for m in SNIPER_T_RE.finditer(line)]
        for value in values:
            bad = [e for e in _bad_entries(value) if not denied(e)]
            if bad:
                reported.update(e.strip("\"'").lower() for e in bad)
                issues.append(Issue("examples", where,
                                    f"target value {value!r} is not an example value"))
        for value in _scope_values(line, fenced):
            for entry in _bad_entries(value):
                reported.add(entry.strip("\"'").lower())
                issues.append(Issue("examples", where,
                                    f"SNIPER_MCP_SCOPE entry {entry!r} (in {value!r}) is not "
                                    "an example value"))
            if fenced and value.strip() and value.strip() != SCOPE_PLACEHOLDER \
                    and not SCOPE_REFERENCE_RE.fullmatch(value.strip()):
                issues.append(Issue(
                    "consistency", where,
                    f"SNIPER_MCP_SCOPE snippet value {value!r} must be {SCOPE_PLACEHOLDER}"))
        # References are replaced by their defaults: TARGET=${TARGET:-shop.acme.ch} is
        # what a reader who copies the line ends up with.
        pieces = [_expand_references(piece) for piece in _code_pieces(line, info)]
        issues.extend(_check_explicit_hosts(where, pieces, fenced, reported))
        if fenced:
            issues.extend(_check_host_tokens(where, line, pieces, info, reported))
    return issues


def _code_pieces(line: str, info: str | None) -> list[str]:
    """The parts of a snippet line that can name a host: the whole line, or in a
    program-language block its string literals and its comment."""
    if info not in PROGRAM_LANGUAGES:
        return [line]
    pieces = [a if a is not None else b for a, b in STRING_LITERAL_RE.findall(line)]
    code = STRING_LITERAL_RE.sub(" ", line)
    marker = COMMENT_MARKERS[info]
    if marker in code:
        pieces.append(code.split(marker, 1)[1])
    return pieces


def _reverse_dns_identifier(host: str) -> bool:
    return any(host == name or host.startswith(name + ".")
               for name in REVERSE_DNS_IDENTIFIERS)


def _denied_name(host: str) -> bool:
    """example.com, example.net, example.org and their subdomains: judged by the
    always-denied name rule, which allows them on the refusal-example pages."""
    return host in DENIED_EXAMPLE_NAMES or host.endswith(
        tuple("." + name for name in DENIED_EXAMPLE_NAMES))


def _host_ok(host: str) -> bool:
    """A host named explicitly in a snippet (a URL host, the host of user@host) may be a
    placeholder, a reserved example name or an allowlisted link host. An address (or a
    version after @, as in sn1per-mcp@0.9.0) is left to the address check."""
    host = host.strip().lower().rstrip(".")
    if not host or PLACEHOLDER_RE.fullmatch(host) or re.fullmatch(r"[0-9.]+", host):
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return _entry_ok(host) or _allowed_host(host) or _denied_name(host)


def _authority_host(authority: str) -> str:
    host = authority.rsplit("@", 1)[-1]
    if host.startswith("["):
        return host[1:].split("]")[0].lower()
    return host.split(":")[0].lower()


def _check_explicit_hosts(where: str, pieces: list[str], fenced: bool,
                          reported: set[str]) -> list[Issue]:
    """URL hosts (any scheme) and the host of user@host, in fenced blocks and inline code
    spans alike: these are written to be copied (a client entry, an ssh command)."""
    issues = []
    place = "in a code block" if fenced else "in inline code"
    for piece in pieces:
        found = [("URL host", _authority_host(m.group(1))) for m in CODE_URL_RE.finditer(piece)]
        found += [("user@host host", m.group(1).lower()) for m in USER_AT_HOST_RE.finditer(piece)]
        for kind, host in found:
            if _host_ok(host) or host.rstrip(".") in reported:
                continue
            reported.add(host.rstrip("."))
            issues.append(Issue("examples", where,
                                f"{kind} {host!r} {place} is not an example value"))
    return issues


def _check_host_tokens(where: str, line: str, pieces: list[str], info: str,
                       reported: set[str]) -> list[Issue]:
    """Every dotted name in a fenced code line (a scope-file line, a command argument)
    is a reserved example name, an allowlisted link host or a file name."""
    if info == "toml" and TOML_HEADER_RE.match(line):
        return []  # [tool.ruff] is a table name
    issues = []
    for piece in pieces:
        # A wildcard scope entry: *.shop.acme.test is checked as shop.acme.test.
        piece = piece.replace("*.", " ")
        for match in HOST_TOKEN_RE.finditer(piece):
            host, tld = match.group(1).lower(), match.group(2).lower()
            if piece[match.end():match.end() + 1] in ("(", "["):
                continue  # a call or a subscript: json.load(...), os.environ[...]
            if tld in FILE_EXTENSIONS and (tld not in TLD_FILE_EXTENSIONS
                                           or host.count(".") == 1):
                continue  # a file name: server.json, nmap-192.0.2.10.txt, install.sh
            if _reverse_dns_identifier(host):
                continue
            if _entry_ok(host) or _allowed_host(host) or host in reported:
                continue
            if _denied_name(host):
                continue  # judged by the always-denied name rule
            issues.append(Issue("examples", where, f"host name {host!r} in a code block is "
                                                   "not an example value"))
    return issues


# --- checks: links ----------------------------------------------------------------------

# Every `](target` of an inline link or image, at any nesting depth: the outer link of
# a badge `[![alt](image)](target)` is matched as well as the inner image.
MD_TARGET_RE = re.compile(r"\]\(\s*<?([^)\s>]+)")
# A reference definition; never a footnote definition ([^1]: text).
MD_REF_RE = re.compile(r"^\s{0,3}\[(?!\^)[^\]]+\]:\s*<?(\S+?)>?(?:\s|$)", re.MULTILINE)
HTML_ATTR_RE = re.compile(
    r"""(?i)(?<![\w-])(src|href|srcset)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""")
ABSOLUTE_LINK_RE = re.compile(r"(?i)(https?:|mailto:)")
URL_RE = re.compile(r"https?://[^\s<>()\[\]\"'`]+", re.IGNORECASE)


def check_links(tree: Tree) -> list[Issue]:
    issues = []
    readme = tree.text("README.md")
    if readme is not None:
        for target in readme_link_targets(readme):
            if not ABSOLUTE_LINK_RE.match(target):
                issues.append(Issue("links", "README.md",
                                    f"relative link {target!r} (pypi.org renders README.md; "
                                    "use an absolute URL)"))
    checked = [rel for rel, _ in tree.items()
               if rel in LINK_CHECKED_FILES or (rel.startswith("docs/") and rel.endswith(".md"))]
    for rel in checked:
        text = tree.text(rel) or ""
        for number, line, info in _fenced_lines(text):
            # Example payloads in code are no links: a URL whose host is an example
            # value (.example, .test, RFC 5737) is allowed inside a fenced block or an
            # inline code span. Everywhere else, and for every other host, the
            # allowlist applies.
            in_code = ([line] if info is not None
                       else [m.group(2) for m in INLINE_CODE_RE.finditer(line)])
            example_urls = {u.rstrip(".,;:") for code in in_code for u in URL_RE.findall(code)
                            if (h := _url_host(u.rstrip(".,;:"))) and _entry_ok(h)}
            for url in URL_RE.findall(line):
                url = url.rstrip(".,;:")
                host = _url_host(url)
                if url in example_urls:
                    continue
                if not _host_in_allowlist(host):
                    issues.append(Issue("links", f"{rel}:{number}",
                                        f"link host {host!r} is not in the allowlist"))
                if host == "sn1persecurity.com":
                    issues.extend(_check_company_link(rel, number, url))
    for rel, text in tree.items():
        if FUTURE_DOCS_URL in text or FUTURE_DOCS_URL.rstrip("/") in text:
            issues.append(Issue("links", rel, "links the documentation page that is not live "
                                              "until a later release"))
    return issues


def _url_host(url: str) -> str:
    # WHATWG URL parsers end the authority of an http(s) URL at a backslash as well, so
    # a backslash before the userinfo cannot hide the real host behind an example host.
    host = re.split(r"[/\\?#]", re.sub(r"(?i)^https?://", "", url), maxsplit=1)[0]
    if host.startswith("["):
        return host[1:].split("]")[0].lower()
    return host.split("@")[-1].split(":")[0].lower()


def readme_link_targets(text: str) -> list[str]:
    """Every link and image target of a Markdown file outside fenced code blocks:
    inline links and images at any nesting depth, reference definitions, and the
    src, href and srcset attributes of inline HTML."""
    body = "\n".join(line for _, line, info in _fenced_lines(text) if info is None)
    targets = MD_TARGET_RE.findall(body) + MD_REF_RE.findall(body)
    for match in HTML_ATTR_RE.finditer(body):
        value = next(v for v in match.groups()[1:] if v is not None).strip()
        if match.group(1).lower() == "srcset":
            targets += [part.split()[0] for part in value.split(",") if part.strip()]
        else:
            targets.append(value)
    return targets


def _host_in_allowlist(host: str) -> bool:
    for entry in LINK_HOST_ALLOWLIST:
        if entry.startswith("."):
            if host == entry[1:] or host.endswith(entry):
                return True
        elif host == entry:
            return True
    return False


def _check_company_link(rel: str, number: int, url: str) -> list[Issue]:
    rest = re.sub(r"(?i)^https?://sn1persecurity\.com", "", url)
    path, _, query = rest.partition("?")
    query = query.split("#")[0]
    path = path.split("#")[0] or "/"
    issues = []
    if path != "/" and not re.fullmatch(r"/wordpress/[a-z0-9-]+(?:/[a-z0-9-]+)*/", path):
        issues.append(Issue("links", f"{rel}:{number}",
                            f"sn1persecurity.com link {url!r} is not the /wordpress/<slug>/ "
                            "form with a trailing slash"))
    if UTM_GITHUB not in query:
        issues.append(Issue("links", f"{rel}:{number}",
                            f"sn1persecurity.com link {url!r} lacks {UTM_GITHUB}"))
    return issues


# --- checks: consistency ----------------------------------------------------------------

PIN_RE = re.compile(r"sn1per-mcp(?:==|@)(\d[0-9A-Za-z.+!-]*\w)")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
USES_RE = re.compile(r"^\s*-?\s*uses:\s*(\S+)", re.MULTILINE)
PINNED_ACTION_RE = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


def check_consistency(tree: Tree, version: str) -> list[Issue]:
    issues: list[Issue] = []
    root = tree.root

    # pyproject: dynamic version from the single source, description, classifiers.
    import tomllib

    try:
        pyproject = tomllib.loads(tree.text("pyproject.toml") or "")
    except tomllib.TOMLDecodeError as exc:
        return [Issue("consistency", "pyproject.toml", f"invalid TOML: {exc}")]
    project = pyproject.get("project", {})
    if "version" in project or project.get("dynamic") != ["version"]:
        issues.append(Issue("consistency", "pyproject.toml",
                            "version must be dynamic (single source in __init__.py)"))
    dynamic = pyproject.get("tool", {}).get("setuptools", {}).get("dynamic", {})
    if dynamic.get("version") != {"attr": "sniper_mcp.__version__"}:
        issues.append(Issue("consistency", "pyproject.toml",
                            "tool.setuptools.dynamic.version must be sniper_mcp.__version__"))
    if project.get("description") != DESCRIPTION:
        issues.append(Issue("consistency", "pyproject.toml",
                            "description differs from the registry description"))
    issues.extend(_check_classifiers(project.get("classifiers", []), version))

    # server.json
    server = load_json(tree, "server.json", issues)
    if isinstance(server, dict):
        issues.extend(_check_server_json(server, version, project))

    # Plugin and marketplace files.
    issues.extend(_check_plugin_files(tree, version))

    # Dockerfile labels.
    docker = tree.text("Dockerfile")
    if docker is not None:
        issues.extend(_check_dockerfile(docker, version))

    # README: mcp-name token, pins, scope placeholder.
    readme = tree.text("README.md")
    if readme is not None:
        if MCP_NAME_TOKEN not in readme.splitlines():
            issues.append(Issue("consistency", "README.md",
                                f"the line {MCP_NAME_TOKEN} is missing"))
        if SCOPE_PLACEHOLDER not in readme:
            issues.append(Issue("consistency", "README.md",
                                f"the scope placeholder {SCOPE_PLACEHOLDER} is missing"))
    for rel, text in tree.items():
        if rel == "README.md" or (rel.startswith("docs/") and rel.endswith(".md")):
            for number, line in enumerate(text.splitlines(), 1):
                for pin in PIN_RE.findall(line):
                    if pin != version:
                        issues.append(Issue("consistency", f"{rel}:{number}",
                                            f"version pin {pin} differs from {version}"))

    # CHANGELOG top entry.
    changelog = tree.text("CHANGELOG.md")
    if changelog is not None:
        heads = re.findall(r"^## \[([^\]]+)\]", changelog, re.MULTILINE)
        heads = [h for h in heads if h.lower() != "unreleased"]
        if not heads or heads[0] != version:
            issues.append(Issue("consistency", "CHANGELOG.md",
                                f"the top entry must be [{version}]"))

    # Documented environment variables equal the parsed set.
    env_vars = set(read_settings_env_vars(root))
    configuration = tree.text("docs/configuration.md")
    if configuration is not None:
        documented = set()
        for line in configuration.splitlines():
            if line.lstrip().startswith("|"):
                first = line.strip().strip("|").split("|")[0]
                documented.update(re.findall(r"`(SNIPER_[A-Z0-9_]+)`", first))
        if documented != env_vars:
            missing = sorted(env_vars - documented)
            extra = sorted(documented - env_vars)
            issues.append(Issue("consistency", "docs/configuration.md",
                                f"environment table differs from settings.py: missing "
                                f"{missing}, not a setting {extra}"))
    for rel, text in tree.items():
        if is_doc(rel):
            for number, line in enumerate(text.splitlines(), 1):
                for name in re.findall(r"\bSNIPER_[A-Z0-9_]*[A-Z0-9]\b", line):
                    if name not in env_vars:
                        issues.append(Issue("consistency", f"{rel}:{number}",
                                            f"{name} is not a documented setting"))

    issues.extend(_check_spdx(tree))
    issues.extend(_check_workflows(tree))
    issues.extend(_check_icon(root))
    issues.extend(_check_license_files(tree))
    return issues


def _check_classifiers(classifiers: list[str], version: str) -> list[Issue]:
    issues = []
    try:
        import trove_classifiers
    except ImportError:
        return [Issue("consistency", "pyproject.toml",
                      "trove-classifiers is not installed (pip install -e '.[dev]')")]
    for classifier in classifiers:
        if classifier not in trove_classifiers.classifiers:
            issues.append(Issue("consistency", "pyproject.toml",
                                f"invalid classifier {classifier!r}"))
    status = [c for c in classifiers if c.startswith("Development Status ::")]
    if version.startswith("0.") and status != [BETA]:
        issues.append(Issue("consistency", "pyproject.toml",
                            f"a 0.x version needs exactly {BETA!r}, found {status}"))
    if any(c.startswith("License ::") for c in classifiers):
        issues.append(Issue("consistency", "pyproject.toml",
                            "no license classifier next to the SPDX expression"))
    return issues


def _check_server_json(server: dict, version: str, project: dict) -> list[Issue]:
    issues = []

    def bad(message: str) -> None:
        issues.append(Issue("consistency", "server.json", message))

    if server.get("$schema") != SERVER_JSON_SCHEMA:
        bad("$schema differs")
    if server.get("name") != REGISTRY_NAME:
        bad(f"name must be {REGISTRY_NAME}")
    if server.get("title") != REGISTRY_TITLE or len(server.get("title", "")) > 100:
        bad("title differs or is longer than 100 characters")
    description = server.get("description", "")
    if len(description) > 100:
        bad("description is longer than 100 characters")
    if description != project.get("description"):
        bad("description differs from the pyproject description")
    if server.get("version") != version:
        bad(f"version {server.get('version')} differs from {version}")
    icons = server.get("icons") or []
    tag = f"/v{version}/"
    if not icons or any(tag not in icon.get("src", "") for icon in icons):
        bad(f"icon URL must be pinned to the tag v{version}")
    packages = server.get("packages") or []
    if len(packages) != 1:
        bad("exactly one package expected")
    for package in packages:
        if package.get("version") != version:
            bad(f"package version {package.get('version')} differs from {version}")
        if package.get("identifier") != "sn1per-mcp" or package.get("registryType") != "pypi":
            bad("package must be the PyPI distribution sn1per-mcp")
        if package.get("transport") != {"type": "stdio"}:
            bad("transport must be stdio")
        env = package.get("environmentVariables") or []
        names = [e.get("name") for e in env]
        if names != list(SERVER_JSON_ENV):
            bad(f"environment variables {names} differ from the published set")
        if any(e.get("isRequired") is not False for e in env):
            bad("every environment variable must have isRequired false")
        if any(e.get("isSecret") is not False for e in env):
            bad("no environment variable is a secret")
        scope = next((e for e in env if e.get("name") == "SNIPER_MCP_SCOPE"), {})
        if scope.get("placeholder") != SERVER_JSON_SCOPE_PLACEHOLDER:
            bad(f"SNIPER_MCP_SCOPE placeholder must be {SERVER_JSON_SCOPE_PLACEHOLDER}")
    return issues


def _check_plugin_files(tree: Tree, version: str) -> list[Issue]:
    issues: list[Issue] = []
    market = load_json(tree, ".claude-plugin/marketplace.json", issues)
    if isinstance(market, dict):
        plugins = market.get("plugins") or []
        metadata = market.get("metadata") if isinstance(market.get("metadata"), dict) else {}
        ok = (market.get("name") == "sn1per-mcp" and market.get("owner") == OWNER
              and metadata.get("description") == TAGLINE
              and len(plugins) == 1 and plugins[0].get("name") == "sn1per"
              and plugins[0].get("source") == "./plugins/sn1per"
              and plugins[0].get("description") == TAGLINE)
        if not ok:
            issues.append(Issue("consistency", ".claude-plugin/marketplace.json",
                                "name, owner, source or description differs"))
        for plugin in plugins:
            if plugin.get("version") != version:
                issues.append(Issue("consistency", ".claude-plugin/marketplace.json",
                                    f"plugin version {plugin.get('version')} differs from "
                                    f"{version}"))
    plugin = load_json(tree, "plugins/sn1per/.claude-plugin/plugin.json", issues)
    if isinstance(plugin, dict):
        if plugin.get("version") != version:
            issues.append(Issue("consistency", "plugins/sn1per/.claude-plugin/plugin.json",
                                f"version {plugin.get('version')} differs from {version}"))
        if (plugin.get("name") != "sn1per" or plugin.get("description") != TAGLINE
                or plugin.get("author") != OWNER or plugin.get("homepage") != REPO_URL
                or plugin.get("license") != "Apache-2.0"):
            issues.append(Issue("consistency", "plugins/sn1per/.claude-plugin/plugin.json",
                                "name, description, author, homepage or license differs"))
    mcp = load_json(tree, "plugins/sn1per/.mcp.json", issues)
    if isinstance(mcp, dict):
        entry = (mcp.get("mcpServers") or {}).get("sn1per") or {}
        expected = ["--from", f"sn1per-mcp=={version}", "sn1per-mcp"]
        if entry.get("command") != "uvx" or entry.get("args") != expected:
            issues.append(Issue("consistency", "plugins/sn1per/.mcp.json",
                                f"server entry must run uvx {' '.join(expected)}"))
        expected_env = {name: "${" + name + ":-}" for name in
                        ("SNIPER_MCP_SCOPE", "SNIPER_MCP_SCOPE_FILE",
                         "SNIPER_MCP_AUTHORIZATION_REF")}
        if entry.get("env") != expected_env:
            issues.append(Issue("consistency", "plugins/sn1per/.mcp.json",
                                "env must pass only the scope, scope file and authorization "
                                "reference, empty when unset"))
    skill = tree.text("plugins/sn1per/skills/authorized-scan/SKILL.md")
    if skill is not None and not skill.startswith("---\nname: authorized-scan\n"):
        issues.append(Issue("consistency", "plugins/sn1per/skills/authorized-scan/SKILL.md",
                            "frontmatter must start with name: authorized-scan"))
    return issues


def _dockerfile_label(docker: str, key: str) -> str | None:
    match = re.search(re.escape(key) + r'="([^"]*)"', docker)
    return match.group(1) if match else None


def _check_dockerfile(docker: str, version: str) -> list[Issue]:
    issues = []
    expected = {
        "org.opencontainers.image.title": "Sn1per MCP Server",
        "org.opencontainers.image.description": DESCRIPTION,
        "org.opencontainers.image.version": version,
        "org.opencontainers.image.licenses": "Apache-2.0",
        "org.opencontainers.image.source": REPO_URL,
        "io.modelcontextprotocol.server.name": REGISTRY_NAME,
    }
    for key, value in expected.items():
        found = _dockerfile_label(docker, key)
        if found != value:
            issues.append(Issue("consistency", "Dockerfile",
                                f"label {key} is {found!r}, expected {value!r}"))
    if not re.search(r"^FROM python:3\.13-slim@sha256:[0-9a-f]{64}\s*$", docker, re.MULTILINE):
        issues.append(Issue("consistency", "Dockerfile",
                            "base image must be python:3.13-slim pinned by digest"))
    if not re.search(r'^ENTRYPOINT \["sn1per-mcp"\]\s*$', docker, re.MULTILINE):
        issues.append(Issue("consistency", "Dockerfile", 'ENTRYPOINT must be ["sn1per-mcp"]'))
    if not re.search(r"^USER 10001:10001\s*$", docker, re.MULTILINE):
        issues.append(Issue("consistency", "Dockerfile", "must run as USER 10001:10001"))
    if "SNIPER_SCAN_ENABLED=false" not in docker:
        issues.append(Issue("consistency", "Dockerfile", "must set SNIPER_SCAN_ENABLED=false"))
    if re.search(r"pip install[^\n]*\s-e\s", docker):
        issues.append(Issue("consistency", "Dockerfile", "never an editable install"))
    return issues


def _check_spdx(tree: Tree) -> list[Issue]:
    issues = []
    for rel, text in tree.items():
        if rel.endswith(".py") and rel.startswith(("src/", "tests/", "scripts/")):
            lines = text.splitlines()
            if lines and lines[0].startswith("#!"):
                lines = lines[1:]
            if lines[:2] != SPDX_HEADER:
                issues.append(Issue("consistency", rel, "missing the SPDX and copyright header"))
    return issues


def _check_workflows(tree: Tree) -> list[Issue]:
    issues = []
    for rel, text in tree.items():
        if rel.startswith(".github/workflows/") and rel.endswith((".yml", ".yaml")):
            for ref in USES_RE.findall(text):
                ref = ref.strip("'\"")
                if ref.startswith("./"):
                    continue
                if not PINNED_ACTION_RE.match(ref):
                    issues.append(Issue("consistency", rel,
                                        f"action {ref} is not pinned to a full commit SHA"))
            if "pull_request_target" in text:
                issues.append(Issue("consistency", rel, "never pull_request_target"))
    return issues


def _check_icon(root: Path) -> list[Issue]:
    path = root / "assets" / "sn1per-mcp-256.png"
    if not path.is_file():
        return []
    data = path.read_bytes()[:32]
    if data[:8] != PNG_SIGNATURE or data[12:16] != b"IHDR":
        return [Issue("consistency", "assets/sn1per-mcp-256.png", "not a PNG file")]
    width, height = struct.unpack(">II", data[16:24])
    if (width, height) != (256, 256):
        return [Issue("consistency", "assets/sn1per-mcp-256.png",
                      f"icon is {width}x{height}, expected 256x256")]
    return []


def _check_license_files(tree: Tree) -> list[Issue]:
    issues = []
    license_text = tree.text("LICENSE") or ""
    if not license_text.lstrip().startswith("Apache License") or (
            "Version 2.0, January 2004" not in license_text):
        issues.append(Issue("consistency", "LICENSE", "not the Apache License 2.0 text"))
    notice = tree.text("NOTICE") or ""
    if not notice.startswith("Sn1per MCP Server\nCopyright 2026 Sn1perSecurity LLC\n"):
        issues.append(Issue("consistency", "NOTICE", "first lines differ"))
    return issues


# --- checks: decisions file -------------------------------------------------------------

def parse_env_file(path: Path) -> dict[str, str]:
    values = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def check_decisions(path: Path, version: str) -> list[Issue]:
    try:
        values = parse_env_file(path)
    except OSError as exc:
        return [Issue("decisions", str(path), f"cannot read: {exc}")]
    expected = {
        "VERSION": version,
        "TAG": f"v{version}",
        "REGISTRY_NAME": REGISTRY_NAME,
        "REGISTRY_TITLE": REGISTRY_TITLE,
        "REGISTRY_DESCRIPTION": DESCRIPTION,
        "PYPI_SUMMARY": DESCRIPTION,
        "REGISTRY_SCHEMA": SERVER_JSON_SCHEMA,
        "MCP_NAME_TOKEN": MCP_NAME_TOKEN,
        "TAGLINE": TAGLINE,
        "SCOPE_PLACEHOLDER": SCOPE_PLACEHOLDER,
        "SERVER_JSON_SCOPE_PLACEHOLDER": SERVER_JSON_SCOPE_PLACEHOLDER,
        "FUTURE_DOCS_URL": FUTURE_DOCS_URL,
        "LINK_HOST_ALLOWLIST": " ".join(LINK_HOST_ALLOWLIST),
        "SCRUB_REGEX": SCRUB_PATTERN,
        "UTM_GITHUB": UTM_GITHUB,
        "SUPPORT_EMAIL": SUPPORT_EMAIL,
        "REPO_URL": REPO_URL,
        "DEVELOPMENT_STATUS": BETA,
        "DENIED_EXAMPLE_NAMES": " ".join(DENIED_EXAMPLE_NAMES),
        "SPDX_HEADER_LINE_1": SPDX_HEADER[0],
        "SPDX_HEADER_LINE_2": SPDX_HEADER[1],
    }
    issues = []
    for key, value in expected.items():
        if values.get(key) != value:
            issues.append(Issue("decisions", key,
                                f"decisions file has {values.get(key)!r}, script has {value!r}"))
    return issues


# --- checks: drift on non-repository surfaces -------------------------------------------

# Q.1: other surfaces carry no install pins and no environment tables. A
# version-agnostic install command (`pipx install sn1per-mcp`) is allowed.
DRIFT_PATTERNS = (
    (re.compile(r"sn1per-mcp\s*(?:==|@|~=|>=)\s*\d"), "version pin"),
    # A Markdown table row with a setting name in any cell.
    (re.compile(r"^[ \t]*\|[^\n]*\bSNIPER_[A-Z0-9_]+", re.MULTILINE), "environment table"),
    # Tag names in any case; the variable name itself in capitals only, so a tool name
    # such as sniper_scan in a table cell is not an environment table.
    (re.compile(r"(?i:<t[dh])[^>]*>\s*(?i:<code>)?SNIPER_[A-Z0-9_]+"), "environment table"),
)


def check_drift(surfaces: list[Path]) -> list[Issue]:
    issues = []
    for surface in surfaces:
        if not surface.is_dir():
            issues.append(Issue("drift", str(surface), "not a directory"))
            continue
        # Every file: a staged site's dist/ or build/ output is what gets published.
        for path in walk_all(surface):
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for regex, label in DRIFT_PATTERNS:
                for match in regex.finditer(text):
                    number = text.count("\n", 0, match.start()) + 1
                    issues.append(Issue("drift", f"{path}:{number}",
                                        f"{label} on a non-repository surface (link the "
                                        "repository docs instead)"))
    return issues


# --- checks: built distributions --------------------------------------------------------

def check_dist(dist: Path, version: str) -> list[Issue]:
    issues: list[Issue] = []

    def bad(path: str, message: str, category: str = "dist") -> None:
        issues.append(Issue(category, path, message))

    stem = f"sn1per_mcp-{version}"
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if [w.name for w in wheels] != [f"{stem}-py3-none-any.whl"]:
        bad(str(dist), f"expected one wheel {stem}-py3-none-any.whl, found "
                       f"{[w.name for w in wheels]}")
    if [s.name for s in sdists] != [f"{stem}.tar.gz"]:
        bad(str(dist), f"expected one sdist {stem}.tar.gz, found {[s.name for s in sdists]}")
    for wheel in wheels:
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist()
            info = f"{stem}.dist-info/"
            for name in names:
                if not (name.startswith("sniper_mcp/") or name.startswith(info)):
                    bad(wheel.name, f"unexpected member {name}")
                if name.startswith("tests/") or "/tests/" in name:
                    bad(wheel.name, f"tests must not be in the wheel: {name}")
            for required in ("licenses/LICENSE", "licenses/NOTICE", "METADATA",
                             "entry_points.txt"):
                if info + required not in names:
                    bad(wheel.name, f"missing {info}{required}")
            if info + "METADATA" in names:
                metadata = archive.read(info + "METADATA").decode("utf-8")
                if "Name: sn1per-mcp\n" not in metadata or f"Version: {version}\n" not in metadata:
                    bad(wheel.name, "METADATA name or version differs")
                if "License-Expression: Apache-2.0\n" not in metadata:
                    bad(wheel.name, "METADATA lacks License-Expression: Apache-2.0")
                if MCP_NAME_TOKEN not in metadata.splitlines():
                    bad(wheel.name, f"METADATA lacks the line {MCP_NAME_TOKEN} (it comes from "
                                    "README.md)", "docs-pending")
            if info + "entry_points.txt" in names:
                entry_points = archive.read(info + "entry_points.txt").decode("utf-8")
                for script in ("sn1per-mcp", "sniper-mcp-server"):
                    if f"{script} = sniper_mcp.server:main" not in entry_points:
                        bad(wheel.name, f"console script {script} missing")
    for sdist in sdists:
        with tarfile.open(sdist) as archive:
            names = [m.name for m in archive.getmembers()]
        prefix = stem + "/"
        relative = {n[len(prefix):] for n in names if n.startswith(prefix)}
        for required in ("LICENSE", "NOTICE", "TRADEMARKS.md", "server.json", "README.md",
                         "pyproject.toml", "tests/conftest.py",
                         # tests/test_release_files.py loads both scripts.
                         "scripts/check_release_consistency.py", "scripts/mcp-call.py"):
            if required not in relative:
                bad(sdist.name, f"missing {required}")
        if not any(n.startswith("tests/fixtures/") for n in relative):
            bad(sdist.name, "missing tests/fixtures/")
        for required in ("SECURITY.md", "CHANGELOG.md"):
            if required not in relative:
                bad(sdist.name, f"missing {required}", "docs-pending")
        if not any(n.startswith("docs/") for n in relative):
            bad(sdist.name, "missing docs/", "docs-pending")
        for name in relative:
            parts = name.split("/")
            if name in NOT_EXPORTED_FILES or any(
                    p in SKIPPED_DIRS - {"build", "dist"} or p.endswith(".pyc") for p in parts):
                bad(sdist.name, f"must not ship {name}")
    return issues


# --- verification placeholders ------------------------------------------------------------

# Claims that only the live verification may upgrade (support matrix, tested clients,
# dates and commit ids) carry an HTML comment that opens with VERIFY and a colon, next
# to the claim-safe fallback wording. The private branch keeps them (a note); a CI
# checkout and the export fail on every one left. Any HTML comment that contains the
# word verify, in any case and with or without the colon, counts, so that a misspelt
# placeholder cannot slip through. The pattern is built from parts so that this file
# never contains a marker itself.
# Any HTML comment with a word that starts with "verif" (VERIFY, VERIFY_LATER, Verified),
# also when the comment spans lines. "unverified" does not count: the prefix must start a word.
VERIFY_MARKER_RE = re.compile("<!" + r"--(?:(?!--" + r">).)*?\b" + "verif",
                              re.IGNORECASE | re.DOTALL)


def verify_markers(tree: Tree) -> list[str]:
    """Each placeholder as path:line, the line being where its comment opens."""
    found = []
    for rel, text in sorted(tree.items()):
        for match in VERIFY_MARKER_RE.finditer(text):
            found.append(f"{rel}:{text.count(chr(10), 0, match.start()) + 1}")
    return found


# --- driver -----------------------------------------------------------------------------

def run(args: argparse.Namespace) -> tuple[list[Issue], list[str]]:
    root = Path(args.root).resolve()
    version = read_version(root)
    only = set(args.only.split(",")) if args.only else None
    notes: list[str] = []
    issues: list[Issue] = []

    def wanted(category: str) -> bool:
        return only is None or category in only

    tree_needed = any(wanted(c) for c in ("missing", "docs-pending", "not-exported", "scrub",
                                         "em-dash", "examples", "links", "consistency"))
    if tree_needed:
        mode = "export" if args.export else "private" if args.private_branch else "checkout"
        tree = Tree(root, mode)
        notes += tree.notes
        if tree.skipped_internal:
            notes.append("not scanned (never exported): " + ", ".join(tree.skipped_internal))
        issues += [i for i in check_layout(tree) if wanted(i.category)]
        if wanted("scrub"):
            issues += check_scrub(tree)
        if wanted("em-dash"):
            issues += check_em_dash(tree)
        if wanted("examples"):
            issues += check_examples(tree)
        if wanted("links"):
            issues += check_links(tree)
        if wanted("consistency"):
            issues += check_consistency(tree, version)
            markers = verify_markers(tree)
            if tree.private and markers:
                notes.append(f"{len(markers)} verification placeholders remain (filled by the "
                             "verification phase; the export fails on them): "
                             + ", ".join(markers))
            elif markers:
                issues += [Issue("consistency", where, "verification placeholder (an HTML "
                                 "comment opening with VERIFY:) left in a published file")
                           for where in markers]
    if args.decisions and wanted("decisions"):
        issues += check_decisions(Path(args.decisions), version)
    if args.surfaces and wanted("drift"):
        issues += check_drift([Path(s) for s in args.surfaces])
    if args.dist and wanted("dist"):
        issues += check_dist(Path(args.dist), version)

    # A problem inside a documentation file belongs to the docs category, except a
    # scrub, em-dash or example-value problem: those fail whatever the docs state.
    final = []
    for issue in issues:
        rel = issue.path.split(":")[0]
        if issue.category not in NOT_RELABELLED and is_doc(rel):
            issue = Issue("docs-pending", issue.path, f"[{issue.category}] {issue.message}")
        final.append(issue)
    return final, notes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Release checks for the Sn1per MCP Server repository.")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parent.parent),
                        help="repository root (default: the parent of scripts/)")
    parser.add_argument("--allow-pending-docs", action="store_true",
                        help="report the docs-pending category without failing")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--export", action="store_true",
                      help="the tree is the public export: build, cache and virtual-"
                           "environment directories fail as well")
    mode.add_argument("--private-branch", action="store_true",
                      help="the tree is the private release branch or a developer clone: "
                           "the never-exported files are noted, not read or failed")
    parser.add_argument("--decisions", metavar="FILE",
                        help="compare the embedded constants with this decisions file")
    parser.add_argument("--surfaces", metavar="DIR", nargs="+",
                        help="non-repository surfaces for the drift check")
    parser.add_argument("--dist", metavar="DIR", help="check the built wheel and sdist")
    parser.add_argument("--only", metavar="CATEGORIES",
                        help="comma-separated categories to check: " + ",".join(CATEGORIES))
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    parser.add_argument("--print-version", action="store_true",
                        help="print the package version and exit")
    args = parser.parse_args(argv)

    if args.print_version:
        print(read_version(Path(args.root).resolve()))
        return 0
    if args.only and not set(args.only.split(",")) <= set(CATEGORIES):
        parser.error(f"unknown category in --only; choose from {', '.join(CATEGORIES)}")

    issues, notes = run(args)
    failing = [i for i in issues
               if not (args.allow_pending_docs and i.category == "docs-pending")]
    if args.json:
        print(json.dumps({
            "ok": not failing,
            "issues": [{"category": i.category, "path": i.path, "message": i.message}
                       for i in issues],
            "notes": notes,
        }, indent=2))
    else:
        for note in notes:
            print(f"note: {note}")
        for category in CATEGORIES:
            group = [i for i in issues if i.category == category]
            if group:
                state = ("reported only" if args.allow_pending_docs
                         and category == "docs-pending" else "FAIL")
                print(f"{category}: {len(group)} ({state})")
                for issue in group:
                    print(issue.render())
        print("release checks: " + ("passed" if not failing else f"{len(failing)} failing"))
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
