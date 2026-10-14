# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Packaging metadata and source hygiene (contract A.1-A.4, O.5 P0-01, P0-03)."""

from __future__ import annotations

import ast
import importlib.metadata
import re
import tomllib
from pathlib import Path

import trove_classifiers

import sniper_mcp

REPO = Path(__file__).resolve().parent.parent
DESCRIPTION = ("Run scoped, authorized Sn1per pentest, recon and attack surface scans from AI "
               "agents; read findings.")
CLASSIFIERS = [
    "Development Status :: 4 - Beta",
    "Environment :: Console",
    "Intended Audience :: Information Technology",
    "Intended Audience :: System Administrators",
    "Operating System :: POSIX :: Linux",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3 :: Only",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Programming Language :: Python :: 3.14",
    "Topic :: Security",
]
KEYWORDS = ["mcp", "mcp-server", "model-context-protocol", "sn1per", "pentest",
            "penetration-testing", "recon", "reconnaissance", "attack-surface-management",
            "security-testing", "osint", "kali-linux"]


def pyproject() -> dict:
    return tomllib.loads((REPO / "pyproject.toml").read_text())


def test_version_single_source():
    meta = importlib.metadata.metadata("sn1per-mcp")
    assert sniper_mcp.__version__ == "0.9.0" == meta["Version"]
    project = pyproject()["project"]
    assert "version" not in project and project["dynamic"] == ["version"]
    assert pyproject()["tool"]["setuptools"]["dynamic"]["version"] == {
        "attr": "sniper_mcp.__version__"}
    init = (REPO / "src" / "sniper_mcp" / "__init__.py").read_text()
    assert [ln for ln in init.splitlines() if not ln.startswith("#")] == [
        '__version__ = "0.9.0"']


def test_version_is_hardcoded_nowhere_else_in_src():
    """A.3: every other module reads sniper_mcp.__version__; no string literal (code,
    docstring or f-string part) repeats the version. Comments are not code."""
    version = re.compile(r"(?<![\d.])" + re.escape(sniper_mcp.__version__) + r"(?!\d|\.\d)")
    found = []
    for path in sorted((REPO / "src" / "sniper_mcp").rglob("*.py")):
        if path.name == "__init__.py" and path.parent.name == "sniper_mcp":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                    and version.search(node.value):
                found.append(f"{path.relative_to(REPO)}:{node.lineno}")
    assert found == []


def test_runtime_dependencies_exactly():
    requires = sorted(r.replace(" ", "") for r in importlib.metadata.requires("sn1per-mcp")
                      if "extra ==" not in r)
    assert requires == ["idna<4,>=3.7", "mcp<2,>=1.28.1", "pydantic<3,>=2.11"]


def test_dev_extra_and_build_system():
    data = pyproject()
    assert data["build-system"] == {"requires": ["setuptools>=77", "wheel"],
                                    "build-backend": "setuptools.build_meta"}
    assert data["project"]["optional-dependencies"]["dev"] == [
        "pytest>=8.2", "pytest-asyncio>=0.24", "ruff>=0.6", "build>=1.2", "twine>=5.1",
        "trove-classifiers"]


def test_metadata_fields():
    meta = importlib.metadata.metadata("sn1per-mcp")
    assert meta["Name"] == "sn1per-mcp"
    assert meta["Summary"] == DESCRIPTION and len(DESCRIPTION) <= 100
    assert meta["Requires-Python"] == ">=3.11"
    assert meta["License-Expression"] == "Apache-2.0"
    assert sorted(meta.get_all("License-File")) == ["LICENSE", "NOTICE"]
    assert not any(c.startswith("License ::") for c in meta.get_all("Classifier"))
    assert meta.get_all("Classifier") == CLASSIFIERS
    assert all(c in trove_classifiers.classifiers for c in CLASSIFIERS)
    assert meta["Keywords"].split(",") == KEYWORDS
    assert "hacking" not in meta["Keywords"]
    assert meta["Author-email"] == "Sn1perSecurity LLC <support@sn1persecurity.com>"
    urls = dict(u.split(", ", 1) for u in meta.get_all("Project-URL"))
    assert urls == {
        "Homepage": "https://sn1persecurity.com/?utm_source=pypi&utm_medium=package"
                    "&utm_campaign=sn1per-mcp",
        "Documentation": "https://github.com/1N3/sn1per-mcp/tree/main/docs",
        "Source": "https://github.com/1N3/sn1per-mcp",
        "Issues": "https://github.com/1N3/sn1per-mcp/issues",
        "Changelog": "https://github.com/1N3/sn1per-mcp/blob/main/CHANGELOG.md",
        "Security": "https://github.com/1N3/sn1per-mcp/security/policy",
    }


def test_license_files_present():
    license_text = (REPO / "LICENSE").read_text()
    assert "Apache License" in license_text and "Version 2.0, January 2004" in license_text
    notice = (REPO / "NOTICE").read_text()
    assert notice.startswith("Sn1per MCP Server\nCopyright 2026 Sn1perSecurity LLC\n")


def test_spdx_header_in_every_python_file():
    files = [p for root in ("src", "tests") for p in (REPO / root).rglob("*.py")
             if "__pycache__" not in p.parts]
    assert files
    for path in files:
        lines = path.read_text().splitlines()
        if lines and lines[0].startswith("#!"):
            lines = lines[1:]
        assert lines[:2] == ["# SPDX-License-Identifier: Apache-2.0",
                             "# Copyright 2026 Sn1perSecurity LLC"], path


def test_no_em_dash_in_source_tree():
    forbidden = [chr(0x2014), "&" + "mdash;", "&#" + "8212;", "&#x" + "2014;"]
    for root in ("src", "tests"):
        for path in (REPO / root).rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts:
                text = path.read_text(errors="replace")
                assert not any(f in text for f in forbidden), path


# The P.5 export scrub pattern. Every alternative is stored reversed so that this file,
# which the scrub also covers, never contains a token it searches for.
_SCRUB_ALTERNATIVES_REVERSED = (
    ')<!?(/emoh/',
    '/tsetnep/',
    '/repins/)]-._9-0z-aZ-A[!<?(',
    '@zyad0rex',
    'liamnotorp',
    'liamhsuh',
    'E413x0',
    'ytilibisaef',
    '#? evitceriD',
    'pcm-deifinu',
    'enigne?] _-[gar',
    'tneilc_gar',
    'ENIGNE_GAR',
    'tool_yreuq',
    'enigne egdelwonk',
    '0008:tsohlacol',
    'revres-ytiruces-pcm',
    'niahctnelis',
    ')8/0!?(.\\0.\\0.\\01',
    '.\\85.\\861.\\291',
    '.\\0.\\71.\\271',
    '.\\232.\\561',
    '.\\842.\\401',
    'eriftset',
    'bewnluv',
    'itcivnitset',
    'dnuorg-tsetnep',
    'gfum',
    'yapellez',
    'elbatiolpsatem',
    'dm.\\EDUALC',
)
SCRUB = re.compile("(" + "|".join(a[::-1] for a in _SCRUB_ALTERNATIVES_REVERSED) + ")",
                   re.IGNORECASE)


def test_scrub_pattern_matches_its_own_tokens():
    assert SCRUB.search("RAG" + "_ENG" + "INE_URL")
    assert SCRUB.search("_RAG" + "_ENG" + "INE = 1")
    assert SCRUB.search("/pen" + "test/x")
    assert not SCRUB.search("10.0.0.0/8")


def test_src_and_tests_pass_the_p5_scrub():
    hits = []
    for root in ("src", "tests"):
        for path in (REPO / root).rglob("*"):
            built = any(part == "__pycache__" or part.endswith(".egg-info") for part in path.parts)
            if path.is_file() and not built:
                text = path.read_text(errors="replace")
                for number, line in enumerate(text.splitlines(), 1):
                    for match in SCRUB.finditer(line):
                        hits.append(f"{path.relative_to(REPO)}:{number}: {match.group(0)}")
    assert hits == []
