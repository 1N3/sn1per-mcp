# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""The public documentation agrees with the code (contract Q.1, Q.4-Q.6, Q.14).

The pages under docs/ are the canonical public description of the server. These tests
read them as text and compare them with what the code registers and returns: tool
descriptions, parameter descriptions, annotations and error lists (docs/tools.md), the
error and warning code tables (results.py), the example payloads (shape, against real
calls through the stubs), the mode tables (modes.py), the settings defaults and the
command-line flags (settings.py, server.py), and the scan failure reasons (jobs.py).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import pytest

from sniper_mcp import jobs, modes, results, server, settings
from sniper_mcp.tools import status
from tests import support

REPO = Path(__file__).resolve().parent.parent
DOCS = REPO / "docs"
if not (DOCS / "tools.md").is_file():
    pytest.skip("docs/ is not present", allow_module_level=True)

TOOLS_MD = (DOCS / "tools.md").read_text(encoding="utf-8")
EDITIONS_MD = (DOCS / "editions.md").read_text(encoding="utf-8")
CONFIGURATION_MD = (DOCS / "configuration.md").read_text(encoding="utf-8")
TROUBLESHOOTING_MD = (DOCS / "troubleshooting.md").read_text(encoding="utf-8")
README_MD = (REPO / "README.md").read_text(encoding="utf-8")


# --- Markdown helpers ------------------------------------------------------------------

def section(text: str, heading: str) -> str:
    """The body of the section that starts with the exact heading line, up to the next
    heading of the same or a higher level (a '#' line inside a code block is no heading)."""
    level = len(heading) - len(heading.lstrip("#"))
    lines = text.splitlines()
    start = lines.index(heading) + 1
    end = len(lines)
    inside_fence = False
    for index in range(start, len(lines)):
        if re.match(r"^\s*(```|~~~)", lines[index]):
            inside_fence = not inside_fence
        match = None if inside_fence else re.match(r"^(#+) ", lines[index])
        if match and len(match.group(1)) <= level:
            end = index
            break
    return "\n".join(lines[start:end])


def table_rows(text: str, header_start: str) -> list[list[str]]:
    """The body rows of the first Markdown table whose header line starts with
    header_start, as lists of stripped cells."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.startswith(header_start):
            rows = []
            for row in lines[index + 2:]:
                if not row.startswith("|"):
                    break
                rows.append([cell.strip() for cell in row.strip().strip("|").split(" | ")])
            return rows
    raise AssertionError(f"no table starting with {header_start!r}")


def codes_in(cell: str) -> list[str]:
    return re.findall(r"`([a-z_]+)`", cell)


def json_after(text: str, marker: str) -> Any:
    """The first ```json block after the marker line."""
    tail = text[text.index(marker):]
    match = re.search(r"```json\n(.*?)\n```", tail, re.DOTALL)
    assert match, marker
    return json.loads(match.group(1))


# --- tools.md against the registered tools ---------------------------------------------

@pytest.fixture
def registered(iso):
    """The tools/list of a server with the destructive tools enabled."""
    iso.setenv(SNIPER_MCP_ENABLE_DESTRUCTIVE="1")

    async def listing():
        async with support.session() as client:
            return (await client.list_tools()).tools

    import anyio

    return {tool.name: tool for tool in anyio.run(listing)}


def test_every_registered_tool_has_a_section_with_its_exact_description(registered):
    assert len(registered) == 12
    for name, tool in registered.items():
        body = section(TOOLS_MD, f"## {name}")
        quoted = [line[2:] for line in body.splitlines() if line.startswith("> ")]
        assert quoted == [tool.description], name


def test_every_parameter_description_appears_verbatim(registered):
    for name, tool in registered.items():
        for param, schema in tool.inputSchema.get("properties", {}).items():
            assert f'"{schema["description"]}"' in TOOLS_MD, (name, param)


def test_tool_summary_table_matches_titles_and_annotations(registered):
    rows = table_rows(TOOLS_MD, "| Tool | Title | Read-only |")
    documented = {codes_in(row[0])[0]: row for row in rows}
    assert set(documented) == set(registered)
    yes_no = {True: "yes", False: "no"}
    for name, tool in registered.items():
        row = documented[name]
        hints = tool.annotations
        assert row[1:6] == [tool.title, yes_no[hints.readOnlyHint],
                            yes_no[hints.destructiveHint], yes_no[hints.idempotentHint],
                            yes_no[hints.openWorldHint]], name


def test_each_tool_lists_exactly_its_error_codes():
    golden = support.golden()["tools"]
    for name, entry in golden.items():
        body = section(TOOLS_MD, f"## {name}")
        lines = [line for line in body.splitlines() if line.startswith("**Errors:**")]
        assert len(lines) == 1, name
        if name == "sniper_status":
            assert codes_in(lines[0]) == ["internal_error"]
        else:
            assert sorted(codes_in(lines[0])) == sorted(entry["errors"]), name


def test_error_code_table_equals_results():
    rows = table_rows(TOOLS_MD, "| Code | Tools | Retry | Meaning |")
    documented = {codes_in(row[0])[0]: row[2] for row in rows}
    assert documented == results.ERROR_CODES


def test_warning_code_table_equals_results():
    rows = table_rows(TOOLS_MD, "| Code | Where it appears | Meaning |")
    documented = [code for row in rows for code in codes_in(row[0])]
    assert sorted(documented) == sorted(results.WARNING_CODES)


def test_untrusted_notice_is_quoted_exactly():
    assert results.UNTRUSTED_NOTICE in section(TOOLS_MD, "### Untrusted content")


def test_readme_tool_table_lists_every_tool(registered):
    rows = table_rows(README_MD, "| Tool | What it does |")
    assert sorted(codes_in(row[0])[0] for row in rows) == sorted(registered)


# --- example payloads in tools.md against real calls -----------------------------------

def shape(value: Any) -> Any:
    """Key order of every object (recursively; lists by their first element) and the JSON
    type of every scalar (None for null)."""
    if isinstance(value, dict):
        return {key: shape(item) for key, item in value.items()}
    if isinstance(value, list):
        return [shape(value[0])] if value else []
    if value is None:
        return None
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    raise TypeError(f"not a JSON value: {value!r}")


def same_shape(documented: Any, real: Any, where: str = "") -> None:
    if documented is None or real is None:
        return  # null on either side: the value is optional or not set in one of them
    if isinstance(documented, dict):
        assert isinstance(real, dict), where
        assert list(documented) == list(real), where
        for key in documented:
            same_shape(documented[key], real[key], f"{where}.{key}")
    elif isinstance(documented, list):
        assert isinstance(real, list), where
        if documented and real:
            same_shape(documented[0], real[0], f"{where}[0]")
    else:
        assert documented == real, f"{where}: documented {documented}, real {real}"


@pytest.fixture
def real_payloads(iso, monkeypatch):
    """One real result per tool, in the situations the documented examples show."""
    monkeypatch.setattr(jobs, "CANCEL_TERM_GRACE_SECONDS", 1.0)
    monkeypatch.setattr(jobs, "CANCEL_POLL_SECONDS", 3.0)
    status.clear_sudo_cache()
    iso.copy_loot("se-11.x")
    iso.resolve("app.example", "192.0.2.10")
    iso.public_addresses.add("192.0.2.10")
    iso.setenv(SNIPER_MCP_SCOPE="app.example,192.0.2.0/24,!dev.app.example",
               SNIPER_MCP_ENABLE_DESTRUCTIVE="1")
    iso.make_workspace("old-ws", {"notes.txt": "x\n"})
    iso.make_workspace("acme-2026q4", {"nmap/nmap-app.example.txt": "22/tcp open ssh\n"})
    for directory in (iso.install_dir, iso.loot_base, iso.workspace_dir):
        os.chmod(directory, 0o755)  # I.3 step 6: the delete root must not be group-writable
    found: dict[str, dict] = {}

    async def collect() -> None:
        found["sniper_status"], _ = await support.call("sniper_status")
        found["always_denied"], _ = await support.call("sniper_scan", {"target": "example.com"})
        found["out_of_scope"], _ = await support.call("sniper_scan",
                                                      {"target": "shop.other.example"})
        iso.set_knobs(sleep=30)
        found["sniper_scan"], _ = await support.call("sniper_scan", {"target": "app.example"})
        job = found["sniper_scan"]["job_id"]
        found["scan_status"], _ = await support.call(
            "scan_status", {"job_id": job, "workspace": "app.example"})
        found["cancel_scan"], _ = await support.call("cancel_scan", {"job_id": job})
        iso.set_knobs(files=["scans/stub-output.txt"])
        for tool, arguments in (
                ("list_workspaces", {}),
                ("get_findings", {"workspace": "app.example"}),
                ("get_ports", {"workspace": "192.0.2.0-24", "host": "192.0.2.1"}),
                ("get_subdomains", {"workspace": "app.example"}),
                ("get_technologies", {"workspace": "app.example", "host": "app.example"}),
                ("grep_loot", {"workspace": "app.example", "pattern": "nginx"})):
            found[tool], _ = await support.call(tool, arguments)
        answer = support.Elicitation("accept", "acme-2026q4")
        found["export_workspace"], _ = await support.call(
            "export_workspace", {"workspace": "acme-2026q4"}, **answer.kwargs())
        answer = support.Elicitation("accept", "old-ws")
        found["delete_workspace"], _ = await support.call(
            "delete_workspace", {"workspace": "old-ws", "confirm": True}, **answer.kwargs())

    import anyio

    try:
        anyio.run(collect)
    finally:
        jobs.terminate_all()
        jobs.JOBS.clear()
    return found


TOOLS_WITH_EXAMPLES = ("sniper_status", "sniper_scan", "scan_status", "cancel_scan",
                       "list_workspaces", "get_findings", "get_ports", "get_subdomains",
                       "get_technologies", "grep_loot", "delete_workspace", "export_workspace")


def test_example_results_have_the_shape_of_real_results(real_payloads):
    for name in TOOLS_WITH_EXAMPLES:
        documented = json_after(section(TOOLS_MD, f"## {name}"), "**Example result:**")
        real = real_payloads[name]
        assert "error" not in real, (name, real)
        same_shape(shape(documented), shape(real), name)


def test_refusal_examples_are_real_refusals(real_payloads):
    body = section(TOOLS_MD, "## sniper_scan")
    denied = json_after(body, "always-denied documentation domain")
    assert denied == real_payloads["always_denied"]
    out = json_after(body, "**Refusal example** (out of scope)")
    real = real_payloads["out_of_scope"]
    assert {k: v for k, v in out["error"].items() if k != "details"} == \
        {k: v for k, v in real["error"].items() if k != "details"}
    assert list(out["error"]["details"]) == list(real["error"]["details"])


# --- editions.md against modes.py --------------------------------------------------------

TARGET_TYPE_WORDS = {"hostname": "hostname", "ipv4": "IPv4", "cidr": "IPv4 CIDR"}


@pytest.mark.parametrize("dialect, heading", [
    ("11.x", "### 11.x dialect (Sn1per SE, Professional and Enterprise)"),
    ("9.x", "### 9.x dialect (Sn1per Community Edition 9.2)"),
])
def test_mode_tables_equal_the_dialect_tables(dialect, heading):
    rows = table_rows(section(EDITIONS_MD, heading), "| Mode | Class | Flags |")
    expected = []
    for mode in modes.table(dialect):
        entry = modes.status_entry(mode)
        name = f"`{entry['name']}`" + (" (default)" if entry["name"] == modes.DEFAULT_MODE
                                       else "")
        expected.append([
            name, entry["class"], ", ".join(f"`{flag}`" for flag in entry["flags"]),
            ", ".join(TARGET_TYPE_WORDS[t] for t in entry["target_types"]),
            "required" if entry["requires_port"] else "no", entry["description"]])
    assert rows == expected


# --- configuration.md against settings.py and server.py ----------------------------------

SCALAR_DEFAULTS = {
    "SNIPER_EDITION": ("edition", "auto"), "SNIPER_SCAN_ENABLED": ("scan_enabled", True),
    "SNIPER_MCP_ALLOW_ANY_TARGET": ("allow_any_target", False),
    "SNIPER_MCP_DNS_POLICY": ("dns_policy", "strict"),
    "SNIPER_MCP_CIDR_CAP": ("cidr_cap", 16),
    "SNIPER_MCP_ALLOW_INTRUSIVE": ("allow_intrusive", False),
    "SNIPER_MCP_MAX_CONCURRENT_SCANS": ("max_concurrent_scans", 2),
    "SNIPER_MCP_ENABLE_DESTRUCTIVE": ("enable_destructive", False),
    "SNIPER_MCP_REDACT": ("redact", True), "SNIPER_MCP_REVEAL_SECRETS": ("reveal_secrets", False),
    "SNIPER_MCP_LOG_RETENTION_DAYS": ("log_retention_days", 30),
}


def test_environment_table_defaults_equal_the_settings_defaults(tmp_path):
    rows = table_rows(CONFIGURATION_MD, "| Variable | Type | Default | Effect |")
    documented = {re.findall(r"`(SNIPER_[A-Z0-9_]+)`", row[0])[0]: row[2] for row in rows}
    assert sorted(documented) == sorted(settings.ENV_VARS)
    loaded = settings.load_settings({"HOME": str(tmp_path)}, euid=1000)
    for var, (attribute, value) in SCALAR_DEFAULTS.items():
        assert getattr(loaded, attribute) == value, var
        text = str(value).lower() if isinstance(value, bool) else str(value)
        assert documented[var] == f"`{text}`", var


def test_command_line_table_names_exactly_the_flags_of_the_server():
    rows = table_rows(CONFIGURATION_MD, "| Invocation | Behaviour |")
    documented = {flag for row in rows for flag in re.findall(r"--[a-z-]+", row[0])}
    assert documented == set(re.findall(r"--[a-z-]+", server.USAGE))
    assert f"`sn1per-mcp {server.__version__}`" in CONFIGURATION_MD


# --- troubleshooting.md against jobs.py and results.py ----------------------------------

def test_scan_failure_reasons_equal_the_classification():
    rows = table_rows(TROUBLESHOOTING_MD, "| `state_reason` | Typical cause |")
    documented = sorted(code for row in rows for code in codes_in(row[0]))
    expected = sorted([reason for reason, _, _ in jobs.FAILURE_PATTERNS]
                      + ["engine_removed", "exit_status", "no_output"])
    assert documented == expected


def test_troubleshooting_codes_exist():
    rows = table_rows(TROUBLESHOOTING_MD, "| Code | What it means | What to do |")
    known = set(results.ERROR_CODES) | set(results.WARNING_CODES)
    for row in rows:
        for code in re.findall(r"^`([a-z_]+)`|, `([a-z_]+)`", row[0]):
            name = code[0] or code[1]
            assert name in known, name


# --- links between the documentation files ----------------------------------------------

DOC_PAGES = ("README.md", "SECURITY.md", "SUPPORT.md", "CONTRIBUTING.md", "CHANGELOG.md",
             *(f"docs/{p.name}" for p in sorted(DOCS.glob("*.md"))))
REPO_URL_PREFIXES = ("https://github.com/1N3/sn1per-mcp/blob/main/",
                     "https://github.com/1N3/sn1per-mcp/tree/main/")


def github_slug(heading: str) -> str:
    """GitHub's heading anchor: lower case, punctuation other than '-' and '_' dropped,
    spaces turned into hyphens."""
    text = heading.strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def anchors(rel: str) -> set[str]:
    text = (REPO / rel).read_text(encoding="utf-8")
    inside_fence = False
    found = set()
    for line in text.splitlines():
        if re.match(r"^\s*(```|~~~)", line):
            inside_fence = not inside_fence
        elif not inside_fence and (match := re.match(r"^#{1,6} (.+)$", line)):
            found.add(github_slug(match.group(1)))
    return found


# The sdist (A.4) carries README.md, docs/, SECURITY.md and CHANGELOG.md but not the other
# community files, so the cross-file link check needs a repository checkout.
@pytest.mark.skipif(not (REPO / ".github").is_dir() or not (REPO / "SUPPORT.md").is_file(),
                    reason="needs a repository checkout; the sdist does not ship every page")
def test_links_between_docs_point_at_existing_files_and_headings():
    checked = 0
    for rel in DOC_PAGES:
        base = (REPO / rel).parent
        text = (REPO / rel).read_text(encoding="utf-8")
        for target in re.findall(r"\]\(([^)\s]+)\)", text):
            if target.startswith("https://github.com/1N3/sn1per-mcp#"):
                path, anchor = "README.md", target.split("#", 1)[1]
            elif target.startswith(REPO_URL_PREFIXES):
                path, _, anchor = target.split("/main/", 1)[1].partition("#")
            elif re.match(r"^[a-z]+:", target):
                continue  # another site, or mailto:
            elif target.startswith("#"):
                path, anchor = rel, target[1:]
            else:
                local, _, anchor = target.partition("#")
                path = (base / local).resolve().relative_to(REPO).as_posix()
            assert (REPO / path).exists(), (rel, target)
            if anchor:
                assert anchor in anchors(path), (rel, target)
            checked += 1
    assert checked > 50


def test_same_shape_compares_scalar_types():
    same_shape(shape({"a": 1, "b": [{"c": "x"}], "d": None}),
               shape({"a": 2.5, "b": [{"c": "y"}], "d": True}))
    for documented, real in (({"a": 1}, {"a": "1"}), ({"a": True}, {"a": 1}),
                             ({"a": [{"c": "x"}]}, {"a": [{"c": 3}]})):
        with pytest.raises(AssertionError):
            same_shape(shape(documented), shape(real))


# --- egress filter guidance (security-model.md, remote.md; Q.7, Q.8, D.7) ------------------

SECURITY_MODEL_MD = (DOCS / "security-model.md").read_text(encoding="utf-8")
REMOTE_MD = (DOCS / "remote.md").read_text(encoding="utf-8")
EGRESS_HOST = "### Egress filter recipe (documented, unverified)"
EGRESS_CONTAINERS = "#### Scanning containers on a Docker bridge network (documented, unverified)"
CONTAINERS_ANCHOR = "security-model.md#" + github_slug(EGRESS_CONTAINERS.lstrip("# "))


def code_blocks(text: str) -> list[str]:
    return re.findall(r"^```[a-z]+\n(.*?)^```$", text, re.DOTALL | re.MULTILINE)


def nft_rules(block: str) -> list[str]:
    """The rule lines of an nftables example: the lines with a verdict, without comments
    and without the chain's base-chain line (which carries the policy)."""
    lines = (line.strip() for line in block.splitlines())
    return [line for line in lines
            if re.search(r"\b(accept|reject|drop)\b", line)
            and not line.startswith(("#", "type "))]


def nft_chains(block: str) -> dict[str, list[str]]:
    """The rules of each chain of an nftables example, by chain name, in order."""
    return {name: nft_rules(body) for name, body in
            re.findall(r"^\s*chain (\w+) \{\n(.*?)^\s*\}$", block, re.DOTALL | re.MULTILINE)}


# Replies to inbound connections (an SSH session, a published web UI) must pass before any
# block rule: nft's meta skuid gives a SYN-ACK its root-owned listener's owner, so without
# this rule the recipe rejects every inbound connection from a private client address.
ESTABLISHED = "ct state established,related accept"


def untested_note(body: str) -> str:
    """The paragraph that says the recipe was not run as written and what to check
    before relying on it (E2: it replaced the VERIFY comment, so the checks the
    verification run would need stay on the page and under test)."""
    (note,) = [p for p in body.split("\n\n") if "not been run as written" in p]
    assert "<!" + "--" not in body, "no HTML comment in the recipe sections"
    return note


def test_host_egress_recipe_filters_host_processes_and_says_so():
    body = section(SECURITY_MODEL_MD, EGRESS_HOST).split(EGRESS_CONTAINERS)[0]
    (recipe,) = [b for b in code_blocks(body) if "table inet sn1per_egress" in b]
    assert "type filter hook output" in recipe
    chains = nft_chains(recipe)
    assert list(chains) == ["output"]
    first, *rules = chains["output"]
    assert first == ESTABLISHED
    assert len(rules) == 4 and all(rule.startswith("meta skuid 0 ") for rule in rules)
    # The page explains why replies pass and that new connections are still rejected.
    assert "replies to inbound connections (an SSH session, a web UI) still leave" in body
    assert "first packet of a new outbound connection to a blocked range" in body
    note = untested_note(body)  # documented, unverified
    assert "SSH session from a private client address" in note
    assert "web UI from a private client address" in note
    assert "counters rose" in note and "nft -c -f" in note
    # The output-hook recipe never sees forwarded container traffic; the page says so and
    # points at the container variant.
    assert "forwarded packets have no owning process" in body
    assert f"(#{CONTAINERS_ANCHOR.split('#')[1]})" in body


def test_container_egress_variant_filters_the_forward_path():
    body = section(SECURITY_MODEL_MD, EGRESS_CONTAINERS)
    note = untested_note(body)  # documented, unverified
    assert "SSH session to the Docker host from a private client address" in note
    assert "published web UI" in note and "from a private client address" in note
    # S8 re-review 2: the userland-proxy paths must be part of the check.
    assert "from the Docker host itself (localhost)" in note
    assert "through an SSH tunnel (ssh -L) to a port published on localhost" in note
    assert "from an IPv6 client if the Docker host serves IPv6" in note
    blocks = [b for b in code_blocks(body) if "chain forward" in b]
    assert len(blocks) == 1
    assert "type filter hook forward" in blocks[0] and "type filter hook input" in blocks[0]
    chains = nft_chains(blocks[0])
    assert list(chains) == ["forward", "input"]
    for name, (first, *rules) in chains.items():
        assert first == ESTABLISHED, name
        assert rules and not any("skuid" in rule for rule in rules), name
        assert all(rule.startswith('iifname "<bridge-interface>" ') for rule in rules), name
        assert any("@block_v4" in r and "reject" in r for r in rules), name
        assert any("@block_v6" in r and "reject" in r for r in rules), name
    # Neighbour discovery is untracked, so the input chain accepts it explicitly before
    # the fc00::/7 and fe80::/10 rejects.
    nd = [r for r in chains["input"] if "icmpv6 type" in r]
    assert len(nd) == 1 and "nd-neighbor-solicit" in nd[0] and "nd-neighbor-advert" in nd[0]
    assert chains["input"].index(nd[0]) < next(
        i for i, r in enumerate(chains["input"]) if "@block_v6" in r)
    assert "com.docker.network.bridge.name=<bridge-interface>" in body
    # An existing container can keep its network (licence fingerprint), with the trade-off.
    assert "docker network inspect" in body and "every container on that network" in body
    assert "a published web UI port" in body
    # The input chain covers only the host's private and link-local addresses.
    assert "Docker host's private and link-local addresses" in body
    assert "services on the Docker host itself" not in body
    # The resolver caveat of the host recipe holds for containers too.
    assert "Add the resolver that the container uses to the allow sets" in body
    # iptables-only hosts: DOCKER-USER is forward-only, the input side goes to INPUT.
    iptables = next(p for p in body.split("\n\n") if "DOCKER-USER" in p)
    assert "`INPUT` chain" in iptables and "-i <bridge-interface>" in iptables
    assert "ESTABLISHED,RELATED" in iptables
    # Pass-through in DOCKER-USER is RETURN (ACCEPT would skip Docker's isolation rules),
    # and an iptables output filter needs the same bridge accept as the output chain.
    assert "`-j RETURN` rather than `-j ACCEPT`" in iptables
    assert "accept `-o <bridge-interface>`" in iptables
    # The in-container variant is honest about NET_ADMIN.
    inside = body.split("**Inside the container.**")[1]
    assert "NET_ADMIN" in inside and "can delete the table" in inside


def test_docker_recipes_never_point_at_the_host_output_recipe_alone():
    docker = section(REMOTE_MD, "## Docker")
    lines = [line for line in docker.splitlines() if "egress" in line.lower()]
    assert lines, "the Docker recipes must carry the egress note"
    for line in lines:
        assert CONTAINERS_ANCHOR in line, line
    recipe_a = section(REMOTE_MD, next(line for line in REMOTE_MD.splitlines()
                                       if line.startswith("### Recipe A:")))
    note = next(line for line in recipe_a.splitlines() if "egress" in line.lower())
    assert "forward" in note and "NET_ADMIN" in note
    assert "on the Docker host if needed" not in REMOTE_MD
    professional = section(REMOTE_MD, "### Sn1per Professional through `docker exec`")
    note = next(line for line in professional.splitlines() if "egress" in line.lower())
    assert "docker network inspect" in note and "every container on that network" in note
    # S8 re-review 2: the published web UI needs the output-chain bridge accept.
    assert "Keep the `output` chain rule for the bridge interface" in note
    assert "from the Docker host itself and through an SSH tunnel" in note
    assert "replies to the published web UI pass" not in note


def test_docker_host_output_chain_lets_the_port_publishing_proxy_reach_the_container():
    """S8 re-review 2: on a Docker host the recipe's output chain stays loaded, and Docker's
    port-publishing proxy (root, gateway address to the container, a private address)
    opens new connections, which meta skuid 0 ... @block_v4 rejected: the published web
    UI failed from localhost, through an ssh -L tunnel, and for IPv6 clients without
    Docker's IPv6 NAT. The variant replaces the output chain with one that accepts the
    bridge right after the established rule and keeps every other rule of the recipe."""
    host_body = section(SECURITY_MODEL_MD, EGRESS_HOST).split(EGRESS_CONTAINERS)[0]
    (recipe,) = [b for b in code_blocks(host_body) if "table inet sn1per_egress" in b]
    host_rules = nft_chains(recipe)["output"]
    body = section(SECURITY_MODEL_MD, EGRESS_CONTAINERS)
    (docker_output,) = [b for b in code_blocks(body) if "chain output" in b]
    assert "table inet" not in docker_output and "type filter hook output" in docker_output
    assert nft_chains(docker_output)["output"] == [
        host_rules[0], 'oifname "<bridge-interface>" accept', *host_rules[1:]]
    assert "Docker's port-publishing proxy" in docker_output
    # The prose says what the rule is for and no longer claims the proxy's traffic
    # passes as a reply.
    assert "replace its `output` chain with this version" in body
    assert "and so does Docker's port-publishing proxy on the gateway address" not in body
    assert ("without the `oifname \"<bridge-interface>\" accept` rule the `output` chain "
            "rejects that connection") in body
    # An interface name set with com.docker.network.bridge.name is read, not derived.
    assert "{{index .Options \"com.docker.network.bridge.name\"}}" in body
