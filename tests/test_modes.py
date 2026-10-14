# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Mode tables, the intrusive gate, the enum, D.6 compatibility and argv (O.5 P0-06).

Golden argv for every mode of both dialects runs through the stub sudo and
stub CLI and asserts the exact argv they recorded (O.3).
"""

from __future__ import annotations

import pytest

from sniper_mcp import jobs, modes, paths, targets
from sniper_mcp.tools import status
from tests import support

# D.2 / D.3 pinned: name -> (class, requires_port, target types, engine file probes).
GOLDEN_11 = {
    "stealth": ("active", False, ("hostname", "ipv4"), ("conf/flyover", "modes/normal.sh")),
    "recon_passive": ("active", False, ("hostname",),
                      ("conf/recon_passive", "modes/normal.sh")),
    "discover": ("active", False, ("ipv4", "cidr"),
                 ("modes/discover.sh", "conf/flyover", "modes/normal.sh")),
    "fullportscan": ("intrusive", False, ("hostname", "ipv4"),
                     ("conf/fullportscan", "modes/normal.sh")),
    "normal": ("intrusive", False, ("hostname", "ipv4"), ("conf/default", "modes/normal.sh")),
    "web": ("intrusive", False, ("hostname", "ipv4"), ("conf/default", "modes/normal.sh")),
    "port": ("intrusive", True, ("hostname", "ipv4"), ("conf/default", "modes/normal.sh")),
    "vulnscan": ("intrusive", False, ("hostname", "ipv4"), ("conf/vulnscan", "modes/normal.sh")),
    "full_scan": ("intrusive", False, ("hostname", "ipv4"),
                  ("conf/full_scan", "modes/normal.sh")),
}
GOLDEN_9 = {
    "stealth": ("active", False, ("hostname", "ipv4"), ("modes/stealth.sh",)),
    "discover": ("active", False, ("ipv4", "cidr"),
                 ("modes/discover.sh", "modes/flyover.sh")),
    "fullportonly": ("active", False, ("hostname", "ipv4"), ("modes/fullportonly.sh",)),
    "vulnscan": ("active", False, ("hostname", "ipv4"), ("modes/vulnscan.sh",)),
    "normal": ("intrusive", False, ("hostname", "ipv4"), ("modes/normal.sh",)),
    "web": ("intrusive", False, ("hostname", "ipv4"), ("modes/web.sh",)),
    "port": ("intrusive", True, ("hostname", "ipv4"), ("modes/normal.sh",)),
    "webporthttp": ("intrusive", True, ("hostname", "ipv4"), ("modes/webporthttp.sh",)),
    "webporthttps": ("intrusive", True, ("hostname", "ipv4"), ("modes/webporthttps.sh",)),
    "webscan": ("intrusive", False, ("hostname", "ipv4"), ("modes/webscan.sh",)),
}
# D.4: never offered, in either dialect.
EXCLUDED_11 = ["recon_active", "flyover", "webscan", "webporthttp", "webporthttps", "recon",
               "osint", "osint-stage2", "ad", "ad_info", "sniper-ad-exploit", "airstrike",
               "nuke", "massportscan", "massweb", "masswebscan", "massvulnscan"]
EXCLUDED_9 = ["bruteforce", "fullportscan", "osint", "recon", "osint_stage_2", "web_autopwn",
              "normal_webporthttp", "normal_webporthttps", "airstrike", "nuke",
              "massportscan", "massweb", "masswebscan", "massvulnscan", "flyover",
              "sc0pe", "javascript-analysis", "static-grep-search"]


# D.2 / D.3 pinned byte for byte: name -> (flags, model-facing description).
PINNED_TEXT_11 = {
    "stealth": (
        ("port_scan", "web_probe", "vuln_templates", "third_party_osint"),
        "Lightest scan (profile conf/flyover): default-port nmap scan without service "
        "scripts, HTTP probing, crawling, screenshots, TLS and nuclei technology, takeover "
        "and static checks. No brute force or exploitation."),
    "recon_passive": (
        ("subdomain_enum", "third_party_osint", "web_probe", "vuln_templates", "port_scan"),
        "Subdomain and OSINT reconnaissance (profile conf/recon_passive): third-party OSINT "
        "APIs and DNS brute force, then HTTP probing, crawling and nuclei checks of "
        "discovered hosts. Not passive: it sends DNS and HTTP traffic and port-scans if no "
        "earlier results exist."),
    "discover": (
        ("host_discovery", "port_scan", "fan_out_in_range"),
        "Host discovery across an IPv4 range (ping and TCP port sweep), then a "
        "stealth-profile scan of every live host inside the range."),
    "fullportscan": (
        ("port_scan", "service_scripts"),
        "All 65,535 TCP ports with OS and version detection, then nmap service scripts for "
        "each open service; those script sets include brute-force and exploit checks."),
    "normal": (
        ("port_scan", "service_scripts", "web_probe", "vuln_templates", "injection_testing",
         "credential_bruteforce", "exploitation", "third_party_osint"),
        "Sn1per standard full scan (profile conf/default): default-port scan, nmap service "
        "scripts, web checks, nuclei, sqlmap and WPScan, automatic credential brute force on "
        "common services, Metasploit exploit modules, whois and web-archive lookups."),
    "web": (
        ("port_scan", "service_scripts", "web_probe", "vuln_templates", "injection_testing",
         "credential_bruteforce", "exploitation", "third_party_osint"),
        "The standard full scan with the port scan limited to TCP 80 and 443."),
    "port": (
        ("port_scan", "service_scripts", "web_probe", "vuln_templates", "injection_testing",
         "credential_bruteforce", "exploitation", "third_party_osint"),
        "The standard full scan with the port scan limited to one TCP port."),
    "vulnscan": (
        ("port_scan", "service_scripts", "vuln_templates", "scanner_integrations",
         "injection_testing", "credential_bruteforce", "exploitation"),
        "Vulnerability-focused profile (conf/vulnscan): reuses earlier port results when "
        "present, nmap service scripts, nuclei, Burp or ZAP active scans when configured, "
        "sqlmap, WPScan, credential brute force and Metasploit exploit modules."),
    "full_scan": (
        ("port_scan", "service_scripts", "web_probe", "vuln_templates", "injection_testing",
         "credential_bruteforce", "exploitation", "third_party_osint"),
        "Most aggressive profile (conf/full_scan): everything in normal plus Nikto, "
        "Metasploit import and credential brute force on every supported service."),
}
PINNED_TEXT_9 = {
    "stealth": (
        ("port_scan", "web_probe", "content_discovery", "third_party_osint"),
        "Lightest CE scan: light port scan, HTTP fingerprinting (whatweb, WAF detection, "
        "TLS), small-wordlist content discovery, screenshots and web-archive lookups. No "
        "brute force or exploitation."),
    "discover": (
        ("host_discovery", "fan_out_in_range"),
        "Host discovery across an IPv4 range (ping, TCP and UDP sweeps), then a light flyover"
        " scan (ports, web fingerprint, screenshots) of every live host inside the range."),
    "fullportonly": (
        ("port_scan", "vuln_templates"),
        "Port scan only: all TCP ports plus selected UDP ports with version detection and the"
        " vulners script. No web checks."),
    "vulnscan": (
        ("scanner_integrations", "vuln_templates"),
        "Runs the vulnerability-scanner integrations enabled in Sn1per's config (Nessus, "
        "OpenVAS; both off by default) and Sn1per's sc0pe checks. Little is scanned unless "
        "one of them is configured."),
    "normal": (
        ("port_scan", "service_scripts", "web_probe", "content_discovery", "vuln_templates",
         "credential_bruteforce", "exploitation", "third_party_osint"),
        "CE standard full scan: default-port scan, nmap service scripts including brute-force"
        " scripts, web content discovery, nuclei, Metasploit modules for detected services, "
        "whois and web-archive lookups."),
    "web": (
        ("port_scan", "service_scripts", "web_probe", "content_discovery", "vuln_templates",
         "credential_bruteforce", "exploitation", "third_party_osint"),
        "The CE standard scan limited to TCP 80 and 443; web checks include the http-brute "
        "script."),
    "port": (
        ("port_scan", "service_scripts", "web_probe", "content_discovery", "vuln_templates",
         "credential_bruteforce", "exploitation", "third_party_osint"),
        "The CE standard scan limited to one TCP port."),
    "webporthttp": (
        ("service_scripts", "web_probe", "content_discovery", "vuln_templates",
         "credential_bruteforce"),
        "Web checks against one HTTP port: nmap HTTP scripts including http-brute, content "
        "discovery, nuclei; Metasploit web modules only if enabled in sniper.conf."),
    "webporthttps": (
        ("service_scripts", "web_probe", "content_discovery", "vuln_templates",
         "credential_bruteforce"),
        "Same as webporthttp over HTTPS."),
    "webscan": (
        ("injection_testing", "vuln_templates"),
        "DAST active scanning of HTTP and HTTPS (Arachni, OWASP ZAP, Burp when configured) "
        "plus nuclei. Sends attack payloads."),
}


@pytest.mark.parametrize(("dialect", "golden"), [("11.x", GOLDEN_11), ("9.x", GOLDEN_9)])
def test_tables_are_pinned(dialect, golden):
    table = modes.table(dialect)
    assert [m.name for m in table] == list(golden)
    for mode in table:
        assert (mode.mode_class, mode.requires_port, mode.target_types, mode.probes) \
            == golden[mode.name], mode.name
        assert set(mode.flags) <= set(modes.FLAGS)
        assert mode.description and "\u2014" not in mode.description


@pytest.mark.parametrize(("dialect", "pinned"),
                         [("11.x", PINNED_TEXT_11), ("9.x", PINNED_TEXT_9)])
def test_flags_and_descriptions_are_pinned(dialect, pinned):
    """Flags and descriptions match the D.2/D.3 tables exactly (drift caught pre-P0-15)."""
    table = modes.table(dialect)
    assert [m.name for m in table] == list(pinned)
    for mode in table:
        assert (mode.flags, mode.description) == pinned[mode.name], mode.name


@pytest.mark.parametrize("dialect", ["11.x", "9.x"])
def test_intrusive_iff_intrusive_flags(dialect):
    for mode in modes.table(dialect):
        assert mode.intrusive == bool(modes.INTRUSIVE_FLAGS & set(mode.flags)), mode.name


@pytest.mark.parametrize(("dialect", "excluded"), [("11.x", EXCLUDED_11), ("9.x", EXCLUDED_9)])
def test_excluded_modes_are_invalid_mode(dialect, excluded):
    present = {m.name: True for m in modes.table(dialect)}
    for name in excluded:
        with pytest.raises(modes.ModeError) as caught:
            modes.check_mode(dialect, name, allow_intrusive=True, present=present)
        assert caught.value.code == "invalid_mode", name
        assert name not in caught.value.details["available_modes"]


def test_enum_per_dialect_and_gate():
    all_11 = {m.name: True for m in modes.MODES_11}
    all_9 = {m.name: True for m in modes.MODES_9}
    assert modes.enum_names("11.x", all_11, False) == ["stealth", "recon_passive", "discover"]
    assert modes.enum_names("11.x", all_11, True) == list(GOLDEN_11)
    assert modes.enum_names("9.x", all_9, False) == ["stealth", "discover", "fullportonly",
                                                    "vulnscan"]
    assert modes.enum_names("9.x", all_9, True) == list(GOLDEN_9)
    # Files missing on disk are not offered.
    assert modes.enum_names("11.x", {**all_11, "discover": False}, False) == [
        "stealth", "recon_passive"]
    # Unknown dialect: the union of both tables, still gated.
    union = modes.enum_names(None, None, False)
    assert union == ["stealth", "recon_passive", "discover", "fullportonly", "vulnscan"]
    assert set(modes.enum_names(None, None, True)) == set(GOLDEN_11) | set(GOLDEN_9)


def test_schema_default_only_inside_the_enum():
    assert modes.schema_default(["stealth", "discover"]) == "stealth"
    assert modes.schema_default(["recon_passive", "discover"]) is None


def test_gate_and_missing_files():
    present = {m.name: True for m in modes.MODES_11}
    with pytest.raises(modes.ModeError) as caught:
        modes.check_mode("11.x", "normal", allow_intrusive=False, present=present)
    assert caught.value.code == "mode_not_allowed"
    with pytest.raises(modes.ModeError) as caught:
        modes.check_mode("11.x", "normal", allow_intrusive=True,
                         present={**present, "normal": False})
    assert caught.value.code == "engine_file_missing"


def _t(value: str) -> targets.Target:
    return targets.normalize_target(value, cidr_cap=16)


@pytest.mark.parametrize(("mode", "target", "code"), [
    ("discover", "app.example", "target_type_not_supported_for_mode"),
    ("recon_passive", "192.0.2.10", "target_type_not_supported_for_mode"),
    ("recon_passive", "192.0.2.0/24", "target_type_not_supported_for_mode"),
    ("stealth", "192.0.2.0/24", "target_type_not_supported_for_mode"),
    ("normal", "192.0.2.0/24", "target_type_not_supported_for_mode"),
    ("discover", "192.0.2.10", None),
    ("discover", "192.0.2.0/24", None),
    ("recon_passive", "app.example", None),
    ("stealth", "http://192.0.2.10/", None),
])
def test_d6_target_types(mode, target, code):
    row = modes.get("11.x", mode)
    if code is None:
        modes.check_target_type(row, _t(target))
        return
    with pytest.raises(modes.ModeError) as caught:
        modes.check_target_type(row, _t(target))
    assert caught.value.code == code


@pytest.mark.parametrize(("dialect", "mode", "target", "port", "result"), [
    ("11.x", "port", "app.example", 8443, 8443),
    ("11.x", "port", "app.example", None, "port_required"),
    ("11.x", "port", "https://app.example/", None, 443),
    ("11.x", "port", "http://app.example/", None, 80),
    ("11.x", "port", "http://app.example:8080/", None, 8080),
    ("11.x", "port", "http://app.example:8080/", 8080, 8080),
    ("11.x", "port", "http://app.example:8080/", 9090, "invalid_argument"),
    ("11.x", "stealth", "app.example", 8443, "port_not_supported_for_mode"),
    ("11.x", "stealth", "https://app.example:443/", None, None),
    ("11.x", "stealth", "https://app.example:8443/", None, "port_not_supported_for_mode"),
    ("9.x", "webporthttps", "app.example", None, "port_required"),
    ("9.x", "webporthttp", "http://app.example/", None, 80),
    ("11.x", "port", "app.example", 0, "invalid_argument"),
    ("11.x", "port", "app.example", 65536, "invalid_argument"),
    ("11.x", "port", "app.example", True, "invalid_argument"),
])
def test_ports(dialect, mode, target, port, result):
    row = modes.get(dialect, mode)
    if isinstance(result, str):
        with pytest.raises(modes.ModeError) as caught:
            modes.resolve_port(row, _t(target), port)
        assert caught.value.code == result
    else:
        assert modes.resolve_port(row, _t(target), port) == result


def test_build_argv_examples_of_d5():
    sudo = ["/usr/bin/sudo", "-n", "--"]
    cli = "/opt/fake-sn1per/sniper"
    assert modes.build_argv(sudo, cli, "app.example", modes.get("11.x", "stealth"),
                            "app.example", None) == [
        *sudo, cli, "-t", "app.example", "-m", "stealth", "-w", "app.example"]
    assert modes.build_argv(sudo, cli, "www.app.example", modes.get("11.x", "port"),
                            "acme-2026q4", 8443) == [
        *sudo, cli, "-t", "www.app.example", "-m", "port", "-w", "acme-2026q4", "-p", "8443"]
    assert modes.build_argv([], cli, "192.0.2.0/24", modes.get("11.x", "discover"),
                            "192.0.2.0-24", None) == [
        cli, "-t", "192.0.2.0/24", "-m", "discover", "-w", "192.0.2.0-24"]


@pytest.mark.parametrize(("target", "workspace", "port", "mode"), [
    ("-c/etc/x", "w", None, "stealth"), ("app.example", "-d", None, "stealth"),
    ("app.example", "w", 8443, "stealth"), ("app.example", "w", None, "port"),
    ("app.example", "w", 0, "port"), ("a b", "w", None, "stealth"),
    ("app.example", "../w", None, "stealth"),
])
def test_build_argv_refuses_unsafe_inputs(target, workspace, port, mode):
    with pytest.raises(ValueError):
        modes.build_argv([], "/opt/fake-sn1per/sniper", target, modes.get("11.x", mode),
                         workspace, port)
    with pytest.raises(ValueError):
        modes.build_argv([], "relative/sniper", "app.example", modes.get("11.x", "stealth"),
                         "w", None)


# --- dispatch through the stubs ------------------------------------------------------

SCOPE = "app.scan.test,192.0.2.10,192.0.2.0/24"


@pytest.fixture(autouse=True)
def _fresh_jobs(iso):
    status.clear_sudo_cache()
    # Strict DNS policy (F.5): the scope has IP entries, so the name must resolve into them.
    iso.resolve("app.scan.test", "192.0.2.10", public=False)
    yield
    jobs.terminate_all()
    jobs.JOBS.clear()


def _dispatch_cases():
    cases = []
    for install, golden in (("se-11.0", GOLDEN_11), ("ce-9.2", GOLDEN_9)):
        for name, (_cls, requires_port, types, _probes) in golden.items():
            if "hostname" in types:
                target = "app.scan.test"
            elif name == "discover":
                target = "192.0.2.0/24"
            else:
                target = "192.0.2.10"
            cases.append((install, name, target, 8443 if requires_port else None))
    return cases


@pytest.mark.parametrize(("install", "mode", "target", "port"), _dispatch_cases(),
                         ids=lambda v: str(v))
async def test_golden_argv_for_every_mode_through_the_stubs(iso, monkeypatch, install, mode,
                                                            target, port):
    # Production spawns in "/" (D.5). Layer 1 resolves relative argv words against the
    # spawn directory, and a host may have a directory named like a mode (for example
    # "/web"); spawning inside the temp root keeps this test independent of the host.
    monkeypatch.setattr(paths, "SPAWN_CWD", str(iso.tmp))
    iso.use_install(install)
    iso.setenv(SNIPER_MCP_SCOPE=SCOPE, SNIPER_MCP_ALLOW_INTRUSIVE="1")
    arguments = {"target": target, "mode": mode, "workspace": "acme-2026q4"}
    if port is not None:
        arguments["port"] = port
    payload, is_error = await support.call("sniper_scan", arguments)
    assert not is_error, payload
    jobs.JOBS[payload["job_id"]].process.wait(timeout=30)
    cli = str(iso.cli_path)
    expected = [cli, "-t", target, "-m", mode, "-w", "acme-2026q4"]
    if port is not None:
        expected += ["-p", str(port)]
    assert iso.calls("sniper") == [expected]
    assert iso.calls("sudo")[-1] == [str(iso.sudo_path), "-n", "--", *expected]
    for argv in iso.calls():
        assert not {"-c", "-f", "-o", "-d", "--export", "-u", "-dt", "-fp", "-s"} & set(argv)
    golden = GOLDEN_11 if install == "se-11.0" else GOLDEN_9
    assert payload["mode_class"] == golden[mode][0]
    assert payload["port"] == port
    assert payload["dialect"] == ("11.x" if install == "se-11.0" else "9.x")


async def test_intrusive_modes_absent_from_the_schema_without_the_gate(iso):
    async with support.session() as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
        result = await client.call_tool("sniper_scan", {"target": "app.scan.test",
                                                        "mode": "normal"})
    schema = tools["sniper_scan"].inputSchema
    mode_schema = schema["properties"]["mode"]
    assert mode_schema["enum"] == ["stealth", "recon_passive", "discover"]
    assert mode_schema["default"] == "stealth"
    assert result.isError and iso.calls() == []


async def test_gate_on_offers_every_mode_of_the_dialect(iso):
    iso.use_install("ce-9.2")
    iso.setenv(SNIPER_MCP_ALLOW_INTRUSIVE="true")
    async with support.session() as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    assert tools["sniper_scan"].inputSchema["properties"]["mode"]["enum"] == list(GOLDEN_9)


async def test_without_stealth_on_disk_mode_is_required_and_has_no_default(iso):
    (iso.install_dir / "conf" / "flyover").unlink()
    async with support.session() as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
        missing = await client.call_tool("sniper_scan", {"target": "app.scan.test"})
    schema = tools["sniper_scan"].inputSchema
    assert schema["properties"]["mode"]["enum"] == ["recon_passive"]
    assert "default" not in schema["properties"]["mode"]
    assert "mode" in schema["required"]
    assert missing.isError and iso.calls() == []


async def test_engine_file_missing_at_run_time(iso):
    iso.setenv(SNIPER_MCP_SCOPE="app.scan.test")
    async with support.session() as client:
        (iso.install_dir / "conf" / "flyover").unlink()
        from sniper_mcp import edition

        edition.clear_cache()
        result = await client.call_tool("sniper_scan", {"target": "app.scan.test"})
    assert result.isError
    assert result.structuredContent["error"]["code"] == "engine_file_missing"
    assert iso.calls() == []


@pytest.mark.parametrize(("mode", "target", "port", "code"), [
    ("discover", "app.scan.test", None, "target_type_not_supported_for_mode"),
    ("stealth", "192.0.2.0/24", None, "target_type_not_supported_for_mode"),
    ("recon_passive", "192.0.2.10", None, "target_type_not_supported_for_mode"),
    ("port", "app.scan.test", None, "port_required"),
    ("stealth", "app.scan.test", 8443, "port_not_supported_for_mode"),
    ("stealth", "https://app.scan.test:8443/", None, "port_not_supported_for_mode"),
    ("port", "http://app.scan.test:8080/", 9090, "invalid_argument"),
])
async def test_compatibility_refusals_spawn_nothing(iso, mode, target, port, code):
    iso.setenv(SNIPER_MCP_SCOPE=SCOPE, SNIPER_MCP_ALLOW_INTRUSIVE="1")
    arguments = {"target": target, "mode": mode}
    if port is not None:
        arguments["port"] = port
    payload, is_error = await support.call("sniper_scan", arguments)
    assert is_error and payload["error"]["code"] == code, payload
    assert iso.calls() == []


@pytest.mark.parametrize("port", [0, 65536, -1])
async def test_port_bounds_in_the_schema(iso, port):
    iso.setenv(SNIPER_MCP_SCOPE=SCOPE, SNIPER_MCP_ALLOW_INTRUSIVE="1")
    async with support.session() as client:
        result = await client.call_tool("sniper_scan", {"target": "app.scan.test",
                                                        "mode": "port", "port": port})
    assert result.isError and result.structuredContent is None
    assert iso.calls() == []


async def test_url_default_port_feeds_a_port_mode(iso):
    iso.setenv(SNIPER_MCP_SCOPE=SCOPE, SNIPER_MCP_ALLOW_INTRUSIVE="1")
    payload, is_error = await support.call("sniper_scan", {"target": "https://app.scan.test/",
                                                           "mode": "port"})
    assert not is_error, payload
    jobs.JOBS[payload["job_id"]].process.wait(timeout=30)
    assert iso.calls("sniper")[-1] == [str(iso.cli_path), "-t", "app.scan.test", "-m", "port",
                                       "-w", "app.scan.test", "-p", "443"]


@pytest.mark.parametrize(("mode", "target", "warned"), [
    ("discover", "192.0.2.0/24", True), ("recon_passive", "app.scan.test", True),
    ("stealth", "app.scan.test", False),
])
async def test_follow_up_targets_warning(iso, mode, target, warned):
    iso.setenv(SNIPER_MCP_SCOPE=SCOPE)
    payload, is_error = await support.call("sniper_scan", {"target": target, "mode": mode})
    assert not is_error, payload
    jobs.JOBS[payload["job_id"]].process.wait(timeout=30)
    codes = [w["code"] for w in payload["warnings"]]
    assert ("follow_up_targets_unchecked" in codes) == warned


async def test_pro_workspace_limit_warning_only_for_a_new_workspace(iso):
    iso.use_install("pro")
    iso.setenv(SNIPER_MCP_SCOPE=SCOPE)
    payload, _ = await support.call("sniper_scan", {"target": "app.scan.test",
                                                    "workspace": "new-ws"})
    jobs.JOBS[payload["job_id"]].process.wait(timeout=30)
    assert payload["edition"] == "pro" and payload["workspace_created"] is True
    assert [w["code"] for w in payload["warnings"]] == ["pro_workspace_limit"]
    iso.make_workspace("old-ws")
    payload, _ = await support.call("sniper_scan", {"target": "app.scan.test",
                                                    "workspace": "old-ws"})
    jobs.JOBS[payload["job_id"]].process.wait(timeout=30)
    assert payload["workspace_created"] is False and payload["warnings"] == []


# --- invalid_mode and mode_not_allowed through the tool (F.9 step 4, P0-06) ------------------
# The schema enum is built at startup (D.1), so these codes reach a client only when the
# engine on disk changes after startup, or when detection failed at startup and the enum
# is the union of both tables.

def _audited_refusals(iso) -> list[tuple[str, str]]:
    import json

    lines = [json.loads(line) for line in iso.audit_log.read_text().splitlines() if line]
    return [(r["decision"], r["reason_code"]) for r in lines if r["event"] == "scan_request"]


async def test_mode_of_the_other_dialect_is_invalid_mode(iso):
    iso.setenv(SNIPER_MCP_SCOPE=SCOPE)
    async with support.session() as client:
        iso.use_install("ce-9.2")  # the engine changed after startup
        result = await client.call_tool("sniper_scan", {"target": "app.scan.test",
                                                        "mode": "recon_passive"})
    error = result.structuredContent["error"]
    assert result.isError and error["code"] == "invalid_mode"
    assert error["retry"] == "after_change"
    assert error["details"]["available_modes"] == ["stealth", "discover", "fullportonly",
                                                   "vulnscan"]
    assert iso.calls() == []
    assert _audited_refusals(iso) == [("refused", "invalid_mode")]


async def test_union_enum_when_detection_fails_at_startup(iso):
    iso.cli_link.unlink()
    iso.cli_path.unlink()
    iso.setenv(SNIPER_MCP_SCOPE=SCOPE, SNIPER_MCP_ALLOW_INTRUSIVE="1")
    async with support.session() as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
        enum = tools["sniper_scan"].inputSchema["properties"]["mode"]["enum"]
        assert set(enum) == set(GOLDEN_11) | set(GOLDEN_9)
        refused = await client.call_tool("sniper_scan", {"target": "app.scan.test"})
        assert refused.structuredContent["error"]["code"] == "cli_not_found"
        iso.use_install("se-11.0")
        # webscan is a CE mode; in 11.x it is deliberately excluded (D.4).
        result = await client.call_tool("sniper_scan", {"target": "app.scan.test",
                                                        "mode": "webscan"})
    error = result.structuredContent["error"]
    assert error["code"] == "invalid_mode"
    assert "webscan" not in error["details"]["available_modes"]
    assert iso.calls() == []


async def test_intrusive_mode_of_the_new_dialect_is_mode_not_allowed(iso):
    iso.use_install("ce-9.2")
    iso.setenv(SNIPER_MCP_SCOPE=SCOPE)
    async with support.session() as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
        # vulnscan is active in CE 9.x and is offered with the gate off ...
        assert "vulnscan" in tools["sniper_scan"].inputSchema["properties"]["mode"]["enum"]
        iso.use_install("se-11.0")
        # ... but intrusive in 11.x, so the gate refuses it at run time.
        result = await client.call_tool("sniper_scan", {"target": "app.scan.test",
                                                        "mode": "vulnscan"})
    error = result.structuredContent["error"]
    assert result.isError and error["code"] == "mode_not_allowed"
    assert error["retry"] == "never"
    assert "SNIPER_MCP_ALLOW_INTRUSIVE" in error["hint"]
    assert iso.calls() == []
    assert _audited_refusals(iso) == [("refused", "mode_not_allowed")]
