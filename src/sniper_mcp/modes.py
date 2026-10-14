# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Static scan-mode tables per engine dialect, the mode enum and the argv (contract D).

The tables are versioned with the contract and selected by the detected
dialect; they are never derived from the engine's file names (D.1). The argv
only ever uses ``-t``, ``-m``, ``-w`` and, for port modes, ``-p`` (D.5).
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from sniper_mcp import targets

DIALECT_9 = "9.x"
DIALECT_11 = "11.x"
DIALECTS = (DIALECT_11, DIALECT_9)
DEFAULT_MODE = "stealth"

ACTIVE = "active"
INTRUSIVE = "intrusive"

# D.1 flags vocabulary; a mode is intrusive iff its flags include an INTRUSIVE_FLAGS item.
FLAGS = (
    "port_scan", "service_scripts", "web_probe", "content_discovery", "vuln_templates",
    "subdomain_enum", "third_party_osint", "host_discovery", "fan_out_in_range",
    "scanner_integrations", "credential_bruteforce", "exploitation", "injection_testing",
)
INTRUSIVE_FLAGS = frozenset({"service_scripts", "credential_bruteforce", "exploitation",
                             "injection_testing"})
# Modes with these flags make the engine reach hosts the scope guard never sees (D.7).
FOLLOW_UP_FLAGS = frozenset({"subdomain_enum", "fan_out_in_range"})

HOST_TYPES = (targets.HOSTNAME, targets.IPV4)
RANGE_TYPES = (targets.IPV4, targets.IPV4_CIDR)

# Every 11.x mode except discover runs modes/normal.sh (D.2, C.2 step 10).
_NORMAL_11 = "modes/normal.sh"
# Only these argv options are ever passed to the engine (D.1).
ALLOWED_OPTIONS = frozenset({"-t", "-m", "-w", "-p"})


@dataclass(frozen=True)
class Mode:
    """One row of a D.2 or D.3 table."""

    name: str
    mode_class: str
    flags: tuple[str, ...]
    target_types: tuple[str, ...]
    requires_port: bool
    probes: tuple[str, ...]  # engine files relative to the install dir (C.2 step 10)
    description: str

    @property
    def intrusive(self) -> bool:
        return self.mode_class == INTRUSIVE


_NORMAL_11_FLAGS = ("port_scan", "service_scripts", "web_probe", "vuln_templates",
                    "injection_testing", "credential_bruteforce", "exploitation",
                    "third_party_osint")

# D.2: dialect 11.x (Sn1per SE 11.x, Professional 2026, Enterprise).
MODES_11: tuple[Mode, ...] = (
    Mode("stealth", ACTIVE, ("port_scan", "web_probe", "vuln_templates", "third_party_osint"),
         HOST_TYPES, False, ("conf/flyover", _NORMAL_11),
         "Lightest scan (profile conf/flyover): default-port nmap scan without service "
         "scripts, HTTP probing, crawling, screenshots, TLS and nuclei technology, takeover "
         "and static checks. No brute force or exploitation."),
    Mode("recon_passive", ACTIVE, ("subdomain_enum", "third_party_osint", "web_probe",
                                   "vuln_templates", "port_scan"),
         (targets.HOSTNAME,), False, ("conf/recon_passive", _NORMAL_11),
         "Subdomain and OSINT reconnaissance (profile conf/recon_passive): third-party OSINT "
         "APIs and DNS brute force, then HTTP probing, crawling and nuclei checks of "
         "discovered hosts. Not passive: it sends DNS and HTTP traffic and port-scans if no "
         "earlier results exist."),
    Mode("discover", ACTIVE, ("host_discovery", "port_scan", "fan_out_in_range"),
         RANGE_TYPES, False, ("modes/discover.sh", "conf/flyover", _NORMAL_11),
         "Host discovery across an IPv4 range (ping and TCP port sweep), then a "
         "stealth-profile scan of every live host inside the range."),
    Mode("fullportscan", INTRUSIVE, ("port_scan", "service_scripts"),
         HOST_TYPES, False, ("conf/fullportscan", _NORMAL_11),
         "All 65,535 TCP ports with OS and version detection, then nmap service scripts for "
         "each open service; those script sets include brute-force and exploit checks."),
    Mode("normal", INTRUSIVE, _NORMAL_11_FLAGS, HOST_TYPES, False,
         ("conf/default", _NORMAL_11),
         "Sn1per standard full scan (profile conf/default): default-port scan, nmap service "
         "scripts, web checks, nuclei, sqlmap and WPScan, automatic credential brute force on "
         "common services, Metasploit exploit modules, whois and web-archive lookups."),
    Mode("web", INTRUSIVE, _NORMAL_11_FLAGS, HOST_TYPES, False,
         ("conf/default", _NORMAL_11),
         "The standard full scan with the port scan limited to TCP 80 and 443."),
    Mode("port", INTRUSIVE, _NORMAL_11_FLAGS, HOST_TYPES, True,
         ("conf/default", _NORMAL_11),
         "The standard full scan with the port scan limited to one TCP port."),
    Mode("vulnscan", INTRUSIVE, ("port_scan", "service_scripts", "vuln_templates",
                                 "scanner_integrations", "injection_testing",
                                 "credential_bruteforce", "exploitation"),
         HOST_TYPES, False, ("conf/vulnscan", _NORMAL_11),
         "Vulnerability-focused profile (conf/vulnscan): reuses earlier port results when "
         "present, nmap service scripts, nuclei, Burp or ZAP active scans when configured, "
         "sqlmap, WPScan, credential brute force and Metasploit exploit modules."),
    Mode("full_scan", INTRUSIVE, _NORMAL_11_FLAGS, HOST_TYPES, False,
         ("conf/full_scan", _NORMAL_11),
         "Most aggressive profile (conf/full_scan): everything in normal plus Nikto, "
         "Metasploit import and credential brute force on every supported service."),
)

_NORMAL_9_FLAGS = ("port_scan", "service_scripts", "web_probe", "content_discovery",
                   "vuln_templates", "credential_bruteforce", "exploitation",
                   "third_party_osint")
_WEBPORT_9_FLAGS = ("service_scripts", "web_probe", "content_discovery", "vuln_templates",
                    "credential_bruteforce")

# D.3: dialect 9.x (Sn1per Community Edition 9.2).
MODES_9: tuple[Mode, ...] = (
    Mode("stealth", ACTIVE, ("port_scan", "web_probe", "content_discovery",
                             "third_party_osint"),
         HOST_TYPES, False, ("modes/stealth.sh",),
         "Lightest CE scan: light port scan, HTTP fingerprinting (whatweb, WAF detection, "
         "TLS), small-wordlist content discovery, screenshots and web-archive lookups. No "
         "brute force or exploitation."),
    Mode("discover", ACTIVE, ("host_discovery", "fan_out_in_range"),
         RANGE_TYPES, False, ("modes/discover.sh", "modes/flyover.sh"),
         "Host discovery across an IPv4 range (ping, TCP and UDP sweeps), then a light "
         "flyover scan (ports, web fingerprint, screenshots) of every live host inside the "
         "range."),
    Mode("fullportonly", ACTIVE, ("port_scan", "vuln_templates"),
         HOST_TYPES, False, ("modes/fullportonly.sh",),
         "Port scan only: all TCP ports plus selected UDP ports with version detection and "
         "the vulners script. No web checks."),
    Mode("vulnscan", ACTIVE, ("scanner_integrations", "vuln_templates"),
         HOST_TYPES, False, ("modes/vulnscan.sh",),
         "Runs the vulnerability-scanner integrations enabled in Sn1per's config (Nessus, "
         "OpenVAS; both off by default) and Sn1per's sc0pe checks. Little is scanned unless "
         "one of them is configured."),
    Mode("normal", INTRUSIVE, _NORMAL_9_FLAGS, HOST_TYPES, False, ("modes/normal.sh",),
         "CE standard full scan: default-port scan, nmap service scripts including "
         "brute-force scripts, web content discovery, nuclei, Metasploit modules for detected "
         "services, whois and web-archive lookups."),
    Mode("web", INTRUSIVE, _NORMAL_9_FLAGS, HOST_TYPES, False, ("modes/web.sh",),
         "The CE standard scan limited to TCP 80 and 443; web checks include the http-brute "
         "script."),
    Mode("port", INTRUSIVE, _NORMAL_9_FLAGS, HOST_TYPES, True, ("modes/normal.sh",),
         "The CE standard scan limited to one TCP port."),
    Mode("webporthttp", INTRUSIVE, _WEBPORT_9_FLAGS, HOST_TYPES, True,
         ("modes/webporthttp.sh",),
         "Web checks against one HTTP port: nmap HTTP scripts including http-brute, content "
         "discovery, nuclei; Metasploit web modules only if enabled in sniper.conf."),
    Mode("webporthttps", INTRUSIVE, _WEBPORT_9_FLAGS, HOST_TYPES, True,
         ("modes/webporthttps.sh",),
         "Same as webporthttp over HTTPS."),
    Mode("webscan", INTRUSIVE, ("injection_testing", "vuln_templates"),
         HOST_TYPES, False, ("modes/webscan.sh",),
         "DAST active scanning of HTTP and HTTPS (Arachni, OWASP ZAP, Burp when configured) "
         "plus nuclei. Sends attack payloads."),
)

TABLES: Mapping[str, tuple[Mode, ...]] = {DIALECT_11: MODES_11, DIALECT_9: MODES_9}


class ModeError(ValueError):
    """A mode, target type or port is refused (H.2 code in ``code``)."""

    def __init__(self, code: str, message: str, hint: str,
                 details: dict[str, object] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.hint = hint
        self.details = dict(details or {})


def table(dialect: str) -> tuple[Mode, ...]:
    return TABLES[dialect]


def get(dialect: str, name: str) -> Mode | None:
    for mode in TABLES.get(dialect, ()):
        if mode.name == name:
            return mode
    return None


def probe(dialect: str, install_dir: str) -> dict[str, bool]:
    """C.2 step 10: whether every engine file of each mode exists (never executed)."""
    modes_dir = os.path.join(install_dir, "modes")
    has_modes_dir = os.path.isdir(modes_dir)
    present: dict[str, bool] = {}
    for mode in TABLES[dialect]:
        present[mode.name] = has_modes_dir and all(
            os.path.isfile(os.path.join(install_dir, rel)) for rel in mode.probes)
    return present


def mode_allowed(mode: Mode, allow_intrusive: bool) -> bool:
    """D.1 intrusive gate."""
    return allow_intrusive or not mode.intrusive


def enum_names(dialect: str | None, present: Mapping[str, bool] | None,
               allow_intrusive: bool) -> list[str]:
    """The ``mode`` enum of ``sniper_scan`` (D.1).

    Known dialect: table modes present on disk and allowed by the gate. Unknown
    dialect: the union of both tables (introspection only; runtime validation
    refuses), with the gate still applied to every entry.
    """
    if dialect is None:
        names: list[str] = []
        for candidate in DIALECTS:
            for mode in TABLES[candidate]:
                if mode_allowed(mode, allow_intrusive) and mode.name not in names:
                    names.append(mode.name)
        return names
    present = present or {}
    return [m.name for m in TABLES[dialect]
            if mode_allowed(m, allow_intrusive) and present.get(m.name, False)]


def schema_default(names: Sequence[str]) -> str | None:
    """``stealth`` when it is in the enum, else no default (``mode`` becomes required)."""
    return DEFAULT_MODE if DEFAULT_MODE in names else None


def check_mode(dialect: str, name: str, *, allow_intrusive: bool,
               present: Mapping[str, bool]) -> Mode:
    """F.9 step 4: dialect table, intrusive gate, engine file present."""
    mode = get(dialect, name)
    if mode is None:
        available = enum_names(dialect, present, allow_intrusive)
        raise ModeError("invalid_mode", f"Mode {name} is not a scan mode of the {dialect} "
                        "engine on this host.", "Use a mode listed by sniper_status.",
                        {"available_modes": available})
    if not mode_allowed(mode, allow_intrusive):
        raise ModeError("mode_not_allowed", f"Mode {name} runs brute force, exploitation or "
                        "injection testing and is disabled on this server.",
                        "Only the operator can enable intrusive modes "
                        "(SNIPER_MCP_ALLOW_INTRUSIVE=1). Use an active mode such as stealth.")
    if not present.get(name, False):
        raise ModeError("engine_file_missing", f"The engine files of mode {name} are missing "
                        "on this host.", "Use another mode listed by sniper_status, or "
                        "repair the Sn1per installation.",
                        {"engine_files": list(mode.probes)})
    return mode


def resolve_port(mode: Mode, target: targets.Target, port: int | None) -> int | None:
    """D.6 and the URL port rules of E.1 step 3; returns the port for argv, or None."""
    if port is not None and (isinstance(port, bool) or not isinstance(port, int)
                             or not 1 <= port <= 65535):
        raise ModeError("invalid_argument", "port must be an integer from 1 to 65535.",
                        "Pass a TCP port number.")
    url_port = target.url_port
    if port is not None and url_port is not None and port != url_port:
        raise ModeError("invalid_argument", f"The URL port {url_port} and the port parameter "
                        f"{port} differ.", "Pass the port once.")
    if mode.requires_port:
        if port is not None:
            return port
        if url_port is not None:
            return url_port
        if target.url_default_port is not None:
            return target.url_default_port
        raise ModeError("port_required", f"Mode {mode.name} needs a TCP port.",
                        "Pass the port parameter.")
    if port is not None:
        raise ModeError("port_not_supported_for_mode", f"Mode {mode.name} takes no port.",
                        "Omit the port parameter, or use a mode that sniper_status lists with "
                        "requires_port=true.")
    if url_port is not None and url_port != target.url_default_port:
        raise ModeError("port_not_supported_for_mode", f"Mode {mode.name} takes no port, but "
                        f"the URL names port {url_port}.",
                        "Pass the URL without the port, or use a mode that sniper_status "
                        "lists with requires_port=true.")
    return None


def check_target_type(mode: Mode, target: targets.Target) -> None:
    """D.6: the target type must be one the mode accepts."""
    if target.target_type not in mode.target_types:
        if target.target_type == targets.IPV4_CIDR:
            hint = "Ranges need mode discover; pass one host for other modes."
        elif mode.name == "discover":
            hint = "Mode discover takes an IPv4 address or IPv4 range."
        else:
            hint = f"Mode {mode.name} takes: {', '.join(mode.target_types)}."
        raise ModeError("target_type_not_supported_for_mode",
                        f"Mode {mode.name} does not take a {target.target_type} target.", hint,
                        {"target_type": target.target_type,
                         "accepted": list(mode.target_types)})


def follow_up_targets(mode: Mode) -> bool:
    """D.7: the engine may reach hosts beyond the requested target."""
    return bool(FOLLOW_UP_FLAGS.intersection(mode.flags))


def build_argv(sudo_prefix: Sequence[str], cli_realpath: str, target: str, mode: Mode,
               workspace: str, port: int | None) -> list[str]:
    """D.5 argv. Re-checks its inputs so a caller bug can never inject an option."""
    if not os.path.isabs(cli_realpath):
        raise ValueError("the CLI path must be absolute")
    if not target or target.startswith("-") or any(ch.isspace() for ch in target):
        raise ValueError("refusing an unsafe target in argv")
    if not targets.is_valid_workspace(workspace):
        raise ValueError("refusing an unsafe workspace in argv")
    argv = [*sudo_prefix, cli_realpath, "-t", target, "-m", mode.name, "-w", workspace]
    if mode.requires_port:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("a port mode needs a port from 1 to 65535")
        argv += ["-p", str(port)]
    elif port is not None:
        raise ValueError("this mode takes no port")
    return argv


def status_entry(mode: Mode) -> dict[str, object]:
    """One ``modes.available`` item of ``sniper_status`` (H.5)."""
    return {"name": mode.name, "class": mode.mode_class, "flags": list(mode.flags),
            "requires_port": mode.requires_port, "target_types": list(mode.target_types),
            "description": mode.description}


def unavailable_entry(mode: Mode, reason_code: str) -> dict[str, object]:
    """One ``modes.unavailable`` item of ``sniper_status`` (H.5)."""
    if reason_code == "mode_not_allowed":
        reason = ("Intrusive modes are disabled. The operator can enable them with "
                  "SNIPER_MCP_ALLOW_INTRUSIVE=1.")
    else:
        reason = ("The engine files of this mode are missing on this host: "
                  + ", ".join(mode.probes) + ".")
    return {"name": mode.name, "class": mode.mode_class, "reason_code": reason_code,
            "reason": reason}


def all_names(dialects: Iterable[str] = DIALECTS) -> list[str]:
    names: list[str] = []
    for dialect in dialects:
        for mode in TABLES[dialect]:
            if mode.name not in names:
                names.append(mode.name)
    return names
