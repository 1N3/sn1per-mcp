# Sn1per editions

The Sn1per MCP Server supports Sn1per Community Edition 9.x and the 11.x engine used by Sn1per SE, Sn1per Professional and Sn1per Enterprise; the [edition matrix](#edition-matrix) lists what has been verified. This page explains how the server detects the edition, which editions have been verified, which scan modes each engine offers, and what is specific to each edition.

## How detection works

At startup, and again (cached for 30 seconds) whenever `sniper_status`, `sniper_scan`, `delete_workspace` or `--check` runs, the server reads, but never runs, the Sn1per CLI:

1. **Find the CLI:** `SNIPER_BIN` if set, else `sniper` on the server's `PATH`, else `/usr/share/sniper/sniper`. The server uses the realpath of that file, which must be owned by root; otherwise scans and deletes are refused with `cli_untrusted` (fix: `sudo chown root:root <realpath>`). The read tools keep working.
2. **Read the header** (at most 64 KiB): the `VER=` line gives the engine version and the `INSTALL_DIR=` line the install directory. An `INSTALL_DIR=` value that is not a plain absolute path is ignored with the warning `install_dir_marker_invalid`. The `INSTALL_DIR=` value is used, and shown in `sniper_status`, only when root chose the CLI file: the file and every directory above it are owned by root and not writable by group or others. Otherwise it is ignored with the warning `install_dir_marker_untrusted`, and the install directory is `SNIPER_INSTALL_DIR` or `/usr/share/sniper`. Sn1per Community Edition makes its CLI world-writable on every scan, so this is expected there after the first scan.
3. **Engine dialect:** version 9 selects the Community Edition dialect (`9.x`); version 11 selects the SE, Professional and Enterprise dialect (`11.x`). 9.2 is the reference Community Edition version. 9.0 and 9.1 are not supported: the server still selects the `9.x` dialect for them, with the warning `engine_version_untested`. Any other version, or none, makes scanning unavailable (`edition_unsupported`) unless `SNIPER_EDITION` names a concrete edition (warning `dialect_from_override`).
4. **Edition label:** the `9.x` dialect is always `ce`. In the `11.x` dialect, the server looks for the text `Sn1per Enterprise` in `<install dir>/pro/index.php` (label `enterprise`), then for `<install dir>/pro/api/license.php` (label `pro`), and otherwise uses `se`.
5. **Changelog version:** the first version heading of `<install dir>/CHANGELOG.md`, for example `11.3 [Unreleased]`. Sn1per 11.0, 11.1 and the 11.3 development build all print `VER="11.0"`, so the changelog version is the better identifier for bug reports.
6. **Checks:** every mode's engine file must exist (otherwise that mode is unavailable, `engine_file_missing`); Sn1per must be reachable as `sniper` on root's `PATH` (it calls itself by that name while it scans; otherwise scans are refused with `engine_path_missing`); permission problems are reported as the warning `install_world_writable` (see the per-edition notes); and when the kernel's hard-link protection (`fs.protected_hardlinks`) is off, the warning `protected_hardlinks_off` is added.

`sniper_status` reports the result in its `edition` object (label, display name, `detected` or `override`, dialect, engine version, changelog version and the markers found) and its `paths` object.

### Override

`SNIPER_EDITION` accepts `auto` (default), `ce`, `community` (same as `ce`), `se`, `pro` and `enterprise`. A concrete value sets the label. The dialect still comes from the engine version when it can be read; if the override implies a different dialect, the detected dialect is kept and `sniper_status` shows the warning `edition_override_conflict`. Set the override only when the CLI is a wrapper that the detection cannot read.

### Changing the edition or the CLI path

If you change the edition (for example from Sn1per Community Edition to Sn1per Professional) or the CLI moves:

1. Run `sn1per-mcp --env-file <env file> --check` and note the new CLI realpath.
2. Update the sudoers rule in `/etc/sudoers.d/sn1per-mcp` with that realpath ([install.md](install.md#privilege-setup)).
3. Restart your client session. The server reads its configuration and the mode list at startup.

## Edition matrix

"Verified" means exercised by the 0.9.0 verification run on 2026-10-12, on the engine shown. "Expected" means no known blocker, but not exercised. "Not supported" means it does not work or is not offered.

| Edition | Engine that was run | Dialect | Status |
|---|---|---|---|
| Sn1per Community Edition 9.2 | repository `master` at `a5450bc` (2026-07-04), `VER="9.2"`, changelog 9.2; disposable Kali Rolling container, server running as root | 9.x | verified 2026-10-12, with the server running as root |
| Sn1per Community Edition 9.2 with the server running as a normal user through sudo | - | 9.x | expected |
| Later Sn1per Community Edition 9.x releases | - | 9.x | expected |
| Sn1per SE 11.0 | released 11.0 tree, `VER="11.0"`, changelog 11.0; disposable Kali Rolling container, server as root and as a normal user through sudo | 11.x | verified 2026-10-12 |
| Sn1per SE 11.1 | released 11.1 tree, `VER="11.0"`, changelog 11.1; same container, server as root | 11.x | verified 2026-10-12, as root |
| Sn1per Enterprise, 11.3 development build | `VER="11.0"`, changelog `11.3 [Unreleased]`; a live host, server as a normal user through sudo | 11.x | verified 2026-10-12, as a normal user |
| Other 11.x releases, including 11.2 | - | 11.x | expected |
| Sn1per Professional 2026 | - | 11.x | uses the same 11.x engine as SE and Enterprise; not yet run on a Professional install |
| Sn1per Community Edition below 9.2 | - | - | not supported |
| Sn1per Enterprise v10.x | - | - | not supported |

All three 11.x builds print `VER="11.0"`; `sniper_status` tells them apart by `edition.engine_changelog_version`, which was verified on all three.

### Per-tool results

Each cell is the status of that tool on that engine. Some defects were found by the verification run and fixed afterwards in 0.9.0; for those the cell says so, and the tool counts as expected until a run repeats it with the fix. Where a second run on 2026-10-12 repeated it, the cell says verified.

| Tool | Community Edition 9.2 (server as root) | SE 11.0 and 11.1 | Enterprise 11.3 development build (server as a normal user) | Professional 2026 |
|---|---|---|---|---|
| `sniper_status` | verified | verified | verified | expected |
| `list_workspaces` | verified | verified | verified | expected |
| `scan_status` | verified | verified | verified | expected |
| `get_findings` | verified | verified | verified | expected |
| `get_ports` | verified | verified | verified | expected |
| `get_subdomains` | verified for an IP target | expected (the test install produced no subdomain data) | verified | expected |
| `get_technologies` | verified (it returned nothing from Community Edition loot during the first run; fixed afterwards and verified again) | expected (the test install produced no technology data) | verified | expected |
| `grep_loot` | verified | verified | verified (one very long line in a file could end a search early; fixed afterwards and verified again) | expected |
| `sniper_scan` | verified (`stealth`, `fullportonly`) | verified (`stealth`; 11.0 as root and as a normal user, 11.1 as root) | verified (`stealth`) | expected |
| `cancel_scan` | verified as root | verified as root; as a normal user: expected (it did not stop the scan during the run; fixed afterwards, see the Enterprise column) | verified as a normal user (it did not stop the scan during the first run; fixed afterwards and verified again on live scans) | expected |
| `delete_workspace` | verified, after removing group and world write access from the install tree (see the per-edition notes) | expected | expected | expected |
| `export_workspace` | verified | expected | expected | expected |

Scan modes that were launched: `stealth` and `fullportonly` (9.x) and `stealth` (11.x). The other modes are expected; their refusal paths (target type, port, scope) were verified. For how `cancel_scan` now stops a scan that runs through sudo, and what was verified about it, see [tools.md](tools.md#cancel_scan).

## Scan modes

The server offers a fixed list of modes per engine dialect. It does not derive modes from Sn1per's file names, and it passes only the target, mode, workspace and (for port modes) port to the CLI. Every mode sends traffic to the target. Modes of class `intrusive` are offered only when `SNIPER_MCP_ALLOW_INTRUSIVE=1` ([configuration.md](configuration.md#scan-modes-and-the-intrusive-gate)). A mode whose engine file is missing on the host is unavailable (`engine_file_missing`).

The descriptions below are the ones `sniper_status` gives the model. They describe Sn1per's default profiles; edited profiles change what a mode does.

The flags are the vocabulary `sniper_status` uses for what a mode does: `port_scan`, `service_scripts`, `web_probe`, `content_discovery`, `vuln_templates`, `subdomain_enum`, `third_party_osint`, `host_discovery`, `fan_out_in_range`, `scanner_integrations`, `credential_bruteforce`, `exploitation` and `injection_testing`. A mode is `intrusive` exactly when its flags include `service_scripts`, `credential_bruteforce`, `exploitation` or `injection_testing`.

### 11.x dialect (Sn1per SE, Professional and Enterprise)

In 11.x every mode except `discover` runs the same scan script; the mode name selects a configuration profile.

| Mode | Class | Flags | Targets | Port | Description |
|---|---|---|---|---|---|
| `stealth` (default) | active | `port_scan`, `web_probe`, `vuln_templates`, `third_party_osint` | hostname, IPv4 | no | Lightest scan (profile conf/flyover): default-port nmap scan without service scripts, HTTP probing, crawling, screenshots, TLS and nuclei technology, takeover and static checks. No brute force or exploitation. |
| `recon_passive` | active | `subdomain_enum`, `third_party_osint`, `web_probe`, `vuln_templates`, `port_scan` | hostname | no | Subdomain and OSINT reconnaissance (profile conf/recon_passive): third-party OSINT APIs and DNS brute force, then HTTP probing, crawling and nuclei checks of discovered hosts. Not passive: it sends DNS and HTTP traffic and port-scans if no earlier results exist. |
| `discover` | active | `host_discovery`, `port_scan`, `fan_out_in_range` | IPv4, IPv4 CIDR | no | Host discovery across an IPv4 range (ping and TCP port sweep), then a stealth-profile scan of every live host inside the range. |
| `fullportscan` | intrusive | `port_scan`, `service_scripts` | hostname, IPv4 | no | All 65,535 TCP ports with OS and version detection, then nmap service scripts for each open service; those script sets include brute-force and exploit checks. |
| `normal` | intrusive | `port_scan`, `service_scripts`, `web_probe`, `vuln_templates`, `injection_testing`, `credential_bruteforce`, `exploitation`, `third_party_osint` | hostname, IPv4 | no | Sn1per standard full scan (profile conf/default): default-port scan, nmap service scripts, web checks, nuclei, sqlmap and WPScan, automatic credential brute force on common services, Metasploit exploit modules, whois and web-archive lookups. |
| `web` | intrusive | `port_scan`, `service_scripts`, `web_probe`, `vuln_templates`, `injection_testing`, `credential_bruteforce`, `exploitation`, `third_party_osint` | hostname, IPv4 | no | The standard full scan with the port scan limited to TCP 80 and 443. |
| `port` | intrusive | `port_scan`, `service_scripts`, `web_probe`, `vuln_templates`, `injection_testing`, `credential_bruteforce`, `exploitation`, `third_party_osint` | hostname, IPv4 | required | The standard full scan with the port scan limited to one TCP port. |
| `vulnscan` | intrusive | `port_scan`, `service_scripts`, `vuln_templates`, `scanner_integrations`, `injection_testing`, `credential_bruteforce`, `exploitation` | hostname, IPv4 | no | Vulnerability-focused profile (conf/vulnscan): reuses earlier port results when present, nmap service scripts, nuclei, Burp or ZAP active scans when configured, sqlmap, WPScan, credential brute force and Metasploit exploit modules. |
| `full_scan` | intrusive | `port_scan`, `service_scripts`, `web_probe`, `vuln_templates`, `injection_testing`, `credential_bruteforce`, `exploitation`, `third_party_osint` | hostname, IPv4 | no | Most aggressive profile (conf/full_scan): everything in normal plus Nikto, Metasploit import and credential brute force on every supported service. |

### 9.x dialect (Sn1per Community Edition 9.2)

| Mode | Class | Flags | Targets | Port | Description |
|---|---|---|---|---|---|
| `stealth` (default) | active | `port_scan`, `web_probe`, `content_discovery`, `third_party_osint` | hostname, IPv4 | no | Lightest CE scan: light port scan, HTTP fingerprinting (whatweb, WAF detection, TLS), small-wordlist content discovery, screenshots and web-archive lookups. No brute force or exploitation. |
| `discover` | active | `host_discovery`, `fan_out_in_range` | IPv4, IPv4 CIDR | no | Host discovery across an IPv4 range (ping, TCP and UDP sweeps), then a light flyover scan (ports, web fingerprint, screenshots) of every live host inside the range. |
| `fullportonly` | active | `port_scan`, `vuln_templates` | hostname, IPv4 | no | Port scan only: all TCP ports plus selected UDP ports with version detection and the vulners script. No web checks. |
| `vulnscan` | active | `scanner_integrations`, `vuln_templates` | hostname, IPv4 | no | Runs the vulnerability-scanner integrations enabled in Sn1per's config (Nessus, OpenVAS; both off by default) and Sn1per's sc0pe checks. Little is scanned unless one of them is configured. |
| `normal` | intrusive | `port_scan`, `service_scripts`, `web_probe`, `content_discovery`, `vuln_templates`, `credential_bruteforce`, `exploitation`, `third_party_osint` | hostname, IPv4 | no | CE standard full scan: default-port scan, nmap service scripts including brute-force scripts, web content discovery, nuclei, Metasploit modules for detected services, whois and web-archive lookups. |
| `web` | intrusive | `port_scan`, `service_scripts`, `web_probe`, `content_discovery`, `vuln_templates`, `credential_bruteforce`, `exploitation`, `third_party_osint` | hostname, IPv4 | no | The CE standard scan limited to TCP 80 and 443; web checks include the http-brute script. |
| `port` | intrusive | `port_scan`, `service_scripts`, `web_probe`, `content_discovery`, `vuln_templates`, `credential_bruteforce`, `exploitation`, `third_party_osint` | hostname, IPv4 | required | The CE standard scan limited to one TCP port. |
| `webporthttp` | intrusive | `service_scripts`, `web_probe`, `content_discovery`, `vuln_templates`, `credential_bruteforce` | hostname, IPv4 | required | Web checks against one HTTP port: nmap HTTP scripts including http-brute, content discovery, nuclei; Metasploit web modules only if enabled in sniper.conf. |
| `webporthttps` | intrusive | `service_scripts`, `web_probe`, `content_discovery`, `vuln_templates`, `credential_bruteforce` | hostname, IPv4 | required | Same as webporthttp over HTTPS. |
| `webscan` | intrusive | `injection_testing`, `vuln_templates` | hostname, IPv4 | no | DAST active scanning of HTTP and HTTPS (Arachni, OWASP ZAP, Burp when configured) plus nuclei. Sends attack payloads. |

### Targets and modes

| Target | `discover` | `recon_passive` | Every other mode |
|---|---|---|---|
| Hostname | refused (`target_type_not_supported_for_mode`) | allowed | allowed |
| IPv4 address | allowed (one host) | refused | allowed |
| IPv4 CIDR range | allowed if the prefix is at least the CIDR cap | refused | refused (the 11.x engine would silently switch a range to discover) |
| `http://` or `https://` URL | reduced to its host first, then as hostname or IPv4 | same | same |

IPv6 targets are not supported in this version (`unsupported_target`): the engine runs nmap without IPv6 support. A `port` is required by `port` (both dialects) and by `webporthttp` and `webporthttps` (9.x), and refused by every other mode.

### Modes that are not offered in 0.9.0

| Dialect | Mode | Reason |
|---|---|---|
| 11.x | `recon_active` | Its profile starts child scans of every discovered domain and IP address, which can be third-party hosting outside your scope and which the scope check cannot see. |
| 11.x | `flyover` | Same profile as `stealth` in 11.x. |
| 11.x | `webscan` | Behaves exactly like `web` in 11.x; the name wrongly implies DAST. |
| 11.x | `webporthttp`, `webporthttps` | Not distinct modes in 11.x; use `port`. |
| 11.x | `recon`, `osint`, `osint-stage2` | Internal stages, not modes; as mode names they silently run a full `normal` scan. |
| 11.x | `ad`, `ad_info`, `sniper-ad-exploit` and the AD profile | Libraries, not modes; the AD profile enables AD exploitation. |
| 11.x | every other profile | Reachable only through Sn1per's `-c` option, which the server never passes. |
| both | `airstrike`, `nuke`, `massportscan`, `massweb`, `masswebscan`, `massvulnscan`, CE `flyover` | They need a target file. Each target would need its own scope, DNS and audit decision. Run several single-target scans instead. |
| 9.x | `bruteforce`, `fullportscan`, `osint`, `recon`, `osint_stage_2`, `web_autopwn`, `normal_webporthttp`, `normal_webporthttps` | Helper files, not CLI modes; as mode names they silently run a normal scan. |
| both | `sc0pe*`, `javascript-analysis`, `static-grep-search` | Helpers. |

### What Sn1per does beyond the requested target

- `discover` scans every live host it finds inside the requested range. In 11.x it runs up to 3 of these child scans in parallel by default; the server's concurrency cap does not count them.
- Modes that use third-party OSINT send target names to third-party services (OSINT APIs, web archives, certificate and DNS datasets, whois). `recon_passive` also probes the subdomains it discovers.
- `normal`, `web`, `port`, `vulnscan` and `full_scan` (11.x) may contact out-of-band interaction servers through nuclei and run whois for IP targets.
- Every launch runs Sn1per's update and licence checks (see the per-edition notes).
- The scope applies to the requested target at launch time. It cannot see or stop Sn1per's follow-up requests. Results of `recon_passive` and `discover` carry the warning `follow_up_targets_unchecked`. See [security-model.md](security-model.md) for the egress filter that mitigates this.

## Per-edition notes

### Sn1per Community Edition (9.x)

- **Permissions:** Sn1per Community Edition runs `chmod 777 -Rf /usr/share/sniper` and `chmod 4777` on the CLI during every scan. After the first scan, `sniper_status` therefore shows the warning `install_world_writable`, and it no longer shows the CLI realpath, which any local user could then have chosen (`sn1per-mcp --check` still prints it, with a caution). It also ignores the CLI's `INSTALL_DIR=` line, with the warning `install_dir_marker_untrusted`; the install directory stays `/usr/share/sniper`, or `SNIPER_INSTALL_DIR` when you set it. This is expected, and it is why you should run Sn1per Community Edition on a dedicated, single-user VM or container ([security-model.md](security-model.md)).
- **Delete:** `delete_workspace` is refused with `tree_insecure` after any scan, because a local user could swap the workspace for a link before Sn1per deletes it as root. To use it, remove group and world write access first, then retry:

  ```bash
  sudo chmod go-w /usr/share/sniper /usr/share/sniper/loot /usr/share/sniper/loot/workspace
  ```

  The next scan makes these directories world-writable again.
- **Update check:** every launch sends the host machine-id to the Sn1perSecurity update service.
- **Exit codes:** Sn1per Community Edition exits with status 0 after almost every failure, so the server judges a scan from its log and the files it wrote, never from the exit code alone ([troubleshooting.md](troubleshooting.md)).

### Sn1per SE (scan engine, 11.x)

- The 11.x engine without a web UI. Detected when neither the Enterprise branding nor the Professional licence file is present.
- Every launch sends the licence key, the machine-id and usage statistics to the update service and runs the response as root.

### Sn1per Professional (2026)

- Sn1per Professional 2026 installs the 11.x engine first and the Professional web UI on top, so it uses the 11.x dialect. Scanning through the MCP server is enabled for Professional.
- **Licence and update checks on every launch:** Sn1per sends the licence key, the machine-id and usage statistics, and runs the update server's response as root. When the licensed number of workspaces or hosts is exceeded, the licence check can stop every running scan on the host, and other licence checks can remove the install. The first scan of a day can also take longer while Sn1per updates itself.
- **Workspaces:** reuse one workspace per engagement. Every `sniper_scan` that would create a new workspace on Professional carries the warning `pro_workspace_limit` ("Sn1per Professional licenses a limited number of workspaces; exceeding the limit can stop every running scan on this host"). The server does not enforce licences.
- **Bare metal:** install the MCP server with pipx as the client's user and add the sudoers rule ([install.md](install.md)).
- **Docker (`docker exec`):** install the MCP server with pipx inside the Professional container and register `docker exec -i <container> /root/.local/bin/sn1per-mcp --env-file /root/.config/sn1per-mcp/env` ([remote.md](remote.md#sn1per-professional-through-docker-exec)). The install is lost when the container is recreated. Give the container a fixed MAC address: Docker gives it a new one when it is restarted, reconnected to a network or recreated, and with a new hardware fingerprint the 11.x licence check deletes the Sn1per install on the first scan of the next day (this applies to every 11.x engine in a container, SE and Enterprise included) and can trigger the licence protections described above.

### Sn1per Enterprise (11.x)

- Detected by the `Sn1per Enterprise` branding of its web UI. Uses the 11.x dialect and the same licence and update checks as SE.
- **Not the "MCP Servers" tab:** the Sn1per Enterprise Configuration Editor has an "MCP Servers" tab. That tab configures MCP servers that Sn1per itself uses. It is unrelated to the Sn1per MCP Server on this page, which lets your AI assistant drive Sn1per.
- On some Enterprise installs `conf/` and `modes/` are world-writable; `sniper_status` then shows `install_world_writable`. The server warns; it does not refuse.
- Deleting a workspace through the MCP server does not remove Enterprise UI workspace assignments or engine-wide references to it.
