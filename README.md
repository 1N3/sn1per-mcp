# Sn1per MCP Server

Drive your self-hosted Sn1per from your AI assistant: scoped, audited, for authorized testing.

[![PyPI version of sn1per-mcp](https://img.shields.io/pypi/v/sn1per-mcp)](https://pypi.org/project/sn1per-mcp/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/1N3/sn1per-mcp/blob/main/LICENSE)

<!-- mcp-name: io.github.1N3/sn1per-mcp -->

> For authorized security testing only. Use the Sn1per MCP Server only against systems you own or are explicitly permitted, in writing, to test, and within the scope of that permission.

**Status:** beta (0.9.x). Tool names, parameters and output fields follow the [compatibility promise for 0.x releases](https://github.com/1N3/sn1per-mcp/blob/main/docs/install.md#compatibility-promise-for-0x).

## What it does

Sn1per MCP Server connects the AI assistant you already use to the Sn1per installation on your own Linux host. It runs locally over stdio beside Sn1per, refuses scan requests for targets outside the scope you configure ([see the limits](https://github.com/1N3/sn1per-mcp/blob/main/docs/security-model.md)), records every scan, cancel, delete and export request it acts on in a local audit log, and returns Sn1per's findings, open ports, subdomains and technologies as structured data with secrets redacted by default. It supports Sn1per Community Edition 9.x and the 11.x engine used by SE, Professional and Enterprise; the edition matrix lists what has been verified. It is free and open source under the Apache-2.0 license, and is intended for authorized security testing only.

The server runs beside Sn1per on your host: loot stays there, and tool results leave the host only through your MCP client and the model service it uses. Read [Data handling and privacy](https://github.com/1N3/sn1per-mcp#data-handling-and-privacy) for what does leave the host.

Sn1per does the scanning. The Sn1per MCP Server lets the AI assistant you already use drive it. Generic tool-runner MCP servers expose individual commands. The Sn1per MCP Server drives Sn1per's orchestrated scan modes and returns its structured results, with scope enforcement and an audit log.

### What it is not

- It is not a scanner by itself. It launches and reads the Sn1per installation that is already on your host.
- It does not include Sn1per. Install Sn1per first ([Sn1per Community Edition](https://github.com/1N3/Sn1per), or the Professional or Enterprise installer from your licence).
- It is not for shared multi-user hosts. Run it on a dedicated, single-user scanning VM or container.

## Requirements

- A Linux host with Sn1per Community Edition 9.x or the 11.x engine (Sn1per SE, Sn1per Professional or Sn1per Enterprise).
- Python 3.11 or later. Ubuntu 22.04 and Kali 2022.x ship Python 3.10 and need a uv-managed Python ([install guide](https://github.com/1N3/sn1per-mcp/blob/main/docs/install.md)).
- Root, or a passwordless sudo rule for the Sn1per CLI. That rule is equivalent to full root access for the user it names; read the [security model](https://github.com/1N3/sn1per-mcp/blob/main/docs/security-model.md) before you add it.
- An MCP client that runs local stdio servers. Web, mobile and remote-connector clients are not supported in 0.9.0 (stdio only).

## Quick start

Replace `<user>` with the user who runs your MCP client. The env file is the canonical configuration, so `--check` sees exactly what the client will run.

1. Install pipx, then install the server as that user (never run pipx with `sudo`):

   ```bash
   sudo apt install pipx
   pipx ensurepath
   # open a new shell, then:
   pipx install sn1per-mcp==0.9.0
   ```

2. Create the env file `/home/<user>/.config/sn1per-mcp/env` with mode 0600:

   ```bash
   mkdir -p /home/<user>/.config/sn1per-mcp
   install -m 0600 /dev/null /home/<user>/.config/sn1per-mcp/env
   ```

   Put this line in it, then replace the placeholder with the targets you are authorized to test. The placeholder itself is refused (`scope_invalid`), so nothing is scanned until you do.

   ```text
   SNIPER_MCP_SCOPE=<authorized-targets>
   ```

3. Check the configuration. The output includes the realpath of the Sn1per CLI that the sudo rule must name:

   ```bash
   /home/<user>/.local/bin/sn1per-mcp --env-file /home/<user>/.config/sn1per-mcp/env --check
   ```

4. Add the sudoers drop-in with that realpath (`/usr/share/sniper/sniper` on a standard install). Skip this step if the client runs as root. Full steps: [docs/install.md](https://github.com/1N3/sn1per-mcp/blob/main/docs/install.md#privilege-setup).

   ```bash
   sudo visudo -f /etc/sudoers.d/sn1per-mcp
   ```

   ```text
   <user> ALL=(root) NOPASSWD: /usr/share/sniper/sniper
   ```

5. Register the server with Claude Code (other clients: [docs/clients.md](https://github.com/1N3/sn1per-mcp/blob/main/docs/clients.md)):

   ```bash
   claude mcp add sn1per -s user -- /home/<user>/.local/bin/sn1per-mcp --env-file /home/<user>/.config/sn1per-mcp/env
   ```

6. Start a new client session and ask: "Run sniper_status".

## Client setup

Only clients that passed the 0.9.0 client tests (2026-10-12) are listed. Configuration paths, approval settings and per-client notes are in [docs/clients.md](https://github.com/1N3/sn1per-mcp/blob/main/docs/clients.md).

| Client | Status | Delete and export tools (need MCP elicitation) |
|---|---|---|
| Claude Code (2.1.284) | verified | yes, in interactive sessions; `claude -p` without an SDK host cancels the confirmation, so nothing is deleted or exported |
| Codex CLI (0.125.0) | verified in `codex exec` only | no in `codex exec`, which declines the confirmation; the interactive Codex interface is not yet tested |
| Web, mobile and remote-connector clients | not supported in 0.9.0 (stdio only) | not applicable |

**Claude Code:** the one-line command in the quick start (step 5). **Codex CLI:** the `config.toml` entry, and the approval setting that `export_workspace` needs there, are in [docs/clients.md](https://github.com/1N3/sn1per-mcp/blob/main/docs/clients.md#codex-cli). Other clients that start local stdio servers are not yet tested with 0.9.0.

Is Sn1per on another machine, or is your client on macOS or Windows? See [docs/remote.md](https://github.com/1N3/sn1per-mcp/blob/main/docs/remote.md) for the SSH recipe (verified with a Linux OpenSSH client; Windows and macOS clients documented, unverified), WSL2 (documented, unverified) and the Docker recipes (documented, unverified).

## Editions

The server detects the edition and engine from the Sn1per CLI on the host. "Verified" means exercised by the 0.9.0 verification run on 2026-10-12; "expected" means no known blocker, but not exercised. The per-tool results, the scan modes that were run and the fixes made after the run are in [docs/editions.md](https://github.com/1N3/sn1per-mcp/blob/main/docs/editions.md#edition-matrix), together with the mode tables and per-edition notes.

| Edition | Engine dialect | Status |
|---|---|---|
| Sn1per Community Edition 9.2 (repository `master` at `a5450bc`) | 9.x | verified 2026-10-12, with the server running as root |
| Later Sn1per Community Edition 9.x releases | 9.x | expected |
| Sn1per SE 11.0 and 11.1 | 11.x | verified 2026-10-12 (11.0 as root and as a normal user through sudo, 11.1 as root) |
| Sn1per Enterprise, 11.3 development build | 11.x | verified 2026-10-12, as a normal user through sudo |
| Other 11.x releases, including 11.2 | 11.x | expected |
| Sn1per Professional 2026 | 11.x | uses the same 11.x engine as SE and Enterprise; not yet run on a Professional install |
| Sn1per Community Edition below 9.2 | - | not supported |

**Platforms:** Linux only. Verified on Kali Rolling (amd64). Ubuntu 24.04: verified for the install and the MCP session (no scan was run on Ubuntu). Debian 12 and 13 and Parrot: expected. Ubuntu 22.04 and Kali 2022.x: expected only with a uv-managed Python or a separately installed Python 3.11 or later; their system Python 3.10 is refused. BlackArch: expected; needs a `sniper` symlink on `PATH`. arm64: expected. macOS and Windows are not supported as the server host; use them as the client host over SSH ([docs/remote.md](https://github.com/1N3/sn1per-mcp/blob/main/docs/remote.md)).

## Tools

Full parameters, example results and error codes: [docs/tools.md](https://github.com/1N3/sn1per-mcp/blob/main/docs/tools.md).

| Tool | What it does | Read-only or changes state | Availability |
|---|---|---|---|
| `sniper_status` | Reports the detected edition, the scan modes available, the configured scope and why scanning may be unavailable | Read-only | Always |
| `list_workspaces` | Lists the Sn1per loot workspaces on the host | Read-only | Always |
| `scan_status` | Reports a scan's state and a redacted log tail, or whether anything runs in a workspace | Read-only | Always |
| `get_findings` | Reads findings with severity, title, location and host | Read-only | Always |
| `get_ports` | Reads open ports with protocol, service and version | Read-only | Always |
| `get_subdomains` | Reads discovered subdomains | Read-only | Always |
| `get_technologies` | Reads detected web technologies | Read-only | Always |
| `grep_loot` | Searches loot files in one workspace (or in all of them, when the operator asks) for a string or an extended regular expression | Read-only | Always |
| `sniper_scan` | Starts a Sn1per scan of one target, as root, and returns a job handle | Changes state: sends traffic to the target | Always registered; refuses every target until you configure a scope |
| `cancel_scan` | Stops a scan that this server started | Changes state | Always |
| `delete_workspace` | Permanently deletes one workspace and its scan data, as root, after the human types the workspace name | Changes state: irreversible | Only with `SNIPER_MCP_ENABLE_DESTRUCTIVE=1` and a client with MCP elicitation |
| `export_workspace` | Writes a tar.gz archive of one workspace into the server's state directory, after the human types the workspace name | Changes state: writes a file | Only with `SNIPER_MCP_ENABLE_DESTRUCTIVE=1` and a client with MCP elicitation |

## Configuration

All settings, the scope grammar and the command-line flags: [docs/configuration.md](https://github.com/1N3/sn1per-mcp/blob/main/docs/configuration.md).

- **Scope (required for scans):** `SNIPER_MCP_SCOPE` and/or `SNIPER_MCP_SCOPE_FILE` list the domains, IPv4 and IPv6 addresses and CIDR ranges you are authorized to test, with `!` exclusions. With no scope, every scan request is refused. One invalid entry makes the whole scope invalid.
- **Intrusive modes:** modes that run credential brute force, exploitation or injection testing are off until you set `SNIPER_MCP_ALLOW_INTRUSIVE=1`. The default mode is `stealth`.
- **Destructive tools:** `delete_workspace` and `export_workspace` exist only with `SNIPER_MCP_ENABLE_DESTRUCTIVE=1`, and both ask the human to type the workspace name.
- **Redaction:** secrets in results are redacted by default (`SNIPER_MCP_REDACT`). Redaction is pattern-based; it is not data-loss prevention.

## Security model

The server is a set of controls around a root-capable engine, not a security boundary. Read [docs/security-model.md](https://github.com/1N3/sn1per-mcp/blob/main/docs/security-model.md) before you deploy it. In short:

- The passwordless sudo rule for the Sn1per CLI is equivalent to full root access for that user.
- The scope applies to the target the agent requests, at launch time. Sn1per resolves names again during the scan, may contact third-party services, and some modes scan hosts they discover. Use an egress filter on the scanning host.
- These controls do not stop an agent that also has shell or file-write access as the same user. Keep the scope and env files under `/etc/sn1per-mcp/`, owned by root, and deny those tools for them.
- Everything read from loot, logs and searches is returned as untrusted data, because scanned systems control it.

## Responsible use

The Sn1per MCP Server lets an AI agent launch active security scans. Scans send traffic to the target, can be intrusive, and run with root privileges through sudo.

- Use it only against systems you own or are explicitly authorized, in writing, to test, and only within the scope and rules of engagement of that authorization. Unauthorized scanning is illegal in many jurisdictions.
- You, the operator, are responsible for every action your agent takes, including actions triggered by content the agent reads (for example prompt injection in a web page or in scan output).
- Configure the target scope (`SNIPER_MCP_SCOPE` or `SNIPER_MCP_SCOPE_FILE`) before you use the scan tools. The server refuses scan requests for targets outside that scope ([see the limits](https://github.com/1N3/sn1per-mcp/blob/main/docs/security-model.md)).
- Brute-force and exploitation modes and destructive tools are off by default. Turn intrusive modes on (`SNIPER_MCP_ALLOW_INTRUSIVE=1`) only when your rules of engagement allow credential brute force and exploitation.
- The server records every scan, cancel, delete and export request it acts on in a local audit log. Keep that log with your engagement evidence.
- Sn1per Community Edition is governed by its own EULA, which also prohibits scanning without permission.

This software is provided under the Apache License 2.0, without warranty of any kind.

## Data handling and privacy

- The MCP server itself sends no telemetry. Its only network activity is the DNS lookups it makes to check hostname targets against your scope.
- Sn1per runs its own update and licence checks every time a scan starts, including scans launched through this server. Sn1per Community Edition sends the host machine-id. Sn1per SE, Professional and Enterprise send the licence key, the machine-id and usage statistics, and run the update server's response as root; Professional licence checks can stop every running scan or remove the install. The MCP server never suppresses these checks. Per-edition details: [docs/editions.md](https://github.com/1N3/sn1per-mcp/blob/main/docs/editions.md).
- Scans send traffic to the target and, depending on the mode, to third-party services (OSINT APIs, web archives, certificate and DNS datasets, whois) and to out-of-band interaction servers.
- Tool results (findings, hostnames, ports and search matches, which may include personal data such as harvested e-mail addresses) are returned to your MCP client and from there to the model service it uses. Some clients route model traffic through the client vendor's own backend, and transcripts may be stored or synced in the vendor's cloud. Make sure your engagement contract and data-protection obligations allow this, or use a locally hosted model.
- The server writes job records, job logs, exports and the audit log to its state directory, `/home/<user>/.local/state/sn1per-mcp` by default (`/root/.local/state/sn1per-mcp` for root), with owner-only permissions. Job logs and exports on disk are not redacted. Treat the state directory as engagement evidence.

## Remote use, upgrade, uninstall and troubleshooting

- Client on another machine (macOS, Windows, another Linux host), WSL2 and Docker: [docs/remote.md](https://github.com/1N3/sn1per-mcp/blob/main/docs/remote.md).
- Upgrade, rollback and uninstall (including removing the sudoers rule): [docs/install.md](https://github.com/1N3/sn1per-mcp/blob/main/docs/install.md).
- Common problems and error codes: [docs/troubleshooting.md](https://github.com/1N3/sn1per-mcp/blob/main/docs/troubleshooting.md).

## Support and security

- Questions and help: [SUPPORT.md](https://github.com/1N3/sn1per-mcp/blob/main/SUPPORT.md).
- Report a vulnerability privately through [GitHub Private Vulnerability Reporting](https://github.com/1N3/sn1per-mcp/security/advisories/new) or as described in [SECURITY.md](https://github.com/1N3/sn1per-mcp/blob/main/SECURITY.md). Do not open a public issue for a vulnerability.
- Contributions are welcome under the Developer Certificate of Origin: see [CONTRIBUTING.md](https://github.com/1N3/sn1per-mcp/blob/main/CONTRIBUTING.md).
- This project follows the [Code of Conduct](https://github.com/1N3/sn1per-mcp/blob/main/CODE_OF_CONDUCT.md).

## License and trademarks

The Apache License 2.0 ([LICENSE](https://github.com/1N3/sn1per-mcp/blob/main/LICENSE), [NOTICE](https://github.com/1N3/sn1per-mcp/blob/main/NOTICE)) covers this MCP server only. It does not cover Sn1per. Sn1per Community Edition is source-available under its own EULA. Sn1per Professional and Sn1per Enterprise are commercial products of Sn1perSecurity LLC and are licensed separately. "Sn1per" and the Sn1per logo are trademarks of Sn1perSecurity LLC; see [TRADEMARKS.md](https://github.com/1N3/sn1per-mcp/blob/main/TRADEMARKS.md).

## Get notified

Every install command pins an exact version, so you only receive fixes when you upgrade. A PyPI yank does not reach installs pinned with `==`. To hear about new releases and security fixes:

- On GitHub, choose **Watch**, then **Custom**, then select **Releases** and **Security alerts** for this repository.
- Read the [releases page](https://github.com/1N3/sn1per-mcp/releases) and the [security advisories](https://github.com/1N3/sn1per-mcp/security/advisories).

Sn1per MCP Server is published by Sn1perSecurity LLC.
