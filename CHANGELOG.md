# Changelog

All notable changes to the Sn1per MCP Server are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Every release has an "Upgrade notes" section. The compatibility rules for 0.x releases are in [docs/install.md](docs/install.md#compatibility-promise-for-0x).

## [0.9.0] - 2026-11-04

Public beta.

### Added

- Local stdio MCP server for Sn1per, installed as `sn1per-mcp` from PyPI (Python 3.11 or later, Linux).
- Edition detection from the Sn1per CLI: Sn1per Community Edition 9.x and the 11.x engine used by Sn1per SE, Sn1per Professional and Sn1per Enterprise, with the `SNIPER_EDITION` override.
- `sniper_scan` with fixed per-engine mode tables, `stealth` as the default mode, a strict target grammar, and a job handle that survives the client session.
- `scan_status` with job states, failure reasons and a redacted log tail, and `cancel_scan` to stop a scan started through the server.
- Structured loot readers: `list_workspaces`, `get_findings` (with severity summary and filters), `get_ports`, `get_subdomains`, `get_technologies` and `grep_loot`, all with paging.
- Opt-in `delete_workspace` and `export_workspace` (`SNIPER_MCP_ENABLE_DESTRUCTIVE=1`), confirmed by the human through MCP elicitation.
- `sniper_status` and `sn1per-mcp --check` to show what the server can do on the host and why scanning may be unavailable.
- Configuration through the environment or an env file (`--env-file`), with recipes for SSH, WSL2 and Docker.
- An allowlist-based plugin mechanism (`SNIPER_MCP_PLUGINS`).

### Security

- A mandatory, fail-closed target scope (`SNIPER_MCP_SCOPE`, `SNIPER_MCP_SCOPE_FILE`) with exclusions, a CIDR cap and a strict DNS policy. Scan requests for targets outside the scope are refused; the scope applies to the requested target at launch time (see the [security model](https://github.com/1N3/sn1per-mcp/blob/main/docs/security-model.md)).
- Always-denied loopback and cloud-metadata names and addresses, and the three IANA example domains (the documentation hosts under `.com`, `.net` and `.org`), including IPv6 forms that embed an IPv4 address.
- Brute-force, exploitation and injection modes are off unless `SNIPER_MCP_ALLOW_INTRUSIVE=1`.
- A local JSONL audit log of every scan, cancel, delete and export request the server acts on, hash-chained per session and written before the action.
- Secrets in results are redacted by default; untrusted content from scanned systems is labelled and cleaned of control and invisible characters.
- `sniper_status` and the refusal hints list a file name found on disk only when root chose it: other names under `conf/` and `modes/` are counted, not listed, and a CLI realpath that root did not choose is replaced by a note (`sn1per-mcp --check` prints it on the host). The CLI's `INSTALL_DIR=` line is used and shown only when root chose the CLI file (warning `install_dir_marker_untrusted` otherwise).
- Loot is read without following symbolic links; the loot directory's identity is pinned; FIFOs, devices and hard-linked files are skipped.
- Scans and deletes require a root-owned Sn1per CLI; when the server does not run as root, they also require a root-owned `sudo` and a passwordless sudo rule, checked before launch. Every subprocess gets a minimal environment.
- A fixed rate limit on scan requests and a concurrency cap.

### Upgrade notes

First public release. There is no upgrade path from earlier versions.

[0.9.0]: https://github.com/1N3/sn1per-mcp/releases/tag/v0.9.0
