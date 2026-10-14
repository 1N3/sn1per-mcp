# Troubleshooting

## Start with `--check`

Run the server's self-check with the same env file your client entry passes:

```bash
/home/<user>/.local/bin/sn1per-mcp --env-file /home/<user>/.config/sn1per-mcp/env --check
```

It validates the configuration, detects the Sn1per edition, checks the state directory, parses the scope, checks the sudo rule and Sn1per's `PATH`, and prints the CLI realpath that the sudoers rule must name. It never launches a scan and never resolves DNS names.

| Exit status | Meaning |
|---|---|
| 0 | Scanning is ready. |
| 1 | The server would run, but scanning is unavailable. The reasons are listed (an unconfigured or invalid scope counts). |
| 2 | Configuration error. Each problem is printed as `sn1per-mcp: config error: <VAR>: <reason>`. |

Without `--env-file`, `--check` reports `scope_not_configured` even though the client (which passes the env file) works. Add `--json` for the full `sniper_status` structure.

In the client, ask the model to run `sniper_status`. It reports the same information plus the client's capabilities.

## Error codes and fixes

| Code | What it means | What to do |
|---|---|---|
| `scope_not_configured` | No scope is set. | Set `SNIPER_MCP_SCOPE` or `SNIPER_MCP_SCOPE_FILE` in the env file ([configuration.md](configuration.md#scope)), then start a new client session. |
| `scope_invalid` | At least one scope entry is invalid; the whole scope is refused. | `sniper_status` lists the bad entries and reasons. The placeholder `<authorized-targets>` is invalid by design: replace it. A scope file must be a regular file owned by the server's user or root and not writable by group or others. |
| `out_of_scope`, `excluded` | The target is outside the scope, or matches an exclusion. | Add the target to the scope only if you are authorized to test it. The agent must not retry with other spellings. |
| `cli_not_found` | No Sn1per CLI was found. | Install Sn1per, or set `SNIPER_BIN` to the CLI's absolute path. |
| `cli_untrusted` | The CLI's realpath is not owned by root. | `sudo chown root:root <realpath>`, with the realpath from `--check`, when `--check` prints it without a caution. With the caution, other local users could have chosen or replaced that file: reinstall Sn1per so that the CLI and every directory above it are owned by root and not writable by group or others, and do not chown the file. |
| `sudo_untrusted` | The `sudo` binary is not owned by root, or is writable by group or others. | Fix the ownership and mode of `/usr/bin/sudo`. The server uses `/usr/bin/sudo` whenever it exists; only when it does not, it uses the first `sudo` on its `PATH`, so fix or remove that one. |
| `sudo_missing` | Sudo is needed (the server does not run as root) but no `sudo` binary exists. | Install sudo, or run the server as root in a dedicated container. |
| `sudo_not_configured` | `sudo -n -l <cli>` failed. | Add the drop-in `/etc/sudoers.d/sn1per-mcp` ([install.md](install.md#privilege-setup)). See [Sudo problems](#sudo-problems). |
| `not_root` | `SNIPER_NEEDS_SUDO=false`, but the server does not run as root. | Remove `SNIPER_NEEDS_SUDO=false`, or run the server as root. |
| `engine_path_missing` | Sn1per is not reachable as `sniper` on root's `PATH`. | `sudo ln -s <cli realpath> /usr/local/bin/sniper`, with the realpath from `--check` (see [BlackArch](#blackarch-and-a-missing-sniper-command)). If `--check` prints a caution next to the realpath, first make that file and every directory above it owned by root and not writable by group or others. |
| `install_dir_marker_untrusted` (a warning) | Other local users can change the Sn1per CLI or a directory above it, so its `INSTALL_DIR=` line was not used. Expected on Sn1per Community Edition after a scan, which makes the CLI world-writable. | Nothing when Sn1per is installed in `/usr/share/sniper`. Otherwise set `SNIPER_INSTALL_DIR` (and `SNIPER_LOOT_BASE` if the loot lives elsewhere) in the env file. |
| `edition_unsupported` | The engine version is neither 9.x nor 11.x, or cannot be read. | Supported engines are Sn1per Community Edition 9.x and the 11.x engine. Set `SNIPER_EDITION` only if the CLI is a wrapper. |
| `mode_not_allowed` (in `sniper_status` under `modes.unavailable`), or a schema error naming `mode` | An intrusive mode while intrusive modes are off: such modes are left out of the `mode` enum. | Use `stealth`, or set `SNIPER_MCP_ALLOW_INTRUSIVE=1` if your rules of engagement allow brute force and exploitation, then start a new client session. |
| `engine_file_missing` | The mode's profile or mode file is missing from the Sn1per install. | Reinstall or update Sn1per; `sniper_status` lists the modes that are available. |
| `scan_disabled` | `SNIPER_SCAN_ENABLED=false`: a read-only deployment. | Remove the setting (or set it to `true`) if this host may scan, then start a new client session. |
| `tree_insecure` | `/usr/share/sniper`, `loot` or `loot/workspace` is a link, not owned by root, or writable by group or others without the sticky bit. Expected on Sn1per Community Edition after a scan. | `sudo chmod go-w /usr/share/sniper /usr/share/sniper/loot /usr/share/sniper/loot/workspace`, then retry the delete. |
| `rate_limited` | More than 6 scan calls passed the scope check within 60 seconds. | Wait a minute. The limit is fixed. |
| `concurrency_limit` | The cap on running scans is reached. | Wait for a scan to finish, cancel one, or raise `SNIPER_MCP_MAX_CONCURRENT_SCANS`. |
| `target_busy` | A scan of the same target is running. | Wait for it to finish. |
| `loot_dir_changed` | The loot directory is no longer the directory the server identified at startup (for example it was replaced or moved). | Check that `/usr/share/sniper/loot` (or `SNIPER_LOOT_BASE`) was not replaced by someone else, then start a new client session. |
| `state_dir_insecure` | The state directory belongs to another user or is a symbolic link. | Point `SNIPER_MCP_STATE_DIR` at a directory owned by the server's user, or fix the ownership. |
| `audit_unavailable` | The audit log cannot be written. Scans, cancels, deletes and exports are refused. | Check that the audit log's directory exists and the file is owned by the server's user and not writable by others. |
| `elicitation_unsupported` | The client cannot ask the human to type the workspace name. | Use a client with MCP elicitation ([clients.md](clients.md)), or delete from a shell: `sudo sniper -w <workspace> -d`. |
| `workspace_busy` | A scan is running in that workspace. | Wait for it to finish, or cancel it. |
| `dns_unresolved`, `dns_timeout` | The target name did not resolve, or the lookup timed out. | See [DNS refusals](#dns-refusals). |
| `special_use_address`, `private_address_not_in_scope`, `resolved_out_of_scope` | The name resolves to an address the scope does not allow. | See [DNS refusals](#dns-refusals). |
| `always_denied` | A loopback, metadata or documentation name or address. | See [`example.com` is refused](#examplecom-is-refused). |

The full list of codes is in [tools.md](tools.md#error-codes).

## `sn1per-mcp: command not found` right after install

pipx installs into `~/.local/bin`, which is not on your `PATH` until you run `pipx ensurepath` and open a new shell. Until then, use the absolute path `/home/<user>/.local/bin/sn1per-mcp`. Client entries should always use the absolute path.

## pipx says the package "requires a different Python"

Your system Python is 3.10 (Ubuntu 22.04, Kali 2022.x, the current Sn1per Community Edition AWS Marketplace image). The server needs Python 3.11 or later. Use a uv-managed Python or a newer interpreter ([install.md](install.md#hosts-whose-system-python-is-310)):

```bash
uvx --python 3.12 --from sn1per-mcp==0.9.0 sn1per-mcp
```

## The client says "connection closed" at startup

The server exited before the MCP handshake. Common causes:

- **A configuration error (exit status 2).** Run `--check` with the same `--env-file` and fix each reported line. An unknown key in the env file is an error, so check for typos.
- **The wrong Python.** The command in the client entry starts an interpreter older than 3.11. Use the pipx-installed `/home/<user>/.local/bin/sn1per-mcp`.
- **`mcp` 2.x installed outside the pinned package.** The server needs `mcp` 1.x. If you installed it into a shared environment with `mcp` 2.x, reinstall with pipx or uvx, which keep the pinned dependencies.
- **A GUI client cannot find the command.** Use absolute paths ([clients.md](clients.md)).

The client's MCP log usually shows the server's stderr, including the `config error` lines.

## The package name uses the digit 1

The package is `sn1per-mcp`, with the digit 1. `sniper-mcp` is blocked on PyPI as a look-alike name and is not an alias, so `pipx install sniper-mcp` fails.

## Sudo problems

- The rule must name the realpath that `--check` prints (`/usr/share/sniper/sniper` on a standard install), not a symlink such as `/usr/bin/sniper`.
- The path must be alone at the end of its line. Nothing may follow it, not even a period.
- The rule must be passwordless (`NOPASSWD:`). The server never handles passwords.
- Use the drop-in `/etc/sudoers.d/sn1per-mcp`, created with `sudo visudo -f /etc/sudoers.d/sn1per-mcp`, and check everything with `sudo visudo -c`.
- Test it as the client's user: `sudo -n -l /usr/share/sniper/sniper` must print the path without asking for a password.
- If the edition or CLI path changed, update the rule and start a new client session.

## PEP 668: "externally-managed-environment"

Kali, Debian and Ubuntu refuse `pip install` into the system Python. Use pipx or uv ([install.md](install.md)). Never use `--break-system-packages`, `pip install --user`, `sudo pip` or `sudo pipx`.

## BlackArch and a missing `sniper` command

BlackArch installs the CLI as `/usr/bin/sn1per` only. Sn1per calls itself as `sniper` while it scans, so the server refuses scans with `engine_path_missing` until you add the link:

```bash
sudo ln -s /usr/share/sniper/sniper /usr/local/bin/sniper
```

Use the realpath that `--check` prints if it differs.

## IPv6 targets

IPv6 targets are refused with `unsupported_target`: Sn1per runs nmap without IPv6 support in this version. Scan the hostname or an IPv4 address instead. IPv6 addresses may still appear in the scope, where they are used to check what hostnames resolve to.

## `example.com` is refused

`example.com`, `example.net` and `example.org` (and every name under them) are real hosts operated by IANA for documentation. The server refuses them as `always_denied`, whatever the scope says, and refuses them as positive scope entries (`scope_invalid`). Use your real authorized targets. The same applies to loopback names and cloud-metadata names such as `metadata.google.internal`.

## A scan "failed" or a Sn1per Community Edition scan exits immediately

`scan_status` reports `state: "failed"` with a `state_reason`. Read the log tail in the same result, or the log file at `log_path`.

### Scan failed reasons

| `state_reason` | Typical cause | What to do |
|---|---|---|
| `sudo_password_required` | No passwordless sudo rule. | Add the drop-in ([install.md](install.md#privilege-setup)). |
| `sudo_terminal_required` | The sudoers configuration has `requiretty`. | Remove `requiretty` for this user or rule. |
| `sudo_not_allowed` | The rule names another path. | Use the realpath that `--check` prints. |
| `not_root` | Sn1per was started without root. | Check the sudo rule, or `SNIPER_NEEDS_SUDO`. |
| `engine_not_on_path` | Sn1per could not call itself as `sniper`. | Add the `sniper` link (BlackArch above). |
| `engine_files_missing` | Sn1per's own scripts were missing when it started. A Sn1per 11.x licence check removes the install when the host's hardware fingerprint changes, for example when a container gets a new MAC address after a restart. | Reinstall Sn1per. In containers, run Sn1per 11.x with a fixed MAC address ([remote.md](remote.md#docker)). |
| `engine_removed` | A Sn1per file that existed when the scan started was gone when it ended (same causes). | As for `engine_files_missing`. |
| `target_unresolvable` | Sn1per could not resolve the target. | Check the name and the host's DNS. |
| `engine_out_of_scope` | Sn1per's own out-of-scope setting skipped the target. | Check Sn1per's configuration. |
| `unsupported_target` | Sn1per treated the target as a mobile application id. | Use a different target form. |
| `invalid_port` | nmap rejected the port. | Use a port from 1 to 65535. |
| `missing_port` | A port mode ran without a port. | Pass `port`. |
| `license_limit` | Sn1per Professional's licence limit was exceeded. | See [Sn1per Professional licence-limit messages](#sn1per-professional-licence-limit-messages). |
| `unknown_option`, `missing_target`, `missing_target_file` | Sn1per rejected the command line. | Report a bug with `sn1per-mcp --version` and the engine version. |
| `exit_status` | Sn1per exited with a non-zero status and no known message. | Read the log tail. |
| `no_output` | Sn1per wrote no file into the workspace after the scan started. | Read the log tail. Common causes are an unresolvable target, missing tools, a missing `sniper` link, or Sn1per's update step failing. |

Sn1per Community Edition exits with status 0 after almost every failure, so the server judges a scan from its log and the files it wrote. A scan that ends within 2 seconds is reported by `sniper_scan` itself, as `scan_failed_early` with the reason and the log tail.

Sn1per 11.x prints `Checking for updates...[OK]` even when its update server cannot be reached, so that line does not show that the check ran.

## A cancelled scan is still running

`cancel_scan` returns `cancel_incomplete` when some of the scan's processes did not end, and `scan_status` then shows the job as `running` with `state_reason: "cancel_incomplete"` until they do. The hint names the processes and their sessions; stop them from a shell, for example with `sudo pkill -TERM -s <session ids>`. When the server runs as a normal user, it can stop a scan only through sudo; see [cancel_scan](tools.md#cancel_scan) for how that works and what was verified.

## Stale "running" markers

`scan_status(workspace=...)` may report `stale_markers: true` with `is_running: false`. Sn1per leaves its running markers behind when a scan is killed or crashes. No process is scanning that workspace; the markers are Sn1per's files and do not block new scans through the MCP server. If the process table hides other users' processes (`process_check: "unavailable"`), `is_running` falls back to the markers and may be wrong.

## Sn1per Professional licence-limit messages

A job log with a "limit exceeded" message (`state_reason: license_limit`) means Sn1per Professional's licence check found more workspaces or hosts than your licence allows, and it can stop every running scan on the host. Reuse one workspace per engagement (the `workspace` parameter of `sniper_scan`) and remove workspaces you no longer need. The MCP server does not enforce or change licence limits; contact `support@sn1persecurity.com` about your licence.

## DNS refusals

- `dns_unresolved`: the name has no A or AAAA record from the host's resolver. Check the name. With `SNIPER_MCP_DNS_POLICY=lenient`, unresolvable names are allowed with a warning.
- `dns_timeout`: the lookup took more than 5 seconds, or too many lookups were pending. Retry later, and check the host's resolver.
- `special_use_address`: the name resolves to a loopback, link-local, metadata, multicast or reserved address. Only an explicit scope entry inside that range allows it.
- `private_address_not_in_scope`: the name resolves to a private or other non-public address. Add the covering private range to the scope if it is part of your engagement.
- `resolved_out_of_scope`: your scope lists IP or CIDR ranges, and the name resolves outside all of them. Add the range, or remove the IP entries if the engagement is defined by domain names only.

The refusal lists the resolved and offending addresses in `details`.

## Delete or export: "elicitation not supported"

`delete_workspace` and `export_workspace` ask the human to type the workspace name through MCP elicitation. Clients without it get `elicitation_unsupported`. Use a client that supports it ([clients.md](clients.md)), delete from a shell (`sudo sniper -w <workspace> -d`), or archive the workspace directory yourself. Both tools exist only with `SNIPER_MCP_ENABLE_DESTRUCTIVE=1`.

## The tools do not appear in a web or mobile client

The server uses stdio only. Web, mobile and remote-connector clients (for example claude.ai or ChatGPT connectors) cannot start it. Use a desktop or terminal client, with the [SSH recipe](remote.md#ssh) if Sn1per runs on another machine.

## Where the logs are

| What | Where |
|---|---|
| Server log | stderr of the server process, usually shown in your client's MCP log |
| Job records and job logs | `<state dir>/jobs/<job id>.json` and `<job id>.log` (default state directory `/home/<user>/.local/state/sn1per-mcp`) |
| Audit log | `<state dir>/audit.jsonl`, or `SNIPER_MCP_AUDIT_LOG` |
| Exports | `<state dir>/exports/` |
| Sn1per loot | `/usr/share/sniper/loot/workspace/<workspace>/`, or `SNIPER_LOOT_BASE` |

Job logs and exports are not redacted.

## Filing a bug

Open an issue with the bug template on [the issue tracker](https://github.com/1N3/sn1per-mcp/issues). Include `sn1per-mcp --version`, the edition and engine version from `sniper_status`, your client and its version, the OS and the Python version.

Before you post, remove targets, hostnames, IP addresses, loot content and credentials from everything you paste, including log tails. Replace them with `app.example` style names or `192.0.2.x` addresses. Report security vulnerabilities privately ([SECURITY.md](https://github.com/1N3/sn1per-mcp/blob/main/SECURITY.md)), never in a public issue.
