# Configuration

This page lists every setting of the Sn1per MCP Server, the scope grammar, the intrusive-mode gate, the destructive tools, redaction, the state directory and audit log, plugins and the command-line flags.

## How configuration is read

- The server reads its settings from the process environment and, optionally, from an env file passed with `--env-file <absolute path>`.
- Precedence: **process environment, then the env file, then the built-in default.** A value in the environment wins over the same key in the env file; an empty value in the environment counts as unset, so the env file can fill it.
- The env file is the canonical way to configure the server in every setup: local clients, SSH, WSL2 and Docker. `--check` run with the same `--env-file` sees exactly what the client will run. Variables set in a client's `env` map (or with `claude mcp add -e KEY=VALUE`) also reach the server and win over the env file, but `--check` cannot see them, so the docs use the env file.
- Settings are read once at startup. Changing any variable needs a server restart (restart the client, or start a new client session). The scope file is the only input that is re-read while the server runs.
- An invalid value, an unknown key in the env file, or an unsupported transport setting stops the server before it starts: it prints one line per problem to stderr, in the form `sn1per-mcp: config error: <VAR>: <reason>`, and exits with status 2. `--check` reports the same problems.
- Startup checks are syntactic only (types, ranges, allowed values, absolute paths). Conditions on the filesystem (a missing CLI, scope-file ownership, state-directory ownership, an unwritable audit log) are reported at run time by the affected tools, by `sniper_status` and by `--check`, so the read tools keep working.
- The server never logs the environment and never returns environment values to the model, except the fields `sniper_status` reports.

### Value formats

- **Booleans** accept `1`, `true`, `yes`, `on` and `0`, `false`, `no`, `off` (case-insensitive, surrounding spaces ignored). An empty value means "unset". Anything else is a configuration error.
- **Integers** are base 10 within the stated range.
- **Paths** must be absolute. `~` is not expanded.

### The env file

Pass it with `--env-file <absolute path>`. The server never reads an env file it was not given.

- **Locations:** `/home/<user>/.config/sn1per-mcp/env` with mode 0600 (`/root/.config/sn1per-mcp/env` for root), or, in hardened setups where the agent must not be able to edit it, `/etc/sn1per-mcp/env` owned `root:root` with mode 0644. No setting is a secret, so a world-readable file owned by root is acceptable.
- **File checks:** the file is opened without following symbolic links and must be a regular file owned by the server's user or by root, not writable by group or others, and at most 64 KiB. Anything else is a configuration error (exit 2).
- **Grammar:** one `KEY=VALUE` per line. Blank lines and lines that start with `#` are ignored. `KEY` uses capital letters, digits and `_`. The value is everything after the first `=`, with one optional pair of surrounding double quotes removed. There are no escapes, no variable expansion, no `export` keyword and no command substitution.
- **Allowed keys:** exactly the variables in the table below, each at most once. Any other key, or a key that appears twice, is a configuration error, which catches typos.

Example (copy it and replace the placeholder):

```text
# /home/<user>/.config/sn1per-mcp/env
SNIPER_MCP_SCOPE=<authorized-targets>
SNIPER_MCP_AUTHORIZATION_REF=<your statement-of-work or ticket id>
```

## Environment variables

| Variable | Type | Default | Effect |
|---|---|---|---|
| `SNIPER_EDITION` | `auto`, `ce`, `community` (same as `ce`), `se`, `pro`, `enterprise` | `auto` | Overrides the detected edition label. The scan dialect still comes from the engine version when it can be read; the override sets the dialect only when it cannot. See [editions.md](editions.md). |
| `SNIPER_BIN` | absolute path | detected | The Sn1per CLI to run. The server always runs its realpath, which must be owned by root. A missing file is reported as `cli_not_found`; a realpath not owned by root as `cli_untrusted`. |
| `SNIPER_INSTALL_DIR` | absolute path | the `INSTALL_DIR=` value in the CLI when root chose the CLI file ([editions.md](editions.md#how-detection-works)), else `/usr/share/sniper` | Sn1per's install directory (`modes/`, `conf/`, `pro/`, `CHANGELOG.md`). |
| `SNIPER_LOOT_BASE` | absolute path | `<install dir>/loot` | The directory that contains `workspace/`. The read tools work from here. |
| `SNIPER_SCAN_ENABLED` | boolean | `true` | `false` makes a read-only deployment: `sniper_scan` and `delete_workspace` refuse with `scan_disabled`; the read tools, `scan_status`, `cancel_scan` and `export_workspace` still work. |
| `SNIPER_NEEDS_SUDO` | boolean | `true` when the server does not run as root | Whether Sn1per is started through `sudo -n --`. `false` while not running as root makes scans refuse with `not_root`. |
| `SNIPER_MCP_SCOPE` | list | empty | Authorized targets and `!` exclusions, separated by commas and/or whitespace; at most 10,000 entries and 1 MiB. Required for scanning (see [Scope](#scope)). |
| `SNIPER_MCP_SCOPE_FILE` | absolute path | unset | A scope file with one or more entries per line and `#` comments. Re-read on every `sniper_scan` and `sniper_status` call; combined with `SNIPER_MCP_SCOPE`. |
| `SNIPER_MCP_ALLOW_ANY_TARGET` | boolean | `false` | Lab override: scope membership is not enforced (see [Lab override](#lab-override)). Recorded in every audit line. |
| `SNIPER_MCP_AUTHORIZATION_REF` | string, 1-256 printable characters | empty | Free-text authorization reference, such as a statement-of-work or ticket id. Recorded in every scan, delete and export audit line and shown in `sniper_scan` results and `sniper_status`. |
| `SNIPER_MCP_DNS_POLICY` | `strict`, `lenient` | `strict` | How hostname targets are checked against the addresses they resolve to (see [DNS policy](#dns-policy)). |
| `SNIPER_MCP_CIDR_CAP` | integer 8-32 | `16` | The largest CIDR target allowed is `/<cap>`. |
| `SNIPER_MCP_ALLOW_INTRUSIVE` | boolean | `false` | `true` offers the intrusive scan modes (credential brute force, exploitation, injection testing, service brute-force scripts). Otherwise they are not offered (`mode_not_allowed`). |
| `SNIPER_MCP_MAX_CONCURRENT_SCANS` | integer 1-16 | `2` | Cap on this user's scans launched through the MCP server that are starting or running, counted across every server process that shares the state directory. |
| `SNIPER_MCP_ENABLE_DESTRUCTIVE` | boolean | `false` | `true` registers `delete_workspace` and `export_workspace`. Read at startup only. |
| `SNIPER_MCP_REDACT` | boolean | `true` | Pattern redaction of secrets in every loot and log string returned to the model. `false` turns it off, and every read result then carries the `redaction_disabled` warning. |
| `SNIPER_MCP_REVEAL_SECRETS` | boolean | `false` | `true` lets the read tools and `grep_loot` also read the `credentials/` folder and the credential files listed under [Redaction](#redaction-and-reveal-secrets). It does not turn redaction off. |
| `SNIPER_MCP_STATE_DIR` | absolute path | `$XDG_STATE_HOME/sn1per-mcp` when `XDG_STATE_HOME` is set and absolute, else `$HOME/.local/state/sn1per-mcp` | Job records, job logs, exports and the default audit log location. When this variable is not set, `XDG_STATE_HOME` is not set (or not absolute) and `HOME` is unset or not absolute, that is a configuration error. |
| `SNIPER_MCP_AUDIT_LOG` | absolute path | `<state dir>/audit.jsonl` | The JSONL audit log. |
| `SNIPER_MCP_LOG_RETENTION_DAYS` | integer 0-3650 | `30` | Age limit for job logs and job records of finished jobs. `0` keeps them forever. Never applies to the audit log or exports. |
| `SNIPER_MCP_PLUGINS` | list | empty | Comma-separated allowlist of plugins to load, as `<distribution>:<entry-point-name>` pairs (at most 16). Empty means no plugins, even if some are installed. |

## Scope

The scope is the list of targets you are authorized to test. `sniper_scan` refuses every target that is not inside it.

- **Sources:** `SNIPER_MCP_SCOPE` and the file named by `SNIPER_MCP_SCOPE_FILE`. The effective scope is their union.
- **Not configured:** with both empty (and no lab override), every scan is refused with `scope_not_configured`.
- **Separators:** commas, spaces, tabs or newlines. In the file, `#` starts a comment that runs to the end of the line.
- **Limits:** 10,000 entries in total and 1 MiB per source.

### Entry types

| Entry | Example | Matches |
|---|---|---|
| Domain | `app.example` | That name and every subdomain, on label boundaries: `www.app.example` matches, `notapp.example` and `evil-app.example` do not. |
| Single-label name | `corp` | Only that exact name, never as a suffix (`app.corp` does not match). |
| Subdomain wildcard | `*.app.example` | Subdomains only, not `app.example` itself. A wildcard over a single label (`*.corp`) is invalid. |
| IPv4 or IPv6 address | `192.0.2.10`, `2001:db8::10` | Exactly that address. |
| CIDR range | `192.0.2.0/24`, `2001:db8::/48` | Addresses inside it. Must be canonical (no host bits set). IPv4 prefixes must be `/8` or longer, IPv6 prefixes `/32` or longer. |
| Exclusion | `!dev.app.example`, `!*.dev.app.example`, `!192.0.2.13`, `!192.0.2.128/25` | Same matching as the entry without `!`. Exclusions always win. |

Notes:

- **Normalization:** entries are normalized like targets: full-width characters are mapped to ASCII, one trailing dot is removed, names are lowercased, and internationalized names are converted to their ASCII (A-label) form. `münchen.example` and `xn--mnchen-3ya.example` are the same entry.
- **IPv4-mapped IPv6 entries** are converted to the equivalent IPv4 entry, and the IPv4 rules then apply, so a mapped range that covers every IPv4 address is invalid. No IPv6 entry ever covers an address that embeds an IPv4 address; such answers are matched only through the embedded IPv4 address (see [DNS policy](#dns-policy)).
- **Domain exclusions never apply to IP or CIDR targets.** `!dev.app.example` does not stop a `discover` scan of the range its address is in. When the scope mixes domain exclusions with IP or CIDR entries, `sniper_status` shows the warning `domain_exclusions_not_applied_to_ip_targets`.
- **Domain entries never authorize IP or CIDR targets**, and IP or CIDR entries never authorize hostname targets directly. IP and CIDR entries matter for hostnames only through the DNS checks.
- **CIDR targets** (mode `discover` only) are in scope only when the whole range is inside one scope IP or CIDR entry, and are refused with `excluded` when they overlap any IP or CIDR exclusion, because Sn1per cannot skip addresses inside a range.

### Entries that are refused

The scope is validated fail-closed: **if any entry is invalid, the whole scope is invalid.** `sniper_scan` then refuses with `scope_invalid` and lists up to 20 bad entries with reasons, and `sniper_status` shows them. A typo never widens or narrows the scope silently. You can fix a scope file without restarting the server.

- The placeholder `<authorized-targets>` used in these docs is invalid by design.
- Always-denied names (loopback and cloud-metadata names, and the IANA documentation domains; the full list is in [security-model.md](security-model.md#always-denied-targets)) are invalid as positive entries, so a pasted documentation value fails loudly. They may appear as exclusions.
- A wildcard over a single label, an empty label, a non-canonical CIDR range, a CIDR prefix shorter than the floors above, and anything that does not parse.

### Scope file and the hardened location

A scope file is opened without following symbolic links and must be a regular file owned by the server's user or by root, not writable by group or others, and at most 1 MiB. Anything else makes the scope invalid (`scope_invalid`).

If the server's user can modify the scope file (it owns the file, or the server runs as root), `sniper_status` and every `sniper_scan` result carry the warning `scope_file_writable_by_server_user`: an agent with shell or file-write tools that runs as the same user could widen the scope. The hardened layout keeps the scope and the env file under `/etc/sn1per-mcp/`, owned by root, and runs the server as a non-root user:

```bash
sudo install -d -o root -g root -m 0755 /etc/sn1per-mcp
sudo install -o root -g root -m 0644 /dev/null /etc/sn1per-mcp/scope
sudo install -o root -g root -m 0644 /dev/null /etc/sn1per-mcp/env
sudoedit /etc/sn1per-mcp/scope
sudoedit /etc/sn1per-mcp/env
```

`/etc/sn1per-mcp/scope` (one or more entries per line, `#` comments):

```text
# Engagement <your statement-of-work or ticket id>
<authorized-targets>
```

`/etc/sn1per-mcp/env`:

```text
SNIPER_MCP_SCOPE_FILE=/etc/sn1per-mcp/scope
SNIPER_MCP_AUTHORIZATION_REF=<your statement-of-work or ticket id>
```

Then register the server with `--env-file /etc/sn1per-mcp/env`.

**Change tracking:** each scope gets a digest (the first 16 hex characters of a SHA-256 over the sorted, normalized entries), shown in `sniper_status` and recorded in the audit log. When a re-read of the scope gives a different digest, the server writes a `scope_changed` audit line before it acts on the new scope.

### DNS policy

Hostname targets (including the host of a URL target) are resolved once per request with the system resolver: 5 seconds per lookup, in a pool of 2 worker threads per process. When both workers are busy, the request fails at once with `dns_timeout`. The name looked up is exactly the normalized name Sn1per will receive. Literal IPv4 and CIDR targets are never resolved. The resolved addresses (at most 64, plus the total count) are recorded in the audit log and returned in the `sniper_scan` result.

**`strict` (default)** refuses the target when:

1. the name does not resolve (`dns_unresolved`), or the lookup times out (`dns_timeout`);
2. any address is in the always-deny set (loopback, link-local, cloud metadata, multicast and reserved ranges), unless a scope entry lists it explicitly (`special_use_address`);
3. any address is inside an IP or CIDR exclusion (`excluded`);
4. any address is not publicly routable and is not inside a scope IP or CIDR entry (`private_address_not_in_scope`). This stops an in-scope public name from pointing the scan into an internal network;
5. the scope contains at least one IP or CIDR entry and any address is outside all of them (`resolved_out_of_scope`). A scope with only domain entries trusts public DNS answers; a scope that declares IP ranges binds names to them.

**IPv6 answers that embed an IPv4 address** (IPv4-mapped and IPv4-compatible addresses, the NAT64 prefixes of RFC 6052 and RFC 8215, 6to4 and Teredo) are judged by both forms for rules 2 and 3, and only by the embedded IPv4 address for rules 4 and 5. A name that resolves to the NAT64 form of an internal or metadata address is therefore refused like the address itself.

"Not publicly routable" comes from a fixed table copied from the IANA special-purpose address registries, not from the Python runtime, so results do not change between Python patch releases. It covers the private ranges (RFC 1918), shared address space (RFC 6598), unique local IPv6 addresses (RFC 4193), link-local addresses (RFC 3927) and the documentation ranges, among others. The table is listed in [security-model.md](security-model.md#always-denied-targets).

**`lenient`** applies only rules 2 and 3. Names that do not resolve are allowed with the warning `dns_unresolved`.

**Limitation:** Sn1per and its tools resolve names again during the scan and may contact other hosts. A hostile authoritative DNS server can answer differently later. The scope covers the requested target at launch time only. See [security-model.md](security-model.md).

### Rate limit and concurrency

- **Rate limit (fixed, not configurable):** at most 6 `sniper_scan` calls per server process in any 60-second window may pass the scope check. Later calls in the window are refused with `rate_limited` and audited. This bounds the DNS lookups an agent can trigger with names it chooses.
- **Concurrency cap:** `SNIPER_MCP_MAX_CONCURRENT_SCANS` (default 2) counts this user's starting and running scans across every server process that shares the state directory. At the cap, scans are refused with `concurrency_limit`.
- **Same target:** a second scan of a target that is already being scanned is refused with `target_busy`, because Sn1per writes one temporary configuration file per target.
- Sn1per's own parallelism (for example the child scans of `discover`) is not counted.

Both the cap and the same-target check run before any DNS lookup, so refused calls trigger no lookups.

### Lab override

`SNIPER_MCP_ALLOW_ANY_TARGET=1` is for lab use only.

- **Skipped:** the "scope not configured" refusal, scope membership, and DNS rules 4 and 5.
- **Still enforced:** the target grammar, the always-denied names and addresses (an explicit listing in `SNIPER_MCP_SCOPE` still works), the exclusions of a configured scope, the CIDR cap, the "does not resolve" refusal under `strict`, DNS rules 2 and 3 (including embedded IPv4), the mode rules and the intrusive gate, the rate limit and the concurrency cap.
- Every `sniper_scan` result carries the warning `allow_any_target` ("Scope membership was not enforced because SNIPER_MCP_ALLOW_ANY_TARGET is set; the operator is responsible for authorization"), every audit line records `allow_any_target: true`, and `sniper_status` reports it.
- Never use it in recordings or demos. The operator takes full responsibility for every target.

### Refusals

Scope refusals are tool errors (`isError: true`) with `retry: "never"`. They name the target and the scope digest but never list the full scope (the model can read it from `sniper_status`). The hint tells the agent not to retry with other spellings, encodings, IP forms or wider ranges, and to ask the operator instead. Every refusal is written to the audit log.

## Scan modes and the intrusive gate

No mode is passive: every mode sends traffic to the target. Modes are in one of two classes:

- **active:** port scans, HTTP probing, crawling, screenshots, TLS checks, content discovery with wordlists, detection templates (nuclei, sc0pe, the nmap vulners script), host discovery and third-party lookups.
- **intrusive:** may run credential brute force, exploitation modules (Metasploit, backdoor checks), injection or DAST active scanning, or nmap per-service script sets that include brute-force and exploit-check scripts.

With `SNIPER_MCP_ALLOW_INTRUSIVE` unset or `false`, intrusive modes are not offered to the model: they are left out of the `mode` enum of `sniper_scan`, so a call that names one is rejected before it reaches the server, and `sniper_status` lists them as unavailable with the reason `mode_not_allowed`. The default mode is `stealth` on both engine dialects; if `stealth` is not available on a host, the `mode` parameter has no default and must be given.

The mode tables for each engine dialect are in [editions.md](editions.md#scan-modes). The classes describe Sn1per's default profiles; if you edit Sn1per's `conf/` profiles or `sniper.conf`, you change what a mode does.

## Destructive tools

`delete_workspace` and `export_workspace` are registered only when `SNIPER_MCP_ENABLE_DESTRUCTIVE=1` is set at startup. Without it they do not appear in the tool list.

- Both ask the human to confirm by typing the workspace name through MCP elicitation. Clients without form elicitation cannot use them (`elicitation_unsupported`). An agent-style client may answer elicitations itself instead of asking the human; the server-side opt-in is the primary control.
- `delete_workspace` also needs `confirm=true`, a write-capable deployment (`SNIPER_SCAN_ENABLED` not `false`) and the root-owned layout described in [editions.md](editions.md) and [security-model.md](security-model.md#residual-risks-of-delete-and-export). On Sn1per Community Edition it is refused with `tree_insecure` after any scan, until you remove group and world write access from `/usr/share/sniper`, `loot` and `loot/workspace`.
- `export_workspace` writes `<state dir>/exports/<workspace>-<timestamp>.tar.gz` with mode 0600. The model cannot choose the path. It leaves out the `credentials/` folder and known credential files unless `include_credentials=true`.

## Redaction and reveal-secrets

Redaction is on by default. Every string read from loot, logs and Sn1per output is cleaned (terminal escape sequences and control characters removed, invisible characters removed or made visible), then redacted, then shortened to its display limit. Redaction always runs before shortening, so a cut never leaves part of a secret visible.

Redaction replaces matches with `[REDACTED:<type>]` and counts them per type in the `redaction` object of the result. It covers private-key blocks, Kerberos and timeroast hashes, NetNTLM and LM/NT hashes, crypt-style password hashes, cracked-hash `hash:plaintext` lines, base64 Kerberos tickets, `DOMAIN\user:password` pairs, nmap and Metasploit credential results, passwords in URLs, `Authorization` and cookie header values, Slack webhooks, JWTs, cloud and source-hosting tokens and API keys, Azure SAS signatures, and the values of key/value assignments whose key looks secret (for example `..._KEY`, `..._TOKEN`, `password`).

**Limits:** redaction is pattern-based, not data-loss prevention. New secret formats can slip through. Personal data such as harvested e-mail addresses is not redacted. Job logs and exports on disk are never redacted.

**`SNIPER_MCP_REDACT=false`** returns raw text, with the warning `redaction_disabled` on every result that carries untrusted strings.

**File exclusions.** Unless `SNIPER_MCP_REVEAL_SECRETS=true`, the read tools and `grep_loot` skip:

- every directory named `credentials` or `bloodhound`, at any depth, in any letter case;
- files whose names end with `.pfx`, `.p12`, `.ccache`, `.kirbi`, `.keytab`, `.key`, `.pem`, `.pot`, `.potfile`, `.hccapx`, `.22000` or `.dit`;
- files whose names contain `kerberoast`, `asrep`, `as_rep`, `timeroast`, `hash_cracking`, `hashcat`, `secretsdump`, `potfile`, `gpp_laps`, `credential_harvest`, `lsass` or `ntds`.

These exclusions do not protect credentials on their own: Sn1per also copies hashes and cleartext pairs into other loot folders, which is why redaction is on by default. `SNIPER_MCP_REVEAL_SECRETS=true` only widens which files can be read; it does not turn redaction off. Operators who need raw credentials set both switches and should use a locally hosted model.

## State directory

```text
<state dir>/                     0700, owned by the server's user
  audit.jsonl                    0600, the default audit log
  scan.lock                      0600, empty; lock file for the concurrency cap
  jobs/                          0700
    <job id>.json                0600, job record
    <job id>.log                 0600, Sn1per stdout and stderr (not redacted)
  exports/                       0700
    <workspace>-<timestamp>.tar.gz   0600
```

- The default is `/home/<user>/.local/state/sn1per-mcp` (`/root/.local/state/sn1per-mcp` for root). It is never under `/tmp`.
- Missing directories are created with mode 0700. An existing directory that belongs to the server's user but is readable by others is changed to 0700, with the warning `state_dir_permissions_fixed`. A directory that belongs to another user, or is a symbolic link, makes scan, cancel, delete and export refuse with `state_dir_insecure`; the read tools keep working.
- Job ids are 16 lowercase hex characters. Treat them as opaque.
- **Retention:** at startup and at most once an hour, job records and job logs of finished jobs older than `SNIPER_MCP_LOG_RETENTION_DAYS` days are deleted (`0` keeps them forever). Running jobs, the audit log and exports are never deleted.
- Scans keep running after the server process or the client session ends. `scan_status` reports them from the job record after a restart.

## Audit log

The server writes one JSON object per line to `SNIPER_MCP_AUDIT_LOG` (default `<state dir>/audit.jsonl`), with mode 0600.

- **Fail-closed:** `sniper_scan`, `cancel_scan`, `delete_workspace` and `export_workspace` write their request line before they act. If that write fails, the tool refuses with `audit_unavailable` and does nothing. The read tools do not depend on the audit log.
- **Events:** `server_start`, `server_stop`, `scan_request` (every call, accepted or refused), `scan_exit`, `cancel_request`, `delete_request`, `export_request`, `plugin_loaded`, `plugin_error` and `scope_changed`, plus the events that a loaded plugin writes, named `plugin:<entry-point-name>:<event>` with the plugin's distribution in their `result` object.
- **Common fields:** `schema_version`, `ts` (UTC, ISO 8601 with milliseconds and `Z`), `event`, `server_version`, `pid`, `session` (8 random hex characters per server process), `seq`, `prev`, `client` (name and version from the MCP client) and `request_id`.
- **Action fields** (scan, cancel, delete and export): `tool`, `decision` (`accepted`, `refused`, `declined`, `completed`, `failed`), `reason_code`, `reason`, `target_input`, `target`, `target_type`, `resolved_addresses`, `resolved_addresses_total`, `mode`, `mode_class`, `port`, `workspace`, `job_id`, `argv` (accepted scans and deletes), `sudo`, `edition`, `dialect`, `engine_version`, `scope_source`, `scope_digest`, `matched_scope_entry`, `allow_any_target`, `allow_intrusive`, `dns_policy`, `authorization_ref`, `elicitation` and `result`.
- **Never in the audit log:** loot content, findings, log tails, search patterns or matches, environment variables and secrets.
- Lines are written with ASCII escapes, so control or bidirectional characters in target names cannot disguise the log in a terminal. The server never reads the log back, and no tool returns its content.

### Hash chain

`seq` is 1 for the first record a server session writes and increases by one per record. `prev` is the SHA-256 (hex) of the exact bytes of the previous line that session wrote, without its newline, or `null` when `seq` is 1. Anyone who recomputes the chain can detect deleted, reordered or edited lines within a session. The chain does not stop the server's user, or an agent running as that user, from rewriting a whole session consistently or deleting the file. The log is hash-chained per session; it is not tamper-proof. Use the append-only recipe below where that matters.

### Rotation

The server never rotates, truncates or deletes the audit log. Keep it with your engagement evidence. A `logrotate` example (documented, unverified; the file stays open in the server, so it uses `copytruncate`):

```text
/home/<user>/.local/state/sn1per-mcp/audit.jsonl {
    su <user> <user>
    monthly
    rotate 24
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

With `copytruncate`, lines written between the copy and the truncation can be lost, and a session's hash chain continues from the rotated file into the new one; verify the chain across both files.

### Append-only recipe

Make the audit log append-only so that the server's user can no longer truncate or rewrite it:

```bash
sudo chattr +a /home/<user>/.local/state/sn1per-mcp/audit.jsonl
lsattr /home/<user>/.local/state/sn1per-mcp/audit.jsonl
```

The server tolerates the resulting permission error when it tries to correct the file mode (warning `audit_log_mode_not_fixed`), unless the file is writable by group or others, which makes the audit log unavailable. `logrotate` with `copytruncate` then fails, so rotation becomes a root task: clear the attribute (`chattr -a`), rotate, and set it again (`chattr +a`). Filesystems without the attribute (some container overlay filesystems) cannot use this recipe.

## Plugins

Plugins add tools to the server through the Python entry-point group `sn1per_mcp.plugins`.

- Only plugins listed in `SNIPER_MCP_PLUGINS` are loaded. Installed plugins that are not listed are never imported.
- Each entry is `<distribution>:<entry-point-name>`, for example `my-plugin-dist:my-tools`. An entry point loads only if both its name and its distribution match, so another installed package that declares the same entry-point name is ignored.
- A plugin that fails to load is reported (`sniper_status`, audit log) and the server keeps running without it. A plugin that removes or replaces a core tool makes the server exit with status 3.
- `sniper_status` lists each allowlisted plugin with its distribution, version, install path, status and tools, and carries the `plugins_loaded` warning when any plugin is loaded. `sn1per-mcp --check` also lists installed plugins that are not allowlisted.
- The plugin API (version 1) is experimental during 0.x; plugins pin `sn1per-mcp>=0.9,<0.10`.

> **Warning:** Plugins run inside the Sn1per MCP Server process with the same user, the same sudo rights and access to its memory and environment. Enable only plugins you trust.

## Command-line flags

| Invocation | Behaviour |
|---|---|
| `sn1per-mcp` | Starts the stdio MCP server. Logs go to stderr only; stdout carries only MCP messages. |
| `sn1per-mcp --version` | Prints `sn1per-mcp 0.9.0` and exits 0. |
| `sn1per-mcp --check [--json]` | Does not start the server. Validates the configuration, detects the edition, checks the state directory, parses the scope, runs the sudo check and the engine `PATH` check, then prints a summary (or, with `--json`, the `sniper_status` structure) including the CLI realpath that the sudoers rule must name. Exit 0: scanning is ready. Exit 1: the server would run but scanning is unavailable (the reasons are listed; an unconfigured or invalid scope counts). Exit 2: configuration error. It never launches a scan and never resolves DNS names. |
| `sn1per-mcp --env-file PATH [other flags]` | Loads the env file first. Combines with the other flags. |
| `sn1per-mcp --help` | Prints usage and exits 0. Any other argument, `--json` without `--check`, or `--env-file` given twice prints usage to stderr and exits 2. |

stdio is the only transport. There is no HTTP or SSE mode, and no host or port flag.

`--check` sees only its own environment and `--env-file`. To check what a client will run, pass the same `--env-file` that the client entry passes; without it, `--check` reports `scope_not_configured` even though the client works.
