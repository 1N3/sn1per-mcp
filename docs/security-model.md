# Security model

The Sn1per MCP Server lets an AI agent drive Sn1per, which runs as root and sends traffic to the targets it scans. This page describes what the server defends against, the controls it applies and where they stop, the facts you must know before you deploy it, and a recommended deployment.

The controls reduce risk. They do not make an AI agent with root-capable tools harmless, and they are not a boundary against an agent that also has shell or file-write access as the same user.

## Threat model

The server is designed with these threats in mind:

- **A prompt-injected agent.** The model reads loot, Sn1per output and web content that the scanned systems control. Text in those results can try to make the agent scan other targets, cancel or delete work, export data, or leak data from other engagements.
- **Local users on the scanning host.** Sn1per Community Edition makes its install and loot tree world-writable. Another local user can place files, links or renamed folders in it.
- **An agent that also has shell or file-write tools** running as the same user as the server. Such an agent can bypass the server entirely (see disclosure (j)).

## Trust boundaries

| Party | What it can do | What it is trusted with |
|---|---|---|
| The model | Chooses tool calls and arguments | Nothing. Every argument is validated, and every scan is checked against the operator's scope. |
| The MCP client and the client vendor's backend | Starts the server, passes tool calls and results, may store transcripts | Every tool result. Some clients route model traffic through the client vendor's own backend. |
| The server's user | Runs the server, owns the state directory, the audit log and (by default) the scope and env files | The configuration, unless you move it to root-owned files under `/etc/sn1per-mcp/`. |
| Root, through sudo | Runs the Sn1per CLI | Everything on the host. The sudo rule is root-equivalent. |
| Sn1per (the engine) | Scans, writes loot, runs update and licence checks | Everything root can do. The server does not limit what Sn1per does once it starts. |
| Targets | Answer scans; control the content that ends up in loot | Nothing. All loot is untrusted data. |
| Third-party services | Receive target names from OSINT, archive, certificate, DNS and whois lookups, and from out-of-band interaction servers | Target names and request data. |

## Controls and their limits

| Control | What it does | Limit |
|---|---|---|
| Target scope | Refuses scan requests for targets outside `SNIPER_MCP_SCOPE` and the scope file; fail-closed on any invalid entry; label-boundary matching; exclusions win ([configuration.md](configuration.md#scope)) | Applies to the requested target at launch time only. The lab override skips scope membership. An agent with file-write access as the server's user can edit a user-owned scope file. |
| DNS policy | Resolves hostname targets and refuses names that point at special-use, excluded, internal or out-of-scope addresses, including through IPv6 forms that embed an IPv4 address | Sn1per resolves names again during the scan; a hostile DNS server can answer differently later. |
| Rate limit | At most 6 scan calls per server process per 60 seconds past the scope check | Bounds the volume of DNS lookups and launches; it does not close the target-name channel (disclosure (k)). |
| Intrusive gate | Brute-force, exploitation and injection modes are off unless the operator enables them | Mode classes describe Sn1per's default profiles. Edited profiles change what a mode does. |
| Destructive opt-in and elicitation | Delete and export exist only with `SNIPER_MCP_ENABLE_DESTRUCTIVE=1`, and the human must type the workspace name | Agent-style clients may answer the confirmation themselves (disclosure (h)). |
| Tree check before a delete | Refuses a delete when `/usr/share/sniper`, `loot` or `loot/workspace` is a link, not owned by root, or group- or world-writable without the sticky bit; checked again after the confirmation | See the residual delete risks below. |
| Root-owned CLI and `sudo` | Refuses scans and deletes when the CLI realpath is not owned by root (`cli_untrusted`) or the `sudo` binary is not owned by root or is writable by others (`sudo_untrusted`) | World-writable files under `modes/` and `conf/` are only a warning, because Sn1per Community Edition makes them so on every scan. |
| Audit log | Records every scan, cancel, delete and export request it acts on, accepted or refused, before acting; fail-closed | Hash-chained per session, not tamper-proof (disclosure (l)). A call that the MCP SDK rejects against the input schema (for example a `mode` that is not offered on this host) never reaches the server and is not recorded. |
| Input validation | Strict grammar for targets, workspaces, ports, modes and search patterns; no leading dashes, shell characters, control or invisible characters, alternate IPv4 notations or mixed-script names; a scan passes only `-t`, `-m`, `-w` and `-p` to the CLI, and `delete_workspace` only `-w` and `-d` | - |
| No-follow loot reads | Every loot path is opened component by component without following symbolic links; the loot directory's identity is pinned at startup (`loot_dir_changed`); FIFOs, devices and hard-linked files are skipped | `grep_loot` cannot detect hard links (disclosure (n)). |
| Redaction | Pattern-based redaction of secrets in every untrusted string, before any truncation | Not data-loss prevention: new formats can slip through, personal data is not redacted, and files on disk are not redacted. |
| Untrusted labelling | Every string from loot, logs and file names is returned under `untrusted_content` with a fixed notice, after control and invisible characters are removed | A label, not a filter. The model can still be influenced by the content. |
| stdio only | No HTTP or SSE listener; nothing is reachable over the network | - |
| Minimal subprocess environment | Sn1per and grep receive a fixed, minimal environment, never the client's environment | - |

## What you must know before you deploy

**(a) The sudo rule is root-equivalent.** A passwordless sudo rule for the Sn1per CLI gives the user it names full root access, because the CLI sources arbitrary files as root (its configuration files and, on some installs, world-writable files under `conf/` and `modes/`). Anyone who can act as that user, including an agent with shell access, can become root.

**(b) Sn1per Community Edition makes itself world-writable.** On every scan it runs `chmod 777 -Rf /usr/share/sniper` and `chmod 4777` on the CLI. Any local user can then change what root runs on the next scan. Use a dedicated, single-user VM or container for Sn1per Community Edition.

**(c) Every launch runs Sn1per's update and licence checks.** Sn1per Community Edition sends the host machine-id. Sn1per SE, Professional and Enterprise send the licence key, the machine-id and usage statistics, and run the update server's response as root. Professional licence checks can stop every running scan or remove the install. In a container, every 11.x engine deletes its own install when its hardware fingerprint changes, which a restart without a fixed MAC address causes ([remote.md](remote.md#sn1per-professional-through-docker-exec)). The MCP server never suppresses or pre-empts these checks. The MCP server itself sends no telemetry.

**(d) Tool results leave the host through your MCP client.** Findings, hostnames, ports and search matches are returned to your MCP client and from there to the model service it uses. Some clients route model traffic through the client vendor's own backend, and transcripts may be stored or synced in the vendor's cloud ([clients.md](clients.md)). Use a locally hosted model when your engagement does not allow this.

**(e) Sn1per contacts more than the requested target.** `discover` scans every live host it finds inside the requested range. Modes with third-party OSINT send target names to OSINT APIs, web archives, certificate and DNS datasets and whois. Several modes may contact out-of-band interaction servers through nuclei. `recon_passive` probes the subdomains it discovers, so a hostile in-scope domain can publish subdomains that point at internal, link-local or cloud-metadata addresses, and Sn1per will probe them from your scanning host. Results of such modes carry the warning `follow_up_targets_unchecked`. The scope check cannot see or stop these follow-up requests; use the egress filter below.

**(f) Sn1per's loot and temporary files are readable by others.** Sn1per leaves the loot tree world-writable after scans, and writes a per-target configuration file, including API keys from its configuration, to a predictable path under `/tmp`. Other local users can read them, and the predictable path lets a local user interfere with the file before Sn1per writes it.

**(g) Deleting a workspace has residual risks.** See [Residual risks of delete and export](#residual-risks-of-delete-and-export).

**(h) Agent clients may answer confirmations themselves.** The delete and export confirmation uses MCP elicitation, which asks the human to type the workspace name. An agent-style client may answer elicitations itself instead of asking the human. The server-side opt-in (`SNIPER_MCP_ENABLE_DESTRUCTIVE`) is the primary control; the confirmation is the second.

**(i) Files on disk are not redacted.** Job logs (`jobs/*.log`) and exports in the state directory hold raw Sn1per output and loot. The state directory has mode 0700. Treat it as engagement evidence.

**(j) These controls are not a boundary against an agent with shell or file-write access as the same user.** Such an agent can edit a user-owned scope or env file, change the client configuration (for example to set `SNIPER_MCP_ALLOW_ANY_TARGET` or `SNIPER_MCP_ENABLE_DESTRUCTIVE`), or run `sudo sniper` directly through the root-equivalent rule. If your agent has such tools:

- deny them for the scope file, the env file, the client configuration and `sudo`;
- keep the scope and env files under `/etc/sn1per-mcp/`, owned by root ([configuration.md](configuration.md#scope-file-and-the-hardened-location));
- run the server as a non-root user.

**(k) Target names are a residual exfiltration channel.** A target name is data. The authoritative DNS server of an in-scope domain sees every name the agent asks the server to check, even names the server then refuses, and scanned web servers see every request. A prompt-injected agent could encode data from other engagements into such names. The rate limit bounds the volume; it does not close the channel.

**(l) The audit log is hash-chained per session, not tamper-proof.** The `seq` and `prev` fields make deleted, reordered or edited lines within a session detectable, but the server's user can rewrite a whole session consistently or delete the file. Use the append-only recipe ([configuration.md](configuration.md#append-only-recipe)) where that matters.

**(m) Plugins are fully trusted code.** Plugins run inside the Sn1per MCP Server process with the same user, the same sudo rights and access to its memory and environment. Enable only plugins you trust. Loading needs an explicit `<distribution>:<entry-point-name>` allowlist entry.

**(n) Hard links on hosts without hard-link protection.** On hosts where the kernel setting `fs.protected_hardlinks` is off, a local user can hard-link the operator's files into the world-writable loot tree. The loot readers and export skip files with more than one link; `grep_loot` cannot detect them. `sniper_status` warns with `protected_hardlinks_off`.

## Always-denied targets

These targets are refused in every configuration, including under the lab override. Names are refused without any DNS lookup.

**Names:** `localhost`, every name ending in `.localhost`, `localhost.localdomain`, `ip6-localhost`, `ip6-loopback`, `metadata`, `metadata.google.internal`, `metadata.goog`, `instance-data`, `instance-data.ec2.internal`, and `example.com`, `example.net` and `example.org` with every name under them. The last three are real hosts operated by IANA for documentation; they are refused so that a copied example can never reach them. Always-denied names are also invalid as positive scope entries.

**Addresses** (literal targets, CIDR targets that overlap them, and addresses that hostnames resolve to):

| Family | Ranges |
|---|---|
| IPv4 | `0.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16` (link-local; includes the `169.254.169.254` cloud metadata address and the `169.254.170.2` container credentials address), `100.100.100.200/32` (Alibaba Cloud metadata), `168.63.129.16/32` (Azure platform endpoint), `224.0.0.0/4` (multicast), `240.0.0.0/4` (reserved, includes `255.255.255.255`) |
| IPv6 | `::/96` (unspecified, loopback and the deprecated IPv4-compatible form), `fe80::/10` (link-local), `fec0::/10` (deprecated site-local), `ff00::/8` (multicast), `fd00:ec2::/32` (AWS instance metadata, DNS and NTP over IPv6) |
| Embedded IPv4 | Any IPv6 address whose embedded IPv4 address is in the IPv4 row: IPv4-mapped (`::ffff:0:0/96`), IPv4-compatible (`::/96`), NAT64 (the well-known prefix of RFC 6052 and the local-use prefix `64:ff9b:1::/48` of RFC 8215), 6to4 (RFC 3056) and Teredo (`2001::/32`, both embedded addresses) |

An always-denied address is allowed only when a scope IP or CIDR entry contains it and that entry lies entirely inside the always-deny set (for example a deliberate loopback entry). A broad entry that merely overlaps it does not authorize it.

**Addresses that are not publicly routable** (used by the strict DNS policy: a hostname that resolves to one of these is refused unless a scope IP or CIDR entry covers it). The table is copied from the IANA IPv4 and IPv6 Special-Purpose Address Registries (as last updated 2025-10-09), taking every block whose "Globally Reachable" value is False, plus the always-deny set:

| Family | Not publicly routable | Public exceptions inside those blocks |
|---|---|---|
| IPv4 | `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`, `192.88.99.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `240.0.0.0/4`, `255.255.255.255/32`, `224.0.0.0/4`, `100.100.100.200/32`, `168.63.129.16/32` | `192.0.0.9/32`, `192.0.0.10/32` |
| IPv6 | `::/96`, `::ffff:0:0/96`, `64:ff9b:1::/48`, `100::/64`, `100:0:0:1::/64`, `2001::/23`, `2001:db8::/32`, `3fff::/20`, `5f00::/16`, `fc00::/7`, `fe80::/10`, `fec0::/10`, `ff00::/8`, `fd00:ec2::/32` | `2001:1::1/128`, `2001:1::2/128`, `2001:1::3/128`, `2001:3::/32`, `2001:4:112::/48`, `2001:20::/28`, `2001:30::/28` |

The NAT64 well-known prefix (RFC 6052) and the 6to4 prefix (RFC 3056) are not in the table: an address there is judged through its embedded IPv4 address. Sources: [IANA IPv4 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv4-special-registry) and [IANA IPv6 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv6-special-registry). Updating this table is a patch-level change, listed under "Upgrade notes" when it refuses something previously accepted.

## Residual risks of delete and export

- **Root delete.** Sn1per deletes a workspace with a root `rm -Rf` of its directory. The server refuses the delete when a local user could swap the workspace for a link (`tree_insecure`), which makes `delete_workspace` unusable on Sn1per Community Edition after a scan until the operator removes group and world write access. Even when the check passes, the workspace directory itself may be world-writable (Sn1per makes it so after scans), so anything a local user places inside it is deleted with it. `rm -Rf` does not follow links inside the tree. Do not enable destructive tools on shared hosts.
- **Hard links.** On hosts where `fs.protected_hardlinks` is off, a local user can hard-link the operator's files into the loot tree. The readers and export skip files with more than one link; `grep_loot` cannot, and `sniper_status` warns with `protected_hardlinks_off`.
- **Engine-wide references remain.** Deleting a workspace does not remove engine-wide references to it (for example Sn1per's notification log, its list of all targets, and Sn1per Enterprise UI workspace assignments).
- **Exports hold loot.** An export archive has mode 0600 and leaves out the `credentials/` folder and known credential files unless `include_credentials=true`. Sn1per also copies hashes and cleartext credentials into other loot folders, so treat every export as sensitive.

## Recommended deployment

1. **A dedicated, single-user scanning VM or container.** Do not run Sn1per or the MCP server on a shared host or on your workstation.
2. **The server as a non-root user** with the named sudoers drop-in ([install.md](install.md#privilege-setup)), or as root inside a dedicated container ([remote.md](remote.md)).
3. **Root-owned configuration.** Keep the scope and env files at `/etc/sn1per-mcp/scope` and `/etc/sn1per-mcp/env`, owned `root:root` with mode 0644, and register the server with `--env-file /etc/sn1per-mcp/env`.
4. **Client approval.** Require approval for `sniper_scan`, `cancel_scan`, `delete_workspace` and `export_workspace`, and never auto-approve them ([clients.md](clients.md#recommended-approval-settings)).
5. **Deny shell and file-write tools** for the scope file, the env file, the client configuration and `sudo` if your agent has them.
6. **Intrusive modes and destructive tools off** unless the engagement needs them.
7. **Set `SNIPER_MCP_AUTHORIZATION_REF`** to your statement-of-work or ticket id, so every audit line carries it.
8. **Append-only audit log** where the record matters ([configuration.md](configuration.md#append-only-recipe)).
9. **An egress filter** for the scanning host, because the scope check cannot see Sn1per's follow-up traffic.

### Egress filter recipe (documented, unverified)

This `nftables` example rejects traffic from root-owned processes (Sn1per and its tools run as root) to link-local addresses (RFC 3927), the cloud metadata addresses, the AWS IPv6 metadata range, and the private ranges (RFC 1918, RFC 6598, RFC 4193) that are not in your scope.

The chain sits on the `output` hook, so it filters only processes of the host or container it is loaded in. It does not filter a scanning container on a Docker bridge network when you load it on the Docker host: the host forwards that container's packets, and forwarded packets have no owning process, so `meta skuid 0` never matches them. For a scanning container, use the [variant for containers](#scanning-containers-on-a-docker-bridge-network-documented-unverified).

The first rule accepts the packets of connections that already exist, so replies to inbound connections (an SSH session, a web UI) still leave the host, even when a root-owned listener sends them to a private client address. The first packet of a new outbound connection to a blocked range is not part of an existing connection, so it is still rejected. Connection tracking also counts a packet that answers traffic a remote host sent first (a UDP reply, for example) as part of that exchange, so such packets are not filtered either.

On cloud hosts the same rule also blocks root-owned cloud agents that use the metadata service, so apply it only on a dedicated scanning VM, or inside a dedicated scanning container. If your DNS resolver has a private address, add it to the allow sets, or Sn1per's own lookups fail.

```text
#!/usr/sbin/nft -f
# /etc/nftables.d/sn1per-egress.nft - documented, unverified example
table inet sn1per_egress {
    # Private addresses that ARE in your scope, and a private DNS resolver if you use one.
    set allow_v4 {
        type ipv4_addr
        flags interval
        # elements = { <in-scope private range>, <resolver address> }
    }
    set allow_v6 {
        type ipv6_addr
        flags interval
        # elements = { <in-scope private range> }
    }
    # RFC 1918, RFC 6598 (includes 100.100.100.200), link-local RFC 3927
    # (includes 169.254.169.254 and 169.254.170.2), and the Azure platform endpoint.
    set block_v4 {
        type ipv4_addr
        flags interval
        elements = { 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12,
                     192.168.0.0/16, 168.63.129.16 }
    }
    # RFC 4193 (includes the AWS metadata range fd00:ec2::/32) and IPv6 link-local.
    set block_v6 {
        type ipv6_addr
        flags interval
        elements = { fc00::/7, fe80::/10 }
    }
    chain output {
        type filter hook output priority filter; policy accept;
        # Replies to inbound connections (SSH, a web UI) and their ICMP errors.
        ct state established,related accept
        meta skuid 0 ip daddr @allow_v4 accept
        meta skuid 0 ip6 daddr @allow_v6 accept
        meta skuid 0 ip daddr @block_v4 counter reject with icmpx type admin-prohibited
        meta skuid 0 ip6 daddr @block_v6 counter reject with icmpx type admin-prohibited
    }
}
```

Load it with `sudo nft -f /etc/nftables.d/sn1per-egress.nft` and check the counters with `sudo nft list table inet sn1per_egress`. Loopback traffic is not blocked.

This recipe has not been run as written. Before you rely on it, test it on a disposable scanning VM: check the file with `sudo nft -c -f /etc/nftables.d/sn1per-egress.nft`, load it, run one scan of a lab target you are authorized to test, and confirm that the counters rose for a probe to a blocked range. With the rules loaded, confirm that an SSH session from a private client address and the Sn1per Professional or Enterprise web UI from a private client address still work.

#### Scanning containers on a Docker bridge network (documented, unverified)

Traffic from a container on a Docker bridge network passes the Docker host's `forward` hook, not its `output` hook, so filter it there. Rules on the Docker host are the stronger choice, because nothing inside the container can change them. A container started with `--network host` shares the host's network stack instead; for it, the recipe above applies unchanged on the host.

**On the Docker host (preferred).** Give the scanning container its own bridge network with a fixed interface name, so that the rules can match it:

```bash
docker network create -o com.docker.network.bridge.name=<bridge-interface> <network>
```

Add `--network <network>` to the `docker run` command of [recipe A](remote.md#recipe-a-docker-exec--i-into-a-long-lived-sn1per-community-edition-container). If the container already runs and you do not want to recreate it (recreating a Sn1per Professional container changes its licence fingerprint), match the bridge interface of the network it already uses instead. `docker network inspect -f '{{index .Options "com.docker.network.bridge.name"}}' <network>` prints the interface name when the network was created with one (it prints `docker0` for Docker's default `bridge` network); when it prints nothing, the interface is `br-` followed by the first 12 characters of the network id, which `docker network inspect -f '{{.Id}}' <network>` prints. The trade-off is that the rules then filter every container on that network.

Then, on the Docker host, change the recipe above in two places and load the file again. First, replace its `output` chain with this version, which adds one rule after the first: it accepts the Docker host's own connections to the containers on the scanning bridge.

```text
    chain output {
        type filter hook output priority filter; policy accept;
        # Replies to inbound connections (SSH, a web UI) and their ICMP errors.
        ct state established,related accept
        # The Docker host's own connections to containers on <bridge-interface>, such as
        # Docker's port-publishing proxy, which runs as root.
        oifname "<bridge-interface>" accept
        meta skuid 0 ip daddr @allow_v4 accept
        meta skuid 0 ip6 daddr @allow_v6 accept
        meta skuid 0 ip daddr @block_v4 counter reject with icmpx type admin-prohibited
        meta skuid 0 ip6 daddr @block_v6 counter reject with icmpx type admin-prohibited
    }
```

Second, add these two chains inside `table inet sn1per_egress`, so that they use the same allow and block sets:

```text
    # Traffic that a scanning container on <bridge-interface> sends through the host.
    chain forward {
        type filter hook forward priority filter; policy accept;
        # Replies to inbound connections, such as a published web UI.
        ct state established,related accept
        iifname "<bridge-interface>" ip daddr @allow_v4 accept
        iifname "<bridge-interface>" ip6 daddr @allow_v6 accept
        iifname "<bridge-interface>" ip daddr @block_v4 counter reject with icmpx type admin-prohibited
        iifname "<bridge-interface>" ip6 daddr @block_v6 counter reject with icmpx type admin-prohibited
    }
    # Traffic from the container to the Docker host's own addresses.
    chain input {
        type filter hook input priority filter; policy accept;
        # Replies to connections the Docker host opened, such as those of Docker's
        # port-publishing proxy.
        ct state established,related accept
        # IPv6 neighbour discovery with the gateway (not tracked by conntrack).
        iifname "<bridge-interface>" icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept
        iifname "<bridge-interface>" ip daddr @allow_v4 accept
        iifname "<bridge-interface>" ip6 daddr @allow_v6 accept
        iifname "<bridge-interface>" ip daddr @block_v4 counter reject with icmpx type admin-prohibited
        iifname "<bridge-interface>" ip6 daddr @block_v6 counter reject with icmpx type admin-prohibited
    }
```

These rules match the bridge interface, not a process owner. As in the recipe above, the first rule of each chain lets replies pass: a browser on a private client address that opens a published web UI port (the Sn1per Professional UI, for example) still gets its answers through the `forward` chain, while a new connection that the container opens to a blocked range is rejected. A browser on the Docker host itself (`localhost`), an SSH tunnel to a port published on `localhost`, and IPv6 clients when Docker's IPv6 NAT rules are off take another path: Docker's port-publishing proxy, a root process on the Docker host, opens a new connection from the gateway address to the container. Docker's default bridge addresses are private, so without the `oifname "<bridge-interface>" accept` rule the `output` chain rejects that connection and the web UI does not load. The rule also lets other processes of the Docker host reach the containers on that bridge, and nothing else. The `input` chain also stops the container from reaching services on the Docker host's private and link-local addresses, including its gateway address on the bridge; a public address of the Docker host stays reachable. The MCP server does not need those services, because the client reaches it through `docker exec`. A reject in this table holds even when Docker's own firewall rules accept the packet.

Add the resolver that the container uses to the allow sets. On a user-defined network, Docker's embedded DNS forwards lookups to the Docker host's upstream resolvers from the container's network namespace, so when that upstream has a private address (a home or office router, or the upstream behind `systemd-resolved`), the `forward` chain (or the `input` chain, when the resolver runs on the Docker host) rejects the container's lookups and the scans fail.

If the Docker host manages its firewall with `iptables` only, put the forward-side rules in Docker's `DOCKER-USER` chain, which sits on the forward path only, and the input-side rules in the `INPUT` chain. Match the bridge with `-i <bridge-interface>` in both, and start both with a rule for `-m conntrack --ctstate ESTABLISHED,RELATED`. In `DOCKER-USER`, let that rule and the allow-set rules continue with `-j RETURN` rather than `-j ACCEPT`: an `ACCEPT` there skips Docker's own forwarding rules, including its isolation between Docker networks. If you filter the Docker host's own output with `iptables`, accept `-o <bridge-interface>` there right after the established rule, for the reason given for the `output` chain above.

**Inside the container.** Install `nftables` in the container and load the recipe above unchanged in the container's own network namespace. There `meta skuid 0` matches, because the scan runs as root in the container. Recipe A grants the container `NET_ADMIN`, so root in the container can delete the table: this variant guards against mistakes, not against anything that runs as root in that container. The rules are also lost when the container is recreated.

These variants have not been run as written. Before you rely on them, apply both of them for recipe A on a disposable Linux Docker host, run one scan of a lab target in the container, and confirm that the counters rose for a probe from the container to a blocked range. With the rules loaded, confirm that an SSH session to the Docker host from a private client address still works, and that a published web UI (the Sn1per Professional UI, for example) still loads from a private client address, from the Docker host itself (localhost), through an SSH tunnel (ssh -L) to a port published on localhost, and from an IPv6 client if the Docker host serves IPv6.

## What the server never does

- It never sends telemetry. Its only network activity is the DNS lookups it makes to check hostname targets against your scope. (Sn1per's own update and licence checks are described in disclosure (c).)
- It never returns environment variables or their values (except the fields `sniper_status` reports), any file outside the configured loot tree, any file reached through a symbolic link, non-regular files, the audit log, or the internals of job records.
- It never asks for, stores or handles passwords. The sudo rule must be passwordless.
- It never passes Sn1per's configuration-file, target-file, update, task-deletion or export options to the CLI. A scan passes only the target, mode, workspace and (for port modes) port; `delete_workspace` passes only the workspace and Sn1per's workspace-delete option.
- It never touches Sn1per's update-check markers, and never writes Sn1per's own configuration.
- It never listens on a network port.

## Reporting a vulnerability

Report security issues privately through GitHub Private Vulnerability Reporting on this repository or by e-mail, as described in [SECURITY.md](https://github.com/1N3/sn1per-mcp/blob/main/SECURITY.md). Do not open a public issue.
