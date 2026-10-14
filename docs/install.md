# Install, upgrade and uninstall

This page covers installing the Sn1per MCP Server on the host where Sn1per runs, the privilege setup, upgrades and rollbacks, uninstalling, and the compatibility promise for 0.x releases.

In every command, replace `<user>` with the user who runs your MCP client. Root users use `/root` instead of `/home/<user>`.

## Platforms

"Verified" means exercised by the 0.9.0 verification run on 2026-10-12; "expected" means no known blocker, but not exercised.

| Dimension | Status |
|---|---|
| Server host OS | Linux. Kali Rolling (amd64): verified. Ubuntu 24.04: verified for the install, `--check`, an MCP session, upgrade and uninstall (no Sn1per engine and no scan were run on Ubuntu). Debian 12 and 13 and Parrot: expected. |
| Hosts with Python 3.10 as the system Python | Ubuntu 22.04 and Kali 2022.x (including the current Sn1per Community Edition AWS Marketplace image, Kali 2022.2): expected only with a uv-managed Python or a separately installed Python 3.11 or later (see below). The system Python 3.10 is not supported: pip, uv and pipx refuse the package on it (verified). |
| BlackArch | Expected; needs a `sniper` symlink on `PATH` (see below). |
| CPU architecture | amd64: verified. arm64: expected (the server is pure Python; Sn1per's tools vary). |
| Python | 3.12, 3.13 and 3.14: verified. 3.11: expected. |
| MCP SDK | `mcp` 1.30.0: verified. `mcp` 1.28.1 up to the latest 1.x release: expected. `mcp` 2.x is not supported. |
| Install methods | pipx as a normal user and as root, the pinned upgrade and rollback form, the uninstall steps and the uvx route over SSH: verified with a local copy of the package. The commands as published here run against PyPI once 0.9.0 is published. |
| macOS and Windows | Not supported as the server host. Run your MCP client there and connect to the Linux host over SSH ([remote.md](remote.md)). |

## Install Sn1per first

The MCP server does not include Sn1per. Install one of these first:

- **Sn1per Community Edition:** follow the instructions in the [Sn1per repository](https://github.com/1N3/Sn1per). There is no Community Edition apt package.
- **Sn1per Professional and Sn1per Enterprise:** follow the installation guide that came with your licence, or ask `support@sn1persecurity.com`.

Then run `sniper_status` (or `--check`, below) after installing the MCP server to confirm the edition it detected.

## Install with pipx (primary on Kali, Debian and Ubuntu)

Install as the user who runs the MCP client:

```bash
sudo apt install pipx
pipx ensurepath
```

Open a new shell so that `~/.local/bin` is on your `PATH`, then:

```bash
pipx install sn1per-mcp==0.9.0
```

Until you open a new shell, call the server by its absolute path, `/home/<user>/.local/bin/sn1per-mcp`. Use the absolute path in every client entry too, because GUI clients often start without `~/.local/bin` on their `PATH`.

- **Never run pipx with `sudo`.** `sudo pipx` installs under `/root`, where a client running as a normal user cannot use it.
- **Root users** run `pipx` as root directly and use `/root/.local/bin/sn1per-mcp`.

## Install with uv (secondary)

Install uv by following the [official uv installation guide](https://docs.astral.sh/uv/getting-started/installation/). Then the client runs the server through `uvx` with an exact version pin:

```bash
uvx --from sn1per-mcp==0.9.0 sn1per-mcp
```

The client needs `uvx` on its `PATH`. GUI clients often do not have it: use the absolute path to `uvx` in the client entry. `uv tool install` is not a documented install path for this package.

## Hosts whose system Python is 3.10

Ubuntu 22.04 and Kali 2022.x (including the Sn1per Community Edition AWS Marketplace image) ship Python 3.10, which the server does not support. Use one of these:

```bash
# uv-managed Python (uv downloads Python 3.12 for this tool only)
uvx --python 3.12 --from sn1per-mcp==0.9.0 sn1per-mcp
```

```bash
# pipx with a Python 3.11 or later interpreter that is already installed
pipx install --python python3.11 sn1per-mcp==0.9.0
```

With uvx, every `--check` on this page takes its uvx form. Run it once from a normal login session after you have created the env file ([Configure the scope](#configure-the-scope)); it also downloads Python 3.12 and the package, so the first client connection starts quickly:

```bash
/home/<user>/.local/bin/uvx --python 3.12 --from sn1per-mcp==0.9.0 sn1per-mcp --env-file /home/<user>/.config/sn1per-mcp/env --check
```

## Package name and PEP 668

- The package name uses the digit 1: `sn1per-mcp`. The name `sniper-mcp` is blocked on PyPI as a look-alike and is not an alias.
- Kali, Debian and Ubuntu mark their system Python as externally managed (PEP 668). Use pipx or uv. Never use `pip install --user`, `--break-system-packages`, `sudo pip` or `sudo pipx`.

## The console script

The command is `sn1per-mcp`. Check the installed version with:

```bash
/home/<user>/.local/bin/sn1per-mcp --version
```

It prints `sn1per-mcp 0.9.0`.

The package also installs an alias, `sniper-mcp-server`. Avoid it. Sn1per's `-dt` option and the Sn1per Professional licence-limit check stop every process whose command line contains `sniper`, which includes a server started through that alias (and through `python -m sniper_mcp`). Use `sn1per-mcp` everywhere.

## Configure the scope

Create the env file and set your scope before you register the server with a client:

```bash
mkdir -p /home/<user>/.config/sn1per-mcp
install -m 0600 /dev/null /home/<user>/.config/sn1per-mcp/env
```

Add this line to `/home/<user>/.config/sn1per-mcp/env` and replace the placeholder with the targets you are authorized to test:

```text
SNIPER_MCP_SCOPE=<authorized-targets>
```

The placeholder is refused as `scope_invalid`, so scans stay refused until you replace it. The scope grammar, the scope file and the hardened root-owned layout are in [configuration.md](configuration.md#scope).

## Privilege setup

Sn1per must run as root. If your MCP client runs as root, no sudo rule is needed. Otherwise the server runs the Sn1per CLI through `sudo -n` and needs a passwordless rule for that one file.

> **Warning:** a passwordless sudo rule for the Sn1per CLI is equivalent to full root access for the user it names. The CLI reads configuration files as root and Sn1per Community Edition makes its install world-writable during scans. Use a dedicated, single-user scanning VM or container. See [security-model.md](security-model.md).

1. Find the CLI realpath. `--check` prints it (`/usr/share/sniper/sniper` on a standard install); uvx users run the uvx form of this command ([above](#hosts-whose-system-python-is-310)):

   ```bash
   /home/<user>/.local/bin/sn1per-mcp --env-file /home/<user>/.config/sn1per-mcp/env --check
   ```

2. Create the named drop-in with `visudo`, which refuses to save a file with a syntax error:

   ```bash
   sudo visudo -f /etc/sudoers.d/sn1per-mcp
   ```

3. Put exactly one line in it, with the user and the realpath from step 1, and nothing after the path:

   ```text
   <user> ALL=(root) NOPASSWD: /usr/share/sniper/sniper
   ```

4. Set the mode and check the whole sudoers configuration:

   ```bash
   sudo chmod 0440 /etc/sudoers.d/sn1per-mcp
   sudo visudo -c
   ```

5. Verify the rule and the server's view of it:

   ```bash
   sudo -n -l /usr/share/sniper/sniper
   /home/<user>/.local/bin/sn1per-mcp --env-file /home/<user>/.config/sn1per-mcp/env --check
   ```

   `sudo -n -l <path>` prints the path when the rule allows it, and fails without asking for a password when it does not. `--check` exits 0 when scanning is ready.

The CLI realpath must be owned by root (otherwise scans are refused with `cli_untrusted`), and the `sudo` binary must be owned by root and not writable by group or others (otherwise `sudo_untrusted`).

If the edition or the CLI path changes later (for example after you move from Sn1per Community Edition to Sn1per Professional), update the rule with the new realpath from `--check` and restart your client session.

## BlackArch

BlackArch installs the CLI as `/usr/bin/sn1per` only. Sn1per calls itself as `sniper` while it scans, so the server refuses scans (`engine_path_missing`) until you add the link that `--check` suggests:

```bash
sudo ln -s /usr/share/sniper/sniper /usr/local/bin/sniper
```

Use the realpath that `--check` prints if it differs.

## Register with a client

Register the server with the env file as its only argument. For Claude Code:

```bash
claude mcp add sn1per -s user -- /home/<user>/.local/bin/sn1per-mcp --env-file /home/<user>/.config/sn1per-mcp/env
```

Other clients, configuration file locations and recommended approval settings: [clients.md](clients.md). Remote and container setups: [remote.md](remote.md).

## Upgrade

1. Install the new version with an exact pin.
   - pipx: remove the installed version, then install the new one:

     ```bash
     pipx uninstall sn1per-mcp
     pipx install sn1per-mcp==<new version>
     ```

   - uvx: change the pin in the client entry, for example `uvx --from sn1per-mcp==<new version> sn1per-mcp`
2. Read the "Upgrade notes" of every release between your version and the new one in the [CHANGELOG](https://github.com/1N3/sn1per-mcp/blob/main/CHANGELOG.md).
3. Restart your client sessions. MCP clients start the server when a session starts, so a running session keeps the old version.

`pipx upgrade` is not used here: it takes no version and always moves to the newest release. `pipx install --force` is not used either: when `uv` is on your `PATH`, recent pipx releases (for example pipx 1.15 on Kali) create the environment with uv, which will not replace an existing one, so the command fails and the old version stays installed. Uninstalling first works with every pipx version and both of its backends. `pipx uninstall` removes only the package: your env file, the state directory (audit log and job records) and the client registration stay. If the install step fails, for example because of a mistyped version, run it again with the right version before you restart your client.

## Rollback

Remove the installed version and install the older one, then restart your client sessions:

```bash
pipx uninstall sn1per-mcp
pipx install sn1per-mcp==<older version>
```

uvx users change the pin in the client entry back to the older version.

## Uninstall

1. Stop running scans. Ask your client to run `scan_status` and then `cancel_scan` for each running job. Scans keep running after the client session ends.
2. Remove the client registration. For Claude Code:

   ```bash
   claude mcp remove sn1per -s user
   ```

   For other clients, delete the `sn1per` entry from their configuration file ([clients.md](clients.md)).
3. Remove the package:

   ```bash
   pipx uninstall sn1per-mcp
   ```

   uvx users clear the cached copy instead:

   ```bash
   uv cache clean sn1per-mcp
   ```

4. Remove the sudoers rule and check the remaining configuration:

   ```bash
   sudo rm /etc/sudoers.d/sn1per-mcp
   sudo visudo -c
   ```

5. SSH setups: remove the forced-command line from `~/.ssh/authorized_keys` on the Sn1per host, and remove the env file (`~/.config/sn1per-mcp/env`, or `/etc/sn1per-mcp/` in hardened setups).
6. Docker setups: run `docker exec <container> pipx uninstall sn1per-mcp`, and remove the state volume when you no longer need its contents (see step 7).
7. Before you delete the state directory (`~/.local/state/sn1per-mcp` by default), decide what to keep. The audit log (`audit.jsonl`) is the engagement record; `exports/` may contain credentials; `jobs/*.log` is raw, unredacted Sn1per output. Treat all of it as engagement evidence.
8. Leave the Sn1per loot alone. It belongs to Sn1per, not to the MCP server.

## Compatibility promise for 0.x

0.9.x is a beta. These rules apply until 1.0.0:

1. **Patch releases (0.9.x)** are backward compatible: no tool, parameter, environment variable, error code or output field is removed or renamed. Behaviour changes only to fix bugs or to tighten safety. A safety tightening that refuses something previously accepted is listed under "Upgrade notes".
2. **Minor releases (0.10, 0.11 and later)** may rename or remove tools, parameters or environment variables only with a deprecation alias that is kept for at least one minor release and announced in "Upgrade notes". Using an alias adds a `deprecated` warning to results and a line on stderr.
3. **Tool names are stable identifiers.** Clients key approval rules on `mcp__<server>__<tool>`, so a renamed tool keeps its old name registered for one minor release.
4. **`schema_version`.** Every structured result, audit record and job record carries `schema_version: "1"`. Fields may be added in any release, and consumers must ignore unknown fields. Removing or renaming a field, or changing its type or meaning, increases `schema_version` and is called out in "Upgrade notes".
5. **Error and warning codes** are stable. New codes may be added; the meaning of a code never changes.
6. **Scan modes** follow Sn1per. Modes may be added in any release. Removal follows rule 2 unless Sn1per itself drops the mode.
7. **Defaults:** a default that weakens safety never changes in a patch release. A default that strengthens safety may change in any release, with "Upgrade notes".
8. **Supported versions:** only the latest minor release receives fixes ([SECURITY.md](https://github.com/1N3/sn1per-mcp/blob/main/SECURITY.md)).
9. **1.0.0:** after the beta, the public surface becomes the 1.x stable contract, with no breaking changes within 1.x.
10. **Plugin API** version 1 is experimental during 0.x. Plugins pin `sn1per-mcp>=0.9,<0.10`.
11. **Published versions are immutable.** A wrong release is replaced by a new patch version. A PyPI yank does not reach installs pinned with `==`, so fixes are announced through GitHub releases and security advisories ([Get notified](https://github.com/1N3/sn1per-mcp#get-notified)).
12. **MCP SDK 2.x:** the package stays on `mcp>=1.28.1,<2` until the first `mcp` 1.x security advisory without a 1.x fix, or a 1.x end-of-life notice. Either one triggers a minor release that moves to `mcp` 2.x.
