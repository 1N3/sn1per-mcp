# Remote use: SSH, WSL2 and Docker

The Sn1per MCP Server uses stdio only, so it must run on the machine where Sn1per runs, and your MCP client must start it there. This page covers the setups where the client and Sn1per are not on the same Linux host.

## When you need this page

- Your MCP client runs on macOS or Windows, and Sn1per runs on a Kali VM, a VPS or another Linux host.
- Sn1per runs on a cloud instance, for example the Sn1per Community Edition AWS Marketplace image.
- Sn1per runs in WSL2 on a Windows machine.
- Sn1per runs in a Docker container.

In every recipe the configuration lives in an env file next to the server, passed with `--env-file`. A client's `env` map does not cross SSH, and does not reach WSL unless you list each variable in `WSLENV`, so the env file is the one place that always works.

"Verified" means exercised by the 0.9.0 verification run on 2026-10-12; "documented, unverified" means the recipe is published but was not run as written.

| Setup | Status |
|---|---|
| Client on another machine over SSH, Linux OpenSSH client | verified (Sn1per host: Kali Rolling, OpenSSH 10.5p1) |
| SSH with the uvx forced command (hosts whose system Python is 3.10) | verified for the connection (the 3.10 host's Python download was not run) |
| SSH from Windows (`ssh.exe`) or macOS clients, and registering the SSH command in a client application (the verified session used a test driver) | documented, unverified |
| WSL2 | documented, unverified |
| Docker recipe A (`docker exec -i` into a long-lived Sn1per Community Edition container) | documented, unverified (its steps 5 to 7 were run with a Kali-based Sn1per Community Edition container; step 5 is corrected since) |
| Docker recipe C (read-only loot sidecar) | documented, unverified |
| Sn1per Professional through `docker exec` | documented, unverified |
| macOS with Docker Desktop | documented, unverified |
| Docker recipe B (the MCP server as the container's entrypoint) | not recommended |

## SSH

The client starts the server over SSH with a dedicated key. On the Sn1per host, that key can do one thing only: start the server with its env file.

### 1. Set up the Sn1per host

On the Linux host where Sn1per runs, as the user that will own the key:

1. Install the server with pipx, create the env file with your scope, and add the sudoers rule, as described in [install.md](install.md).
2. Check the configuration from a normal login session:

   ```bash
   /home/<user>/.local/bin/sn1per-mcp --env-file /home/<user>/.config/sn1per-mcp/env --check
   ```

On a host whose system Python is 3.10 (for example the current Sn1per Community Edition AWS Marketplace image, Kali 2022.2), install uv and use the uv-managed Python form from [install.md](install.md#hosts-whose-system-python-is-310) instead of the pipx path. Run the check of step 2 in its uvx form instead, once, from a normal login session. It also downloads Python 3.12 and the package, so the first client connection starts quickly:

```bash
/home/<user>/.local/bin/uvx --python 3.12 --from sn1per-mcp==0.9.0 sn1per-mcp --env-file /home/<user>/.config/sn1per-mcp/env --check
```

The `authorized_keys` line in step 3 then starts the server through `uvx`:

```text
restrict,command="/home/<user>/.local/bin/uvx --python 3.12 --from sn1per-mcp==0.9.0 sn1per-mcp --env-file /home/<user>/.config/sn1per-mcp/env" ssh-ed25519 AAAA... sn1per-mcp
```

### 2. Create a dedicated key on the client machine

```bash
ssh-keygen -t ed25519 -f ~/.ssh/sn1per-mcp -C sn1per-mcp
```

Leave the passphrase empty, or load the key into an SSH agent that your GUI client can see. A GUI client cannot answer a passphrase prompt.

### 3. Restrict the key on the Sn1per host

Add the public key (`~/.ssh/sn1per-mcp.pub` on the client) to `/home/<user>/.ssh/authorized_keys` on the Sn1per host, on one line, with these options in front of it:

```text
restrict,command="/home/<user>/.local/bin/sn1per-mcp --env-file /home/<user>/.config/sn1per-mcp/env" ssh-ed25519 AAAA... sn1per-mcp
```

- `restrict` turns off port, agent and X11 forwarding, pseudo-terminal allocation and `~/.ssh/rc` for this key.
- `command="..."` is a forced command: whatever the client asks to run, sshd runs only the server with its env file.

### 4. Accept the host key once

The client entries below use `BatchMode=yes`, which refuses unknown host keys. Connect once from a terminal on the client machine to accept the host key:

```bash
ssh -T -i ~/.ssh/sn1per-mcp -o IdentitiesOnly=yes <user>@<host> sn1per-mcp < /dev/null
```

Before you answer `yes` to the host key prompt, compare the fingerprint it shows with the one the Sn1per host prints for its key, for example with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` run on that host: this key reaches a root-capable server. The server then starts, reads the end of its input and exits.

### 5. Test the connection

This sends one MCP `initialize` request through the restricted key. The answer is one line of JSON whose `serverInfo` names `sn1per-mcp` and version `0.9.0`:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"ssh-probe","version":"0"}}}' \
  | ssh -T -i ~/.ssh/sn1per-mcp -o IdentitiesOnly=yes -o BatchMode=yes <user>@<host> sn1per-mcp
```

Remember that this key still reaches a root-capable server. Protect it like any other credential for the Sn1per host.

### 6. Register the server in the client

`IdentitiesOnly=yes` is required. Without it, ssh may offer another key first (for example your default key). If sshd accepts that unrestricted key, the forced command does not apply: the client either fails with `sn1per-mcp: command not found`, or, where `~/.local/bin` is on the `PATH` of SSH commands, it starts the server without its env file and so without your scope.

The entries below are documented, unverified: the verified SSH session was driven by a test client with exactly these arguments, not by Claude Code or Claude Desktop (Claude Desktop is not yet tested with 0.9.0).

**Claude Code** (macOS or Linux client):

```bash
claude mcp add sn1per -s user -- ssh -T -i <dedicated key> -o IdentitiesOnly=yes -o BatchMode=yes <user>@<host> sn1per-mcp
```

**Claude Desktop** (`claude_desktop_config.json`), macOS or Linux client:

```json
{
  "mcpServers": {
    "sn1per": {
      "command": "ssh",
      "args": ["-T", "-i", "<dedicated key>", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "<user>@<host>", "sn1per-mcp"]
    }
  }
}
```

**Claude Desktop** on Windows uses the absolute path of the OpenSSH client (backslashes are doubled in JSON):

```json
{
  "mcpServers": {
    "sn1per": {
      "command": "C:\\Windows\\System32\\OpenSSH\\ssh.exe",
      "args": ["-T", "-i", "<dedicated key>", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "<user>@<host>", "sn1per-mcp"]
    }
  }
}
```

Replace `<dedicated key>` with the absolute path of the private key, for example `/Users/<you>/.ssh/sn1per-mcp` on macOS or `C:\\Users\\<you>\\.ssh\\sn1per-mcp` on Windows. Other clients take the same command and arguments ([clients.md](clients.md)).

To change the configuration, edit the env file on the Sn1per host and start a new client session.

## WSL2 (documented, unverified)

For a Windows client with Sn1per in a Kali WSL2 distribution:

1. Inside the WSL distribution, install the server, create the env file and add the sudoers rule as described in [install.md](install.md).
2. Point the client at `wsl.exe`. The client's `env` map does not reach WSL unless `WSLENV` lists each variable, so the env file carries the configuration:

   ```json
   {
     "mcpServers": {
       "sn1per": {
         "command": "wsl.exe",
         "args": ["-d", "kali-linux", "--", "/home/<user>/.local/bin/sn1per-mcp", "--env-file", "/home/<user>/.config/sn1per-mcp/env"]
       }
     }
   }
   ```

   The equivalent command line is `wsl.exe -d kali-linux -- /home/<user>/.local/bin/sn1per-mcp --env-file /home/<user>/.config/sn1per-mcp/env`. Use the name of your distribution if it differs (`wsl.exe -l -v` lists them).

## Docker

Sn1perSecurity publishes no container image for Sn1per or for the MCP server. You build the images locally.

> **Warning:** membership in the `docker` group on the client host is equivalent to root on that host. A client that runs `docker exec` can do anything Docker can.

### Recipe A: `docker exec -i` into a long-lived Sn1per Community Edition container

The MCP server is installed inside a Sn1per Community Edition container that keeps running, and the client starts it with `docker exec -i`. The container runs as root, so no sudo rule is needed. Scans keep running after the client session ends.

1. Build the Sn1per Community Edition image from its repository:

   ```bash
   git clone https://github.com/1N3/Sn1per.git
   cd Sn1per
   docker build -t <ce-image> .
   ```

2. Create named volumes for the loot and for the MCP server's state (job records and the audit log then survive container recreation):

   ```bash
   docker volume create sn1per-loot
   docker volume create sn1per-mcp-state
   ```

3. Start a long-lived container with the capabilities nmap needs:

   ```bash
   docker run -d --name <container> --init \
     --cap-add NET_ADMIN --cap-add NET_RAW \
     -v sn1per-loot:/usr/share/sniper/loot \
     -v sn1per-mcp-state:/root/.local/state/sn1per-mcp \
     <ce-image> sleep infinity
   ```

4. Install the MCP server inside the container, as root, with pipx:

   ```bash
   docker exec <container> sh -c 'apt-get update && apt-get install -y pipx && pipx install sn1per-mcp==0.9.0'
   ```

5. Create the env file on the Docker host, then copy it into the container. Create an empty file with mode 0600:

   ```bash
   install -m 0600 /dev/null sn1per-mcp.env
   ```

   Put this line in it, and replace the placeholder with your authorized targets:

   ```text
   SNIPER_MCP_SCOPE=<authorized-targets>
   ```

   Copy it into the container as a file that root owns, with mode 0600. Do not use `docker cp`: the copy keeps your user's uid, and the server, which runs as root in the container, refuses an env file that neither it nor root owns (`--check` exits 2):

   ```bash
   docker exec <container> mkdir -p /root/.config/sn1per-mcp
   docker exec -i <container> sh -c 'umask 077 && cat > /root/.config/sn1per-mcp/env' < sn1per-mcp.env
   ```

6. Check the configuration:

   ```bash
   docker exec <container> /root/.local/bin/sn1per-mcp --env-file /root/.config/sn1per-mcp/env --check
   ```

7. Register the server. Claude Code:

   ```bash
   claude mcp add sn1per -s user -- docker exec -i <container> /root/.local/bin/sn1per-mcp --env-file /root/.config/sn1per-mcp/env
   ```

   Clients with a JSON configuration:

   ```json
   {
     "mcpServers": {
       "sn1per": {
         "command": "docker",
         "args": ["exec", "-i", "<container>", "/root/.local/bin/sn1per-mcp", "--env-file", "/root/.config/sn1per-mcp/env"]
       }
     }
   }
   ```

Notes:

- The pipx install and the env file live in the container's filesystem. Repeat steps 4 and 5 after you recreate the container.
- Sn1per Community Edition makes its install world-writable inside the container on every scan, as on bare metal ([editions.md](editions.md#sn1per-community-edition-9x)).
- The scan reaches every network the container can reach, including internal, link-local and cloud metadata addresses that a hostile in-scope domain can point its subdomains at. The host egress filter recipe in [security-model.md](security-model.md#egress-filter-recipe-documented-unverified) does not filter this container: it matches root-owned processes of the host on the `output` hook, and the Docker host forwards the container's traffic instead. Use the variant for containers in [security-model.md](security-model.md#scanning-containers-on-a-docker-bridge-network-documented-unverified): either rules in the Docker host's forward path that match the container's bridge interface, or the recipe loaded inside the container. Root in the container holds `NET_ADMIN` in this recipe and can remove a filter loaded inside the container, so prefer the rules on the Docker host.

### Recipe C: read-only loot sidecar

A separate container reads the loot volume read-only and never scans. It needs no root and no sudo rule. This uses the introspection `Dockerfile` in this repository, which does not contain Sn1per and runs as a non-root user.

1. Build the image from a checkout of the release:

   ```bash
   git clone https://github.com/1N3/sn1per-mcp.git
   cd sn1per-mcp
   git checkout v0.9.0
   docker build -t <mcp-image> .
   ```

2. Register it with the loot volume mounted read-only:

   ```json
   {
     "mcpServers": {
       "sn1per": {
         "command": "docker",
         "args": ["run", "-i", "--rm",
                  "-v", "sn1per-loot:/usr/share/sniper/loot:ro",
                  "-e", "SNIPER_SCAN_ENABLED=false",
                  "-e", "SNIPER_LOOT_BASE=/usr/share/sniper/loot",
                  "<mcp-image>"]
       }
     }
   }
   ```

Notes:

- `sniper_scan` and `delete_workspace` refuse with `scan_disabled`; the read tools work.
- The container's user must be able to read the loot. Sn1per Community Edition leaves its loot world-readable; other installs may not.
- Each session starts a fresh container, and its state directory is discarded when the session ends. Keep destructive tools off in this recipe.

### Sn1per Professional through `docker exec`

If Sn1per Professional runs in a container, install the MCP server inside it with pipx as root (step 4 of recipe A), create the env file (step 5), and register `docker exec -i <container> /root/.local/bin/sn1per-mcp --env-file /root/.config/sn1per-mcp/env`.

- The install is lost when the container is recreated; repeat the steps afterwards.
- **Give the container a fixed MAC address** (`docker run --mac-address <mac-address>`, or `mac_address:` in a Compose file) when you create it. Docker gives a container a new MAC address when it is restarted or reconnected to a network, and every Sn1per 11.x engine (SE, Professional and Enterprise) fingerprints the host by that address on the first scan of each day: with a new fingerprint, Sn1per deletes its own install (`sniper`, `modes/`, `conf/`, `pro/` and more). The MCP server then reports the scan as failed (`engine_files_missing` or `engine_removed`). Recreating the container with a new MAC address has the same effect, and can also trigger the licence protections described in [editions.md](editions.md#sn1per-professional-2026).
- Mount a named volume at `/root/.local/state/sn1per-mcp` to keep job records and the audit log.
- The egress note of recipe A applies here too: filter the container's traffic on the Docker host's forward path ([security-model.md](security-model.md#scanning-containers-on-a-docker-bridge-network-documented-unverified)). To avoid recreating the container, match the bridge interface of the network it already uses (found with `docker network inspect`), at the cost of filtering every container on that network. Keep the `output` chain rule for the bridge interface that the variant adds: without it, the published web UI fails from the Docker host itself and through an SSH tunnel, because Docker's port-publishing proxy then cannot reach the container.

### macOS with Docker Desktop (documented, unverified)

Recipe A should work on Docker Desktop for macOS with the same commands. Network scanning from inside Docker Desktop's virtual machine can behave differently from a Linux host (for example raw-socket port scans), so verify the results on a lab target first. The host-side egress filter for containers needs a Linux Docker host; on Docker Desktop, use the [variant loaded inside the container](security-model.md#scanning-containers-on-a-docker-bridge-network-documented-unverified).

### Recipe B: not recommended

Running the MCP server as the container's entrypoint (`docker run -i --rm` of a combined Sn1per and MCP image) ends every scan when the client session ends, because the container stops with its main process. Use recipe A instead.
