# MCP clients

The Sn1per MCP Server is a local stdio server: your MCP client must be able to start a local process. This page lists the clients tested with 0.9.0, a configuration snippet for each, and the approval settings we recommend. Only clients that passed the 0.9.0 client tests (2026-10-12) are listed as verified.

## Tested clients

| Client | Configuration location | Elicitation (delete and export) | Annotations honoured | Server instructions shown | Tool-name prefix | Status |
|---|---|---|---|---|---|---|
| Claude Code | `claude mcp add` (user scope) | yes in interactive sessions; `claude -p` without an SDK host cancels the confirmation | no: read tools need an allow rule too, and `ask` rules are honoured in every permission mode | yes | `mcp__sn1per__` (plugin route: `mcp__plugin_sn1per_sn1per__`) | verified (2.1.284) |
| Codex CLI | `~/.codex/config.toml` | declared; `codex exec` declines the confirmation; the interactive interface is not yet tested | yes: tools marked destructive need approval, `export_workspace` does not unless you ask for it (see below) | yes | the `mcp__sn1per__` namespace | verified in `codex exec` only (0.125.0) |
| Web, mobile and remote-connector clients (for example claude.ai or ChatGPT connectors) | - | - | - | - | - | not supported in 0.9.0 (stdio only) |

"Elicitation" decides whether `delete_workspace` and `export_workspace` work: they ask the human to type the workspace name through MCP form elicitation, and clients without it get `elicitation_unsupported`. Headless runs answer the prompt themselves: `claude -p` without an SDK host cancels it and `codex exec` declines it, so nothing is deleted or exported and the result carries `confirmation: "cancelled"` or `"declined"`, not an error. A program that hosts Claude Code through its SDK receives the prompt and may answer it, which is the agent-answers-for-the-human risk described in [security-model.md](security-model.md). `sniper_status` reports what your client declared in `client.elicitation`.

Claude Code was tested as the real client with a scripted local model, and Codex CLI in `codex exec` with a scripted model service. Other clients that start local stdio servers, for example Claude Desktop, VS Code agent mode, Cursor and Gemini CLI, are not yet tested with 0.9.0; see [Other clients](#other-clients).

## Before you register

1. Install the server and create the env file ([install.md](install.md)).
2. Run `sn1per-mcp --env-file <env file> --check` with the same env file the client entry will use.
3. Use absolute paths in every entry. GUI clients often start without `~/.local/bin` (pipx) or the `uvx` location on their `PATH`. The examples use `/home/<user>/.local/bin/sn1per-mcp`; root users use `/root/.local/bin/sn1per-mcp`.
4. Use the registration key `sn1per`. Approval rules and tool names are keyed on it (`mcp__sn1per__sniper_scan` in Claude Code).

MCP clients start the server when a session starts. After any change to the env file or the client entry, start a new session.

## Claude Code

```bash
claude mcp add sn1per -s user -- /home/<user>/.local/bin/sn1per-mcp --env-file /home/<user>/.config/sn1per-mcp/env
```

Check with `claude mcp list`, and remove with `claude mcp remove sn1per -s user`. Claude Code documentation: [Connect Claude Code to tools via MCP](https://code.claude.com/docs/en/mcp).

The confirmation of `delete_workspace` and `export_workspace` appears as a form in interactive sessions: type the workspace name and choose Accept, or press Esc to cancel. Claude Code may show the message on one line cut at the window width; the message therefore starts with what is about to happen, and the text field repeats the risk.

### Claude Code plugin (marketplace route)

This repository is also a Claude Code plugin marketplace. The plugin starts the server through uvx, so it needs uv installed and `uvx` on the client's `PATH`. It reads `SNIPER_MCP_SCOPE`, `SNIPER_MCP_SCOPE_FILE` and `SNIPER_MCP_AUTHORIZATION_REF` from the environment Claude Code starts with; an unset variable reaches the server as an empty value, which counts as not set.

```text
/plugin marketplace add 1N3/sn1per-mcp
```

Then run `/plugin`, open the marketplace `sn1per-mcp` and install its plugin `sn1per`.

Through the plugin the tools have the prefix `mcp__plugin_sn1per_sn1per__` instead of `mcp__sn1per__`, so the approval rules must use that prefix ([below](#recommended-approval-settings)). Register the server by one route only: with both, the model sees every tool twice. The variable expansion and the prefix were tested with Claude Code 2.1.284; the uvx download the plugin runs is checked when 0.9.0 is published.

## Codex CLI

Add the server to `~/.codex/config.toml`, together with the approval setting for `export_workspace`:

```toml
[mcp_servers.sn1per]
command = "/home/<user>/.local/bin/sn1per-mcp"
args = ["--env-file", "/home/<user>/.config/sn1per-mcp/env"]

[mcp_servers.sn1per.tools.export_workspace]
approval_mode = "prompt"
```

Codex CLI uses the tool annotations to decide what needs approval: tools marked destructive (`sniper_scan`, `cancel_scan`, `delete_workspace`) need it, but `export_workspace` is not marked destructive and would run without approval. The `approval_mode = "prompt"` lines close that gap; `default_tools_approval_mode = "prompt"` under `[mcp_servers.sn1per]` makes every tool of this server ask. Never set `approval_mode = "approve"` for the four tools that change state.

## Other clients

These clients start local stdio servers but are not yet tested with 0.9.0. Use the same absolute command and the `--env-file` argument as in the Claude Code entry, under the server key `sn1per`, in the client's own configuration file: Claude Desktop `claude_desktop_config.json` (Linux beta; on macOS and Windows use the [SSH recipe](remote.md#ssh)), VS Code `mcp.json` (top-level key `servers`), Cursor `~/.cursor/mcp.json` or `.cursor/mcp.json`, Gemini CLI `~/.gemini/settings.json`. Keep their confirmation for the four tools that change state.

## Recommended approval settings

Always require approval for the four tools that change state, and never auto-approve them:

- `sniper_scan` (starts a root scan that sends traffic to the target)
- `cancel_scan`
- `delete_workspace`
- `export_workspace`

The read tools (`sniper_status`, `list_workspaces`, `scan_status`, `get_findings`, `get_ports`, `get_subdomains`, `get_technologies`, `grep_loot`) change nothing.

**Claude Code:** add this to your settings (for example `~/.claude/settings.json` for every project). The `ask` rules make Claude Code ask before each of the four tools; they win over `allow` rules, over the bypass-permissions mode and over auto mode, which interactive sessions now start in by default. Claude Code does not approve read tools from their annotations either, so the `allow` list spares you a prompt for each read:

```json
{"permissions": {"ask": ["mcp__sn1per__sniper_scan", "mcp__sn1per__cancel_scan", "mcp__sn1per__delete_workspace", "mcp__sn1per__export_workspace"], "allow": ["mcp__sn1per__sniper_status", "mcp__sn1per__list_workspaces", "mcp__sn1per__scan_status", "mcp__sn1per__get_findings", "mcp__sn1per__get_ports", "mcp__sn1per__get_subdomains", "mcp__sn1per__get_technologies", "mcp__sn1per__grep_loot"]}}
```

Do not add the four tools to an `allow` list. If you use the plugin route, the plain rules above do not apply to it; use the same rules with the plugin prefix:

```json
{"permissions": {"ask": ["mcp__plugin_sn1per_sn1per__sniper_scan", "mcp__plugin_sn1per_sn1per__cancel_scan", "mcp__plugin_sn1per_sn1per__delete_workspace", "mcp__plugin_sn1per_sn1per__export_workspace"]}}
```

With `claude -p` and no way to ask (`--permission-prompts none`), tools under an `ask` rule are denied.

**Codex CLI:** keep the `approval_mode = "prompt"` setting for `export_workspace` shown above, and do not run Codex in a mode that skips all approvals while this server is registered.

## Transcripts and data

- Tool results go to your client and from there to the model service it uses. Some clients route model traffic through the client vendor's own backend.
- Clients may store or sync conversation transcripts, including tool results, in the client vendor's cloud. Check your client's data settings against your engagement's data-handling rules.
- A locally hosted model keeps tool results on your own infrastructure. No local-model setup has been tested with 0.9.0.

## Clients that are not supported

Web, mobile and remote-connector clients (for example claude.ai or ChatGPT connectors) cannot start a local process and are not supported in 0.9.0. The server has no HTTP or SSE transport. If the tools do not appear in such a client, that is expected.
