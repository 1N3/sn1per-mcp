# Security policy

## Reporting a vulnerability

Please report security issues privately, not in public issues, discussions or pull requests:

- **GitHub:** use "Report a vulnerability" on the [Security tab](https://github.com/1N3/sn1per-mcp/security) of this repository (GitHub Private Vulnerability Reporting), or
- **E-mail:** `support@sn1persecurity.com`, with "Security" in the subject.

Please include:

- the output of `sn1per-mcp --version`;
- your MCP client and its version;
- the Sn1per edition and engine version (from `sniper_status`: `edition.label`, `edition.engine_version` and `edition.engine_changelog_version`);
- the steps to reproduce, with real targets, hostnames, IP addresses, loot and credentials removed. Use `app.example` style names and `192.0.2.x` addresses instead.

## What happens next

- We acknowledge your report within 5 business days.
- We confirm the issue, agree a disclosure date with you, and keep you informed while we work on a fix.
- We publish fixes as a new patch release with a GitHub Security Advisory. Where a CVE is warranted, we request it through GitHub, which is a CVE Numbering Authority.

A PyPI yank does not reach installs pinned with `==`, so advisories and release notes are how users learn about a fix. See [Get notified](https://github.com/1N3/sn1per-mcp#get-notified).

## Scope

- **In scope:** this MCP server: input validation, target and scope checks, privilege handling, loot path confinement, redaction, tool behaviour, the audit log, and packaging.
- **Sn1per Community Edition:** report issues the same way and we will route them to the Sn1per project.
- **Sn1per Professional and Sn1per Enterprise:** customers should use their support channel.
- **Not vulnerabilities on their own:** behaviour that the [security model](https://github.com/1N3/sn1per-mcp/blob/main/docs/security-model.md) already documents as a limit or residual risk, such as the root-equivalent sudo rule, Sn1per's update and licence checks, or an agent that also has shell access as the same user. A way to make a documented control fail is in scope.

## Supported versions

Only the latest minor release receives security fixes.

| Version | Supported |
|---|---|
| 0.9.x | yes |
| earlier versions | no |

## Abuse

To report misuse of this software against your systems, e-mail `support@sn1persecurity.com`. We cannot control how third parties use open-source software, but we review every report.
