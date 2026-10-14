# Contributing

Thank you for helping with the Sn1per MCP Server. This page explains the sign-off rule, how to set up a development environment, the test policy, the style rules and what a pull request needs.

By contributing you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Developer Certificate of Origin (DCO)

Every commit must be signed off. A sign-off certifies that you wrote the change or otherwise have the right to submit it under the project's license, as described in the [Developer Certificate of Origin](https://developercertificate.org/).

Sign off with `-s`:

```bash
git commit -s -m "Describe the change"
```

This adds a line such as `Signed-off-by: Your Name <you@users.noreply.github.com>` to the commit message. Contributions are accepted under the Apache License 2.0, the same license as the project (inbound equals outbound). There is no separate contributor license agreement.

## Development setup

You need Linux, Git and Python 3.11 or later. Sn1per is not needed for development or tests.

```bash
git clone https://github.com/1N3/sn1per-mcp.git
cd sn1per-mcp
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
```

`make venv` does the same in one step (it creates `.venv` and installs the package with the dev extra).

- Keep the quotes around `'.[dev]'`. zsh, the default shell on Kali, rejects the unquoted form.
- Always work in a virtual environment. Never use `pip install --user`, `--break-system-packages` or `sudo pip`.

`make help` lists the targets: `venv`, `test`, `lint`, `build`, `check` and `clean`.

### Keep local files out of Git

Keep personal notes, editor settings and AI-agent instruction files out of the repository with `.git/info/exclude` in your clone, not with `.gitignore`:

```bash
echo '<file name>' >> .git/info/exclude
```

The repository's release checks reject internal file names and paths, so they must never be committed.

## Test policy

The test suite must never touch a real system. In short:

- **No real scans.** No test executes a real `sniper` or `sudo`. Tests that launch scans run against stub CLIs and a stub `sudo` that refuse to run anything outside the test's temporary directory.
- **No network and no DNS.** Name resolution goes through an injectable resolver that tests replace with a fake mapping.
- **No real loot and no personal files.** Tests use synthetic loot fixtures and fake install trees in a temporary directory. Never copy real loot into the repository.
- **Secret-shaped values are generated at run time.** Never commit a value that looks like a real token, key or hash, even as a test fixture; build it by concatenation in the test helpers.
- **The guard cannot be switched off.** An interpreter-level guard blocks process creation, network access and reads of real Sn1per and home-directory paths during tests. There is no marker, flag or environment variable that enables real execution, and none will be accepted.

Run the tests:

```bash
make test
```

`make test` runs `pytest` inside a private network namespace when your system allows unprivileged user namespaces, and directly otherwise. You can also run `python -m pytest -q -p no:cacheprovider`.

## Style

- `ruff check` must pass (`make lint`).
- Every `.py` file starts with the two header lines `# SPDX-License-Identifier: Apache-2.0` and `# Copyright 2026 Sn1perSecurity LLC` (after a shebang, if any).
- Never use the em-dash character (U+2014) or any HTML entity for it, in code, comments, docs or commit messages. Use a hyphen (` - ` between clauses).
- Examples follow the example-value rule: target names under `.example` (or `.test` in tests), addresses from the documentation ranges `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24`, and the placeholder `<authorized-targets>` in every copy-paste configuration snippet. The IANA example domains under `.com`, `.net` and `.org` are real hosts: they appear only in tests of the rule that refuses them, and in the refusal examples of three docs pages.
- Docs name private and special address ranges by RFC or in words, not as literals.
- Plain English, no idioms. Every code block has a language tag.

Run `ruff` and the release consistency checks (scrub, em-dash, example values, links and version consistency) before you open a pull request:

```bash
make lint
```

`make lint` treats your clone as a development tree, so a local file that you keep out of Git with `.git/info/exclude` is listed in a note instead of failing the check. CI runs the strict mode, which you can reproduce with `make lint CHECK_FLAGS=`.

## Behaviour changes start with the docs

The documents under `docs/` describe the public behaviour: tools, parameters, error codes, settings and the security model. A change to behaviour starts there. Update the relevant page in the same pull request as the code, and describe the change under "Upgrade notes" in `CHANGELOG.md` when users need to act. Follow the [compatibility promise for 0.x](docs/install.md#compatibility-promise-for-0x): do not rename or remove a tool, parameter, environment variable, error code or output field without a deprecation alias.

## Pull request checklist

- [ ] Every commit is signed off (`git commit -s`).
- [ ] Tests are added or updated, and `make test` passes.
- [ ] `make lint` passes.
- [ ] Docs under `docs/` and the README are updated for any behaviour change.
- [ ] `CHANGELOG.md` has an entry, with "Upgrade notes" if users need to act.
- [ ] No real targets, loot, credentials, internal hostnames or personal paths in code, tests, docs or commit messages.

## Security issues

Do not open a public issue or pull request for a vulnerability. Follow [SECURITY.md](SECURITY.md).
