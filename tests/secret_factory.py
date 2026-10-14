# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Secret-shaped test values, built at run time (contract O.4).

No literal in this file (or anywhere in the repository) has the shape of a real
secret: every value is assembled by concatenation when a test runs, so secret
scanners and the repository meta-test (O.5 P0-11) find nothing committed.

``RULE_SAMPLES`` holds one loot line per K.2 rule. Each entry gives the line,
the secret fragments that must never appear in a redacted result, and the
redaction type the rule counts. ``write_rule_fixtures`` writes one file per
rule into a workspace.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

DASHES = "-" * 5
HEX32 = "a1" * 16
HEX32B = "b2" * 16


def key_block(kind: str = "RSA ", lines: int = 3, body: str = "TUlJ" * 15,
              end: bool = True) -> str:
    """A private-key block of ``lines`` body lines."""
    text = "\n".join(body for _ in range(lines))
    block = f"{DASHES}BEGIN {kind}PRIVATE KEY{DASHES}\n{text}"
    return block + (f"\n{DASHES}END {kind}PRIVATE KEY{DASHES}" if end else "")


def one_line_escaped_key() -> str:
    return (f'{{"key":"{DASHES}BEGIN EC PRIVATE KEY{DASHES}' + "\\n" + "MHcC" * 10 + "\\n"
            + f'{DASHES}END EC PRIVATE KEY{DASHES}"}}')


def jwt(length: int = 20) -> str:
    return "eyJ" + "h" * length + ".eyJ" + "p" * length + "." + "s" * length


def github_token(length: int = 40) -> str:
    return "gh" + "p_" + "g" * length


def aws_key_id() -> str:
    return "AKIA" + "Q" * 16


def slack_webhook() -> str:
    return "https://hooks.slack" + ".com/services/" + "T0/B0/" + "w" * 24


@dataclass(frozen=True)
class Sample:
    rule: int
    kind: str
    line: str
    secrets: tuple[str, ...]


def _samples() -> list[Sample]:
    s: list[Sample] = []
    add = s.append
    add(Sample(1, "private-key", key_block(body="S0VZ" * 15), ("S0VZ",)))
    add(Sample(1, "private-key", one_line_escaped_key(), ("MHcC",)))
    add(Sample(1, "private-key", "UEFS" * 16 + "\n" + f"{DASHES}END PRIVATE KEY{DASHES}",
               ("UEFS",)))
    add(Sample(2, "krb5tgs", "$" + "krb5tgs$23$*svc$CORP$http/web*$" + HEX32 + ":Plain1",
               (HEX32, "Plain1")))
    add(Sample(3, "krb5asrep", "$" + "krb5asrep$23$alice@CORP:" + HEX32B, (HEX32B,)))
    add(Sample(4, "krb5pa", "$" + "krb5pa$18$alice$CORP$" + "c3" * 16, ("c3" * 16,)))
    add(Sample(5, "sntp-ms", "1000:" + "$" + "sntp-ms$" + "d4" * 16 + "$" + "e5" * 24,
               ("d4" * 16,)))
    add(Sample(6, "netntlm", "bob::CORP:" + "11" * 8 + ":" + "f6" * 16 + ":0101" + "00" * 20,
               ("f6" * 16,)))
    add(Sample(7, "lm-ntlm", "Administrator:500:" + HEX32 + ":" + HEX32B + ":::",
               (HEX32, HEX32B)))
    add(Sample(8, "crypt-hash", "root:" + "$" + "6$saltsalt$" + "C" * 40 + ":19000:0",
               ("C" * 40,)))
    add(Sample(9, "potfile", "c7" * 16 + ":Summer2026!", ("Summer2026!",)))
    add(Sample(10, "kerberos-ticket", "ticket doI" + "T" * 120, ("T" * 50,)))
    add(Sample(11, "password", "CORP\\alice:Winter2026x", ("Winter2026x",)))
    add(Sample(12, "password", "|     admin:ab - Valid credentials", (":ab ",)))
    add(Sample(12, "password", "|   commstr9 - Valid credentials", ("commstr9",)))
    add(Sample(13, "password", "[+] Login Successful: root:toorpass9@app.example",
               ("toorpass9",)))
    add(Sample(13, "password", "Success: 'CORP\\bob:two words here'", ("two words",)))
    add(Sample(14, "password", "ftp://anon:hunter2x@files.app.example/", ("hunter2x",)))
    add(Sample(15, "authorization", "Authorization: Bearer " + "Z" * 30, ("Z" * 30,)))
    add(Sample(16, "cookie", "Set-Cookie: sid=" + "k" * 24 + "; Path=/; HttpOnly",
               ("k" * 24,)))
    add(Sample(17, "slack-webhook", "notify " + slack_webhook(), ("w" * 24,)))
    add(Sample(18, "jwt", "token " + jwt(), ("h" * 20,)))
    add(Sample(19, "aws-access-key-id", "key " + aws_key_id(), ("Q" * 16,)))
    add(Sample(20, "github-token", "gh " + github_token(), ("g" * 36,)))
    add(Sample(21, "gitlab-token", "gl " + "glp" + "at-" + "L" * 22, ("L" * 22,)))
    add(Sample(22, "slack-token", "sl " + "xox" + "b-" + "1" * 12 + "-" + "N" * 20,
               ("N" * 20,)))
    add(Sample(23, "google-api-key", "g " + "AI" + "za" + "G" * 35, ("G" * 35,)))
    add(Sample(24, "google-oauth-token", "o " + "ya" + "29." + "O" * 30, ("O" * 30,)))
    add(Sample(25, "stripe-key", "s " + "sk" + "_live_" + "R" * 24, ("R" * 24,)))
    add(Sample(26, "api-key", "a " + "sk" + "-ant-" + "A" * 30, ("A" * 30,)))
    add(Sample(27, "azure-sas", "https://acct.blob.app.example/c?sv=1&sig=" + "V" * 24 + "&se=2",
               ("V" * 24,)))
    add(Sample(28, "secret", 'SHODAN_API_KEY="' + "x9" * 12 + '"', ("x9" * 12,)))
    add(Sample(28, "secret", 'HUNTERIO_KEY="' + "h7" * 10 + '"', ("h7" * 10,)))
    add(Sample(28, "secret", "TOMBAIO_KEY='" + "t5" * 10 + "'", ("t5" * 10,)))
    add(Sample(28, "slack-webhook", 'SLACK_WEBHOOK_URL="' + slack_webhook() + '"',
               ("w" * 24,)))
    add(Sample(28, "secret", "password: ab", ("password: ab",)))
    # Query parameters inside URLs: the first one after "?" or "#" too (fix round 2).
    add(Sample(28, "secret", "GET http://app.example/login?password=" + "u8" * 6 + " HTTP/1.1",
               ("u8" * 6,)))
    add(Sample(28, "secret", "[+] http://192.0.2.10/?apikey=" + "k6" * 8, ("k6" * 8,)))
    add(Sample(28, "secret", "Location: /cb#access_token=" + "a4" * 8, ("a4" * 8,)))
    add(Sample(28, "secret", '{"url":"https://app.example/?token=' + "j3" * 8 + '"}',
               ("j3" * 8,)))
    return s


RULE_SAMPLES: list[Sample] = _samples()


def write_rule_fixtures(workspace: Path, subdir: str = "output") -> list[tuple[str, Sample]]:
    """One file per sample under ``<workspace>/<subdir>/``; every line carries the marker
    ``RULEFIXTURE`` so a single grep finds them all. Returns (relative path, sample)."""
    written = []
    target = workspace / subdir
    target.mkdir(parents=True, exist_ok=True)
    for index, sample in enumerate(RULE_SAMPLES):
        name = f"rule{sample.rule:02d}-{index:02d}.txt"
        lines = [f"RULEFIXTURE {line}" for line in sample.line.split("\n")]
        (target / name).write_text("\n".join(lines) + "\n")
        written.append((f"{subdir}/{name}", sample))
    return written
