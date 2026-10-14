# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Untrusted-string sanitizing (J.6) and redaction (K) as used by job-log tails (L.5).

Secret-shaped values are assembled at run time (O.4): no literal in this file
has the shape of a real token.
"""

from __future__ import annotations

import pytest

from sniper_mcp import redact, sanitize
from tests import support

D = "-" * 5
HEX32 = "a1" * 16
HEX32B = "b2" * 16


def r(text: str) -> tuple[str, dict[str, int]]:
    return redact.redact(text)


# --- J.6 sanitizing ----------------------------------------------------------------------

@pytest.mark.parametrize(("raw", "clean"), [
    (b"\x1b[1;31mred\x1b[0m", "red"),
    (b"\x1b]0;window title\x07text", "text"),
    (b"\x1b]8;;http://x\x1b\\link", "link"),
    (b"\x1b(Bplain\x1bMx", "plainx"),
    (b"10%\r50%\r100%", "100%"),
    (b"line\r\nnext\r\n", "line\nnext\n"),
    (b"a\x00b\x07c\x7fd\x08e", "abcde"),
    ("a\u0085b".encode(), "ab"),
    (b"bad \xff byte", "bad \ufffd byte"),
    ("x\u200by\u202ez\ufeff".encode(), "x<U+200B>y<U+202E>z<U+FEFF>"),
    ("p\U000f0000q".encode(), "p<U+F0000>q"),  # Co
    ("n\u0378o".encode(), "n<U+0378>o"),  # Cn (unassigned)
    (b"tab\tkept\nnewline", "tab\tkept\nnewline"),
])
def test_sanitize_steps(raw, clean):
    assert sanitize.sanitize(raw).text == clean


def test_invisible_characters_are_dropped_and_counted():
    out = sanitize.sanitize("a\U000e0041b\ufe0fc\U000e0100d")
    assert out.text == "abcd" and out.invisible_removed == 3


def test_truncation_marks_the_cut():
    assert sanitize.truncate("abcdef", 10) == ("abcdef", False)
    assert sanitize.truncate("a" * 30, 20) == ("a" * 9 + "[truncated]", True)
    assert sanitize.truncate_tail("x" * 10 + "END", 12) == ("[truncated]D", True)


# --- K.2 rules, one fixture each ---------------------------------------------------------

def key_block(kind: str = "RSA ", lines: int = 3, end: bool = True) -> str:
    body = "\n".join("TUlJ" * 15 for _ in range(lines))
    block = f"{D}BEGIN {kind}PRIVATE KEY{D}\n{body}"
    return block + (f"\n{D}END {kind}PRIVATE KEY{D}" if end else "")


@pytest.mark.parametrize(("text", "expected", "counts"), [
    # 1 private keys: multi-line, one-line escaped, END without BEGIN, missing END
    (f"x {key_block()} y", "x [REDACTED:private-key] y", {"private-key": 1}),
    (f"{key_block('', 2)}\n{key_block('OPENSSH ', 2)}",
     "[REDACTED:private-key]\n[REDACTED:private-key]", {"private-key": 2}),
    ('{"k":"' + f"{D}BEGIN EC PRIVATE KEY{D}" + "\\nMHcC\\n" + f"{D}END EC PRIVATE KEY{D}"
     + '\\n"}', '{"k":"[REDACTED:private-key]\\n"}', {"private-key": 1}),
    ("TUlJ\nTUlJ\n" + f"{D}END PRIVATE KEY{D}\nafter", "[REDACTED:private-key]\nafter",
     {"private-key": 1}),
    (f"{D}BEGIN PGP PRIVATE KEY BLOCK{D}\nlQOY\n{D}END PGP PRIVATE KEY BLOCK{D}",
     "[REDACTED:private-key]", {"private-key": 1}),
    # 2-5 Kerberos and timeroast
    ("hash " + "$" + "krb5tgs$23$*u$D$s*$" + HEX32 + ":Pass1", "hash [REDACTED:krb5tgs]",
     {"krb5tgs": 1}),
    ("$" + "krb5asrep$23$u@D:" + HEX32, "[REDACTED:krb5asrep]", {"krb5asrep": 1}),
    ("$" + "krb5pa$18$u$D$" + HEX32, "[REDACTED:krb5pa]", {"krb5pa": 1}),
    ("$" + "sntp-ms$" + HEX32 + "$" + HEX32B, "[REDACTED:sntp-ms]", {"sntp-ms": 1}),
    # 6 NetNTLMv2 and v1
    ("bob::CORP:" + "11" * 8 + ":" + HEX32 + ":0101" + "00" * 20, "[REDACTED:netntlm]",
     {"netntlm": 1}),
    ("bob::CORP:" + "ab" * 24 + ":" + "cd" * 24 + ":" + "ef" * 8, "[REDACTED:netntlm]",
     {"netntlm": 1}),
    # 7 LM:NT pairs
    ("Administrator:500:" + HEX32 + ":" + HEX32B + ":::", "Administrator:500:"
     "[REDACTED:lm-ntlm]", {"lm-ntlm": 1}),
    # 8 crypt hashes
    ("root:" + "$" + "6$salt$" + "x" * 20 + ":19000", "root:[REDACTED:crypt-hash]",
     {"crypt-hash": 1}),
    ("$" + "DCC2$10240#user#" + HEX32, "[REDACTED:crypt-hash]", {"crypt-hash": 1}),
    # 9 potfile
    (HEX32 + ":Summer2026!", "[REDACTED:potfile]", {"potfile": 1}),
    ('"' + HEX32 + ':pw" tail', '"[REDACTED:potfile]" tail', {"potfile": 1}),
    # 10 base64 kirbi
    ("ticket doI" + "A" * 120, "ticket [REDACTED:kerberos-ticket]", {"kerberos-ticket": 1}),
    # 11 DOMAIN\user:password
    ("CORP\\alice:Winter2026", "CORP\\alice:[REDACTED:password]", {"password": 1}),
    # 12 nmap brute results and snmp community strings
    ("|     admin:ab - Valid credentials", "|     admin:[REDACTED:password] - Valid "
     "credentials", {"password": 1}),
    ("|   private - Valid credentials", "|   [REDACTED:password] - Valid credentials",
     {"password": 1}),
    # 13 Metasploit login results, quoted passwords up to the quote
    ("Login Successful: root:toor@host", "Login Successful: root:[REDACTED:password]",
     {"password": 1}),
    ("Success: 'bob:two words' (x)", "Success: 'bob:[REDACTED:password]' (x)",
     {"password": 1}),
    ("Success: 'CORP\\bob:two words'", "Success: 'CORP\\bob:[REDACTED:password]'",
     {"password": 1}),
    # 14 URL credentials
    ("ftp://anon:hunter2@files.app.example/x", "ftp://anon:[REDACTED:password]@"
     "files.app.example/x", {"password": 1}),
    # 15 Authorization headers keep the scheme word
    ("> Authorization: Basic " + "QWxh" * 4, "> Authorization: Basic "
     "[REDACTED:authorization]", {"authorization": 1}),
    ("Proxy-Authorization: tok" + "e" * 10, "Proxy-Authorization: [REDACTED:authorization]",
     {"authorization": 1}),
    # 16 cookies keep names and attributes
    ("Set-Cookie: sid=abc; Path=/; HttpOnly", "Set-Cookie: sid=[REDACTED:cookie]; Path=/; "
     "HttpOnly", {"cookie": 1}),
    ("Cookie: a=1; b=2", "Cookie: a=[REDACTED:cookie]; b=[REDACTED:cookie]", {"cookie": 2}),
    # 17 Slack webhook URLs
    ("post https://hooks.slack" + ".com/services/" + "T0/B0/" + "x" * 24,
     "post [REDACTED:slack-webhook]", {"slack-webhook": 1}),
    # 18 JWT
    ("jwt eyJ" + "a" * 20 + ".eyJ" + "b" * 20 + "." + "c" * 20, "jwt [REDACTED:jwt]",
     {"jwt": 1}),
    # 19-27 provider tokens
    ("id AKIA" + "Q" * 16, "id [REDACTED:aws-access-key-id]", {"aws-access-key-id": 1}),
    ("gh" + "p_" + "a" * 36, "[REDACTED:github-token]", {"github-token": 1}),
    ("github" + "_pat_" + "a" * 30, "[REDACTED:github-token]", {"github-token": 1}),
    ("glp" + "at-" + "a" * 20, "[REDACTED:gitlab-token]", {"gitlab-token": 1}),
    ("xox" + "b-" + "1" * 12 + "-abc", "[REDACTED:slack-token]", {"slack-token": 1}),
    ("AI" + "za" + "a" * 35, "[REDACTED:google-api-key]", {"google-api-key": 1}),
    ("ya" + "29." + "a" * 25, "[REDACTED:google-oauth-token]", {"google-oauth-token": 1}),
    ("sk" + "_live_" + "a" * 24, "[REDACTED:stripe-key]", {"stripe-key": 1}),
    ("sk" + "-proj-" + "a" * 30, "[REDACTED:api-key]", {"api-key": 1}),
    ("dckr" + "_pat_" + "a" * 24, "[REDACTED:api-key]", {"api-key": 1}),
    ("https://acct.blob.core.app.example/c?sv=1&sig=" + "a" * 20 + "&se=2",
     "https://acct.blob.core.app.example/c?sv=1&sig=[REDACTED:azure-sas]&se=2",
     {"azure-sas": 1}),
    # 28 sensitive keys (the engine's own config keys included)
    ('SHODAN_API_KEY="' + "s" * 20 + '"', 'SHODAN_API_KEY="[REDACTED:secret]"',
     {"secret": 1}),
    ("HUNTERIO_KEY=" + "h" * 12, "HUNTERIO_KEY=[REDACTED:secret]", {"secret": 1}),
    ("export TOMBAIO_KEY='" + "t" * 12 + "'", "export TOMBAIO_KEY='[REDACTED:secret]'",
     {"secret": 1}),
    ('"password": "' + "p" * 8 + '"', '"password": "[REDACTED:secret]"', {"secret": 1}),
    ("password: ab", "password: [REDACTED:secret]", {"secret": 1}),
    ("db_pass=x;host=a", "db_pass=[REDACTED:secret];host=a", {"secret": 1}),
    ("AccountKey=" + "k" * 20 + ";EndpointSuffix=x", "AccountKey=[REDACTED:secret];"
     "EndpointSuffix=x", {"secret": 1}),
    ("token=ab", "token=ab", {}),  # under 3 characters and not a password key
])
def test_each_rule(text, expected, counts):
    assert r(text) == (expected, counts)


def test_slack_webhook_in_a_key_value_line_is_counted_once():
    url = "https://hooks.slack" + ".com/services/" + "T0/B0/" + "y" * 24
    text, counts = r(f'SLACK_WEBHOOK_URL="{url}"')
    assert url not in text and counts == {"slack-webhook": 1}


def test_no_token_is_redacted_twice():
    done = "Authorization: Bearer [REDACTED:jwt] password=[REDACTED:secret]"
    assert r(done) == (done, {})
    once, first = r("password=" + "z" * 10 + " Cookie: a=" + "y" * 5)
    assert first == {"cookie": 1, "secret": 1}
    assert r(once) == (once, {})


def test_redaction_never_leaves_part_of_a_secret_around_the_cut():
    token = "gh" + "p_" + "b" * 40
    line = "x" * 1990 + token
    text, _ = r(line)
    cut, _ = sanitize.truncate(text, 2000)
    assert "bbbb" not in cut


def test_batched_line_redaction_equals_line_by_line():
    from tests import secret_factory

    samples = [line for s in secret_factory.RULE_SAMPLES for line in s.line.split("\n")]
    tricky = ["foo:", "password=abcdef", "Login Successful:", "root:toor", "x" * 31,
              "a1" * 16 + ":", "Authorization", ": Bearer abc", "key", "= value123",
              "[REDACTED:jwt] token=[REDACTED:secret]", "", "monkey business: 42",
              "[REDACTED:jwt]" + "a1" * 16 + ":plain", "x " + "-" * 5 + "END PRIVATE KEY"
              + "-" * 5, "QUJD" + "-" * 5 + "END PRIVATE KEY" + "-" * 5 + " tail"]
    noise = [f"P3 - MEDIUM, Header {i}, app.example:{i}, not set" for i in range(700)]
    lines = []
    for index, line in enumerate(noise):
        lines.append(line)
        if index % 7 == 0:
            lines.append(samples[index % len(samples)])
        if index % 11 == 0:
            lines.append(tricky[index % len(tricky)])
    expected = [redact.redact(line, record_line=True) for line in lines]
    assert redact.redact_lines(lines) == expected
    assert redact.redact_lines([]) == []


def test_prefilters_never_hide_a_match():
    from tests import secret_factory

    for sample in secret_factory.RULE_SAMPLES:
        for line in [sample.line, *sample.line.split("\n")]:
            for (kind, pattern, _build), prefilter in zip(redact._RULES, redact._PREFILTERS,
                                                          strict=True):
                if pattern.search(line) and kind != "secret":
                    assert prefilter(line), (kind, line)


# --- linear time on attacker-written input (fix round 1) ------------------------------------
# Loot lines reach 64 KiB, grep re-reads 8 MiB and both are attacker-written. Each case is
# a shape that made a rule (or rule 1's span search) scan quadratically; a quadratic
# pattern needs hours on 8 MiB, a linear one well under a second.

MIB8 = 8 * 1024 * 1024
BEGIN = f"{D}BEGIN RSA PRIVATE KEY{D}"
END = f"{D}END RSA PRIVATE KEY{D}"


def fill(unit: str, size: int = MIB8) -> str:
    return unit * (size // len(unit))


ADVERSARIAL = {
    # case: (K.2 rule numbers it targets, text)
    "netntlm-run": ((6,), lambda n: "a" * n + "::"),
    "netntlm-colons": ((6,), lambda n: fill("a::", n)),
    "domain-user-run": ((11,), lambda n: "a" * n + "\\"),
    "domain-user-steps": ((11,), lambda n: fill("a\\", n)),
    "valid-run": ((12,), lambda n: "a" * n + " - Valid credentials"),
    "valid-colons": ((12,), lambda n: fill("a:", n) + " XX - Valid credentials"),
    "success-run": ((13,), lambda n: "Success:" + "a" * n),
    "success-quotes": ((13,), lambda n: fill("Success:'", n)),
    "scheme-run": ((14,), lambda n: "a" * n + "://"),
    "scheme-chain": ((14,), lambda n: fill("a://b:", n)),
    "scheme-digits": ((14,), lambda n: "1" * n + "a://"),
    "authorization-blanks": ((15,), lambda n: fill("Authorization" + " " * 10, n)),
    "cookie-words": ((16,), lambda n: fill("Cookie ", n)),
    "jwt-dots": ((18,), lambda n: fill("eyJaaaa.", n)),
    "jwt-run": ((18,), lambda n: "eyJ" + "a" * n),
    "secret-keys": ((28,), lambda n: fill("a" * 200 + " ", n) + "key"),
    "secret-blanks": ((28,), lambda n: "password" + " " * n),
    "potfile-run": ((9,), lambda n: " " + "a" * n),
    "hex-pairs": ((7, 9), lambda n: fill("a1" * 20 + ":", n)),
    "kirbi-runs": ((10,), lambda n: fill("doI" + "A" * 90 + " ", n)),
    "crypt-dollars": ((2, 3, 4, 5, 8), lambda n: fill("$" + "1" + "$", n)),
    "tokens-glued": ((19, 20, 21, 22, 23, 24, 25, 26, 27),
                     lambda n: fill("glp" + "at-." + "AKIA" + "gh" + "p_" + "xox" + "b-"
                                    + "AI" + "za" + "ya" + "29." + "sk" + "_live_"
                                    + "sk" + "-?sig=", n)),
}
_RULE_NUMBERS = [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                 22, 23, 24, 25, 26, 27, 28]


@pytest.mark.parametrize("case", sorted(ADVERSARIAL))
def test_targeted_rules_are_linear_on_8_mib(case):
    numbers, build = ADVERSARIAL[case]
    text = build(MIB8)
    for number, (kind, pattern, _build) in zip(_RULE_NUMBERS, redact._RULES, strict=True):
        if number not in numbers:
            continue
        with support.deadline(4, f"rule {number} ({kind}) on {case}"):
            for _ in pattern.finditer(text):
                pass


def test_every_rule_on_every_adversarial_shape_and_a_64_kib_line():
    for case, (_numbers, build) in ADVERSARIAL.items():
        text = build(128 * 1024)
        with support.deadline(4, case):
            for _kind, pattern, _build in redact._RULES:
                for _ in pattern.finditer(text):
                    pass
            redact.redact(text[:65536])
            redact.redact_lines([text[:65536]] * 4)


@pytest.mark.parametrize("text", [
    fill(END),                                         # orphan END markers on one line
    fill("x" * 100 + END + "\n"),                      # one per line
    fill(BEGIN + "\\n" + "x" + END + " "),             # escaped one-line blocks
    fill(BEGIN + "\\n"),                               # escaped, no END
    fill(BEGIN + "\n"),                                # BEGIN lines without END
    f"{D}BEGIN " + fill("AAAA "),                      # a never-ending key type
    BEGIN + "\n" + fill(END + BEGIN + "\n"),            # chained END+BEGIN lines (round 2)
], ids=["orphan-ends", "orphan-end-lines", "escaped", "escaped-no-end", "begins", "words",
        "end-begin-chain"])
def test_rule_1_spans_are_linear_on_8_mib(text):
    with support.deadline(8, "rule 1 spans"):
        redact._key_spans(text)
        redact._key_spans(text, record_line=True)
        redact.private_key_line_numbers(text)
        redact.collapse_key_blocks(text.split("\n"))


def test_token_dense_lines_are_redacted_in_batches():
    lines = ["password=x"] * 200_000
    with support.deadline(10, "200,000 token lines"):
        out = redact.redact_lines(lines)
    assert out[0] == ("password=[REDACTED:secret]", {"secret": 1}) and out[-1] == out[0]


# --- rule anchors keep the leftmost match ------------------------------------------------------

@pytest.mark.parametrize(("text", "expected"), [
    ("1.2http://u:pw@h.app.example", "1.2http://u:[REDACTED:password]@h.app.example"),
    ("x|admin:ab - Valid credentials", "x|admin:[REDACTED:password] - Valid credentials"),
    ("::admin:ab - Valid credentials", "::admin:[REDACTED:password] - Valid credentials"),
    ("q'CORP\\bob:two words' z", "q'CORP\\bob:[REDACTED:password]' z"),
    ("x CORP\\bob:pw", "x CORP\\bob:[REDACTED:password]"),
    ("x\tbob::CORP:" + "11" * 8 + ":" + HEX32 + ":0101", "x\t[REDACTED:netntlm]"),
])
def test_start_anchored_rules_keep_their_matches(text, expected):
    assert r(text)[0] == expected


def test_no_rule_matches_across_a_newline_in_a_batch():
    lines = ["Success:", "user:pass", "Authorization", ": Bearer abcdefgh", "password",
             "= value123", "export", "TOKEN=abcdef", "Cookie", ": a=1",
             '"password"', ': "abcdef"']
    assert redact.redact_lines(lines) == [redact.redact(line, record_line=True)
                                          for line in lines]
    assert [text for text, _ in redact.redact_lines(lines)][:6] == lines[:6]


def test_text_after_a_token_is_not_at_a_token_boundary():
    line = "[REDACTED:jwt]" + HEX32 + ":plain"
    assert r(line) == (line, {})
    assert redact.redact_lines([line]) == [(line, {})]


def test_record_line_end_marker_takes_only_the_key_run():
    line = f"P1 - CRITICAL, Key leak, https://app.example/k, QUJD\\nQUJD{END}"
    text, counts = redact.redact(line, record_line=True)
    assert text == "P1 - CRITICAL, Key leak, https://app.example/k,[REDACTED:private-key]"
    assert counts == {"private-key": 1}
    window, _ = redact.redact(line)  # a grep or log window: from the start of the window
    assert window == "[REDACTED:private-key]"


def test_osc_sequences_never_span_lines():
    # The unterminated OSC loses only its two-character introducer; both lines stay.
    assert sanitize.sanitize("a\x1b]0;x\nb\x07c").text == "a0;x\nbc"


# --- fix round 2: linear coalescing, rule 28 on URLs ---------------------------------------------

SECRET = "v4lue" + "Q" * 8  # a value of a sensitive key (not token-shaped)


@pytest.mark.parametrize(("text", "expected"), [
    # The first query parameter after "?" or "#": the scheme ("https:") is not a key
    # whose value swallows the rest of the URL.
    (f"GET http://app.test/login?password={SECRET} HTTP/1.1",
     "GET http://app.test/login?password=[REDACTED:secret] HTTP/1.1"),
    (f"https://app.test/api?api_key={SECRET}&x=1",
     "https://app.test/api?api_key=[REDACTED:secret]&x=1"),
    (f"[+] http://192.0.2.10/?apikey={SECRET}", "[+] http://192.0.2.10/?apikey=[REDACTED:secret]"),
    (f"Location: /cb#access_token={SECRET}", "Location: /cb#access_token=[REDACTED:secret]"),
    (f"https://app.test/cb#state=1&id_token={SECRET}",
     "https://app.test/cb#state=1&id_token=[REDACTED:secret]"),
    (f"url: https://app.test/?secret={SECRET}", "url: https://app.test/?secret=[REDACTED:secret]"),
    # A JSON-quoted URL: the non-sensitive key "url" does not consume its quoted value.
    ('{"url":"https://a.test/?token=' + SECRET + '"}',
     '{"url":"https://a.test/?token=[REDACTED:secret]"}'),
    ('{"note": "see password=' + SECRET + ' here"}',
     '{"note": "see password=[REDACTED:secret] here"}'),
    (f"P2 - HIGH, Token in URL, https://app.test/?token={SECRET}, seen",
     "P2 - HIGH, Token in URL, https://app.test/?token=[REDACTED:secret], seen"),
    # Keys that do not start with a letter, and keys longer than 128 characters (judged by
    # their last 128 characters).
    (f"--password={SECRET}", "--password=[REDACTED:secret]"),
    ("a" * 130 + f"_PASSWORD={SECRET}", "a" * 130 + "_PASSWORD=[REDACTED:secret]"),
    # Unchanged: no sensitive key; a host after "://" or "@" is not a key.
    ("https://app.test/?q=1&page=2", "https://app.test/?q=1&page=2"),
    ("https://token.app.test:8443/x", "https://token.app.test:8443/x"),
    ("ssh://admin@secret.app.test:2222", "ssh://admin@secret.app.test:2222"),
])
def test_rule_28_reads_query_parameters_inside_urls(text, expected):
    out, counts = r(text)
    assert out == expected
    assert counts == ({"secret": 1} if "[REDACTED" in expected else {})
    assert redact.redact_lines([text]) == [(out, counts)]


def lines_of(unit: str, size: int = MIB8, width: int = 65535) -> list[str]:
    """``size`` characters of 64 KiB lines, each a repetition of ``unit``."""
    line = fill(unit, width)
    return [line] * (size // (width + 1))


# Shapes whose matches emit no token (rule 15 on a bare scheme word, rule 16 on a cookie
# without "=", rule 28 on keys that are not sensitive) and shapes for the rule 28 key and
# value split. Each runs in a few seconds on 8 MiB; quadratic coalescing took minutes.
LINEAR_8_MIB = {
    "rule-15-scheme-only": lambda: lines_of('Authorization":"Basic" '),
    "rule-16-no-equals": lambda: ["Cookie: abc"] * (MIB8 // 12),
    "rule-16-no-equals-parts": lambda: lines_of("Cookie: " + "a;" * 30 + " "),
    "rule-28-not-sensitive": lambda: lines_of("a=b "),
    "rule-28-key-chain": lambda: lines_of("a="),
    "rule-28-scheme-chain": lambda: lines_of("https:"),
    "rule-28-open-quotes": lambda: lines_of('k:"'),
    "rule-28-url-params": lambda: lines_of("http://a.test/?x=1&"),
    "rule-28-sensitive": lambda: lines_of(f"password={SECRET} "),
    "rule-28-long-keys": lambda: lines_of("a" * 300 + "_password=x "),
}


@pytest.mark.parametrize("case", sorted(LINEAR_8_MIB))
def test_tokenless_and_rule_28_shapes_are_linear_on_8_mib(case):
    from sniper_mcp import parsers

    lines = LINEAR_8_MIB[case]()
    with support.deadline(30, f"redact_lines on {case}"):
        redact.redact_lines(lines)
    # One block of 8 MiB, past the 256 KiB batch cap: the rules themselves are linear.
    with support.deadline(30, f"one 8 MiB block of {case}"):
        redact._redact_block(lines)
    data = ("\n".join(lines) + "\n").encode()
    with support.deadline(30, f"file_lines on {case}"):
        parsers.file_lines(data, parsers.Options())
    with support.deadline(30, f"redact on one 64 KiB line of {case}"):
        redact.redact(lines[0])


def test_coalesce_joins_each_run_once():
    pieces = [("a", None)] * 100_000 + [("[REDACTED:x]", "x")] + [("b", None)] * 3 + [("", None)]
    assert redact._coalesce(pieces) == [("a" * 100_000, None), ("[REDACTED:x]", "x"),
                                        ("bbb", None)]
    plain = [("p" * 20, None)] * (MIB8 // 20)  # 8 MiB of plain pieces, one run
    with support.deadline(5, "coalescing 8 MiB of plain pieces"):
        assert redact._coalesce(plain) == [("p" * (MIB8 // 20 * 20), None)]


def test_batches_are_capped_by_size():
    lines = ["x" * 100_000] * 7 + ["y"] * 600
    blocks = list(redact._blocks(lines))
    assert [len(b) for b in blocks] == [2, 2, 2, 512, 89]
    assert all(len(b) <= redact._BATCH_LINES for b in blocks)
    assert all(sum(len(x) + 1 for x in b) <= redact._BATCH_CHARS for b in blocks if len(b) > 1)
