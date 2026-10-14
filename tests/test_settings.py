# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Configuration parsing (contract B.1, B.2, B.5)."""

from __future__ import annotations

import os

import pytest

from sniper_mcp import settings
from sniper_mcp.settings import ConfigError, load_settings

BASE = {"HOME": "/nonexistent-home-for-tests"}


def load(**env: str) -> settings.Settings:
    return load_settings({**BASE, **env}, euid=1000)


def problems(**env: str) -> list[str]:
    with pytest.raises(ConfigError) as raised:
        load(**env)
    return [p.var for p in raised.value.problems]


def test_defaults():
    s = load()
    assert s.edition == "auto"
    assert s.scan_enabled is True
    assert s.needs_sudo is True  # euid 1000 is not root
    assert s.scope == "" and s.scope_file is None and not s.scope_configured
    assert s.allow_any_target is False and s.allow_intrusive is False
    assert s.dns_policy == "strict" and s.cidr_cap == 16
    assert s.max_concurrent_scans == 2
    assert s.enable_destructive is False
    assert s.redact is True and s.reveal_secrets is False
    assert s.state_dir == "/nonexistent-home-for-tests/.local/state/sn1per-mcp"
    assert s.audit_log == s.state_dir + "/audit.jsonl"
    assert s.log_retention_days == 30
    assert s.plugins == ()


def test_needs_sudo_auto_is_false_for_root():
    assert load_settings(BASE, euid=0).needs_sudo is False


@pytest.mark.parametrize("value,expected", [
    ("1", True), ("TRUE", True), (" yes ", True), ("On", True),
    ("0", False), ("false", False), ("NO", False), ("off", False)])
def test_boolean_values(value, expected):
    assert load(SNIPER_MCP_ALLOW_INTRUSIVE=value).allow_intrusive is expected


def test_empty_string_means_unset():
    s = load(SNIPER_SCAN_ENABLED="", SNIPER_MCP_CIDR_CAP="", SNIPER_EDITION="")
    assert s.scan_enabled is True and s.cidr_cap == 16 and s.edition == "auto"


@pytest.mark.parametrize("var,value", [
    ("SNIPER_SCAN_ENABLED", "maybe"),
    ("SNIPER_MCP_CIDR_CAP", "7"),
    ("SNIPER_MCP_CIDR_CAP", "33"),
    ("SNIPER_MCP_CIDR_CAP", "0x10"),
    ("SNIPER_MCP_CIDR_CAP", "-16"),
    ("SNIPER_MCP_MAX_CONCURRENT_SCANS", "17"),
    ("SNIPER_MCP_LOG_RETENTION_DAYS", "3651"),
    ("SNIPER_MCP_DNS_POLICY", "loose"),
    ("SNIPER_EDITION", "community-plus"),
    ("SNIPER_BIN", "relative/sniper-bin"),
    ("SNIPER_INSTALL_DIR", "~/sn1per"),
    ("SNIPER_MCP_SCOPE_FILE", "scope.txt"),
    ("SNIPER_MCP_AUDIT_LOG", "audit.jsonl"),
    ("SNIPER_MCP_AUTHORIZATION_REF", "SOW\n1"),
    ("SNIPER_MCP_AUTHORIZATION_REF", "x" * 257),
    ("SNIPER_MCP_PLUGINS", "UPPER:rag"),
    ("SNIPER_MCP_PLUGINS", "no-colon"),
    ("MCP_TRANSPORT", "sse"),
    ("MCP_TRANSPORT", "streamable-http"),
])
def test_invalid_values_are_config_errors(var, value):
    assert var in problems(**{var: value})


_INTEGER_VARS = {
    "SNIPER_MCP_CIDR_CAP": (8, 32),
    "SNIPER_MCP_MAX_CONCURRENT_SCANS": (1, 16),
    "SNIPER_MCP_LOG_RETENTION_DAYS": (0, 3650),
}


@pytest.mark.parametrize("var", sorted(_INTEGER_VARS))
@pytest.mark.parametrize("value", ["9" * 5000, "1" + "0" * 4300, "0" * 11 + "16", " " + "7" * 20])
def test_oversized_integers_are_config_errors_not_crashes(var, value):
    """int() raises ValueError above 4,300 digits; that must stay a B.1 config error."""
    with pytest.raises(ConfigError) as raised:
        load(**{var: value})
    low, high = _INTEGER_VARS[var]
    assert [p.line() for p in raised.value.problems] == [
        f"sn1per-mcp: config error: {var}: expected a base-10 integer from {low} to {high}"]


def test_integers_with_a_few_leading_zeros_are_accepted():
    assert load(SNIPER_MCP_CIDR_CAP="0016").cidr_cap == 16


def test_every_problem_is_reported_at_once():
    found = problems(SNIPER_SCAN_ENABLED="maybe", SNIPER_MCP_CIDR_CAP="99", MCP_TRANSPORT="sse")
    assert set(found) == {"SNIPER_SCAN_ENABLED", "SNIPER_MCP_CIDR_CAP", "MCP_TRANSPORT"}


def test_problem_line_format():
    with pytest.raises(ConfigError) as raised:
        load(SNIPER_MCP_CIDR_CAP="99")
    assert raised.value.problems[0].line().startswith(
        "sn1per-mcp: config error: SNIPER_MCP_CIDR_CAP: ")


def test_stdio_transport_values_are_accepted():
    load(MCP_TRANSPORT="stdio")
    load(MCP_TRANSPORT="")


def test_edition_alias_and_values():
    assert load(SNIPER_EDITION="community").edition == "ce"
    assert load(SNIPER_EDITION="Enterprise").edition == "enterprise"


def test_plugins_pairs():
    s = load(SNIPER_MCP_PLUGINS="sn1per-mcp-extra:tools, other.dist:x_1")
    assert s.plugins == (("sn1per-mcp-extra", "tools"), ("other.dist", "x_1"))
    assert "SNIPER_MCP_PLUGINS" in problems(
        SNIPER_MCP_PLUGINS=",".join(f"d{i}:e" for i in range(17)))


def test_state_dir_from_xdg_and_explicit():
    assert load(XDG_STATE_HOME="/xdg").state_dir == "/xdg/sn1per-mcp"
    assert load(XDG_STATE_HOME="relative").state_dir.endswith("/.local/state/sn1per-mcp")
    assert load(SNIPER_MCP_STATE_DIR="/srv/state").state_dir == "/srv/state"


def test_missing_home_without_state_dir_is_an_error():
    with pytest.raises(ConfigError) as raised:
        load_settings({}, euid=1000)
    assert raised.value.problems[0].var == "SNIPER_MCP_STATE_DIR"
    assert load_settings({"SNIPER_MCP_STATE_DIR": "/srv/state"}, euid=1000).state_dir


def test_scope_configured_by_either_source():
    assert load(SNIPER_MCP_SCOPE="app.example").scope_configured
    assert load(SNIPER_MCP_SCOPE_FILE="/etc/scope-file").scope_configured
    assert not load(SNIPER_MCP_SCOPE="  ").scope_configured


def test_removed_variables_warn_once_each():
    lines = settings.removed_variable_warnings(
        {"RAG_TIMEOUT": "x", "MCP_PORT": "1", "SNIPER_MCP_JOB_LOG_DIR": "", "OTHER": "y",
         "SNIPER_MCP_LOOT_MAX_BYTES": "9"})
    assert lines == [
        "sn1per-mcp: warning: MCP_PORT is no longer supported and is ignored",
        "sn1per-mcp: warning: RAG_TIMEOUT is no longer supported and is ignored",
        "sn1per-mcp: warning: SNIPER_MCP_LOOT_MAX_BYTES is no longer supported and is ignored",
    ]


def test_only_the_three_removed_rag_names_warn():
    """Other names with the same prefix may be a plugin's own variables (M): no warning."""
    removed = [name for name in settings.REMOVED_VARS if name.startswith("RAG_")]
    assert len(removed) == 3 and "RAG_TIMEOUT" in removed
    env = {name: "x" for name in removed}
    env.update({"RAG_COLLECTION": "x", "RAG_TOP_K": "5"})
    lines = settings.removed_variable_warnings(env)
    assert lines == [f"sn1per-mcp: warning: {name} is no longer supported and is ignored"
                     for name in sorted(removed)]


# --- env file (B.5) -------------------------------------------------------

def test_env_file_grammar():
    text = ('# comment\n\nSNIPER_MCP_SCOPE="app.example,192.0.2.0/24"\n'
            "SNIPER_MCP_ALLOW_INTRUSIVE=1\r\nSNIPER_MCP_AUTHORIZATION_REF=SOW=1 x\n")
    values = settings.parse_env_file(text, "/cfg/env")
    assert values == {"SNIPER_MCP_SCOPE": "app.example,192.0.2.0/24",
                      "SNIPER_MCP_ALLOW_INTRUSIVE": "1",
                      "SNIPER_MCP_AUTHORIZATION_REF": "SOW=1 x"}


@pytest.mark.parametrize("line", [
    "SNIPER_MCP_SCOPPE=app.example",  # typo
    "export SNIPER_MCP_SCOPE=app.example",
    "sniper_mcp_scope=app.example",
    " SNIPER_MCP_SCOPE=app.example",
    "NO_EQUALS_SIGN",
    "MCP_TRANSPORT=stdio",  # not a B.2 variable
    "RAG_TIMEOUT=30",
])
def test_env_file_rejects_bad_lines(line):
    with pytest.raises(ConfigError):
        settings.parse_env_file(line + "\n", "/cfg/env")


def test_env_file_rejects_duplicates():
    with pytest.raises(ConfigError):
        settings.parse_env_file("SNIPER_MCP_SCOPE=a.example\nSNIPER_MCP_SCOPE=b.example\n", "/e")


def test_process_environment_wins_over_env_file():
    merged = settings.merge_env({"SNIPER_MCP_SCOPE": "app.example", "SNIPER_EDITION": ""},
                                {"SNIPER_MCP_SCOPE": "other.example", "SNIPER_EDITION": "ce",
                                 "SNIPER_MCP_REDACT": "1"})
    assert merged["SNIPER_MCP_SCOPE"] == "app.example"
    assert merged["SNIPER_EDITION"] == "ce"
    assert merged["SNIPER_MCP_REDACT"] == "1"


def _write(path, text, mode=0o600):
    path.write_text(text)
    path.chmod(mode)
    return str(path)


def test_load_env_file_ok(iso):
    path = _write(iso.tmp / "env", "SNIPER_MCP_SCOPE=app.example\n")
    assert settings.load_env_file(path) == {"SNIPER_MCP_SCOPE": "app.example"}


@pytest.mark.parametrize("case", ["relative", "missing", "group_writable", "world_writable",
                                  "symlink", "directory", "too_large", "not_utf8"])
def test_load_env_file_rejects_unsafe_files(iso, case):
    target = iso.tmp / "env"
    if case == "relative":
        path = "env"
    elif case == "missing":
        path = str(iso.tmp / "absent")
    elif case == "group_writable":
        path = _write(target, "SNIPER_MCP_SCOPE=a.example\n", 0o620)
    elif case == "world_writable":
        path = _write(target, "SNIPER_MCP_SCOPE=a.example\n", 0o602)
    elif case == "symlink":
        real = _write(iso.tmp / "real-env", "SNIPER_MCP_SCOPE=a.example\n")
        target.symlink_to(real)
        path = str(target)
    elif case == "directory":
        target.mkdir()
        path = str(target)
    elif case == "too_large":
        path = _write(target, "# " + "x" * (64 * 1024) + "\n")
    else:
        target.write_bytes(b"SNIPER_MCP_SCOPE=\xff\n")
        target.chmod(0o600)
        path = str(target)
    with pytest.raises(ConfigError) as raised:
        settings.load_env_file(path)
    assert raised.value.problems[0].var == "--env-file"


def test_load_env_file_rejects_other_owner(iso, monkeypatch):
    from sniper_mcp import paths

    path = _write(iso.tmp / "env", "SNIPER_MCP_SCOPE=a.example\n")
    real_geteuid = os.geteuid
    monkeypatch.setattr(paths, "TRUSTED_UID", real_geteuid() + 1)
    monkeypatch.setattr(os, "geteuid", lambda: real_geteuid() + 2)
    with pytest.raises(ConfigError):
        settings.load_env_file(path)
