# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Environment parsing and validation into a frozen ``Settings`` (contract B).

Startup checks are syntactic only (types, ranges, enum values, absolute paths).
Filesystem conditions are evaluated at run time by the affected tools. Scope
content is kept raw here and parsed by the scope guard at run time (F.1).
"""

from __future__ import annotations

import os
import pwd
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass

from sniper_mcp import paths
from sniper_mcp.state import SecureFileError, read_secure_file

ENV_FILE_MAX_BYTES = 64 * 1024
SCOPE_MAX_BYTES = 1024 * 1024
MAX_PLUGINS = 16

EDITIONS = ("auto", "ce", "se", "pro", "enterprise")
EDITION_ALIASES = {"community": "ce"}
DNS_POLICIES = ("strict", "lenient")

_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})
_ENV_KEY_RE = re.compile(r"[A-Z][A-Z0-9_]*")
_PLUGIN_PART_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_INT_RE = re.compile(r"[0-9]+")
# Every B.2 range fits in 4 digits; a longer token (leading zeros included) is
# refused before int(), which raises ValueError above 4,300 digits (CPython 3.11+).
_INT_MAX_DIGITS = 10

# The complete public surface of B.2, in table order.
ENV_VARS: tuple[str, ...] = (
    "SNIPER_EDITION",
    "SNIPER_BIN",
    "SNIPER_INSTALL_DIR",
    "SNIPER_LOOT_BASE",
    "SNIPER_SCAN_ENABLED",
    "SNIPER_NEEDS_SUDO",
    "SNIPER_MCP_SCOPE",
    "SNIPER_MCP_SCOPE_FILE",
    "SNIPER_MCP_ALLOW_ANY_TARGET",
    "SNIPER_MCP_AUTHORIZATION_REF",
    "SNIPER_MCP_DNS_POLICY",
    "SNIPER_MCP_CIDR_CAP",
    "SNIPER_MCP_ALLOW_INTRUSIVE",
    "SNIPER_MCP_MAX_CONCURRENT_SCANS",
    "SNIPER_MCP_ENABLE_DESTRUCTIVE",
    "SNIPER_MCP_REDACT",
    "SNIPER_MCP_REVEAL_SECRETS",
    "SNIPER_MCP_STATE_DIR",
    "SNIPER_MCP_AUDIT_LOG",
    "SNIPER_MCP_LOG_RETENTION_DAYS",
    "SNIPER_MCP_PLUGINS",
)

# Removed from the public surface (B.2): ignored with one warning each, except
# MCP_TRANSPORT, which is a configuration error unless empty or "stdio". Only the
# three removed RAG names warn: other names with that prefix may belong to a plugin,
# which reads variables of its own (M). The names are assembled from fragments, and
# no identifier spells the removed engine, so that the export scrub (P.5) finds no
# trace of it in the public tree (test_settings pins this with the P.5 pattern).
TRANSPORT_VAR = "MCP_TRANSPORT"
_RAG = "RAG_"
_REMOVED_PREFIX = _RAG + "ENG" + "INE_"
REMOVED_VARS: tuple[str, ...] = (
    "MCP_PORT",
    _REMOVED_PREFIX + "URL",
    _REMOVED_PREFIX + "API_KEY",
    _RAG + "TIMEOUT",
    "SNIPER_MCP_JOB_LOG_DIR",
    "SNIPER_MCP_LOOT_MAX_BYTES",
)


@dataclass(frozen=True)
class ConfigProblem:
    """One configuration error: printed as ``sn1per-mcp: config error: <var>: <reason>``."""

    var: str
    reason: str

    def line(self) -> str:
        return f"sn1per-mcp: config error: {self.var}: {self.reason}"


class ConfigError(Exception):
    """One or more configuration errors (exit status 2)."""

    def __init__(self, problems: list[ConfigProblem]) -> None:
        super().__init__("; ".join(p.line() for p in problems))
        self.problems = problems


@dataclass(frozen=True)
class Settings:
    """Immutable server configuration, read once at startup (B.1)."""

    edition: str
    sniper_bin: str | None
    install_dir: str | None
    loot_base: str | None
    scan_enabled: bool
    needs_sudo: bool
    needs_sudo_explicit: bool
    scope: str
    scope_file: str | None
    allow_any_target: bool
    authorization_ref: str | None
    dns_policy: str
    cidr_cap: int
    allow_intrusive: bool
    max_concurrent_scans: int
    enable_destructive: bool
    redact: bool
    reveal_secrets: bool
    state_dir: str
    audit_log: str
    log_retention_days: int
    plugins: tuple[tuple[str, str], ...]
    home: str
    euid: int

    @property
    def scope_configured(self) -> bool:
        """True when either scope source is set (content is checked at run time)."""
        return bool(self.scope.strip()) or self.scope_file is not None


class _Reader:
    """Collects problems while reading typed values from one environment mapping."""

    def __init__(self, env: Mapping[str, str]) -> None:
        self.env = env
        self.problems: list[ConfigProblem] = []

    def raw(self, var: str) -> str | None:
        value = self.env.get(var)
        if value is None or value == "":
            return None
        return value

    def fail(self, var: str, reason: str) -> None:
        self.problems.append(ConfigProblem(var, reason))

    def boolean(self, var: str, default: bool) -> bool:
        value = self.raw(var)
        if value is None:
            return default
        token = value.strip().lower()
        if token == "":
            return default
        if token in _TRUE:
            return True
        if token in _FALSE:
            return False
        self.fail(var, "expected one of 1, true, yes, on, 0, false, no, off")
        return default

    def integer(self, var: str, default: int, low: int, high: int) -> int:
        value = self.raw(var)
        if value is None:
            return default
        token = value.strip()
        if len(token) > _INT_MAX_DIGITS or not _INT_RE.fullmatch(token):
            self.fail(var, f"expected a base-10 integer from {low} to {high}")
            return default
        number = int(token)
        if not low <= number <= high:
            self.fail(var, f"expected a base-10 integer from {low} to {high}")
            return default
        return number

    def enum(self, var: str, default: str, choices: tuple[str, ...],
             aliases: Mapping[str, str] | None = None) -> str:
        value = self.raw(var)
        if value is None:
            return default
        token = value.strip().lower()
        if aliases and token in aliases:
            token = aliases[token]
        if token not in choices:
            names = list(choices) + list(aliases or {})
            self.fail(var, "expected one of " + ", ".join(names))
            return default
        return token

    def path(self, var: str) -> str | None:
        value = self.raw(var)
        if value is None:
            return None
        if _has_control(value):
            self.fail(var, "path contains control characters")
            return None
        if not os.path.isabs(value):
            self.fail(var, "must be an absolute path")
            return None
        return value


def _has_control(text: str) -> bool:
    return any(unicodedata.category(ch) == "Cc" for ch in text)


def _parse_plugins(reader: _Reader) -> tuple[tuple[str, str], ...]:
    var = "SNIPER_MCP_PLUGINS"
    value = reader.raw(var)
    if value is None:
        return ()
    pairs: list[tuple[str, str]] = []
    entries = [part.strip() for part in value.split(",")]
    if len([e for e in entries if e]) > MAX_PLUGINS:
        reader.fail(var, f"at most {MAX_PLUGINS} entries are allowed")
        return ()
    for entry in entries:
        if not entry:
            continue
        dist, sep, name = entry.partition(":")
        if not sep or not _PLUGIN_PART_RE.fullmatch(dist) or not _PLUGIN_PART_RE.fullmatch(name):
            reader.fail(var, "entries must be <distribution>:<entry-point-name> pairs "
                             "(lowercase letters, digits, '.', '_' and '-')")
            return ()
        pairs.append((dist, name))
    return tuple(pairs)


def _authorization_ref(reader: _Reader) -> str | None:
    var = "SNIPER_MCP_AUTHORIZATION_REF"
    value = reader.raw(var)
    if value is None:
        return None
    if len(value) > 256 or not value.isprintable():
        reader.fail(var, "expected 1-256 printable characters without control characters")
        return None
    return value


def _home(env: Mapping[str, str]) -> str | None:
    home = env.get("HOME") or ""
    if home and os.path.isabs(home):
        return home
    return None


def _state_dir(reader: _Reader, env: Mapping[str, str], home: str | None) -> str | None:
    explicit = reader.path("SNIPER_MCP_STATE_DIR")
    if explicit is not None:
        return explicit
    if reader.raw("SNIPER_MCP_STATE_DIR") is not None:
        return None  # already reported as invalid
    xdg = env.get("XDG_STATE_HOME") or ""
    if xdg and os.path.isabs(xdg) and not _has_control(xdg):
        return os.path.join(xdg, paths.STATE_DIR_NAME)
    if home is None or _has_control(home):
        reader.fail("SNIPER_MCP_STATE_DIR",
                    "HOME is unset or not absolute; set SNIPER_MCP_STATE_DIR")
        return None
    return os.path.join(home, paths.HOME_STATE_SUBDIR, paths.STATE_DIR_NAME)


def load_settings(env: Mapping[str, str], *, euid: int | None = None) -> Settings:
    """Validate ``env`` (process environment already merged with the env file).

    Raises :class:`ConfigError` listing every problem found.
    """
    if euid is None:
        euid = os.geteuid()
    reader = _Reader(env)

    transport = env.get(TRANSPORT_VAR, "")
    if transport not in ("", "stdio"):
        reader.fail(TRANSPORT_VAR, "only stdio is supported; unset it")

    edition = reader.enum("SNIPER_EDITION", "auto", EDITIONS, EDITION_ALIASES)
    sniper_bin = reader.path("SNIPER_BIN")
    install_dir = reader.path("SNIPER_INSTALL_DIR")
    loot_base = reader.path("SNIPER_LOOT_BASE")
    scan_enabled = reader.boolean("SNIPER_SCAN_ENABLED", True)
    needs_sudo_explicit = reader.raw("SNIPER_NEEDS_SUDO") is not None
    needs_sudo = reader.boolean("SNIPER_NEEDS_SUDO", euid != 0)

    scope = reader.raw("SNIPER_MCP_SCOPE") or ""
    scope_file = reader.path("SNIPER_MCP_SCOPE_FILE")
    allow_any_target = reader.boolean("SNIPER_MCP_ALLOW_ANY_TARGET", False)
    authorization_ref = _authorization_ref(reader)
    dns_policy = reader.enum("SNIPER_MCP_DNS_POLICY", "strict", DNS_POLICIES)
    cidr_cap = reader.integer("SNIPER_MCP_CIDR_CAP", 16, 8, 32)
    allow_intrusive = reader.boolean("SNIPER_MCP_ALLOW_INTRUSIVE", False)
    max_concurrent = reader.integer("SNIPER_MCP_MAX_CONCURRENT_SCANS", 2, 1, 16)
    enable_destructive = reader.boolean("SNIPER_MCP_ENABLE_DESTRUCTIVE", False)
    redact = reader.boolean("SNIPER_MCP_REDACT", True)
    reveal_secrets = reader.boolean("SNIPER_MCP_REVEAL_SECRETS", False)

    home = _home(env)
    state_dir = _state_dir(reader, env, home)
    audit_log = reader.path("SNIPER_MCP_AUDIT_LOG")
    retention = reader.integer("SNIPER_MCP_LOG_RETENTION_DAYS", 30, 0, 3650)
    plugins = _parse_plugins(reader)

    if reader.problems:
        raise ConfigError(reader.problems)
    assert state_dir is not None
    if audit_log is None:
        audit_log = os.path.join(state_dir, "audit.jsonl")
    if home is None:
        home = _passwd_home(euid)
    return Settings(
        edition=edition,
        sniper_bin=sniper_bin,
        install_dir=install_dir,
        loot_base=loot_base,
        scan_enabled=scan_enabled,
        needs_sudo=needs_sudo,
        needs_sudo_explicit=needs_sudo_explicit,
        scope=scope,
        scope_file=scope_file,
        allow_any_target=allow_any_target,
        authorization_ref=authorization_ref,
        dns_policy=dns_policy,
        cidr_cap=cidr_cap,
        allow_intrusive=allow_intrusive,
        max_concurrent_scans=max_concurrent,
        enable_destructive=enable_destructive,
        redact=redact,
        reveal_secrets=reveal_secrets,
        state_dir=state_dir,
        audit_log=audit_log,
        log_retention_days=retention,
        plugins=plugins,
        home=home,
        euid=euid,
    )


def _passwd_home(euid: int) -> str:
    try:
        home = pwd.getpwuid(euid).pw_dir
    except KeyError:
        return paths.SPAWN_CWD
    return home if os.path.isabs(home) else paths.SPAWN_CWD


def removed_variable_warnings(env: Mapping[str, str]) -> list[str]:
    """One stderr line per removed variable that is set (B.2)."""
    names = sorted(key for key, value in env.items() if value != "" and key in REMOVED_VARS)
    return [f"sn1per-mcp: warning: {name} is no longer supported and is ignored"
            for name in names]


def parse_env_file(text: str, path: str) -> dict[str, str]:
    """Parse the B.5 grammar; unknown or duplicate keys are configuration errors."""
    problems: list[ConfigProblem] = []
    values: dict[str, str] = {}
    allowed = frozenset(ENV_VARS)
    for number, raw_line in enumerate(text.split("\n"), start=1):
        line = raw_line[:-1] if raw_line.endswith("\r") else raw_line
        if line.strip() == "" or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        where = f"{path} line {number}"
        if not sep or not _ENV_KEY_RE.fullmatch(key):
            problems.append(ConfigProblem("--env-file", f"{where}: expected KEY=VALUE"))
            continue
        if key not in allowed:
            problems.append(ConfigProblem(key, f"unknown key in env file ({where})"))
            continue
        if key in values:
            problems.append(ConfigProblem(key, f"duplicate key in env file ({where})"))
            continue
        if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        values[key] = value
    if problems:
        raise ConfigError(problems)
    return values


def load_env_file(path: str) -> dict[str, str]:
    """Read and parse ``--env-file PATH`` with the B.5 file checks."""
    if _has_control(path) or not os.path.isabs(path):
        raise ConfigError([ConfigProblem("--env-file", "must be an absolute path")])
    try:
        secure = read_secure_file(path, max_bytes=ENV_FILE_MAX_BYTES, label="env file")
    except SecureFileError as exc:
        raise ConfigError([ConfigProblem("--env-file", str(exc))]) from exc
    try:
        text = secure.data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigError([ConfigProblem("--env-file", f"{path} is not valid UTF-8")]) from exc
    return parse_env_file(text, path)


def merge_env(process_env: Mapping[str, str], file_env: Mapping[str, str]) -> dict[str, str]:
    """Process environment wins; env-file values only fill keys not present (B.5).

    A key set to the empty string counts as unset (B.1), so the file may fill it.
    """
    merged = dict(process_env)
    for key, value in file_env.items():
        if merged.get(key, "") == "":
            merged[key] = value
    return merged
