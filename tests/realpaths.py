# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Real host paths: the only file under tests/ allowed to name them (contract O.2).

Three users, none of which ever reaches these paths:
- the guard (tests/guard/hook.py) protects them, pins the allowed binaries and
  validates the roots forwarded to guarded children;
- tests/test_guard.py points blocked calls at them to prove the guard trips;
- tests/test_paths.py asserts the defaults of ``sniper_mcp.paths`` against them,
  with the filesystem patched.
"""

from __future__ import annotations

SNIPER_SHARE = "/usr/share/sniper"
SNIPER_SHARE_CLI = "/usr/share/sniper/sniper"
SNIPER_SHARE_LOOT = "/usr/share/sniper/loot"
SNIPER_SHARE_WORKSPACE = "/usr/share/sniper/loot/workspace"
SNIPER_USR_BIN = "/usr/bin/sniper"
# A top-level Sn1per source checkout directory, protected like the install.
SNIPER_TOP = "/sniper"
SNIPER_TOP_PREFIX = SNIPER_TOP + "/"
ROOT_HOME = "/root"

SUDO_BIN = "/usr/bin/sudo"
GREP_BIN = "/usr/bin/grep"
TRUE_BIN = "/bin/true"
FALSE_BIN = "/bin/false"
SLEEP_BIN = "/bin/sleep"

PROC_ROOT = "/proc"
PROC_SYS_FS = "/proc/sys/fs"
ENGINE_PATH_DIRS = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")
MINIMAL_ENV_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Directories whose content no test may open (Layer 1 adds the real $HOME at run time).
PROTECTED_ROOTS = (SNIPER_SHARE, SNIPER_TOP, ROOT_HOME)

# A root forwarded to a guarded child in SN1PER_MCP_TEST_GUARD may not be "/" or
# contain any of these directories (or a protected root, or the interpreter
# prefix) ...
SYSTEM_DIRS = (
    "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64", "/media", "/mnt",
    "/opt", "/proc", ROOT_HOME, "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/usr/bin",
    "/usr/lib", "/usr/local", "/usr/local/bin", "/usr/sbin", "/usr/share", "/var", "/var/tmp",
)
# ... and a temp root may not lie inside these (binaries and system configuration).
SYSTEM_TREES = ("/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/proc",
                "/sbin", "/sys", "/usr")

# Argv elements that are always blocked, whatever else the Popen rules say.
BLOCKED_ARGV_SUFFIXES = ("/sniper", "/sn1per", "/sudo")
BLOCKED_ARGV_SUBSTRINGS = (SNIPER_SHARE,)
BLOCKED_ARGV_PREFIXES = (SNIPER_TOP_PREFIX,)

# Meta-test (O.2 item 5): literals no other file under tests/ may contain.
FORBIDDEN_LITERALS = (SNIPER_SHARE, SNIPER_TOP_PREFIX, SNIPER_USR_BIN)
HOME_PATH_PATTERN = r"[/]home[/][A-Za-z0-9._-]+|/root(?![A-Za-z0-9._-])"
