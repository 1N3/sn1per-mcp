# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Every system path and system constant the server uses (contract P.3, O.2).

No other module under ``sniper_mcp`` names a system path. Code reads these
values as ``paths.NAME`` at call time (never ``from sniper_mcp.paths import``),
so the test isolation fixture can patch this module as a whole and the real
checks then run against a fake install in a temporary directory.
"""

from __future__ import annotations

# Sn1per CLI fallback when SNIPER_BIN is unset and `sniper` is not on PATH (C.2 step 1).
CLI_FALLBACK = "/usr/share/sniper/sniper"

# Default engine install dir when neither SNIPER_INSTALL_DIR nor the CLI's
# INSTALL_DIR= marker gives one (C.2 step 5).
DEFAULT_INSTALL_DIR = "/usr/share/sniper"

# Default loot base for the default install dir (C.2 step 6: <install_dir>/loot).
DEFAULT_LOOT_BASE = "/usr/share/sniper/loot"

# Name of the loot subdirectory of an install dir, and of the workspace
# subdirectory of a loot base.
LOOT_SUBDIR = "loot"
WORKSPACE_SUBDIR = "workspace"

# The tree that both engine dialects hardcode in their delete routine
# (I.3 steps 5-6).
DELETE_ROOT = "/usr/share/sniper"
DELETE_ROOT_LOOT = "/usr/share/sniper/loot"
DELETE_ROOT_WORKSPACE = "/usr/share/sniper/loot/workspace"

# Directories searched for an executable `sniper` on root's PATH (C.2 step 12).
ENGINE_PATH_DIRS: tuple[str, ...] = (
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
)

# Symlink suggested by the engine-PATH hint (C.2 step 12). Hint text only; never checked.
ENGINE_PATH_HINT_LINK = "/usr/local/bin/sniper"

# PATH of the minimal environment given to every child process (D.5).
MINIMAL_ENV_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Working directory of every engine child process (D.5).
SPAWN_CWD = "/"

# Preferred sudo binary (D.5); `shutil.which("sudo")` is the fallback.
SUDO = "/usr/bin/sudo"

# Preferred GNU grep binary (J.5); `shutil.which("grep")` is the fallback.
GREP = "/usr/bin/grep"

# Process table root (L.3, L.4) and the fs sysctl directory (C.2 step 13).
PROC_ROOT = "/proc"
PROC_SYS_FS = "/proc/sys/fs"

# The uid that ownership checks treat as root (C.2 step 1, D.5, I.3 step 6, B.5).
TRUSTED_UID = 0

# Top of the directory walk that decides whether root chose every name on the CLI
# realpath, which sniper_status shows only then (C.2 step 1, H.5). The test isolation
# fixture points it at the test's own directory, which stands in for "/".
FILESYSTEM_ROOT = "/"

# Fixed directory name of the server's state dir under XDG_STATE_HOME or
# ~/.local/state (B.2 SNIPER_MCP_STATE_DIR).
STATE_DIR_NAME = "sn1per-mcp"
HOME_STATE_SUBDIR = ".local/state"

# Hardened scope file location named in the scope_file_writable_by_server_user warning
# (F.1, Q.7). Text only; the server reads only the file SNIPER_MCP_SCOPE_FILE names.
HARDENED_SCOPE_FILE = "/etc/sn1per-mcp/scope"
