# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""System constants (contract P.3, O.2): defaults are the real paths; tests patch them."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

from sniper_mcp import paths
from tests import realpaths

PATHS_FILE = Path(__file__).resolve().parent.parent / "src" / "sniper_mcp" / "paths.py"


def _pristine():
    spec = importlib.util.spec_from_file_location("_pristine_paths", PATHS_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_default_constants_are_the_real_system_paths():
    p = _pristine()
    assert p.CLI_FALLBACK == realpaths.SNIPER_SHARE_CLI
    assert p.DEFAULT_INSTALL_DIR == realpaths.SNIPER_SHARE
    assert p.DEFAULT_LOOT_BASE == realpaths.SNIPER_SHARE_LOOT
    assert p.DELETE_ROOT == realpaths.SNIPER_SHARE
    assert p.DELETE_ROOT_LOOT == realpaths.SNIPER_SHARE_LOOT
    assert p.DELETE_ROOT_WORKSPACE == realpaths.SNIPER_SHARE_WORKSPACE
    assert p.ENGINE_PATH_DIRS == realpaths.ENGINE_PATH_DIRS
    assert p.MINIMAL_ENV_PATH == realpaths.MINIMAL_ENV_PATH
    assert p.SUDO == realpaths.SUDO_BIN and p.GREP == realpaths.GREP_BIN
    assert p.PROC_ROOT == realpaths.PROC_ROOT and p.PROC_SYS_FS == realpaths.PROC_SYS_FS
    assert p.TRUSTED_UID == 0 and p.SPAWN_CWD == "/" and p.FILESYSTEM_ROOT == "/"


def test_isolation_patches_every_install_constant(iso):
    tmp = str(iso.tmp)
    for name in ("CLI_FALLBACK", "DEFAULT_INSTALL_DIR", "DEFAULT_LOOT_BASE", "DELETE_ROOT",
                 "DELETE_ROOT_LOOT", "DELETE_ROOT_WORKSPACE", "SUDO"):
        assert getattr(paths, name).startswith(tmp + "/"), name
    assert all(d.startswith(tmp + "/") for d in paths.ENGINE_PATH_DIRS)
    assert paths.TRUSTED_UID == os.geteuid() and paths.FILESYSTEM_ROOT == tmp
    assert os.environ["PATH"] == str(iso.bin_dir)
    assert not any(k.startswith(("RAG_", "MCP_")) for k in os.environ)
    assert os.environ["HOME"].startswith(tmp + "/")


def test_default_resolution_with_a_patched_filesystem(iso):
    from sniper_mcp import edition, settings

    iso.delenv("SNIPER_BIN", "SNIPER_INSTALL_DIR", "SNIPER_LOOT_BASE")
    config = settings.load_settings(os.environ)
    # `sniper` on the (patched) PATH is the stub link; the realpath is the fake install.
    cli = edition.resolve_cli(config)
    assert cli.configured == str(iso.cli_link) and cli.realpath == str(iso.cli_path)
    # The install dir comes from the CLI's INSTALL_DIR= marker (C.2 steps 3 and 5).
    detection = edition.detect(config, fresh=True)
    assert detection.cli_install_dir == str(iso.install_dir)
    assert detection.install_dir == str(iso.install_dir)
    assert detection.loot_base == str(iso.loot_base)
    # Without anything on PATH the fallback constant is used.
    iso.cli_link.unlink()
    cli = edition.resolve_cli(settings.load_settings(os.environ))
    assert cli.configured == str(iso.cli_path) and cli.status == "ok"
    iso.cli_path.unlink()
    assert edition.resolve_cli(settings.load_settings(os.environ)).status == "cli_not_found"
