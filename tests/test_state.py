# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""State directory and secure file helpers (contract L.1)."""

from __future__ import annotations

import json
import os
import stat

import pytest

from sniper_mcp import paths, state


def mode(path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def test_creates_private_tree_regardless_of_umask(iso):
    target = iso.tmp / "a" / "b" / "state"
    old = os.umask(0)
    try:
        status = state.prepare_state_dir(str(target))
    finally:
        os.umask(old)
    assert status.ok and status.warnings == ()
    for path in (target, target / "jobs", target / "exports", iso.tmp / "a", iso.tmp / "a" / "b"):
        assert mode(path) == 0o700, path


def test_umask_without_owner_bits_still_gives_0700(iso):
    target = iso.tmp / "c" / "state"
    old = os.umask(0o777)
    try:
        status = state.prepare_state_dir(str(target))
    finally:
        os.umask(old)
    assert status.ok and status.warnings == ()
    for path in (target, target / "jobs", target / "exports", iso.tmp / "c"):
        assert mode(path) == 0o700, path


def test_no_chmod_with_follow_symlinks_false(iso, monkeypatch):
    """Where fchmodat lacks AT_SYMLINK_NOFOLLOW, chmod(follow_symlinks=False) raises
    NotImplementedError (not an OSError); the state dir must not depend on it."""
    real_chmod = os.chmod

    def chmod(path, mode, *, dir_fd=None, follow_symlinks=True):
        if not follow_symlinks:
            raise NotImplementedError("chmod: follow_symlinks unavailable on this platform")
        return real_chmod(path, mode, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "chmod", chmod)
    status = state.prepare_state_dir(str(iso.tmp / "d" / "state"))
    assert status.ok, status.problem


def test_loose_mode_is_fixed_with_a_warning(iso):
    target = iso.tmp / "loose"
    target.mkdir(mode=0o755)
    target.chmod(0o755)
    status = state.prepare_state_dir(str(target))
    assert status.ok and status.warnings == ("state_dir_permissions_fixed",)
    assert mode(target) == 0o700


def test_symlink_is_insecure(iso):
    real = iso.tmp / "real"
    real.mkdir()
    link = iso.tmp / "link"
    link.symlink_to(real)
    status = state.prepare_state_dir(str(link))
    assert not status.ok and "real directory" in status.problem


def test_symlinked_subdirectory_is_insecure(iso):
    target = iso.tmp / "st"
    target.mkdir(mode=0o700)
    (iso.tmp / "elsewhere").mkdir()
    (target / "jobs").symlink_to(iso.tmp / "elsewhere")
    assert not state.prepare_state_dir(str(target)).ok


def test_file_in_place_of_directory_is_insecure(iso):
    target = iso.tmp / "file"
    target.write_text("x")
    assert not state.prepare_state_dir(str(target)).ok


def test_other_owner_is_insecure(iso, monkeypatch):
    target = iso.tmp / "owned"
    target.mkdir(mode=0o700)
    real = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real + 1)
    status = state.prepare_state_dir(str(target))
    assert not status.ok and "owned by uid" in status.problem


def test_create_exclusive_and_atomic_json(iso):
    path = iso.tmp / "rec.json"
    state.write_json_atomic(str(path), {"schema_version": "1", "x": "é"})
    assert json.loads(path.read_text()) == {"schema_version": "1", "x": "é"}
    assert mode(path) == 0o600
    state.write_json_atomic(str(path), {"y": 1})
    assert json.loads(path.read_text()) == {"y": 1}
    assert [p.name for p in iso.tmp.iterdir() if p.name.endswith(".tmp")] == []
    log = iso.tmp / "job.log"
    os.close(state.create_exclusive(str(log)))
    assert mode(log) == 0o600
    with pytest.raises(FileExistsError):
        state.create_exclusive(str(log))
    link = iso.tmp / "link.log"
    link.symlink_to(iso.tmp / "target.log")
    with pytest.raises(OSError):
        state.create_exclusive(str(link))
    assert not (iso.tmp / "target.log").exists()


def test_read_secure_file_never_blocks_on_a_fifo(iso):
    fifo = iso.tmp / "scope"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(state.SecureFileError, match="not a regular file"):
        state.read_secure_file(str(fifo), max_bytes=100, label="scope file")


@pytest.mark.parametrize(("server_uid", "expected"), [
    (0, "it must be owned by uid 0 (root)"),
    (None, "it must be owned by uid {other} (the server's user) or uid 0 (root)"),
])
def test_a_foreign_owner_is_named_in_the_error(iso, monkeypatch, server_uid, expected):
    """V1: a file copied with "docker cp" keeps the host user's uid; the error names that
    owner instead of repeating "or by root" to a server that runs as root."""
    real = os.geteuid()
    other = real + 1 if server_uid is None else server_uid
    target = iso.tmp / "env"
    target.write_text("SNIPER_MCP_SCOPE=app.example\n")
    target.chmod(0o600)
    monkeypatch.setattr(paths, "TRUSTED_UID", 0)
    monkeypatch.setattr(os, "geteuid", lambda: other)
    with pytest.raises(state.SecureFileError) as caught:
        state.read_secure_file(str(target), max_bytes=1000, label="--env-file: env file")
    assert str(caught.value) == (f"--env-file: env file {target} is owned by uid {real}; "
                                 + expected.format(other=other))
