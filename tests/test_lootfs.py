# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sn1perSecurity LLC
"""Safe opener, walker, exclusions and loot base identity (contract J.1, J.2, O.4 traps).

Every trap (symbolic links, hard links, FIFOs, odd names, a swapped loot base) is
created at test time inside the temporary tree, never committed.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from sniper_mcp import lootfs
from sniper_mcp.lootfs import LootBase, LootError, ReadStats


def _tree(root: Path) -> Path:
    ws = root / "workspace" / "app.example"
    for relative, content in {
        "nmap/nmap-app.example.txt": "22/tcp open ssh\n",
        "credentials/canary.txt": "CANARY\n",
        "CrEdentials/canary.txt": "CANARY\n",
        "BloodHound/data.json": "{}\n",
        "output/notes.txt": "notes\n",
        "output/svc_kerberoast_hashes.txt": "x\n",
        "output/DC.NTDS.dit": "x\n",
        "output/Cert.PFX": "x\n",
        "deep/a/b/c.txt": "deep\n",
    }.items():
        path = ws / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return ws


@pytest.fixture
def base(tmp_path: Path) -> tuple[LootBase, Path]:
    loot = tmp_path / "loot"
    _tree(loot)
    return LootBase(str(loot)), loot


# --- exclusions (J.2) ----------------------------------------------------------------------

@pytest.mark.parametrize("name", ["credentials", "Credentials", "CREDENTIALS", "CrEdentials",
                                  "bloodhound", "BloodHound"])
def test_excluded_dirs_in_any_case(name):
    assert lootfs.is_excluded_dir(name)


@pytest.mark.parametrize("name", [
    "a.pfx", "A.P12", "x.ccache", "t.kirbi", "h.keytab", "server.KEY", "c.pem", "h.pot",
    "john.potfile", "w.hccapx", "w.22000", "ntds.dit", "users_KERBEROAST.txt", "asrep.txt",
    "AS_REP-roast.txt", "timeroast.out", "hash_cracking.log", "hashcat.out",
    "secretsdump.txt", "gpp_laps.txt", "credential_harvest.csv", "lsass.dmp", "NTDS.txt",
    "potfile-copy"])
def test_excluded_files_in_any_case(name):
    assert lootfs.is_excluded_file(name)


@pytest.mark.parametrize("name", ["ai-findings-combined.csv", "nmap-app.example.txt",
                                  "domains-all-sorted.txt", "keys.txt", "pem-notes"])
def test_ordinary_names_are_not_excluded(name):
    assert not lootfs.is_excluded_file(name)


def test_grep_exclusion_arguments_cover_every_rule_in_every_case():
    args = lootfs.grep_exclusion_args()
    assert "--exclude-dir=[cC][rR][eE][dD][eE][nN][tT][iI][aA][lL][sS]" in args
    assert "--exclude-dir=[bB][lL][oO][oO][dD][hH][oO][uU][nN][dD]" in args
    assert "--exclude=*[kK][eE][rR][bB][eE][rR][oO][aA][sS][tT]*" in args
    assert "--exclude=*.[pP][fF][xX]" in args
    assert "--exclude=*.22000" in args
    assert len(args) == (len(lootfs.EXCLUDED_DIRS) + len(lootfs.EXCLUDED_SUFFIXES)
                         + len(lootfs.EXCLUDED_SUBSTRINGS))


# --- opener and walker (J.1) ----------------------------------------------------------------

def test_walk_skips_excluded_trees_and_files(base):
    loot_base, _ = base
    stats = ReadStats()
    ws = loot_base.open_workspace("app.example", stats)
    try:
        found = sorted(item.relpath for item in lootfs.walk(ws, stats, exclude=True))
    finally:
        os.close(ws)
    assert found == ["deep/a/b/c.txt", "nmap/nmap-app.example.txt", "output/notes.txt"]
    assert stats.excluded_dirs == 3 and stats.excluded_files == 3


def test_walk_without_exclusions_sees_everything(base):
    loot_base, _ = base
    stats = ReadStats()
    ws = loot_base.open_workspace("app.example", stats)
    try:
        found = {item.relpath for item in lootfs.walk(ws, stats, exclude=False)}
    finally:
        os.close(ws)
    assert "credentials/canary.txt" in found and "CrEdentials/canary.txt" in found
    assert "output/DC.NTDS.dit" in found


def test_walk_never_follows_links_and_skips_special_files(base, tmp_path):
    loot_base, loot = base
    ws = loot / "workspace" / "app.example"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("OUTSIDE\n")
    (ws / "nmap" / "leak.txt").symlink_to(outside / "secret.txt")
    (ws / "nmap" / "creds.txt").symlink_to(ws / "credentials" / "canary.txt")
    (ws / "nmap" / "environ.txt").symlink_to("/proc/self/environ")
    (ws / "linkdir").symlink_to(outside)
    os.mkfifo(ws / "nmap" / "nmap-192.0.2.1.txt")
    stats = ReadStats()
    fd = loot_base.open_workspace("app.example", stats)
    try:
        names = set()
        for item in lootfs.walk(fd, stats, exclude=True):  # dir_fd is valid during the yield
            names.add(item.relpath)
            assert lootfs.read_file(item.dir_fd, item.name, stats) is not None
    finally:
        os.close(fd)
    assert not names & {"nmap/leak.txt", "nmap/creds.txt", "nmap/environ.txt",
                        "nmap/nmap-192.0.2.1.txt"}
    assert not any(n.startswith("linkdir/") for n in names)
    assert stats.symlinks_skipped == 4 and stats.special_skipped == 1


def test_read_file_refuses_links_fifos_and_hard_links(tmp_path):
    directory = tmp_path / "d"
    directory.mkdir()
    (directory / "plain.txt").write_text("plain\n")
    (directory / "link.txt").symlink_to(directory / "plain.txt")
    os.mkfifo(directory / "fifo.txt")
    outside = tmp_path / "operator-file.txt"
    outside.write_text("operator secret\n")
    os.link(outside, directory / "hard.txt")
    stats = ReadStats()
    fd = os.open(directory, lootfs.DIR_FLAGS)
    try:
        assert lootfs.read_file(fd, "plain.txt", stats).data == b"plain\n"
        assert lootfs.read_file(fd, "link.txt", stats) is None
        assert lootfs.read_file(fd, "fifo.txt", stats) is None  # O_NONBLOCK: never blocks
        assert lootfs.read_file(fd, "hard.txt", stats) is None
        assert lootfs.read_file(fd, "hard.txt", stats, allow_hardlinks=True) is not None
        assert lootfs.read_file(fd, "../d/plain.txt", stats) is None
        assert lootfs.read_file(fd, "..", stats) is None
    finally:
        os.close(fd)
    assert stats.hardlinks_skipped == 1 and stats.special_skipped == 1


def test_read_file_caps(tmp_path):
    (tmp_path / "big.txt").write_bytes(b"x" * 100)
    stats = ReadStats()
    fd = os.open(tmp_path, lootfs.DIR_FLAGS)
    try:
        data = lootfs.read_file(fd, "big.txt", stats, cap=10)
    finally:
        os.close(fd)
    assert data.data == b"x" * 10 and data.truncated
    assert stats.bytes_read == 10 and stats.files_read == 1


def test_per_call_file_cap(monkeypatch):
    monkeypatch.setattr(lootfs, "CALL_FILE_CAP", 2)
    stats = ReadStats(files_read=2)
    assert not stats.can_read() and stats.call_cap_reached


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores permission bits")
def test_unreadable_entries_are_counted(tmp_path):
    locked = tmp_path / "locked"
    locked.mkdir()
    (tmp_path / "locked-file.txt").write_text("x")
    (tmp_path / "locked-file.txt").chmod(0)
    locked.chmod(0)
    stats = ReadStats()
    fd = os.open(tmp_path, lootfs.DIR_FLAGS)
    try:
        assert lootfs.open_dir(fd, "locked", stats) is None
        assert lootfs.read_file(fd, "locked-file.txt", stats) is None
    finally:
        os.close(fd)
        locked.chmod(0o700)
    assert stats.unreadable == 2


# --- workspaces and the loot base identity ----------------------------------------------------

def test_symlinked_workspace_is_not_found(base):
    loot_base, loot = base
    (loot / "workspace" / "linked").symlink_to(loot / "workspace" / "app.example")
    with pytest.raises(LootError) as caught:
        loot_base.open_workspace("linked")
    assert caught.value.code == "workspace_not_found"
    with pytest.raises(LootError) as caught:
        lootfs.workspace_path(str(loot / "workspace"), "linked")
    assert caught.value.code == "workspace_not_found"
    assert lootfs.workspace_names(str(loot / "workspace")) == ["app.example"]


@pytest.mark.parametrize("name", ["..", "a..b", "trailing.", "-x", "a/b"])
def test_invalid_workspace_names(base, name):
    loot_base, _ = base
    with pytest.raises(LootError) as caught:
        loot_base.open_workspace(name)
    assert caught.value.code == "invalid_workspace"


def test_symlinked_workspace_root_is_absent(tmp_path):
    loot = tmp_path / "loot"
    loot.mkdir()
    real = tmp_path / "elsewhere"
    _tree(real)
    (loot / "workspace").symlink_to(real / "workspace")
    loot_base = LootBase(str(loot))
    assert loot_base.open_workspace_root() is None
    with pytest.raises(LootError) as caught:
        loot_base.open_workspace("app.example")
    assert caught.value.code == "workspace_not_found"


def test_swapped_loot_base_is_loot_dir_changed(base, tmp_path):
    loot_base, loot = base
    loot_base.record_if_exists()
    assert loot_base.identity is not None
    os.rename(loot, tmp_path / "loot-original")
    other = tmp_path / "attacker"
    _tree(other)
    loot.symlink_to(other)  # a parent made world-writable lets a local user do this
    for call in (loot_base.check, loot_base.open_workspace_root,
                 lambda: loot_base.open_workspace("app.example")):
        with pytest.raises(LootError) as caught:
            call()
        assert caught.value.code == "loot_dir_changed"


def test_loot_base_created_after_startup_is_pinned_at_first_open(tmp_path):
    loot = tmp_path / "later"
    loot_base = LootBase(str(loot))
    loot_base.record_if_exists()
    assert loot_base.identity is None and loot_base.open_workspace_root() is None
    _tree(loot)
    fd = loot_base.open_workspace("app.example")
    os.close(fd)
    assert loot_base.identity == (os.stat(loot).st_dev, os.stat(loot).st_ino)
    os.rename(loot, tmp_path / "moved")
    _tree(loot)
    with pytest.raises(LootError) as caught:
        loot_base.check()
    assert caught.value.code == "loot_dir_changed"


def test_identity_pinning_is_thread_safe(base):
    loot_base, _ = base
    errors = []

    def worker():
        try:
            loot_base.check()
        except LootError as exc:  # pragma: no cover - would be a race bug
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors


def test_odd_names_are_listed_but_never_unsafe_components(tmp_path):
    directory = tmp_path / "d"
    directory.mkdir()
    for name in ("a:b.txt", "new\nline.txt", "ctl\x1bname.txt"):
        (directory / name).write_text("x")
    fd = os.open(directory, lootfs.DIR_FLAGS)
    try:
        names = [entry.name for entry in lootfs.list_dir(fd)]
    finally:
        os.close(fd)
    assert sorted(names) == sorted(["a:b.txt", "new\nline.txt", "ctl\x1bname.txt"])
    assert not any(lootfs.SOURCE_NAME_RE.fullmatch(n) for n in names)
