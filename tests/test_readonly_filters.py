"""Read-only entry points must not execute configured Git filter programs."""
import os
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gitreal as g
import gitreal_mcp as mcp


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          capture_output=True, text=True).stdout


def initialize(repo):
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.name", "Fixture")
    git(repo, "config", "user.email", "fixture@example.invalid")
    (repo / "tracked.txt").write_text("base\n")
    git(repo, "add", "tracked.txt")
    git(repo, "commit", "-qm", "base")


def configure_filter(repo, tmp_path, pattern="*.txt", driver_kind="clean"):
    marker = tmp_path / "filter-ran"
    driver = tmp_path / "driver.py"
    driver.write_text("import pathlib,sys\npathlib.Path(" + repr(str(marker)) +
                      ").write_text('unexpected write')\nsys.stdout.buffer.write(sys.stdin.buffer.read())\n")
    git(repo, "config", "filter.fixture." + driver_kind, sys.executable + " " + str(driver))
    (repo / ".git/info/attributes").write_text(pattern + " filter=fixture\n")
    return marker


@pytest.mark.parametrize("route", ["status", "mcp", "fleet", "stage"])
@pytest.mark.parametrize("driver_kind", ["clean", "process"])
def test_readonly_routes_refuse_active_filters(tmp_path, route, driver_kind):
    repo = tmp_path / "repo"
    initialize(repo)
    marker = configure_filter(repo, tmp_path, driver_kind=driver_kind)
    # Equal size forces Git to inspect bytes rather than infer dirt from size.
    (repo / "tracked.txt").write_text("edit\n")
    os.utime(repo / "tracked.txt", (1, 1))
    if route == "mcp":
        state = mcp.get_status(str(repo))
    elif route == "fleet":
        state = g.build_fleet_state(str(tmp_path), [str(repo)], {"quick": True})
    elif route == "stage":
        state = g.stage_paths_state(str(repo), ["tracked.txt"])
        assert state["requested_action"]["decision"] == "BLOCK"
    else:
        state = g.build_state(g.GitRepo(str(repo)), {"quick": True})
    assert state["read_complete"] is False
    assert not marker.exists()


def test_staging_untracked_filter_is_refused_before_isolated_add(tmp_path):
    repo = tmp_path / "repo"
    initialize(repo)
    marker = configure_filter(repo, tmp_path, pattern="new.txt")
    (repo / "new.txt").write_text("new\n")
    index = (repo / ".git/index").read_bytes()
    state = g.stage_paths_state(str(repo), ["new.txt"])
    assert state["requested_action"]["decision"] == "BLOCK"
    assert "filter" in " ".join(state["requested_action"]["reasons"])
    assert (repo / ".git/index").read_bytes() == index
    assert not marker.exists()


def test_unused_installed_filter_does_not_block_status(tmp_path):
    repo = tmp_path / "repo"
    initialize(repo)
    marker = configure_filter(repo, tmp_path, pattern="*.unused")
    state = g.build_state(g.GitRepo(str(repo)), {"quick": True})
    assert state["read_complete"] is True, state["read_errors"]
    assert not marker.exists()


def test_submodule_filter_is_refused_before_recursive_status(tmp_path):
    repo = tmp_path / "repo"
    initialize(repo)
    child = repo / "child"
    initialize(child)
    git(repo, "add", "child")
    git(repo, "commit", "-qm", "gitlink")
    marker = configure_filter(child, tmp_path)
    (child / "tracked.txt").write_text("edit\n")
    os.utime(child / "tracked.txt", (1, 1))
    state = g.build_state(g.GitRepo(str(repo)), {"quick": True})
    assert state["read_complete"] is False
    assert not marker.exists()


def test_filter_batches_cover_tail_and_retain_total_bound(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    initialize(repo)
    for name in ('b.txt', 'c.txt', 'z.txt'):
        (repo / name).write_text('fixture\n')
    git(repo, 'add', '.')
    git(repo, 'commit', '-qm', 'paths')
    marker = configure_filter(repo, tmp_path, pattern='*.unused')
    monkeypatch.setattr(g, 'REF_MAX_WORKTREE_ENTRIES', 1)
    monkeypatch.setattr(g, 'STATUS_FILTER_BATCH_SIZE', 2)
    g._status_filter_preflight(g.GitRepo(str(repo)))
    (repo / '.git/info/attributes').write_text('z.txt filter=fixture\n')
    with pytest.raises(ValueError, match='Active clean/process'):
        g._status_filter_preflight(g.GitRepo(str(repo)))
    monkeypatch.setattr(g, 'STATUS_FILTER_MAX_PATHS', 3)
    with pytest.raises(ValueError, match='bounded inventory'):
        g._status_filter_preflight(g.GitRepo(str(repo)))
    assert not marker.exists()


LFS_COMMANDS = {"clean": "git-lfs clean -- %f", "smudge": "git-lfs smudge -- %f",
                "process": "git-lfs filter-process"}


def configure_lfs(repo, pattern="*.txt", **changed):
    for field, command in {**LFS_COMMANDS, **changed}.items():
        git(repo, "config", "filter.lfs." + field, command)
    (repo / ".git/info/attributes").write_text(pattern + " filter=lfs\n")


def test_standard_git_lfs_driver_is_trusted(tmp_path):
    repo = tmp_path / "repo"
    initialize(repo)
    configure_lfs(repo)
    g._status_filter_preflight(g.GitRepo(str(repo)), ["tracked.txt"])
    assert g._ref_inspection_preflight(g.GitRepo(str(repo)))["head_oid"]
    state = g.build_state(g.GitRepo(str(repo)), {"quick": True})
    assert state["read_complete"] is True, state["read_errors"]


@pytest.mark.parametrize("field", ["clean", "smudge", "process"])
def test_altered_lfs_command_is_not_trusted(tmp_path, field):
    repo = tmp_path / "repo"
    initialize(repo)
    configure_lfs(repo, **{field: LFS_COMMANDS[field] + " --altered"})
    with pytest.raises(ValueError, match="Active clean/process"):
        g._status_filter_preflight(g.GitRepo(str(repo)))
    with pytest.raises(ValueError, match="checkout filters"):
        g._ref_inspection_preflight(g.GitRepo(str(repo)))


def test_trusting_lfs_still_refuses_other_drivers(tmp_path):
    repo = tmp_path / "repo"
    initialize(repo)
    marker = configure_filter(repo, tmp_path)
    configure_lfs(repo, pattern="*.bin")
    (repo / ".git/info/attributes").write_text("*.bin filter=lfs\n*.txt filter=fixture\n")
    (repo / "tracked.txt").write_text("edit\n")
    os.utime(repo / "tracked.txt", (1, 1))
    state = g.build_state(g.GitRepo(str(repo)), {"quick": True})
    assert state["read_complete"] is False
    assert not marker.exists()
