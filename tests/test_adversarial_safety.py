"""Data-loss regressions. All Git writes are confined to pytest temporary repos.

Assertions describe preservation, not the implementation's chosen point deductions.
No real repository content or credentials are scanned.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gitreal as g
import gitreal_mcp as mcp


def git(path, *args, check=True):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    return subprocess.run(
        ["git", "-C", str(path), "-c", "core.hooksPath=" + os.devnull,
         "-c", "commit.gpgsign=false", *args],
        check=check, capture_output=True, text=True, env=env,
    )


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    git(path, "init", "-q", "-b", "main")
    git(path, "config", "user.name", "Safety regression")
    git(path, "config", "user.email", "safety@example.invalid")
    (path / "tracked.txt").write_text("base\n")
    git(path, "add", "tracked.txt")
    git(path, "commit", "-qm", "base")
    return path


def upstream(repo, tmp_path):
    bare = tmp_path / "remote.git"
    bare.mkdir()
    git(bare, "init", "--bare", "-q")
    git(repo, "remote", "add", "origin", str(bare))
    git(repo, "push", "-qu", "origin", "main")


@pytest.mark.parametrize("name", [
    "build/real_source.py", "dist/unpublished.png", "vendor/original.c",
    ".cache/precious.sqlite", "backup.bak", "unsaved.tmp", "research.log",
])
def test_untracked_names_never_prove_disposability(repo, name):
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"unique work never committed\n")
    state = g.build_state(g.GitRepo(str(repo)), {})
    assert state["scores"]["safe_delete_band"] != "GO", name
    assert mcp.check_discard(str(repo))["recommendation"] != "OK_TO_DISCARD"


def test_ignored_data_prevents_blanket_discard_approval(repo):
    (repo / ".gitignore").write_text(".env\ndata/\n")
    git(repo, "add", ".gitignore")
    git(repo, "commit", "-qm", "ignore private local data")
    (repo / ".env").write_text("fixture only; not a credential\n")
    (repo / "data").mkdir()
    (repo / "data/precious.json").write_text('{"unique": true}\n')
    state = g.build_state(g.GitRepo(str(repo)), {})
    assert not state["files"]
    assert state["ignored_count"] >= 2
    assert state["scores"]["safe_delete_band"] != "GO"


def test_clean_ahead_commits_prevent_blanket_discard_approval(repo, tmp_path):
    upstream(repo, tmp_path)
    for n in range(2):
        (repo / "tracked.txt").write_text(f"local work {n}\n")
        git(repo, "add", "tracked.txt")
        git(repo, "commit", "-qm", f"local {n}")
    state = g.build_state(g.GitRepo(str(repo)), {})
    assert not state["files"] and state["status"]["ahead"] == 2
    assert state["scores"]["safe_delete_band"] != "GO"


def test_stash_only_work_prevents_blanket_discard_approval(repo):
    (repo / "tracked.txt").write_text("unique stash work\n")
    git(repo, "stash", "push", "-qm", "unique")
    state = g.build_state(g.GitRepo(str(repo)), {})
    assert not state["files"] and state["stash_summary"]["count"] == 1
    assert state["scores"]["safe_delete_band"] != "GO"


def test_stash_ref_without_reflog_cannot_look_empty(repo, tmp_path):
    upstream(repo, tmp_path)
    (repo / "tracked.txt").write_text("stash content still retained by its ref\n")
    git(repo, "stash", "push", "-qm", "fixture stash")
    (repo / ".git/logs/refs/stash").unlink()
    assert git(repo, "rev-parse", "--verify", "refs/stash").stdout
    state = g.build_state(g.GitRepo(str(repo)), {"quick": True})
    assert state["read_complete"] is False
    assert not state["closeout"]["local_state_complete"]


def test_working_tree_stash_presence_is_not_durable_recovery(repo):
    (repo / "tracked.txt").write_text("unique stash work\n")
    git(repo, "stash", "push", "-qm", "unique")
    git(repo, "stash", "apply")
    state = g.build_state(g.GitRepo(str(repo)), {})
    reasons = " ".join(state["scores"]["safe_delete_reasons"]).lower()
    assert "safe to clear" not in reasons
    assert "none hold unique work" not in reasons


@pytest.mark.parametrize("failure", ["ls-files", "for-each-ref", "worktree"])
def test_required_inventory_read_failure_is_not_empty(repo, failure):
    obj = g.GitRepo(str(repo))
    original = obj._run

    def fail(*args, **kwargs):
        if args and args[0] == failure:
            return "", 124, "injected inventory timeout"
        return original(*args, **kwargs)

    obj._run = fail
    state = g.build_state(obj, {})
    assert state["read_complete"] is False
    assert state["scores"]["safe_delete_band"] != "GO"


def test_rename_and_quoted_paths_are_lossless(repo):
    new = 'build/renamed space\tquote"\nü.py'
    (repo / "build").mkdir()
    git(repo, "mv", "tracked.txt", new)
    state = g.build_state(g.GitRepo(str(repo)), {})
    assert state["status"]["renamed"] == [new]
    assert state["status"]["staged"][0]["path"] == new
    assert next(f for f in state["files"] if f["path"] == new)["staged_size"] == 5


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_hidden_index_flags_prevent_false_clean_discard(repo, flag):
    git(repo, "update-index", flag, "tracked.txt")
    (repo / "tracked.txt").write_text("hidden unique edits\n")
    state = g.build_state(g.GitRepo(str(repo)), {})
    assert state["scores"]["safe_delete_band"] != "GO"


def test_side_branch_upstream_is_not_proof_tip_was_pushed(repo, tmp_path):
    upstream(repo, tmp_path)
    git(repo, "checkout", "-qb", "feature")
    git(repo, "push", "-qu", "origin", "feature")
    git(repo, "commit", "--allow-empty", "-qm", "unpublished feature")
    git(repo, "checkout", "-q", "main")
    state = g.build_state(g.GitRepo(str(repo)), {})
    feature = next(b for b in state["side_branches"] if b["name"] == "feature")
    assert feature["pushed"] is False


def test_large_staged_blob_is_not_green_at_exact_threshold(repo):
    with (repo / "large.bin").open("wb") as out:
        out.truncate(g.LARGE_FILE_WARN)
    git(repo, "add", "large.bin")
    state = g.build_state(g.GitRepo(str(repo)), {})
    assert state["scores"]["safe_commit_band"] != "GO"


def test_missing_safety_evidence_never_defaults_to_clean():
    scores = g.compute_scores({})
    assert scores["safe_commit_band"] != "GO"
    assert scores["safe_delete_band"] != "GO"


def action(repo, name, target=None):
    return g.assess_action(g.build_state(g.GitRepo(str(repo)), {"quick": True}), name, target)


def test_explicit_noops_are_allowed_but_blanket_discard_is_not(repo):
    assert not mcp.check_discard(str(repo))["safe"]
    for name in ("discard_tracked", "clean_untracked", "clean_ignored"):
        assert action(repo, name)["safe"], name
    reset = action(repo, "reset_hard", "HEAD")
    assert reset["safe"] and reset["resolved_target"] == git(repo, "rev-parse", "HEAD").stdout.strip()
    assert not action(repo, "reset_hard")["safe"]


def test_ignored_data_blocks_only_affected_clean_scope(repo):
    (repo / ".gitignore").write_text("local-data/\n")
    git(repo, "add", ".gitignore")
    git(repo, "commit", "-qm", "ignore local data")
    (repo / "local-data").mkdir()
    (repo / "local-data/precious.txt").write_text("unique fixture\n")
    assert action(repo, "clean_untracked")["safe"]
    assert not action(repo, "clean_ignored")["safe"]
    assert action(repo, "reset_hard", "HEAD")["safe"]


def test_empty_untracked_directories_are_not_clean_noops(repo):
    (repo / "precious-empty").mkdir()
    state = g.build_state(g.GitRepo(str(repo)), {"quick": True})
    assert not state["status"]["untracked"]
    assert "precious-empty/" in state["untracked_inventory"]
    assert not state["actions"]["clean_untracked"]["safe"]
    assert not state["actions"]["clean_ignored"]["safe"]


def test_reset_target_not_cleanliness_controls_commit_loss(repo, tmp_path):
    upstream(repo, tmp_path)
    git(repo, "commit", "--allow-empty", "-qm", "local work")
    assert action(repo, "reset_hard", "HEAD")["safe"]
    assert not action(repo, "reset_hard", "origin/main")["safe"]


def test_restore_from_index_preserves_staged_only_work(repo):
    (repo / "tracked.txt").write_text("staged work\n")
    git(repo, "add", "tracked.txt")
    assert action(repo, "discard_tracked")["safe"]
    assert not action(repo, "reset_hard", "HEAD")["safe"]
    assert action(repo, "commit_index")["safe"]


def test_commit_assesses_index_not_unrelated_working_data(repo):
    (repo / "tracked.txt").write_text("staged work\n")
    git(repo, "add", "tracked.txt")
    (repo / "tracked.txt").write_bytes(b"x" * (g.LARGE_FILE_WARN + 1))
    (repo / ".env").write_text("fixture only; not staged\n")
    assert action(repo, "commit_index")["safe"]
    assert not action(repo, "discard_tracked")["safe"]


def test_removing_a_previously_tracked_local_data_file_is_allowed(repo):
    (repo / "data.sqlite").write_text("synthetic fixture, not real user data\n")
    git(repo, "add", "data.sqlite")
    git(repo, "commit", "-qm", "fixture legacy tracked data")
    git(repo, "rm", "--cached", "data.sqlite")
    assert action(repo, "commit_index")["safe"]
    assert not action(repo, "clean_untracked")["safe"]


@pytest.mark.parametrize("data", [b"unique text\n", b"\x00\xffunique binary\x00"])
def test_stash_needs_committed_copy_not_just_applied_copy(repo, data):
    (repo / "tracked.txt").write_bytes(data)
    git(repo, "stash", "push", "-qm", "unique")
    git(repo, "stash", "apply")
    assert not action(repo, "drop_stash", "stash@{0}")["safe"]
    git(repo, "add", "tracked.txt")
    git(repo, "commit", "-qm", "retain stash version")
    assert action(repo, "drop_stash", "stash@{0}")["safe"]


def test_stash_proof_preserves_saved_index_variant_too(repo):
    (repo / "tracked.txt").write_text("unique saved index\n")
    git(repo, "add", "tracked.txt")
    (repo / "tracked.txt").write_text("different saved worktree\n")
    git(repo, "stash", "push", "-qm", "two variants")
    (repo / "tracked.txt").write_text("different saved worktree\n")
    git(repo, "add", "tracked.txt")
    git(repo, "commit", "-qm", "retain only worktree variant")
    assert not action(repo, "drop_stash", "stash@{0}")["safe"]


def test_stash_proof_includes_untracked_parent(repo):
    (repo / "unique.bin").write_bytes(b"\x00unique untracked fixture")
    git(repo, "stash", "push", "-u", "-qm", "untracked")
    assert not action(repo, "drop_stash", "stash@{0}")["safe"]
    git(repo, "stash", "apply")
    git(repo, "add", "unique.bin")
    git(repo, "commit", "-qm", "retain untracked fixture")
    assert action(repo, "drop_stash", "stash@{0}")["safe"]


def test_uncapped_unpushed_count_is_not_preview_length(repo, tmp_path):
    upstream(repo, tmp_path)
    for n in range(51):
        git(repo, "commit", "--allow-empty", "-qm", f"local {n}")
    result = mcp.get_status(str(repo))
    assert result["unpushed_commit_count"] == 51
    assert len(result["unpushed"]) <= 10


def test_other_upstream_does_not_prove_origin_equality(repo, tmp_path):
    upstream(repo, tmp_path)
    git(repo, "commit", "--allow-empty", "-qm", "not on origin")
    git(repo, "branch", "other")
    git(repo, "config", "branch.main.remote", ".")
    git(repo, "config", "branch.main.merge", "refs/heads/other")
    result = mcp.get_status(str(repo))
    assert result["ahead"] == result["behind"] == 0
    assert result["main_equals_origin_main"] is False
    assert not result["closeout"]["local_state_complete"]


def test_tag_only_unpublished_commit_cannot_pass_closeout(repo, tmp_path):
    upstream(repo, tmp_path)
    tree = git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()
    head = git(repo, "rev-parse", "HEAD").stdout.strip()
    local = git(repo, "commit-tree", tree, "-p", head, "-m", "unpublished tagged work").stdout.strip()
    git(repo, "tag", "local-only", local)
    result = mcp.get_status(str(repo))
    assert result["main_equals_origin_main"] is True
    assert result["branch_ahead_commit_count"] == 0
    assert result["unpushed_commit_count"] == 1
    assert not result["closeout"]["local_state_complete"]


def test_repeated_parent_subdirectory_queries_stay_scope_blocked(repo):
    child = repo / "subdirectory"
    child.mkdir()
    obj = g.GitRepo(str(child))
    for _ in range(2):
        state = g.build_state(obj, {"quick": True})
        assert state["topology"]["kind"] == "tracked_inside_parent"
        assert not any(a["safe"] for a in state["actions"].values())
        assert obj.root == str(child)


def test_mid_scan_ignored_creation_cannot_receive_clean_approval(repo):
    (repo / ".gitignore").write_text("local-only.txt\n")
    git(repo, "add", ".gitignore")
    git(repo, "commit", "-qm", "ignore fixture")
    obj = g.GitRepo(str(repo))
    original = obj.ignored_entries
    called = False

    def changing_inventory():
        nonlocal called
        result = original()
        if not called:
            called = True
            (repo / "local-only.txt").write_text("created during inspection\n")
        return result

    obj.ignored_entries = changing_inventory
    state = g.build_state(obj, {"quick": True})
    assert state["read_complete"] is False
    assert not state["actions"]["clean_ignored"]["safe"]


def test_source_changed_since_import_fails_closed(repo, monkeypatch):
    monkeypatch.setattr(g, "ENGINE_SOURCE_SHA256", "previous version")
    state = g.build_state(g.GitRepo(str(repo)), {"quick": True})
    assert state["read_complete"] is False
    assert not any(a["safe"] for a in state["actions"].values())


def test_direct_snapshot_does_not_write_index_or_dashboard(repo):
    before = (repo / ".git/index").read_bytes()
    g.build_state(g.GitRepo(str(repo)), {"quick": True})
    assert (repo / ".git/index").read_bytes() == before
    assert not (repo / ".git-real").exists()


def test_cli_failed_publication_never_claims_snapshot_written(repo):
    destination = repo / ".git-real/git-real.json"
    destination.mkdir(parents=True)
    result = subprocess.run(
        [sys.executable, g.__file__, str(repo), "--quick", "--once"],
        capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "snapshot written" not in result.stdout
    assert destination.is_dir()


def test_atomic_snapshots_echo_fresh_request_ids(repo):
    import json
    ids = []
    for token in ("first-request", "second-request"):
        result = subprocess.run(
            [sys.executable, g.__file__, str(repo), "--quick", "--once", "--request-id", token],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, result.stderr
        state = json.loads((repo / ".git-real/git-real.json").read_text())
        assert state["request_id"] == token
        ids.append(state["publication_id"])
    assert ids[0] != ids[1]


def test_mcp_carries_failed_read_evidence_instead_of_zero_counts(repo, monkeypatch):
    original = g.GitRepo.status

    def failed(self):
        result = original(self)
        result.update(ok=False, complete=False, error="injected failure")
        return result

    monkeypatch.setattr(g.GitRepo, "status", failed)
    result = mcp.get_status(str(repo))
    assert result["read_complete"] is False
    assert result["dirty_file_count"] is None
    assert result["conflict_count"] is None
    assert result["read_errors"]
    assert not any(a["safe"] for a in result["actions"].values())


def test_noncanonical_stash_cannot_hide_unique_parent_ancestry(repo):
    base = git(repo, "rev-parse", "HEAD").stdout.strip()
    tree = git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()
    (repo / "ancestry-only.txt").write_text("unique parent-only fixture\n")
    git(repo, "add", "ancestry-only.txt")
    git(repo, "commit", "-qm", "unique ancestry")
    unique = git(repo, "rev-parse", "HEAD").stdout.strip()
    index = git(repo, "commit-tree", tree, "-p", unique, "-m", "noncanonical index").stdout.strip()
    stash = git(repo, "commit-tree", tree, "-p", base, "-p", index, "-m", "crafted stash").stdout.strip()
    git(repo, "update-ref", "refs/heads/main", base, unique)
    git(repo, "read-tree", "--reset", "-u", base)
    git(repo, "update-ref", "--create-reflog", "-m", "crafted fixture", "refs/stash", stash)
    assert unique in git(repo, "rev-list", "--all").stdout
    result = action(repo, "drop_stash", "stash@{0}")
    assert result["safe"] is False
    assert any("ancestry" in reason for reason in result["reasons"])


def test_detached_head_commit_requires_a_durable_branch(repo):
    git(repo, "checkout", "--detach", "-q")
    (repo / "tracked.txt").write_text("would be detached work\n")
    git(repo, "add", "tracked.txt")
    assert not action(repo, "commit_index")["safe"]


def test_active_bisect_is_not_a_completed_workflow(repo, tmp_path):
    upstream(repo, tmp_path)
    git(repo, "bisect", "start")
    state = g.build_state(g.GitRepo(str(repo)), {"quick": True})
    assert "BISECT_START" in state["active_operations"]
    assert not state["closeout"]["local_state_complete"]
    (repo / "tracked.txt").write_text("edit during bisect\n")
    git(repo, "add", "tracked.txt")
    assert not action(repo, "commit_index")["safe"]


def test_legacy_summary_never_grants_blanket_discard(repo, tmp_path):
    upstream(repo, tmp_path)
    state = g.build_state(g.GitRepo(str(repo)), {"quick": True})
    assert state["closeout"]["local_state_complete"]
    assert state["scores"]["safe_delete_band"] != "GO"
    assert state["scores"]["safe_delete_authorizes_action"] is False
    assert state["actions"]["clean_untracked"]["safe"]


def test_empty_or_missing_fleet_is_not_verified_complete(tmp_path):
    for root in (tmp_path, tmp_path / "missing"):
        result = mcp.get_fleet(str(root))
        assert result["read_complete"] is False
        assert result["read_errors"]


def test_fleet_and_ignore_write_reject_stale_adapter(repo, monkeypatch):
    monkeypatch.setattr(mcp, "_ADAPTER_SOURCE_SHA256", "old adapter")
    assert mcp.get_fleet(str(repo))["read_complete"] is False
    assert mcp.do_gitignore_add(str(repo), "fixture/")["ok"] is False
    assert not (repo / ".gitignore").exists()


def test_agent_wiring_cannot_overwrite_symlink_target(repo, tmp_path):
    outside = tmp_path / "outside-instructions.md"
    outside.write_text("preserve outside content\n")
    (repo / "AGENTS.md").symlink_to(outside)
    with pytest.raises(OSError):
        g.wire_agents(str(repo))
    assert outside.read_text() == "preserve outside content\n"


def test_negated_ssh_host_is_not_selected(tmp_path):
    cfg = tmp_path / "ssh-config"
    cfg.write_text("Host * !github.com\n  HostName incorrect.invalid\n  IdentityFile wrong\n")
    result = g.resolve_remote_identity("git@github.com:fixture/repo.git", str(cfg))
    assert result["real_host"] == "github.com"
    assert result["identity_pinned"] is False
    assert result["authentication_verified"] is False


@pytest.mark.parametrize("url", [
    "HTTPS://fixture-user:fixture-password@example.invalid/repo.git",
    "ssh://fixture-user:fixture-password@example.invalid/repo.git",
    "https://example.invalid/repo.git?password=fixture-password",
])
def test_displayed_remote_redacts_synthetic_userinfo_and_query(url):
    assert "fixture-password" not in g.redact_url_credentials(url)
