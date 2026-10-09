"""Commit review for paths that follow what HEAD already tracks.

Artifact-like names and large files still block when they are new to the
repository. They become review notes when HEAD already tracks the same location
(a vendored tree, a same-kind file in the same directory) or the file was
already large in HEAD, so the change is stored as a delta.
"""
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gitreal as g


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          capture_output=True, text=True).stdout


def initialize(repo, files):
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.name", "Fixture")
    git(repo, "config", "user.email", "fixture@example.invalid")
    for name, data in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "base")


def commit_verdict(repo, *staged):
    git(repo, "add", "--", *staged)
    return g.build_state(g.GitRepo(str(repo)), {"quick": True})["actions"]["commit_index"]


def test_vendored_file_under_tracked_vendor_tree_is_a_review_note(tmp_path):
    repo = tmp_path / "repo"
    initialize(repo, {"web/vendor/three/examples/loader.js": b"export {}\n", "README.md": b"x\n"})
    new = repo / "web/vendor/three/build/three.min.js"
    new.parent.mkdir(parents=True)
    new.write_text("/* vendored */\n")
    action = commit_verdict(repo, "web/vendor/three/build/three.min.js")
    assert action["decision"] == "ALLOW" and action["safe"] is True, action["reasons"]


def test_vendored_file_without_tracked_vendor_tree_still_blocks(tmp_path):
    repo = tmp_path / "repo"
    initialize(repo, {"README.md": b"x\n"})
    new = repo / "web/vendor/three/build/three.min.js"
    new.parent.mkdir(parents=True)
    new.write_text("/* vendored */\n")
    action = commit_verdict(repo, "web/vendor/three/build/three.min.js")
    assert action["decision"] == "BLOCK"
    assert any("possible artifact" in reason for reason in action["reasons"])


def test_staged_files_do_not_establish_themselves(tmp_path):
    repo = tmp_path / "repo"
    initialize(repo, {"README.md": b"x\n"})
    for name in ("a", "b"):
        path = repo / "dist" / f"{name}.js"
        path.parent.mkdir(exist_ok=True)
        path.write_text(name + "\n")
    action = commit_verdict(repo, "dist/a.js", "dist/b.js")
    assert action["decision"] == "BLOCK"


def test_log_beside_a_tracked_log_is_a_review_note_but_a_new_log_location_blocks(tmp_path):
    repo = tmp_path / "repo"
    initialize(repo, {"qa/run1/pytest.log": b"ok\n"})
    (repo / "qa/run1/rerun.log").write_text("ok\n")
    assert commit_verdict(repo, "qa/run1/rerun.log")["decision"] == "ALLOW"
    git(repo, "commit", "-qm", "log")
    (repo / "qa/run2").mkdir()
    (repo / "qa/run2/pytest.log").write_text("ok\n")
    assert commit_verdict(repo, "qa/run2/pytest.log")["decision"] == "BLOCK"


def test_change_to_a_file_already_large_in_head_is_a_review_note(tmp_path):
    repo = tmp_path / "repo"
    big = b"a" * (g.LARGE_FILE_WARN + 10)
    initialize(repo, {"game/index.html": big})
    (repo / "game/index.html").write_bytes(big[:-1] + b"b")
    action = commit_verdict(repo, "game/index.html")
    assert action["decision"] == "ALLOW" and action["safe"] is True, action["reasons"]


def test_new_large_file_still_blocks(tmp_path):
    repo = tmp_path / "repo"
    initialize(repo, {"README.md": b"x\n"})
    (repo / "big.bin").write_bytes(b"a" * (g.LARGE_FILE_WARN + 10))
    action = commit_verdict(repo, "big.bin")
    assert action["decision"] == "BLOCK"
    assert any("large file" in reason for reason in action["reasons"])
