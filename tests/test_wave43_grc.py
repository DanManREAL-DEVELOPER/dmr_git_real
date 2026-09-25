#!/usr/bin/env python3
"""WAVE 43 GIT_REAL highs: GRC-01, GRC-02, GRC-03, GRC-06.

Isolated tmp git repos and in-memory HTML only. Never touches workshop trees.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

import gitreal as g  # noqa: E402
import gitreal_mcp as mcp  # noqa: E402


def _git(cwd, *args, check=True):
    return subprocess.run(
        ["git", "-C", str(cwd), *args],
        check=check,
        capture_output=True,
        text=True,
    )


def _init_repo(path) -> str:
    path = str(path)
    os.makedirs(path, exist_ok=True)
    subprocess.run(["git", "init", "-q", "-b", "main", path], check=True)
    _git(path, "config", "user.email", "wave43@example.invalid")
    _git(path, "config", "user.name", "gitreal-test")
    return path


def _commit_file(path, name, body, msg):
    with open(os.path.join(path, name), "w", encoding="utf-8") as fh:
        fh.write(body)
    _git(path, "add", name)
    _git(path, "commit", "-qm", msg)


def _state(path):
    return g.build_state(g.GitRepo(path), {})


# ---------------------------------------------------------------------------
# GRC-01 — Discard approval can include unsaved staged work and conflicts
# ---------------------------------------------------------------------------
def test_grc01_staged_only_is_not_ok_to_discard(tmp_path):
    d = _init_repo(tmp_path / "staged")
    _commit_file(d, "notes.txt", "v1\n", "initial")
    with open(os.path.join(d, "notes.txt"), "w", encoding="utf-8") as fh:
        fh.write("v2 staged unsaved\n")
    _git(d, "add", "notes.txt")

    st = _state(d)
    scores = st["scores"]
    disc = mcp.check_discard(d)

    assert st["status"]["staged"]
    assert not st["status"]["modified"]
    assert scores["safe_delete"] < 80
    assert scores["safe_delete_band"] != "GO"
    assert scores["safe_delete_label"] != "SAFE TO DISCARD"
    assert disc["recommendation"] != "OK_TO_DISCARD"
    assert disc["recommendation"] in ("REVIEW_FIRST", "DO_NOT_DISCARD")


def test_grc01_conflict_only_is_not_discard_approved(tmp_path):
    d = _init_repo(tmp_path / "conflict")
    _commit_file(d, "f.txt", "base\n", "base")
    _git(d, "checkout", "-q", "-b", "other")
    _commit_file(d, "f.txt", "other\n", "other")
    _git(d, "checkout", "-q", "main")
    _commit_file(d, "f.txt", "mainline\n", "mainline")
    merged = _git(d, "merge", "other", check=False)
    assert merged.returncode != 0

    st = _state(d)
    scores = st["scores"]
    disc = mcp.check_discard(d)

    assert st["status"]["conflicts"]
    assert scores["safe_delete"] < 40
    assert scores["safe_delete_band"] == "STOP"
    assert "SAFE TO DISCARD" not in scores["safe_delete_label"]
    assert disc["recommendation"] == "DO_NOT_DISCARD"


# ---------------------------------------------------------------------------
# GRC-02 — Failed Git reads can be reported as a clean repository
# ---------------------------------------------------------------------------
def test_grc02_failed_status_is_not_a_clean_tree(tmp_path):
    d = _init_repo(tmp_path / "failstat")
    _commit_file(d, "ok.txt", "ok\n", "ok")
    repo = g.GitRepo(d)
    orig = repo._run

    def fake(*args, **kwargs):
        if args and args[0] == "status":
            return "", 124, "git command timed out"
        return orig(*args, **kwargs)

    repo._run = fake
    st = repo.status()
    assert st.get("ok") is False
    assert st.get("complete") is False
    assert st.get("error")

    state = g.build_state(repo, {})
    assert state.get("read_complete") is False
    assert state["scores"]["safe_commit_band"] != "GO"
    assert state["scores"]["safe_delete_band"] != "GO"
    assert state["scores"]["safe_delete_label"] != "SAFE TO DISCARD"
    assert state["scores"]["safe_commit"] == 0
    assert state["scores"]["safe_delete"] == 0


def test_grc02_fleet_exception_is_not_counted_clean(tmp_path, monkeypatch):
    boom_path = str(tmp_path / "missing-repo")

    def boom(path, config):
        raise RuntimeError("status timeout")

    monkeypatch.setattr(g, "repo_summary", boom)
    fleet = g.build_fleet_state(str(tmp_path), [boom_path], {})
    row = fleet["repos"][0]
    assert row.get("error")
    assert row.get("read_complete") is False
    assert row.get("is_repo") is not True
    assert fleet["totals"]["clean_repos"] == 0


# ---------------------------------------------------------------------------
# GRC-03 — Stash advice can call unknown or unique work safe to clear
# ---------------------------------------------------------------------------
def test_grc03_untracked_only_stash_is_not_empty_or_safe_to_clear(tmp_path):
    d = _init_repo(tmp_path / "stash-u")
    _commit_file(d, "tracked.txt", "keep\n", "base")
    with open(os.path.join(d, "unique-untracked.txt"), "w", encoding="utf-8") as fh:
        fh.write("never committed unique work\n")
    _git(d, "stash", "push", "-u", "-qm", "untracked-only")

    details = g.GitRepo(d).stash_details()
    assert details, "expected the untracked stash to be inspected"
    assert details[0]["verdict"] != "empty"
    assert details[0]["verdict"] in ("unmerged", "unknown")

    scores = _state(d)["scores"]
    reasons = " ".join(scores["safe_delete_reasons"]).lower()
    assert "safe to clear" not in reasons
    assert "none hold unique work" not in reasons


def test_grc03_failed_stash_show_is_unknown_not_empty(tmp_path):
    d = _init_repo(tmp_path / "stash-fail")
    _commit_file(d, "t.txt", "a\n", "base")
    with open(os.path.join(d, "t.txt"), "w", encoding="utf-8") as fh:
        fh.write("b\n")
    _git(d, "stash", "push", "-qm", "edits")
    repo = g.GitRepo(d)
    orig = repo._run

    def fake(*args, **kwargs):
        if args[:2] == ("stash", "show"):
            return "", 1, "stash show failed"
        return orig(*args, **kwargs)

    repo._run = fake
    details = repo.stash_details()
    assert details
    assert details[0]["verdict"] == "unknown"
    assert details[0].get("inspection_ok") is False


def test_grc03_unknown_or_uninspected_stash_is_not_safe_to_clear():
    base = {
        "status": {
            "staged": [], "modified": [], "conflicts": [], "untracked": [],
            "ok": True, "complete": True,
        },
        "files": [],
        "unpushed": [],
        "topology": {"kind": "own_repo"},
    }
    unknown = g.compute_scores({
        **base,
        "stash_summary": {
            "count": 1, "empty": 0, "superseded": 0, "unmerged": 0,
            "unknown": 1, "uninspected": 0, "inspection_complete": False,
        },
    })
    truncated = g.compute_scores({
        **base,
        "stash_summary": {
            "count": 30, "empty": 0, "superseded": 25, "unmerged": 0,
            "unknown": 0, "uninspected": 5, "inspection_complete": False,
        },
    })
    for scores in (unknown, truncated):
        blob = " ".join(scores["safe_delete_reasons"]).lower()
        assert "safe to clear" not in blob
        assert "none hold unique work" not in blob


def test_grc03_stash_presence_is_working_tree_not_head(tmp_path):
    d = _init_repo(tmp_path / "stash-basis")
    _commit_file(d, "app.txt", "l1\nl2\n", "base")
    with open(os.path.join(d, "app.txt"), "w", encoding="utf-8") as fh:
        fh.write("l1\nUNIQUE\nl2\n")
    _git(d, "stash", "push", "-qm", "unique")
    details = g.GitRepo(d).stash_details()
    assert details
    row = details[0]
    assert row.get("presence_basis") == "working_tree"
    assert "already_in_working_tree" in row
    assert row.get("already_in_head") is not True


# ---------------------------------------------------------------------------
# GRC-06 — Repository text is not consistently escaped in dashboard HTML
# ---------------------------------------------------------------------------
def test_grc06_root_name_is_html_escaped():
    payload = '</title><img src=x onerror=alert(1)>'
    html = g.render_html({"root_name": payload, "scores": {}}, 8787, 4.0)
    assert payload not in html
    assert "&lt;/title&gt;" in html


def test_grc06_embedded_json_cannot_break_script():
    payload = "</script><script>alert(1)</script>"
    html = g.render_html({"root_name": "repo", "xss": payload}, 8787, 4.0)
    fleet = g.render_fleet_html(
        {"xss": payload, "totals": {"repos": 1}, "repos": []}, 8787, 4.0
    )
    for doc in (html, fleet):
        assert payload not in doc
        assert "</script><script>alert(1)</script>" not in doc


def test_grc06_stat_helper_escapes_repo_text():
    compact = g.HTML_TEMPLATE.replace(" ", "")
    assert "stat('Currentbranch',esc(" in compact
    assert "st.upstream?esc(st.upstream)" in compact
    assert "stat('Defaultbranch',esc(" in compact


def test_grc06_clean_committed_tree_still_discard_ok(tmp_path):
    d = _init_repo(tmp_path / "clean")
    _commit_file(d, "clean.txt", "clean\n", "clean")
    disc = mcp.check_discard(d, operation="clean_untracked")
    assert disc["recommendation"] == "OK_TO_DISCARD"
    assert disc["safe_discard_pct"] == 100


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q", "--tb=short"]))
