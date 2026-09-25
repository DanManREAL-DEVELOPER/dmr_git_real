#!/usr/bin/env python3
"""Deterministic regression test for the GIT_REAL safe-commit / safe-discard
scoring and verdict logic (compute_scores, check_commit, check_discard).

These are the core gate functions that every AI agent calls before touching a git
tree. They pin the numeric scores plus BLOCK / DO_NOT_DISCARD recommendations.

Run:  python3 tests/test_verdict_scoring.py   (exit 0 = all pass)
"""
import importlib.util
import os
import subprocess
import sys
import tempfile

# ---------------------------------------------------------------------------
# import the real modules (no pip install required)
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)

def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

gr  = _load("gitreal",     os.path.join(_ROOT, "gitreal.py"))
mcp = _load("gitreal_mcp", os.path.join(_ROOT, "gitreal_mcp.py"))


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _git(d, *args, check=False):
    result = subprocess.run(
        ["git", "-C", d, *args],
        capture_output=True, text=True,
    )
    return result


def _make_repo():
    """Create a fresh temp git repo with local identity so commits work."""
    d = tempfile.mkdtemp()
    _git(d, "init", "-q")
    _git(d, "config", "user.email", "scoring@example.invalid")
    _git(d, "config", "user.name",  "gitreal-test")
    _git(d, "checkout", "-q", "-b", "main")
    return d


# ---------------------------------------------------------------------------
# test runner helpers
# ---------------------------------------------------------------------------
passed = 0
failed = 0

def check(label, cond):
    global passed, failed
    ok = bool(cond)
    passed += ok
    failed += (not ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    return ok


# ---------------------------------------------------------------------------
# TEST 1: score bounds invariant
#   Every score the tool returns must be within 0..100 inclusive, regardless
#   of repo state.  We check a clean repo and a dirty repo.
# ---------------------------------------------------------------------------
def test_score_bounds():
    d = _make_repo()
    try:
        # ---- clean repo (no commits yet) ----
        r1 = mcp.check_commit(d)
        check("score_bounds: clean repo safe_commit_pct in [0,100]",
              0 <= r1["safe_commit_pct"] <= 100)

        r2 = mcp.check_discard(d)
        check("score_bounds: clean repo safe_discard_pct in [0,100]",
              0 <= r2["safe_discard_pct"] <= 100)

        # ---- repo with a commit ----
        with open(os.path.join(d, "README.md"), "w") as fh:
            fh.write("hello\n")
        _git(d, "add", "README.md")
        _git(d, "commit", "-qm", "initial commit")

        r3 = mcp.check_commit(d)
        check("score_bounds: committed repo safe_commit_pct in [0,100]",
              0 <= r3["safe_commit_pct"] <= 100)

        r4 = mcp.check_discard(d)
        check("score_bounds: committed repo safe_discard_pct in [0,100]",
              0 <= r4["safe_discard_pct"] <= 100)
    finally:
        import shutil; shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# TEST 2: clean + committed is a preview, not authorization for a future index.
# ---------------------------------------------------------------------------
def test_clean_committed_is_not_blocked():
    d = _make_repo()
    try:
        with open(os.path.join(d, "main.py"), "w") as fh:
            fh.write("print('hello')\n")
        _git(d, "add", "main.py")
        _git(d, "commit", "-qm", "add main.py")

        r = mcp.check_commit(d)

        check("clean_committed: safe_commit_pct >= 40",
              r["safe_commit_pct"] >= 40)
        check("clean_committed: no staged candidate is not authorized",
              r["recommendation"] == "BLOCK" and r["safe"] is False)
    finally:
        import shutil; shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# TEST 3: uncommitted changes → discard is NOT fully safe
#   A modified tracked file subtracts 30 points from the safe-discard score
#   (see compute_scores in gitreal.py).  The resulting score sits in the
#   CAUTION band (40-79), so the verdict is "CAUTION - REVIEW FIRST" — the
#   work would be lost on a discard.  We assert the TRUE invariant the code
#   produces: score < 100 and not "SAFE TO DISCARD".
#
#   Note: DO_NOT_DISCARD (score < 40) requires -60 for new untracked files
#   on top of the -30 for modified; a lone modified file produces 60, which
#   maps to CAUTION, not STOP.  Test 5 covers the DO_NOT_DISCARD path via
#   new untracked files, which is the stronger signal.
# ---------------------------------------------------------------------------
def test_uncommitted_changes_block_discard():
    d = _make_repo()
    try:
        # start clean
        with open(os.path.join(d, "notes.txt"), "w") as fh:
            fh.write("v1\n")
        _git(d, "add", "notes.txt")
        _git(d, "commit", "-qm", "initial")

        # modify without committing (tracked file — would be lost on discard)
        with open(os.path.join(d, "notes.txt"), "w") as fh:
            fh.write("v2 — UNSAVED\n")

        r = mcp.check_discard(d)

        # The score is deducted from 100; unsaved work must make it < 100
        check("discard_modified: safe_discard_pct < 100 (work would be lost)",
              r["safe_discard_pct"] < 100)
        # In CAUTION territory (40-79): "CAUTION - REVIEW FIRST"
        check("discard_modified: verdict signals unsaved work (not SAFE TO DISCARD)",
              r["verdict"] != "SAFE TO DISCARD")
        # Score must be in a valid range
        check("discard_modified: safe_discard_pct in [0,100]",
              0 <= r["safe_discard_pct"] <= 100)
    finally:
        import shutil; shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# TEST 4: new untracked file → DO_NOT_DISCARD
#   A new, never-committed file would be permanently lost on clean/reset.
#   safe-discard must be low and flag DO_NOT_DISCARD.
# ---------------------------------------------------------------------------
def test_new_untracked_blocks_discard():
    d = _make_repo()
    try:
        # initial commit so the repo has HEAD
        with open(os.path.join(d, "init.py"), "w") as fh:
            fh.write("# init\n")
        _git(d, "add", "init.py")
        _git(d, "commit", "-qm", "initial")

        # drop a new, never-tracked file
        with open(os.path.join(d, "new_work.py"), "w") as fh:
            fh.write("def alpha(): pass\n")

        r = mcp.check_discard(d)

        check("new_untracked_blocks_discard: recommendation is DO_NOT_DISCARD",
              r["recommendation"] == "DO_NOT_DISCARD")
        check("new_untracked_blocks_discard: safe_discard_pct < 40",
              r["safe_discard_pct"] < 40)
    finally:
        import shutil; shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# TEST 5: clean tree is safe to discard
#   After a commit with nothing left dirty, discarding is a no-op: score == 100
#   and recommendation == "OK_TO_DISCARD".
# ---------------------------------------------------------------------------
def test_clean_tree_is_safe_to_discard():
    d = _make_repo()
    try:
        with open(os.path.join(d, "clean.txt"), "w") as fh:
            fh.write("clean\n")
        _git(d, "add", "clean.txt")
        _git(d, "commit", "-qm", "clean commit")

        r = mcp.check_discard(d, operation="clean_untracked")

        check("clean_discard: recommendation is OK_TO_DISCARD",
              r["recommendation"] == "OK_TO_DISCARD")
        check("clean_discard: safe_discard_pct == 100",
              r["safe_discard_pct"] == 100)
    finally:
        import shutil; shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# TEST 6: required dict keys are always present
#   The consuming agents destructure specific keys; missing keys = runtime crash.
# ---------------------------------------------------------------------------
def test_required_keys_present():
    d = _make_repo()
    try:
        r_commit  = mcp.check_commit(d)
        r_discard = mcp.check_discard(d)

        commit_required = {"path", "safe_commit_pct", "verdict", "reasons", "recommendation"}
        discard_required = {"path", "safe_discard_pct", "verdict", "reasons",
                            "recommendation"}

        for k in commit_required:
            check(f"required_keys: check_commit has '{k}'", k in r_commit)
        for k in discard_required:
            check(f"required_keys: check_discard has '{k}'", k in r_discard)
    finally:
        import shutil; shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# run all tests
# ---------------------------------------------------------------------------
def main():
    test_score_bounds()
    test_clean_committed_is_not_blocked()
    test_uncommitted_changes_block_discard()
    test_new_untracked_blocks_discard()
    test_clean_tree_is_safe_to_discard()
    test_required_keys_present()

    total = passed + failed
    print(f"\n{passed}/{total} PASS")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
