"""Tests for the enriched git_real_status MCP payload.

Verifies it surfaces WHAT each thing is, not just how many: named side branches with
their last commit subject, the unpushed commits with subjects, and HEAD's subject. This
is the feature that lets an agent answer "what was that branch I forgot?" without a git-log
expedition. get_status() is plain logic, so this runs without the MCP SDK installed.

Run:  python tests/test_mcp_status.py   (exit 0 = all pass)
"""
import os, sys, subprocess, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import gitreal_mcp


def _git(d, *a):
    return subprocess.run(["git", "-C", d, *a], capture_output=True, check=True)


def _repo():
    d = tempfile.mkdtemp()
    _git(d, "init", "-q")
    _git(d, "config", "user.email", "developer@example.invalid")
    _git(d, "config", "user.name", "t")
    _git(d, "checkout", "-q", "-b", "main")
    return d


def main():
    passed = failed = 0

    def check(label, cond):
        nonlocal passed, failed
        ok = bool(cond)
        passed += ok
        failed += (not ok)
        print(("PASS" if ok else "FAIL"), label)

    d = _repo()
    # a commit on main
    open(os.path.join(d, "a.txt"), "w").write("a\n")
    _git(d, "add", "."); _git(d, "commit", "-qm", "initial commit on main")
    # Give main a real upstream before making another local commit. GIT_REAL
    # deliberately reports zero unpushed commits when no upstream exists,
    # because a remote-less repository has nowhere to push them.
    remote = tempfile.mkdtemp()
    subprocess.run(["git", "init", "--bare", "-q", remote], check=True, capture_output=True)
    _git(d, "remote", "add", "origin", remote)
    _git(d, "push", "-qu", "origin", "main")
    # a side branch with a memorable, unmerged commit (the "forgotten branch")
    _git(d, "checkout", "-q", "-b", "feature/old-idea")
    open(os.path.join(d, "b.txt"), "w").write("b\n")
    _git(d, "add", "."); _git(d, "commit", "-qm", "wip: trying the dark theme")
    # back to main and move it forward so the feature stays unmerged
    _git(d, "checkout", "-q", "main")
    open(os.path.join(d, "c.txt"), "w").write("c\n")
    _git(d, "add", "."); _git(d, "commit", "-qm", "main moves on")

    st = gitreal_mcp.get_status(d)

    # backward-compatible keys still present
    check("keeps safe_commit_pct", "safe_commit_pct" in st)
    check("keeps side_branch_count", st.get("side_branch_count") >= 1)
    check("keeps unpushed_commit_count", st.get("unpushed_commit_count") >= 1)

    # NEW: HEAD subject
    check("last_commit carries subject", (st.get("last_commit") or {}).get("subject") == "main moves on")

    # NEW: the side branch is NAMED and carries its last commit subject
    names = {b.get("name"): b for b in (st.get("side_branches") or [])}
    check("side branch is named", "feature/old-idea" in names)
    check("side branch carries its commit subject",
          names.get("feature/old-idea", {}).get("subject") == "wip: trying the dark theme")
    check("side branch reports merged + pushed state",
          names.get("feature/old-idea", {}).get("merged_into_default") is False
          and names.get("feature/old-idea", {}).get("pushed") is False)

    # NEW: unpushed commits carry subjects (not just a count)
    up = st.get("unpushed") or []
    check("unpushed list carries subjects", "main moves on" in [c.get("subject") for c in up])
    check("unpushed entries have hash + subject", all(c.get("hash") and c.get("subject") for c in up))

    total = passed + failed
    print(f"\n{passed}/{total} passed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
