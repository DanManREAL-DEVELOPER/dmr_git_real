"""Tests for secret-in-history detection.
Committed secret => incident; working-tree-only secret => caught in time; no --history => no scan;
committed-then-DELETED secret => still an incident (full commit-graph walk, not current-tree blobs).
Run:  python tests/test_secret_history.py
"""
import os, sys, subprocess, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import gitreal

KEY = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'


def _git(d, *a):
    subprocess.run(["git", "-C", d, *a], capture_output=True)


def _repo():
    d = tempfile.mkdtemp()
    _git(d, "init", "-q"); _git(d, "config", "user.email", "developer@example.invalid")
    _git(d, "config", "user.name", "t"); _git(d, "checkout", "-q", "-b", "main")
    return d


def _state(d, history=True):
    cfg = {"muted_secret_files": []}
    if history:
        cfg["check_history"] = True
    return gitreal.build_state(gitreal.GitRepo(d), cfg)


def main():
    passed = failed = 0

    # 1) secret committed to a tracked file -> incident
    d = _repo()
    open(os.path.join(d, "config.py"), "w").write(KEY)
    _git(d, "add", "."); _git(d, "commit", "-qm", "add config")
    s = _state(d)
    ok = s["secrets_in_history"] >= 1
    print(("PASS" if ok else "FAIL"), "committed secret -> incident   ->", s["secrets_in_history"])
    passed += ok; failed += (not ok)

    # 2) secret only in working tree (never committed) -> caught in time
    d2 = _repo()
    open(os.path.join(d2, "a.txt"), "w").write("x"); _git(d2, "add", "."); _git(d2, "commit", "-qm", "init")
    open(os.path.join(d2, ".env"), "w").write(KEY)
    s2 = _state(d2)
    ok2 = len(s2["secrets"]) >= 1 and s2["secrets_in_history"] == 0
    print(("PASS" if ok2 else "FAIL"), "working-tree only -> caught     ->", s2["secrets_in_history"])
    passed += ok2; failed += (not ok2)

    # 3) without --history -> no history scan performed
    s3 = _state(d, history=False)
    ok3 = s3["history_checked"] is False and s3["secrets_in_history"] == 0
    print(("PASS" if ok3 else "FAIL"), "no --history -> no scan         ->", s3["history_checked"])
    passed += ok3; failed += (not ok3)

    # 4) secret committed THEN deleted (git rm) -> NOT in the current tree, but STILL an
    #    incident. This is the blind spot: a current-tree/tracked-blob scan reports it clean.
    d4 = _repo()
    open(os.path.join(d4, "leak.py"), "w").write(KEY)
    _git(d4, "add", "."); _git(d4, "commit", "-qm", "oops added secret")
    _git(d4, "rm", "-q", "leak.py"); _git(d4, "commit", "-qm", "remove secret")
    open(os.path.join(d4, "ok.txt"), "w").write("clean\n")
    _git(d4, "add", "."); _git(d4, "commit", "-qm", "later work")
    s4 = _state(d4)
    ok4 = len(s4["secrets"]) == 0 and s4["secrets_in_history"] >= 1
    print(("PASS" if ok4 else "FAIL"), "committed-then-deleted -> caught->", s4["secrets_in_history"])
    passed += ok4; failed += (not ok4)

    total = passed + failed
    print(f"\n{passed}/{total} passed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
