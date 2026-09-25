#!/usr/bin/env python3
"""v1.1 situational-awareness features (script-style; exits 0 on pass, 1 on fail).

Covers the six gaps found during the 2026-07-07 _MAIN cleanup:
  #1 fleet recursion into nested repos
  #2 stash triage (superseded vs unmerged)
  #3 repo topology (own repo vs tracked-inside-parent)
  #4 paths+sizes named in warnings
  #5 remote-identity resolution (ssh alias / bare host / https)
  #6 push-weight (pack size + largest blobs)
"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import gitreal as g  # noqa: E402

fails = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    if not cond:
        fails.append(name)


def _git(cwd, *args):
    subprocess.run(["git", "-C", cwd, *args], check=True,
                   capture_output=True, text=True)


with tempfile.TemporaryDirectory() as tmp:
    root = os.path.join(tmp, "workspace")
    child = os.path.join(root, "child_repo")
    os.makedirs(child)
    # workspace root repo
    subprocess.run(["git", "init", "-q", "-b", "main", root], check=True)
    _git(root, "config", "user.email", "situational@example.invalid")
    _git(root, "config", "user.name", "t")
    open(os.path.join(root, "root.txt"), "w").write("root\n")
    _git(root, "add", "root.txt")
    _git(root, "commit", "-qm", "root init")
    # nested child repo
    subprocess.run(["git", "init", "-q", "-b", "main", child], check=True)
    _git(child, "config", "user.email", "situational@example.invalid")
    _git(child, "config", "user.name", "t")
    open(os.path.join(child, "app.txt"), "w").write("l1\nl2\n")
    _git(child, "add", "app.txt")
    _git(child, "commit", "-qm", "child init")

    # #1 fleet recursion: root repo + nested child both discovered
    repos = g.discover_repos(root, max_depth=3)
    check("#1 fleet finds root+nested", len(repos) >= 2, f"{len(repos)} repos")
    check("#1 nested child discovered", any(r.rstrip("/").endswith("child_repo") for r in repos))

    # #3 topology
    st_root = g.build_state(g.GitRepo(root), {})
    check("#3 root is own_repo", st_root["topology"]["kind"] == "own_repo")
    subdir = os.path.join(root, "sub")
    os.makedirs(subdir)
    open(os.path.join(subdir, "f.txt"), "w").write("x")
    st_sub = g.build_state(g.GitRepo(subdir), {})
    check("#3 subdir is tracked_inside_parent",
          st_sub["topology"]["kind"] == "tracked_inside_parent")

    # #2 stash triage in child: one unmerged, one superseded
    open(os.path.join(child, "app.txt"), "w").write("l1\nUNIQUE\nl2\n")
    _git(child, "stash", "push", "-qm", "unique")
    open(os.path.join(child, "app.txt"), "w").write("l1\nl2\nADDED\n")
    _git(child, "stash", "push", "-qm", "willsupersede")
    open(os.path.join(child, "app.txt"), "w").write("l1\nl2\nADDED\n")
    _git(child, "add", "app.txt")
    _git(child, "commit", "-qm", "land ADDED")
    st_child = g.build_state(g.GitRepo(child), {})
    summ = st_child["stash_summary"]
    check("#2 stash summary counts", summ["count"] == 2, str(summ))
    check("#2 one unmerged", summ["unmerged"] == 1, str(summ))
    check("#2 one superseded", summ["superseded"] == 1, str(summ))

    # #4 paths+sizes named in warnings
    open(os.path.join(child, "big.bin"), "wb").write(b"\0" * 6_000_000)
    os.makedirs(os.path.join(child, "node_modules"))
    open(os.path.join(child, "node_modules", "x.js"), "w").write("x")
    st_junk = g.build_state(g.GitRepo(child), {})
    reasons = " ".join(st_junk["scores"]["safe_commit_reasons"])
    check("#4 names large file + size", "big.bin" in reasons and "MB" in reasons, reasons[:80])
    check("#4 names build artifact path", "node_modules" in reasons)

    # #4b staged payload size comes from the index. Git LFS keeps a small
    # pointer there while the working tree contains the expanded asset.
    lfs_path = os.path.join(child, "asset.uasset")
    open(lfs_path, "wb").write(b"x" * 6_000_000)
    pointer = (b"version https://git-lfs.github.com/spec/v1\n"
               b"oid sha256:" + b"0" * 64 + b"\nsize 6000000\n")
    oid = subprocess.run(
        ["git", "-C", child, "hash-object", "-w", "--stdin"],
        input=pointer, check=True, capture_output=True,
    ).stdout.decode().strip()
    _git(child, "update-index", "--add", "--cacheinfo", f"100644,{oid},asset.uasset")
    _git(child, "update-index", "--skip-worktree", "asset.uasset")
    st_lfs = g.build_state(g.GitRepo(child), {})
    lfs_entry = next(f for f in st_lfs["files"] if f["path"] == "asset.uasset")
    check("#4b staged LFS pointer uses index size",
          lfs_entry["size"] == len(pointer) and lfs_entry["staged_size"] == len(pointer),
          str(lfs_entry))
    check("#4b expanded LFS working file is not commit bloat",
          not lfs_entry["large"] and lfs_entry["working_size"] == 6_000_000,
          str(lfs_entry))

    # Ordinary staged binaries still warn because their index blobs are large.
    direct_path = os.path.join(child, "direct-large.bin")
    open(direct_path, "wb").write(b"y" * 6_000_000)
    _git(child, "add", "direct-large.bin")
    st_direct = g.build_state(g.GitRepo(child), {})
    direct_entry = next(f for f in st_direct["files"] if f["path"] == "direct-large.bin")
    check("#4b ordinary staged large file still warns",
          direct_entry["large"] and direct_entry["size"] == 6_000_000,
          str(direct_entry))

    # #6 push weight
    pw = st_child["push_weight"]
    check("#6 pack size present", bool(pw.get("pack_human")))
    check("#6 largest_blobs listed", isinstance(pw.get("largest_blobs"), list))

# #5 remote identity (uses live ~/.ssh/config; assert structure, not machine-specific values)
https = g.resolve_remote_identity("https://github.com/o/r.git")
check("#5 https flagged", https["scheme"] == "https" and https["warning"])
ssh = g.resolve_remote_identity("git@github.com:o/r.git")
check("#5 ssh parsed", ssh["scheme"] == "ssh" and ssh["host"] == "github.com")
bare = g.resolve_remote_identity("git@nonexistent-host-xyz.example:o/r.git")
check("#5 unknown host no crash", bare["host"] == "nonexistent-host-xyz.example")

print()
if fails:
    print(f"FAILED: {len(fails)} -> {fails}")
    sys.exit(1)
print("ALL v1.1 SITUATIONAL TESTS PASSED")
sys.exit(0)
