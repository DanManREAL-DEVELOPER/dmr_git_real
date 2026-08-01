#!/usr/bin/env python3
"""
GIT_REAL MCP server  --  let AI agents CALL git situational awareness as tools.

"Checking GIT_REAL before I touch this tree."

This exposes GIT_REAL's safety checks as Model Context Protocol tools so Claude
Code / Codex / any MCP client can ask, mid-task:
  - is_safe_to_commit   -> should I commit right now?
  - is_safe_to_discard  -> is it safe to nuke this dirty tree?
  - list_secrets        -> are there secrets I must not commit?
  - git_real_status     -> full state for a repo
  - git_real_fleet      -> safety summary across every repo under a folder
  - gitignore_add       -> append a pattern to a repo's .gitignore

It imports the canonical single-file tool (gitreal.py) sitting next to it, so it
always reflects your current detection rules and scoring -- no logic is duplicated.

Install + run:
    pip install mcp
    python gitreal_mcp.py            # stdio transport

Register with Claude Code (~/.claude/mcp config) or Codex -- see README.
"""
from __future__ import annotations

import os
import sys

# import the canonical GIT_REAL tool that lives next to this file
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gitreal  # noqa: E402

_CFG = {"muted_secret_files": []}
_UNPUSHED_PREVIEW = 10   # cap unpushed commit subjects in the MCP summary to avoid flooding


def _abs(path: str) -> str:
    return os.path.abspath(os.path.expanduser(path or "."))


def _state(path: str) -> dict:
    return gitreal.build_state(gitreal.GitRepo(_abs(path)), _CFG)


# ---------------------------------------------------------------------------
# plain logic (independently testable, no MCP required)
# ---------------------------------------------------------------------------
def get_status(path: str = ".") -> dict:
    s = _state(path)
    sc, st = s.get("scores", {}), s.get("status", {})
    if not s.get("is_repo"):
        return {"is_repo": False, "path": _abs(path),
                "message": "Not a git repository."}
    return {
        "is_repo": True, "path": s["root"], "name": s["root_name"],
        "branch": "(detached)" if st.get("detached") else st.get("branch"),
        "upstream": st.get("upstream"), "ahead": st.get("ahead"), "behind": st.get("behind"),
        "safe_commit_pct": sc.get("safe_commit"), "safe_commit_verdict": sc.get("safe_commit_label"),
        "safe_discard_pct": sc.get("safe_delete"), "safe_discard_verdict": sc.get("safe_delete_label"),
        "dirty_file_count": len(s.get("files", [])),
        "secret_count": len(s.get("secrets", [])),
        "side_branch_count": len(s.get("side_branches", [])),
        "unpushed_commit_count": len(s.get("unpushed", [])),
        "files": [{"path": f["path"], "category": f["category"],
                   "has_secret": bool(f.get("has_secret") or f.get("secret_filename"))}
                  for f in s.get("files", [])],
        # WHAT each thing is, not just how many, so an agent can answer "what was that
        # side branch / unpushed commit?" without a git-log expedition.
        "last_commit": ({"hash": s["last_commit"].get("hash"),
                         "subject": s["last_commit"].get("subject"),
                         "when": s["last_commit"].get("when")}
                        if s.get("last_commit") else None),
        "side_branches": [{"name": b.get("name"), "subject": b.get("subject"),
                           "last_commit": b.get("last_commit_rel"),
                           "merged_into_default": b.get("merged_into_default"),
                           "pushed": b.get("pushed")}
                          for b in s.get("side_branches", [])],
        "unpushed": [{"hash": c.get("hash"), "subject": c.get("subject")}
                     for c in s.get("unpushed", [])[:_UNPUSHED_PREVIEW]],
        # --- v1.1 situational awareness ---
        # (#3) is this its own repo, or tracked inside a parent (half-extracted)?
        "topology": s.get("topology", {}),
        # (#2) stashes with triage: dead/superseded vs unmerged work to preserve
        "stashes": {
            "count": s.get("stash_summary", {}).get("count", 0),
            "summary": s.get("stash_summary", {}),
            "detail": s.get("stashes_detail", []),
        },
        # (#5) which account/key each remote push authenticates as
        "remotes": s.get("remotes_detail", []),
        # (#6) pack size + largest tracked blobs -> know a heavy/slow push first
        "push_weight": s.get("push_weight", {}),
    }


def check_commit(path: str = ".") -> dict:
    s = _state(path)
    sc = s.get("scores", {})
    pct = sc.get("safe_commit")
    return {
        "path": s.get("root", _abs(path)),
        "safe_commit_pct": pct,
        "verdict": sc.get("safe_commit_label"),
        "secrets_present": bool(s.get("secrets")),
        "reasons": sc.get("safe_commit_reasons", []),
        # Mirrors the engine's 80/40 bands (safe_commit_label) so this surface can
        # never say a plain OK below the governance GO bar (§6: commit needs >= 80).
        "recommendation": (
            "BLOCK" if (pct is None or pct < 40 or s.get("secrets"))
            else "OK" if pct >= 80
            else "CAUTION"
        ),
    }


def check_discard(path: str = ".") -> dict:
    s = _state(path)
    sc = s.get("scores", {})
    pct = sc.get("safe_delete")
    return {
        "path": s.get("root", _abs(path)),
        "safe_discard_pct": pct,
        "verdict": sc.get("safe_delete_label"),
        "reasons": sc.get("safe_delete_reasons", []),
        "stashes": s.get("stash_summary", {}),      # (#2) unmerged work survives a discard
        "topology": s.get("topology", {}).get("kind"),
        # Same banding as safe_delete_label: discard is destructive, so the 40-79
        # zone must read as review-first, never as a green light.
        "recommendation": (
            "DO_NOT_DISCARD" if (pct is None or pct < 40)
            else "OK_TO_DISCARD" if pct >= 80
            else "REVIEW_FIRST"
        ),
    }


def get_secrets(path: str = ".") -> dict:
    s = _state(path)
    secs = s.get("secrets", [])
    return {
        "path": s.get("root", _abs(path)),
        "secret_count": len(secs),
        "secrets": secs,  # values are already masked by GIT_REAL
        "stop": bool(secs),
    }


def check_history(path: str = ".") -> dict:
    cfg = dict(_CFG)
    cfg["check_history"] = True
    s = gitreal.build_state(gitreal.GitRepo(_abs(path)), cfg)
    incidents = s.get("history_incidents", [])
    return {
        "path": s.get("root", _abs(path)),
        "secrets_in_history": len(incidents),
        "incidents": incidents,  # masked, with commit hash
        "stop": bool(incidents),
        "recommendation": "ROTATE_AND_SCRUB" if incidents else "OK",
    }


def get_fleet(root: str = ".") -> dict:
    r = _abs(root)
    paths = gitreal.discover_repos(r)
    fs = gitreal.build_fleet_state(r, paths, _CFG)
    return {
        "root": r,
        "totals": fs.get("totals", {}),
        "repos": [{
            "name": x.get("name"), "path": x.get("path"),
            "safe_commit_pct": x.get("safe_commit"), "safe_discard_pct": x.get("safe_delete"),
            "dirty_file_count": x.get("dirty_files"), "secret_count": x.get("secret_count"),
            "side_branch_count": x.get("side_branches"), "unpushed_commit_count": x.get("unpushed"),
            "stash_count": x.get("stashes"), "stash_summary": x.get("stash_summary", {}),
            "topology": x.get("topology"), "embedded": x.get("embedded", False),
            "external": x.get("external", False), "remote_owner": x.get("remote_owner"),
            "push_weight": x.get("push_weight", {}),
        } for x in fs.get("repos", [])],
    }


def do_gitignore_add(path: str = ".", pattern: str = "") -> dict:
    ok = gitreal.add_to_gitignore(_abs(path), pattern)
    return {"ok": ok, "path": _abs(path), "pattern": pattern}


# ---------------------------------------------------------------------------
# MCP wiring (optional import; logic above works without it)
# ---------------------------------------------------------------------------
try:
    from mcp.server.fastmcp import FastMCP
    _HAVE_MCP = True
except Exception:  # noqa: BLE001
    _HAVE_MCP = False

if _HAVE_MCP:
    mcp = FastMCP("git-real")

    @mcp.tool()
    def git_real_status(path: str = ".") -> dict:
        """Full GIT_REAL situational awareness for a repo: safe-commit and safe-discard
        scores, branch/push state, dirty file list, secret and side-branch counts. Also
        names each side branch with its last commit subject and lists your unpushed commits,
        so you can tell WHAT a forgotten branch or commit was without running git log.
        v1.1 adds: 'stashes' (per-stash triage - empty/superseded/unmerged, so you can tell
        dead stashes from unmerged work to preserve before clearing); 'topology' (is this its
        OWN repo, or tracked inside a parent = a half-extracted standalone where git commands
        act on the parent); 'remotes' (which SSH key/account each push authenticates as, flagging
        bare/ambiguous hosts); and 'push_weight' (pack size + largest tracked blobs, so a heavy
        or slow push is known BEFORE you attempt it)."""
        return get_status(path)

    @mcp.tool()
    def is_safe_to_commit(path: str = ".") -> dict:
        """Check BEFORE committing. Returns a 0-100 safe-commit score, a verdict, the
        reasons, and whether secrets are present. recommendation=BLOCK means do not commit."""
        return check_commit(path)

    @mcp.tool()
    def is_safe_to_discard(path: str = ".") -> dict:
        """Check BEFORE discarding/cleaning a working tree (git checkout . / clean / reset).
        A low safe-discard score means there is unsaved work: recommendation=DO_NOT_DISCARD."""
        return check_discard(path)

    @mcp.tool()
    def list_secrets(path: str = ".") -> dict:
        """List detected secrets (masked) in a repo's working tree. stop=true means STOP:
        do not commit until resolved."""
        return get_secrets(path)

    @mcp.tool()
    def secrets_in_history(path: str = ".") -> dict:
        """Scan git history for ALREADY-COMMITTED secrets (incidents), separate from
        working-tree secrets. Non-empty incidents means a secret is already in your history:
        recommendation=ROTATE_AND_SCRUB (rotate the key and scrub history). Walks the FULL
        commit graph, so it also catches a secret that was committed and later deleted.
        Slower than the other checks because it diffs every commit on every ref."""
        return check_history(path)

    @mcp.tool()
    def git_real_fleet(root: str = ".") -> dict:
        """Scan every git repo under a folder and return a per-repo safety summary plus
        totals. v1.1 recurses into NESTED repos: when `root` is itself a repo full of
        standalones (a monorepo/workspace root like _MAIN), it now reports the root AND
        every nested repo, instead of just the root. Per-repo fields include stash counts
        with triage, an 'embedded' flag (half-extracted standalone tracked inside a parent),
        and push_weight. Totals include total_stashes, repos_with_unmerged_stashes,
        embedded_repos, and heavy_repos. Use to triage many worktrees at once."""
        return get_fleet(root)

    @mcp.tool()
    def gitignore_add(path: str = ".", pattern: str = "") -> dict:
        """Append a pattern to a repo's .gitignore (e.g. 'dist/' or '.env')."""
        return do_gitignore_add(path, pattern)


def main():
    if not _HAVE_MCP:
        sys.stderr.write(
            "GIT_REAL MCP server needs the MCP SDK.\n"
            "  pip install mcp\n"
            "Then register this file as an MCP server (stdio). See README.\n")
        sys.exit(1)
    mcp.run()


if __name__ == "__main__":
    main()
