#!/usr/bin/env python3
"""
GIT_REAL MCP server  --  let AI agents CALL git situational awareness as tools.

"Checking GIT_REAL before I touch this tree."

This exposes GIT_REAL's safety checks as Model Context Protocol tools so Claude
Code / Codex / any MCP client can ask, mid-task:
  - is_safe_to_commit   -> should I commit right now?
  - is_safe_to_discard  -> preservation evidence for one explicit operation
  - git_real_status     -> full state for a repo
  - git_real_fleet      -> safety summary across every repo under a folder
  - gitignore_add       -> append a pattern to a repo's .gitignore

It imports the canonical single-file tool (gitreal.py) sitting next to it.
State is read fresh per call; source changes require a reconnect and fail closed.

Install + run:
    pip install mcp
    python gitreal_mcp.py            # stdio transport

Register with Claude Code (~/.claude/mcp config) or Codex -- see README.
"""
from __future__ import annotations

import os
import sys
import hashlib
import inspect

# import the canonical GIT_REAL tool that lives next to this file
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gitreal  # noqa: E402

_CFG = {"quick": True}
with open(__file__, "rb") as _source_file:
    _ADAPTER_SOURCE_SHA256 = hashlib.sha256(_source_file.read()).hexdigest()
_UNPUSHED_PREVIEW = 10   # cap unpushed commit subjects in the MCP summary to avoid flooding


def _abs(path: str) -> str:
    return os.path.abspath(os.path.expanduser(path or "."))


def _adapter_current() -> bool:
    try:
        with open(__file__, "rb") as source:
            current = hashlib.sha256(source.read()).hexdigest()
    except OSError:
        current = None
    return current == _ADAPTER_SOURCE_SHA256


def _state(path: str, config: dict | None = None) -> dict:
    state = gitreal.build_state(gitreal.GitRepo(_abs(path)), {**_CFG, **(config or {})})
    if not _adapter_current():
        state["read_complete"] = False
        state["read_errors"].append("MCP adapter changed after startup; reconnect this server.")
        state["scores"] = gitreal.compute_scores(state)
        state["actions"] = {name: gitreal.assess_action(state, name)
                            for name in state.get("actions", {})}
        if config and config.get("operation") in gitreal.REF_ACTIONS:
            gitreal.requested_action(state, config["operation"], config.get("target"), config.get("expected_binding"))
        state["closeout"] = gitreal.closeout_state(state)
    return state


# ---------------------------------------------------------------------------
# plain logic (independently testable, no MCP required)
# ---------------------------------------------------------------------------
def get_status(path: str = ".", operation: str | None = None, target: str | None = None,
               request_id: str | None = None, expected_binding: str | None = None) -> dict:
    assessment_requested = operation is not None or target is not None or expected_binding is not None
    if assessment_requested and operation not in gitreal.REF_ACTIONS:
        # Invalid optional assessment inputs must not fall through to ordinary
        # status, which can invoke a configured clean/process filter.
        s = {"schema_version": gitreal.SCHEMA_VERSION, "root": _abs(path),
             "read_complete": False, "read_errors": [
                 "Status operation checks support only exact branch/integration/origin-push operations; no Git inspection ran."],
             "request_id": request_id, "publication_id": None, "status": {}}
        gitreal.requested_action(s, operation, target, expected_binding)
        return {**s, "is_repo": None, "path": s["root"], "generated_at": None}
    s = _state(path, {"operation": operation, "target": target, "request_id": request_id,
                      "expected_binding": expected_binding})
    if assessment_requested and "requested_action" not in s:
        gitreal.requested_action(s, operation, target, expected_binding)
    sc, st = s.get("scores", {}), s.get("status", {})
    # Only a confirmed non-repository gets this short answer. A read stopped at
    # admission (e.g. stale source) has unknown is_repo and keeps the full
    # incomplete projection, so it cannot be mistaken for "not a repository".
    if s.get("is_repo") is False:
        return {"is_repo": False, "path": _abs(path), "read_complete": False,
                "schema_version": s.get("schema_version"), "read_errors": s.get("read_errors"),
                **({"requested_action": s["requested_action"], "actions": s["actions"],
                    "request_id": s.get("request_id"), "publication_id": s.get("publication_id")}
                   if "requested_action" in s else {}),
                "message": "Not a git repository."}
    unpushed = [{"hash": c.get("hash"), "subject": c.get("subject")}
                for c in s.get("unpushed", [])[:_UNPUSHED_PREVIEW]]
    preview_total = s["branch_ahead_commit_count"] if s["read_complete"] else None
    return {
        "schema_version": s["schema_version"], "version": s["version"],
        "engine_source_sha256": s["engine_source_sha256"],
        "generated_at": s["generated_at"], "publication_id": s["publication_id"],
        "request_id": s.get("request_id"),
        **({"requested_action": s["requested_action"]} if "requested_action" in s else {}),
        "read_complete": s["read_complete"], "read_errors": s["read_errors"],
        "root": s["root"], "status": st, "scores": sc, "actions": s["actions"],
        "object_storage": s["object_storage"],
        "elapsed_ms": s["elapsed_ms"], "closeout": s["closeout"],
        "main_equals_origin_main": s["main_equals_origin_main"],
        "main_oid": s["main_oid"], "origin_main_oid": s["origin_main_oid"],
        "remote_verification": s["remote_verification"],
        "unpushed_count_scope": s["unpushed_count_scope"],
        "branch_ahead_commit_count": s["branch_ahead_commit_count"],
        "secret_scan_state": s["secret_scan_state"],
        "conflict_count": len(st["conflicts"]) if s["read_complete"] else None,
        "stash_count": len(s["stashes"]) if s["read_complete"] else None,
        "worktrees": s["worktrees"],
        "extra_worktree_count": s["extra_worktree_count"] if s["read_complete"] else None,
        "stale_worktree_count": s["stale_worktree_count"] if s["read_complete"] else None,
        "ignored_count": s["ignored_count"] if s["read_complete"] else None,
        "index_inventory": s["index_inventory"],
        "hidden_path_count": len(s["index_inventory"]["hidden_paths"]) if s["read_complete"] else None,
        "active_operations": s["active_operations"], "index_locked": s["index_locked"],
        "is_repo": s.get("is_repo"), "path": s["root"], "name": s["root_name"],
        "branch": "(detached)" if st.get("detached") else st.get("branch"),
        "upstream": st.get("upstream"), "ahead": st.get("ahead"), "behind": st.get("behind"),
        "safe_commit_pct": sc.get("safe_commit"), "safe_commit_verdict": sc.get("safe_commit_label"),
        "safe_discard_pct": sc.get("safe_delete"), "safe_discard_verdict": sc.get("safe_delete_label"),
        "dirty_file_count": len(s.get("files", [])) if s["read_complete"] else None,
        "side_branch_count": len(s.get("side_branches", [])) if s["read_complete"] else None,
        "unpushed_commit_count": s["unpushed_commit_count"] if s["read_complete"] else None,
        "files": [{"path": f["path"], "category": f["category"]} for f in s.get("files", [])],
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
        "unpushed": unpushed,
        # Subject coverage is current-upstream only, unlike the all-local-ref count.
        "unpushed_preview": {
            "scope": "CURRENT_BRANCH_LOCAL_UPSTREAM", "upstream": st.get("upstream"),
            "limit": _UNPUSHED_PREVIEW, "returned_count": len(unpushed),
            "total_count": preview_total,
            "complete": preview_total is not None and len(unpushed) == preview_total,
            "truncated": len(unpushed) < preview_total if preview_total is not None else None,
        },
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
    action = gitreal.assess_action(s, "commit_index")
    return {
        **action, "schema_version": s["schema_version"], "generated_at": s["generated_at"],
        "read_complete": s["read_complete"], "read_errors": s["read_errors"],
        "path": s.get("root", _abs(path)),
        "safe_commit_pct": pct,
        "verdict": "SAFE FOR INSPECTED INDEX" if action["safe"] else "COMMIT NOT APPROVED",
        # Only the engine's exact operation decision authorizes this verdict.
        "recommendation": "OK" if action["safe"] else "BLOCK",
    }


def check_discard(path: str = ".", operation: str | None = None, target: str | None = None) -> dict:
    discard_operations = ("discard_tracked", "clean_untracked", "clean_ignored", "reset_hard", "drop_stash")
    needs_target = operation in ("reset_hard", "drop_stash")
    valid_target = (isinstance(target, str) and bool(target.strip())) if needs_target else target is None
    if operation not in discard_operations or not valid_target:
        # Malformed or wrong-tool requests must not cause repository inspection.
        s = {"schema_version": gitreal.SCHEMA_VERSION, "root": _abs(path),
             "generated_at": None, "publication_id": None, "read_complete": False,
             "read_errors": ["A supported discard operation with its applicable target is required; no Git inspection ran."]}
    else:
        s = _state(path)
    sc = s.get("scores", {})
    action = gitreal.assess_action(s, operation, target)
    return {
        **action, "schema_version": s["schema_version"], "generated_at": s["generated_at"],
        "read_complete": s["read_complete"], "read_errors": s["read_errors"],
        "path": s.get("root", _abs(path)),
        "safe_discard_pct": 100 if action["safe"] else 0,
        "summary_safe_discard_pct": sc.get("safe_delete"),
        "verdict": "SAFE FOR EXACT OPERATION" if action["safe"] else "DISCARD NOT APPROVED",
        "stashes": s.get("stash_summary", {}),      # (#2) unmerged work survives a discard
        "topology": s.get("topology", {}).get("kind"),
        # Summary scores do not approve another operation or later state.
        "recommendation": "OK_TO_DISCARD" if action["safe"] else "DO_NOT_DISCARD",
    }




def get_fleet(root: str = ".") -> dict:
    r = _abs(root)
    def incomplete(message: str) -> dict:
        return {"root": r, "schema_version": gitreal.SCHEMA_VERSION,
                "read_complete": False, "read_errors": [message], "totals": {}, "repos": []}

    if not os.path.isdir(r) or not _adapter_current():
        return incomplete("Invalid fleet root or outdated MCP process; refresh/reconnect.")
    projection = os.path.join(r, "governance", "generated", "REPOSITORY_FLEET.json")
    registry_paths = []
    info = {}
    if os.path.lexists(projection):
        if not os.path.isfile(projection):
            return incomplete("Fleet registry is not a regular readable file; no discovery fallback ran.")
        try:
            registry_paths = gitreal.load_registry_repo_paths(projection)
            info = gitreal.registry_fleet_paths(r, registry_paths)
            paths = list(info.get("present") or [])
        except (OSError, ValueError):
            return incomplete("Fleet registry is unreadable or invalid; no discovery fallback ran.")
    else:
        try:
            paths = gitreal.discover_repos(r)
        except (OSError, ValueError):
            return incomplete("Fleet discovery could not be completed; no complete inventory is claimed.")
    fs = gitreal.build_fleet_state(r, paths, _CFG, registry_paths=registry_paths or None)
    if not _adapter_current():
        return incomplete("MCP adapter changed during fleet inspection; reconnect and inspect again.")
    return {
        "root": r,
        "schema_version": gitreal.SCHEMA_VERSION,
        "generated_at": fs.get("generated_at"),
        "read_complete": bool(fs.get("read_complete")) and not info.get("drift_missing"),
        "read_errors": fs.get("read_errors", []) + (["Registered repositories are missing"] if info.get("drift_missing") else []),
        "drift_missing": info.get("drift_missing", []),
        "drift_unregistered": info.get("drift_unregistered", []),
        "inventory_scope": fs.get("inventory_scope"),
        "totals": fs.get("totals", {}),
        "repos": [{
            "name": x.get("name"), "path": x.get("path"),
            "branch": x.get("branch"), "schema_version": x.get("schema_version"),
            "read_complete": x.get("read_complete"), "error": x.get("error"),
            "actions": x.get("actions", {}), "closeout": x.get("closeout", {}),
            "object_storage": x.get("object_storage", {}),
            "main_equals_origin_main": x.get("main_equals_origin_main"),
            "extra_worktree_count": x.get("extra_worktree_count"),
            "safe_commit_pct": x.get("safe_commit"), "safe_discard_pct": x.get("safe_delete"),
            "dirty_file_count": x.get("dirty_files"),
            "side_branch_count": x.get("side_branches"), "unpushed_commit_count": x.get("unpushed"),
            "stash_count": x.get("stashes"), "stash_summary": x.get("stash_summary", {}),
            "topology": x.get("topology"), "embedded": x.get("embedded", False),
            "external": x.get("external", False), "remote_owner": x.get("remote_owner"),
            "ahead": x.get("ahead"), "behind": x.get("behind"),
            "hooks": x.get("hooks"), "worktrees": x.get("worktrees"),
            "governed_by_registry": x.get("governed_by_registry", False),
            "push_weight": x.get("push_weight", {}),
        } for x in fs.get("repos", [])],
    }


def do_gitignore_add(path: str = ".", pattern: str = "") -> dict:
    if not isinstance(pattern, str) or not pattern.strip() or any(c in pattern for c in ("\n", "\r", "\0")):
        return {"ok": False, "path": _abs(path), "error": "One nonempty ignore pattern is required; no Git inspection ran."}
    state = _state(path)
    if state.get("read_complete") is not True or state.get("topology", {}).get("kind") != "own_repo":
        return {"ok": False, "path": _abs(path), "error": "A fresh, readable repository root is required."}
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

    # Older supported SDKs have no annotation type/keyword. Keep registration
    # available there, while giving capable clients explicit mutation metadata.
    try:
        from mcp.types import ToolAnnotations
    except ImportError:
        ToolAnnotations = None

    def _tool(*, read_only: bool = True):
        if ToolAnnotations is not None and "annotations" in inspect.signature(mcp.tool).parameters:
            return mcp.tool(annotations=ToolAnnotations(
                readOnlyHint=read_only, destructiveHint=False,
                idempotentHint=True, openWorldHint=False))
        return mcp.tool()

    @_tool()
    def git_real_status(path: str = ".", operation: str | None = None, target: str | None = None,
                        request_id: str | None = None, expected_binding: str | None = None) -> dict:
        """Fresh schema-2 metadata for the actual repository root: complete/error state,
        exact operation decisions, conflicts, ignored and hidden-index counts, stashes,
        branches, worktrees, local-ref closeout and object-storage backlog evidence.
        Optional operation: create_branch, switch_branch, fast_forward, delete_branch or
        push_origin. Requires an exact refs/heads/<name> target and fresh request_id;
        expected_binding revalidates a previous input_binding without executing Git.
        Require matching requested_action/actions entry ALLOW and safe=true. Git-safety
        evidence never grants ownership or publication authority.
        Unpushed counts cover all local refs; unpushed_preview reports the scope, exact
        total and truncation of the bounded current-upstream subjects, not publication
        proof. Remote state uses LOCAL_TRACKING_REFS_ONLY, not live network verification. Deep stash and
        push-weight telemetry are deferred for speed. Scores never authorize deletion.
        Reconnect after source upgrades; a stale loaded process fails closed."""
        return get_status(path, operation, target, request_id, expected_binding)

    @_tool()
    def is_safe_to_commit(path: str = ".") -> dict:
        """Check a plain commit of the inspected index. Require safe=true and decision=ALLOW.
        Does not approve commit -a, path arguments, amend, or a future modified index.
        No staged candidate is BLOCK, not approval to stage arbitrary working files."""
        return check_commit(path)

    @_tool()
    def is_safe_to_discard(path: str = ".", operation: str | None = None, target: str | None = None) -> dict:
        """Read-only safety check for one EXACT operation: discard_tracked, clean_untracked,
        clean_ignored, reset_hard (requires target commit), or drop_stash (requires stash ref).
        Missing/unsupported operations are BLOCK, even with a clean tree. Require safe=true
        and decision=ALLOW. Scores never authorize deletion. Evidence is bound to the
        inspected root, HEAD, index and resolved target, not future concurrent changes."""
        return check_discard(path, operation, target)


    @_tool()
    def git_real_fleet(root: str = ".") -> dict:
        """Read selected repositories from the fleet registry, or bounded folder discovery.
        Returns per-repository schema-2 actions, closeout evidence and inventory errors.
        Missing/empty/unreadable scope is not a complete fleet; remote-owner hints never
        exclude selected repositories from totals. This is not blanket action permission."""
        return get_fleet(root)

    @_tool(read_only=False)
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
