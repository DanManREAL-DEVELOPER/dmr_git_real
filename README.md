<p align="center">
  <img
    src="./assets/brand/git-real-readme-loop-960x540.gif"
    alt="GIT_REAL: get real about your repo. Stop fighting agents over dirty trees!"
    width="960"
  >
</p>

<h1 align="center">GIT_REAL</h1>

<p align="center">
  <strong>Get real about your repo.</strong> Stop fighting agents over dirty trees.
</p>

<p align="center">
  Drop-in git situational awareness, for humans <strong>and</strong> AI agents.<br>
  <sub>one file &middot; zero required dependencies &middot; <code>python gitreal.py</code> &middot; Linux / macOS / Windows / WSL2</sub>
</p>

---

## Get protected in three steps

**1. Clone this repository.**

```bash
git clone https://github.com/DanManREAL-DEVELOPER/dmr_git_real.git
cd dmr_git_real
```

**2. Install GIT_REAL into the repository you want protected.**

```bash
python setup_gitreal.py "/absolute/path/to/your/project" --with-hook
```

**3. Require the exact receipt.**

```text
GIT_REAL_SETUP_PASS
```

The installer copies the v1.2 engine, wires the operation-specific agent contract,
adds `.git-real/` to `.gitignore`, and can install a fail-closed pre-commit check.
For a deterministic agent runbook, use [`AGENT_SETUP.md`](./AGENT_SETUP.md).

## The problem

You run multiple AI coding agents (Claude Code, Codex, Cursor) across 8 to 12 worktrees. They leave dirty trees, untracked files, and stray side branches everywhere. Then an agent stops and asks:

> "There's a dirty working tree here, what do you want to do with it?"

...and you have no idea what it means, whether it is junk, or whether it is an hour of unsaved work you are about to nuke.

GIT_REAL answers that. Visually for you, and in machine-readable JSON for the agents themselves.

## The fix: your agents read the verdict, not you

GIT_REAL v1.2 uses **operation-specific preservation checks**. A clean working tree,
an ignored path, or a directory named `build/` is not blanket permission to delete
anything. The legacy scores remain summaries; the generic discard score never
returns `GO`. Agents must use the explicit action result instead.

Drop this into your repo's `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, or any agent's system instructions:

> Refresh for the **actual repository root** immediately before assessing an action.
> Require `schema_version == 2`, `read_complete == true`, and no `read_errors`.
> For a plain commit of the current index, require
> `actions.commit_index.safe == true` and `decision == "ALLOW"`.
> For deletion/reset/stash removal, select the exact supported operation and target;
> require that action's `safe == true` and `decision == "ALLOW"`.
> Missing evidence, unsupported flags, or an unspecified operation is not approval.
> A watcher, an earlier JSON file, or a score alone is not fresh evidence.

Fast read-only JSON, with no dashboard files written:

```bash
python gitreal.py /absolute/repository/root --quick --json
```

An explicit check, **not execution**, for a plain `git clean -fd`:

```bash
python gitreal.py /absolute/repository/root --quick --json --operation clean_untracked
```

Exit status is `0` for a complete read/allowed requested action, `1` for a denied
requested action, and nonzero for a failed read or publication. A status-only
exit `0` does not mean every action is allowed.

Or let GIT_REAL install it for you: `python gitreal.py --wire-agents` injects this block into your `CLAUDE.md` / `AGENTS.md` / `.cursorrules` as an idempotent managed block (re-running replaces it, never duplicates; it creates `AGENTS.md` if none of them exist).

The [MCP server](#agent-integration-mcp) exposes the same engine. It reads repository
state on each call. Reconnect after changing the engine or adapter source: a loaded
v1.2 process detects that change and fails closed rather than claiming current rules.

## Three ways to run it

**Single repo.** Drop `gitreal.py` in and run:
```bash
python gitreal.py
# dashboard: http://127.0.0.1:8787   writes .git-real/git-real.{html,json}
```

**FLEET, the multi-repo command center** (the one for your 8 to 12 worktrees):
```bash
python gitreal.py ~/projects --all
# scans every git repo under the folder and puts them on ONE wall
```

The FLEET wall shows every repo as a card with its safe-commit and safe-discard scores, dirty count, side-branch count, and push state, sorted most-dangerous-first. Click a card for the full breakdown.

**MCP, so your agents can call it** (see [Agent integration](#agent-integration-mcp) below).

## What it tracks

- **Dirty, staged, untracked, and conflicted paths**, including lossless rename and unusual-filename handling. Untracked directories may be collapsed. Names are review hints, not proof of disposability.
- **Publication evidence**: branch, upstream, exact ahead/behind counts, all-local-ref unpublished commit counts (including tags/custom refs), and a bounded current-upstream preview. No remote-tracking history means unknown publication, not zero unpushed work. Remote-tracking refs are local observations, not live server verification.
- **Main and side branches**: flags side branches that are unmerged or unpushed so stranded agent work stops vanishing.
- **Ignored paths and empty untracked directories**: collapsed inventories protect paths that ordinary status does not show. Ignored data blocks ignored-file cleaning, not unrelated staged commits.
- **Hidden index flags, worktrees, stashes, and active Git operations**: unknown/read-failed inventories cannot masquerade as empty collections.
- **.gitignore suggestions**: possible artifacts are suggestions only. Ignoring a path is neither a backup nor deletion authorization.


## Exact operation contract

| Operation | Exact assessed scope | Preservation rule |
|---|---|---|
| `commit_index` | Plain `git commit` of the inspected index | Staged candidate, structural checks, named branch, no conflict or active operation. Not `-a`, amend, or path arguments. |
| `discard_tracked` | `git restore --worktree -- .`, from the index | No unstaged changes, conflicts, or status-hidden paths. Staged-only work remains in the index. |
| `clean_untracked` | `git clean -fd` | No untracked candidates, including empty directories. No second force flag. |
| `clean_ignored` | `git clean -fdx` | No untracked or ignored candidates. No second force flag. |
| `reset_hard` | Nonrecursive reset to an explicit commit | Target preserves current HEAD ancestry; no dirty/hidden tracked work; a different target cannot have unproven local-path collisions. Use the returned resolved OID, not a mutable branch name. |
| `drop_stash` | One selected `stash@{N}` | Canonical stash ancestry and exact saved index, worktree, and untracked deltas durably present in the retained current branch. Working-tree presence alone is insufficient. |

These checks do not perform the action or grant user authorization. Other checkout
targets, force-push, branch/worktree removal, recursive submodule operations,
`stash clear`, and additional flags are **not assessed**. Preserve work and follow
the owner's workflow instead of translating a different action's `ALLOW` into permission.

The commit score evaluates the actual index when staged changes exist; otherwise
it is only a working-tree preview. Filename-based local-data/key exclusions are
not a content secret scan. Neither score is a statistical probability or a backup.
The compatibility discard score is capped below `GO` so old score-only consumers
fail conservatively during migration.

All-local-ref coverage can include **retained archive tags or backup history**,
not just new commits awaiting delivery. Preserve and classify those refs; never
push archived history or delete its only reference merely to make a counter zero.

## Agent integration (MCP)

The [agent hook](#the-fix-your-agents-read-the-verdict-not-you) above works straight from the JSON file - no server needed. For agents that prefer to **call** the check live mid-task ("checking GIT_REAL before I touch this tree"), GIT_REAL also ships an MCP server for Claude Code, Codex, or any MCP client - the same verdict, exposed as tools.

Tools exposed: `is_safe_to_commit`, `is_safe_to_discard`, `git_real_status`, `git_real_fleet`, `gitignore_add`.

`git_real_status` returns schema/publication metadata, read completeness, actual
conflicts, exact local `main`/`origin/main` equality, worktrees, hidden-index count,
actions and a local closeout summary. Incomplete counts are `null`, not zero.
`is_safe_to_discard(path, operation, target)` requires the exact operation; omitting
it returns `DO_NOT_DISCARD`, even for a clean repository.

```bash
pip install mcp          # the MCP SDK (only needed for the MCP server, not the dashboard)
```

**Claude Code** (run from where `gitreal_mcp.py` lives, use the absolute path):
```bash
claude mcp add --transport stdio git-real -- python /abs/path/to/gitreal_mcp.py
```
or edit `~/.claude.json` (or a project `.mcp.json`):
```json
{ "mcpServers": { "git-real": { "type": "stdio", "command": "python", "args": ["/abs/path/to/gitreal_mcp.py"] } } }
```

**Codex** (`codex mcp add git-real -- python /abs/path/to/gitreal_mcp.py`), or edit `~/.codex/config.toml`:
```toml
[mcp_servers.git-real]
command = "python"
args = ["/abs/path/to/gitreal_mcp.py"]
```

Verify the connected client's tools and returned `version`/`schema_version` after
reconnecting. A process started before an upgrade must be replaced; modifying a
Python source file does not hot-reload an already running MCP server.

**No MCP?** Use the fresh CLI JSON or the request-bound file workflow above. An
agent instruction file can name that workflow, but an existing JSON file must
not be treated as current merely because a watcher is running.

## Guardrail mode (pre-commit / CI)

Use an explicit index check for a commit gate:

```bash
python gitreal.py . --quick --json --operation commit_index
```

A pre-commit hook may use that command's exit code. File-based consumers should
generate a unique token, pass `--quick --once --request-id TOKEN`, and require the
same `request_id`, a new `publication_id`, the exact canonical root, schema 2,
complete reads, and `actions.commit_index` ALLOW/true. JSON publication is atomic;
write failures are nonzero and never reported as a successful fresh snapshot.
Pushes use ordinary Git transport; GIT_REAL does not implement a pre-push gate.

Fleet telemetry across selected repositories (not authorization for every action):
```bash
python gitreal.py ~/projects --all --quick --once
```

## Project layout - single file, on purpose

`gitreal.py` is the whole tool: watcher, Git-state scoring, worktree analysis and dashboard HTML live in one file—
no `src/` maze. Drop it in and run. `gitreal_mcp.py` (the MCP server) and `tests/` sit
beside it; brand assets live in `assets/`.

*Contributors: please keep it flat.* The single-file design is the feature, not an
oversight - it's what makes GIT_REAL a true drop-in.

## Install

No build step, no package required for the dashboard (pure Python standard library). Optional `watchdog` gives instant file-event updates instead of polling:

```bash
pip install watchdog   # optional, GIT_REAL falls back to polling without it
```

### CLI

```
python gitreal.py [PATH] [options]

  PATH               folder to watch (default: current dir)
  --all / --fleet    FLEET mode: scan PATH for ALL repos (the multi-repo wall)
  --port N           dashboard port (default: 8787)
  --once             generate output once and exit (CI / pre-commit)
  --quick            metadata inventory; defer deep stash/push-weight telemetry
  --json             print fresh JSON without writing dashboard files
  --operation NAME   assess one supported operation; never execute it
  --target VALUE     explicit reset commit or selected stash ref
  --request-id TOKEN echo a caller's unique refresh token
  --fail-under N     guardrail: exit 1 if safe-commit < N
  --poll             force polling watcher (use on /mnt/c or network drives)
  --no-server        write files only, no dashboard server
  --interval S       rescan/poll interval seconds (default: 4)
  --init             git init if PATH is not a repo yet
  --wire-agents      install the agent hook into CLAUDE.md / AGENTS.md / .cursorrules
```

> **WSL2 note:** on Windows drives (`/mnt/c/...`) inotify is unreliable, so GIT_REAL auto-switches to polling. Native paths (`~/...`) use real file events.
>
> **Pin your worktrees:** drop a `.git-real/fleet.json` like `{"repos": ["~/proj/a", "~/proj/b"]}` to always include specific repos in FLEET mode.

## JSON shape (for agents and tooling)

```jsonc
{
  "schema_version": 2,
  "version": "1.2.0",
  "read_complete": true,
  "read_errors": [],
  "root": "/absolute/repository/root",
  "publication_id": "unique-per-inspection",
  "remote_verification": "LOCAL_TRACKING_REFS_ONLY",
  "actions": {
    "clean_untracked": {
      "safe": false,
      "decision": "BLOCK",
      "reasons": ["Untracked paths have no proven durable copy."]
    }
  },
  "files": [{ "path": "newfeature.py", "category": "new" }],
  "side_branches": [{ "name": "feature/x", "merged_into_default": false, "pushed": false }],
  "unpushed": [{ "hash": "a1b2c3d", "subject": "wip" }]
}
```

FLEET writes `.git-real/git-real-fleet.json` with `totals` plus a per-repo summary array.

## Known limitations

- **Snapshots are not atomic execution locks.** Repeated metadata observations detect some changes during inspection, but another process can write after a path/ref was observed. Refresh immediately before acting, coordinate writers, and never reuse a snapshot after a state change. No read-only scan can prevent a future writer.
- **Recovery evidence is deliberately conservative.** Untracked/ignored content is not approved for deletion merely because it resembles output. Some safely redundant work will still require an explicit preservation workflow. A stash with multiple saved variants may remain blocked even after one variant is committed.
- **Closeout is not live remote verification.** `LOCAL_STATE_COMPLETE` proves the inspected local state against local tracking refs only. Delivery workflows must separately establish current remote synchronization. Missing refs, malformed data, read failures and stale loaded code are not clean states.
- **No content secret scanner, backup service, or automatic enforcement.** The dashboard/MCP is advisory evidence unless a hook or agent follows it. A hook can also be bypassed. SSH identity fields are configuration hints, never proof of authenticated identity.

## Regression checks

The adversarial suite uses disposable repositories, including untracked artifacts,
ignored data, hidden index flags, unusual filenames, clean-but-ahead branches,
stash variants, read failures, stale publication, and explicit no-op scopes.

```bash
python -m pytest tests/test_adversarial_safety.py tests/test_wave43_grc.py -q
```

## The story

Why a solo dev built this: [`Background_Story.md`](./Background_Story.md).

## License

MIT, see `LICENSE`.

<sub>Not affiliated with the unrelated <code>watany-dev/gitreal</code>. The name was suggested by the author's daughter: "GIT_REAL", get real.</sub>
