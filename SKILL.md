---
name: git-real-closeout
description: End-of-session Git closeout using fresh GIT_REAL v1.2 operation evidence. Use when the user says "do a GIT_REAL CLOSEOUT", "GIT_REAL CLOSEOUT", or asks to end with repository work preserved, committed, and delivered where authorized.
---

# GIT_REAL CLOSEOUT

Use this workflow to preserve work and leave an evidence-backed handoff. A
closeout is not permission to delete, rewrite history, force push, or publish.

## 1. Read fresh state

From the actual repository root:

```bash
python gitreal.py . --quick --json
```

Stop when any of these is true:

- `version != "1.2.0"`
- `schema_version != 2`
- `read_complete != true`
- `read_errors` is non-empty
- `root` is not the intended repository
- conflicts or an active Git operation require owner resolution

Do not rely on an older `.git-real/git-real.json`, a watcher, or a score.

## 2. Reconcile the intended work

Review staged, modified, untracked, ignored, stash, worktree, side-branch, and
publication evidence. Stage deliberately. Do not use `git add -A` merely to
make the tree look clean.

Anything you did not create is reported and preserved unless the owner
explicitly authorizes a specific action.

## 3. Prove the plain commit operation

Immediately before a normal commit of the current index:

```bash
python gitreal.py . --quick --json --operation commit_index
```

Commit only when the fresh result has:

```text
requested_action.operation == "commit_index"
requested_action.safe == true
requested_action.decision == "ALLOW"
```

Review the exact staged paths and commit with an honest message. The returned
decision does not cover `git commit -a`, amend, path arguments, or a later
changed index.

## 4. Deliver only when authorized

If delivery includes a push, push the authorized branch through ordinary Git
transport and verify current remote state separately. GIT_REAL reports local
tracking refs; it does not prove that the server is current.

If no remote exists or push was not authorized, state that plainly.

## 5. Destructive actions are separate

Never use `git reset --hard`, `git clean`, restore/checkout discard, stash
deletion, branch deletion, or history rewrite as a generic cleanup step.

When the owner authorizes one exact destructive operation, refresh with that
operation and target and require its own `ALLOW`. Unsupported flags or missing
target evidence are a block.

## 6. Final proof

Run a fresh status read:

```bash
python gitreal.py . --quick --json
```

Report:

```text
Version/schema:
Read complete:
Working tree:
Staged paths:
Conflicts:
Stashes:
Side branches:
Local publication evidence:
Remote verification:
Commit:
Push:
Remaining work:
```

End with:

```text
GIT_REAL_CLOSEOUT_PASS
```

only when the requested closeout outcome is actually complete. Otherwise end
with:

```text
GIT_REAL_CLOSEOUT_BLOCKED: <single blocking reason>
```
