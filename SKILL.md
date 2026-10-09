---
name: git-real-closeout
description: End-of-session Git closeout using fresh GIT_REAL v1.3.1 operation evidence. Use when the user says "do a GIT_REAL CLOSEOUT", "GIT_REAL CLOSEOUT", or asks to end with repository work preserved, committed, and delivered where authorized.
---

# GIT_REAL CLOSEOUT

Use this workflow to preserve work and leave an evidence-backed handoff. A
closeout is not permission to delete, rewrite history, force push, or publish.
Apply it to a live closeout request, not a quoted example or a request to review
this file. Follow the user's existing authorized scope and applicable tool
permissions; this skill supplies operation evidence, not new authority.

## 1. Read fresh state

From the actual repository root containing the intended installed runtime
(otherwise use the supplied path to that runtime):

```bash
python gitreal.py . --quick --json
```

Do not use a result to approve a Git action when any of these is true:

- the command failed or the response is not a JSON object
- `version != "1.3.1"`
- `schema_version` is not the integer `2`
- `is_repo != true`
- `read_complete != true`
- `read_errors` is missing, not a list, or non-empty
- `root` is not the intended repository
- `publication_id` is not a nonempty string

Resolve routine errors or conflicts when their intended outcome is already
authorized and clear. Preserve unrelated work and continue independent work.
Ask only when an unresolved choice would change scope, ownership or the intended
result. An active operation is not permission to abort or rewrite it: reconcile
its state and obtain fresh evidence for the next supported action. The engine
can assess a verified, fully resolved normal merge for `commit_index`; an
unresolved merge or another unfinished operation is not automatically approved.

Do not rely on an older `.git-real/git-real.json`, a watcher, or a score.

## 2. Reconcile the intended work

Review staged, modified, untracked, ignored, stash, worktree, side-branch, and
publication evidence. Stage deliberately. Do not use `git add -A` merely to
make the tree look clean.

Preserve unrelated or uncertain-ownership work. Existing authorization can cover
edits to pre-existing files and routine conflict resolution; do not require a
new permission merely because you did not create a file. Keep the requested
change separate from unrelated work, and clarify only consequential ambiguity.

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

Require an object for `requested_action`, an actual boolean `safe`, and evidence
bound to the intended root, HEAD, index fingerprint and publication identity.
The user's authorization and this preservation verdict are separate requirements.

Review the exact staged paths and commit with an honest message. The returned
decision does not cover `git commit -a`, amend, path arguments, or a later
changed index.

## 4. Deliver only when authorized

If delivery includes a push, push the authorized branch through ordinary Git
transport and verify current remote state separately. GIT_REAL reports local
tracking refs; it does not prove that the server is current.

If no remote exists or push was not authorized, state that plainly. Do not create
a remote or expand delivery merely to satisfy a closeout label.

## 5. Destructive actions are separate

Never use `git reset --hard`, `git clean`, restore/checkout discard, stash
deletion, branch deletion, or history rewrite as a generic cleanup step.

When the owner authorizes one exact destructive operation, refresh with that
operation and target and require its own `ALLOW`. Unsupported flags or missing
target evidence are a block.

## 6. Final proof

After repository changes, read the resulting state. If no relevant state changed,
reuse a still-current read instead of repeating it solely for this checklist:

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

Name the material blocker in that final line and report any other unresolved
items in the handoff. Unrelated preserved work does not make an otherwise
completed scoped closeout fail. These are handoff labels written by the agent,
not engine receipts, release criteria or proof that a remote server is current.
