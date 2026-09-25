# The GIT_REAL background story

## The problem was never just a dirty tree

AI coding agents made it easy to run several workstreams at once. They also
made it easy to lose the context that gives Git state meaning: which untracked
file is real work, which branch is unpublished, which stash still contains a
unique variant, and whether a “cleanup” command is actually destructive.

The recurring question was simple:

> There is a dirty working tree. What should I do with it?

Plain `git status` describes state. It does not decide whether a particular
operation preserves that state.

## The first answer was a dashboard

GIT_REAL began as one dependency-free Python file that turns repository
metadata into a local dashboard and machine-readable JSON. It inventories
working-tree changes, refs, upstream state, worktrees, stashes, ignored paths,
and side branches. FLEET mode puts several repositories on one wall so the
riskiest unfinished work is visible first.

That solved visibility, but visibility was not enough.

## Why v1.2 changed the contract

Early versions summarized repository risk with commit and discard scores. Those
scores were useful for orientation, but a generic score can be misused as
permission for a command it never assessed.

GIT_REAL v1.2 therefore moved to operation-specific preservation checks.

A plain commit of the current index is not the same operation as `git commit
-a`. `git clean -fd` is not the same as `git clean -fdx`. Resetting to an
explicit commit is not the same as checking out an arbitrary branch. Dropping
one stash is not the same as clearing every stash.

The v1.2 engine returns an `ALLOW` or `BLOCK` for the exact supported operation
and target. The result is bound to the repository root, HEAD, index
fingerprint, and a unique publication ID. Incomplete reads and unknown
publication evidence fail closed.

That is the product's real purpose: not to tell an agent that a repository
“looks fine,” but to force the agent to name the operation it intends to
perform and show preservation evidence for that operation.

## Local by design

The core has no telemetry and sends no repository data to a hosted service.
The dashboard binds locally, the MCP adapter uses stdio, and `--json` can
produce a fresh result without writing dashboard files.

GIT_REAL deliberately does not inspect repository file contents for secrets.
Secret scanning is a different security control and should be handled by a
dedicated scanner.

## Built with the workflow it protects

GIT_REAL was developed in the same environment it is meant to help: multiple
agents, multiple worktrees, unfinished branches, and frequent handoffs. Its
adversarial tests now cover cases such as ignored data, hidden index flags,
unusual filenames, clean-but-ahead branches, stash variants, incomplete reads,
stale publications, and explicit no-op scopes.

The lesson was direct: evidence must describe the exact action, and unknown
must remain unknown.

## Why it is called GIT_REAL

My daughter suggested the name—“GIT_REAL,” like “get real.” It fit the tool:
stop guessing, inspect the actual repository, and make the intended operation
explicit.

GIT_REAL is MIT licensed. Use it, test it against ugly repositories, and keep
the evidence honest.

— DanManREAL
