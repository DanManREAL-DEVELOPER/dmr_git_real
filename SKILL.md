---
name: git-real-closeout
description: End-of-session Git closeout driven by GIT_REAL. Use when the user says "do a GIT_REAL CLOSEOUT", "GIT_REAL CLOSEOUT", or asks to end the session with the repository proven clean. Refreshes the verdict, commits and pushes only under GO bands, hard-stops on secrets, and finishes with an exact receipt.
---

# GIT_REAL CLOSEOUT

When the user says **"do a GIT_REAL CLOSEOUT"**, end the session so that no work is lost,
no secret leaves the machine, and the repository provably reads clean. Follow the steps in
order. Never skip a gate to finish faster.

## Step 1 — Refresh the verdict

Run from the repository root:

```bash
python gitreal.py . --once --no-server
```

Then read:

```text
.git-real/git-real.json
```

## Step 2 — Hard stops (check these before touching anything)

Stop the closeout and report to the user — do not commit, push, or discard — if any of
these is true:

- `secrets` is non-empty. Report file paths only, never secret values.
- `scan.truncated` is `true`. An incomplete scan is not a clean scan.
- `status.conflicts` is non-empty. Conflicts need the user's resolution.

## Step 3 — Commit the real work

Only when `scores.safe_commit_band` is `GO`:

1. Stage deliberately. Review what is staged; do not blind-add everything.
2. Commit with an honest message describing what actually changed.
3. Junk or generated files do not get committed — extend `.gitignore` instead.

Discarding anything requires `scores.safe_delete_band` to be `GO` **and** the user's
explicit approval for that specific discard.

## Step 4 — Push

If the repository has a remote, push the current branch, then confirm in a fresh verdict
that `ahead` is `0`. If there is no remote, state that plainly instead of claiming a push.

## Step 5 — Leftovers

A closeout leaves no loose ends:

- No stashes you created this session.
- No side branches you created this session that the user did not ask to keep.
- Anything you did not create — old stashes, foreign branches — is reported, never deleted.

## Step 6 — Prove it and print the receipt

Re-run:

```bash
python gitreal.py . --once --no-server
```

Report exactly these facts from the fresh JSON:

```text
Safe commit band: value from scores.safe_commit_band
Secret count: length of secrets
Scan truncated: value from scan.truncated
Working tree: clean or the exact remaining paths
Pushed: yes + branch, or "no remote"
```

End with this exact line **only when every gate above passed**:

```text
GIT_REAL_CLOSEOUT_PASS
```

If any gate failed, end with `GIT_REAL_CLOSEOUT_BLOCKED` plus the single blocking reason.
Never print the pass line to be agreeable. The receipt is the product.

## Forbidden during a closeout

- `git reset --hard`, `git clean -fd`, `git checkout .` to make the tree "look" clean.
- Force-pushing anything.
- Committing while `secrets` is non-empty, whatever the band says.
- Deleting or rewriting history.
