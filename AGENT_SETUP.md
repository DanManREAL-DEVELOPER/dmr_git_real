# GIT_REAL setup runbook for any coding agent

## Objective

Install GIT_REAL into one target Git project, wire the agent contract, run verification, and stop only after the exact success receipt appears.

## Inputs

You need two absolute paths:

```text
GIT_REAL_DOWNLOAD = the directory containing setup_gitreal.py
TARGET_PROJECT = the Git project to protect
```

Do not guess either path. Confirm both directories exist before continuing.

## One-command installation

Run this from `GIT_REAL_DOWNLOAD` after replacing the target placeholder with the real absolute path:

```bash
python setup_gitreal.py "/absolute/path/to/target/project" --with-hook
```

Success requires the exact final line:

```text
GIT_REAL_SETUP_PASS
```

If the line is absent, setup did not prove success. Read the single `GIT_REAL_SETUP_FAIL` message and fix that cause.

## Verify again without changing files

```bash
python setup_gitreal.py "/absolute/path/to/target/project" --check
```

Success requires:

```text
GIT_REAL_CHECK_PASS
```

## Verify the target runtime

Run this from `TARGET_PROJECT`:

```bash
python gitreal.py . --once --no-server
```

Open and read:

```text
.git-real/git-real.json
```

The minimum acceptance checks are:

```text
is_repo = true
scores.safe_commit_band exists
scores.safe_delete_band exists
secrets is an empty list
scan.truncated = false
```

Do not claim the repository is safe to commit unless `scores.safe_commit_band` is `GO`.

Do not discard work unless `scores.safe_delete_band` is `GO`.

## Existing-file rules

- If `gitreal.py` already exists and differs, stop. Re-run with `--replace` only after the user authorizes replacement. The installer backs up the old file under `.git-real/backups/`.
- If an unmanaged pre-commit hook already exists, the installer preserves it and prints `SKIPPED pre-commit hook`. Do not overwrite it.
- If the target is not a Git repository, stop. Use `--init` only when creating a repository is explicitly intended.
- Never upload `.git-real/`. It contains local repository metadata.

## Agent operating contract after installation

Before `git commit`, `git checkout .`, `git clean -fd`, or `git reset --hard`:

```bash
python gitreal.py . --once --no-server
```

Then read `.git-real/git-real.json` and obey the three gates:

1. Commit only when `scores.safe_commit_band` is `GO`.
2. Discard only when `scores.safe_delete_band` is `GO`.
3. Stop when `secrets` is non-empty or `scan.truncated` is true.

## Final agent report

Report only these concrete facts:

```text
Setup receipt: GIT_REAL_SETUP_PASS or the exact failure
Check receipt: GIT_REAL_CHECK_PASS or the exact failure
Safe commit band: value from JSON
Safe discard band: value from JSON
Secret count: length of secrets
Scan truncated: value from scan.truncated
Hook: installed, updated, skipped-existing, or not requested
```
