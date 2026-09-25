# GIT_REAL v1.2 setup runbook for coding agents

## Objective

Install the public GIT_REAL v1.2 engine into one existing Git repository, wire
the operation-specific agent contract, and stop only after an exact success
receipt.

## Inputs

Confirm both paths before acting:

```text
GIT_REAL_DOWNLOAD = directory containing setup_gitreal.py
TARGET_PROJECT = existing Git repository to protect
```

## Install

Run from `GIT_REAL_DOWNLOAD`:

```bash
python setup_gitreal.py "/absolute/path/to/target/project" --with-hook
```

Success requires the exact final line:

```text
GIT_REAL_SETUP_PASS
```

The installer copies `gitreal.py` and `gitreal_mcp.py`, adds `.git-real/` to
`.gitignore`, wires the managed agent block, optionally installs a pre-commit
hook, and performs a fresh schema-2 verification.

A different existing runtime is never overwritten implicitly. Use `--replace`
only after replacement is authorized; the installer first preserves the old
file under `.git-real/backups/`.

## Verify without changing files

```bash
python setup_gitreal.py "/absolute/path/to/target/project" --check
```

Success requires:

```text
GIT_REAL_CHECK_PASS
```

## Read fresh repository state

Run against the actual repository root:

```bash
python gitreal.py "/absolute/path/to/target/project" --quick --json
```

Treat the result as usable only when all of these are true:

```text
version == "1.2.0"
schema_version == 2
root == the canonical target root
read_complete == true
read_errors is empty
```

A watcher, an older JSON file, a score, or a clean-looking working tree is not
fresh authorization.

## Assess an exact operation

Plain commit of the inspected index:

```bash
python gitreal.py "/absolute/path/to/target/project"   --quick --json --operation commit_index
```

Before acting, require:

```text
requested_action.operation == "commit_index"
requested_action.safe == true
requested_action.decision == "ALLOW"
```

Other supported checks include:

```bash
python gitreal.py "/absolute/path/to/target/project"   --quick --json --operation discard_tracked

python gitreal.py "/absolute/path/to/target/project"   --quick --json --operation clean_untracked

python gitreal.py "/absolute/path/to/target/project"   --quick --json --operation clean_ignored

python gitreal.py "/absolute/path/to/target/project"   --quick --json --operation reset_hard --target <commit-oid>

python gitreal.py "/absolute/path/to/target/project"   --quick --json --operation drop_stash --target 'stash@{0}'
```

An `ALLOW` applies only to the exact returned operation, target, repository
root, HEAD, index fingerprint, and publication ID. It does not authorize a
different command, additional flags, recursive submodule behavior, force push,
branch deletion, or future state after another writer changes the repository.

## Important boundary

GIT_REAL v1.2 deliberately does not inspect repository file contents for
secrets. Use a dedicated secret scanner and your repository's security controls
for that separate job.

## Final report

Report concrete evidence:

```text
Setup receipt: GIT_REAL_SETUP_PASS or exact failure
Check receipt: GIT_REAL_CHECK_PASS or exact failure
Version/schema: values from fresh JSON
Read complete: true/false
Operation checked: exact operation and target
Decision: ALLOW or BLOCK
Reasons: exact returned reasons
Hook: installed, updated, skipped-existing, or not requested
```
