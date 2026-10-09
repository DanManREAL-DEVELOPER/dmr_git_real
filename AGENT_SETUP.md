# GIT_REAL v1.3.1 setup runbook for coding agents

## Objective

When asked to install GIT_REAL, complete the authorized setup in the selected
repository and report its actual receipt. The installer can wire a focused Git
action contract; that contract does not authorize later Git actions or publishing.

## Inputs

Resolve the supplied or unambiguous paths before acting. Ask only if the target
or replacement scope remains unclear:

```text
GIT_REAL_DOWNLOAD = directory containing setup_gitreal.py
TARGET_PROJECT = existing Git repository to protect
```

## Install

Run from `GIT_REAL_DOWNLOAD`:

```bash
python setup_gitreal.py "/absolute/path/to/target/project"
```

Use Python 3.10 or newer and an available Git executable. Add `--with-hook` when
the selected setup includes a managed pre-commit hook; it is optional. This
workflow does not implicitly authorize repository initialization or client setup.

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

## Check an existing installation

Use this mode when checking an existing installation. A normal verified install
already performs its fresh runtime check; repeating it is not a setup requirement.
This mode performs no installer file writes. It executes the installed engine
for fresh evidence; it is not a sandbox for arbitrary replacement runtime code.

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
version == "1.3.1"
schema_version is the integer 2
root == the canonical target root
is_repo == true
read_complete == true
read_errors is an empty list
publication_id is a nonempty string
```

Require a successful command and a JSON object. An incomplete or malformed result
blocks the affected action; it does not require abandoning independent authorized
work. Resolve routine scope-preserving failures before asking about a real choice.

A watcher, an older JSON file, a score, or a clean-looking working tree is not
fresh authorization.

## Assess an exact operation

Plain commit of the inspected index:

```bash
python gitreal.py "/absolute/path/to/target/project" --quick --json --operation commit_index
```

Before acting, require:

```text
requested_action.operation == "commit_index"
requested_action.safe == true
requested_action.decision == "ALLOW"
```

Other supported checks include:

```bash
python gitreal.py "/absolute/path/to/target/project" --quick --json --operation discard_tracked

python gitreal.py "/absolute/path/to/target/project" --quick --json --operation clean_untracked

python gitreal.py "/absolute/path/to/target/project" --quick --json --operation clean_ignored

python gitreal.py "/absolute/path/to/target/project" --quick --json --operation reset_hard --target "COMMIT_OID"

python gitreal.py "/absolute/path/to/target/project" --quick --json --operation drop_stash --target 'stash@{0}'
```

Replace `COMMIT_OID` with the intended commit ID. These commands assess an
operation; they do not execute it. Require the operation to be in the user's
authorized scope as well as its fresh preservation verdict. For a reset, use the
returned `resolved_target` OID for the authorized Git action.

An `ALLOW` applies only to the exact returned operation, target, repository
root, HEAD, index fingerprint, and publication ID. The commit/discard checks above
do not cover branch changes, push, additional flags or recursive submodules.
Other supported operations have their own contracts in `README.md`; no verdict
covers future state after another writer changes the repository.

## Using an existing MCP connection

If an MCP client is already configured, `git_real_status(path)` supplies fresh
schema-2 state. `is_safe_to_commit(path)` returns the commit verdict directly:
`operation`, `safe`, `decision`, root and binding fields are at the top level,
not under `requested_action`. `is_safe_to_discard(path, operation, target)` accepts
the five discard checks above, with a target only for reset or stash removal.
The status tool's optional operation arguments are for branch/integration/origin
checks; do not pass `commit_index` or a discard operation to that interface.

Require complete, error-free evidence and the exact action in either interface;
scores never grant permission. After a source upgrade, a loaded MCP process can
refuse stale evidence until reconnected. Handle that within the authorized client
scope, or use the permitted fresh CLI path; this runbook does not itself authorize
a client restart, installation or configuration change.

## Important boundary

GIT_REAL v1.3.1 does not inspect repository contents for secrets. Its receipts do
not establish their absence or authorize a separate scanning workflow.

The installer appends the exact ignore line without rewriting existing bytes.
It refuses symlinks, multiply linked files and incompatible destination types
before runtime copying. Hook setup also refuses a symlinked `.git` directory and
an existing `core.hooksPath`; omit `--with-hook` to preserve a custom hook setup.
An unmanaged hook is preserved and reported as skipped.

The installer retains its narrower managed-instruction contract: an unambiguous
marker pair, valid UTF-8 and LF line endings. The direct `--wire-agents` command
now supports byte-preserving updates for non-UTF8 bytes, a UTF-8 BOM and existing
line endings; the installer still refuses those managed files when its own
preflight does not accept them. `--no-wire-agents` preserves instruction files
and installs only the selected remaining parts. This option also leaves
unselected instruction symlinks alone.

Verification requires a complete schema-2 response, a publication identity,
the exact target root and a consistent commit decision. A valid `BLOCK` decision
can accompany a successful installation; setup success is not commit approval.
`--no-verify` ends with `GIT_REAL_SETUP_UNVERIFIED`.

Installation is not a multi-file transaction. Preflight catches known invalid
destinations before copying, and explicit replacements retain unique backups;
a later I/O or runtime failure can still leave a partial installation. Inspect
the reported failure and retained backups before resuming it.

## Final report

Report concrete evidence for the mode actually run; mark other modes not run.
Do not run `--check` or a Git action merely to fill a report field:

```text
Setup receipt: GIT_REAL_SETUP_PASS, GIT_REAL_SETUP_UNVERIFIED, exact failure, or not run
Check receipt: GIT_REAL_CHECK_PASS, exact failure, or not run
Version/schema: values from fresh JSON
Read complete: true/false
Operation checked: exact operation and target
Decision: ALLOW or BLOCK
Reasons: exact returned reasons
Hook: installed, updated, skipped-existing, or not requested
```
