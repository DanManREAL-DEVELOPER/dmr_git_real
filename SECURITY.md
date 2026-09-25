# Security policy

## Report a vulnerability

Use the repository host's private security-advisory feature. Do not open a
public issue containing credentials, private paths, customer data, or an
actionable exploit.

## What GIT_REAL v1.2 protects

GIT_REAL provides local, operation-specific evidence about Git repository
state. It is designed to prevent an agent from translating a vague signal such
as “clean tree” or “looks like build output” into permission to commit or
destroy work.

The v1.2 engine:

- reads Git status, refs, index metadata, worktrees, stashes, ignored paths, and
  active operations;
- distinguishes a plain index commit from destructive operations;
- fails closed when required reads are incomplete;
- binds an `ALLOW` decision to the exact operation, target, root, HEAD, index
  fingerprint, and publication ID;
- reports unknown publication state as unknown rather than zero.

## What GIT_REAL does not provide

- It is not a content secret scanner.
- It is not a malware scanner, backup service, or access-control system.
- A snapshot is not an execution lock; another writer may change the repository
  immediately after inspection.
- Local remote-tracking refs are not proof of current server state.
- An `ALLOW` for one operation is not authorization for another command or
  additional flags.
- Scores are summaries and never owner authorization.

Use dedicated secret scanning, signed release controls, backups, and repository
permissions alongside GIT_REAL.

## Safe use

- Refresh immediately before the exact action being assessed.
- Require schema 2, a complete read, and no read errors.
- Never reuse a result after repository state changes.
- Preserve unknown or unproven work.
- Do not publish `.git-real/` without reviewing local metadata.
- Reconnect MCP clients after replacing the engine; a running Python process
  does not hot-reload changed source.

## Release verification

Maintainers run:

```bash
python scripts/release_check.py
```

The release is not ready unless the final line is:

```text
GIT_REAL_RELEASE_CHECK_PASS
```
