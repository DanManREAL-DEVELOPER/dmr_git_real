# Security policy

## Report a vulnerability

Use the repository host's private security-advisory feature. Do not open a public issue containing a live credential, private path, or exploit payload.

## What GIT_REAL protects

GIT_REAL provides a local early-warning layer for risky Git state. It masks detected secret values in JSON and HTML output. Guard commands fail closed when a requested secret scan is incomplete.

## What GIT_REAL cannot guarantee

- Regex and entropy checks cannot detect every credential format.
- Allowlist entries can hide real secrets when used carelessly.
- A clean working-tree scan does not prove clean history unless `--history` ran.
- A clean history scan covers the Git objects and refs available in that clone.
- Scores express evidence and risk; they are not authorization from a repository owner.

## Safe disclosure rules

- Revoke or rotate an exposed credential before discussing it.
- Share masked values only.
- Do not attach `.git-real/` reports without reviewing local metadata.
- Do not paste private keys, tokens, passwords, or unredacted remote URLs into an issue.

## Release verification

Maintainers run:

```bash
python scripts/release_check.py
```

The release is not ready unless the final line is:

```text
GIT_REAL_RELEASE_CHECK_PASS
```
