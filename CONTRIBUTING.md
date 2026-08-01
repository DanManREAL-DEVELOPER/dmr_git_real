# Contributing

GIT_REAL intentionally keeps its runtime flat and easy to vendor. Preserve that property.

## Required checks

```bash
python scripts/release_check.py
```

Every bug fix must add or strengthen a regression test. Every new output field must remain safe for local JSON, dashboard, and MCP consumers.

## Safety rules

- Never commit a live credential or private key.
- Use synthetic repositories and `example.invalid` identities in tests.
- Never add personal absolute paths to fixtures, screenshots, or documentation.
- Keep `.git-real/`, virtual environments, caches, and local configuration untracked.
- Do not weaken a failing guard. Fix the cause or document a narrowly justified false positive.

## Runtime compatibility

The dashboard stays standard-library-only. Optional behavior must degrade cleanly when `watchdog` or `mcp` is unavailable.
