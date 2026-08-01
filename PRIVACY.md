# Privacy

## Network behavior

The core `gitreal.py` tool does not send repository data to an external service.

The optional dashboard listens on `127.0.0.1`. The optional MCP server uses local stdio. Package installation may contact the configured Python package index only when the user explicitly installs optional dependencies.

## Data written locally

Every scan writes local files under `.git-real/` in the target repository.

Those files may contain:

- Absolute local paths.
- Repository and file names.
- Branch names and upstream state.
- Commit subjects and authors already present in Git history.
- Stash names and messages.
- Remote URLs after embedded HTTP credentials are redacted.
- SSH identity key basenames, never key contents.
- Secret findings with values masked.

The installer adds `.git-real/` to `.gitignore`. Do not upload, attach, publish, or screenshot that directory without reviewing it.

## Data not collected

GIT_REAL has no account system, telemetry client, analytics identifier, advertising SDK, or hosted data store.

## Public examples

Documentation and tests use synthetic names, invalid example addresses, and temporary repositories. Release checks reject common personal absolute-path shapes from tracked text.
