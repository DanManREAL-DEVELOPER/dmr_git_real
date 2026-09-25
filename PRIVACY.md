# Privacy

## Network behavior

The core `gitreal.py` tool sends no repository data to an external service.

The optional dashboard listens on `127.0.0.1`. The optional MCP server uses
local stdio. Installing optional Python packages may contact the package index
configured by the user.

## Data GIT_REAL reads

GIT_REAL v1.2 reads Git and filesystem metadata needed to assess repository
operations, including:

- repository and file names;
- status, index modes and object IDs;
- branches, tags, upstream refs, worktrees, and stashes;
- commit subjects already present in Git metadata;
- ignored and untracked path names;
- remote URLs after embedded HTTP credentials are redacted;
- SSH identity key basenames, never key contents.

GIT_REAL v1.2 deliberately does not inspect repository file contents for
secrets.

## Data written locally

Dashboard/file mode writes local reports under `.git-real/`. `--json` prints a
fresh result to stdout without publishing dashboard files.

Local reports can contain absolute paths, repository names, file names, branch
names, commit subjects, stash messages, remote metadata, and action evidence.
The installer adds `.git-real/` to `.gitignore`.

Do not upload, attach, publish, or screenshot `.git-real/` without reviewing
it.

## Data not collected

GIT_REAL shas no account system, telemetry client, analytics identifier,
advertising SDK, or hosted data store.

## Public examples

Documentation and tests use synthetic identities, `example.invalid` addresses,
and disposable repositories. The release gate rejects common personal
absolute-path shapes from the public text surface.
