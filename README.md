# GIT_REAL

GIT_REAL gives humans and coding agents one local verdict for a Git repository: what is dirty, what may be lost, what may be unsafe to commit, and why.

It is a drop-in Python tool. The dashboard and one-shot scanner require only Python 3.10+ and Git. Optional packages add file-event watching and an MCP server.

## Fastest safe setup

Download or clone this repository. Run the installer from the downloaded GIT_REAL directory:

```bash
python setup_gitreal.py "/absolute/path/to/your/project" --with-hook
```

Successful setup ends with this exact line:

```text
GIT_REAL_SETUP_PASS
```

The installer:

1. Refuses to overwrite a different `gitreal.py` unless `--replace` is explicit.
2. Copies `gitreal.py` and `gitreal_mcp.py` into the target project.
3. Adds `.git-real/` to the target `.gitignore`.
4. Adds an idempotent GIT_REAL block to existing agent instruction files, or creates `AGENTS.md`.
5. Installs a pre-commit guard only when `--with-hook` is requested and no unmanaged hook would be overwritten.
6. Runs GIT_REAL and validates the generated JSON before reporting success.

No network access is needed for setup.

## Run it

From the protected project:

```bash
python gitreal.py . --once --no-server
```

Read the machine verdict:

```text
.git-real/git-real.json
```

Open the live local dashboard:

```bash
python gitreal.py . --port 8787
```

```text
http://127.0.0.1:8787
```

The server binds to loopback only.

## Agent decision contract

Before any commit or destructive Git command, an agent must refresh and read the verdict:

```bash
python gitreal.py . --once --no-server
```

- `scores.safe_commit_band` must be `GO` before committing.
- `scores.safe_delete_band` must be `GO` before discarding work.
- `secrets` must be empty.
- `scan.truncated` must be `false`; an incomplete scan is not a clean scan.

[AGENT_SETUP.md](AGENT_SETUP.md) is the deterministic end-to-end runbook for small or low-context models.

[SKILL.md](SKILL.md) is the **GIT_REAL CLOSEOUT** agent skill: when the user says "do a GIT_REAL CLOSEOUT", the agent ends the session with the repository proven clean — commit and push only under `GO` bands, hard-stop on secrets, exact receipt at the end. Drop it into your agent's skills directory or let the installer's agent-instructions block point to it.

## What it detects

- Dirty, staged, untracked, conflicting, junk, and large files.
- Unpushed commits, side branches, stashes, upstream state, and repository topology.
- Curated secret patterns and suspicious high-entropy values, always masked in reports.
- Already-committed secrets when `--history` is requested.
- Repository push weight and the largest tracked blobs.
- Multiple repositories through FLEET mode.

## Guard commands

Block on a suspected working-tree secret or a commit score below 80:

```bash
python gitreal.py . --once --no-server --fail-on-secret --fail-under 80
```

Audit committed history:

```bash
python gitreal.py . --once --no-server --history --fail-on-secret
```

Scan a folder containing multiple repositories:

```bash
python gitreal.py "/absolute/path/to/projects" --all --once --no-server --fail-on-secret
```

## Optional MCP server

Install the MCP SDK:

```bash
python -m pip install -r requirements-mcp.txt
```

Start the stdio server:

```bash
python gitreal_mcp.py
```

Available tools:

- `git_real_status`
- `is_safe_to_commit`
- `is_safe_to_discard`
- `list_secrets`
- `secrets_in_history`
- `git_real_fleet`
- `gitignore_add`

## Privacy boundary

GIT_REAL has no telemetry. Its core does not upload repository data.

The local `.git-real/` output can contain absolute paths, repository names, file names, branch names, commit subjects, stash messages, and remote metadata. The installer adds that directory to `.gitignore`. Do not publish or attach `.git-real/` without reviewing it.

Read [PRIVACY.md](PRIVACY.md) and [SECURITY.md](SECURITY.md) before using reports outside the local machine.

## Validate this distribution

```bash
python scripts/release_check.py
```

Successful release validation ends with:

```text
GIT_REAL_RELEASE_CHECK_PASS
```

## Limits

- Scores are conservative heuristics, not guarantees.
- The built-in secret scanner is intentionally bounded and cannot detect every credential format.
- A clean result applies only to the files and history actually scanned in that run.
- GIT_REAL reports a verdict; only a wired hook, CI command, or agent policy enforces it.

## License

MIT. See [LICENSE](LICENSE).
