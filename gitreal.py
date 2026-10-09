#!/usr/bin/env python3
"""
GIT_REAL - drop-in git situational-awareness for humans AND AI agents.

Mission: show the FULL DETAIL + SCOPE of a folder's git state so NO GIT
CONFUSION IS EVER CAUSED AGAIN.

Slogan: "Get real about your repo. Stop fighting agents over dirty trees." (GIT_REAL)

Drop this single file into ANY folder and run:

    python gitreal.py

It will:
  * immediately begin tracking git end-to-end (modified / staged / untracked /
    branches / push state / stashes / ignored)
  * classify every new file as DIRTY until committed
  * compute structural commit/discard summary scores; explicit operation
    decisions are required before treating a snapshot as action evidence
  * write two outputs that auto-refresh:
        .git-real/git-real.html   <- for HUMANS (live dashboard)
        .git-real/git-real.json   <- for AGENTS (Claude Code / Codex read this)
  * serve a read-only live dashboard at http://127.0.0.1:8787

Zero hard dependencies (pure stdlib). If `watchdog` is installed it is used for
instant file events; otherwise GIT_REAL falls back to lightweight polling.

Usage:
    python gitreal.py [PATH] [--port N] [--poll] [--no-server] [--once]
                       [--interval SECONDS] [--init]

    PATH            folder to watch (default: current dir)
    --port N        dashboard port (default: 8787)
    --poll          force polling watcher (use for /mnt/c or networked drives)
    --no-server     write files only, no dashboard server
    --once          generate output once and exit (CI / snapshot)
    --interval S    rescan/poll interval seconds (default: 4)
    --init          run `git init` if PATH is not a git repo
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import html
import http.server
import json
import os
import re
import socketserver
import stat
import subprocess
import shutil
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone

VERSION = "1.3.1"
SCHEMA_VERSION = 2
with open(__file__, "rb") as _source_file:
    ENGINE_SOURCE_SHA256 = hashlib.sha256(_source_file.read()).hexdigest()
OUTPUT_DIRNAME = ".git-real"
DEFAULT_PORT = 8787
DEFAULT_INTERVAL = 4.0
LARGE_FILE_WARN = 5_000_000          # bytes; warn about big untracked/staged files
LARGE_FILE_CRIT = 50_000_000         # bytes; Git-LFS territory
DEBOUNCE_SECONDS = 0.75              # collapse bursts of fs events into one rescan

# stage_paths resource ceilings are implementation bounds, not safety thresholds.
# GIT_REAL still decides from the exact simulated manifest rather than a magic
# "N files is safe" cutoff.
STAGE_MAX_REQUEST_PATHS = 4096
STAGE_MAX_PATH_BYTES = 4096
STAGE_MAX_MANIFEST_ENTRIES = 50_000
STAGE_MAX_REPORTED_PATHS = 128
STAGE_MAX_METADATA_ENTRIES = 4096

# Untracked junk that should almost always be gitignored.
JUNK_DIR_NAMES = {
    "node_modules", "__pycache__", ".venv", "venv", "env", ".env.d",
    "dist", "build", ".next", ".nuxt", "target", "out", ".cache",
    "coverage", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".gradle",
    ".turbo", ".parcel-cache", "bower_components", ".terraform", "vendor",
}
JUNK_FILE_RULES = [re.compile(p, re.IGNORECASE) for p in [
    r".*\.pyc$", r".*\.pyo$", r".*\.log$", r"^\.ds_store$", r"^thumbs\.db$",
    r".*\.tmp$", r".*\.temp$", r".*\.bak$", r".*\.swp$", r".*\.swo$",
    r".*\.class$", r".*\.o$", r".*\.obj$", r".*\.egg-info$", r".*~$",
]]

# Suggested .gitignore additions, keyed by what triggers them.
GITIGNORE_SUGGESTIONS = {
    "node_modules": "node_modules/",
    "__pycache__": "__pycache__/",
    ".venv": ".venv/",
    "venv": "venv/",
    "env": "env/",
    "dist": "dist/",
    "build": "build/",
    ".next": ".next/",
    "target": "target/",
    "out": "out/",
    "coverage": "coverage/",
    ".pytest_cache": ".pytest_cache/",
    ".mypy_cache": ".mypy_cache/",
    ".cache": ".cache/",
    ".DS_Store": ".DS_Store",
    "Thumbs.db": "Thumbs.db",
    ".env": ".env",
    ".gradle": ".gradle/",
    ".terraform": ".terraform/",
}

BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".pdf", ".zip",
    ".gz", ".tar", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib", ".bin",
    ".wasm", ".mp4", ".mov", ".avi", ".mkv", ".mp3", ".wav", ".flac", ".ogg",
    ".woff", ".woff2", ".ttf", ".otf", ".glb", ".gltf", ".fbx", ".obj",
    ".psd", ".ai", ".sketch", ".db", ".sqlite", ".pyc", ".class", ".o",
}




# ----------------------------------------------------------------------------
# formatting + remote-identity helpers
# ----------------------------------------------------------------------------
def human_size(n) -> str:
    """Human-readable byte size (e.g. 1536 -> '1.5 KB')."""
    try:
        n = int(n)
    except (TypeError, ValueError):
        return "0 B"
    if n <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    f = float(n)
    i = 0
    while f >= 1024 and i < len(units) - 1:
        f /= 1024
        i += 1
    return f"{int(f)} {units[i]}" if i == 0 else f"{f:.1f} {units[i]}"


def _parse_ssh_config(path: str | None = None) -> list[tuple[list[str], dict]]:
    """Parse ~/.ssh/config into [(host_patterns, {hostname, identityfile, user}), ...]."""
    path = path or os.path.expanduser("~/.ssh/config")
    blocks: list[tuple[list[str], dict]] = []
    if not os.path.isfile(path):
        return blocks
    cur_hosts: list[str] | None = None
    cur: dict = {}
    try:
        with open(path, "r", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                # split key from value on first run of whitespace (or '=')
                m = re.match(r"^(\S+)\s*=?\s*(.*)$", line)
                if not m:
                    continue
                key, val = m.group(1).lower(), m.group(2).strip()
                if key == "host":
                    if cur_hosts is not None:
                        blocks.append((cur_hosts, cur))
                    cur_hosts = val.split()
                    cur = {}
                elif cur_hosts is not None and key in ("hostname", "identityfile", "user"):
                    cur.setdefault(key, val)
        if cur_hosts is not None:
            blocks.append((cur_hosts, cur))
    except OSError:
        pass
    return blocks


def redact_url_credentials(url: str) -> str:
    """Strip userinfo from a URL so a token embedded in a remote never leaves this function.

    credential-bearing HTTPS remote           -> https://***@github.com/o/r.git
    ssh://git@host/o/r.git                    -> unchanged (a bare username is not a secret)
    """
    if not url:
        return url
    def redact(match):
        scheme, userinfo = match.group(1), match.group(2)
        if scheme.lower().startswith(("http:", "https:")) or ":" in userinfo:
            return scheme + "***@"
        return match.group(0)
    redacted = re.sub(r"^([a-z][a-z0-9+.-]*://)([^/@]+)@", redact, url, flags=re.I)
    # Query strings/fragments are not required for displayed repository identity.
    return re.sub(r"[?#].*$", "?[redacted]", redacted) if "://" in redacted else redacted


def resolve_remote_identity(url: str, ssh_config_path: str | None = None) -> dict:
    """Display URL/basic Host-config hints, never authenticate or prove an account.

    Includes, Match/exec, system config, command-line overrides and SSH agent
    selection are outside this lightweight parser. No shell/config commands run.
    """
    # Never store credential-bearing userinfo. An HTTPS remote can carry a PAT
    # An HTTPS remote may contain a credential; the raw string would otherwise reach
    # git-real.json, the HTTP API, the dashboard HTML and the MCP response.
    url = redact_url_credentials(url)
    info = {
        "url": url, "scheme": None, "host": None,
        "is_ssh_alias": False,      # host string maps to a DIFFERENT real hostname
        "identity_pinned": False,   # ~/.ssh/config pins an IdentityFile for this host
        "identity_file": None, "real_host": None, "warning": None,
        "authentication_verified": False,
        "basis": "URL and basic user Host-block hints only; not effective SSH configuration or account proof",
    }
    if not url:
        return info
    if url.lower().startswith(("http://", "https://")):
        info["scheme"] = "https"
        hm = re.match(r"https?://(?:[^@/]+@)?([^/]+)/", url, flags=re.I)
        info["host"] = hm.group(1) if hm else None
        info["real_host"] = info["host"]
        info["warning"] = ("HTTPS remote - the push authenticates with a stored "
                           "credential/token, not an SSH key; the account can't be "
                           "verified from git config alone.")
        return info
    sm = re.match(r"^(?:ssh://)?(?:([^@]+)@)?([^:/]+)[:/](.+)$", url)
    if not sm:
        info["scheme"] = "unknown"
        return info
    info["scheme"] = "ssh"
    info["host"] = sm.group(2)
    merged = {}
    for patterns, cfg in _parse_ssh_config(ssh_config_path):
        positive = any(fnmatch.fnmatchcase(info["host"].lower(), pat.lower())
                       for pat in patterns if not pat.startswith("!"))
        negative = any(fnmatch.fnmatchcase(info["host"].lower(), pat[1:].lower())
                       for pat in patterns if pat.startswith("!"))
        if positive and not negative:
            for key, value in cfg.items():
                merged.setdefault(key, value)
    if merged:
        info["real_host"] = merged.get("hostname") or info["host"]
        info["is_ssh_alias"] = info["real_host"] != info["host"]
        info["identity_pinned"] = bool(merged.get("identityfile"))
        if merged.get("identityfile"):
            info["identity_file"] = os.path.basename(os.path.expanduser(merged["identityfile"]))
    if info["real_host"] is None:
        info["real_host"] = info["host"]
    # ambiguous only when a bare well-known host has NO pinned key and is NOT an alias
    if (info["host"] in ("github.com", "gitlab.com", "bitbucket.org")
            and not info["identity_pinned"] and not info["is_ssh_alias"]):
        info["warning"] = (f"Bare '{info['host']}' remote with no pinned key - the push "
                           f"identity is whatever default SSH key/agent answers, which may "
                           f"not be the intended account. Pin a Host alias + IdentityFile.")
    return info


# ----------------------------------------------------------------------------
# git interface (raw subprocess; no third-party deps)
# ----------------------------------------------------------------------------
class GitRepo:
    def __init__(self, root: str, *, git_environment: dict[str, str] | None = None):
        self.root = os.path.abspath(root)
        self.read_errors: list[str] = []
        self.git_environment = None if git_environment is None else dict(git_environment)

    def _run(self, *args, timeout=25, input_text=None):
        try:
            r = subprocess.run(
                ["git", "--no-optional-locks", "-C", self.root,
                 "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", *args],
                capture_output=True, text=True, encoding="utf-8",
                errors="surrogateescape", timeout=timeout,
                input=input_text,
                env={**(os.environ if self.git_environment is None else self.git_environment),
                     "LC_ALL": "C", "GIT_OPTIONAL_LOCKS": "0",
                     "GIT_NO_LAZY_FETCH": "1"},
            )
            return r.stdout, r.returncode, r.stderr
        except FileNotFoundError:
            return "", 127, "git not found on PATH"
        except subprocess.TimeoutExpired:
            return "", 124, "git command timed out"
        except Exception as e:  # noqa: BLE001
            return "", 1, str(e)

    def _required(self, *args, **kwargs):
        """A failed required inventory is unknown, never an empty collection."""
        out, rc, err = self._run(*args, **kwargs)
        if rc:
            self.read_errors.append(f"git {args[0]} inventory failed (rc={rc})")
        return out, rc, err

    def is_repo(self) -> bool:
        out, rc, _ = self._run("rev-parse", "--is-inside-work-tree")
        return rc == 0 and out.strip() == "true"

    def init(self):
        return self._run("init")

    def has_commits(self) -> bool:
        _, rc, _ = self._run("rev-parse", "--verify", "HEAD")
        return rc == 0

    # --- status -------------------------------------------------------------
    def status(self) -> dict:
        """Parse NUL-delimited porcelain; collapsed directories are never disposable."""
        try:
            _status_filter_preflight(self)
        except (OSError, ValueError, RuntimeError) as exc:
            out, rc, err = "", 1, str(exc)
        else:
            out, rc, err = self._run(
                "status", "--porcelain=v2", "-z", "--branch",
                "--untracked-files=normal", "--ignore-submodules=none")
        data = {
            "branch": None, "upstream": None, "ahead": 0, "behind": 0,
            "detached": False, "oid": None,
            "staged": [], "modified": [], "untracked": [], "conflicts": [],
            "renamed": [],
            "submodules": [], "ahead_behind_known": False,
            "ok": rc == 0,
            "complete": rc == 0,
            "error": None if rc == 0 else (err.strip() or f"git status failed (rc={rc})"),
        }
        if rc != 0:
            self.read_errors.append(data["error"])
            return data
        def malformed(message):
            data.update(ok=False, complete=False, error=message)
            self.read_errors.append(message)
            return data
        if out and not out.endswith("\0"):
            return malformed("Incomplete porcelain status framing")
        records = iter(out.split("\0"))
        for line in records:
            if not line:
                continue
            if line.startswith("# "):
                key, separator, value = line[2:].partition(" ")
                if key in {"branch.head", "branch.oid", "branch.upstream", "branch.ab"} and (not separator or not value):
                    return malformed("Malformed porcelain branch header")
            if line.startswith("# branch.head "):
                head = line.split(" ", 2)[2]
                if head == "(detached)":
                    data["detached"] = True
                else:
                    data["branch"] = head
            elif line.startswith("# branch.upstream "):
                data["upstream"] = line.split(" ", 2)[2]
            elif line.startswith("# branch.ab "):
                m = re.fullmatch(r"# branch\.ab \+([0-9]+) -([0-9]+)", line)
                if not m:
                    return malformed("Malformed porcelain ahead/behind header")
                data["ahead"], data["behind"] = int(m.group(1)), int(m.group(2))
                data["ahead_behind_known"] = True
            elif line.startswith("# branch.oid "):
                oid = line.split(" ", 2)[2]
                if oid != "(initial)" and not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", oid):
                    return malformed("Malformed porcelain branch object name")
                data["oid"] = oid
            elif line.startswith("1 ") or line.startswith("2 "):
                renamed = line.startswith("2 ")
                parts = line.split(" ", 9 if renamed else 8)
                if len(parts) != (10 if renamed else 9) or len(parts[1]) != 2:
                    return malformed("Malformed porcelain status record")
                xy = parts[1]
                path = parts[-1]
                if not path:
                    return malformed("Missing porcelain status path")
                if renamed:
                    original = next(records, None)
                    if not original:
                        return malformed("Truncated rename record")
                    data["renamed"].append(path)
                if parts[2].startswith("S"):
                    data["submodules"].append({"path": path, "state": parts[2]})
                staged_flag, work_flag = xy[0], xy[1]
                if staged_flag != ".":
                    data["staged"].append({"path": path, "x": staged_flag,
                                           "mode": parts[4], "oid": parts[7]})
                if work_flag != ".":
                    data["modified"].append({"path": path, "y": work_flag})
            elif line.startswith("u "):
                parts = line.split(" ", 10)
                if len(parts) != 11 or not parts[-1]:
                    return malformed("Malformed conflict record")
                data["conflicts"].append(parts[-1])
            elif line.startswith("? "):
                if not line[2:]:
                    return malformed("Missing untracked status path")
                data["untracked"].append(line[2:])
            elif not line.startswith("# "):
                return malformed("Unknown porcelain status record")
        if data["oid"] is None or (data["branch"] is None and not data["detached"]):
            return malformed("Missing porcelain branch evidence")
        return data

    def index_blob_size(self, path: str) -> int | None:
        """Return the staged blob size for *path*, or None when no blob is staged."""
        out, rc, _ = self._required("cat-file", "-s", f":{path}")
        if rc != 0:
            return None
        try:
            return int(out.strip())
        except (TypeError, ValueError):
            self.read_errors.append("Malformed staged blob size")
            return None

    def index_inventory(self) -> dict:
        """Metadata only: detect status-hidden work and fingerprint the index."""
        out, rc, _ = self._required("ls-files", "--stage", "-v", "-z")
        data = {"hidden_paths": [], "gitlinks": [], "unmerged_paths": [],
                "fingerprint": hashlib.sha256(out.encode("utf-8", "surrogateescape")).hexdigest()}
        if rc:
            return data
        if out and not out.endswith("\0"):
            self.read_errors.append("Incomplete index inventory framing")
            return data
        seen = set()
        for row in out.split("\0"):
            if not row:
                continue
            tag, _, rest = row.partition(" ")
            meta, sep, path = rest.partition("\t")
            fields = meta.split()
            if (not sep or len(tag) != 1 or tag.upper() not in "HSMRCK?U" or len(fields) != 3
                    or not path or os.path.isabs(path)
                    or any(part in ("", ".", "..") for part in path.split("/"))
                    or fields[0] not in ("100644", "100755", "120000", "160000")
                    or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", fields[1])
                    or fields[2] not in ("0", "1", "2", "3") or (path, fields[2]) in seen):
                self.read_errors.append("Malformed index inventory")
                continue
            seen.add((path, fields[2]))
            if tag.islower() or tag.upper() == "S":
                data["hidden_paths"].append({"path": path, "flag": tag})
            if fields[0] == "160000":
                data["gitlinks"].append(path)
            if fields[2] != "0":
                data["unmerged_paths"].append(path)
        return data

    def worktrees(self) -> list[dict]:
        out, rc, _ = self._required("worktree", "list", "--porcelain", "-z")
        if rc:
            return []
        rows, row = [], {}
        for field in out.split("\0"):
            if not field:
                if row:
                    rows.append(row)
                    row = {}
                continue
            key, _, value = field.partition(" ")
            if key == "worktree":
                row["path"] = value
            else:
                row[key] = value or True
        if row:
            rows.append(row)
        if not rows or any(not r.get("path") for r in rows):
            self.read_errors.append("Missing or malformed worktree inventory")
        return rows

    def refs_inventory(self) -> dict[str, str]:
        out, rc, _ = self._required(
            "for-each-ref", "--format=%(refname) %(objectname)")
        refs = {}
        if not rc:
            for line in out.splitlines():
                fields = line.split()
                if len(fields) != 2 or not re.fullmatch(r"[0-9a-f]{40,64}", fields[1]):
                    self.read_errors.append("Malformed ref inventory")
                    continue
                refs[fields[0]] = fields[1]
        return refs

    def staged_blob_sizes(self, staged: list[dict]) -> dict[str, int]:
        oids = sorted({s["oid"] for s in staged
                       if s.get("x") != "D" and s.get("mode") != "160000"
                       and re.fullmatch(r"[0-9a-f]{40,64}", s.get("oid", ""))})
        if not oids:
            return {}
        out, rc, _ = self._required(
            "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)",
            input_text="\n".join(oids) + "\n")
        sizes = {}
        for line in out.splitlines() if not rc else []:
            fields = line.split()
            if len(fields) == 3 and fields[0] in oids and fields[1] == "blob" and fields[2].isdigit():
                sizes[fields[0]] = int(fields[2])
            else:
                self.read_errors.append("Staged blob metadata is missing or malformed")
        if len(sizes) != len(oids):
            self.read_errors.append("Staged blob size inventory is incomplete")
        return sizes

    def operation_markers(self) -> dict:
        names = ("index.lock", "MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD",
                 "rebase-merge", "rebase-apply", "sequencer", "BISECT_START")
        out, rc, _ = self._required("rev-parse", "--git-path", "index")
        if rc or not out.strip():
            return {"index_locked": True, "active_operations": ["unknown"]}
        index = out.rstrip("\n")
        if not os.path.isabs(index):
            index = os.path.join(self.root, index)
        gitdir = os.path.dirname(index)
        markers = {"index_locked": os.path.lexists(index + ".lock"),
                   "active_operations": [n for n in names[1:] if os.path.lexists(os.path.join(gitdir, n))],
                   "merge_parents": []}
        if "MERGE_HEAD" in markers["active_operations"]:
            try:
                path = os.path.join(gitdir, "MERGE_HEAD")
                if not stat.S_ISREG(os.lstat(path).st_mode):
                    raise ValueError("MERGE_HEAD is not a regular file")
                with open(path, "rb") as stream:
                    raw = stream.read(65537)
                parents = raw.decode("ascii").splitlines()
                if (len(raw) > 65536 or not parents
                        or any(not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", p) for p in parents)):
                    raise ValueError("Malformed MERGE_HEAD parent inventory")
                out, rc, _ = self._required(
                    "cat-file", "--batch-check=%(objectname) %(objecttype)",
                    input_text="\n".join(parents) + "\n")
                if rc or out.splitlines() != [p + " commit" for p in parents]:
                    raise ValueError("MERGE_HEAD parents are not verified commit objects")
                markers["merge_parents"] = parents
            except (OSError, UnicodeError, ValueError) as exc:
                self.read_errors.append(str(exc))
        return markers

    def ignored_entries(self) -> list[str]:
        """Ignored files, directories collapsed (node_modules/ as one entry)."""
        out, rc, _ = self._required(
            "ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z"
        )
        if rc != 0:
            return []
        return [entry for entry in out.split("\0") if entry]

    def untracked_entries(self) -> list[str]:
        """Include empty directories, which status omits but clean -d removes."""
        out, rc, _ = self._required(
            "ls-files", "--others", "--directory", "--exclude-standard", "-z")
        return [entry for entry in out.split("\0") if entry] if not rc else []

    def branches(self) -> list[dict]:
        fmt = "%(refname:short)\t%(upstream:short)\t%(upstream:track)\t%(committerdate:relative)\t%(objectname:short)\t%(contents:subject)"
        out, rc, _ = self._required("for-each-ref", f"--format={fmt}", "refs/heads")
        result = []
        if rc != 0:
            return result
        for line in out.splitlines():
            f = line.split("\t", 5)
            while len(f) < 6:
                f.append("")
            result.append({
                "name": f[0], "upstream": f[1] or None, "track": f[2] or "",
                "last_commit_rel": f[3], "oid": f[4], "subject": f[5],
            })
        return result

    def default_branch(self) -> str | None:
        out, rc, _ = self._run("symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD")
        if rc == 0 and out.strip():
            return out.strip().split("/", 1)[-1]
        names = {b["name"] for b in self.branches()}
        for cand in ("main", "master", "trunk", "develop"):
            if cand in names:
                return cand
        return None

    def merged_branches(self, base: str) -> set[str]:
        out, rc, _ = self._required("branch", "--merged", base, "--format=%(refname:short)")
        if rc != 0:
            return set()
        return {l.strip() for l in out.splitlines() if l.strip()}

    def unpushed_commits(self, has_upstream: bool) -> list[dict]:
        # No upstream tracking branch -> there is nothing to be "ahead" of, so
        # This is only a current-upstream subject preview. Without an upstream,
        # leave the preview empty; build_state separately reports publication
        # uncertainty and all-local-ref coverage. Empty preview is not proof.
        if not has_upstream:
            return []
        out, rc, _ = self._required("log", "@{upstream}..HEAD", "--pretty=%h\t%s", "-n", "50")
        if rc != 0:
            return []
        commits = []
        for line in out.splitlines():
            h, _, s = line.partition("\t")
            if h:
                commits.append({"hash": h, "subject": s})
        return commits

    def stashes(self) -> list[str]:
        out, rc, _ = self._required("stash", "list")
        if rc != 0:
            return []
        return [l for l in out.splitlines() if l.strip()]

    def last_commit(self) -> dict | None:
        out, rc, _ = self._run("log", "-1", "--pretty=%h\t%an\t%ar\t%s")
        if rc != 0 or not out.strip():
            return None
        h, an, ar, s = (out.strip().split("\t", 3) + ["", "", "", ""])[:4]
        return {"hash": h, "author": an, "when": ar, "subject": s}

    def remotes(self) -> list[str]:
        out, rc, _ = self._required("remote")
        if rc != 0:
            return []
        return [l for l in out.splitlines() if l.strip()]

    def remote_url(self, name: str = "origin") -> str | None:
        out, rc, _ = self._run("remote", "get-url", name)
        if rc == 0 and out.strip():
            return out.strip()
        return None

    def toplevel(self) -> str | None:
        """Absolute path of the repo root that actually owns self.root (walks up)."""
        out, rc, _ = self._run("rev-parse", "--show-toplevel")
        if rc == 0 and out.strip():
            return os.path.abspath(out.strip())
        return None

    # --- stash triage -------------------------------------------------------
    def _patch_reverse_applies(self, patch: str) -> bool | None:
        """True if `patch` reverse-applies cleanly (its changes are already present)."""
        try:
            r = subprocess.run(
                ["git", "-C", self.root, "apply", "--reverse", "--check", "-"],
                input=patch, capture_output=True, text=True, timeout=15,
            )
            return r.returncode == 0
        except Exception:  # noqa: BLE001
            return None

    def stash_details(self, limit: int | None = None) -> list[dict]:
        """Per-stash triage so a caller can tell dead/superseded from unmerged work.

        verdict: 'empty' (captured nothing) | 'superseded' (reverse-applies to the
        working tree) | 'unmerged' (content NOT cleanly in the working tree -
        PRESERVE before dropping) | 'unknown' (inspection failed).

        Reverse-apply proves working-tree presence, not committed recovery in HEAD.
        Untracked stash parents are included. A failed show is unknown, not empty.
        """
        if limit is None:
            limit = int(os.environ.get("GITREAL_STASH_INSPECT_LIMIT", "200"))
        out, rc, err = self._run("stash", "list", "--format=%gd%x00%gs%x00%cr")
        if rc != 0:
            return [{
                "ref": None, "message": "", "age": "", "files": None,
                "added": 0, "deleted": 0,
                "already_in_working_tree": None, "already_in_head": None,
                "presence_basis": "working_tree",
                "verdict": "unknown", "inspection_ok": False,
                "error": err.strip() or f"stash list failed (rc={rc})",
            }]
        if not out.strip():
            return []
        details = []
        for line in out.splitlines():
            if not line.strip():
                continue
            parts = line.split("\x00")
            ref = parts[0] if parts else ""
            msg = parts[1] if len(parts) > 1 else ""
            age = parts[2] if len(parts) > 2 else ""
            if not ref:
                continue
            if len(details) >= limit:
                continue
            stat_out, stat_rc, stat_err = self._run(
                "stash", "show", "--include-untracked", "--numstat", ref)
            if stat_rc != 0:
                details.append({
                    "ref": ref, "message": msg, "age": age, "files": None,
                    "added": 0, "deleted": 0,
                    "already_in_working_tree": None, "already_in_head": None,
                    "presence_basis": "working_tree",
                    "verdict": "unknown", "inspection_ok": False,
                    "error": stat_err.strip() or f"stash show failed (rc={stat_rc})",
                })
                continue
            files = added = deleted = 0
            for sline in stat_out.splitlines():
                cols = sline.split("\t")
                if len(cols) >= 3:
                    files += 1
                    if cols[0].isdigit():
                        added += int(cols[0])
                    if cols[1].isdigit():
                        deleted += int(cols[1])
            already = None
            inspection_ok = True
            if files > 0:
                patch, pc, perr = self._run(
                    "stash", "show", "--include-untracked", "-p", ref)
                if pc != 0:
                    details.append({
                        "ref": ref, "message": msg, "age": age, "files": files,
                        "added": added, "deleted": deleted,
                        "already_in_working_tree": None, "already_in_head": None,
                        "presence_basis": "working_tree",
                        "verdict": "unknown", "inspection_ok": False,
                        "error": perr.strip() or f"stash show -p failed (rc={pc})",
                    })
                    continue
                if patch.strip():
                    already = self._patch_reverse_applies(patch)
                    if already is None:
                        inspection_ok = False
            if files == 0:
                verdict = "empty"
            elif already is True:
                verdict = "superseded"
            elif already is False:
                verdict = "unmerged"
            else:
                verdict = "unknown"
            details.append({
                "ref": ref, "message": msg, "age": age, "files": files,
                "added": added, "deleted": deleted,
                "already_in_working_tree": already,
                "already_in_head": None,
                "presence_basis": "working_tree",
                "verdict": verdict,
                "inspection_ok": inspection_ok and verdict != "unknown",
            })
        return details

    def object_storage(self) -> dict:
        """Cheap metadata inventory, never a reachability or content scan."""
        data = {
            "complete": False, "errors": [], "loose_count": None,
            "loose_bytes": None, "packed_count": None, "pack_count": None,
            "packed_kib": None, "pack_bytes": None, "garbage_count": None,
            "garbage_bytes": None,
            "effective_loose_threshold": None, "fanout_threshold": None,
            "max_fanout": None, "sampled_fanout": "17", "sampled_fanout_count": None,
            "gc_log": {"status": "unknown"},
            "pending_maintenance": {"status": "unknown"},
            "maintenance_required": None, "inventory_fingerprint": None,
            "config_fingerprint": None, "unsupported_reasons": [],
        }
        errors = data["errors"]
        try:
            raw, rc, _ = self._run("count-objects", "-v")
            if rc:
                raise ValueError("git count-objects inventory failed")
            counts = {}
            for line in raw.splitlines():
                key, sep, value = line.partition(":")
                if not sep or key in counts:
                    raise ValueError("Malformed object count inventory")
                if key == "alternate":
                    data["unsupported_reasons"].append("alternate object store")
                    continue
                if key not in ("count", "size", "in-pack", "packs", "size-pack", "prune-packable", "garbage", "size-garbage"):
                    raise ValueError("Unknown object count inventory field")
                if not value.strip().isdigit():
                    raise ValueError("Malformed object count inventory value")
                counts[key] = int(value.strip())
            if set(counts) != {"count", "size", "in-pack", "packs", "size-pack", "prune-packable", "garbage", "size-garbage"}:
                raise ValueError("Incomplete object count inventory")
            data.update(packed_count=counts["in-pack"], pack_count=counts["packs"],
                        packed_kib=counts["size-pack"], pack_bytes=counts["size-pack"] * 1024,
                        garbage_count=counts["garbage"], garbage_bytes=counts["size-garbage"] * 1024)

            cfg, rc, _ = self._run("config", "--null", "--list")
            if rc or (cfg and not cfg.endswith("\0")):
                raise ValueError("Git configuration inventory failed")
            data["config_fingerprint"] = hashlib.sha256(
                cfg.encode("utf-8", "surrogateescape")).hexdigest()
            config = {}
            for record in cfg.split("\0"):
                if record:
                    key, sep, value = record.partition("\n")
                    if not sep or not key:
                        raise ValueError("Malformed Git configuration inventory")
                    config[key.lower()] = value
            for key in config:
                if (key.startswith("extensions.") and key != "extensions.objectformat"
                        or key.endswith(".promisor") or key.startswith("repack.")):
                    data["unsupported_reasons"].append("unsupported object-storage Git configuration")
                    break
            def numeric(name, default):
                value = config.get(name, str(default))
                if not re.fullmatch(r"\d+", value):
                    raise ValueError("Malformed object-maintenance threshold configuration")
                return int(value)
            auto = numeric("gc.auto", 6700)
            limit = numeric("gc.autopacklimit", 50)
            data["effective_loose_threshold"] = auto
            data["effective_pack_threshold"] = limit
            # Git samples fanout 17, not the fullest of all 256 buckets.
            # Disabled auto-GC does not erase a pre-existing object backlog.
            trigger = auto or 6700
            data["fanout_threshold"] = (trigger + 255) // 256

            def git_path(name):
                value, code, _ = self._run("rev-parse", "--git-path", name)
                if code or not value.strip():
                    raise ValueError("Git object-storage path could not be resolved")
                path = value.rstrip("\n")
                return os.path.abspath(path if os.path.isabs(path) else os.path.join(self.root, path))

            objects = git_path("objects")
            if not stat.S_ISDIR(os.lstat(objects).st_mode):
                raise ValueError("Object store is not an ordinary directory")
            inventory = hashlib.sha256()
            loose_count = loose_bytes = 0
            fanouts = {}
            oid_tail = 38 if config.get("extensions.objectformat", "sha1") == "sha1" else 62
            if config.get("extensions.objectformat", "sha1") not in ("sha1", "sha256"):
                raise ValueError("Unsupported Git object format")
            def walk_error(exc):
                raise exc

            for directory, dirs, files in os.walk(objects, followlinks=False, onerror=walk_error):
                dirs.sort()
                for name in sorted(dirs + files):
                    path = os.path.join(directory, name)
                    info = os.lstat(path)
                    if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                        raise ValueError("Object store contains an unsafe file type")
                    relative = os.path.relpath(path, objects).replace(os.sep, "/")
                    inventory.update(f"{relative}\0{info.st_mode}\0{info.st_size}\0{info.st_mtime_ns}\0".encode("utf-8", "surrogateescape"))
                    parts = relative.split("/")
                    if (stat.S_ISREG(info.st_mode) and len(parts) == 2
                            and re.fullmatch(r"[0-9a-f]{2}", parts[0])
                            and re.fullmatch(r"[0-9a-f]{" + str(oid_tail) + r"}", parts[1])):
                        loose_count += 1
                        loose_bytes += info.st_size
                        fanouts[parts[0]] = fanouts.get(parts[0], 0) + 1
                    if relative == "info/alternates":
                        data["unsupported_reasons"].append("alternate object store")
                    if relative.startswith("pack/") and relative.endswith((".promisor", ".keep")):
                        data["unsupported_reasons"].append("promisor or protected pack")
            if loose_count != counts["count"]:
                raise ValueError("Git and filesystem loose-object inventories disagree")
            data.update(loose_count=loose_count, loose_bytes=loose_bytes,
                        max_fanout=max(fanouts.values(), default=0),
                        sampled_fanout_count=fanouts.get("17", 0),
                        inventory_fingerprint=inventory.hexdigest())

            log = git_path("gc.log")
            if os.path.lexists(log):
                info = os.lstat(log)
                if not stat.S_ISREG(info.st_mode) or info.st_size > 8192:
                    raise ValueError("gc.log is unsafe or exceeds bounded inspection size")
                with open(log, "rb") as stream:
                    content = stream.read(8193)
                if len(content) != info.st_size:
                    raise ValueError("gc.log changed during inspection")
                warning = b"warning: There are too many unreachable loose objects; run 'git prune' to remove them."
                recognized = content.strip() == warning
                data["gc_log"] = {
                    "status": "loose_unreachable_warning" if recognized else "other",
                    "size_bytes": info.st_size, "sha256": hashlib.sha256(content).hexdigest(),
                    "mtime_ns": info.st_mtime_ns,
                }
            else:
                data["gc_log"] = {"status": "absent"}
            pending = git_path("dmr-object-maintenance.pending")
            if os.path.lexists(pending):
                info = os.lstat(pending)
                if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
                    raise ValueError("Maintenance recovery marker is unsafe or oversized")
                with open(pending, "rb") as stream:
                    content = stream.read(4097)
                if len(content) != info.st_size:
                    raise ValueError("Maintenance recovery marker changed during inspection")
                data["pending_maintenance"] = {
                    "status": "present", "size_bytes": info.st_size,
                    "sha256": hashlib.sha256(content).hexdigest(), "mtime_ns": info.st_mtime_ns,
                }
            else:
                data["pending_maintenance"] = {"status": "absent"}
            data["maintenance_required"] = bool(
                loose_count >= trigger or data["sampled_fanout_count"] > data["fanout_threshold"]
                or counts["packs"] > limit > 0 or counts["garbage"] > 0
                or data["gc_log"]["status"] != "absent"
                or data["pending_maintenance"]["status"] != "absent"
            )
            data["complete"] = True
        except (OSError, ValueError) as exc:
            errors.append(str(exc))
        data["unsupported_reasons"] = sorted(set(data["unsupported_reasons"]))
        return data

    # --- push weight --------------------------------------------------------
    def pack_size_bytes(self) -> int:
        """Approx on-disk object size (loose + packed), in bytes."""
        out, rc, _ = self._run("count-objects", "-v")
        if rc != 0:
            return 0
        total = 0
        for line in out.splitlines():
            if line.startswith(("size:", "size-pack:")):
                try:
                    total += int(line.split(":", 1)[1].strip()) * 1024  # KiB -> bytes
                except (ValueError, IndexError):
                    pass
        return total

    def largest_tracked_blobs(self, n: int = 5) -> list[dict]:
        """Largest files tracked in HEAD - the drivers of clone/push weight."""
        out, rc, _ = self._run("ls-tree", "-r", "-l", "HEAD")
        if rc != 0:
            return []
        rows = []
        for line in out.splitlines():
            head, _, path = line.partition("\t")
            if not path:
                continue
            meta = head.split()
            if len(meta) < 4 or meta[1] != "blob" or not meta[3].isdigit():
                continue
            rows.append({"path": path, "size": int(meta[3])})
        rows.sort(key=lambda r: r["size"], reverse=True)
        return rows[:n]


# ----------------------------------------------------------------------------
# working-tree classification
# ----------------------------------------------------------------------------
def classify_untracked(root: str, path: str) -> str:
    """Never infer recoverability from a filename, extension, or directory name.

    A binary, backup, log, cache, or build directory can contain the only copy
    of human work. Artifact hints remain available separately for commit review.
    """
    return "new"


def artifact_hint(path: str) -> bool:
    """A name-based review hint, deliberately NOT deletion evidence."""
    base = path.rstrip("/").split("/")[-1]
    if any(part in JUNK_DIR_NAMES for part in path.split("/")):
        return True
    return any(r.match(base) for r in JUNK_FILE_RULES)


def mark_established_paths(repo, files: list) -> None:
    """Mark commit candidates that follow what HEAD already tracks.

    An artifact-like path is established when HEAD already tracks that path, files
    under the same artifact-named directory (e.g. a vendored ``vendor/`` tree), or a
    same-rule file in the same directory. A large file is established when its HEAD
    version was already large, so the change is stored as a delta. HEAD, not the
    index, is the reference: freshly staged files never establish themselves.
    """
    if any(f.get("artifact_candidate") for f in files):
        out, rc, _ = repo._run("ls-tree", "-r", "-z", "--name-only", "HEAD", timeout=120)
        if rc == 0:
            committed, dirs, names = set(), set(), {}
            for path in out.split("\0"):
                if not path:
                    continue
                committed.add(path)
                parts = path.split("/")
                for i in range(1, len(parts)):
                    dirs.add("/".join(parts[:i]) + "/")
                names.setdefault("/".join(parts[:-1]), []).append(parts[-1])
            for f in files:
                if not f.get("artifact_candidate") or f.get("category") == "junk":
                    continue
                path = f["path"].rstrip("/")
                parts = path.split("/")
                trigger = next((i for i, part in enumerate(parts[:-1]) if part in JUNK_DIR_NAMES), None)
                if path in committed:
                    f["artifact_established"] = True
                elif trigger is not None:
                    f["artifact_established"] = "/".join(parts[:trigger + 1]) + "/" in dirs
                else:
                    rule = next((r for r in JUNK_FILE_RULES if r.match(parts[-1])), None)
                    f["artifact_established"] = bool(rule) and any(
                        rule.match(name) for name in names.get("/".join(parts[:-1]), []))
    for f in files:
        if f.get("large") and not f.get("huge") and not f.get("untracked") and f.get("x") != "A":
            out, rc, _ = repo._run("cat-file", "-s", "HEAD:" + f["path"].rstrip("/"))
            f["large_already_tracked"] = (rc == 0 and out.strip().isdigit()
                                          and int(out.strip()) >= LARGE_FILE_WARN)


def protected_commit_path(path: str) -> bool:
    """Filename-only exclusion; this is not a repository-content secret scan."""
    base = path.rsplit("/", 1)[-1].lower()
    return (
        (base == ".env" or base.startswith(".env.")) and base != ".env.example"
        or base in {"id_rsa", "id_ed25519", "gcp-service-account.json"}
        or base.endswith((".key", ".pem", ".p12", ".pfx", ".db", ".sqlite", ".sqlite3"))
    )




# ----------------------------------------------------------------------------
# scoring
# ----------------------------------------------------------------------------
def verdict_band(score: int, positive_is_good=True) -> str:
    if score >= 80:
        return "GO"
    if score >= 40:
        return "CAUTION"
    return "STOP"


def summarize_stashes(stash_lines: list[str], details: list[dict]) -> dict:
    """Combine stash list + inspected detail. Truncation and unknown are first-class."""
    list_failed = any(
        d.get("ref") is None and d.get("inspection_ok") is False for d in details
    )
    if list_failed and not stash_lines:
        err = next((d.get("error") for d in details if d.get("error")), "stash list failed")
        return {
            "count": None, "inspected": 0, "uninspected": None,
            "empty": 0, "superseded": 0, "unmerged": 0, "unknown": 1,
            "inspection_complete": False, "error": err,
        }
    inspected = [d for d in details if d.get("ref")]
    unknown = sum(1 for d in inspected if d.get("verdict") == "unknown")
    uninspected = max(0, len(stash_lines) - len(inspected))
    complete = (
        uninspected == 0
        and unknown == 0
        and all(d.get("inspection_ok", True) for d in inspected)
    )
    return {
        "count": len(stash_lines),
        "inspected": len(inspected),
        "uninspected": uninspected,
        "empty": sum(1 for d in inspected if d.get("verdict") == "empty"),
        "superseded": sum(1 for d in inspected if d.get("verdict") == "superseded"),
        "unmerged": sum(1 for d in inspected if d.get("verdict") == "unmerged"),
        "unknown": unknown,
        "inspection_complete": complete,
    }


def resolved_merge_commit(state: dict) -> bool:
    """Only a verified, fully resolved normal merge can finish via plain commit."""
    return bool(
        state.get("active_operations") == ["MERGE_HEAD"]
        and state.get("merge_parents")
        and not state.get("index_locked")
        and state.get("status", {}).get("conflicts") == []
        and state.get("index_inventory", {}).get("unmerged_paths") == []
    )


def compute_scores(state: dict) -> dict:
    st = state.get("status") or {}
    files = state.get("files") or []
    read_failed = (
        st.get("ok") is not True
        or st.get("complete") is not True
        or state.get("read_complete") is False
    )
    if read_failed:
        reason = st.get("error") or "; ".join(state.get("read_errors") or []) or "Git read failed."
        msg = f"Git status was not read successfully: {reason}"
        return {
            "safe_commit": 0, "safe_commit_band": "STOP",
            "safe_commit_label": "GIT READ FAILED",
            "safe_commit_reasons": [f"{msg} Not a verified clean tree."],
            "safe_delete": 0, "safe_delete_band": "STOP",
            "safe_delete_label": "GIT READ FAILED",
            "safe_delete_reasons": [f"{msg} Discard is not approved."],
            "unpreserved_work": ["unknown"],
        }

    n_staged = len(st.get("staged") or [])
    n_modified = len(st.get("modified") or [])
    n_conflicts = len(st.get("conflicts") or [])
    untracked_new = [f for f in files if f.get("untracked") or f.get("category") in ("new", "junk")]
    n_untracked = max(len(untracked_new), len(st.get("untracked") or []))
    commit_files = [f for f in files if f.get("staged")] if n_staged else files
    recorded_files = [f for f in commit_files if f.get("x") != "D"]
    # Paths that follow what HEAD already tracks are review notes, not blocks
    # (Dan 2026-10-09: GIT_REAL must not block agents on legitimate work).
    untracked_junk = [f for f in recorded_files if (f.get("artifact_candidate") or f.get("category") == "junk")
                      and not f.get("artifact_established")]
    established_artifacts = [f for f in recorded_files if f.get("artifact_established")]
    large_files = [f for f in recorded_files if f.get("large") and not f.get("large_already_tracked")]
    changed_large = [f for f in recorded_files if f.get("large") and f.get("large_already_tracked")]
    protected = [f for f in recorded_files if protected_commit_path(f["path"])]
    has_dirty = bool(n_staged or n_modified or n_conflicts or n_untracked)
    unpushed = state.get("unpushed") or []
    unpreserved = []
    if n_conflicts:
        unpreserved.append("conflicts")
    if n_staged:
        unpreserved.append("staged")
    if n_modified:
        unpreserved.append("modified")
    if n_untracked:
        unpreserved.append("untracked_new")

    # ---- Safe Commit % : how clean/safe is committing right now? ------------
    sc = 100
    sc_reasons = []
    if not has_dirty:
        sc_reasons.append("Working tree is clean - nothing to commit.")
    elif has_dirty:
        if n_conflicts:
            sc = 0
            sc_reasons.append(f"{n_conflicts} unmerged/conflicted path(s).")
        if untracked_junk:
            sc -= 25
            _jn = ", ".join(f["path"] for f in untracked_junk[:3])
            _jm = f" +{len(untracked_junk) - 3} more" if len(untracked_junk) > 3 else ""
            sc_reasons.append(f"{len(untracked_junk)} possible artifact path(s), review origin before committing: {_jn}{_jm}.")
        if large_files:
            sc = min(sc - 21, 79)
            _lg = ", ".join(f"{f['path']} ({human_size(f.get('size', 0))})" for f in large_files[:3])
            _lm = f" +{len(large_files) - 3} more" if len(large_files) > 3 else ""
            sc_reasons.append(f"{len(large_files)} large file(s) - will bloat history: {_lg}{_lm}.")
        if established_artifacts:
            _en = ", ".join(f["path"] for f in established_artifacts[:3])
            _em = f" +{len(established_artifacts) - 3} more" if len(established_artifacts) > 3 else ""
            sc_reasons.append(f"Review note: {len(established_artifacts)} artifact-like path(s) follow a location "
                              f"HEAD already tracks: {_en}{_em}.")
        if changed_large:
            _cl = ", ".join(f"{f['path']} ({human_size(f.get('size', 0))})" for f in changed_large[:3])
            sc_reasons.append(f"Review note: {len(changed_large)} file(s) already large in HEAD changed; "
                              f"Git stores the change as a delta: {_cl}.")
        if (n_staged + n_modified + len(untracked_new)) > 200:
            sc -= 15
            sc_reasons.append("Very large changeset (>200 files) - possible accidental `git add -A`.")
        if sc == 100:
            sc_reasons.append("No detected structural commit hazards; review only the intended staged paths.")
    if protected:
        sc = 0
        sc_reasons.append("Protected local-data/key filename(s) must not be committed: "
                          + ", ".join(repr(f["path"]) for f in protected[:5]))
    if any(f.get("huge") for f in recorded_files):
        sc = min(sc, 39)
    if state.get("index_locked") or (state.get("active_operations") and not resolved_merge_commit(state)):
        sc = 0
        sc_reasons.append("Index lock or Git operation in progress; resolve its intended workflow first.")
    if st.get("detached"):
        sc = 0
        sc_reasons.append("Detached HEAD has no durable branch destination; retain work on a named branch first.")
    sc = max(0, min(100, sc))

    # Discard summary only. Exact operation verdicts below supply safety evidence.
    sd = 100
    sd_reasons = []
    if not has_dirty:
        sd = 100
        sd_reasons.append("No ordinary working-tree changes detected; not blanket reset/clean/stash approval.")
    else:
        if n_untracked:
            # Never-committed work is unrecoverable, so this must land BELOW the
            # CAUTION/STOP boundary (40), not exactly on it. A flat -60 from 100
            # scored 40 and read as OK_TO_DISCARD to the MCP client.
            sd = min(sd - 60, 39)
            sd_reasons.append(f"{n_untracked} untracked path(s) lack a proven durable copy; cleaning may permanently lose work.")
        if n_conflicts:
            sd = min(sd, 39)
            sd_reasons.append(
                f"{n_conflicts} unmerged/conflicted path(s) would be destroyed by "
                f"checkout/reset; discard is not approved.")
        if n_staged:
            sd = min(sd - 30, 39)
            sd_reasons.append(
                f"{n_staged} staged change(s) are unsaved index work and would be "
                f"discarded; checkout/reset/clean are not authorized.")
        if n_modified:
            sd = min(sd - 30, 39)
            sd_reasons.append(f"{n_modified} tracked file(s) have uncommitted edits that would be discarded.")
    pending = max(len(unpushed), st.get("ahead") or 0)
    if pending:
        sd = min(sd, 39)
        unpreserved.append("unpushed_commits")
        sd_reasons.append(f"{pending} commit(s) ahead of the local upstream ref; resetting to it removes branch work.")
    if state.get("local_commits_without_upstream"):
        sd = min(sd, 39)
        sd_reasons.append("Local commits have no upstream recovery evidence; zero ahead does not mean published.")
    if state.get("ignored_count"):
        sd = min(sd, 39)
        unpreserved.append("ignored_paths")
        sd_reasons.append(f"{state['ignored_count']} ignored path(s) are outside ordinary status and vulnerable to ignored-file cleaning.")
    if state.get("index_inventory", {}).get("hidden_paths"):
        sd = 0
        unpreserved.append("status_hidden_paths")
        sd_reasons.append("Index flags can hide working-tree edits; tracked discard is not proven safe.")
    if state.get("side_branches") or st.get("detached"):
        sd = min(sd, 39)
        sd_reasons.append("Side-branch or detached work requires target-specific preservation evidence.")
    if state.get("index_locked") or state.get("active_operations"):
        sd = 0
        sd_reasons.append("Index lock or Git operation in progress; preserve its state.")

    # stash triage (#2) - stashes survive `git clean`/`checkout`, but they hide work
    summ = state.get("stash_summary", {})
    inspect_incomplete = bool(
        summ.get("unknown")
        or summ.get("uninspected")
        or summ.get("error")
        or summ.get("inspection_complete") is False
    )
    if summ.get("error") or summ.get("count"):
        sd = min(sd, 39)
        unpreserved.append("stashes")
        parts = []
        if summ.get("unmerged"):
            parts.append(f"{summ['unmerged']} unmerged (PRESERVE before dropping)")
        if summ.get("superseded"):
            parts.append(f"{summ['superseded']} superseded (already in the working tree)")
        if summ.get("empty"):
            parts.append(f"{summ['empty']} empty")
        if summ.get("unknown"):
            parts.append(f"{summ['unknown']} unknown (inspection failed)")
        if summ.get("uninspected"):
            parts.append(f"{summ['uninspected']} uninspected")
        n_txt = "?" if summ.get("count") is None else str(summ.get("count"))
        detail = "; ".join(parts) if parts else n_txt
        if summ.get("unmerged"):
            sd_reasons.append(
                f"{n_txt} stash(es) [{detail}] - {summ['unmerged']} hold work not "
                f"cleanly in the working tree; archive/apply before clearing stashes.")
        elif inspect_incomplete:
            sd_reasons.append(
                f"{n_txt} stash(es) [{detail}] - inspection is incomplete or unknown; "
                f"do not drop these stashes.")
        else:
            sd_reasons.append(
                f"{n_txt} stash(es) [{detail}] - working-tree presence is not durable recovery; "
                "retain until the selected stash has committed-copy evidence.")
    elif inspect_incomplete:
        sd = 0
        sd_reasons.append("Stash inventory is incomplete; preserve it.")
    # Backward-safe migration: old clients that only understand score >= 80 or
    # band GO must never interpret a generic snapshot as blanket deletion permission.
    sd = max(0, min(79, sd))
    sd_reasons.append("Choose an exact operation; this legacy summary never authorizes discard.")

    # topology (#3) - loud, unmissable warning if this path is not its own repo
    topo = state.get("topology", {})
    if topo.get("kind") == "tracked_inside_parent":
        sc = sd = 0
        warn = "[TOPOLOGY] " + topo.get(
            "note", "This path is tracked inside a parent repo; results reflect the parent.")
        sc_reasons.insert(0, warn)
        sd_reasons.insert(0, warn)

    return {
        "safe_commit": sc,
        "safe_commit_band": verdict_band(sc),
        "safe_commit_label": ("INDEX CHECKS PASS" if n_staged else "NOTHING STAGED - PREVIEW") if sc >= 80 else ("REVIEW BEFORE COMMIT" if sc >= 40 else "DO NOT COMMIT"),
        "safe_commit_reasons": sc_reasons,
        "safe_commit_scope": "index" if n_staged else "working_tree_preview",
        "safe_delete": sd,
        "safe_delete_band": verdict_band(sd),
        "safe_delete_label": "EXPLICIT OPERATION REQUIRED" if sd >= 40 else "DO NOT DISCARD - PRESERVE WORK",
        "safe_delete_reasons": sd_reasons,
        "safe_delete_scope": "summary_only",
        "safe_delete_authorizes_action": False,
        "unpreserved_work": unpreserved,
    }


# ----------------------------------------------------------------------------
# operation-specific safety evidence (read-only; never performs the operation)
# ----------------------------------------------------------------------------
ACTION_SCOPES = {
    "maintain_objects": "preservation-only git repack -a -d --cruft without expiration; no unreachable-object pruning or reflog expiry",
    "commit_index": "git commit of the inspected index (not -a, path arguments, or amend)",
    "stage_paths": "read-only expansion and safety assessment of requested staging pathspecs",
    "discard_tracked": "git restore --worktree -- . (from the index; no submodule recursion)",
    "clean_untracked": "git clean -fd (not -x, -X, or a second -f)",
    "clean_ignored": "git clean -fdx (not a second -f)",
    "reset_hard": "git reset --hard <resolved target OID> (no submodule recursion)",
    "drop_stash": "git stash drop <selected stash ref> with committed-copy proof",
    "create_branch": "nonforcing git switch --no-track -c <new local branch> <inspected HEAD OID>; no tree change",
    "switch_branch": "git switch --no-guess --no-overwrite-ignore --no-recurse-submodules <existing local branch>",
    "fast_forward": "on main, git -c submodule.recurse=false merge --ff-only --no-autostash --no-overwrite-ignore <resolved branch OID>",
    "delete_branch": "on main, git branch -d -- <non-current integrated local branch>; never -D",
    "push_origin": "git push --no-force --no-follow-tags --recurse-submodules=no origin <inspected main OID>:refs/heads/main",
}
REF_ACTIONS = ("create_branch", "switch_branch", "fast_forward", "delete_branch", "push_origin")
REF_MAX_WORKTREE_ENTRIES = 50_000
STATUS_FILTER_MAX_PATHS = 200_000
STATUS_FILTER_BATCH_SIZE = 4096
REF_MAX_AGE_SECONDS = 60


def _maintenance_hazards(state: dict) -> list[str]:
    storage = state.get("object_storage") or {}
    reasons = []
    if (storage.get("complete") is not True or storage.get("errors")
            or not isinstance(storage.get("loose_count"), int)
            or not isinstance(storage.get("loose_bytes"), int)
            or storage.get("maintenance_required") is not True
            or not storage.get("inventory_fingerprint") or not storage.get("config_fingerprint")
            or not state.get("refs_fingerprint")):
        reasons.append("Complete object-storage evidence and a real maintenance backlog are required.")
    if storage.get("unsupported_reasons"):
        reasons.append("Alternate, promisor, protected-pack, or unsupported Git configuration needs a separate preservation plan.")
    if storage.get("garbage_count"):
        reasons.append("Git reports garbage files; repacking cannot safely account for them.")
    if (storage.get("gc_log") or {}).get("status") not in ("absent", "loose_unreachable_warning"):
        reasons.append("Unrecognized gc.log evidence needs inspection; do not silence it.")
    if (storage.get("pending_maintenance") or {}).get("status") != "absent":
        reasons.append("An earlier maintenance attempt has an unresolved private recovery receipt.")
    if state.get("extra_worktree_count") != 0:
        reasons.append("Shared worktree object stores require separate coordination.")
    gitdir = os.path.join(state.get("root") or "", ".git")
    try:
        if not stat.S_ISDIR(os.lstat(gitdir).st_mode):
            raise OSError("linked, bare, or symlinked Git directory")
        markers = ("HEAD.lock", "packed-refs.lock", "shallow.lock", "config.lock",
                   "gc.pid", "objects/info/alternates.lock", "objects/pack/multi-pack-index.lock")
        if any(os.path.lexists(os.path.join(gitdir, name)) for name in markers):
            reasons.append("A Git writer or maintenance lock is present.")
        def walk_error(exc):
            raise exc
        for folder in ("refs", "objects/pack", "objects"):
            location = os.path.join(gitdir, folder)
            if os.path.isdir(location):
                for directory, dirs, files in os.walk(location, onerror=walk_error):
                    if (any(name.endswith(".lock") for name in dirs + files)
                            or (folder == "objects" and directory == location
                                and any(name.startswith("tmp_obj") for name in files))):
                        reasons.append("A Git ref or object writer lock is present.")
                        break
    except OSError:
        reasons.append("The Git directory or writer-lock inventory is unsafe or unreadable.")
    return reasons


def _metadata_digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode()).hexdigest()


def _ref_read(repo: GitRepo, *args, **kwargs) -> str:
    out, rc, err = repo._run(*args, **kwargs)
    # Warnings such as an ignored broken ref are incomplete evidence, even at rc=0.
    # Do not relay stderr: Git configuration errors can contain remote credentials.
    if rc or err:
        raise ValueError(f"Git {args[0]} operation evidence failed or was incomplete.")
    return out


def _attribute_sources_fingerprint(repo: GitRepo) -> str:
    if any(os.environ.get(key) for key in ("GIT_ATTR_NOSYSTEM", "GIT_ATTR_SOURCE")):
        raise ValueError("Overridden attribute-source environments are not assessed.")
    paths = [_ref_read(repo, "rev-parse", "--path-format=absolute", "--git-path", "info/attributes").rstrip("\n")]
    for name in ("GIT_ATTR_SYSTEM", "GIT_ATTR_GLOBAL"):
        paths.append(_ref_read(repo, "var", name).rstrip("\n"))
    inventory = {}
    for value in paths:
        if not value:
            continue
        path = os.path.abspath(os.path.join(repo.root, value))
        if path != os.path.realpath(path):
            raise ValueError("Symlinked external attribute metadata is not assessed.")
        if not os.path.lexists(path):
            inventory[path] = "absent"
            continue
        info = os.lstat(path)
        if path == os.devnull:
            inventory[path] = "null device"
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_size > 16_000_000:
            raise ValueError("External attribute metadata is unsafe or exceeds the bounded inventory.")
        with open(path, "rb") as stream:
            raw = stream.read(info.st_size + 1)
        after = os.lstat(path)
        if len(raw) != info.st_size or any(getattr(after, key) != getattr(info, key) for key in (
                "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns", "st_dev", "st_ino")):
            raise ValueError("External attribute metadata changed during inspection.")
        inventory[path] = hashlib.sha256(raw).hexdigest()
    return _metadata_digest(inventory)


# The standard Git LFS driver exactly as `git lfs install` configures it. Only a
# driver whose every configured command matches this definition is trusted; any
# other driver, or an altered LFS command in any config scope, stays refused.
TRUSTED_FILTER_DRIVERS = {
    "lfs": {"clean": "git-lfs clean -- %f", "smudge": "git-lfs smudge -- %f",
            "process": "git-lfs filter-process"},
}


def _trusted_filter_drivers(config: str) -> set[str]:
    """Driver names from NUL-delimited `git config --list` output that are trusted."""
    commands: dict[str, list[tuple[str, str]]] = {}
    for record in config.split("\0"):
        key, separator, value = record.partition("\n")
        if not separator or not key.startswith("filter."):
            continue
        name, _, field = key[7:].rpartition(".")
        if field in ("clean", "smudge", "process"):
            commands.setdefault(name, []).append((field, value))
    return {name for name, configured in commands.items()
            if name in TRUSTED_FILTER_DRIVERS
            and all(value == TRUSTED_FILTER_DRIVERS[name][field] for field, value in configured)}


def _checkout_filter_evidence(repo: GitRepo, paths: list[str], sources: list[str],
                              trusted: frozenset[str] | set[str] = frozenset()) -> tuple[str, bool]:
    """Git attribute metadata only. Never invoke a clean/smudge/process driver.

    The boolean is true when every path is unfiltered or uses a trusted driver.
    """
    fingerprints, inactive = [], True
    for source in [None, *dict.fromkeys(sources)]:
        args = ["check-attr", "-z", "--stdin", "filter"]
        if source is not None:
            args.insert(1, "--source=" + source)
        raw = _ref_read(repo, *args, input_text="\0".join(paths) + ("\0" if paths else ""))
        fields = raw.split("\0")
        if not fields or fields[-1] != "" or len(fields) != 3 * len(paths) + 1:
            raise ValueError("Effective checkout attribute evidence is incomplete.")
        for n, path in enumerate(paths):
            row = fields[n * 3:n * 3 + 3]
            if row[:2] != [path, "filter"]:
                raise ValueError("Effective checkout attribute metadata is ambiguous.")
            inactive = inactive and (row[2] in ("unspecified", "unset") or row[2] in trusted)
        fingerprints.append(hashlib.sha256(raw.encode("utf-8", "surrogateescape")).hexdigest())
    return _metadata_digest(fingerprints), inactive


def _status_filter_preflight(repo: GitRepo, pathspecs: list[str] | None = None,
                             visited: set[str] | None = None) -> None:
    """Refuse executable clean/process filters before status or a staging preview.

    An alternate object store does not sandbox a filter's filesystem/network I/O.
    Check effective attributes without running a driver. Status also visits
    populated submodules, so inspect their own configuration recursively.
    """
    visited = set() if visited is None else visited
    root = os.path.realpath(repo.root)
    if root in visited or len(visited) >= 128:
        raise ValueError("Recursive filter metadata exceeds the bounded inventory.")
    visited.add(root)
    _readonly_index_admission(repo)
    config = _ref_read(repo, "config", "--null", "--list")
    if config and not config.endswith("\0"):
        raise ValueError("Filter configuration metadata is incomplete.")
    drivers = set()
    for record in config.split("\0"):
        if not record:
            continue
        key, separator, value = record.partition("\n")
        if not separator:
            raise ValueError("Filter configuration metadata is malformed.")
        if key.startswith("filter.") and key.rsplit(".", 1)[-1] in ("clean", "process") and value:
            drivers.add(key[7:].rsplit(".", 1)[0])
    raw = _ref_read(repo, "ls-files", "--stage", "-z")
    if raw and not raw.endswith("\0"):
        raise ValueError("Filter index metadata is incomplete.")
    paths, submodules = set(), set()
    for entry in raw.split("\0"):
        if not entry:
            continue
        metadata, separator, path = entry.partition("\t")
        if not separator or len(metadata.split()) != 3:
            raise ValueError("Filter index metadata is malformed.")
        paths.add(path)
        if metadata.split()[0] == "160000":
            submodules.add(path)
    if pathspecs is not None:
        candidates = _ref_read(repo, "ls-files", "--cached", "--others", "--exclude-standard",
                               "-z", "--", *pathspecs)
        if candidates and not candidates.endswith("\0"):
            raise ValueError("Staging filter candidate metadata is incomplete.")
        paths.update(path for path in candidates.split("\0") if path)
    if drivers & {"unset", "unspecified"}:
        raise ValueError("Reserved filter names make read-only attribute evidence ambiguous.")
    # The standard Git LFS driver is trusted; every other active driver is refused.
    drivers -= _trusted_filter_drivers(config)
    if drivers:
        if len(paths) > STATUS_FILTER_MAX_PATHS:
            raise ValueError("Filter paths exceed the bounded inventory.")
        ordered = sorted(paths)
        # Ordinary status only needs filter metadata, not the richer bounded
        # tree/collision inventory required by reference-changing operations.
        # Cover every path in bounded requests; never sample or skip the tail.
        for offset in range(0, len(ordered), STATUS_FILTER_BATCH_SIZE):
            batch = ordered[offset:offset + STATUS_FILTER_BATCH_SIZE]
            attributes = _ref_read(repo, "check-attr", "-z", "--stdin", "filter",
                                   input_text="\0".join(batch) + "\0")
            fields = attributes.split("\0")
            if len(fields) != len(batch) * 3 + 1 or fields[-1] != "":
                raise ValueError("Effective filter metadata is incomplete.")
            for n, path in enumerate(batch):
                row = fields[n * 3:n * 3 + 3]
                if row[:2] != [path, "filter"]:
                    raise ValueError("Effective filter metadata is ambiguous.")
                if row[2] in drivers:
                    raise ValueError("Active clean/process filters are outside read-only inspection; no driver was invoked.")
    for path in submodules:
        child = os.path.join(root, path)
        if os.path.lexists(os.path.join(child, ".git")):
            _status_filter_preflight(GitRepo(child), visited=visited)


def _ref_inspection_preflight(repo: GitRepo) -> dict:
    # Status can invoke clean/process filters on dirty tracked files. Ref-operation
    # inspections refuse active filters before that read, not after a driver ran.
    attributes = _attribute_sources_fingerprint(repo)
    cfg = _ref_read(repo, "config", "--null", "--list")
    if cfg and not cfg.endswith("\0"):
        raise ValueError("Preflight configuration metadata is incomplete.")
    for record in cfg.split("\0"):
        if record:
            key, sep, _ = record.partition("\n")
            if not sep or not key or key.lower().endswith(".promisor"):
                raise ValueError("Partial/unknown inspection metadata is not assessed.")
            if key.lower().startswith(("filter.unset.", "filter.unspecified.")):
                raise ValueError("Reserved attribute-state driver names make inactive-filter evidence ambiguous.")
    head = _ref_read(repo, "rev-parse", "--verify", "HEAD^{commit}").strip()
    tree = _operation_tree(repo, head)
    raw = _ref_read(repo, "ls-files", "-z")
    if raw and not raw.endswith("\0"):
        raise ValueError("Preflight index paths are incomplete.")
    paths = sorted(set(tree) | {path for path in raw.split("\0") if path})
    if len(paths) > REF_MAX_WORKTREE_ENTRIES:
        raise ValueError("Preflight attribute paths exceed the bounded inventory.")
    fingerprint, inactive = _checkout_filter_evidence(repo, paths, [head], _trusted_filter_drivers(cfg))
    if not inactive:
        raise ValueError("Active or unresolved checkout filters are outside read-only ref inspection; no driver was invoked.")
    return {"head_oid": head, "attribute_sources_fingerprint": attributes,
            "effective_filters_fingerprint": fingerprint}


def _worktree_metadata(root: str) -> dict:
    """Bound filesystem names/types/stat data, not file contents or secret patterns."""
    entries = {}
    repo = GitRepo(root)
    ignored_dirs = {path.rstrip("/") for path in _ref_read(
        repo, "ls-files", "--others", "--ignored", "--directory", "--exclude-standard", "-z"
    ).split("\0") if path.endswith("/")}
    pending = [(root, "")]
    while pending:
        directory, prefix = pending.pop()
        with os.scandir(directory) as children:
            for child in sorted(children, key=lambda entry: entry.name):
                if not prefix and child.name in (".git", OUTPUT_DIRNAME):
                    continue
                path = prefix + child.name
                if child.name == ".git":
                    raise ValueError("Nested repository metadata is outside this operation's scope.")
                info = child.stat(follow_symlinks=False)
                if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)
                        or stat.S_ISLNK(info.st_mode)):
                    raise ValueError("A working path has an unsupported filesystem type.")
                entries[path] = [info.st_mode, info.st_size, info.st_mtime_ns,
                                 info.st_ctime_ns, info.st_dev, info.st_ino]
                if len(entries) > REF_MAX_WORKTREE_ENTRIES:
                    raise ValueError("Working-path metadata exceeds the bounded operation inventory.")
                if stat.S_ISDIR(info.st_mode) and path not in ignored_dirs:
                    pending.append((child.path, path + "/"))
    return entries


def _reflog_fingerprint(gitdirs: set[str]) -> str:
    """Bind recovery metadata without publishing reflog identities/messages."""
    inventory = {}
    total = 0
    for gitdir in sorted(gitdirs):
        location = os.path.join(gitdir, "logs")
        if not os.path.lexists(location):
            continue
        if not stat.S_ISDIR(os.lstat(location).st_mode):
            raise ValueError("Reflog metadata must be an ordinary directory.")
        def walk_error(exc):
            raise exc
        for folder, dirs, files in os.walk(location, followlinks=False, onerror=walk_error):
            for name in dirs + files:
                path = os.path.join(folder, name)
                info = os.lstat(path)
                if name.endswith(".lock") or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                    raise ValueError("Recovery metadata has an unsafe type or writer lock.")
                if stat.S_ISREG(info.st_mode):
                    total += info.st_size
                    if total > 16_000_000 or len(inventory) >= REF_MAX_WORKTREE_ENTRIES:
                        raise ValueError("Recovery metadata exceeds the bounded operation inventory.")
                    with open(path, "rb") as stream:
                        raw = stream.read(info.st_size + 1)
                    after = os.lstat(path)
                    if len(raw) != info.st_size or any(getattr(after, key) != getattr(info, key) for key in (
                            "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns", "st_dev", "st_ino")):
                        raise ValueError("Reflog recovery metadata changed during inspection.")
                    inventory[path] = hashlib.sha256(raw).hexdigest()
    return _metadata_digest(inventory)


def _ref_operation_inputs(repo: GitRepo, state: dict) -> tuple[dict, dict]:
    """Reobserve the schema-2 inputs and add exact ref-operation bindings."""
    root = state.get("root")
    if (not isinstance(root, str) or root != os.path.realpath(root) or repo.toplevel() != root
            or state.get("topology", {}).get("toplevel") != root):
        raise ValueError("A canonical, actual repository root is required.")
    st, index = state.get("status") or {}, state.get("index_inventory") or {}
    if (not isinstance(state.get("read_errors"), list) or state["read_errors"]
            or state.get("index_locked") is not False or state.get("active_operations") != []
            or not isinstance(index.get("hidden_paths"), list) or index["hidden_paths"]
            or not isinstance(index.get("unmerged_paths"), list) or index["unmerged_paths"]
            or not isinstance(index.get("gitlinks"), list) or index["gitlinks"]
            or type(st.get("detached")) is not bool or state.get("has_commits") is not True):
        raise ValueError("Complete, conflict-free, visible non-submodule index/operation evidence is required.")
    for name in ("staged", "modified", "conflicts", "untracked"):
        if not isinstance(st.get(name), list):
            raise ValueError("Working-tree status evidence is incomplete.")
    if st["conflicts"]:
        raise ValueError("Unmerged work must be reconciled before a ref operation.")
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", st.get("oid") or ""):
        raise ValueError("An inspected HEAD commit is required.")
    paths = _ref_read(repo, "rev-parse", "--path-format=absolute", "--git-dir", "--git-common-dir").splitlines()
    if len(paths) != 2:
        raise ValueError("Git directory topology evidence is incomplete.")
    gitdir, common = paths
    for path in paths:
        if path != os.path.realpath(path) or not stat.S_ISDIR(os.lstat(path).st_mode):
            raise ValueError("Git metadata directories must be ordinary canonical directories.")
    for directory in {gitdir, common}:
        for name in ("index.lock", "HEAD.lock", "packed-refs.lock", "config.lock", "shallow.lock",
                     "FETCH_HEAD.lock", "ORIG_HEAD.lock", "gc.pid"):
            if os.path.lexists(os.path.join(directory, name)):
                raise ValueError("A Git writer or ref lock is present.")
        location = os.path.join(directory, "refs")
        if os.path.lexists(location):
            if not stat.S_ISDIR(os.lstat(location).st_mode):
                raise ValueError("The loose-ref directory is unsafe.")
            def walk_error(exc):
                raise exc
            for folder, dirs, files in os.walk(location, followlinks=False, onerror=walk_error):
                for name in dirs + files:
                    info = os.lstat(os.path.join(folder, name))
                    if name.endswith(".lock"):
                        raise ValueError("A Git ref writer lock is present.")
                    if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                        raise ValueError("Loose-ref metadata contains an unsupported file type.")

    cfg = _ref_read(repo, "config", "--null", "--list")
    if cfg and not cfg.endswith("\0"):
        raise ValueError("Git configuration evidence is truncated.")
    config = {}
    for record in cfg.split("\0"):
        if record:
            key, sep, value = record.partition("\n")
            if not sep or not key:
                raise ValueError("Git configuration evidence is malformed.")
            config.setdefault(key, []).append(value)
    if any(key.lower().endswith(".promisor") or key.lower().startswith("extensions.")
           and key.lower() not in {"extensions.objectformat", "extensions.worktreeconfig"} for key in config):
        raise ValueError("Partial-clone or unsupported repository extensions are not assessed.")
    if "extensions.worktreeconfig" in config:
        if _ref_read(repo, "config", "--bool", "--get", "extensions.worktreeconfig").strip() not in {"true", "false"}:
            raise ValueError("Worktree configuration extension is not a known boolean.")
    if _ref_read(repo, "rev-parse", "--is-shallow-repository").strip() != "false":
        raise ValueError("Shallow-history operations are not assessed.")
    if any(os.environ.get(key) for key in ("GIT_CONFIG", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT",
                                           "GIT_SHALLOW_FILE", "GIT_NO_REPLACE_OBJECTS")):
        raise ValueError("Operation evidence does not support overridden Git configuration/history inputs.")

    refs, symrefs = {}, {}
    raw = _ref_read(repo, "for-each-ref", "--format=%(refname)\t%(objectname)\t%(symref)")
    if raw and not raw.endswith("\n"):
        raise ValueError("Ref operation metadata is truncated.")
    for row in raw.splitlines():
        fields = row.split("\t")
        if (len(fields) != 3 or fields[0] in refs
                or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", fields[1])):
            raise ValueError("Ref operation metadata is malformed.")
        refs[fields[0]] = fields[1]
        if fields[2]:
            symrefs[fields[0]] = fields[2]
    if _metadata_digest(refs) != state.get("refs_fingerprint"):
        raise ValueError("Refs changed since the schema-2 inspection; refresh.")
    preflight = _ref_inspection_preflight(repo)
    if preflight != state.get("ref_inspection_preflight") or preflight["head_oid"] != st["oid"]:
        raise ValueError("Bound effective attribute/HEAD inspection inputs changed; refresh.")
    if repo.status() != st or repo.index_inventory() != index:
        raise ValueError("HEAD, working-tree status or index changed since inspection; refresh.")
    markers = repo.operation_markers()
    if any(state.get(key) != value for key, value in markers.items()):
        raise ValueError("Git operation state changed since inspection; refresh.")
    worktrees = repo.worktrees()
    if not isinstance(state.get("worktrees"), list) or worktrees != state["worktrees"] or not worktrees:
        raise ValueError("Worktree occupancy evidence is missing or changed; refresh.")
    primary = []
    for worktree in worktrees:
        if (not isinstance(worktree.get("path"), str) or not os.path.isdir(worktree["path"])
                or worktree.get("bare") or worktree.get("prunable")
                or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", worktree.get("HEAD") or "")
                or not (isinstance(worktree.get("branch"), str) or worktree.get("detached") is True)):
            raise ValueError("Worktree occupancy metadata is incomplete or stale.")
        held = worktree.get("branch")
        if held and (not held.startswith("refs/heads/") or held in symrefs or refs.get(held) != worktree["HEAD"]):
            raise ValueError("Worktree branch/ref identity is incomplete or ambiguous.")
        if os.path.realpath(worktree["path"]) == root:
            primary.append(worktree)
    if len(primary) != 1 or primary[0]["HEAD"] != st["oid"]:
        raise ValueError("The current worktree/HEAD identity is not proven.")
    head_ref = primary[0].get("branch")
    if head_ref != (None if st["detached"] else "refs/heads/" + (st.get("branch") or "")):
        raise ValueError("The symbolic HEAD and branch evidence disagree.")
    storage = repo.object_storage()
    if storage.get("complete") is not True or storage != state.get("object_storage"):
        raise ValueError("Object/configuration evidence is incomplete or changed; refresh.")
    unsupported_storage = set(storage.get("unsupported_reasons", []))
    worktree_config_only = (
        unsupported_storage == {"unsupported object-storage Git configuration"}
        and "extensions.worktreeconfig" in config
        and not any(key.lower().startswith("repack.") for key in config)
    )
    if unsupported_storage and not worktree_config_only:
        raise ValueError("Alternate/promisor/protected object storage is outside this operation's scope.")
    if hashlib.sha256(cfg.encode("utf-8", "surrogateescape")).hexdigest() != storage.get("config_fingerprint"):
        raise ValueError("Git configuration changed since inspection; refresh.")
    index_path = _ref_read(repo, "rev-parse", "--path-format=absolute", "--git-path", "index").rstrip("\n")
    if index_path != os.path.realpath(index_path) or not stat.S_ISREG(os.lstat(index_path).st_mode):
        raise ValueError("The real index must be an ordinary canonical file.")
    with open(index_path, "rb") as stream:
        index_bytes = stream.read()
    working = _worktree_metadata(root)
    tracked = _ref_read(repo, "ls-files", "-z").split("\0")
    if any(path == OUTPUT_DIRNAME or path.startswith(OUTPUT_DIRNAME + "/") for path in tracked):
        raise ValueError("Tracked assessment-publication paths cannot be excluded from operation bindings.")
    if repo.read_errors:
        raise ValueError("A required operation metadata inventory failed.")
    inputs = {
        "root": root, "gitdir": gitdir, "common_gitdir": common,
        "engine_source_sha256": state.get("engine_source_sha256"),
        "inspection_preflight": preflight,
        "head_ref": head_ref, "head_oid": st["oid"],
        "index_fingerprint": index["fingerprint"],
        "index_file_sha256": hashlib.sha256(index_bytes).hexdigest(),
        "refs_fingerprint": state["refs_fingerprint"], "symrefs_fingerprint": _metadata_digest(symrefs),
        "reflogs_fingerprint": _reflog_fingerprint({gitdir, common}),
        "worktrees_fingerprint": _metadata_digest(worktrees),
        "worktree_fingerprint": _metadata_digest(working),
        "config_fingerprint": storage["config_fingerprint"],
        "object_inventory_fingerprint": storage["inventory_fingerprint"],
    }
    return inputs, {"refs": refs, "symrefs": symrefs, "working": working, "config": config}


def _branch_recovery_tips(repo: GitRepo, target: str) -> list[str]:
    path = _ref_read(repo, "rev-parse", "--path-format=absolute", "--git-path", "logs/" + target).rstrip("\n")
    if not os.path.lexists(path):
        return []
    if not stat.S_ISREG(os.lstat(path).st_mode):
        raise ValueError("Selected branch recovery metadata is unsafe.")
    with open(path, "rb") as stream:
        raw = stream.read(16_000_001)
    if len(raw) > 16_000_000 or raw and not raw.endswith(b"\n"):
        raise ValueError("Selected branch recovery metadata is oversized or truncated.")
    tips = set()
    for row in raw.splitlines():
        fields = row.split(b" ", 2)
        if len(fields) != 3 or any(not re.fullmatch(rb"(?:[0-9a-f]{40}|[0-9a-f]{64})", oid) for oid in fields[:2]):
            raise ValueError("Selected branch recovery OID metadata is malformed.")
        tips.update(oid.decode("ascii") for oid in fields[:2] if set(oid) != {ord("0")})
    return sorted(tips)


def _operation_tree(repo: GitRepo, oid: str) -> dict:
    entries = {}
    raw = _ref_read(repo, "ls-tree", "-r", "-z", "--full-tree", oid)
    if raw and not raw.endswith("\0"):
        raise ValueError("Operation tree metadata is truncated.")
    for row in raw.split("\0"):
        if not row:
            continue
        meta, sep, path = row.partition("\t")
        fields = meta.split()
        if (not sep or len(fields) != 3 or path in entries or fields[1] != "blob"
                or fields[0] not in ("100644", "100755", "120000")
                or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", fields[2])
                or path.startswith("/") or any(p in ("", ".", "..", ".git", OUTPUT_DIRNAME) for p in path.split("/"))):
            raise ValueError("Unsupported, submodule or malformed target-tree metadata.")
        entries[path] = (fields[0], fields[2])
    return entries


def _checkout_collisions(root: str, head: dict, target: dict, working: dict) -> bool:
    for path, entry in target.items():
        if head.get(path) == entry:
            continue
        parts = path.split("/")
        # Existing HEAD leaves are proven clean before this function is used.
        # Everything else, including ignored files and symlinks, is local work.
        for n in range(1, len(parts) + 1):
            prefix = "/".join(parts[:n])
            info = working.get(prefix)
            exists = os.path.lexists(os.path.join(root, prefix))
            if not exists:
                continue
            if info is None:  # Includes case-folded filesystem aliases.
                return True
            if stat.S_ISDIR(info[0]) and os.path.lexists(os.path.join(root, prefix, ".git")):
                return True  # Never write across an opaque ignored repository boundary.
            if n == len(parts):
                if prefix not in head or stat.S_ISDIR(info[0]):
                    return True
            elif not stat.S_ISDIR(info[0]) and not (prefix in head and prefix not in target):
                return True
    return False


def _assess_ref_action(state: dict, operation: str, target: str | None,
                       expected_binding: str | None) -> tuple[list[str], dict]:
    reasons, evidence = [], {"input_binding": None, "binding_inputs": None}
    try:
        if type(state.get("schema_version")) is not int:
            raise ValueError("Schema version must be the explicit integer schema-2 value.")
        stamp = datetime.fromisoformat(state.get("generated_at") or "")
        age = (datetime.now(timezone.utc) - stamp).total_seconds() if stamp.tzinfo else -1
        if not 0 <= age <= REF_MAX_AGE_SECONDS:
            raise ValueError("Operation evidence is stale or has no timezone; refresh within 60 seconds.")
        if (not isinstance(state.get("request_id"), str)
                or not re.fullmatch(r"[A-Za-z0-9._:-]{1,256}", state["request_id"])
                or not isinstance(state.get("publication_id"), str)
                or not re.fullmatch(r"[0-9a-f]{32}", state["publication_id"])
                or state.get("engine_source_sha256") != ENGINE_SOURCE_SHA256):
            raise ValueError("Fresh request/publication/source correlation is required.")
        if not isinstance(target, str) or not target.startswith("refs/heads/"):
            raise ValueError("Select one exact fully qualified local branch ref: refs/heads/<name>.")
        branch = target[len("refs/heads/"):]
        repo = GitRepo(state["root"])
        if (not branch or branch.startswith(("-", "refs/")) or "\0" in target
                or branch in {"HEAD", "@", "FETCH_HEAD", "ORIG_HEAD", "MERGE_HEAD", "CHERRY_PICK_HEAD",
                              "REVERT_HEAD", "AUTO_MERGE", "BISECT_HEAD"}
                or re.fullmatch(r"[0-9a-fA-F]{40,64}", branch)):
            raise ValueError("The target is not an unambiguous supported local branch name.")
        _ref_read(repo, "check-ref-format", target)
        if _ref_read(repo, "check-ref-format", "--branch", branch).strip() != branch:
            raise ValueError("Git branch-name expansion is not an exact local target.")
        evidence.update(target_ref=target, branch_name=branch)
        inputs = state.get("ref_operation_inputs")
        if not isinstance(inputs, dict) or not inputs:
            raise ValueError("; ".join(state.get("ref_operation_errors") or [
                "Operation input bindings are missing; request a fresh operation-specific snapshot."]))
        current, details = _ref_operation_inputs(repo, state)
        if current != inputs:
            raise ValueError("Bound Git/worktree inputs changed since inspection; refresh.")
        refs, config = details["refs"], details["config"]
        head = inputs["head_oid"]
        target_oid = refs.get(target)
        evidence.update(resolved_target=target_oid, target_oid=target_oid,
                        retained_oid=head if operation == "delete_branch" else None)
        if target in details["symrefs"]:
            raise ValueError("Symbolic branch aliases are ambiguous operation targets.")
        commits = [w["HEAD"] for w in state["worktrees"]]
        if state["status"]["detached"] and operation != "create_branch":
            reasons.append("Retain detached HEAD on a named branch before switching away or reconciling refs.")
        if operation == "create_branch":
            if (any(ref == target or ref.startswith(target + "/") or target.startswith(ref + "/")
                    or ref.casefold() == target.casefold() for ref in refs)
                    or os.path.lexists(os.path.join(inputs["common_gitdir"], target))
                    or any(key.startswith("branch." + branch + ".") for key in config)):
                reasons.append("The new branch collides with an existing ref/namespace or branch configuration.")
            evidence["resolved_target"] = head
            evidence["target_oid"] = head
        else:
            if not target_oid:
                raise ValueError("The exact local target branch does not exist.")
            commits.append(target_oid)
            if operation in ("switch_branch", "delete_branch") and any(
                    w.get("branch") == target for w in state["worktrees"]
                    if os.path.realpath(w["path"]) != state["root"]):
                reasons.append("Another worktree holds the target branch; occupancy cannot be bypassed.")
        if operation in ("fast_forward", "delete_branch", "push_origin") and inputs["head_ref"] != "refs/heads/main":
            reasons.append("This bounded operation requires the inspected current main branch.")
        if operation in ("switch_branch", "fast_forward"):
            st = state["status"]
            if st["staged"] or st["modified"]:
                reasons.append("Switch/integration supports only a clean tracked worktree and index; preserve dirty work first.")
            before, after = _operation_tree(repo, head), _operation_tree(repo, target_oid)
            attribute_paths = sorted(before.keys() | after.keys())
            trusted = _trusted_filter_drivers(_ref_read(repo, "config", "--null", "--list"))
            attribute_fingerprint, inactive = _checkout_filter_evidence(
                repo, attribute_paths, [head, target_oid], trusted)
            evidence["checkout_attributes_fingerprint"] = attribute_fingerprint
            if not inactive:
                reasons.append("Active or unresolved checkout filters require a separate preservation assessment.")
            if _checkout_collisions(state["root"], before, after, details["working"]):
                reasons.append("The target may overwrite a local untracked/ignored path or filesystem alias.")
        if operation == "fast_forward" and config.get("branch.main.mergeoptions"):
            reasons.append("Configured main merge options are outside the exact fast-forward-only scope.")
        if operation == "delete_branch":
            recovery_tips = _branch_recovery_tips(repo, target)
            commits.extend(recovery_tips)
            evidence["recovery_tip_count"] = len(recovery_tips)
            if target == inputs["head_ref"]:
                reasons.append("The current branch cannot be deleted.")
            upstream = _ref_read(repo, "for-each-ref", "--format=%(upstream)", target).rstrip("\n")
            evidence["upstream_ref"] = upstream or None
            configured = any(key in config for key in ("branch." + branch + ".remote", "branch." + branch + ".merge"))
            if configured and not upstream:
                reasons.append("The branch's configured deletion upstream is unresolved.")
            if upstream:
                if upstream not in refs or upstream in details["symrefs"]:
                    raise ValueError("The deletion upstream is not an exact known local ref.")
                commits.append(refs[upstream])
        if operation == "push_origin":
            if target != "refs/heads/main" or target_oid != head:
                reasons.append("Only the inspected main tip may be pushed to origin/main.")
            fetch = _ref_read(repo, "remote", "get-url", "--all", "origin").splitlines()
            push = _ref_read(repo, "remote", "get-url", "--push", "--all", "origin").splitlines()
            if len(fetch) != 1 or push != fetch or not fetch[0]:
                raise ValueError("Exactly one existing origin destination matching its fetch URL is required.")
            url = fetch[0]
            scheme = re.match(r"^([a-z][a-z0-9+.-]*)://", url, re.I)
            if (scheme and scheme[1].lower() not in ("https", "http", "ssh", "git", "file")
                    or not scheme and ("::" in url or url.startswith("-") or any(c.isspace() for c in url))):
                raise ValueError("The existing origin uses an unsupported transport form.")
            if any(v.lower() not in ("false", "no", "off", "0") for v in config.get("remote.origin.mirror", [])):
                reasons.append("Mirror push configuration is outside the single nonforcing ref scope.")
            if any(v not in ("main", "main:main", "refs/heads/main:refs/heads/main")
                   for v in config.get("remote.origin.push", [])):
                reasons.append("Broad or forcing configured origin push refspecs are not assessed.")
            tracking = "refs/remotes/origin/main"
            mappings = config.get("remote.origin.fetch", [])
            supported = ("refs/heads/*:refs/remotes/origin/*", "refs/heads/main:refs/remotes/origin/main")
            if len(mappings) != 1 or mappings[0].removeprefix("+") not in supported:
                raise ValueError("The existing origin must have one unambiguous main-to-origin/main tracking mapping.")
            remote_oid = refs.get(tracking)
            if not remote_oid or tracking in details["symrefs"]:
                raise ValueError("Exact existing origin/main local tracking commit evidence is required; no live remote state is inferred.")
            commits.append(remote_oid)
            evidence.update(remote="origin", destination_ref="refs/heads/main", tracking_ref=tracking,
                            origin_main_oid=remote_oid, remote_verification="LOCAL_TRACKING_REFS_ONLY",
                            remote_verified=False, origin_url_sha256=hashlib.sha256(url.encode("utf-8", "surrogateescape")).hexdigest())
        unique = sorted(set(commits))
        objects = _ref_read(repo, "cat-file", "--batch-check=%(objectname) %(objecttype)",
                            input_text="\n".join(unique) + "\n").splitlines()
        if objects != [oid + " commit" for oid in unique]:
            raise ValueError("All inspected history tips must be complete commit objects.")
        def ancestor(base, tip, reason):
            _, rc, err = repo._run("merge-base", "--is-ancestor", base, tip)
            if rc == 1 and not err:
                reasons.append(reason)
            elif rc or err:
                raise ValueError("Required ancestry evidence failed; no integration/publication is inferred.")
        if operation == "fast_forward":
            ancestor(head, target_oid, "The target is not a fast-forward of the inspected HEAD; divergence/rewind is blocked.")
        elif operation == "delete_branch":
            ancestor(target_oid, head, "The branch history is not proven reachable from retained main.")
            for tip in recovery_tips:
                ancestor(tip, head, "Selected branch reflog recovery history is not reachable from retained main; preserve it.")
            if evidence.get("upstream_ref"):
                ancestor(target_oid, refs[evidence["upstream_ref"]], "Nonforcing git branch -d would reject the configured upstream; preserve the branch.")
        elif operation == "push_origin":
            ancestor(evidence["origin_main_oid"], head, "Main does not fast-forward the local origin/main tracking tip; nonforcing push is unproven.")
        final, _ = _ref_operation_inputs(repo, state)
        if final != inputs:
            raise ValueError("Operation inputs changed during target inspection; refresh.")
        binding = "sha256:" + _metadata_digest({
            "operation": operation, "target": target, "inputs": inputs,
            "checkout_attributes_fingerprint": evidence.get("checkout_attributes_fingerprint"),
        })
        evidence.update(input_binding=binding, binding_inputs=inputs,
                        refs_fingerprint=inputs["refs_fingerprint"], config_fingerprint=inputs["config_fingerprint"],
                        worktree_fingerprint=inputs["worktree_fingerprint"], request_id=state["request_id"],
                        generated_at=state["generated_at"])
        if expected_binding is not None and (not isinstance(expected_binding, str)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_binding) or expected_binding != binding):
            reasons.append("Expected operation binding is malformed or stale; no action is approved.")
    except (OSError, ValueError, RuntimeError, TypeError, KeyError) as exc:
        reasons.append(str(exc))
    return reasons, evidence


def assess_action(state: dict, operation: str | None, target: str | None = None,
                  expected_binding: str | None = None) -> dict:
    """Hard preservation predicates. A summary score is never action approval."""
    st = state.get("status") if isinstance(state.get("status"), dict) else {}
    index = state.get("index_inventory") if isinstance(state.get("index_inventory"), dict) else {}
    topology = state.get("topology") if isinstance(state.get("topology"), dict) else {}
    storage = state.get("object_storage") if isinstance(state.get("object_storage"), dict) else {}
    reasons = []
    resolved_target = None
    evidence = {}
    if operation not in ACTION_SCOPES:
        reasons.append("An explicit supported operation is required; no blanket discard approval exists.")
    if (state.get("schema_version") != SCHEMA_VERSION or state.get("is_repo") is not True
            or state.get("read_complete") is not True or state.get("read_errors")
            or st.get("ok") is not True or st.get("complete") is not True):
        reasons.append("Required Git evidence is missing, failed, or incomplete.")
    if topology.get("kind") != "own_repo":
        reasons.append("Request the actual repository root; this path has ambiguous action scope.")
    if operation in REF_ACTIONS and any(not isinstance(state.get(key), dict) for key in (
            "status", "index_inventory", "topology", "object_storage")):
        reasons.append("Required schema-2 operation metadata has an invalid type.")
    if state.get("index_locked") or (state.get("active_operations") and not (
            operation == "commit_index" and resolved_merge_commit(state))):
        reasons.append("An index lock or unfinished Git operation requires reconciliation first.")
    if operation not in ("reset_hard", "drop_stash", *REF_ACTIONS) and target is not None:
        reasons.append("This operation does not accept a target.")
    if expected_binding is not None and operation not in REF_ACTIONS:
        reasons.append("Expected bindings are supported only for exact branch/integration/origin-push assessments.")
    if not reasons:
        hidden = index.get("hidden_paths")
        if operation in REF_ACTIONS:
            ref_reasons, evidence = _assess_ref_action(state, operation, target, expected_binding)
            reasons.extend(ref_reasons)
            resolved_target = evidence.get("resolved_target")
        elif operation == "maintain_objects":
            reasons.extend(_maintenance_hazards(state))
        elif operation == "commit_index":
            scores = state.get("scores") or {}
            if not st.get("staged"):
                reasons.append("No staged changes; this is a preview, not a commit approval.")
            if scores.get("safe_commit_band") != "GO" or scores.get("safe_commit", 0) < 80:
                reasons.extend(scores.get("safe_commit_reasons") or ["Commit hazards require review."])
        elif operation in ("clean_untracked", "clean_ignored"):
            if state.get("untracked_inventory") or st.get("untracked"):
                reasons.append("Untracked paths have no proven durable copy, regardless of names or extensions.")
            if operation == "clean_ignored" and state.get("ignored_count"):
                reasons.append("Ignored paths have no proven durable copy; ignored does not mean disposable.")
        elif operation == "discard_tracked":
            if st.get("modified") or st.get("conflicts") or hidden:
                reasons.append("Working-tree edits, conflicts, or status-hidden paths would not be safely preserved.")
        elif operation == "reset_hard":
            if not target:
                reasons.append("Reset requires an explicit target; a clean tree says nothing about another commit.")
            elif not state.get("has_commits"):
                reasons.append("No current HEAD commit to compare with the target.")
            else:
                repo = GitRepo(state["root"])
                out, rc, _ = repo._run("rev-parse", "--verify", "--end-of-options", target + "^{commit}")
                if rc or not re.fullmatch(r"[0-9a-f]{40,64}", out.strip()):
                    reasons.append("Reset target cannot be resolved to a commit.")
                else:
                    resolved_target = out.strip()
                    _, ancestor_rc, _ = repo._run("merge-base", "--is-ancestor", st["oid"], resolved_target)
                    if ancestor_rc:
                        reasons.append("The target does not preserve current HEAD ancestry, or ancestry could not be proven.")
                    if resolved_target != st["oid"] and (state.get("untracked_inventory") or st.get("untracked") or state.get("ignored_count")):
                        reasons.append("A different target may overwrite untracked/ignored paths; collision-free recovery is unproven.")
                    current, current_rc, _ = repo._run("rev-parse", "--verify", "HEAD")
                    if current_rc or current.strip() != st["oid"]:
                        reasons.append("HEAD changed during target inspection; refresh.")
            if st.get("staged") or st.get("modified") or st.get("conflicts") or hidden:
                reasons.append("Reset would discard index/worktree changes or status-hidden work.")
        elif operation == "drop_stash":
            proof = stash_committed_copy(state, target)
            resolved_target = proof.get("stash_oid")
            if not proof["safe"]:
                reasons.extend(proof["reasons"])
    safe = not reasons
    return {
        "operation": operation, "target": target, "resolved_target": resolved_target,
        "scope": ACTION_SCOPES.get(operation, "unsupported or unspecified"),
        "safe": safe, "decision": "ALLOW" if safe else "BLOCK",
        "reasons": reasons or ["No detected data-loss hazard within this exact operation's scope."],
        "root": state.get("root"), "head_oid": st.get("oid"),
        "index_fingerprint": index.get("fingerprint"),
        "refs_fingerprint": state.get("refs_fingerprint") if operation == "maintain_objects" else None,
        "object_inventory_fingerprint": storage.get("inventory_fingerprint") if operation == "maintain_objects" else None,
        "config_fingerprint": storage.get("config_fingerprint") if operation == "maintain_objects" else None,
        "gc_log": storage.get("gc_log") if operation == "maintain_objects" else None,
        "pending_maintenance": storage.get("pending_maintenance") if operation == "maintain_objects" else None,
        "merge_parents": state.get("merge_parents", []) if operation == "commit_index" else [],
        "publication_id": state.get("publication_id"),
        "limits": "Snapshot evidence, not execution authorization, a backup, a secret scan, or protection against future concurrent writes.",
        **evidence,
    }


def requested_action(state: dict, operation: str, target: str | None = None,
                     expected_binding: str | None = None) -> dict:
    action = assess_action(state, operation, target, expected_binding)
    state.setdefault("actions", {})[operation] = action
    state["requested_action"] = action
    return state



def _absolute_git_path(repo: GitRepo, name: str) -> str:
    out, rc, err = repo._run("rev-parse", "--git-path", name)
    if rc or not out.strip():
        raise RuntimeError(err.strip() or f"could not resolve Git path {name}")
    value = out.strip()
    if not os.path.isabs(value):
        value = os.path.join(repo.root, value)
    return os.path.realpath(value)


def _index_entries(repo: GitRepo) -> dict[str, tuple[str, str, str]]:
    out, rc, err = repo._run("ls-files", "--stage", "-z")
    if rc:
        raise RuntimeError(err.strip() or "could not read index entries")
    if out and not out.endswith("\0"):
        raise RuntimeError("incomplete index entry metadata")
    entries = {}
    seen = set()
    for row in out.split("\0"):
        if not row:
            continue
        meta, sep, path = row.partition("\t")
        fields = meta.split()
        if (not sep or len(fields) != 3 or not path or os.path.isabs(path)
                or any(part in ("", ".", "..") for part in path.split("/"))
                or fields[0] not in ("100644", "100755", "120000", "160000")
                or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", fields[1])
                or fields[2] not in ("0", "1", "2", "3") or (path, fields[2]) in seen):
            raise RuntimeError("malformed index entry")
        seen.add((path, fields[2]))
        entries[path] = (fields[0], fields[1], fields[2])
    return entries


def _index_fingerprint(repo: GitRepo) -> str:
    out, rc, err = repo._run("ls-files", "--stage", "-v", "-z")
    if rc:
        raise RuntimeError(err.strip() or "could not fingerprint index")
    if out and not out.endswith("\0"):
        raise RuntimeError("incomplete index fingerprint metadata")
    return hashlib.sha256(out.encode("utf-8", "surrogateescape")).hexdigest()


def _head_oid(repo: GitRepo) -> str | None:
    out, rc, _ = repo._run("rev-parse", "--verify", "HEAD")
    value = out.strip()
    return value if rc == 0 and re.fullmatch(r"[0-9a-f]{40,64}", value) else None


def _environment_matches(key: str, value: str, expected: str) -> bool:
    if key == "GIT_ALTERNATE_OBJECT_DIRECTORIES":
        return value == expected
    return os.path.normcase(os.path.realpath(value)) == os.path.normcase(os.path.realpath(expected))


def _reported_stage_pathspec(value: object) -> str:
    if not isinstance(value, str):
        return "<non-text pathspec>"
    try:
        encoded = value.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:
        return "<unencodable pathspec>"
    if len(encoded) <= STAGE_MAX_PATH_BYTES:
        return value
    digest = hashlib.sha256(encoded).hexdigest()
    return f"<oversized pathspec bytes={len(encoded)} sha256:{digest}>"


def _stage_result(state: dict, action: dict) -> dict:
    # The result names its own publication; retain original-input lineage too.
    action = {**action, "publication_id": state.get("publication_id")}
    state.setdefault("actions", {})["stage_paths"] = action
    state["requested_action"] = action
    return state


def _readonly_index_admission(repo: GitRepo) -> None:
    # Reading a split index can freshen a shared index in the real Git directory.
    # Refuse it before build_state or any index-reading command. Retained shared
    # metadata is deliberately conservative evidence, not proof it is active.
    setting, code, error = repo._run("config", "--bool", "--get", "core.splitIndex")
    if code not in (0, 1) or (code == 0 and setting.strip() != "false") or (code == 1 and setting):
        raise RuntimeError("Split-index configuration is enabled or unreadable; read-only inspection is not admitted.")
    index_path = _absolute_git_path(repo, "index")
    with os.scandir(os.path.dirname(index_path)) as entries:
        for count, entry in enumerate(entries):
            if count >= STAGE_MAX_METADATA_ENTRIES:
                raise RuntimeError("Index-directory metadata exceeds the bounded read-only admission inventory.")
            if entry.name.startswith("sharedindex."):
                raise RuntimeError("Retained shared-index metadata is outside read-only inspection isolation; preserve it for separate review.")


def _stage_storage_admission(repo: GitRepo) -> None:
    # Keep the staging admission entrypoint while sharing the read-side boundary.
    _readonly_index_admission(repo)


def stage_paths_state(root: str, pathspecs: list[str], quick: bool = True,
                      request_id: str | None = None) -> dict:
    """Assess a candidate index without executing the resulting staging manifest."""
    root = os.path.realpath(os.path.abspath(root))
    real_state = {
        "version": VERSION, "schema_version": SCHEMA_VERSION, "root": root,
        "request_id": request_id, "publication_id": os.urandom(16).hex(),
        "is_repo": False, "read_complete": False,
        "read_errors": ["Staging request was not admitted for repository inspection."],
        "actions": {},
    }
    valid_sequence = isinstance(pathspecs, (list, tuple))
    requested = pathspecs if valid_sequence else []
    base_action = {
        "operation": "stage_paths", "target": None, "resolved_target": None,
        "scope": ACTION_SCOPES["stage_paths"], "safe": False, "decision": "BLOCK",
        "reasons": [], "root": root, "head_oid": None, "index_fingerprint": None,
        "baseline_publication_id": None,
        "limits": (
            "Read-only simulation in an isolated index/object directory. "
            "The manifest is not execution authorization and does not lock future writers."
        ),
        "requested_pathspecs": [_reported_stage_pathspec(value)
                                for value in requested[:STAGE_MAX_REPORTED_PATHS]],
        "requested_pathspecs_truncated": max(0, len(requested) - STAGE_MAX_REPORTED_PATHS),
        "manifest": [], "manifest_digest": None, "candidate_count": 0, "candidate_bytes": 0,
    }
    reasons = []
    if not valid_sequence or not requested:
        reasons.append("At least one staging pathspec in a list or tuple is required.")
    if len(requested) > STAGE_MAX_REQUEST_PATHS:
        reasons.append(f"Staging request exceeds the implementation ceiling of {STAGE_MAX_REQUEST_PATHS} pathspecs.")
    else:
        for pathspec in requested:
            if not isinstance(pathspec, str) or not pathspec or "\0" in pathspec:
                reasons.append("Every staging pathspec must be non-empty bounded text.")
                continue
            try:
                encoded = pathspec.encode("utf-8", "surrogateescape")
            except UnicodeEncodeError:
                reasons.append("Staging pathspec cannot be represented as filesystem bytes.")
                continue
            if len(encoded) > STAGE_MAX_PATH_BYTES:
                reasons.append(f"Staging pathspec exceeds the implementation ceiling of {STAGE_MAX_PATH_BYTES} bytes "
                               f"(sha256:{hashlib.sha256(encoded).hexdigest()}).")
                continue
            if os.path.isabs(pathspec):
                reasons.append(f"Absolute staging pathspec is not supported: {pathspec!r}.")
            if pathspec.startswith("-"):
                reasons.append(f"Staging options are not pathspecs: {pathspec!r}.")
    if reasons:
        base_action["reasons"] = list(dict.fromkeys(reasons))
        return _stage_result(real_state, base_action)
    try:
        real_repo = GitRepo(root)
        _stage_storage_admission(real_repo)
        real_state = build_state(real_repo, {"quick": quick, "request_id": request_id})
        base_action.update(
            head_oid=(real_state.get("status") or {}).get("oid") if real_state.get("has_commits") else None,
            index_fingerprint=(real_state.get("index_inventory") or {}).get("fingerprint"),
            baseline_publication_id=real_state.get("publication_id"),
        )
        if (real_state.get("read_complete") is not True or real_state.get("read_errors")
                or real_state.get("is_repo") is not True
                or (real_state.get("topology") or {}).get("kind") != "own_repo"
                or real_state.get("root") != root):
            raise RuntimeError("A complete read of the actual repository root is required for staging preview.")
        return _stage_paths_preview(real_repo, real_state, base_action, list(requested), quick, request_id)
    except (OSError, ValueError, RuntimeError) as exc:
        base_action["reasons"] = [str(exc) or "Staging preview failed before a complete result."]
        return _stage_result(real_state, base_action)


def _stage_paths_preview(real_repo: GitRepo, real_state: dict, base_action: dict,
                         pathspecs: list[str], quick: bool, request_id: str | None) -> dict:
    root = real_repo.root
    _status_filter_preflight(real_repo, pathspecs)
    real_index = _absolute_git_path(real_repo, "index")
    real_objects = _absolute_git_path(real_repo, "objects")
    before_entries = _index_entries(real_repo)
    before_fingerprint = _index_fingerprint(real_repo)
    before_head = _head_oid(real_repo)
    if (before_fingerprint != base_action["index_fingerprint"]
            or before_head != base_action["head_oid"]):
        raise RuntimeError("The real index or HEAD changed after the baseline inspection; refresh.")

    with tempfile.TemporaryDirectory(prefix="gitreal-stage-") as temp:
        temp_index = os.path.join(temp, "index")
        temp_objects = os.path.join(temp, "objects")
        temp_hooks = os.path.join(temp, "hooks")
        os.makedirs(temp_objects, mode=0o700)
        os.makedirs(temp_hooks, mode=0o700)
        if os.path.isfile(real_index):
            shutil.copy2(real_index, temp_index)

        # Never give the object-writing phase an alternate pointing at real objects:
        # Git may freshen matching alternate objects. Each repo instance owns its
        # effective environment; another caller never sees temporary process globals.
        environment = dict(os.environ)
        for key in ("GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"):
            environment.pop(key, None)
        write_environment = {**environment, "GIT_INDEX_FILE": temp_index, "GIT_OBJECT_DIRECTORY": temp_objects}
        read_environment = {**environment, "GIT_INDEX_FILE": temp_index,
                            "GIT_OBJECT_DIRECTORY": real_objects,
                            "GIT_ALTERNATE_OBJECT_DIRECTORIES": temp_objects}
        sim_repo = GitRepo(root, git_environment=write_environment)
        if (_index_fingerprint(sim_repo) != before_fingerprint
                or _index_fingerprint(real_repo) != before_fingerprint
                or _head_oid(real_repo) != before_head):
            raise RuntimeError("The copied candidate does not match the inspected index/HEAD; refresh.")
        _, add_rc, add_err = sim_repo._run("-c", "core.hooksPath=" + temp_hooks,
                                         "-c", "core.splitIndex=false", "add", "--", *pathspecs, timeout=120)
        if add_rc:
            raise RuntimeError("Git could not expand the requested pathspecs in the isolated staging simulation: "
                               + (add_err.strip() or f"exit {add_rc}"))

        # Only read operations follow. Both old and candidate objects are visible.
        sim_repo.git_environment = dict(read_environment)
        sim_state = build_state(sim_repo, {
            "quick": quick, "request_id": request_id,
            "_allowed_git_environment": {key: read_environment[key] for key in
                                         ("GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES")},
        })
        after_entries = _index_entries(sim_repo)
        after_fingerprint = _index_fingerprint(sim_repo)
        if (after_fingerprint != (sim_state.get("index_inventory") or {}).get("fingerprint")
                or (sim_state.get("status") or {}).get("oid") != (real_state.get("status") or {}).get("oid")):
            raise RuntimeError("Candidate index or HEAD changed after its inspection; refresh.")
        changed_paths = sorted(path for path in set(before_entries) | set(after_entries)
                               if before_entries.get(path) != after_entries.get(path))
        if len(changed_paths) > STAGE_MAX_MANIFEST_ENTRIES:
            base_action.update(candidate_count=len(changed_paths), reasons=[
                f"Expanded staging manifest exceeds the implementation ceiling of {STAGE_MAX_MANIFEST_ENTRIES} entries."])
            return _stage_result(sim_state, base_action)
        oversized_paths = [path for path in changed_paths
                           if len(path.encode("utf-8", "surrogateescape")) > STAGE_MAX_PATH_BYTES]
        if oversized_paths:
            base_action.update(candidate_count=len(changed_paths), reasons=[
                f"{len(oversized_paths)} expanded path(s) exceed the {STAGE_MAX_PATH_BYTES}-byte implementation ceiling."])
            return _stage_result(sim_state, base_action)
        status_by_path = {item.get("path"): item for item in
                          (sim_state.get("status") or {}).get("staged", []) if item.get("path")}
        manifest, total_bytes = [], 0
        for path in changed_paths:
            entry = after_entries.get(path)
            status_item = status_by_path.get(path, {})
            if entry is None:
                manifest.append({"path": path, "kind": "delete", "mode": None,
                                 "oid": None, "index_status": status_item.get("x") or "D"})
                continue
            mode, oid, stage = entry
            size_out, size_rc, _ = sim_repo._run("cat-file", "-s", oid)
            if size_rc or not re.fullmatch(r"[0-9]+", size_out.strip()):
                raise RuntimeError("Candidate object size is missing or malformed; no complete manifest is available.")
            size = int(size_out.strip())
            total_bytes += size
            manifest.append({"path": path, "kind": "gitlink" if mode == "160000" else "blob",
                             "mode": mode, "oid": oid, "stage": stage, "size": size,
                             "index_status": status_item.get("x")})

        # Detect observed changes within this preview; this is not a future-writer lock.
        if (_index_fingerprint(real_repo) != before_fingerprint or _head_oid(real_repo) != before_head
                or _index_fingerprint(sim_repo) != after_fingerprint):
            raise RuntimeError("The real or candidate index/HEAD changed during staging preview; refresh.")
        canonical_manifest = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        commit_action = assess_action(sim_state, "commit_index")
        action_reasons = [] if commit_action.get("safe") is True and commit_action.get("decision") == "ALLOW" else list(
            commit_action.get("reasons") or ["The simulated commit-index decision is not an explicit ALLOW."])
        if not manifest:
            action_reasons.append("The requested pathspecs produce no index change.")
        synthetic_roots = (".cache/", ".config/", ".local/", ".npm/", "go/")
        synthetic = [item["path"] for item in manifest if item["path"] in {p[:-1] for p in synthetic_roots}
                     or item["path"].startswith(synthetic_roots)]
        if synthetic:
            action_reasons.append(f"{len(synthetic)} candidate path(s) are synthetic HOME/cache state and must not enter Git.")
        gitlinks = [item["path"] for item in manifest if item["kind"] == "gitlink"]
        if gitlinks:
            action_reasons.append(f"{len(gitlinks)} candidate gitlink(s) cross repository ownership; stage in their own repositories.")
        action_reasons = list(dict.fromkeys(action_reasons))
        action = {**base_action, "safe": not action_reasons,
                  "decision": "ALLOW" if not action_reasons else "BLOCK",
                  "reasons": action_reasons or ["The isolated candidate index passes GIT_REAL's commit-index preservation checks."],
                  "head_oid": before_head, "index_fingerprint": before_fingerprint,
                  "candidate_index_fingerprint": after_fingerprint, "manifest": manifest,
                  "manifest_digest": "sha256:" + hashlib.sha256(canonical_manifest).hexdigest(),
                  "candidate_count": len(manifest), "candidate_bytes": total_bytes,
                  "simulated_commit_action": commit_action, "simulation_object_directory": "isolated-temporary"}
        return _stage_result(sim_state, action)


def stash_committed_copy(state: dict, target: str | None) -> dict:
    """Prove selected stash deltas are durably present in the current branch.

    Compare tree metadata (mode + blob IDs), never scan content. Both the saved
    index and working tree matter, as does the optional untracked parent. A
    merely reverse-applicable patch or a working-tree copy proves nothing here.
    """
    reasons = []
    st = state.get("status") or {}
    if not target or not re.fullmatch(r"stash@\{[0-9]+\}", target):
        return {"safe": False, "reasons": ["Select one exact stash ref; blanket clearing is not supported."]}
    if not state.get("has_commits") or st.get("detached") or not st.get("branch"):
        return {"safe": False, "reasons": ["A retained current branch commit is required for stash recovery proof."]}
    repo = GitRepo(state["root"])
    out, rc, _ = repo._required("rev-parse", "--verify", "--end-of-options", target + "^{commit}")
    stash_oid = out.strip()
    if rc or not re.fullmatch(r"[0-9a-f]{40,64}", stash_oid):
        return {"safe": False, "reasons": ["Selected stash cannot be resolved."]}
    out, rc, _ = repo._required("rev-list", "--parents", "-n", "1", stash_oid)
    parents = out.split()[1:]
    if rc or len(parents) not in (2, 3):
        return {"safe": False, "reasons": ["Selected object has no verified stash parent structure."]}
    # A reflog entry can point at a crafted merge, not a canonical Git stash.
    # Inspect raw commit headers: rev-list alone can conceal side ancestry.
    def raw_parents(oid):
        raw, code, _ = repo._required("cat-file", "-p", oid)
        if code:
            return None
        header = raw.partition("\n\n")[0]
        return [line[7:] for line in header.splitlines() if line.startswith("parent ")]

    if raw_parents(stash_oid) != parents or raw_parents(parents[1]) != [parents[0]]:
        return {"safe": False, "reasons": ["Noncanonical stash/index ancestry may retain additional work; preserve it."]}
    if len(parents) == 3 and raw_parents(parents[2]) != []:
        return {"safe": False, "reasons": ["Noncanonical untracked-parent ancestry must be preserved."]}
    _, rc, _ = repo._run("merge-base", "--is-ancestor", parents[0], st["oid"])
    if rc:
        reasons.append("The stash base is not proven retained in current branch history.")

    def tree(oid):
        out, rc, _ = repo._required("ls-tree", "-r", "-z", "--full-tree", oid)
        entries = {}
        for row in out.split("\0") if not rc else []:
            if not row:
                continue
            meta, sep, path = row.partition("\t")
            fields = meta.split()
            if not sep or len(fields) != 3:
                repo.read_errors.append("Malformed stash tree metadata")
                continue
            entries[path] = (fields[0], fields[1], fields[2])
        return entries

    base, head = tree(parents[0]), tree(st["oid"])
    missing = set()
    for variant in (tree(stash_oid), tree(parents[1])):
        for path in base.keys() | variant.keys():
            if variant.get(path) != base.get(path) and head.get(path) != variant.get(path):
                missing.add(path)
    if len(parents) == 3:
        for path, entry in tree(parents[2]).items():
            if head.get(path) != entry:
                missing.add(path)
    if missing:
        reasons.append(f"{len(missing)} saved path version(s) are not proven present in HEAD; retain the stash.")
    current, rc, _ = repo._required("rev-parse", "--verify", "HEAD")
    selected, src, _ = repo._required("rev-parse", "--verify", "--end-of-options", target + "^{commit}")
    if rc or src or current.strip() != st["oid"] or selected.strip() != stash_oid:
        reasons.append("HEAD or the selected stash changed during proof; refresh.")
    reasons.extend(repo.read_errors)
    return {"safe": not reasons, "reasons": reasons,
            "stash_oid": stash_oid, "retained_in_head": st["oid"],
            "basis": "exact tree modes/object IDs for saved index, worktree, and untracked deltas"}


def closeout_state(state: dict) -> dict:
    st = state.get("status") or {}
    counts = {
        "dirty_file_count": len(state.get("files", [])),
        "conflict_count": len(st.get("conflicts", [])),
        "stash_count": len(state.get("stashes", [])),
        "side_branch_count": len(state.get("side_branches", [])),
        "extra_worktree_count": state.get("extra_worktree_count"),
        "unpushed_commit_count": state.get("unpushed_commit_count"),
    }
    remaining = [name for name, value in counts.items() if value != 0]
    if st.get("branch") != "main" or st.get("detached"):
        remaining.append("not_on_main")
    if state.get("main_equals_origin_main") is not True:
        remaining.append("main_not_verified_equal_to_origin_main")
    if state.get("index_inventory", {}).get("hidden_paths"):
        remaining.append("status_hidden_paths")
    if state.get("active_operations") or state.get("index_locked"):
        remaining.append("git_operation_in_progress")
    storage = state.get("object_storage") or {}
    storage_complete = (
        storage.get("complete") is True
        and isinstance(storage.get("errors"), list) and not storage["errors"]
        and type(storage.get("loose_count")) is int and storage["loose_count"] >= 0
        and type(storage.get("loose_bytes")) is int and storage["loose_bytes"] >= 0
        and type(storage.get("maintenance_required")) is bool
    )
    if storage_complete and storage["maintenance_required"]:
        remaining.append("object_storage_maintenance")
    complete = (state.get("read_complete") is True and state.get("is_repo") is True
                and state.get("topology", {}).get("kind") == "own_repo"
                and storage_complete)
    if not storage_complete:
        remaining.append("object_storage_incomplete")
    return {**counts, "status": ("BLOCKED" if not complete else
                                 "RECONCILE" if remaining else "LOCAL_STATE_COMPLETE"),
            "local_state_complete": complete and not remaining,
            "remaining": remaining, "remote_verified": False,
            "basis": "Local refs only; remote synchronization must be established by the requested delivery workflow."}


# ----------------------------------------------------------------------------
# state builder
# ----------------------------------------------------------------------------
def _incomplete_state(state: dict, repo: GitRepo, config: dict, started: float) -> dict:
    """Publish an explicit refusal without continuing repository inspection."""
    state["read_complete"] = False
    state["read_errors"] = list(dict.fromkeys(state.get("read_errors", []) + repo.read_errors))
    state["status"].update(ok=False, complete=False, oid=None, submodules=[],
                           ahead_behind_known=False, error="; ".join(state["read_errors"]))
    state.update(index_inventory={"fingerprint": None, "hidden_paths": [], "gitlinks": [],
                                  "unmerged_paths": []},
                 worktrees=[], extra_worktree_count=None, stale_worktree_count=None,
                 active_operations=[], index_locked=None, untracked_inventory=[],
                 ignored_count=None, unpushed_commit_count=None, branch_ahead_commit_count=None,
                 unpushed_count_scope="Uninspected local refs", main_equals_origin_main=None,
                 main_oid=None, origin_main_oid=None, refs_fingerprint=None,
                 consistency="Inspection stopped at admission; inventories are unknown.")
    state["scores"] = state.get("scores") or compute_scores(state)
    state["actions"] = {name: assess_action(state, name) for name in (
        "commit_index", "discard_tracked", "clean_untracked", "clean_ignored",
        "maintain_objects", *REF_ACTIONS)}
    if config.get("operation"):
        requested_action(state, config["operation"], config.get("target"), config.get("expected_binding"))
    state["closeout"] = closeout_state(state)
    state["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
    return state


def build_state(repo: GitRepo, config: dict) -> dict:
    started = time.perf_counter()
    repo.read_errors = []
    try:
        with open(__file__, "rb") as fh:
            if hashlib.sha256(fh.read()).hexdigest() != ENGINE_SOURCE_SHA256:
                repo.read_errors.append("GIT_REAL source changed after this process started; reconnect/restart it.")
    except OSError:
        repo.read_errors.append("Loaded GIT_REAL source cannot be verified")
    root = repo.root
    now = datetime.now(timezone.utc).astimezone()
    state = {
        "version": VERSION,
        "schema_version": SCHEMA_VERSION,
        "engine_source_sha256": ENGINE_SOURCE_SHA256,
        "publication_id": os.urandom(16).hex(),
        "request_id": config.get("request_id"),
        "secret_scan_state": "SKIPPED_BY_OWNER_POLICY",
        "remote_verification": "LOCAL_TRACKING_REFS_ONLY",
        "generated_at": now.isoformat(timespec="seconds"),
        "generated_at_human": now.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "root": root,
        "root_name": os.path.basename(root.rstrip("/")) or root,
        "is_repo": None,
        "has_commits": False,
        "status": {"branch": None, "upstream": None, "ahead": 0, "behind": 0,
                   "detached": False, "staged": [], "modified": [], "untracked": [],
                   "conflicts": [], "renamed": []},
        "files": [],
        "branches": [], "default_branch": None, "side_branches": [],
        "ignored": [], "ignored_count": 0,
        "unpushed": [], "stashes": [], "remotes": [], "last_commit": None,
        "gitignore_suggestions": [],
        "scores": {},
        "topology": {"kind": "unknown", "toplevel": None},
        "stashes_detail": [],
        "stash_summary": {
            "count": 0, "empty": 0, "superseded": 0, "unmerged": 0,
            "unknown": 0, "inspected": 0, "uninspected": 0,
            "inspection_complete": True,
        },
        "read_complete": True,
        "read_errors": [],
        "object_storage": {"complete": False, "errors": ["Object storage not inspected"],
                           "loose_count": None, "loose_bytes": None,
                           "maintenance_required": None},
        "remotes_detail": [],
        "push_weight": {},
    }

    if repo.read_errors:
        return _incomplete_state(state, repo, config, started)
    state["is_repo"] = repo.is_repo()
    if not state["is_repo"]:
        state["read_complete"] = False
        state["read_errors"] = ["Not a readable Git working tree"]
        state["topology"] = {
            "kind": "untracked",
            "toplevel": None,
            "note": "Not inside any git repo - a plain directory. `git init` to make it its own repo.",
        }
        state["scores"] = {
            "safe_commit": 0, "safe_commit_band": "STOP",
            "safe_commit_label": "NOT A GIT REPO",
            "safe_commit_reasons": ["This folder is not a git repository. Run `git init` (or `gitreal . --init`)."],
            "safe_delete": 0, "safe_delete_band": "STOP",
            "safe_delete_label": "NOT A GIT REPO",
            "safe_delete_reasons": ["No git repository to track yet."],
        }
        return _incomplete_state(state, repo, config, started)

    # Hooks legitimately export the default index/repository paths. Accept those
    # exact paths, but do not silently inspect a different index or repository.
    gitdir = os.path.join(root, ".git")
    if os.path.isfile(gitdir):
        try:
            with open(gitdir, encoding="utf-8") as fh:
                link = fh.readline().rstrip("\n")
            if not link.startswith("gitdir: "):
                raise ValueError("not a gitfile")
            gitdir = os.path.abspath(os.path.join(root, link[8:]))
        except (OSError, ValueError):
            repo.read_errors.append("Linked worktree gitdir could not be resolved")
    expected = {"GIT_DIR": gitdir, "GIT_WORK_TREE": root,
                "GIT_INDEX_FILE": os.path.join(gitdir, "index")}
    allowed_environment = config.get("_allowed_git_environment") or {}
    git_environment = getattr(repo, "git_environment", None)
    git_environment = os.environ if git_environment is None else git_environment
    redirected = []
    for key, destination in expected.items():
        value = git_environment.get(key)
        if not value:
            continue
        allowed = allowed_environment.get(key)
        if allowed and _environment_matches(key, value, allowed):
            continue
        actual = value if os.path.isabs(value) else os.path.join(root, value)
        if os.path.normcase(os.path.realpath(actual)) != os.path.normcase(os.path.realpath(destination)):
            redirected.append(key)
    for key in ("GIT_COMMON_DIR", "GIT_NAMESPACE", "GIT_REPLACE_REF_BASE", "GIT_GRAFT_FILE",
                "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"):
        value = git_environment.get(key)
        if not value:
            continue
        allowed = allowed_environment.get(key)
        if allowed and _environment_matches(key, value, allowed):
            continue
        redirected.append(key)
    if redirected:
        repo.read_errors.append("Git environment redirects repository/index scope: " + ", ".join(redirected))
        return _incomplete_state(state, repo, config, started)

    try:
        _readonly_index_admission(repo)
    except (OSError, ValueError, RuntimeError) as exc:
        repo.read_errors.append(str(exc))
        return _incomplete_state(state, repo, config, started)

    # topology (#3): own repo vs tracked-inside-a-parent (half-extracted standalone)
    top = repo.toplevel()
    if top and os.path.normcase(os.path.realpath(top)) != os.path.normcase(os.path.realpath(root)):
        state["topology"] = {
            "kind": "tracked_inside_parent",
            "toplevel": top,
            "note": (f"'{state['root_name']}' is NOT its own git repo - it is tracked "
                     f"inside {top}. git commands run here operate on that PARENT repo, "
                     f"so every field below reflects the parent, not this folder. "
                     "Request the actual repository root before a Git action."),
        }
        parent = build_state(GitRepo(top), config)
        parent["requested_root"] = root
        parent["topology"] = state["topology"]
        parent["scores"] = compute_scores(parent)
        parent["actions"] = {name: assess_action(parent, name) for name in parent.get("actions", {})}
        if config.get("operation") in REF_ACTIONS:
            requested_action(parent, config["operation"], config.get("target"), config.get("expected_binding"))
        parent["closeout"] = closeout_state(parent)
        return parent
    else:
        state["topology"] = {"kind": "own_repo", "toplevel": top or root}
    if not top:
        repo.read_errors.append("Repository root could not be resolved")
    status_permitted = True
    if config.get("operation") in REF_ACTIONS:
        try:
            state["ref_inspection_preflight"] = _ref_inspection_preflight(repo)
        except (OSError, ValueError, RuntimeError, TypeError, KeyError) as exc:
            status_permitted = False
            repo.read_errors.append(str(exc))
    st = repo.status() if status_permitted else {
        **state["status"], "oid": None, "ok": False, "complete": False,
        "submodules": [], "ahead_behind_known": False,
        "error": "Read-only ref inspection preflight failed; status filters were not invoked.",
    }
    state["has_commits"] = bool(st.get("oid") and st["oid"] != "(initial)")
    state["status"] = st
    if st.get("ok") is False or st.get("complete") is False:
        state["read_complete"] = False
        state["read_errors"] = [st.get("error") or "git status failed"]
    state["remotes"] = repo.remotes()
    state["last_commit"] = repo.last_commit()
    state["stashes"] = repo.stashes()
    state["unpushed"] = repo.unpushed_commits(has_upstream=bool(st.get("upstream")))
    state["local_commits_without_upstream"] = state["has_commits"] and not st.get("upstream")
    state["unpushed_commit_count"] = st.get("ahead") if st.get("ahead_behind_known") else None
    if not state["has_commits"]:
        state["unpushed_commit_count"] = 0
    if st.get("upstream") and not st.get("ahead_behind_known"):
        repo.read_errors.append("Upstream comparison is missing or unavailable")
    state["index_inventory"] = repo.index_inventory()
    state["worktrees"] = repo.worktrees()
    state["extra_worktree_count"] = max(0, len(state["worktrees"]) - 1)
    state["stale_worktree_count"] = sum(bool(w.get("prunable")) for w in state["worktrees"])
    state.update(repo.operation_markers())
    refs = repo.refs_inventory()
    state["refs_fingerprint"] = hashlib.sha256(
        json.dumps(refs, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    state["object_storage"] = repo.object_storage()
    if state["object_storage"]["complete"] is not True:
        repo.read_errors.extend(state["object_storage"]["errors"] or ["Object storage inventory incomplete"])
    if bool(refs.get("refs/stash")) != bool(state["stashes"]):
        repo.read_errors.append("Stash ref and reflog inventory disagree; hidden stash work must be preserved.")
    overlays = [name for name in refs if name.startswith("refs/replace/")]
    graft_path, graft_rc, _ = repo._required("rev-parse", "--git-path", "info/grafts")
    if not graft_rc and os.path.lexists(os.path.join(root, graft_path.rstrip("\n"))):
        overlays.append("info/grafts")
    state["history_overlays"] = overlays
    if overlays:
        repo.read_errors.append("Replacement refs or grafts make history-based recovery unproven; remove that ambiguity before acting.")
    state["upstream_is_remote_tracking_ref"] = bool(st.get("upstream") and "refs/remotes/" + st["upstream"] in refs)
    if state["has_commits"] and not state["upstream_is_remote_tracking_ref"]:
        state["local_commits_without_upstream"] = True
        state["unpushed_commit_count"] = None
    state["branch_ahead_commit_count"] = st.get("ahead") if st.get("ahead_behind_known") else None
    state["unpushed_count_scope"] = "All locally referenced commits (including tags/custom refs/worktrees), absent from all local remote-tracking refs"
    if any(name.startswith("refs/remotes/") for name in refs):
        count, count_rc, _ = repo._required("rev-list", "--count", "--all", "--not", "--remotes")
        if not count_rc and count.strip().isdigit():
            state["unpushed_commit_count"] = int(count.strip())
        else:
            state["unpushed_commit_count"] = None
            repo.read_errors.append("Local-ref commit coverage could not be counted")
    state["main_oid"] = refs.get("refs/heads/main")
    state["origin_main_oid"] = refs.get("refs/remotes/origin/main")
    state["main_equals_origin_main"] = (
        state["main_oid"] == state["origin_main_oid"]
        if state["main_oid"] and state["origin_main_oid"] else None)

    # stash triage (#2): dead/superseded vs unmerged work hiding in stashes
    sdet = [] if config.get("quick") else repo.stash_details()
    state["stashes_detail"] = sdet
    state["stash_summary"] = summarize_stashes(state["stashes"], sdet)
    if state["stash_summary"].get("inspection_complete") is False:
        err = state["stash_summary"].get("error")
        if err:
            state["read_errors"] = list(state.get("read_errors") or []) + [err]

    # Remote URL / basic SSH configuration hints; no authentication occurs here.
    rdetail = []
    for rn in state["remotes"]:
        ident = resolve_remote_identity(repo.remote_url(rn) or "")
        ident["name"] = rn
        rdetail.append(ident)
    state["remotes_detail"] = rdetail

    # push weight (#6): pack size + largest tracked blobs -> know a slow/heavy push first
    pack = None if config.get("quick") else repo.pack_size_bytes()
    blobs = [] if config.get("quick") else repo.largest_tracked_blobs(5)
    heavy_blobs = [b for b in blobs if b["size"] >= LARGE_FILE_WARN]
    state["push_weight"] = {
        "pack_bytes": pack,
        "pack_human": human_size(pack),
        "largest_blobs": [
            {"path": b["path"], "size": b["size"], "human": human_size(b["size"])}
            for b in blobs
        ],
        "assessed": not config.get("quick", False),
        "heavy": (bool(heavy_blobs) or pack >= 100_000_000) if pack is not None else None,
        "heavy_note": (
            f"{human_size(pack)} of objects; heavy tracked files: "
            + ", ".join(f"{b['path']} ({human_size(b['size'])})" for b in heavy_blobs[:3])
        ) if heavy_blobs else None,
    }

    # branches
    branches = repo.branches()
    state["branches"] = branches
    default = repo.default_branch()
    state["default_branch"] = default
    merged = repo.merged_branches(default) if default else set()
    side = []
    for b in branches:
        if default and b["name"] == default:
            continue
        b2 = dict(b)
        b2["merged_into_default"] = b["name"] in merged if default else None
        b2["pushed"] = bool(b["upstream"] and "refs/remotes/" + b["upstream"] in refs
                            and not re.search(r"ahead|gone", b["track"]))
        b2["pushed_basis"] = "local_tracking_ref_only"
        side.append(b2)
    state["side_branches"] = side

    # ignored
    ignored = repo.ignored_entries()
    state["untracked_inventory"] = repo.untracked_entries()
    state["ignored"] = ignored[:500]
    state["ignored_count"] = len(ignored)

    # Assemble the dirty/staged/untracked/conflict file list. Ordinary status
    # deliberately does not inspect file bytes for secrets.
    files = []
    seen = set()
    staged_sizes = repo.staged_blob_sizes(st["staged"])

    def add_file(path, category, **extra):
        if path in seen:
            # merge categories: prefer the "worst"
            for f in files:
                if f["path"] == path:
                    f.update({k: v for k, v in extra.items() if v})
                    return
        seen.add(path)
        full = os.path.join(root, path.rstrip("/"))
        working_size = None
        try:
            info = os.lstat(full)
            if stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                working_size = info.st_size
        except FileNotFoundError:
            if category in ("new", "junk"):
                repo.read_errors.append("An untracked path disappeared during inventory")
        except OSError:
            repo.read_errors.append("A working path could not be inspected")
        staged_size = staged_sizes.get(extra.get("oid")) if category == "staged" else None
        # A staged Git LFS asset is a small pointer in the index and an expanded
        # payload in the working tree. Commit risk must measure what Git will
        # actually record, while retaining the working size for visibility.
        size = staged_size if staged_size is not None else working_size
        entry = {
            "path": path, "category": category, "size": size,
            "working_size": working_size, "staged_size": staged_size,
            "large": bool(size and size >= LARGE_FILE_WARN),
            "huge": bool(size and size >= LARGE_FILE_CRIT),
            "artifact_candidate": artifact_hint(path),
        }
        entry.update(extra)
        files.append(entry)

    for s in st["staged"]:
        add_file(s["path"], "staged", staged=True, x=s.get("x"), mode=s.get("mode"), oid=s.get("oid"))
    for m in st["modified"]:
        add_file(m["path"], "modified", modified=True, y=m.get("y"))
    for c in st["conflicts"]:
        add_file(c, "conflict", conflict=True)
    for u in st["untracked"]:
        cat = classify_untracked(root, u)
        add_file(u, cat, untracked=True)

    mark_established_paths(repo, files)
    state["files"] = files


    # gitignore suggestions: junk present and not already ignored
    suggestions = []
    present = set()
    for f in files:
        if not f.get("untracked") or not f.get("artifact_candidate"):
            continue
        base = f["path"].rstrip("/").split("/")[-1]
        # find a suggestion key contained in the path
        for key, pat in GITIGNORE_SUGGESTIONS.items():
            if key == base or key in f["path"].split("/"):
                if pat not in present and pat not in _read_gitignore_lines(root):
                    suggestions.append({"pattern": pat, "reason": f"untracked {f['path']}"})
                    present.add(pat)
                break
    state["gitignore_suggestions"] = suggestions

    # Recheck the observed state so an intervening Git edit is not silently mixed
    # into a snapshot. This detects changes during inspection, not future writers.
    if status_permitted and repo.status() != st:
        repo.read_errors.append("Git status changed during inspection; refresh before acting")
    if repo.refs_inventory() != refs:
        repo.read_errors.append("Git refs changed during inspection; refresh before acting")
    if repo.object_storage() != state["object_storage"]:
        repo.read_errors.append("Git object storage or maintenance configuration changed during inspection; refresh before acting")
    if repo.index_inventory()["fingerprint"] != state["index_inventory"]["fingerprint"]:
        repo.read_errors.append("Git index changed during inspection; refresh before acting")
    if repo.ignored_entries() != ignored:
        repo.read_errors.append("Ignored paths changed during inspection; refresh before acting")
    if repo.untracked_entries() != state["untracked_inventory"]:
        repo.read_errors.append("Untracked paths changed during inspection; refresh before acting")
    if repo.stashes() != state["stashes"]:
        repo.read_errors.append("Stash inventory changed during inspection; refresh before acting")
    if repo.worktrees() != state["worktrees"]:
        repo.read_errors.append("Worktree inventory changed during inspection; refresh before acting")
    markers = repo.operation_markers()
    if any(state[key] != value for key, value in markers.items()):
        repo.read_errors.append("Git operation state changed during inspection; refresh before acting")
    if status_permitted and repo.status() != st:
        repo.read_errors.append("Working-tree state changed at the final observation; refresh before acting")
    state["consistency"] = "Repeated metadata observations, not an atomic filesystem snapshot or a lock on future writers."
    state["read_errors"] = list(dict.fromkeys(state["read_errors"] + repo.read_errors))
    state["read_complete"] = bool(state["read_complete"] and not state["read_errors"])
    state["scores"] = compute_scores(state)
    state["actions"] = {name: assess_action(state, name) for name in (
        "commit_index", "discard_tracked", "clean_untracked", "clean_ignored",
        "maintain_objects", *REF_ACTIONS)}
    if config.get("operation") in REF_ACTIONS:
        try:
            state["ref_operation_inputs"], _ = _ref_operation_inputs(repo, state)
        except (OSError, ValueError, RuntimeError, TypeError, KeyError) as exc:
            state["ref_operation_errors"] = [str(exc)]
        requested_action(state, config["operation"], config.get("target"), config.get("expected_binding"))
    state["closeout"] = closeout_state(state)
    state["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
    return state


def _read_gitignore_lines(root: str) -> set[str]:
    p = os.path.join(root, ".gitignore")
    if not os.path.isfile(p):
        return set()
    try:
        with open(p, "r", errors="replace") as fh:
            return {l.strip() for l in fh if l.strip() and not l.strip().startswith("#")}
    except Exception:  # noqa: BLE001
        return set()


def add_to_gitignore(root: str, pattern: str) -> bool:
    pattern = pattern.strip()
    if not pattern or any(c in pattern for c in ("\n", "\r", "\0")):
        return False
    if os.path.islink(os.path.join(root, ".gitignore")):
        return False
    existing = _read_gitignore_lines(root)
    if pattern in existing:
        return True
    p = os.path.join(root, ".gitignore")
    try:
        prefix = ""
        if os.path.isfile(p):
            with open(p, "rb") as fh:
                data = fh.read()
            if data and not data.endswith(b"\n"):
                prefix = "\n"
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(f"{prefix}{pattern}\n")
        return True
    except Exception:  # noqa: BLE001
        return False


# ----------------------------------------------------------------------------
# HTML dashboard (self-contained; live-polls /api/state, falls back to embedded)
# ----------------------------------------------------------------------------
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GIT_REAL - __ROOT_NAME__</title>
<style>
:root{
  /* OPUS5 DESIGN — remapped by MEANING, not hue. Clean/safe burns signal-lime (verified),
     needs-attention glows violet (inferred), unsafe is coral (live risk), inert is slate. */
  --void:#06070d; --cyan:#c9f24d; --green:#c9f24d; --electric:#c9f24d; --git:#8b6cff;
  --ice:#c9f24d; --amber:#8b6cff; --bad:#ff5f56; --bad-deep:#ff5f56; --grey:#5d6480;
  --ink:#eef0f6; --muted:#8b90a6;
  --glass:#0f1220; --line:#1e2338; --gline:#2b3352;
  --good:#c9f24d; --warn:#8b6cff;
  --lift:none;
  --blue:#c9f24d; --blue-bright:#c9f24d; --panel:#0f1220; --panel2:#141829;
  --signal:#c9f24d; --infer:#8b6cff; --unknown:#5d6480; --alert:#ff5f56; --faint:#565d75;
  --mono:ui-monospace,'SF Mono','JetBrains Mono',Menlo,Consolas,monospace;
  --sans:'Archivo','Inter',system-ui,-apple-system,sans-serif;
}
*{box-sizing:border-box;min-width:0}
body{margin:0;background:var(--void);color:var(--ink);font-family:var(--mono);font-size:14px;
  line-height:1.5;padding:22px;min-height:100vh;position:relative;letter-spacing:.01em}
/* OVERDRIVE background layers (fixed, behind scrolling content) */
#core{position:fixed;inset:0;z-index:0;pointer-events:none}
.aurora{position:fixed;inset:-25%;z-index:0;filter:blur(86px);opacity:.34;pointer-events:none}
.aurora b{position:absolute;border-radius:50%;mix-blend-mode:screen;display:block}
.aurora .b1{width:48vw;height:48vw;background:radial-gradient(circle,#0156EE 0,transparent 66%);top:-14%;left:-8%;animation:f1 23s ease-in-out infinite}
.aurora .b2{width:42vw;height:42vw;background:radial-gradient(circle,#09E1E5 0,transparent 66%);bottom:4%;right:-8%;animation:f2 27s ease-in-out infinite}
.aurora .b3{width:40vw;height:40vw;background:radial-gradient(circle,#02EAA3 0,transparent 66%);bottom:-18%;left:20%;animation:f1 25s ease-in-out infinite}
@keyframes f1{50%{transform:translate(6vw,5vh) scale(1.12)}}
@keyframes f2{50%{transform:translate(-6vw,7vh) scale(1.1)}}
.bgrid{position:fixed;inset:0;z-index:0;pointer-events:none;
  background:linear-gradient(rgba(10,150,250,.12) 1px,transparent 1px) 0 0/100% 42px,linear-gradient(90deg,rgba(10,150,250,.12) 1px,transparent 1px) 0 0/42px 100%;
  mask:radial-gradient(circle at 50% 22%,#000 46%,transparent 100%);animation:drift 24s linear infinite}
@keyframes drift{to{background-position:0 42px,42px 0}}
.bscan{position:fixed;inset:0;z-index:0;pointer-events:none;background:repeating-linear-gradient(0deg,rgba(9,225,229,.03) 0 2px,transparent 2px 4px);mix-blend-mode:screen}
.frame{position:fixed;inset:10px;z-index:5;pointer-events:none}
.frame i{position:absolute;width:24px;height:24px;border:2px solid var(--cyan);opacity:.5;filter:drop-shadow(0 0 6px var(--cyan))}
.frame i:nth-child(1){top:0;left:0;border-right:0;border-bottom:0}.frame i:nth-child(2){top:0;right:0;border-left:0;border-bottom:0}
.frame i:nth-child(3){bottom:0;left:0;border-right:0;border-top:0}.frame i:nth-child(4){bottom:0;right:0;border-left:0;border-top:0}
a{color:var(--cyan);text-decoration:none}
h1,h2,h3{font-family:var(--mono);font-weight:700;letter-spacing:.04em;margin:0}
.clip{clip-path:none}
.wrap{max-width:1200px;margin:0 auto;position:relative;z-index:2}
header{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:6px}
.logo{font-family:var(--mono);font-size:23px;font-weight:800;letter-spacing:.12em;color:#fff;text-shadow:0 0 22px rgba(9,225,229,.7)}
.logo b{color:var(--green);text-shadow:0 0 20px rgba(2,234,163,.9)}
.tag{color:var(--muted);font-size:12px;font-family:var(--mono)}
.path{font-family:var(--mono);font-size:12px;color:var(--muted);word-break:break-all;margin:2px 0 16px}
.slogan{font-family:var(--mono);font-size:12px;color:var(--ice);opacity:.85;margin-left:auto}
.grid{display:grid;gap:15px}
.panel{background:var(--glass);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
  border:1px solid var(--gline);border-radius:16px;padding:16px 18px;
  box-shadow:var(--lift),inset 0 1px 0 rgba(255,255,255,.1)}
.panel h2{font-size:12px;letter-spacing:.18em;color:var(--ice);text-transform:uppercase;margin-bottom:12px;
  display:flex;align-items:center;gap:8px}
.scores{grid-template-columns:1fr 1fr}
.gauge{display:flex;align-items:center;gap:18px}
.dial{--p:0;--c:var(--green);width:112px;height:112px;border-radius:50%;flex:0 0 auto;
  background:conic-gradient(var(--c) calc(var(--p)*1%),rgba(255,255,255,.05) 0);display:grid;place-items:center;
  filter:drop-shadow(0 0 16px var(--c))}
.dial::after{content:'';width:86px;height:86px;border-radius:50%;background:radial-gradient(circle at 50% 35%,#04122b,#01060f);border:1px solid rgba(255,255,255,.06)}
.dial .num{position:absolute;font-family:var(--mono);font-size:30px;font-weight:800;color:#fff;text-shadow:0 0 16px var(--c)}
.dialwrap{position:relative;display:grid;place-items:center}
/* COMMIT reactor */
.reactorbox{position:relative;width:150px;height:150px;flex:0 0 auto;display:grid;place-items:center}
.reactorbox canvas{position:absolute;inset:0;width:100%;height:100%}
.reactorbox .rnum{position:relative;z-index:2;font-family:var(--mono);font-size:44px;font-weight:800;color:#fff;text-shadow:0 0 26px var(--rc,#FF3B5C),0 3px 12px rgba(0,0,0,.85)}
.reactorbox::before{content:'';position:absolute;width:118px;height:118px;border-radius:50%;background:radial-gradient(circle,rgba(2,3,14,.6) 30%,transparent 72%)}
.scoremeta{min-width:0}
.scoremeta .label{font-family:var(--mono);font-size:16px;font-weight:800;letter-spacing:.03em;margin-bottom:4px}
.scoremeta .sub{color:var(--muted);font-size:12px;margin-bottom:8px}
.reasons{list-style:none;padding:0;margin:0;font-size:12px;color:var(--ink)}
.reasons li{padding:3px 0 3px 14px;position:relative;color:#c4d2e6}
.reasons li::before{content:'›';position:absolute;left:0;color:var(--cyan)}
.go{color:var(--good)} .caution{color:var(--warn)} .stop{color:var(--bad)}
.alert{border:1px solid rgba(255,59,92,.55);border-radius:14px;background:linear-gradient(90deg,rgba(255,59,92,.2),rgba(255,59,92,.04));
  display:flex;align-items:center;gap:14px;padding:14px 18px;margin-bottom:15px;box-shadow:var(--lift),0 0 28px rgba(255,59,92,.32)}
.tri{font-size:28px;color:var(--bad-deep);animation:blink 1s steps(2,start) infinite;line-height:1}
@keyframes blink{50%{opacity:.2}}
.alert .txt b{color:#fff;font-family:var(--mono);letter-spacing:.03em}
.alert .txt{font-size:13px}
.cols{grid-template-columns:1fr 1fr}
.cols3{grid-template-columns:1fr 1fr 1fr}
.stat{display:flex;justify-content:space-between;align-items:baseline;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.06)}
.stat:last-child{border-bottom:none}
.stat .k{color:var(--muted);font-size:12px;font-family:var(--mono)}
.stat .v{font-family:var(--mono);font-size:14px}
.flist{list-style:none;padding:0;margin:0;max-height:260px;overflow:auto}
.flist li{display:flex;align-items:center;gap:8px;padding:6px;border-bottom:1px solid rgba(255,255,255,.05);font-size:12.5px}
.flist li:hover{background:rgba(40,70,120,.3)}
.badge{font-family:var(--mono);font-size:10px;font-weight:700;padding:2px 7px;border-radius:5px;letter-spacing:.05em;flex:0 0 auto}
.b-dirty{background:rgba(10,150,250,.16);color:var(--electric);border:1px solid rgba(10,150,250,.5)}
.b-staged{background:rgba(2,234,163,.14);color:var(--green);border:1px solid rgba(2,234,163,.5)}
.b-new{background:rgba(9,225,229,.14);color:var(--cyan);border:1px solid rgba(9,225,229,.5);box-shadow:0 0 10px rgba(9,225,229,.3)}
.b-junk{background:rgba(120,136,168,.14);color:var(--grey);border:1px solid rgba(120,136,168,.4)}
.b-conflict{background:rgba(255,59,92,.16);color:var(--bad);border:1px solid rgba(255,59,92,.5)}
.b-secret{background:var(--bad);color:#fff;box-shadow:0 0 12px rgba(255,59,92,.6);animation:blink 1.1s steps(2,start) infinite}
.b-large{background:rgba(184,139,224,.16);color:#b88be0;border:1px solid rgba(184,139,224,.4)}
.fpath{font-family:var(--mono);word-break:break-all;flex:1 1 auto}
.fsize{color:var(--muted);font-size:11px;flex:0 0 auto}
.empty{color:var(--muted);font-size:12px;font-style:italic;padding:6px 0}
.addrow{display:flex;gap:8px;margin-top:10px}
.addrow input{flex:1;background:rgba(2,9,22,.6);border:1px solid var(--line);color:var(--ink);
  font-family:var(--mono);font-size:12px;padding:8px 10px;outline:none;border-radius:8px}
.addrow input:focus{border-color:var(--cyan)}
button{font-family:var(--mono);font-size:12px;letter-spacing:.04em;cursor:pointer;border-radius:8px;
  background:var(--git);color:#fff;border:none;padding:8px 14px;font-weight:700;box-shadow:0 0 16px rgba(1,86,238,.4)}
button:hover{background:var(--electric)}
button.ghost{background:transparent;border:1px solid var(--line);color:var(--ink);box-shadow:none}
button.ghost:hover{border-color:var(--cyan);color:#fff}
button.warn{background:var(--warn);color:#1a1206;box-shadow:0 0 16px rgba(255,176,32,.4)}
.sugg{display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.06)}
.sugg code{font-family:var(--mono);background:rgba(2,9,22,.6);padding:2px 7px;border:1px solid var(--line);font-size:12px;border-radius:5px}
.sugg .why{color:var(--muted);font-size:11px;flex:1}
.branchrow{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid rgba(255,255,255,.05);font-size:12.5px}
.dot{width:8px;height:8px;border-radius:50%;flex:0 0 auto}
.dot.merged{background:var(--good);box-shadow:0 0 8px var(--good)} .dot.unmerged{background:var(--warn);box-shadow:0 0 8px var(--warn)} .dot.main{background:var(--cyan);box-shadow:0 0 8px var(--cyan)}
.bname{font-family:var(--mono);color:#fff}
.bmeta{color:var(--ice);font-size:11px;margin-left:auto;text-align:right;font-style:italic}
.foot{display:flex;justify-content:space-between;color:var(--muted);font-size:11px;
  font-family:var(--mono);margin-top:18px;flex-wrap:wrap;gap:8px}
.live{display:inline-flex;align-items:center;gap:6px}
.pulse{width:8px;height:8px;border-radius:50%;background:var(--cyan);box-shadow:0 0 10px var(--cyan);animation:pulse 1.6s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:.35}50%{opacity:1}}
.toast{position:fixed;bottom:18px;right:18px;z-index:6;background:var(--panel2);backdrop-filter:blur(14px);border:1px solid var(--cyan);
  color:#fff;font-family:var(--mono);font-size:12px;padding:10px 14px;opacity:0;transform:translateY(8px);
  transition:.25s;border-radius:10px;box-shadow:var(--lift)}
.toast.show{opacity:1;transform:none}
.settings{display:none;margin-top:10px}
.settings.open{display:block}
.pill{font-family:var(--mono);font-size:10px;padding:2px 8px;border:1px solid var(--line);color:var(--ice);border-radius:20px}
@media(max-width:820px){.scores,.cols,.cols3{grid-template-columns:1fr}}

/* ===== OPUS5 DESIGN skin — appended override. Instrument behaviour untouched.
   The aurora blobs and glass blur were the old identity; OPUS5 is a flat void field
   with hard edges and mono data. ===== */
.aurora,.bgrid,.bscan{display:none!important}
body{background:var(--void)!important;font-family:var(--mono)!important}
.panel{background:var(--panel)!important;backdrop-filter:none!important;-webkit-backdrop-filter:none!important;
  border:1px solid var(--line)!important;border-radius:0!important;box-shadow:none!important}
h1,h2,h3{font-family:var(--sans)!important;font-weight:800!important;letter-spacing:-.03em!important}
button,.btn,.pill,.chip,input,select{border-radius:0!important}
</style>
</head>
<body>
<canvas id="core"></canvas>
<div class="aurora"><b class="b1"></b><b class="b2"></b><b class="b3"></b></div>
<div class="bgrid"></div><div class="bscan"></div>
<div class="frame"><i></i><i></i><i></i><i></i></div>
<div class="wrap">
  <header>
    <span class="logo">GIT<b>_</b>REAL</span>
    <span class="tag">v__VERSION__ · situational awareness</span>
    <span class="slogan">Get real about your repo - never debug another agent's dirty tree.</span>
  </header>
  <div class="path" id="rootpath"></div>

  <div id="alertbox"></div>

  <div class="grid scores" style="margin-bottom:14px">
    <div class="panel clip" id="commitcard"></div>
    <div class="panel clip" id="deletecard"></div>
  </div>

  <div class="grid cols3" style="margin-bottom:14px">
    <div class="panel clip"><h2>Branch &amp; Push</h2><div id="branchstat"></div></div>
    <div class="panel clip"><h2>Repository</h2><div id="repostat"></div></div>
    <div class="panel clip"><h2>Stashes &amp; Remotes</h2><div id="miscstat"></div></div>
  </div>

  <div class="grid cols" style="margin-bottom:14px">
    <div class="panel clip">
      <h2>Working Tree <span class="pill" id="dirtycount"></span></h2>
      <ul class="flist" id="dirtylist"></ul>
    </div>
    <div class="panel clip">
      <h2>Branches <span class="pill" id="branchcount"></span></h2>
      <div id="branchlist"></div>
    </div>
  </div>

  <div class="grid cols" style="margin-bottom:14px">
    <div class="panel clip">
      <h2>.gitignore Suggestions</h2>
      <div id="suggestions"></div>
    </div>
    <div class="panel clip">
      <h2>Ignored <span class="pill" id="ignoredcount"></span></h2>
      <ul class="flist" id="ignoredlist"></ul>
    </div>
  </div>

  <div class="panel clip" style="margin-bottom:14px">
    <h2>Settings <button class="ghost" style="margin-left:auto;padding:4px 10px" onclick="toggleSettings()">toggle</button></h2>
    <div class="settings" id="settings">
      <div class="stat"><span class="k">Output JSON (for agents)</span><span class="v"><code>.git-real/git-real.json</code></span></div>
      <div class="stat"><span class="k">Refresh interval</span><span class="v" id="setinterval"></span></div>
      <p class="empty">Read-only dashboard. Agents read <code>.git-real/git-real.json</code> or query <code>GET /api/state</code>. To change the repo (gitignore, mute, init) use the CLI or the GIT_REAL MCP &mdash; the dashboard never writes.</p>
    </div>
  </div>

  <div class="foot">
    <span class="live"><span class="pulse"></span> live · updated <span id="updated"></span></span>
    <span id="reposcope"></span>
  </div>
</div>
<div class="toast" id="toast"></div>

<script>
const EMBEDDED = __STATE_JSON__;
const PORT = __PORT__;
let STATE = EMBEDDED;

function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function bandClass(b){return b==='GO'?'go':(b==='CAUTION'?'caution':'stop');}
function bytes(n){if(n==null)return '';const u=['B','KB','MB','GB'];let i=0,x=n;while(x>=1024&&i<3){x/=1024;i++;}return x.toFixed(x<10&&i>0?1:0)+u[i];}
function toast(m){const t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2200);}

function dial(score,band){
  const c=band==='GO'?'var(--good)':band==='CAUTION'?'var(--warn)':'var(--bad)';
  return `<div class="dialwrap"><div class="dial" style="--p:${score};--c:${c}"></div><span class="num">${score}</span></div>`;
}
function scoreCard(title,score,band,label,reasons,sub){
  return `<h2>${title}</h2><div class="gauge">${dial(score,band)}
    <div class="scoremeta"><div class="label ${bandClass(band)}">${esc(label)}</div>
    <div class="sub">${esc(sub||'')}</div>
    <ul class="reasons">${(reasons||[]).map(r=>`<li>${esc(r)}</li>`).join('')||'<li>-</li>'}</ul></div></div>`;
}

let RX={canvas:null,ctx:null,col:'255,90,110',parts:[]};
function reactorCard(title,score,band,label,reasons,sub){
  const col=band==='GO'?'2,234,163':band==='CAUTION'?'255,176,32':'255,90,110';
  return `<h2>${esc(title)}</h2><div class="gauge">
    <div class="reactorbox" style="--rc:rgb(${col})"><canvas></canvas><span class="rnum">${score==null?'-':score}</span></div>
    <div class="scoremeta"><div class="label ${bandClass(band)}">${esc(label)}</div>
    <div class="sub">${esc(sub||'')}</div>
    <ul class="reasons">${(reasons||[]).map(r=>`<li>${esc(r)}</li>`).join('')||'<li>-</li>'}</ul></div></div>`;
}
function mountReactor(band){
  RX.col=band==='GO'?'2,234,163':band==='CAUTION'?'255,176,32':'255,90,110';
  const c=document.querySelector('#commitcard .reactorbox canvas');
  if(!c){RX.canvas=null;return;} RX.canvas=c;RX.ctx=c.getContext('2d');
  if(!RX.parts.length)for(let i=0;i<70;i++)RX.parts.push({a:Math.random()*7,r:24+Math.random()*54,sp:(Math.random()*.006+.002)*(Math.random()<.5?1:-1),sz:Math.random()*1.5+.4,mix:Math.random()});
}
function reactorLoop(now){
  const c=RX.canvas,g=RX.ctx;
  if(c&&g){const b=c.getBoundingClientRect();if(b.width&&c.width!==Math.round(b.width)){c.width=Math.round(b.width);c.height=Math.round(b.height);}
    const W=c.width,H=c.height,cx=W/2,cy=H/2,t=now*.001,p=1+Math.sin(t*2)*.08,R=Math.min(W,H)*.16*p;
    g.clearRect(0,0,W,H);
    let gr=g.createRadialGradient(cx,cy,0,cx,cy,R*2.6);
    gr.addColorStop(0,'rgba('+RX.col+',.95)');gr.addColorStop(.34,'rgba('+RX.col+',.45)');gr.addColorStop(.72,'rgba('+RX.col+',.08)');gr.addColorStop(1,'rgba(0,0,0,0)');
    g.fillStyle=gr;g.beginPath();g.arc(cx,cy,R*2.6,0,7);g.fill();
    g.fillStyle='rgba(255,255,255,.45)';g.beginPath();g.arc(cx,cy,R*.32*p,0,7);g.fill();
    for(let k=0;k<3;k++){const rr=R*1.5+k*R*.55,sp=(k%2?-1:1)*(.3+k*.15);g.lineWidth=1.5;g.strokeStyle='rgba(9,225,229,'+(.5-k*.12)+')';g.shadowBlur=9;g.shadowColor='rgba(9,225,229,.7)';for(let s=0;s<5;s++){const a0=t*sp+s*1.45;g.beginPath();g.arc(cx,cy,rr,a0,a0+.9);g.stroke();}}g.shadowBlur=0;
    for(const q of RX.parts){q.a+=q.sp;const px=cx+Math.cos(q.a)*q.r,py=cy+Math.sin(q.a)*q.r*.9;const cc=q.mix<.4?'9,225,229':RX.col;g.fillStyle='rgba('+cc+',.9)';g.shadowBlur=6;g.shadowColor='rgba('+cc+',.8)';g.beginPath();g.arc(px,py,q.sz,0,7);g.fill();}g.shadowBlur=0;
  }
  requestAnimationFrame(reactorLoop);
}

function render(){
  const s=STATE, sc=s.scores||{};
  document.getElementById('rootpath').textContent=s.root||'';
  document.getElementById('commitcard').innerHTML=reactorCard('Commit review',sc.safe_commit,sc.safe_commit_band,sc.safe_commit_label,sc.safe_commit_reasons,'require actions.commit_index for the inspected index');
  mountReactor(sc.safe_commit_band);
  document.getElementById('deletecard').innerHTML=scoreCard('Preservation summary',sc.safe_delete,sc.safe_delete_band,sc.safe_delete_label,sc.safe_delete_reasons,'never authorizes deletion; request the exact operation');

  // alert (secret-byte enforcement is intentionally outside ordinary status)
  let ab=document.getElementById('alertbox'); ab.innerHTML='';
  // topology (#3): loud amber banner when this path is NOT its own repo
  const topo=s.topology||{};
  if(topo.kind==='tracked_inside_parent'){
    ab.innerHTML+=`<div class="alert clip" style="border-color:rgba(255,176,32,.55);background:linear-gradient(90deg,rgba(255,176,32,.16),rgba(255,176,32,.03))">`
      +`<span class="tri" style="color:#ffb020">&#9650;</span><div class="txt">`
      +`<b style="color:#ffb020">TOPOLOGY &mdash; not its own repo</b><br>${esc(topo.note||'This path is tracked inside a parent repo; every field reflects the parent, not this folder.')}</div></div>`;
  } else if(topo.kind==='untracked'){
    ab.innerHTML+=`<div class="alert clip" style="border-color:rgba(255,176,32,.4);background:linear-gradient(90deg,rgba(255,176,32,.1),rgba(255,176,32,.02))">`
      +`<span class="tri" style="color:#ffb020">&#9650;</span><div class="txt"><b style="color:#ffb020">Not a git repo</b><br>${esc(topo.note||'')}</div></div>`;
  }

  // branch & push
  const st=s.status||{};
  const branch=st.detached?'(detached HEAD)':(st.branch||'-');
  let bp='';
  bp+=stat('Current branch',esc(branch));
  bp+=stat('Upstream',st.upstream?esc(st.upstream):'<span class="caution">none set</span>');
  bp+=stat('Ahead / Behind',`<span class="${st.ahead?'caution':''}">${st.ahead||0}</span> / <span class="${st.behind?'caution':''}">${st.behind||0}</span>`);
  bp+=stat('Unpushed commits',`<span class="${(s.unpushed||[]).length?'caution':'go'}">${(s.unpushed||[]).length}</span>`);
  document.getElementById('branchstat').innerHTML=bp;

  // repo stat
  const dirty=(st.modified||[]).length, staged=(st.staged||[]).length, unt=(st.untracked||[]).length, conf=(st.conflicts||[]).length;
  let rs='';
  rs+=stat('Staged',`<span class="go">${staged}</span>`);
  rs+=stat('Modified (dirty)',`<span class="${dirty?'caution':''}">${dirty}</span>`);
  rs+=stat('Untracked',`<span class="${unt?'caution':''}">${unt}</span>`);
  rs+=stat('Conflicts',`<span class="${conf?'stop':'go'}">${conf}</span>`);
  rs+=stat('Last commit',s.last_commit?`${esc(s.last_commit.hash)} · ${esc(s.last_commit.when)}`:'-');
  document.getElementById('repostat').innerHTML=rs;

  // stashes (triaged) + remotes (identity) + push weight
  let ms='';
  const ss=s.stash_summary||{}, scount=ss.count||0;
  const sp=[];
  if(ss.unmerged)sp.push(`<span class="caution">${ss.unmerged} unmerged</span>`);
  if(ss.superseded)sp.push(`${ss.superseded} superseded`);
  if(ss.empty)sp.push(`<span style="color:var(--muted)">${ss.empty} empty</span>`);
  ms+=stat('Stashes',scount?`${scount} <span style="opacity:.75;font-size:11px">(${sp.join(', ')})</span>`:'<span class="go">0</span>');
  (s.stashes_detail||[]).slice(0,6).forEach(d=>{
    const vc=d.verdict==='unmerged'?'caution':(d.verdict==='superseded'?'go':'');
    const vl=d.verdict==='unmerged'?'PRESERVE':(d.verdict==='superseded'?'in HEAD':(d.verdict==='empty'?'empty':esc(d.verdict)));
    ms+=`<div class="stat"><span class="k" style="font-size:11px">${esc(d.ref)} <span style="opacity:.55">${esc((d.message||'').slice(0,22))}</span></span>`
      +`<span class="v ${vc}" style="font-size:11px">${vl} · +${d.added||0}/-${d.deleted||0}</span></div>`;
  });
  // remotes with resolved identity (which account/key a push authenticates as)
  const rd=s.remotes_detail||[];
  if(rd.length){
    rd.forEach(r=>{
      const idtxt=r.identity_file?esc(r.identity_file):(r.scheme==='https'?'https / token':'default ssh key');
      const alias=r.is_ssh_alias?` <span class="pill">alias→${esc(r.real_host||'')}</span>`:'';
      const warn=r.warning?`<span class="badge b-large" title="${esc(r.warning)}">⚠</span>`:'';
      ms+=`<div class="stat"><span class="k">${esc(r.name)} ${warn}</span>`
        +`<span class="v" style="font-size:11px">${idtxt}${alias}</span></div>`;
    });
  } else {
    ms+=stat('Remotes','<span class="caution">none</span>');
  }
  ms+=stat('Default branch',esc(s.default_branch||'-'));
  ms+=stat('Side branches',`<span class="${(s.side_branches||[]).length?'caution':''}">${(s.side_branches||[]).length}</span>`);
  const pw=s.push_weight||{};
  if(pw.pack_human)ms+=stat('Repo size (push weight)',`<span class="${pw.heavy?'caution':''}">${esc(pw.pack_human)}${pw.heavy?' ⚠ heavy':''}</span>`);
  document.getElementById('miscstat').innerHTML=ms;

  // dirty/working tree list
  const files=s.files||[];
  document.getElementById('dirtycount').textContent=files.length;
  const dl=document.getElementById('dirtylist');
  if(!files.length){dl.innerHTML='<div class="empty">Clean working tree - nothing dirty.</div>';}
  else dl.innerHTML=files.map(f=>{
    let badges='';
    const cat={staged:'b-staged',modified:'b-dirty',new:'b-new',junk:'b-junk',conflict:'b-conflict'}[f.category]||'b-dirty';
    const cname={staged:'STAGED',modified:'DIRTY',new:'NEW',junk:'JUNK',conflict:'CONFLICT'}[f.category]||'DIRTY';
    badges=`<span class="badge ${cat}">${cname}</span>`+badges;
    if(f.large)badges+='<span class="badge b-large">LARGE</span>';
    return `<li>${badges}<span class="fpath">${esc(f.path)}</span><span class="fsize">${bytes(f.size)}</span></li>`;
  }).join('');

  // branches
  const sb=s.side_branches||[];
  document.getElementById('branchcount').textContent=(s.branches||[]).length;
  const bl=document.getElementById('branchlist');
  let rows='';
  if(s.default_branch){
    const def=(s.branches||[]).find(b=>b.name===s.default_branch);
    rows+=`<div class="branchrow"><span class="dot main"></span><span class="bname">${esc(s.default_branch)}</span>
      <span class="pill">default</span><span class="bmeta">${esc(def?def.last_commit_rel:'')}</span></div>`;
  }
  sb.forEach(b=>{
    const merged=b.merged_into_default;
    const dot=merged?'merged':'unmerged';
    const tag=merged?'<span class="pill">merged</span>':'<span class="pill" style="color:var(--warn);border-color:var(--warn)">UNMERGED</span>';
    const push=b.pushed?'':'<span class="pill" style="color:var(--warn)">unpushed</span>';
    rows+=`<div class="branchrow"><span class="dot ${dot}"></span><span class="bname">${esc(b.name)}</span>${tag}${push}
      <span class="bmeta">${esc(b.last_commit_rel)}<br>${esc((b.subject||'').slice(0,40))}</span></div>`;
  });
  bl.innerHTML=rows||'<div class="empty">No branches.</div>';

  // suggestions
  const sg=s.gitignore_suggestions||[];
  const sd=document.getElementById('suggestions');
  if(!sg.length)sd.innerHTML='<div class="empty">No junk detected outside .gitignore. Clean.</div>';
  else sd.innerHTML=sg.map(x=>`<div class="sugg"><code>${esc(x.pattern)}</code>
    <span class="why">${esc(x.reason)}</span>
    <span class="why" style="opacity:.6">add to .gitignore</span></div>`).join('');

  // ignored
  const ig=s.ignored||[];
  document.getElementById('ignoredcount').textContent=s.ignored_count||0;
  const il=document.getElementById('ignoredlist');
  il.innerHTML=ig.length?ig.map(p=>`<li><span class="badge b-junk">IGNORED</span><span class="fpath">${esc(p)}</span></li>`).join(''):'<div class="empty">Nothing ignored.</div>';

  document.getElementById('updated').textContent=s.generated_at_human||'';
  document.getElementById('reposcope').textContent=`${esc(s.root_name||'')} · ${(s.files||[]).length} dirty · ${(s.side_branches||[]).length} side-branches`;
  document.getElementById('setinterval').textContent=(__INTERVAL__)+'s';
  document.title=`GIT_REAL - ${s.root_name||''} (${(s.scores||{}).safe_commit||0}/${(s.scores||{}).safe_delete||0})`;
}

function stat(k,v){return `<div class="stat"><span class="k">${esc(k)}</span><span class="v">${v}</span></div>`;}

async function refresh(){
  try{
    const r=await fetch(`http://127.0.0.1:${PORT}/api/state`,{cache:'no-store'});
    if(r.ok){STATE=await r.json();render();}
  }catch(e){/* offline static file - keep embedded snapshot */}
}
function toggleSettings(){document.getElementById('settings').classList.toggle('open');}

render();
(function(){const cv=document.getElementById('core');if(!cv)return;const g=cv.getContext('2d');let W,H;
function rs(){W=cv.width=innerWidth;H=cv.height=innerHeight;}rs();addEventListener('resize',rs);
const sf=[];for(let i=0;i<70;i++)sf.push({x:Math.random(),y:Math.random(),v:.0002+Math.random()*.0006,r:Math.random()*1.4+.3,c:Math.random()<.5?'9,225,229':'2,234,163',a:Math.random()*.4+.1});
(function bg(){g.clearRect(0,0,W,H);for(const s of sf){s.y-=s.v;if(s.y<0)s.y=1;g.beginPath();g.arc(s.x*W,s.y*H,s.r,0,7);g.fillStyle='rgba('+s.c+','+s.a+')';g.shadowBlur=5;g.shadowColor='rgba('+s.c+',.7)';g.fill();}g.shadowBlur=0;requestAnimationFrame(bg);})();})();
requestAnimationFrame(reactorLoop);
setInterval(refresh,Math.max(1500,__INTERVAL__*1000));
refresh();
</script>
</body>
</html>"""


def json_for_script(obj) -> str:
    """JSON safe to embed inside a <script> element (no raw HTML specials)."""
    return (
        json.dumps(obj, ensure_ascii=False)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def html_text(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def render_html(state: dict, port: int, interval: float) -> str:
    page = HTML_TEMPLATE
    page = page.replace("__STATE_JSON__", json_for_script(state))
    page = page.replace("__PORT__", str(port))
    page = page.replace("__INTERVAL__", str(interval))
    page = page.replace("__VERSION__", html_text(VERSION))
    page = page.replace("__ROOT_NAME__", html_text(state.get("root_name", "repo")))
    return page


# ----------------------------------------------------------------------------
# app state + output writing
# ----------------------------------------------------------------------------
def atomic_write_text(path: str, content: str):
    """Publish a complete snapshot or raise; never report a stale file as fresh."""
    parent = os.path.dirname(os.path.abspath(path))
    if os.path.islink(path) or os.path.islink(parent):
        raise OSError("Refusing a symlinked GIT_REAL output destination")
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=parent,
                                         prefix=".gitreal-", delete=False) as fh:
            temp_path = fh.name
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp_path, path)
        temp_path = None
    finally:
        if temp_path is not None:
            os.unlink(temp_path)  # Only our own unpublished temporary file.


class App:
    def __init__(self, root: str, port: int, interval: float):
        self.repo = GitRepo(root)
        self.root = self.repo.root
        self.port = port
        self.interval = interval
        self.outdir = os.path.join(self.root, OUTPUT_DIRNAME)
        if os.path.islink(self.outdir):
            raise OSError("Refusing a symlinked GIT_REAL output directory")
        self.config = self._load_config()
        self.state = {}
        self.lock = threading.Lock()
        os.makedirs(self.outdir, exist_ok=True)
        # make our own output dir self-ignoring so it never pollutes the tree
        gi = os.path.join(self.outdir, ".gitignore")
        if not os.path.exists(gi):
            try:
                with open(gi, "w") as fh:
                    fh.write("*\n")
            except Exception:  # noqa: BLE001
                pass

    def _config_path(self):
        return os.path.join(self.outdir, "config.json")

    def _load_config(self):
        p = os.path.join(self.root, OUTPUT_DIRNAME, "config.json")
        if os.path.isfile(p):
            try:
                with open(p) as fh:
                    value = json.load(fh)
                    return value if isinstance(value, dict) else {}
            except Exception:  # noqa: BLE001
                pass
        return {}

    def _save_config(self):
        try:
            with open(self._config_path(), "w") as fh:
                json.dump(self.config, fh, indent=2)
        except Exception:  # noqa: BLE001
            pass

    def rescan(self):
        with self.lock:
            self.state = build_state(self.repo, self.config)
            self._write_outputs()
            return self.state

    def _write_outputs(self):
        atomic_write_text(os.path.join(self.outdir, "git-real.json"),
                          json.dumps(self.state, indent=2) + "\n")
        if not self.config.get("quick"):
            atomic_write_text(os.path.join(self.outdir, "git-real.html"),
                              render_html(self.state, self.port, self.interval))

    def get_state(self):
        with self.lock:
            return self.state


# ----------------------------------------------------------------------------
# HTTP server
# ----------------------------------------------------------------------------
def make_handler(app: App):
    import urllib.parse

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            port = self.server.server_port
            hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
            if port == 80:
                hosts.update({"127.0.0.1", "localhost"})
            host_values = self.headers.get_all("Host", [])
            origins = self.headers.get_all("Origin", [])
            if (len(host_values) != 1 or host_values[0].strip().lower() not in hosts
                    or len(origins) > 1
                    or (origins and origins[0].strip().lower() not in {"http://" + h for h in hosts})):
                self._send(403, json.dumps({"error": "local dashboard origin required"}))
                return
            try:
                parsed = urllib.parse.urlsplit(self.path)
            except ValueError:
                self._send(400, json.dumps({"error": "invalid request target"}))
                return
            if parsed.scheme or parsed.netloc or "#" in self.path:
                self._send(404, json.dumps({"error": "not found"}))
            elif parsed.path in ("/", "/index.html"):
                self._send(200, render_html(app.get_state(), port, app.interval), "text/html; charset=utf-8")
            elif parsed.path == "/api/state":
                self._send(200, json.dumps(app.get_state()))
            else:
                self._send(404, json.dumps({"error": "not found"}))

        # Read-only dashboard: no write endpoints or cross-origin permission.

    return Handler


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ----------------------------------------------------------------------------
# watchers
# ----------------------------------------------------------------------------
def _should_ignore_event(path: str) -> bool:
    norm = path.replace("\\", "/")
    return ("/.git/" in norm or norm.endswith("/.git")
            or f"/{OUTPUT_DIRNAME}/" in norm or norm.endswith(f"/{OUTPUT_DIRNAME}"))


def start_watchdog(app: App):
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler

    timer = {"t": None}
    stopped = threading.Event()
    timer_lock = threading.Lock()

    def debounced():
        with timer_lock:
            if stopped.is_set():
                return
        # A rescan already admitted here may finish after stop; cancellation
        # cannot roll back an in-flight observation or publication.
        app.rescan()

    class H(FileSystemEventHandler):
        def on_any_event(self, event):
            if _should_ignore_event(getattr(event, "src_path", "")):
                return
            with timer_lock:
                if stopped.is_set():
                    return
                if timer["t"]:
                    timer["t"].cancel()
                timer["t"] = threading.Timer(DEBOUNCE_SECONDS, debounced)
                timer["t"].daemon = True
                timer["t"].start()

    obs = Observer()
    observer_stop, observer_join = obs.stop, obs.join

    def stop():
        with timer_lock:
            stopped.set()
            if timer["t"]:
                timer["t"].cancel()
        observer_stop()

    def join(timeout=None):
        deadline = None if timeout is None else time.monotonic() + max(0, timeout)
        observer_join(timeout=timeout)
        with timer_lock:
            pending = timer["t"]
        if pending is not None:
            remaining = None if deadline is None else max(0, deadline - time.monotonic())
            try:
                pending.join(timeout=remaining)
            except RuntimeError:
                pass  # A timer whose start failed has no running thread to join.

    obs.stop, obs.join = stop, join
    try:
        obs.schedule(H(), app.root, recursive=True)
        obs.daemon = True
        obs.start()
    except BaseException:
        obs.stop()
        try:
            obs.join(timeout=2)
        except RuntimeError:
            pass  # The observer itself may not have started.
        raise
    return obs


def start_polling(app: App, stop_event: threading.Event):
    def loop():
        while not stop_event.is_set():
            try:
                # The full builder owns filter/storage admission. A raw status
                # shortcut could execute a filter before that boundary is checked.
                app.rescan()
            except Exception:  # noqa: BLE001
                pass
            stop_event.wait(app.interval)
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t


# ============================================================================
# FLEET MODE  (multi-repo command center)  --  the 8-12 worktree wall
# ============================================================================
SKIP_WALK_DIRS = JUNK_DIR_NAMES | {".git", OUTPUT_DIRNAME, ".hg", ".svn", ".idea"}


def load_registry_repo_paths(repos_file: str, *, relative_root: str | None = None) -> list[str]:
    """Load explicit fleet authority; malformed entries never widen discovery."""
    fd = os.open(repos_file, os.O_RDONLY | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("repos file must be a regular JSON file")
        with os.fdopen(fd, encoding="utf-8") as fh:
            fd = None
            data = json.load(fh)
    finally:
        if fd is not None:
            os.close(fd)
    paths, seen = [], set()

    def add(raw):
        if not isinstance(raw, str) or not raw or "\0" in raw:
            raise ValueError("repository paths must be nonempty strings without NUL")
        expanded = os.path.expanduser(raw)
        if relative_root is not None and not os.path.isabs(expanded):
            expanded = os.path.join(relative_root, expanded)
        path = os.path.abspath(expanded)
        if path not in seen:
            seen.add(path)
            paths.append(path)

    if isinstance(data, dict) and "repositories" in data:
        if not isinstance(data["repositories"], list):
            raise ValueError("repositories must be a list")
        for row in data["repositories"]:
            if not isinstance(row, dict):
                raise ValueError("repository entries must be objects")
            enabled = row.get("discovery_enabled", True)
            if not isinstance(enabled, bool):
                raise ValueError("discovery_enabled must be boolean")
            if enabled:
                add(row.get("physical_location"))
        return paths
    if isinstance(data, dict) and isinstance(data.get("repos"), list):
        for raw in data["repos"]:
            add(raw)
        return paths
    raise ValueError("repos file must contain repositories[] or repos[]")


def discover_all_git(root: str, max_depth: int = 4) -> list[str]:
    """Bounded git discovery that keeps descending into nested repositories.

    This is a drift signal, not fleet authority. It records every `.git` found
    up to max_depth instead of stopping at the first nested repository.
    """
    root = os.path.abspath(root)
    found, seen = [], set()
    base = root.rstrip("/").count("/")
    def walk_error(error):
        raise error

    for dirpath, dirnames, filenames in os.walk(root, onerror=walk_error):
        depth = dirpath.rstrip("/").count("/") - base
        if depth > max_depth:
            dirnames[:] = []
            continue
        has_git = ".git" in dirnames or ".git" in filenames
        dirnames[:] = [d for d in dirnames if d not in SKIP_WALK_DIRS]
        if has_git:
            p = os.path.abspath(dirpath)
            if p not in seen:
                seen.add(p)
                found.append(p)
    return found


def registry_fleet_paths(root: str, registered: list[str], max_depth: int = 4) -> dict:
    """Use registered paths as fleet authority and disk discovery as drift."""
    present = []
    missing = []
    seen = set()
    for raw in registered:
        path = os.path.abspath(raw)
        if path in seen:
            continue
        seen.add(path)
        if os.path.exists(os.path.join(path, ".git")):
            present.append(path)
        else:
            missing.append(path)
    disk = [os.path.abspath(p) for p in discover_all_git(root, max_depth=max_depth)]
    registered_set = set(present) | set(missing)
    unregistered = [p for p in disk if p not in registered_set]
    return {
        "registered": list(seen),
        "present": present,
        "missing": missing,
        "disk": disk,
        "drift_missing": missing,
        "drift_unregistered": unregistered,
    }


def discover_repos(root: str, max_depth: int = 4, pinned=None) -> list[str]:
    """Walk `root` (bounded depth) collecting git repos.

    If `root` is itself a git repo, it is recorded AND discovery keeps descending
    to find nested/embedded repos - the workspace-of-repos case (a monorepo root
    full of standalones, e.g. _MAIN). Nested repos are recorded but not descended
    into. Previously the walk halted at the first `.git`, so a repo-root returned
    only itself and every nested standalone was invisible.
    """
    root = os.path.abspath(root)
    found, seen = [], set()

    # <root>/.gitreal-fleet-ignore: a gitignore for the FLEET SCAN. One relative
    # path per line, '#' comments. A listed repo is invisible to discovery -- for
    # local-only archives Dan never wants in the fleet picture. The parent repo's
    # real .gitignore cannot be this signal: _MAIN gitignores every standalone.
    fleet_ignored = set()
    try:
        with open(os.path.join(root, ".gitreal-fleet-ignore"), encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    fleet_ignored.add(os.path.abspath(os.path.join(root, line)))
    except FileNotFoundError:
        pass

    def add(path):
        p = os.path.abspath(path)
        if p not in seen and p not in fleet_ignored:
            seen.add(p)
            found.append(p)

    if pinned:
        for p in pinned:
            p = os.path.expanduser(p)
            pp = p if os.path.isabs(p) else os.path.join(root, p)
            if os.path.isdir(pp) and os.path.exists(os.path.join(pp, ".git")):
                add(pp)

    base = root.rstrip("/").count("/")
    def walk_error(error):
        raise error

    for dirpath, dirnames, filenames in os.walk(root, onerror=walk_error):
        if os.path.abspath(dirpath) in fleet_ignored:
            dirnames[:] = []
            continue
        depth = dirpath.rstrip("/").count("/") - base
        if depth > max_depth:
            dirnames[:] = []
            continue
        if ".git" in dirnames or ".git" in filenames:
            add(dirpath)
            if os.path.abspath(dirpath) == root:
                # workspace root that is itself a repo: keep scanning for nested repos
                dirnames[:] = [d for d in dirnames
                               if d != ".git" and d not in SKIP_WALK_DIRS]
                continue
            dirnames[:] = []            # a nested repo: record it, don't descend
            continue
        dirnames[:] = [d for d in dirnames if d not in SKIP_WALK_DIRS]
    return found


def repo_summary(path: str, config: dict) -> dict:
    repo = GitRepo(path)
    state = build_state(repo, config)
    sc, st = state.get("scores", {}), state.get("status", {})
    read_complete = state.get("read_complete") is True
    read_errors = [e for e in (state.get("read_errors") or []) if e]
    if read_errors:
        read_complete = False
    if not read_complete and not read_errors:
        read_errors = ["Repository inventory incomplete"]
    return {
        "name": state.get("root_name"), "path": path, "is_repo": state.get("is_repo"),
        "branch": "(detached)" if st.get("detached") else st.get("branch"),
        "safe_commit": sc.get("safe_commit"), "safe_commit_label": sc.get("safe_commit_label"),
        "safe_commit_band": sc.get("safe_commit_band"),
        "safe_delete": sc.get("safe_delete"), "safe_delete_label": sc.get("safe_delete_label"),
        "safe_delete_band": sc.get("safe_delete_band"),
        "read_complete": read_complete,
        "error": "; ".join(read_errors) if not read_complete and read_errors else None,
        "dirty_files": None if not read_complete else len(state.get("files", [])),
        "side_branches": len(state.get("side_branches", [])) if read_complete else None,
        "unpushed": state.get("unpushed_commit_count") if read_complete else None,
        "ahead": st.get("ahead") if read_complete else None,
        "behind": st.get("behind") if read_complete else None,
        "stashes": len(state.get("stashes", [])) if read_complete else None,
        "stash_summary": state.get("stash_summary", {}),
        "topology": state.get("topology", {}).get("kind"),
        "embedded": state.get("topology", {}).get("kind") == "tracked_inside_parent",
        "remotes_detail": state.get("remotes_detail", []),
        "push_weight": {
            "pack_human": state.get("push_weight", {}).get("pack_human"),
            "heavy": state.get("push_weight", {}).get("heavy", False),
        },
        "last_commit": state.get("last_commit"),
        "worktrees": len(state.get("worktrees", [])) if read_complete else None,
        "extra_worktree_count": state.get("extra_worktree_count") if read_complete else None,
        "hidden_path_count": len(state.get("index_inventory", {}).get("hidden_paths", [])) if read_complete else None,
        "schema_version": state.get("schema_version"),
        "generated_at": state.get("generated_at"),
        "actions": state.get("actions", {}), "closeout": state.get("closeout", {}),
        "object_storage": state.get("object_storage", {}),
        "main_equals_origin_main": state.get("main_equals_origin_main"),
        "hooks": _hook_verdict(path) if read_complete else {
            "read_complete": False, "read_errors": ["Repository inspection refused; hooks not inspected"],
            "core_hooks_path": None, "hooks_dir": None, "pre_commit": None, "pre_push": None,
        },
    }


def _worktree_count(repo: GitRepo) -> int | None:
    out, rc, _ = repo._run("worktree", "list")
    if rc != 0 or not out.strip():
        return None
    return len([line for line in out.splitlines() if line.strip()])


def _hook_verdict(path: str) -> dict:
    """Report hook-file presence; never execute hooks or hide metadata failures."""
    repo = GitRepo(path)
    hooks_path_out, rc, err = repo._run("config", "--get", "core.hooksPath")
    unknown = {"read_complete": False, "read_errors": [], "core_hooks_path": None,
               "hooks_dir": None, "pre_commit": None, "pre_push": None}
    if rc not in (0, 1):
        unknown["read_errors"] = ["Hook configuration unavailable: " + err]
        return unknown
    hooks_path = hooks_path_out.strip() if rc == 0 else ""
    resolved, rrc, err = repo._run("rev-parse", "--git-path", "hooks")
    if rrc != 0 or not resolved.strip():
        unknown["read_errors"] = ["Hook directory unavailable: " + err]
        return unknown
    resolved = resolved.strip()
    if not os.path.isabs(resolved):
        resolved = os.path.join(path, resolved)
    return {
        "read_complete": True, "read_errors": [],
        "core_hooks_path": hooks_path or None, "hooks_dir": resolved,
        "pre_commit": os.path.isfile(os.path.join(resolved, "pre-commit"))
        and os.access(os.path.join(resolved, "pre-commit"), os.X_OK),
        "pre_push": os.path.isfile(os.path.join(resolved, "pre-push"))
        and os.access(os.path.join(resolved, "pre-push"), os.X_OK),
    }


def _repo_is_verified_clean(r: dict) -> bool:
    """Failed or incomplete Git reads are not clean repositories."""
    if r.get("error") or r.get("hidden_path_count"):
        return False
    if r.get("read_complete") is not True:
        return False
    if r.get("is_repo") is not True:
        return False
    dirty = r.get("dirty_files")
    if dirty is None:
        return False
    return dirty == 0


def _fleet_failure_state(root: str, reason: str) -> dict:
    """Expose failed fleet observation instead of keeping an apparently fresh scan."""
    now = datetime.now(timezone.utc).astimezone()
    return {"version": VERSION, "schema_version": SCHEMA_VERSION, "mode": "fleet",
            "root": os.path.abspath(root), "read_complete": False, "read_errors": [reason],
            "generated_at": now.isoformat(timespec="seconds"),
            "generated_at_human": now.strftime("%Y-%m-%d %H:%M:%S %Z"),
            "inventory_scope": "Fleet inventory failed; previous selected repositories are not certified.",
            "totals": {"repos": 0, "unknown_repos": 0, "clean_repos": 0,
                       "total_unpushed": None, "unpushed_total_complete": False}, "repos": []}


def build_fleet_state(
    root: str,
    repo_paths: list[str],
    config: dict,
    workers: int = 8,
    registry_paths: list[str] | None = None,
) -> dict:
    import concurrent.futures
    if not os.path.isdir(root):
        return _fleet_failure_state(root, "Fleet root is not a readable directory")
    repo_paths = list(dict.fromkeys(os.path.abspath(p) for p in repo_paths))
    repos = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = {ex.submit(repo_summary, p, config): p for p in repo_paths}
        for f in concurrent.futures.as_completed(futs):
            try:
                repos.append(f.result())
            except Exception as e:  # noqa: BLE001
                repos.append({
                    "name": os.path.basename(str(futs[f]).rstrip("/")) or str(futs[f]),
                    "path": futs[f],
                    "is_repo": None,
                    "error": str(e),
                    "read_complete": False,
                    "dirty_files": None,
                    "safe_delete": None,
                    "safe_commit": None,
                })

    def rank(r):
        sd = r.get("safe_delete")
        if r.get("error") or r.get("read_complete") is False or sd is None:
            sd = -1
        return (sd, -(r.get("dirty_files") or 0), r.get("name") or "")
    repos.sort(key=rank)

    # Remote-owner classification is informational only, never a safety exclusion.
    def _owner(r):
        rd = r.get("remotes_detail") or []
        url = rd[0].get("url") if rd else None
        if not url:
            return None
        m = re.search(r"[/:]([^/:]+)/[^/:]+?(?:\.git)?/?$", url)
        return m.group(1).lower() if m else None
    root_abs = os.path.abspath(root)
    ws_owner = next((_owner(r) for r in repos if os.path.abspath(r.get("path", "")) == root_abs), None)
    if ws_owner is None:  # fall back to the most common remote owner
        from collections import Counter
        c = Counter(o for o in (_owner(r) for r in repos) if o)
        ws_owner = c.most_common(1)[0][0] if c else None
    registered = {os.path.abspath(p) for p in (registry_paths or [])}
    for r in repos:
        o = _owner(r)
        r["remote_owner"] = o
        path_abs = os.path.abspath(r.get("path") or "")
        if path_abs in registered:
            # Workshop governance follows the repository registry, not GitHub org.
            r["external"] = False
            r["governed_by_registry"] = True
        else:
            r["external"] = bool(o and ws_owner and o != ws_owner)
            r["governed_by_registry"] = False
    # Every explicitly selected repository counts. Inferred remote ownership is
    # informational, never permission to hide a dirty or unreadable repository.
    own = repos

    now = datetime.now(timezone.utc).astimezone()
    totals = {
        "repos": len(repos),
        "unknown_repos": sum(1 for r in own if r.get("read_complete") is not True),
        "unknown_unpushed_repos": sum(1 for r in own if r.get("unpushed") is None),
        "local_closeout_complete_repos": sum(1 for r in own if r.get("closeout", {}).get("local_state_complete") is True),
        "object_maintenance_repos": sum(1 for r in own if (r.get("object_storage") or {}).get("maintenance_required") is True),
        "object_storage_unknown_repos": sum(1 for r in own if (r.get("object_storage") or {}).get("complete") is not True),
        "external_repos": sum(1 for r in repos if r.get("external")),
        # All explicitly selected repositories contribute to the alarm counts.
        "dirty_repos": sum(1 for r in own if r.get("dirty_files")),
        "clean_repos": sum(1 for r in own if _repo_is_verified_clean(r)),
        "total_dirty_files": sum(r.get("dirty_files") or 0 for r in own),
        "total_side_branches": sum(r.get("side_branches") or 0 for r in own),
        "total_unpushed": (sum(r["unpushed"] for r in own)
                           if all(r.get("unpushed") is not None for r in own) else None),
        "known_unpushed": sum(r.get("unpushed") or 0 for r in own),
        "unpushed_total_complete": all(r.get("unpushed") is not None for r in own),
        "total_stashes": sum(r.get("stashes") or 0 for r in own),
        "repos_with_unmerged_stashes": sum(
            1 for r in own if (r.get("stash_summary") or {}).get("unmerged")),
        "embedded_repos": sum(1 for r in own if r.get("embedded")),
        "heavy_repos": sum(1 for r in own if (r.get("push_weight") or {}).get("heavy")),
    }
    return {
        "version": VERSION, "mode": "fleet",
        "schema_version": SCHEMA_VERSION,
        "read_complete": bool(repos) and os.path.isdir(root) and all(r.get("read_complete") is True and not r.get("error") for r in repos),
        "read_errors": (["No readable repositories selected"] if not repos else
                        [r.get("error") or "Repository inventory incomplete" for r in repos if r.get("read_complete") is not True or r.get("error")]),
        "inventory_scope": "Selected repositories only; bounded discovery or an explicit registry, not every excluded directory.",
        "generated_at": now.isoformat(timespec="seconds"),
        "generated_at_human": now.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "root": os.path.abspath(root), "totals": totals, "repos": repos,
    }


FLEET_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GIT_REAL · FLEET</title>
<style>
:root{
  /* OPUS5 DESIGN — remapped by MEANING, not hue. */
  --void:#06070d; --cyan:#c9f24d; --green:#c9f24d; --electric:#c9f24d; --git:#8b6cff;
  --ice:#c9f24d; --amber:#8b6cff; --bad:#ff5f56; --bad-deep:#ff5f56; --grey:#5d6480;
  --ink:#eef0f6; --muted:#8b90a6;
  --glass:#0f1220; --line:#1e2338; --gline:#2b3352;
  --good:#c9f24d; --warn:#8b6cff;
  --lift:none;
  --blue:#c9f24d; --blue-bright:#c9f24d; --panel:#0f1220; --panel2:#141829;
  --signal:#c9f24d; --infer:#8b6cff; --unknown:#5d6480; --alert:#ff5f56; --faint:#565d75;
  --mono:ui-monospace,'SF Mono','JetBrains Mono',Menlo,Consolas,monospace;
  --sans:'Archivo','Inter',system-ui,-apple-system,sans-serif;
}

:root{--void:#01010E;--cyan:#09E1E5;--green:#02EAA3;--electric:#0A96FA;--git:#0156EE;--ice:#65D8ED;
--amber:#FFB020;--bad:#FF3B5C;--bad-deep:#FF5A6E;--grey:#7888a8;--ink:#e7eefb;--muted:#9fb0cf;
--glass:rgba(10,20,42,.62);--line:rgba(120,190,255,.16);--gline:rgba(120,190,255,.2);
--good:#02EAA3;--warn:#FFB020;--blue:#0A96FA;--blue-bright:#25d0f7;--panel:var(--glass);
--lift:0 22px 46px rgba(0,0,0,.6);
--mono:'SF Mono','JetBrains Mono',ui-monospace,Menlo,Consolas,monospace;--sans:var(--mono);}
*{box-sizing:border-box;min-width:0}
body{margin:0;background:var(--void);color:var(--ink);font-family:var(--mono);font-size:14px;padding:22px;min-height:100vh;position:relative;letter-spacing:.01em}
.aurora{position:fixed;inset:-25%;z-index:0;filter:blur(86px);opacity:.32;pointer-events:none}
.aurora b{position:absolute;border-radius:50%;mix-blend-mode:screen;display:block}
.aurora .b1{width:48vw;height:48vw;background:radial-gradient(circle,#0156EE 0,transparent 66%);top:-14%;left:-8%;animation:f1 23s ease-in-out infinite}
.aurora .b2{width:42vw;height:42vw;background:radial-gradient(circle,#09E1E5 0,transparent 66%);bottom:4%;right:-8%;animation:f2 27s ease-in-out infinite}
.aurora .b3{width:40vw;height:40vw;background:radial-gradient(circle,#02EAA3 0,transparent 66%);bottom:-18%;left:20%;animation:f1 25s ease-in-out infinite}
@keyframes f1{50%{transform:translate(6vw,5vh) scale(1.12)}}
@keyframes f2{50%{transform:translate(-6vw,7vh) scale(1.1)}}
.bgrid{position:fixed;inset:0;z-index:0;pointer-events:none;background:linear-gradient(rgba(10,150,250,.12) 1px,transparent 1px) 0 0/100% 42px,linear-gradient(90deg,rgba(10,150,250,.12) 1px,transparent 1px) 0 0/42px 100%;mask:radial-gradient(circle at 50% 14%,#000 50%,transparent 100%);animation:drift 24s linear infinite}
@keyframes drift{to{background-position:0 42px,42px 0}}
.bscan{position:fixed;inset:0;z-index:0;pointer-events:none;background:repeating-linear-gradient(0deg,rgba(9,225,229,.03) 0 2px,transparent 2px 4px);mix-blend-mode:screen}
.frame{position:fixed;inset:10px;z-index:5;pointer-events:none}
.frame i{position:absolute;width:24px;height:24px;border:2px solid var(--cyan);opacity:.5;filter:drop-shadow(0 0 6px var(--cyan))}
.frame i:nth-child(1){top:0;left:0;border-right:0;border-bottom:0}.frame i:nth-child(2){top:0;right:0;border-left:0;border-bottom:0}
.frame i:nth-child(3){bottom:0;left:0;border-right:0;border-top:0}.frame i:nth-child(4){bottom:0;right:0;border-left:0;border-top:0}
h1,h2{font-family:var(--mono);margin:0;letter-spacing:.05em}
.clip{clip-path:none}
.wrap{max-width:1340px;margin:0 auto;position:relative;z-index:2}
header{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:16px}
.logo{font-family:var(--mono);font-size:23px;font-weight:800;letter-spacing:.12em;color:#fff;text-shadow:0 0 22px rgba(9,225,229,.7)}
.logo b{color:var(--green);text-shadow:0 0 20px rgba(2,234,163,.9)}
.tag{color:var(--muted);font-size:12px;font-family:var(--mono)}
.slogan{font-family:var(--mono);font-size:12px;color:var(--ice);margin-left:auto;opacity:.85}
.totals{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));gap:12px;margin-bottom:18px}
.tcard{background:var(--glass);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border:1px solid var(--gline);border-radius:13px;padding:13px 15px;box-shadow:var(--lift),inset 0 1px 0 rgba(255,255,255,.08)}
.tcard .n{font-family:var(--mono);font-size:27px;font-weight:800;color:#fff;line-height:1;text-shadow:0 0 16px rgba(9,225,229,.4)}
.tcard .l{color:var(--muted);font-size:10.5px;font-family:var(--mono);text-transform:uppercase;letter-spacing:.08em;margin-top:5px}
.tcard.alert .n{color:var(--bad);text-shadow:0 0 16px rgba(255,59,92,.6)}
.tcard.good .n{color:var(--green);text-shadow:0 0 16px rgba(2,234,163,.5)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:15px}
.repo{background:var(--glass);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border:1px solid var(--gline);border-radius:14px;padding:14px 16px;cursor:pointer;transition:.18s;position:relative;box-shadow:var(--lift),inset 0 1px 0 rgba(255,255,255,.07)}
.repo:hover{border-color:var(--cyan);transform:translateY(-5px);box-shadow:var(--lift),0 0 28px rgba(9,225,229,.28)}
.repo.has-secret{border-color:rgba(255,59,92,.6);box-shadow:var(--lift),0 0 22px rgba(255,59,92,.35);animation:edge 1.3s ease-in-out infinite}
@keyframes edge{50%{box-shadow:var(--lift),0 0 36px rgba(255,59,92,.6)}}
.repo.clean{opacity:.92;border-left:2px solid rgba(2,234,163,.45)}
.repo.dirty{border-left:2px solid rgba(255,176,32,.6)}
.repo.external{opacity:.42;filter:grayscale(.4)}
.rtop{display:flex;align-items:center;gap:8px;margin-bottom:11px}
.rname{font-family:var(--mono);font-size:14.5px;color:#fff;font-weight:700;word-break:break-all}
.rbranch{font-family:var(--mono);font-size:11px;color:var(--ice);margin-left:auto;white-space:nowrap}
.scorebar{display:flex;gap:10px;margin-bottom:11px}
.sc{flex:1;background:rgba(2,9,22,.5);border:1px solid var(--line);border-radius:9px;padding:8px 9px;text-align:center}
.sc .v{font-family:var(--mono);font-size:22px;font-weight:800;line-height:1}
.sc .k{font-size:8.5px;color:var(--muted);font-family:var(--mono);text-transform:uppercase;letter-spacing:.08em;margin-top:4px}
.go{color:var(--good)}.caution{color:var(--warn)}.stop{color:var(--bad)}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip{font-family:var(--mono);font-size:9.5px;font-weight:700;padding:2px 8px;border-radius:20px;letter-spacing:.04em;background:rgba(120,136,168,.14);color:var(--muted);border:1px solid rgba(120,136,168,.3)}
.chip.dirty{background:rgba(255,176,32,.14);color:var(--amber);border-color:rgba(255,176,32,.5)}
.chip.secret{background:var(--bad);color:#fff;border-color:var(--bad);box-shadow:0 0 12px rgba(255,59,92,.6);animation:blink 1.1s steps(2,start) infinite}
.chip.branch{background:rgba(9,225,229,.14);color:var(--cyan);border-color:rgba(9,225,229,.5)}
.chip.push{background:rgba(184,139,224,.14);color:#c4a0e8;border-color:rgba(184,139,224,.4)}
@keyframes blink{50%{opacity:.25}}
.tri{color:var(--bad-deep);animation:blink 1s steps(2,start) infinite}
.empty{color:var(--muted);font-style:italic;padding:30px;text-align:center;font-family:var(--mono)}
.foot{display:flex;justify-content:space-between;color:var(--muted);font-size:11px;font-family:var(--mono);margin-top:20px;flex-wrap:wrap;gap:8px}
.live{display:inline-flex;align-items:center;gap:6px}
.pulse{width:8px;height:8px;border-radius:50%;background:var(--cyan);box-shadow:0 0 10px var(--cyan);animation:pulse 1.6s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:.35}50%{opacity:1}}
.modal{position:fixed;inset:0;background:rgba(1,3,12,.8);backdrop-filter:blur(6px);display:none;align-items:flex-start;justify-content:center;padding:40px 16px;overflow:auto;z-index:50}
.modal.open{display:flex}
.sheet{background:var(--glass);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:1px solid var(--gline);border-radius:18px;max-width:760px;width:100%;padding:24px;box-shadow:var(--lift)}
.sheet h2{color:#fff;font-size:17px;margin-bottom:6px;text-shadow:0 0 16px rgba(9,225,229,.5)}
.sheet .mpath{font-family:var(--mono);font-size:11px;color:var(--muted);word-break:break-all;margin-bottom:14px}
.reasons{list-style:none;padding:0;margin:8px 0}
.reasons li{padding:3px 0 3px 14px;position:relative;font-size:12.5px;color:#c4d2e6}
.reasons li::before{content:'\203a';position:absolute;left:0;color:var(--cyan)}
.flist{list-style:none;padding:0;margin:6px 0;max-height:240px;overflow:auto}
.flist li{display:flex;gap:8px;padding:5px 4px;border-bottom:1px solid rgba(255,255,255,.06);font-size:12px}
.badge{font-family:var(--mono);font-size:9px;font-weight:700;padding:2px 7px;border-radius:5px}
.b-dirty{background:rgba(10,150,250,.16);color:var(--electric)}.b-staged{background:rgba(2,234,163,.14);color:var(--green)}
.b-new{background:rgba(9,225,229,.14);color:var(--cyan)}.b-junk{background:rgba(120,136,168,.14);color:var(--grey)}
.b-secret{background:var(--bad);color:#fff}.b-conflict{background:rgba(255,59,92,.16);color:var(--bad)}
.fpath{font-family:var(--mono);word-break:break-all}
.closex{float:right;cursor:pointer;color:var(--muted);font-family:var(--mono);font-size:20px}
.subhdr{font-family:var(--mono);font-size:11px;color:var(--ice);text-transform:uppercase;letter-spacing:.08em;margin:14px 0 4px}
@media(max-width:640px){.totals{grid-template-columns:repeat(3,1fr)}.grid{grid-template-columns:1fr}}

/* ===== OPUS5 DESIGN skin — appended override. Instrument behaviour untouched.
   Aurora blobs, the blue drift grid and the scanline wash were the old identity.
   OPUS5 is a flat void field, hard edges, mono data, grotesk headings. ===== */
.aurora,.bgrid,.bscan{display:none!important}
body{background:var(--void)!important;font-family:var(--mono)!important}
.panel,.card,.tcard,.repo,.wrap>section{
  background:var(--panel)!important;backdrop-filter:none!important;-webkit-backdrop-filter:none!important;
  border:1px solid var(--line)!important;border-radius:0!important;box-shadow:none!important}
h1,h2,h3,.brand,.title{font-family:var(--sans)!important;font-weight:800!important;letter-spacing:-.03em!important}
button,.btn,.pill,.chip,.badge,input,select,.dial,.tcard,.card{border-radius:0!important}
.pill,.chip,.badge{background:transparent!important;box-shadow:none!important;font-family:var(--mono)!important}
/* Status keeps meaning: clean burns, attention glows cold, unsafe is coral. */
.go{color:var(--signal)!important}
.caution{color:var(--infer)!important}
.stop,.tri{color:var(--alert)!important}
.chip.secret,.b-secret{background:var(--alert)!important;color:#0a0c05!important;box-shadow:none!important;border-color:var(--alert)!important}
.b-conflict{background:color-mix(in srgb,var(--alert) 14%,transparent)!important;color:var(--alert)!important;border-color:var(--alert)!important}
button.warn{background:var(--infer)!important;color:#0a0c05!important;box-shadow:none!important}
.dial .num{color:var(--ink)!important;text-shadow:none!important}
.tcard.alert .n{color:var(--alert)!important;text-shadow:none!important}
*{text-shadow:none!important}

/* Chip + row accents were still on the old amber/cyan/purple rgba values. */
.repo.dirty{border-left:2px solid var(--infer)!important}
.chip{background:transparent!important;border:1px solid var(--line)!important;color:var(--faint)!important;border-radius:0!important}
.chip.dirty{background:color-mix(in srgb,var(--infer) 12%,transparent)!important;color:var(--infer)!important;border-color:color-mix(in srgb,var(--infer) 50%,var(--line))!important}
.chip.branch{background:color-mix(in srgb,var(--signal) 10%,transparent)!important;color:var(--signal)!important;border-color:color-mix(in srgb,var(--signal) 45%,var(--line))!important}
.chip.push{background:color-mix(in srgb,var(--unknown) 14%,transparent)!important;color:var(--unknown)!important;border-color:color-mix(in srgb,var(--unknown) 50%,var(--line))!important}
</style></head><body>
<div class="aurora"><b class="b1"></b><b class="b2"></b><b class="b3"></b></div>
<div class="bgrid"></div><div class="bscan"></div>
<div class="frame"><i></i><i></i><i></i><i></i></div>
<div class="wrap">
  <header>
    <span class="logo">GIT<b>_</b>REAL</span><span class="tag">v__VERSION__ · FLEET command center</span>
    <span class="slogan">__REPO_COUNT__ repos · one wall · zero confusion</span>
  </header>
  <div class="totals" id="totals"></div>
  <div class="grid" id="grid"></div>
  <div class="foot">
    <span class="live"><span id="health">saved snapshot</span> · updated <span id="updated"></span></span>
    <span id="rootp"></span>
  </div>
</div>
<div class="modal" id="modal"><div class="sheet clip" id="sheet"></div></div>
<script>
const EMBEDDED=__STATE_JSON__;const PORT=__PORT__;let STATE=EMBEDDED;let LIVE=false;
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function bc(b){return b==='GO'?'go':b==='CAUTION'?'caution':'stop';}
function tcard(n,l,cls){return `<div class="tcard ${cls||''}"><div class="n">${n}</div><div class="l">${l}</div></div>`;}
function render(){
 const s=STATE,t=s.totals||{};
 document.getElementById('health').textContent=(LIVE?'live':'saved snapshot · live refresh unavailable')+(s.read_complete===true?' · selected inventory complete':' · incomplete: '+((s.read_errors||[]).join('; ')||'inventory unknown'));
 document.getElementById('totals').innerHTML=
   tcard(t.repos||0,'repos')+
   tcard(t.dirty_repos||0,'dirty repos',(t.dirty_repos||t.unknown_repos||s.read_complete!==true?'':'good'))+
   tcard(t.total_dirty_files||0,'dirty files')+
   tcard(t.total_side_branches||0,'side branches')+
   tcard(t.total_unpushed==null?'?':t.total_unpushed,'unpushed')+
   tcard(t.unknown_repos||0,'unknown repos',(t.unknown_repos?'alert':''))+
   tcard(t.total_stashes||0,'stashes',(t.repos_with_unmerged_stashes?'alert':''))+
   tcard(t.embedded_repos||0,'embedded',(t.embedded_repos?'alert':''))+
   tcard(t.heavy_repos||0,'heavy repos')+
   tcard(t.external_repos||0,'external');
 const g=document.getElementById('grid');const repos=s.repos||[];
 if(!repos.length){g.innerHTML='<div class="empty">No git repos found under this root.</div>';}
 else g.innerHTML=repos.map((r,i)=>{
   if(r.error||r.read_complete!==true)return `<div class="repo clip"><div class="rtop"><span class="rname">${esc(r.name)}</span></div><div class="chip">error: ${esc(r.error||'Repository inventory incomplete')}</div></div>`;
   const cls=(r.dirty_files||r.hidden_path_count)?'dirty':'clean';
   let chips='';
   if(r.dirty_files)chips+=`<span class="chip dirty">${r.dirty_files} dirty</span>`;
   if(r.side_branches)chips+=`<span class="chip branch">${r.side_branches} side-branch</span>`;
   if(r.unpushed)chips+=`<span class="chip push">${r.unpushed} unpushed</span>`;
   if(r.unpushed==null)chips+='<span class="chip push">publication unknown</span>';
   if(r.hidden_path_count)chips+=`<span class="chip dirty">${r.hidden_path_count} hidden-index paths</span>`;
   if(r.stashes){const un=(r.stash_summary||{}).unmerged||0;
     chips+=`<span class="chip${un?' secret':' branch'}" title="${un} hold unmerged work">${r.stashes} stash${un?' &middot; '+un+' unmerged':''}</span>`;}
   if(r.embedded)chips+=`<span class="chip branch" title="tracked inside a parent repo - not its own repo">embedded</span>`;
   if((r.push_weight||{}).heavy)chips+=`<span class="chip push" title="heavy pack - slow push/clone">heavy ${esc((r.push_weight||{}).pack_human||'')}</span>`;
   if(r.ahead||r.behind)chips+=`<span class="chip">&#8593;${r.ahead} &#8595;${r.behind}</span>`;
   if(r.external)chips=`<span class="chip" title="different remote owner; still included in safety totals">remote owner · ${esc(r.remote_owner||'unknown')}</span>`+chips;
   if(!chips)chips='<span class="chip" style="color:var(--good)">clean</span>';
   return `<div class="repo clip ${cls}" onclick="openRepo(${i})">
     <div class="rtop"><span class="rname">${esc(r.name)}</span><span class="rbranch">${esc(r.branch||'-')}</span></div>
     <div class="scorebar">
       <div class="sc"><div class="v ${bc(r.safe_commit_band)}">${r.safe_commit==null?'-':r.safe_commit}</div><div class="k">commit</div></div>
       <div class="sc"><div class="v ${bc(r.safe_delete_band)}">${r.safe_delete==null?'-':r.safe_delete}</div><div class="k">discard</div></div>
     </div>
     <div class="chips">${chips}</div></div>`;
 }).join('');
 document.getElementById('updated').textContent=s.generated_at_human||'';
 document.getElementById('rootp').textContent=s.root||'';
 document.title=`GIT_REAL FLEET · ${t.repos||0} repos`;
}
async function refresh(){try{const r=await fetch(`http://127.0.0.1:${PORT}/api/fleet`,{cache:'no-store'});if(!r.ok)throw Error('refresh failed');const next=await r.json();if(!next||next.schema_version!==2||!Array.isArray(next.repos)||typeof next.read_complete!=='boolean')throw Error('invalid fleet response');STATE=next;LIVE=true;}catch(e){LIVE=false;}render();}
async function openRepo(i){
 const r=(STATE.repos||[])[i];if(!r)return;
 const sheet=document.getElementById('sheet');
 sheet.innerHTML=`<span class="closex" onclick="closeModal()">&times;</span><h2>${esc(r.name)}</h2><div class="mpath">${esc(r.path)}</div><div class="empty">loading…</div>`;
 document.getElementById('modal').classList.add('open');
 let st=null;
 try{const resp=await fetch(`http://127.0.0.1:${PORT}/api/repo?path=`+encodeURIComponent(r.path));if(resp.ok)st=await resp.json();}catch(e){}
 if(!st){sheet.querySelector('.empty').textContent='Detail needs the live server (open via the URL, not the file).';return;}
 if(st.read_complete!==true||(st.read_errors||[]).length){sheet.innerHTML=`<span class="closex" onclick="closeModal()">&times;</span><h2>${esc(st.root_name||r.name)}</h2><div class="mpath">${esc(st.root||r.path)}</div><div class="empty">Inspection incomplete: ${esc((st.read_errors||[]).join('; ')||st.error||'inventory unknown')}</div>`;return;}
 const sc=st.scores||{};
 const reasons=(arr)=>`<ul class="reasons">${(arr||[]).map(x=>`<li>${esc(x)}</li>`).join('')||'<li>-</li>'}</ul>`;
 const fl=(st.files||[]).map(f=>{const cm={staged:'b-staged',modified:'b-dirty',new:'b-new',junk:'b-junk',conflict:'b-conflict'}[f.category]||'b-dirty';
   const nm={staged:'STAGED',modified:'DIRTY',new:'NEW',junk:'JUNK',conflict:'CONFLICT'}[f.category]||'DIRTY';
   return `<li><span class="badge ${cm}">${nm}</span><span class="fpath">${esc(f.path)}</span></li>`;}).join('');
 sheet.innerHTML=`<span class="closex" onclick="closeModal()">&times;</span><h2>${esc(st.root_name)}</h2><div class="mpath">${esc(st.root)}</div>
   <div class="scorebar"><div class="sc"><div class="v ${bc(sc.safe_commit_band)}">${sc.safe_commit}</div><div class="k">${esc(sc.safe_commit_label||'')}</div></div>
   <div class="sc"><div class="v ${bc(sc.safe_delete_band)}">${sc.safe_delete}</div><div class="k">${esc(sc.safe_delete_label||'')}</div></div></div>
   <div class="subhdr">why - safe to commit</div>${reasons(sc.safe_commit_reasons)}
   <div class="subhdr">why - safe to discard</div>${reasons(sc.safe_delete_reasons)}
   <div class="subhdr">working tree (${(st.files||[]).length})</div><ul class="flist">${fl||'<li class="fpath">clean</li>'}</ul>`;
}
function closeModal(){document.getElementById('modal').classList.remove('open');}
document.getElementById('modal').addEventListener('click',e=>{if(e.target.id==='modal')closeModal();});
render();setInterval(refresh,Math.max(2000,__INTERVAL__*1000));refresh();
</script></body></html>"""


def render_fleet_html(state: dict, port: int, interval: float) -> str:
    # Substitute the template once so placeholder-looking repository text is data.
    values = {"__STATE_JSON__": json_for_script(state), "__PORT__": str(port),
              "__INTERVAL__": str(interval), "__VERSION__": html_text(VERSION),
              "__REPO_COUNT__": html_text(state.get("totals", {}).get("repos", 0))}
    return re.sub(r"__STATE_JSON__|__PORT__|__INTERVAL__|__VERSION__|__REPO_COUNT__",
                  lambda match: values[match.group(0)], FLEET_HTML)


class FleetApp:
    def __init__(self, root: str, port: int, interval: float, pinned=None, registry_paths=None):
        self.root = os.path.abspath(root)
        self.port, self.interval = port, interval
        self.pinned = list(pinned or [])
        self.registry_authority = registry_paths is not None
        self.registry_paths = list(registry_paths or [])
        self.outdir = os.path.join(self.root, OUTPUT_DIRNAME)
        if os.path.islink(self.outdir):
            raise OSError("Refusing a symlinked GIT_REAL output directory")
        os.makedirs(self.outdir, exist_ok=True)
        gi = os.path.join(self.outdir, ".gitignore")
        if not os.path.lexists(gi):
            try:
                with open(gi, "x", encoding="utf-8") as fh:
                    fh.write("*\n")
            except FileExistsError:
                pass
        self.config = {}
        self.state, self.lock = {}, threading.Lock()
        self.scan_lock = threading.Lock()
        self.drift = {}
        self.repo_paths = self._discover()

    def _discover(self) -> list[str]:
        if self.registry_authority:
            self.drift = registry_fleet_paths(self.root, self.registry_paths)
            return list(self.drift.get("present") or [])
        return discover_repos(self.root, pinned=self.pinned)

    def rescan(self):
        with self.scan_lock:
            try:
                paths = self._discover()
                state = build_fleet_state(
                    self.root, paths, self.config, registry_paths=self.registry_paths,
                )
                if self.registry_authority:
                    state["registry_authority"] = True
                    state["drift_unregistered"] = list(self.drift.get("drift_unregistered") or [])
                    state["drift_missing"] = list(self.drift.get("drift_missing") or [])
                    state["totals"]["drift_unregistered"] = len(state["drift_unregistered"])
                    state["totals"]["drift_missing"] = len(state["drift_missing"])
                    if state["drift_missing"]:
                        state["read_complete"] = False
                        state["read_errors"].append("Registered repositories are missing")
            except Exception as exc:  # noqa: BLE001
                paths = []
                state = _fleet_failure_state(self.root, f"Fleet refresh failed: {exc}")
                state["registry_authority"] = self.registry_authority
            try:
                atomic_write_text(os.path.join(self.outdir, "git-real-fleet.json"),
                                  json.dumps(state, indent=2) + "\n")
                if not self.config.get("quick"):
                    atomic_write_text(os.path.join(self.outdir, "git-real-fleet.html"),
                                      render_fleet_html(state, self.port, self.interval))
            except OSError as exc:
                state["read_complete"] = False
                state["read_errors"].append(f"Fleet snapshot publication failed: {exc}")
            with self.lock:
                self.repo_paths, self.state = paths, state
            return state

    def get_state(self):
        with self.lock:
            return self.state

    def repo_state(self, path: str):
        path = os.path.abspath(path)
        with self.lock:
            selected = {os.path.abspath(p) for p in self.repo_paths}
        if path not in selected:
            return {"error": "unknown repo"}
        return build_state(GitRepo(path), self.config)


def make_fleet_handler(app: "FleetApp"):
    import urllib.parse

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            port = self.server.server_port
            hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
            if port == 80:
                hosts.update({"127.0.0.1", "localhost"})
            host = self.headers.get("Host", "").lower()
            origin = self.headers.get("Origin")
            if host not in hosts or (origin is not None and origin.lower() not in {"http://" + h for h in hosts}):
                self._send(403, json.dumps({"error": "local dashboard origin required"}))
                return
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.scheme or parsed.netloc:
                self._send(404, json.dumps({"error": "not found"}))
            elif parsed.path in ("/", "/index.html"):
                self._send(200, render_fleet_html(app.get_state(), port, app.interval), "text/html; charset=utf-8")
            elif parsed.path == "/api/fleet":
                self._send(200, json.dumps(app.get_state()))
            elif parsed.path == "/api/repo":
                path = urllib.parse.parse_qs(parsed.query).get("path", [""])[0]
                self._send(200, json.dumps(app.repo_state(path)))
            else:
                self._send(404, json.dumps({"error": "not found"}))

        # Read-only dashboard: no write endpoints.

    return H


def run_fleet(args, root: str):
    pinned = []
    registry_paths = None
    repos_file = getattr(args, "repos_file", None)
    if not repos_file:
        default_projection = os.path.join(root, "governance", "generated", "REPOSITORY_FLEET.json")
        if os.path.lexists(default_projection):
            repos_file = default_projection
    try:
        if repos_file:
            registry_paths = load_registry_repo_paths(repos_file)
        else:
            pin_file = os.path.join(root, OUTPUT_DIRNAME, "fleet.json")
            if os.path.lexists(pin_file):
                pinned = load_registry_repo_paths(pin_file, relative_root=root)
        app = FleetApp(root, args.port, args.interval, pinned=pinned, registry_paths=registry_paths)
        app.config.update(quick=getattr(args, "quick", False))
        app.rescan()
    except (OSError, ValueError) as exc:
        print(f"[gitreal] fleet input/refresh failed: {exc}", file=sys.stderr)
        sys.exit(2)
    t = app.state.get("totals", {})

    if args.once:
        print(f"[gitreal] FLEET snapshot result: {app.outdir}/git-real-fleet.json")
        print(f"           {t.get('repos',0)} repos | {t.get('dirty_repos',0)} dirty | {t.get('total_side_branches',0)} side-branches")
        if app.registry_authority:
            print(f"           registry authority | drift_unregistered={t.get('drift_unregistered',0)} "
                  f"| drift_missing={t.get('drift_missing',0)}")
        rc = 0 if app.state.get("read_complete") is True else 2
        if app.state.get("read_errors"):
            print("           incomplete: " + "; ".join(app.state["read_errors"]))
        if args.fail_under is not None:
            low = [r for r in app.state["repos"] if (r.get("safe_commit") or 0) < args.fail_under]
            if low:
                print(f"           !! {len(low)} repo(s) below safe-commit {args.fail_under}")
                rc = max(rc, 1)
        sys.exit(rc)

    print(f"GIT_REAL v{VERSION}  ·  FLEET")
    print(f"  root     : {root}")
    print(f"  repos    : {t.get('repos',0)} discovered")
    print(f"  outputs  : {app.outdir}/git-real-fleet.html  +  git-real-fleet.json")
    stop_event = threading.Event()
    worker = None
    httpd = None

    def loop():
        while not stop_event.is_set():
            stop_event.wait(max(3, args.interval))
            if not stop_event.is_set():
                app.rescan()
    try:
        worker = threading.Thread(target=loop, daemon=True)
        worker.start()
        if not args.no_server:
            try:
                httpd = ThreadingHTTPServer(("127.0.0.1", args.port), make_fleet_handler(app))
                print(f"  dashboard: http://127.0.0.1:{httpd.server_port}")
            except OSError as e:
                print(f"  [!] could not bind port {args.port}: {e}")
        print("  (Ctrl+C to stop)\n")
        if httpd:
            httpd.serve_forever()
        else:
            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        print("\n[gitreal] fleet stopped.")
    finally:
        stop_event.set()
        if worker is not None:
            try:
                worker.join(timeout=2)
            except RuntimeError:
                pass  # A thread whose start failed cannot be joined.
        if httpd:
            httpd.server_close()


# ----------------------------------------------------------------------------
# agent wiring  (--wire-agents): install the GIT_REAL hook into agent rule files
# ----------------------------------------------------------------------------
WIRE_BEGIN = "<!-- GIT_REAL hook -->"
WIRE_END = "<!-- /GIT_REAL -->"
# Fixed basenames, complete preflight and alias rejection bound instruction writes.
WIRE_TARGETS = ("CLAUDE.md", "AGENTS.md", ".cursorrules")
WIRE_DEFAULT = "AGENTS.md"   # created if none of the targets exist yet


def wire_block() -> str:
    """The managed agent-hook block. Points agents at .git-real/git-real.json so they read
    the verdict before commit/discard. Delimited by WIRE_BEGIN / WIRE_END for idempotent
    replacement. Plain hyphens only (no em-dashes)."""
    return "\n".join([
        WIRE_BEGIN,
        "## Git safety (GIT_REAL)",
        "",
        "Before a Git action, request fresh, operation-specific evidence for the actual repo root:",
        "",
        "1. Run `python gitreal.py . --quick --once` and read `.git-real/git-real.json`,",
        "   or call the MCP tool now. A watcher or earlier snapshot is not a substitute.",
        "2. Require schema_version=2, the intended root, read_complete=true and no read_errors.",
        "   Commit only the inspected index when actions.commit_index has safe=true and decision=ALLOW.",
        "3. Discard requires an explicit operation: discard_tracked (restore from index),",
        "   clean_untracked (-fd), clean_ignored (-fdx), reset_hard with target commit, or",
        "   drop_stash with selected stash ref. Use is_safe_to_discard(path, operation, target)",
        "   or CLI --quick --json --operation NAME [--target VALUE]. Require safe=true and ALLOW.",
        "   Legacy scores are summaries only; the generic discard score never grants GO.",
        "",
        "Filename hints, ignored status, working-tree stash copies and reflogs are not recovery proof.",
        "No result approves amend, commit -a, force-push, another checkout target, or recursive/extra-force flags.",
        "Use the resolved reset OID and follow the owner's authorization; preserve unsupported/unknown work.",
        "Snapshots do not lock future writers or verify remote servers. Recheck after any state change.",
        "Reconnect MCP after source upgrades; source-change detection blocks an outdated loaded process.",
        WIRE_END,
    ])


def _wire_read(path: str) -> tuple[bytes, tuple] | None:
    """Read one regular, singly linked file without following its final symlink."""
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise OSError(f"Refusing aliased or nonregular agent instruction file: {path}")
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as source:
        opened = os.fstat(source.fileno())
        if identity(opened) != identity(before):
            raise OSError(f"Agent instruction file changed before reading: {path}")
        data = source.read()
        if identity(os.fstat(source.fileno())) != identity(opened):
            raise OSError(f"Agent instruction file changed while reading: {path}")
    return data, identity(opened)


def _wire_plan(path: str, block: str) -> dict:
    original = _wire_read(path)
    data = original[0] if original is not None else b""
    lines = data.splitlines(keepends=True)
    newline = b"\n"
    for line in lines:
        if line.endswith(b"\r\n"):
            newline = b"\r\n"
            break
        if line.endswith((b"\n", b"\r")):
            newline = line[-1:]
            break
    replacement = block.encode("utf-8").replace(b"\n", newline)
    begin, end = WIRE_BEGIN.encode(), WIRE_END.encode()
    if begin in data or end in data:
        starts, ends, offset = [], [], 0
        for index, line in enumerate(lines):
            text = line.rstrip(b"\r\n")
            bom = 3 if index == 0 and text.startswith(b"\xef\xbb\xbf") else 0
            text = text[bom:]
            if text == begin:
                starts.append(offset + bom)
            if text == end:
                ends.append(offset + bom + len(end))
            offset += len(line)
        if (len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]
                or data.count(begin) != 1 or data.count(end) != 1):
            raise OSError(f"Agent instruction markers must be one ordered pair on complete lines: {path}")
        updated = data[:starts[0]] + replacement + data[ends[0]:]
        action = "unchanged" if updated == data else "updated"
    else:
        separator = b"" if not data or data.endswith(newline * 2) else (newline if data.endswith(newline) else newline * 2)
        updated = data + separator + replacement + newline
        action = "created" if original is None else "inserted"
    return {"original": original, "updated": updated, "action": action}


def _wire_apply(path: str, plan: dict) -> str:
    if _wire_read(path) != plan["original"]:
        raise OSError(f"Agent instruction file changed after preflight: {path}")
    if plan["action"] == "unchanged":
        return "unchanged"
    if plan["original"] is None:
        # Exclusive creation cannot replace a file that appeared after preflight.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags, 0o666)
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(plan["updated"])
        return "created"
    descriptor, temporary = tempfile.mkstemp(prefix=".gitreal-wire-", dir=os.path.dirname(path) or ".")
    temporary_stat = os.fstat(descriptor)
    temporary_identity = (temporary_stat.st_dev, temporary_stat.st_ino)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(plan["updated"])
        os.chmod(temporary, stat.S_IMODE(plan["original"][1][2]))
        if _wire_read(path) != plan["original"]:
            raise OSError(f"Agent instruction file changed before replacement: {path}")
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            try:
                remaining = os.lstat(temporary)
            except FileNotFoundError:
                pass
            else:
                if (remaining.st_dev, remaining.st_ino) == temporary_identity:
                    os.unlink(temporary)
    return plan["action"]


def _wire_one(path: str, block: str) -> str:
    """Preserve bytes outside one managed range; return its actual write result."""
    return _wire_apply(path, _wire_plan(path, block))


def wire_agents(root: str) -> dict:
    """Idempotently install the GIT_REAL agent hook into the repo's agent rule files.
    Updates every one of CLAUDE.md / AGENTS.md / .cursorrules that already exists; if none
    exist, creates AGENTS.md. Preflight every selected file before applying edits.
    Returns {filename: action}. This is not a multi-file transaction or writer lock."""
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        raise OSError(f"Agent wiring requires an existing directory: {root}")
    block = wire_block()
    existing = [n for n in WIRE_TARGETS if os.path.lexists(os.path.join(root, n))]
    targets = existing or [WIRE_DEFAULT]
    plans = {name: _wire_plan(os.path.join(root, name), block) for name in targets}
    return {name: _wire_apply(os.path.join(root, name), plans[name]) for name in targets}


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(prog="gitreal", description="GIT_REAL - git situational awareness for humans and agents.")
    ap.add_argument("path", nargs="?", default=".", help="folder to watch (default: current dir)")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--interval", type=float, default=DEFAULT_INTERVAL)
    ap.add_argument("--poll", action="store_true", help="force polling watcher (use on /mnt/c or network drives)")
    ap.add_argument("--no-server", action="store_true", help="write files only, no dashboard server")
    ap.add_argument("--once", action="store_true", help="generate output once and exit")
    ap.add_argument("--quick", action="store_true", help="inventory only; defer deep stash and push-weight telemetry")
    ap.add_argument("--json", dest="json_output", action="store_true",
                    help="print a fresh JSON snapshot without writing dashboard files")
    ap.add_argument("--operation", choices=tuple(ACTION_SCOPES), help="assess one exact operation without executing it")
    ap.add_argument("--stage-path", action="append", default=[], help="pathspec for --operation stage_paths; repeat for multiple pathspecs")
    ap.add_argument("--target", help="exact refs/heads/<name> for branch/origin checks, reset commit or selected stash ref")
    ap.add_argument("--expect-binding", help="fail closed unless a fresh ref-operation input_binding matches this digest")
    ap.add_argument("--request-id", help="echo a caller's unique refresh token in the snapshot")
    ap.add_argument("--init", action="store_true", help="git init if PATH is not a repo")
    ap.add_argument("--all", "--fleet", dest="all", action="store_true",
                    help="FLEET mode: scan PATH for ALL git repos and show the multi-repo command center")
    ap.add_argument("--repos-file", default=None,
                    help="FLEET registry authority: JSON projection with repositories[] or repos[]")
    ap.add_argument("--fail-under", type=int, default=None, metavar="N",
                    help="guardrail (with --once): exit 1 if safe-commit < N (use as a pre-commit hook)")
    ap.add_argument("--wire-agents", action="store_true",
                    help="install the GIT_REAL hook into CLAUDE.md / AGENTS.md / .cursorrules "
                         "(idempotent; creates AGENTS.md if none exist) and exit")
    args = ap.parse_args()
    if not (0 < args.interval < float("inf")):
        ap.error("--interval must be finite and greater than zero")
    if args.json_output and (args.init or args.wire_agents):
        ap.error("--json cannot initialize Git or write agent instructions")
    if args.repos_file and not args.all:
        ap.error("--repos-file requires --fleet")
    if args.target is not None and args.operation not in ("reset_hard", "drop_stash", *REF_ACTIONS):
        ap.error("--target requires an exact target-bearing operation")
    if args.expect_binding is not None and args.operation not in REF_ACTIONS:
        ap.error("--expect-binding requires a branch/integration/origin-push assessment")
    if args.operation and (args.init or args.wire_agents):
        ap.error("read-only operation assessments cannot initialize Git or write agent instructions")
    if args.stage_path and args.operation != "stage_paths":
        ap.error("--stage-path requires --operation stage_paths")
    if args.operation == "stage_paths" and not args.stage_path:
        ap.error("--operation stage_paths requires at least one --stage-path")
    if args.operation == "stage_paths" and not args.json_output:
        ap.error("--operation stage_paths requires --json")
    if args.operation and not (args.once or args.json_output):
        ap.error("--operation requires --once or --json")
    if args.all and (args.json_output or args.operation or args.target):
        ap.error("--json and operation checks require one explicit repository")

    root = os.path.abspath(os.path.expanduser(args.path))
    if not os.path.isdir(root):
        print(f"[gitreal] not a directory: {root}", file=sys.stderr)
        sys.exit(1)

    if args.wire_agents:
        try:
            results = wire_agents(root)
        except OSError as exc:
            print(f"[gitreal] agent wiring failed: {exc}", file=sys.stderr)
            sys.exit(1)
        for name, action in results.items():
            print(f"[gitreal] {action:9} {os.path.join(root, name)}")
        print("[gitreal] agent hook points at .git-real/git-real.json - "
              "agents read it before commit/discard")
        sys.exit(0)


    if args.all:
        run_fleet(args, root)
        return

    if args.json_output:
        if args.operation == "stage_paths":
            state = stage_paths_state(root, args.stage_path, quick=args.quick, request_id=args.request_id)
        else:
            state = build_state(GitRepo(root), {"quick": args.quick, "request_id": args.request_id,
                                                "operation": args.operation, "target": args.target,
                                                "expected_binding": args.expect_binding})
            if args.operation and "requested_action" not in state:
                requested_action(state, args.operation, args.target, args.expect_binding)
        print(json.dumps(state, ensure_ascii=True))
        if not state.get("read_complete"):
            sys.exit(2)
        if args.operation and not state["requested_action"]["safe"]:
            sys.exit(1)
        if args.fail_under is not None and state["scores"]["safe_commit"] < args.fail_under:
            sys.exit(1)
        return

    app = App(root, args.port, args.interval)
    app.config.update(quick=args.quick, request_id=args.request_id, operation=args.operation,
                      target=args.target, expected_binding=args.expect_binding)

    if args.init and not app.repo.is_repo():
        print(f"[gitreal] git init {root}")
        app.repo.init()

    app.rescan()
    s = app.state
    sc = s.get("scores", {})
    if args.operation and "requested_action" not in s:
        requested_action(s, args.operation, args.target, args.expect_binding)
        app._write_outputs()

    if args.once:
        print(f"[gitreal] snapshot written to {app.outdir}/")
        print(f"           safe-commit {sc.get('safe_commit')}% ({sc.get('safe_commit_label')}) | "
              f"safe-discard {sc.get('safe_delete')}% ({sc.get('safe_delete_label')})")
        rc = 0 if s.get("read_complete") else 2
        if args.operation and not s["requested_action"]["safe"]:
            rc = max(rc, 1)
        if args.fail_under is not None and (sc.get("safe_commit") or 0) < args.fail_under:
            print(f"           !! safe-commit {sc.get('safe_commit')}% is below --fail-under {args.fail_under}")
            rc = max(rc, 1)
        sys.exit(rc)

    # auto-detect WSL /mnt path -> polling is more reliable there
    use_poll = args.poll or root.startswith("/mnt/")

    print(f"GIT_REAL v{VERSION}")
    print(f"  watching : {root}")
    print(f"  outputs  : {app.outdir}/git-real.html  +  git-real.json")
    print(f"  watcher  : {'polling' if use_poll else 'watchdog (events)'}")

    stop_event = threading.Event()
    watcher = None
    safety_thread = None
    httpd = None
    try:
        if not use_poll:
            try:
                watcher = start_watchdog(app)
            except Exception:  # noqa: BLE001
                print("  watchdog not available -> falling back to polling")
                use_poll = True
        if use_poll:
            watcher = start_polling(app, stop_event)
        # periodic safety rescan catches index/commit changes that emit no fs events
        def safety():
            while not stop_event.is_set():
                stop_event.wait(max(8, app.interval * 2))
                if not stop_event.is_set():
                    app.rescan()
        safety_thread = threading.Thread(target=safety, daemon=True)
        safety_thread.start()

        if not args.no_server:
            try:
                httpd = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(app))
                print(f"  dashboard: http://127.0.0.1:{args.port}")
            except OSError as e:
                print(f"  [!] could not bind port {args.port}: {e} (use --port N or --no-server)")
        print("  (Ctrl+C to stop)\n")

        if httpd:
            httpd.serve_forever()
        else:
            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        print("\n[gitreal] stopped.")
    finally:
        stop_event.set()
        if watcher is not None:
            if hasattr(watcher, "stop"):
                watcher.stop()
            watcher.join(timeout=2)
        if safety_thread is not None:
            safety_thread.join(timeout=2)
        if httpd:
            # serve_forever has already unwound in this thread. Release our
            # socket explicitly; shutdown alone does not close it.
            httpd.server_close()


if __name__ == "__main__":
    main()
