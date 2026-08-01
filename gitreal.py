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
  * detect secrets and raise a blinking ALERT
  * compute Safe-Commit% and Safe-Delete% scores (answers: "is it safe to commit
    this?" and "is it safe to nuke this dirty tree?")
  * write two outputs that auto-refresh:
        .git-real/git-real.html   <- for HUMANS (live dashboard)
        .git-real/git-real.json   <- for AGENTS (Claude Code / Codex read this)
  * serve a live dashboard at http://127.0.0.1:8787 with one-click .gitignore add

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
import http.server
import json
import math
import os
import re
import socketserver
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

VERSION = "1.1.0"
OUTPUT_DIRNAME = ".git-real"
DEFAULT_PORT = 8787
DEFAULT_INTERVAL = 4.0
SCAN_SIZE_LIMIT = 1_000_000          # bytes; skip secret-scanning files larger than this
LARGE_FILE_WARN = 5_000_000          # bytes; warn about big untracked/staged files
LARGE_FILE_CRIT = 50_000_000         # bytes; Git-LFS territory
MAX_SCAN_FILES = int(os.environ.get("GITREAL_MAX_SCAN_FILES", "600"))  # safety cap on number of files secret-scanned per pass
HISTORY_TIME_BUDGET = float(os.environ.get("GITREAL_HISTORY_TIME_BUDGET", "15"))
HISTORY_MAX_LINES = int(os.environ.get("GITREAL_HISTORY_MAX_LINES", "400000"))
DEBOUNCE_SECONDS = 0.75              # collapse bursts of fs events into one rescan

# Allowlisting (so a project's own fake fixtures / sample files don't red-alert).
# Inline markers are gitleaks-compatible: drop one in a comment on the secret line.
SECRET_ALLOW_MARKERS = ("gitleaks:allow", "git-real:allow", "gitreal:allow")
# Optional repo-root file: one path glob per line (# comments ok), fnmatch / dir-prefix.
ALLOWLIST_FILENAME = ".gitrealallow"

# ----------------------------------------------------------------------------
# secret detection
# ----------------------------------------------------------------------------
# (name, compiled regex, severity)  severity: "critical" | "high"
_SECRET_RULES = [
    ("AWS Access Key ID",      r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", "critical"),
    ("AWS Secret Access Key",  r"(?i)aws.{0,20}?(secret|access).{0,40}?['\"=:\s]([0-9A-Za-z/+]{40})\b", "critical"),
    ("GitHub PAT (classic)",   r"\bgh[posru]_[0-9A-Za-z]{36}\b", "critical"),
    ("GitHub PAT (fine)",      r"\bgithub_pat_[0-9A-Za-z_]{82}\b", "critical"),
    ("GitLab PAT",             r"\bglpat-[0-9A-Za-z_\-]{20}\b", "critical"),
    ("Stripe Secret Key",      r"\b[sr]k_live_[0-9A-Za-z]{20,}\b", "critical"),
    ("Stripe Test Key",        r"\b[sr]k_test_[0-9A-Za-z]{20,}\b", "high"),
    ("OpenAI API Key",         r"\bsk-(proj-)?[A-Za-z0-9_\-]{20,}\b", "critical"),
    ("Anthropic API Key",      r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b", "critical"),
    ("Google API Key",         r"\bAIza[0-9A-Za-z_\-]{35}\b", "critical"),
    ("Google OAuth Client",    r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b", "high"),
    ("Slack Token",            r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b", "critical"),
    ("Slack Webhook",          r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{40,}", "high"),
    ("Discord Bot Token",      r"\b[MN][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}\b", "high"),
    ("Discord Webhook",        r"https://discord(app)?\.com/api/webhooks/[0-9]{17,}/[A-Za-z0-9_\-]{60,}", "high"),
    ("Twilio API Key",         r"\bSK[0-9a-fA-F]{32}\b", "high"),
    ("SendGrid API Key",       r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", "critical"),
    ("npm Token",              r"\bnpm_[0-9A-Za-z]{36}\b", "critical"),
    ("PyPI Token",             r"\bpypi-AgEIcHlwaS[A-Za-z0-9_\-]{50,}\b", "critical"),
    ("Hugging Face Token",     r"\bhf_[A-Za-z0-9]{30,}\b", "high"),
    ("Private Key Block",      r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----", "critical"),
    ("JSON Web Token",         r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b", "high"),
    # snake_case-aware: a secret-ish word may sit at the TAIL of a longer
    # identifier (aws_secret_access_key, db_password, github_client_secret).
    # \b failed across underscores; the (?:word[_-])* prefix + tail-anchored
    # keyword catches those without over-matching e.g. my_token_count.
    ("Generic Secret Assign",  r"(?i)(?:^|[^A-Za-z0-9_])(?:[A-Za-z0-9]+[_-])*(?:passwd|password|pwd|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token|refresh[_-]?token)\s*[:=]\s*['\"][^'\"\s]{8,}['\"]", "high"),
    ("Connection String",      r"(?i)\b(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp)://[^:\s]+:[^@\s]+@", "high"),
]
SECRET_RULES = [(name, re.compile(pat), sev) for name, pat, sev in _SECRET_RULES]

# Filenames that are secret-bearing by nature; ALERT if present and NOT gitignored.
_SECRET_FILENAME_PATTERNS = [
    r"^\.env$", r"^\.env\.(?!example$|sample$|template$|dist$).+",
    r".*\.pem$", r".*\.key$", r"^id_(rsa|dsa|ecdsa|ed25519)$",
    r".*\.p12$", r".*\.pfx$", r".*\.keystore$", r".*\.jks$",
    r"^credentials$", r"^\.npmrc$", r"^\.pypirc$", r"^\.netrc$",
    r"^secrets?\..+", r".*serviceaccount.*\.json$", r".*-key\.json$",
]
SECRET_FILENAME_RULES = [re.compile(p, re.IGNORECASE) for p in _SECRET_FILENAME_PATTERNS]

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


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def mask_secret(s: str) -> str:
    s = s.strip().strip("'\"")
    if len(s) <= 8:
        return "****"
    return f"{s[:4]}{'*' * 6}{s[-4:]}"


# The "Generic Secret Assign" rule is the noisiest one; these two value shapes are
# real code, NEVER a hardcoded credential, so suppressing them tightens that rule
# without weakening detection (every real-secret fixture carries digits / symbols /
# mixed case and matches NEITHER shape):
#   - shell parameter expansion used as the value: "${VAR:-default}", "${VAR:=x}",
#     "${VAR}", "$VAR", and nested forms "${A:-${B:-}}"  -> a $-reference, no literal.
#   - low-entropy kebab/snake word literals: 'cookie-session', 'auth-token-cookie'
#     -> letters-only dictionary words joined by - / _ with no entropy of a real key.
_SHELL_REF_RE = re.compile(
    r"^\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?[-=?+](.*))?\}$|^\$[A-Za-z_][A-Za-z0-9_]*$")
_KEBAB_SNAKE_WORDS_RE = re.compile(r"^[A-Za-z]+(?:[_-][A-Za-z]+)+$")


def _shell_value_benign(value: str) -> bool:
    """True when `value` is composed only of shell parameter expansions / env refs
    and (recursively) low-entropy default text - never a hardcoded secret. A
    HIGH-entropy literal default (e.g. ${VAR:-<random-key>}) is NOT benign, so a
    secret smuggled in as a shell default is still flagged."""
    v = value.strip()
    if not v:
        return True
    m = _SHELL_REF_RE.match(v)
    if m:
        default = m.group(2)        # text after :- / := / etc.; None for ${VAR} or $VAR
        return True if default is None else _shell_value_benign(default)
    # a plain literal default: benign only if it has no secret-like entropy
    return shannon_entropy(v) < 3.0


def generic_secret_value_is_benign(value: str) -> bool:
    """True when a 'Generic Secret Assign' quoted value is a known non-secret shape
    (shell expansion or low-entropy kebab/snake word literal). Detection-safe: real
    credentials never take either form."""
    if not value:
        return False
    if value.startswith("$") and _shell_value_benign(value):
        return True
    if _KEBAB_SNAKE_WORDS_RE.match(value) and shannon_entropy(value) < 3.5:
        return True
    return False


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
    return re.sub(r"^(https?://)[^@/]+@", r"\1***@", url)


def resolve_remote_identity(url: str, ssh_config_path: str | None = None) -> dict:
    """Resolve a git remote URL to the account/identity a push will authenticate as.

    Accurate about ~/.ssh/config Host aliases (which pin an IdentityFile) versus
    ambiguous bare hosts like github.com (identity = whatever default key/agent
    answers, which may be the wrong account).
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
    }
    if not url:
        return info
    if url.startswith(("http://", "https://")):
        info["scheme"] = "https"
        hm = re.match(r"https?://(?:[^@/]+@)?([^/]+)/", url)
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
    for patterns, cfg in _parse_ssh_config(ssh_config_path):
        if any(fnmatch.fnmatch(info["host"], pat) for pat in patterns):
            real_host = cfg.get("hostname") or info["host"]
            info["real_host"] = real_host
            info["is_ssh_alias"] = real_host != info["host"]
            info["identity_pinned"] = bool(cfg.get("identityfile"))
            if cfg.get("identityfile"):
                info["identity_file"] = os.path.basename(
                    os.path.expanduser(cfg["identityfile"]))
            break
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
    def __init__(self, root: str):
        self.root = os.path.abspath(root)

    def _run(self, *args, timeout=25):
        try:
            r = subprocess.run(
                ["git", "-C", self.root, *args],
                capture_output=True, text=True, timeout=timeout,
            )
            return r.stdout, r.returncode, r.stderr
        except FileNotFoundError:
            return "", 127, "git not found on PATH"
        except subprocess.TimeoutExpired:
            return "", 124, "git command timed out"
        except Exception as e:  # noqa: BLE001
            return "", 1, str(e)

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
        """Parse `git status --porcelain=v2 --branch`."""
        out, rc, _ = self._run("status", "--porcelain=v2", "--branch", "--untracked-files=normal")
        data = {
            "branch": None, "upstream": None, "ahead": 0, "behind": 0,
            "detached": False, "oid": None,
            "staged": [], "modified": [], "untracked": [], "conflicts": [],
            "renamed": [],
        }
        if rc != 0:
            return data
        for line in out.splitlines():
            if line.startswith("# branch.head"):
                head = line.split(" ", 2)[2]
                if head == "(detached)":
                    data["detached"] = True
                else:
                    data["branch"] = head
            elif line.startswith("# branch.upstream"):
                data["upstream"] = line.split(" ", 2)[2]
            elif line.startswith("# branch.ab"):
                m = re.search(r"\+(\d+)\s+-(\d+)", line)
                if m:
                    data["ahead"], data["behind"] = int(m.group(1)), int(m.group(2))
            elif line.startswith("# branch.oid"):
                data["oid"] = line.split(" ", 2)[2]
            elif line.startswith("1 ") or line.startswith("2 "):
                parts = line.split(" ", 8)
                xy = parts[1]
                path = parts[-1]
                if line.startswith("2 "):  # renamed/copied: path<TAB>orig
                    path = path.split("\t")[0]
                    data["renamed"].append(path)
                staged_flag, work_flag = xy[0], xy[1]
                if staged_flag != ".":
                    data["staged"].append({"path": path, "x": staged_flag})
                if work_flag != ".":
                    data["modified"].append({"path": path, "y": work_flag})
            elif line.startswith("u "):
                parts = line.split(" ", 10)
                data["conflicts"].append(parts[-1])
            elif line.startswith("? "):
                data["untracked"].append(line[2:])
        return data

    def ignored_entries(self) -> list[str]:
        """Ignored files, directories collapsed (node_modules/ as one entry)."""
        out, rc, _ = self._run(
            "ls-files", "--others", "--ignored", "--exclude-standard", "--directory"
        )
        if rc != 0:
            return []
        return [l for l in out.splitlines() if l.strip()]

    def branches(self) -> list[dict]:
        fmt = "%(refname:short)\t%(upstream:short)\t%(upstream:track)\t%(committerdate:relative)\t%(objectname:short)\t%(contents:subject)"
        out, rc, _ = self._run("for-each-ref", f"--format={fmt}", "refs/heads")
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
        out, rc, _ = self._run("branch", "--merged", base, "--format=%(refname:short)")
        if rc != 0:
            return set()
        return {l.strip() for l in out.splitlines() if l.strip()}

    def unpushed_commits(self, has_upstream: bool) -> list[dict]:
        # No upstream tracking branch -> there is nothing to be "ahead" of, so
        # nothing is pending-push. (Previously this returned the last 20 commits,
        # which made every remote-less/local-only repo look like it had unpushed
        # work.) A repo with no remote cannot have unpushed commits.
        if not has_upstream:
            return []
        out, rc, _ = self._run("log", "@{upstream}..HEAD", "--pretty=%h\t%s", "-n", "50")
        if rc != 0:
            return []
        commits = []
        for line in out.splitlines():
            h, _, s = line.partition("\t")
            if h:
                commits.append({"hash": h, "subject": s})
        return commits

    def stashes(self) -> list[str]:
        out, rc, _ = self._run("stash", "list")
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
        out, rc, _ = self._run("remote")
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

    def stash_details(self, limit: int = 25) -> list[dict]:
        """Per-stash triage so a caller can tell dead/superseded from unmerged work.

        verdict: 'empty' (captured nothing) | 'superseded' (reverse-applies to the
        tree, i.e. already present) | 'unmerged' (content NOT cleanly in the tree -
        PRESERVE before dropping) | 'unknown'.
        """
        out, rc, _ = self._run("stash", "list", "--format=%gd%x00%gs%x00%cr")
        if rc != 0 or not out.strip():
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
            stat_out, _, _ = self._run("stash", "show", "--numstat", ref)
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
            if files > 0:
                patch, pc, _ = self._run("stash", "show", "-p", ref)
                if pc == 0 and patch.strip():
                    already = self._patch_reverse_applies(patch)
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
                "already_in_head": already, "verdict": verdict,
            })
            if len(details) >= limit:
                break
        return details

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
# classification + secret scan
# ----------------------------------------------------------------------------
def classify_untracked(root: str, path: str) -> str:
    base = path.rstrip("/").split("/")[-1]
    is_dir = path.endswith("/") or os.path.isdir(os.path.join(root, path.rstrip("/")))
    if is_dir and base in JUNK_DIR_NAMES:
        return "junk"
    if any(part in JUNK_DIR_NAMES for part in path.split("/")):
        return "junk"
    if any(r.match(base) for r in JUNK_FILE_RULES):
        return "junk"
    return "new"


def is_secret_filename(path: str) -> bool:
    base = path.rstrip("/").split("/")[-1]
    if base.endswith(".pub"):
        return False
    return any(r.match(base) for r in SECRET_FILENAME_RULES)


def looks_binary(root: str, path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    if ext in BINARY_EXTS:
        return True
    full = os.path.join(root, path)
    try:
        with open(full, "rb") as fh:
            chunk = fh.read(4096)
        return b"\x00" in chunk
    except Exception:  # noqa: BLE001
        return True


def load_secret_allowlist(root: str, config: dict | None = None) -> list[str]:
    """Repo-relative path globs whose secret findings are suppressed. Sourced from an
    optional `.gitrealallow` file at the repo root plus config['secret_allowlist'].
    Lets a project mark its own deliberately-fake test fixtures / sample files so the
    scanner stops red-alerting them - without weakening detection anywhere else."""
    globs: list[str] = []
    p = os.path.join(root, ALLOWLIST_FILENAME)
    try:
        if os.path.isfile(p):
            with open(p, "r", errors="replace") as fh:
                for ln in fh:
                    ln = ln.strip()
                    if ln and not ln.startswith("#"):
                        globs.append(ln)
    except Exception:  # noqa: BLE001
        pass
    if config:
        globs.extend(config.get("secret_allowlist", []) or [])
    return globs


def path_allowlisted(path: str, globs) -> bool:
    """True if `path` (repo-relative) matches an allowlist glob or sits under an
    allowlisted directory prefix (so `tests/` covers `tests/a/b.py`)."""
    if not globs:
        return False
    norm = (path or "").replace("\\", "/").rstrip("/")
    for g in globs:
        gp = g.replace("\\", "/").rstrip("/")
        if not gp:
            continue
        if norm == gp or norm.startswith(gp + "/") or fnmatch.fnmatch(norm, g):
            return True
    return False


def line_allowlisted(text: str) -> bool:
    """True if the line carries an inline allow marker (gitleaks:allow / git-real:allow)."""
    return any(m in text for m in SECRET_ALLOW_MARKERS)


def scan_file_for_secrets(root: str, path: str, allow_globs=None) -> list[dict]:
    full = os.path.join(root, path)
    findings = []
    if allow_globs and path_allowlisted(path, allow_globs):
        return findings
    try:
        if os.path.getsize(full) > SCAN_SIZE_LIMIT:
            return findings
        if looks_binary(root, path):
            return findings
        with open(full, "r", errors="replace") as fh:
            lines = fh.readlines()
    except Exception:  # noqa: BLE001
        return findings
    for i, line in enumerate(lines, 1):
        if len(line) > 2000:
            line = line[:2000]
        if line_allowlisted(line):
            continue
        for name, rx, sev in SECRET_RULES:
            m = rx.search(line)
            if m:
                token = m.group(0)
                if name == "Private Key Block" and not private_key_block_is_real(line):
                    continue
                # guards for the noisiest generic rule
                if name == "Generic Secret Assign":
                    # Extract the value with the SAME class the rule matched: a quoted
                    # run of non-quote, non-space chars, 8+ long. A loose ([^'"]+) grab
                    # over-captures across an apostrophe in prose (e.g. "the site's ...")
                    # into a high-entropy English span that dodges the benign checks -- a
                    # false positive. Real credentials carry no whitespace.
                    val = re.search(r"['\"]([^'\"\s]{8,})['\"]", line)
                    v = val.group(1) if val else ""
                    if generic_secret_value_is_benign(v):
                        continue
                    if val and shannon_entropy(v) < 3.0:
                        continue
                findings.append({
                    "file": path, "line": i, "type": name,
                    "severity": sev, "masked": mask_secret(token),
                })
                break  # one finding per line is enough
    return findings


_PK_MARKER_RX = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----")


def private_key_block_is_real(line: str) -> bool:
    """Marker-only fixtures are not key material (2026-07-10 FP: a scanner
    self-test asserting secretScan(<marker string>) fires). Real key evidence:
    a bare PEM header line (the base64 body follows on the NEXT lines, which a
    per-line scan can't see), or the marker followed by body material on the
    same line (inline string with escaped newlines). A marker embedded in code
    with no body after it is a fixture/reference, not a leak."""
    m = _PK_MARKER_RX.search(line)
    if not m:
        return False
    before = line[:m.start()].strip()
    after = line[m.end():]
    if not before and re.fullmatch(r"[\s'\"`,;)\]]*", after):
        return True  # bare PEM header line — body follows on subsequent lines
    return bool(re.search(r"^(?:\\+[nr]|\s)*[A-Za-z0-9+/=]{40,}", after))


# ----------------------------------------------------------------------------
# secret-in-history detection
# ----------------------------------------------------------------------------
def scan_history_for_secrets(root: str, allow_globs=None,
                             time_budget: float = HISTORY_TIME_BUDGET,
                             max_lines: int = HISTORY_MAX_LINES) -> tuple[list[dict], bool]:
    """Walk the FULL commit graph (every ref, `git log --all -p`) and scan every ADDED
    line for secrets. A hit means the secret was committed at some point - an incident,
    NOT 'caught in time'. This catches a secret that was committed and then DELETED, which
    a current-tree / tracked-blob scan reports clean (the old blind spot). Streams the diff
    and bounds itself by wall-clock + line count; returns (incidents, truncated)."""
    allow_globs = allow_globs or []
    try:
        proc = subprocess.Popen(
            ["git", "-C", root, "log", "--all", "--no-merges", "--no-color",
             "--no-decorate", "-U0", "-p"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, errors="replace", bufsize=1,
        )
    except Exception:  # noqa: BLE001
        return [], False
    incidents: list[dict] = []
    seen: set = set()
    cur_commit = None
    cur_file = None
    cur_allowed = False
    truncated = False
    n = 0
    deadline = time.time() + time_budget
    try:
        for line in proc.stdout:
            n += 1
            if n > max_lines or ((n & 0x7FF) == 0 and time.time() > deadline):
                truncated = True
                break
            if line.startswith("commit "):
                m = re.match(r"commit ([0-9a-f]{7,40})", line)
                if m:
                    cur_commit = m.group(1)[:12]
                continue
            if line.startswith("diff --git"):
                cur_file, cur_allowed = None, False
                continue
            if line.startswith("+++ "):
                p = line[4:].strip()
                cur_file = p[2:] if p.startswith("b/") else None
                cur_allowed = bool(cur_file and path_allowlisted(cur_file, allow_globs))
                continue
            if not line.startswith("+") or line.startswith("+++"):
                continue  # only ADDED lines (skip context / removed / +++ header)
            if cur_allowed:
                continue
            text = line[1:]
            if len(text) > 2000:
                text = text[:2000]
            if line_allowlisted(text):
                continue
            for name, rx, sev in SECRET_RULES:
                m = rx.search(text)
                if not m:
                    continue
                if name == "Private Key Block" and not private_key_block_is_real(text):
                    continue
                if name == "Generic Secret Assign":
                    # Same value class as the rule (non-quote, non-space, 8+). A loose
                    # ([^'"]+) grab over-captures across a prose apostrophe and produces a
                    # false positive (see scan_file_for_secrets). No whitespace in real creds.
                    val = re.search(r"['\"]([^'\"\s]{8,})['\"]", text)
                    v = val.group(1) if val else ""
                    if generic_secret_value_is_benign(v):
                        continue
                    if val and shannon_entropy(v) < 3.0:
                        continue
                masked = mask_secret(m.group(0))
                key = (name, masked, cur_file)
                if key in seen:
                    break
                seen.add(key)
                incidents.append({"type": name, "file": cur_file or "(unknown)",
                                  "severity": sev, "masked": masked,
                                  "commit": cur_commit, "in_history": True})
                break
    finally:
        try:
            proc.stdout.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            proc.terminate()
        except Exception:  # noqa: BLE001
            pass
    return incidents, truncated


# ----------------------------------------------------------------------------
# scoring
# ----------------------------------------------------------------------------
def verdict_band(score: int, positive_is_good=True) -> str:
    if score >= 80:
        return "GO"
    if score >= 40:
        return "CAUTION"
    return "STOP"


def compute_scores(state: dict) -> dict:
    st = state["status"]
    secrets = state["secrets"]
    files = state["files"]

    n_staged = len(st["staged"])
    n_modified = len(st["modified"])
    n_conflicts = len(st["conflicts"])
    untracked_new = [f for f in files if f["category"] == "new"]
    untracked_junk = [f for f in files if f["category"] == "junk"]
    secret_files = [f for f in files if f.get("secret_filename")]
    large_files = [f for f in files if f.get("large")]
    has_dirty = bool(n_staged or n_modified or n_conflicts or untracked_new or untracked_junk)
    unpushed = state["unpushed"]

    # ---- Safe Commit % : how clean/safe is committing right now? ------------
    sc = 100
    sc_reasons = []
    incidents = state.get("history_incidents", [])
    if incidents:
        sc = min(sc, 2)
        sc_reasons.append(f"INCIDENT: {len(incidents)} secret(s) ALREADY COMMITTED to git history - rotate the key(s) and scrub history.")
    if secrets:
        sc = min(sc, 3)
        wt_secrets = [s for s in secrets if not s.get("tracked")]
        if wt_secrets:
            sc_reasons.append(f"{len(wt_secrets)} secret(s) detected in changed files - DO NOT COMMIT.")
    scan = state.get("scan", {})
    if scan.get("truncated"):
        # The secret scan hit its file cap, so a secret could be hiding past it.
        # We CANNOT certify the tree clean - never report GO on an incomplete scan.
        sc = min(sc, 60)
        sc_reasons.append(
            f"INCOMPLETE SCAN: only {scan.get('scanned', 0)} of {scan.get('candidates', 0)} "
            f"file(s) secret-scanned (cap {scan.get('limit', MAX_SCAN_FILES)}); "
            f"{scan.get('unscanned', 0)} file(s) NOT scanned - a secret could be hiding past the cap.")
    if not has_dirty and not secrets:
        sc_reasons.append("Working tree is clean - nothing to commit.")
    elif has_dirty:
        if secret_files:
            sc = min(sc, 8)
            sc_reasons.append(f"{len(secret_files)} secret-bearing file(s) not gitignored (e.g. {secret_files[0]['path']}).")
        if n_conflicts:
            sc -= 50
            sc_reasons.append(f"{n_conflicts} unmerged/conflicted path(s).")
        if untracked_junk:
            sc -= 25
            _jn = ", ".join(f["path"] for f in untracked_junk[:3])
            _jm = f" +{len(untracked_junk) - 3} more" if len(untracked_junk) > 3 else ""
            sc_reasons.append(f"{len(untracked_junk)} build/artifact path(s) not gitignored: {_jn}{_jm}.")
        if large_files:
            sc -= 20
            _lg = ", ".join(f"{f['path']} ({human_size(f.get('size', 0))})" for f in large_files[:3])
            _lm = f" +{len(large_files) - 3} more" if len(large_files) > 3 else ""
            sc_reasons.append(f"{len(large_files)} large file(s) - will bloat history: {_lg}{_lm}.")
        if (n_staged + n_modified + len(untracked_new)) > 200:
            sc -= 15
            sc_reasons.append("Very large changeset (>200 files) - possible accidental `git add -A`.")
        if sc == 100:
            sc_reasons.append("Changes look like normal source edits - safe to commit.")
    sc = max(0, min(100, sc))

    # ---- Safe Delete % : safe to discard the dirty tree? --------------------
    # high = junk/recoverable -> nuke away;  low = precious unsaved work
    sd = 100
    sd_reasons = []
    if not has_dirty:
        sd = 100
        sd_reasons.append("Working tree is clean - nothing would be lost.")
    else:
        if untracked_new:
            # Never-committed work is unrecoverable, so this must land BELOW the
            # CAUTION/STOP boundary (40), not exactly on it. A flat -60 from 100
            # scored 40 and read as OK_TO_DISCARD to the MCP client.
            sd = min(sd - 60, 39)
            sd_reasons.append(f"{len(untracked_new)} new untracked file(s) would be PERMANENTLY lost (never committed).")
        if n_modified:
            sd -= 30
            sd_reasons.append(f"{n_modified} tracked file(s) have uncommitted edits that would be discarded.")
        if n_staged and not n_modified:
            sd -= 15
            sd_reasons.append(f"{n_staged} staged change(s) would be discarded.")
        if unpushed:
            sd -= 10
            sd_reasons.append(f"{len(unpushed)} local commit(s) not on remote - active unsaved-to-remote work present.")
        if untracked_junk and not untracked_new and not n_modified and not n_staged:
            sd_reasons.append("Only build artifacts are dirty - safe to `git clean`.")

    # stash triage (#2) - stashes survive `git clean`/`checkout`, but they hide work
    summ = state.get("stash_summary", {})
    if summ.get("count"):
        parts = []
        if summ.get("unmerged"):
            parts.append(f"{summ['unmerged']} unmerged (PRESERVE before dropping)")
        if summ.get("superseded"):
            parts.append(f"{summ['superseded']} superseded/already-in-HEAD")
        if summ.get("empty"):
            parts.append(f"{summ['empty']} empty")
        detail = "; ".join(parts) if parts else str(summ["count"])
        if summ.get("unmerged"):
            sd_reasons.append(
                f"{summ['count']} stash(es) [{detail}] - {summ['unmerged']} hold work not "
                f"cleanly in HEAD; archive/apply before clearing stashes.")
        else:
            sd_reasons.append(
                f"{summ['count']} stash(es) [{detail}] - none hold unique work; safe to clear.")
    sd = max(0, min(100, sd))

    # topology (#3) - loud, unmissable warning if this path is not its own repo
    topo = state.get("topology", {})
    if topo.get("kind") == "tracked_inside_parent":
        warn = "[TOPOLOGY] " + topo.get(
            "note", "This path is tracked inside a parent repo; results reflect the parent.")
        sc_reasons.insert(0, warn)
        sd_reasons.insert(0, warn)

    return {
        "safe_commit": sc,
        "safe_commit_band": verdict_band(sc),
        "safe_commit_label": "SAFE TO COMMIT" if sc >= 80 else ("REVIEW BEFORE COMMIT" if sc >= 40 else "DO NOT COMMIT"),
        "safe_commit_reasons": sc_reasons,
        "safe_delete": sd,
        "safe_delete_band": verdict_band(sd),
        "safe_delete_label": "SAFE TO DISCARD" if sd >= 80 else ("CAUTION - REVIEW FIRST" if sd >= 40 else "DO NOT DISCARD - UNSAVED WORK"),
        "safe_delete_reasons": sd_reasons,
    }


# ----------------------------------------------------------------------------
# state builder
# ----------------------------------------------------------------------------
def build_state(repo: GitRepo, config: dict) -> dict:
    root = repo.root
    now = datetime.now(timezone.utc).astimezone()
    state = {
        "version": VERSION,
        "generated_at": now.isoformat(timespec="seconds"),
        "generated_at_human": now.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "root": root,
        "root_name": os.path.basename(root.rstrip("/")) or root,
        "is_repo": repo.is_repo(),
        "has_commits": False,
        "status": {"branch": None, "upstream": None, "ahead": 0, "behind": 0,
                   "detached": False, "staged": [], "modified": [], "untracked": [],
                   "conflicts": [], "renamed": []},
        "files": [],
        "branches": [], "default_branch": None, "side_branches": [],
        "ignored": [], "ignored_count": 0,
        "unpushed": [], "stashes": [], "remotes": [], "last_commit": None,
        "secrets": [],
        "scan": {"scanned": 0, "candidates": 0, "unscanned": 0,
                 "truncated": False, "limit": MAX_SCAN_FILES},
        "history_incidents": [], "secrets_in_history": 0,
        "history_checked": False, "history_truncated": False,
        "gitignore_suggestions": [],
        "scores": {},
        "topology": {"kind": "unknown", "toplevel": None},
        "stashes_detail": [],
        "stash_summary": {"count": 0, "empty": 0, "superseded": 0, "unmerged": 0},
        "remotes_detail": [],
        "push_weight": {},
        "muted_secret_files": config.get("muted_secret_files", []),
    }

    if not state["is_repo"]:
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
        return state

    # topology (#3): own repo vs tracked-inside-a-parent (half-extracted standalone)
    top = repo.toplevel()
    if top and os.path.normcase(os.path.realpath(top)) != os.path.normcase(os.path.realpath(root)):
        state["topology"] = {
            "kind": "tracked_inside_parent",
            "toplevel": top,
            "note": (f"'{state['root_name']}' is NOT its own git repo - it is tracked "
                     f"inside {top}. git commands run here operate on that PARENT repo, "
                     f"so every field below reflects the parent, not this folder. "
                     f"Half-extracted standalone: `git init` here to split it out."),
        }
    else:
        state["topology"] = {"kind": "own_repo", "toplevel": top or root}

    state["has_commits"] = repo.has_commits()
    st = repo.status()
    state["status"] = st
    state["remotes"] = repo.remotes()
    state["last_commit"] = repo.last_commit()
    state["stashes"] = repo.stashes()
    state["unpushed"] = repo.unpushed_commits(has_upstream=bool(st["upstream"]))

    # stash triage (#2): dead/superseded vs unmerged work hiding in stashes
    sdet = repo.stash_details()
    state["stashes_detail"] = sdet
    state["stash_summary"] = {
        "count": len(sdet),
        "empty": sum(1 for s in sdet if s["verdict"] == "empty"),
        "superseded": sum(1 for s in sdet if s["verdict"] == "superseded"),
        "unmerged": sum(1 for s in sdet if s["verdict"] == "unmerged"),
    }

    # remote identity (#5): which account/key each push authenticates as
    rdetail = []
    for rn in state["remotes"]:
        ident = resolve_remote_identity(repo.remote_url(rn) or "")
        ident["name"] = rn
        rdetail.append(ident)
    state["remotes_detail"] = rdetail

    # push weight (#6): pack size + largest tracked blobs -> know a slow/heavy push first
    pack = repo.pack_size_bytes()
    blobs = repo.largest_tracked_blobs(5)
    heavy_blobs = [b for b in blobs if b["size"] >= LARGE_FILE_WARN]
    state["push_weight"] = {
        "pack_bytes": pack,
        "pack_human": human_size(pack),
        "largest_blobs": [
            {"path": b["path"], "size": b["size"], "human": human_size(b["size"])}
            for b in blobs
        ],
        "heavy": bool(heavy_blobs) or pack >= 100_000_000,
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
        b2["pushed"] = b["upstream"] is not None
        side.append(b2)
    state["side_branches"] = side

    # ignored
    ignored = repo.ignored_entries()
    state["ignored"] = ignored[:500]
    state["ignored_count"] = len(ignored)
    ignored_set = set(ignored)

    # assemble files list (dirty/staged/untracked/conflict) + classify + scan
    files = []
    seen = set()
    muted = set(config.get("muted_secret_files", []))

    def add_file(path, category, **extra):
        if path in seen:
            # merge categories: prefer the "worst"
            for f in files:
                if f["path"] == path:
                    f.update({k: v for k, v in extra.items() if v})
                    return
        seen.add(path)
        full = os.path.join(root, path.rstrip("/"))
        size = None
        try:
            if os.path.isfile(full):
                size = os.path.getsize(full)
        except Exception:  # noqa: BLE001
            pass
        entry = {
            "path": path, "category": category, "size": size,
            "large": bool(size and size >= LARGE_FILE_WARN),
            "huge": bool(size and size >= LARGE_FILE_CRIT),
            "secret_filename": is_secret_filename(path) and path not in ignored_set and path not in muted,
        }
        entry.update(extra)
        files.append(entry)

    for s in st["staged"]:
        add_file(s["path"], "staged", staged=True, x=s.get("x"))
    for m in st["modified"]:
        add_file(m["path"], "modified", modified=True, y=m.get("y"))
    for c in st["conflicts"]:
        add_file(c, "conflict", conflict=True)
    for u in st["untracked"]:
        cat = classify_untracked(root, u)
        add_file(u, cat, untracked=True)

    # secret content scan (bounded) over text-ish, non-junk-dir files
    allow_globs = load_secret_allowlist(root, config)
    candidates = [f for f in files
                  if not f["path"].endswith("/")
                  and f["path"] not in muted
                  and f["category"] != "junk"]
    secrets = []
    scanned = 0
    scan_truncated = False
    for f in candidates:
        if scanned >= MAX_SCAN_FILES:
            scan_truncated = True            # cap hit: files past here are UNSCANNED
            break
        found = scan_file_for_secrets(root, f["path"], allow_globs=allow_globs)
        scanned += 1
        if found:
            f["has_secret"] = True
            secrets.extend(found)
    state["secrets"] = secrets
    state["files"] = files
    state["scan"] = {
        "scanned": scanned, "candidates": len(candidates),
        "unscanned": max(0, len(candidates) - scanned),
        "truncated": scan_truncated, "limit": MAX_SCAN_FILES,
    }

    # secret-in-history: distinguish "caught in time" from "already committed" (an incident).
    # Walk the FULL commit graph so a committed-then-DELETED secret is still caught - a
    # current-tree / tracked-blob scan alone reports those clean (the old blind spot).
    if config.get("check_history") and state["has_commits"]:
        incidents, hist_truncated = scan_history_for_secrets(root, allow_globs)
        state["history_incidents"] = incidents
        state["history_truncated"] = hist_truncated
        hist_keys = {(i["type"], i["masked"]) for i in incidents}
        for sfd in secrets:                                    # badge still-present findings
            if (sfd["type"], sfd["masked"]) in hist_keys:
                sfd["in_history"] = True
    else:
        state["history_incidents"] = []
        state["history_truncated"] = False
    state["secrets_in_history"] = len(state["history_incidents"])
    state["history_checked"] = bool(config.get("check_history"))

    # gitignore suggestions: junk present and not already ignored
    suggestions = []
    present = set()
    for f in files:
        if f["category"] != "junk":
            continue
        base = f["path"].rstrip("/").split("/")[-1]
        # find a suggestion key contained in the path
        for key, pat in GITIGNORE_SUGGESTIONS.items():
            if key == base or key in f["path"].split("/"):
                if pat not in present and pat not in _read_gitignore_lines(root):
                    suggestions.append({"pattern": pat, "reason": f"untracked {f['path']}"})
                    present.add(pat)
                break
    # also suggest ignoring secret files
    for f in files:
        if f.get("secret_filename"):
            base = f["path"].rstrip("/").split("/")[-1]
            if base not in present and base not in _read_gitignore_lines(root):
                suggestions.append({"pattern": base, "reason": f"secret-bearing file {f['path']}", "secret": True})
                present.add(base)
    state["gitignore_suggestions"] = suggestions

    state["scores"] = compute_scores(state)
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
    if not pattern:
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
  document.getElementById('commitcard').innerHTML=reactorCard('Safe to Commit',sc.safe_commit,sc.safe_commit_band,sc.safe_commit_label,sc.safe_commit_reasons,'agents read this before they commit');
  mountReactor(sc.safe_commit_band);
  document.getElementById('deletecard').innerHTML=scoreCard('Safe to Discard',sc.safe_delete,sc.safe_delete_band,sc.safe_delete_label,sc.safe_delete_reasons,'safe to nuke this dirty tree?');

  // alert
  const secrets=s.secrets||[]; const secFiles=(s.files||[]).filter(f=>f.secret_filename);
  const incidents=s.history_incidents||[];
  let ab=document.getElementById('alertbox'); ab.innerHTML='';
  if(secrets.length||secFiles.length){
    const lines=[];
    secrets.slice(0,6).forEach(x=>lines.push(`${esc(x.type)} in ${esc(x.file)}:${x.line} (${esc(x.masked)})${x.in_history?' <b style="color:#ff3b30">[IN HISTORY'+(x.history_commit?' @'+esc(x.history_commit):'')+']</b>':''}`));
    secFiles.slice(0,4).forEach(f=>lines.push(`secret-bearing file not ignored: ${esc(f.path)}`));
    const head=incidents.length
      ? `INCIDENT - ${incidents.length} secret(s) ALREADY COMMITTED, rotate and scrub history`
      : `SECRET ALERT - ${secrets.length+secFiles.length} finding(s)`;
    ab.innerHTML=`<div class="alert clip"><span class="tri">&#9650;</span><div class="txt">
      <b>${head}</b><br>${lines.join('<br>')}</div></div>`;
  }
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
  bp+=stat('Current branch',branch);
  bp+=stat('Upstream',st.upstream||'<span class="caution">none set</span>');
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
  ms+=stat('Default branch',s.default_branch||'-');
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
    if(f.has_secret)badges+='<span class="badge b-secret">SECRET</span>';
    if(f.secret_filename)badges+='<span class="badge b-secret">!ENV</span>';
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
  document.getElementById('reposcope').textContent=`${esc(s.root_name||'')} · ${(s.files||[]).length} dirty · ${(s.secrets||[]).length} secrets · ${(s.side_branches||[]).length} side-branches`;
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


def render_html(state: dict, port: int, interval: float) -> str:
    html = HTML_TEMPLATE
    html = html.replace("__STATE_JSON__", json.dumps(state))
    html = html.replace("__PORT__", str(port))
    html = html.replace("__INTERVAL__", str(interval))
    html = html.replace("__VERSION__", VERSION)
    html = html.replace("__ROOT_NAME__", state.get("root_name", "repo"))
    return html


# ----------------------------------------------------------------------------
# app state + output writing
# ----------------------------------------------------------------------------
class App:
    def __init__(self, root: str, port: int, interval: float):
        self.repo = GitRepo(root)
        self.root = self.repo.root
        self.port = port
        self.interval = interval
        self.outdir = os.path.join(self.root, OUTPUT_DIRNAME)
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
                    return json.load(fh)
            except Exception:  # noqa: BLE001
                pass
        return {"muted_secret_files": []}

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
        try:
            with open(os.path.join(self.outdir, "git-real.json"), "w") as fh:
                json.dump(self.state, fh, indent=2)
            with open(os.path.join(self.outdir, "git-real.html"), "w") as fh:
                fh.write(render_html(self.state, self.port, self.interval))
        except Exception as e:  # noqa: BLE001
            print(f"[gitreal] write error: {e}", file=sys.stderr)

    def get_state(self):
        with self.lock:
            return self.state


# ----------------------------------------------------------------------------
# HTTP server
# ----------------------------------------------------------------------------
def make_handler(app: App):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self._send(200, render_html(app.get_state(), app.port, app.interval), "text/html; charset=utf-8")
            elif self.path.startswith("/api/state"):
                self._send(200, json.dumps(app.get_state()))
            else:
                self._send(404, json.dumps({"error": "not found"}))

        # Read-only dashboard (v1): no write endpoints. Mutating the repo (gitignore,
        # init, mute) is done via the CLI or the GIT_REAL MCP, not an unauthenticated
        # local HTTP server that any web page could POST to.

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

    def debounced():
        app.rescan()

    class H(FileSystemEventHandler):
        def on_any_event(self, event):
            if _should_ignore_event(getattr(event, "src_path", "")):
                return
            if timer["t"]:
                timer["t"].cancel()
            timer["t"] = threading.Timer(DEBOUNCE_SECONDS, debounced)
            timer["t"].daemon = True
            timer["t"].start()

    obs = Observer()
    obs.schedule(H(), app.root, recursive=True)
    obs.daemon = True
    obs.start()
    return obs


def start_polling(app: App, stop_event: threading.Event):
    def loop():
        last_sig = None
        while not stop_event.is_set():
            try:
                out, _, _ = app.repo._run("status", "--porcelain")
                sig = hashlib.md5(out.encode()).hexdigest()
                if sig != last_sig:
                    app.rescan()
                    last_sig = sig
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
    except OSError:
        pass

    def add(path):
        p = os.path.abspath(path)
        if p not in seen and p not in fleet_ignored:
            seen.add(p)
            found.append(p)

    if pinned:
        for p in pinned:
            pp = p if os.path.isabs(p) else os.path.join(root, p)
            if os.path.isdir(pp) and os.path.exists(os.path.join(pp, ".git")):
                add(pp)

    base = root.rstrip("/").count("/")
    for dirpath, dirnames, filenames in os.walk(root):
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
    return {
        "name": state.get("root_name"), "path": path, "is_repo": state.get("is_repo"),
        "branch": "(detached)" if st.get("detached") else st.get("branch"),
        "safe_commit": sc.get("safe_commit"), "safe_commit_label": sc.get("safe_commit_label"),
        "safe_commit_band": sc.get("safe_commit_band"),
        "safe_delete": sc.get("safe_delete"), "safe_delete_label": sc.get("safe_delete_label"),
        "safe_delete_band": sc.get("safe_delete_band"),
        "dirty_files": len(state.get("files", [])),
        "secret_count": len(state.get("secrets", [])), "secrets": state.get("secrets", [])[:8],
        "secrets_in_history": state.get("secrets_in_history", 0),
        "history_truncated": state.get("history_truncated", False),
        "scan_truncated": state.get("scan", {}).get("truncated", False),
        "side_branches": len(state.get("side_branches", [])),
        "unpushed": len(state.get("unpushed", [])),
        "ahead": st.get("ahead", 0), "behind": st.get("behind", 0),
        "stashes": len(state.get("stashes", [])),
        "stash_summary": state.get("stash_summary", {}),
        "topology": state.get("topology", {}).get("kind"),
        "embedded": state.get("topology", {}).get("kind") == "tracked_inside_parent",
        "remotes_detail": state.get("remotes_detail", []),
        "push_weight": {
            "pack_human": state.get("push_weight", {}).get("pack_human"),
            "heavy": state.get("push_weight", {}).get("heavy", False),
        },
        "last_commit": state.get("last_commit"),
    }


def build_fleet_state(root: str, repo_paths: list[str], config: dict, workers: int = 8) -> dict:
    import concurrent.futures
    repos = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = {ex.submit(repo_summary, p, config): p for p in repo_paths}
        for f in concurrent.futures.as_completed(futs):
            try:
                repos.append(f.result())
            except Exception as e:  # noqa: BLE001
                repos.append({"name": os.path.basename(futs[f]), "path": futs[f],
                              "is_repo": True, "error": str(e)})

    def rank(r):
        return (0 if r.get("secret_count") else 1,
                r.get("safe_delete") if r.get("safe_delete") is not None else 100,
                -(r.get("dirty_files") or 0), r.get("name") or "")
    repos.sort(key=rank)

    # Classify external/vendored repos (remote owned by someone OTHER than the
    # workspace owner) so they don't count against YOUR fleet's cleanliness. A
    # repo with no remote is a local workspace repo, NOT external.
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
    for r in repos:
        o = _owner(r)
        r["remote_owner"] = o
        r["external"] = bool(o and ws_owner and o != ws_owner)
    own = [r for r in repos if not r.get("external")]  # YOUR fleet only

    now = datetime.now(timezone.utc).astimezone()
    totals = {
        "repos": len(repos),
        "external_repos": sum(1 for r in repos if r.get("external")),
        # alarm counts below are over YOUR repos only (external excluded)
        "dirty_repos": sum(1 for r in own if r.get("dirty_files")),
        "repos_with_secrets": sum(1 for r in own if r.get("secret_count")),
        "repos_with_history_secrets": sum(1 for r in own if r.get("secrets_in_history")),
        "scan_truncated_repos": sum(1 for r in own if r.get("scan_truncated")),
        "history_truncated_repos": sum(1 for r in own if r.get("history_truncated")),
        "clean_repos": sum(1 for r in own if not r.get("dirty_files") and not r.get("secret_count") and r.get("is_repo")),
        "total_dirty_files": sum(r.get("dirty_files") or 0 for r in own),
        "total_secrets": sum(r.get("secret_count") or 0 for r in own),
        "total_history_secrets": sum(r.get("secrets_in_history") or 0 for r in own),
        "total_side_branches": sum(r.get("side_branches") or 0 for r in own),
        "total_unpushed": sum(r.get("unpushed") or 0 for r in own),
        "total_stashes": sum(r.get("stashes") or 0 for r in own),
        "repos_with_unmerged_stashes": sum(
            1 for r in own if (r.get("stash_summary") or {}).get("unmerged")),
        "embedded_repos": sum(1 for r in own if r.get("embedded")),
        "heavy_repos": sum(1 for r in own if (r.get("push_weight") or {}).get("heavy")),
    }
    return {
        "version": VERSION, "mode": "fleet",
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
    <span class="live"><span class="pulse"></span> live · updated <span id="updated"></span></span>
    <span id="rootp"></span>
  </div>
</div>
<div class="modal" id="modal"><div class="sheet clip" id="sheet"></div></div>
<script>
const EMBEDDED=__STATE_JSON__;const PORT=__PORT__;let STATE=EMBEDDED;
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function bc(b){return b==='GO'?'go':b==='CAUTION'?'caution':'stop';}
function tcard(n,l,cls){return `<div class="tcard ${cls||''}"><div class="n">${n}</div><div class="l">${l}</div></div>`;}
function render(){
 const s=STATE,t=s.totals||{};
 document.getElementById('totals').innerHTML=
   tcard(t.repos||0,'repos')+
   tcard(t.dirty_repos||0,'dirty repos',(t.dirty_repos?'':'good'))+
   tcard(t.repos_with_secrets||0,'with secrets',(t.repos_with_secrets?'alert':'good'))+
   tcard(t.total_dirty_files||0,'dirty files')+
   tcard(t.total_side_branches||0,'side branches')+
   tcard(t.total_unpushed||0,'unpushed')+
   tcard(t.total_stashes||0,'stashes',(t.repos_with_unmerged_stashes?'alert':''))+
   tcard(t.embedded_repos||0,'embedded',(t.embedded_repos?'alert':''))+
   tcard(t.heavy_repos||0,'heavy repos')+
   tcard(t.external_repos||0,'external');
 const g=document.getElementById('grid');const repos=s.repos||[];
 if(!repos.length){g.innerHTML='<div class="empty">No git repos found under this root.</div>';}
 else g.innerHTML=repos.map((r,i)=>{
   if(r.error)return `<div class="repo clip"><div class="rtop"><span class="rname">${esc(r.name)}</span></div><div class="chip">error: ${esc(r.error)}</div></div>`;
   const cls=r.external?'external':(r.secret_count?'has-secret':(r.dirty_files?'dirty':'clean'));
   let chips='';
   if(r.secret_count)chips+=`<span class="chip secret">&#9650; ${r.secret_count} SECRET${r.secret_count>1?'S':''}</span>`;
   if(r.dirty_files)chips+=`<span class="chip dirty">${r.dirty_files} dirty</span>`;
   if(r.side_branches)chips+=`<span class="chip branch">${r.side_branches} side-branch</span>`;
   if(r.unpushed)chips+=`<span class="chip push">${r.unpushed} unpushed</span>`;
   if(r.stash_count){const un=(r.stash_summary||{}).unmerged||0;
     chips+=`<span class="chip${un?' secret':' branch'}" title="${un} hold unmerged work">${r.stash_count} stash${un?' &middot; '+un+' unmerged':''}</span>`;}
   if(r.embedded)chips+=`<span class="chip branch" title="tracked inside a parent repo - not its own repo">embedded</span>`;
   if((r.push_weight||{}).heavy)chips+=`<span class="chip push" title="heavy pack - slow push/clone">heavy ${esc((r.push_weight||{}).pack_human||'')}</span>`;
   if(r.ahead||r.behind)chips+=`<span class="chip">&#8593;${r.ahead} &#8595;${r.behind}</span>`;
   if(r.external)chips=`<span class="chip" title="remote owned by ${esc(r.remote_owner||'someone else')} — not your fleet; not counted in totals">external · ${esc(r.remote_owner||'3rd-party')}</span>`+chips;
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
 document.getElementById('rootp').textContent=esc(s.root||'');
 document.title=`GIT_REAL FLEET · ${t.repos||0} repos · ${t.repos_with_secrets||0} secret`;
}
async function refresh(){try{const r=await fetch(`http://127.0.0.1:${PORT}/api/fleet`,{cache:'no-store'});if(r.ok){STATE=await r.json();render();}}catch(e){}}
async function openRepo(i){
 const r=(STATE.repos||[])[i];if(!r)return;
 const sheet=document.getElementById('sheet');
 sheet.innerHTML=`<span class="closex" onclick="closeModal()">&times;</span><h2>${esc(r.name)}</h2><div class="mpath">${esc(r.path)}</div><div class="empty">loading…</div>`;
 document.getElementById('modal').classList.add('open');
 let st=null;
 try{const resp=await fetch(`http://127.0.0.1:${PORT}/api/repo?path=`+encodeURIComponent(r.path));if(resp.ok)st=await resp.json();}catch(e){}
 if(!st){sheet.querySelector('.empty').textContent='Detail needs the live server (open via the URL, not the file).';return;}
 const sc=st.scores||{};
 const reasons=(arr)=>`<ul class="reasons">${(arr||[]).map(x=>`<li>${esc(x)}</li>`).join('')||'<li>-</li>'}</ul>`;
 const fl=(st.files||[]).map(f=>{const cm={staged:'b-staged',modified:'b-dirty',new:'b-new',junk:'b-junk',conflict:'b-conflict'}[f.category]||'b-dirty';
   const nm={staged:'STAGED',modified:'DIRTY',new:'NEW',junk:'JUNK',conflict:'CONFLICT'}[f.category]||'DIRTY';
   return `<li><span class="badge ${cm}">${nm}</span>${f.has_secret||f.secret_filename?'<span class="badge b-secret">SECRET</span>':''}<span class="fpath">${esc(f.path)}</span></li>`;}).join('');
 const secs=(st.secrets||[]).map(x=>`<li><span class="badge b-secret">${esc(x.severity)}</span><span class="fpath">${esc(x.type)} - ${esc(x.file)}:${x.line} (${esc(x.masked)})${x.in_history?' <b style="color:#ff3b30">[IN HISTORY]</b>':''}</span></li>`).join('');
 sheet.innerHTML=`<span class="closex" onclick="closeModal()">&times;</span><h2>${esc(st.root_name)}</h2><div class="mpath">${esc(st.root)}</div>
   <div class="scorebar"><div class="sc"><div class="v ${bc(sc.safe_commit_band)}">${sc.safe_commit}</div><div class="k">${esc(sc.safe_commit_label||'')}</div></div>
   <div class="sc"><div class="v ${bc(sc.safe_delete_band)}">${sc.safe_delete}</div><div class="k">${esc(sc.safe_delete_label||'')}</div></div></div>
   <div class="subhdr">why - safe to commit</div>${reasons(sc.safe_commit_reasons)}
   <div class="subhdr">why - safe to discard</div>${reasons(sc.safe_delete_reasons)}
   ${secs?`<div class="subhdr">secrets</div><ul class="flist">${secs}</ul>`:''}
   <div class="subhdr">working tree (${(st.files||[]).length})</div><ul class="flist">${fl||'<li class="fpath">clean</li>'}</ul>`;
}
function closeModal(){document.getElementById('modal').classList.remove('open');}
document.getElementById('modal').addEventListener('click',e=>{if(e.target.id==='modal')closeModal();});
render();setInterval(refresh,Math.max(2000,__INTERVAL__*1000));refresh();
</script></body></html>"""


def render_fleet_html(state: dict, port: int, interval: float) -> str:
    html = FLEET_HTML
    html = html.replace("__STATE_JSON__", json.dumps(state))
    html = html.replace("__PORT__", str(port))
    html = html.replace("__INTERVAL__", str(interval))
    html = html.replace("__VERSION__", VERSION)
    html = html.replace("__REPO_COUNT__", str(state.get("totals", {}).get("repos", 0)))
    return html


class FleetApp:
    def __init__(self, root: str, port: int, interval: float, pinned=None):
        self.root = os.path.abspath(root)
        self.port, self.interval = port, interval
        self.pinned = pinned or []
        self.outdir = os.path.join(self.root, OUTPUT_DIRNAME)
        os.makedirs(self.outdir, exist_ok=True)
        gi = os.path.join(self.outdir, ".gitignore")
        if not os.path.exists(gi):
            try:
                open(gi, "w").write("*\n")
            except Exception:  # noqa: BLE001
                pass
        self.config = {"muted_secret_files": []}
        self.state, self.lock = {}, threading.Lock()
        self.repo_paths = discover_repos(self.root, pinned=self.pinned)

    def rescan(self):
        with self.lock:
            self.repo_paths = discover_repos(self.root, pinned=self.pinned)
            self.state = build_fleet_state(self.root, self.repo_paths, self.config)
            try:
                with open(os.path.join(self.outdir, "git-real-fleet.json"), "w") as fh:
                    json.dump(self.state, fh, indent=2)
                with open(os.path.join(self.outdir, "git-real-fleet.html"), "w") as fh:
                    fh.write(render_fleet_html(self.state, self.port, self.interval))
            except Exception as e:  # noqa: BLE001
                print(f"[gitreal] fleet write error: {e}", file=sys.stderr)
            return self.state

    def get_state(self):
        with self.lock:
            return self.state

    def repo_state(self, path: str):
        path = os.path.abspath(path)
        if path not in {os.path.abspath(p) for p in self.repo_paths}:
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
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self._send(200, render_fleet_html(app.get_state(), app.port, app.interval), "text/html; charset=utf-8")
            elif self.path.startswith("/api/fleet"):
                self._send(200, json.dumps(app.get_state()))
            elif self.path.startswith("/api/repo"):
                q = urllib.parse.urlparse(self.path).query
                path = urllib.parse.parse_qs(q).get("path", [""])[0]
                self._send(200, json.dumps(app.repo_state(path)))
            else:
                self._send(404, json.dumps({"error": "not found"}))

        # Read-only dashboard (v1): no write endpoints (see make_handler).

    return H


def run_fleet(args, root: str):
    pinned = []
    pin_file = os.path.join(root, OUTPUT_DIRNAME, "fleet.json")
    if os.path.isfile(pin_file):
        try:
            pinned = json.load(open(pin_file)).get("repos", [])
        except Exception:  # noqa: BLE001
            pass
    app = FleetApp(root, args.port, args.interval, pinned=pinned)
    app.config["check_history"] = getattr(args, "history", False)
    app.rescan()
    t = app.state.get("totals", {})

    if args.once:
        print(f"[gitreal] FLEET snapshot -> {app.outdir}/git-real-fleet.html")
        print(f"           {t.get('repos',0)} repos | {t.get('dirty_repos',0)} dirty | "
              f"{t.get('repos_with_secrets',0)} with secrets | {t.get('total_side_branches',0)} side-branches")
        rc = 0
        # FLEET --fail-on-secret fails CLOSED, exactly like the single-repo path: any repo
        # with a working-tree secret, a secret ALREADY IN HISTORY, or an incomplete scan
        # (working-tree file cap or history budget) forces a non-zero exit.
        if args.fail_on_secret and (t.get("repos_with_secrets") or t.get("repos_with_history_secrets")
                                    or t.get("scan_truncated_repos") or t.get("history_truncated_repos")):
            if t.get("repos_with_secrets"):
                print(f"           !! {t['repos_with_secrets']} repo(s) contain secrets")
            if t.get("repos_with_history_secrets"):
                print(f"           !! {t['repos_with_history_secrets']} repo(s) have secrets ALREADY IN HISTORY")
            if t.get("scan_truncated_repos"):
                print(f"           !! {t['scan_truncated_repos']} repo(s) had an INCOMPLETE scan "
                      f"(file cap hit) - cannot certify secret-free")
            if t.get("history_truncated_repos"):
                print(f"           !! {t['history_truncated_repos']} repo(s) had an INCOMPLETE history scan "
                      f"(budget hit) - cannot certify history secret-free")
            rc = 2
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

    def loop():
        while not stop_event.is_set():
            stop_event.wait(max(3, args.interval))
            if not stop_event.is_set():
                app.rescan()
    threading.Thread(target=loop, daemon=True).start()

    httpd = None
    if not args.no_server:
        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", args.port), make_fleet_handler(app))
            print(f"  dashboard: http://127.0.0.1:{args.port}")
        except OSError as e:
            print(f"  [!] could not bind port {args.port}: {e}")
    print("  (Ctrl+C to stop)\n")
    try:
        if httpd:
            httpd.serve_forever()
        else:
            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        print("\n[gitreal] fleet stopped.")
    finally:
        stop_event.set()
        if httpd:
            httpd.shutdown()


# ----------------------------------------------------------------------------
# agent wiring  (--wire-agents): install the GIT_REAL hook into agent rule files
# ----------------------------------------------------------------------------
WIRE_BEGIN = "<!-- GIT_REAL hook -->"
WIRE_END = "<!-- /GIT_REAL -->"
# Fixed basenames only (never user input), so wiring can never escape the repo root.
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
        "Before any `git commit`, `git checkout .`, `git clean -fd`, or `git reset --hard`:",
        "",
        "1. Refresh the verdict: run `python gitreal.py . --once` (or call the GIT_REAL MCP",
        "   tool, which is always live; skip the refresh if GIT_REAL is already running and",
        "   watching this repo). The JSON stamps `generated_at` so you can tell if it is stale.",
        "2. Read `.git-real/git-real.json` and act on it:",
        '   - `scores.safe_commit_band` not `"GO"` (or `scores.safe_commit` < 80): do NOT',
        "     commit. Surface `scores.safe_commit_reasons` and fix them first.",
        '   - `scores.safe_delete_band` not `"GO"`: do NOT discard the tree. There is unsaved',
        "     work in `scores.safe_delete_reasons`.",
        "   - `secrets[]` non-empty: STOP and warn the user. A secret is about to be committed.",
        "",
        "Read the verdict and act on it. Do not ask the user about a dirty tree; the answer is",
        "in the file.",
        WIRE_END,
    ])


def _wire_one(path: str, block: str) -> str:
    """Insert or replace the managed block in one file. Returns the action taken:
    created / updated / inserted / unchanged."""
    if not os.path.isfile(path):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(block + "\n")
        return "created"
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        content = fh.read()
    if WIRE_BEGIN in content and WIRE_END in content:
        start = content.index(WIRE_BEGIN)
        end = content.index(WIRE_END, start) + len(WIRE_END)
        new = content[:start] + block + content[end:]
        if new == content:
            return "unchanged"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(new)
        return "updated"
    # append, keeping a blank line of separation from existing content
    sep = "" if content.endswith("\n\n") else ("\n" if content.endswith("\n") else "\n\n")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(sep + block + "\n")
    return "inserted"


def wire_agents(root: str) -> dict:
    """Idempotently install the GIT_REAL agent hook into the repo's agent rule files.
    Updates every one of CLAUDE.md / AGENTS.md / .cursorrules that already exists; if none
    exist, creates AGENTS.md. Never touches any other file and never writes outside `root`.
    Returns {filename: action}."""
    root = os.path.abspath(root)
    block = wire_block()
    existing = [n for n in WIRE_TARGETS if os.path.isfile(os.path.join(root, n))]
    targets = existing or [WIRE_DEFAULT]
    return {name: _wire_one(os.path.join(root, name), block) for name in targets}


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
    ap.add_argument("--init", action="store_true", help="git init if PATH is not a repo")
    ap.add_argument("--all", "--fleet", dest="all", action="store_true",
                    help="FLEET mode: scan PATH for ALL git repos and show the multi-repo command center")
    ap.add_argument("--fail-under", type=int, default=None, metavar="N",
                    help="guardrail (with --once): exit 1 if safe-commit < N (use as a pre-commit hook)")
    ap.add_argument("--fail-on-secret", action="store_true",
                    help="guardrail (with --once): exit 2 if any secret is detected")
    ap.add_argument("--history", action="store_true",
                    help="also scan git history: flag secrets that were ALREADY COMMITTED (incidents)")
    ap.add_argument("--wire-agents", action="store_true",
                    help="install the GIT_REAL hook into CLAUDE.md / AGENTS.md / .cursorrules "
                         "(idempotent; creates AGENTS.md if none exist) and exit")
    args = ap.parse_args()

    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"[gitreal] not a directory: {root}", file=sys.stderr)
        sys.exit(1)

    if args.wire_agents:
        results = wire_agents(root)
        for name, action in results.items():
            print(f"[gitreal] {action:9} {os.path.join(root, name)}")
        print("[gitreal] agent hook points at .git-real/git-real.json - "
              "agents read it before commit/discard")
        sys.exit(0)

    if args.all:
        run_fleet(args, root)
        return

    app = App(root, args.port, args.interval)
    app.config["check_history"] = args.history

    if args.init and not app.repo.is_repo():
        print(f"[gitreal] git init {root}")
        app.repo.init()

    app.rescan()
    s = app.state
    sc = s.get("scores", {})

    if args.once:
        print(f"[gitreal] snapshot written to {app.outdir}/")
        print(f"           safe-commit {sc.get('safe_commit')}% ({sc.get('safe_commit_label')}) | "
              f"safe-discard {sc.get('safe_delete')}% ({sc.get('safe_delete_label')})")
        if s.get("secrets"):
            print(f"           !! {len(s['secrets'])} secret finding(s)")
        hist_secrets = s.get("secrets_in_history", 0) or 0
        if hist_secrets:
            print(f"           !! {hist_secrets} secret(s) ALREADY IN HISTORY (incident) - rotate the key(s) and scrub history")
        scan = s.get("scan", {})
        if scan.get("truncated"):
            print(f"           !! INCOMPLETE SCAN: {scan.get('unscanned')} of {scan.get('candidates')} "
                  f"file(s) NOT scanned (cap {scan.get('limit')}) - cannot certify secret-free")
        if s.get("history_truncated"):
            print("           !! INCOMPLETE HISTORY SCAN (budget hit) - cannot certify history secret-free")
        rc = 0
        # --fail-on-secret fails CLOSED: never exit 0 when a secret could exist unseen. A
        # working-tree secret, a secret ALREADY IN HISTORY, OR a scan we could not finish
        # (working-tree file cap or history budget) each force a non-zero exit.
        if args.fail_on_secret and (s.get("secrets") or hist_secrets
                                    or scan.get("truncated") or s.get("history_truncated")):
            rc = 2
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
    if not use_poll:
        try:
            start_watchdog(app)
        except Exception:  # noqa: BLE001
            print("  watchdog not available -> falling back to polling")
            use_poll = True
    if use_poll:
        start_polling(app, stop_event)
    # periodic safety rescan catches index/commit changes that emit no fs events
    def safety():
        while not stop_event.is_set():
            stop_event.wait(max(8, app.interval * 2))
            if not stop_event.is_set():
                app.rescan()
    threading.Thread(target=safety, daemon=True).start()

    httpd = None
    if not args.no_server:
        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(app))
            print(f"  dashboard: http://127.0.0.1:{args.port}")
        except OSError as e:
            print(f"  [!] could not bind port {args.port}: {e} (use --port N or --no-server)")
    print("  (Ctrl+C to stop)\n")

    try:
        if httpd:
            httpd.serve_forever()
        else:
            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        print("\n[gitreal] stopped.")
    finally:
        stop_event.set()
        if httpd:
            httpd.shutdown()


if __name__ == "__main__":
    main()
