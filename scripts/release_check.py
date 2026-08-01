#!/usr/bin/env python3
"""Fail-closed public release gate for structure, privacy, tests, and runtime."""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", ".git-real", "__pycache__", ".pytest_cache", ".venv", "venv"}
TEXT_SUFFIXES = {"", ".py", ".md", ".txt", ".yml", ".yaml", ".json", ".toml", ".css", ".sh", ".html"}
GENERIC_PRIVATE_PATTERNS = (
    ("POSIX home path", re.compile(r"/(?:home|Users)/[A-Za-z0-9._-]+/")),
    ("Windows user path", re.compile(r"[A-Za-z]:\\\\Users\\\\[^\\\\\s]+", re.IGNORECASE)),
    ("WSL user path", re.compile(r"\\\\wsl\$\\[^\\]+\\home\\[^\\]+", re.IGNORECASE)),
    ("private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("embedded HTTP credential", re.compile(r"https?://[^\s/@:]+:[^\s/@]+@")),
)
EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![A-Za-z0-9._%+-])")
FORBIDDEN_NAMES = {".env", ".env.local", ".env.production", "id_rsa", "id_ed25519"}


def run(command: list[str]) -> tuple[int, str]:
    try:
        result = subprocess.run(
            command,
            cwd=str(ROOT),
            text=True,
            capture_output=True,
            check=False,
            timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    return result.returncode, (result.stdout + result.stderr).strip()


def iter_public_files():
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if any(part in SKIP_DIRS for part in relative.parts):
            continue
        yield path, relative


def privacy_failures() -> list[str]:
    failures: list[str] = []
    private_markers = [item.strip() for item in os.environ.get("GIT_REAL_PRIVATE_MARKERS", "").split(",") if item.strip()]
    for path, relative in iter_public_files():
        if path.name in FORBIDDEN_NAMES or path.name.startswith(".env.") and path.name != ".env.example":
            failures.append(f"forbidden sensitive filename: {relative}")
        if path.suffix.lower() not in TEXT_SUFFIXES or path.stat().st_size > 2_000_000:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            failures.append(f"non-text payload in release surface: {relative}")
            continue
        for label, pattern in GENERIC_PRIVATE_PATTERNS:
            matches = list(pattern.finditer(text))
            if label == "embedded HTTP credential":
                matches = [
                    match for match in matches
                    if "ghp_TOKEN" not in match.group(0) and "***@" not in match.group(0)
                ]
            if matches:
                failures.append(f"{label}: {relative}")
        for line in text.splitlines():
            for email in EMAIL_RE.findall(line):
                allowed_example = email.lower().endswith("@example.invalid")
                allowed_ssh_remote = email.startswith("git@") and email + ":" in line
                allowed_redaction_example = (
                    "http" in line and ("ghp_TOKEN@" in line or "***@" in line)
                )
                if not (allowed_example or allowed_ssh_remote or allowed_redaction_example):
                    failures.append(f"non-example email address: {relative}")
        lowered = text.lower()
        for marker in private_markers:
            escaped = re.escape(marker.lower())
            pattern = re.compile(rf"(?<![a-z0-9]){escaped}(?![a-z0-9])")
            if pattern.search(lowered):
                failures.append(f"configured private marker: {relative}")
    return sorted(set(failures))


def main() -> int:
    failures = privacy_failures()
    private_source_value = os.environ.get("GIT_REAL_PRIVATE_SOURCE", "").strip()
    private_source = Path(private_source_value).expanduser().resolve() if private_source_value else None
    if private_source is not None and private_source.is_dir():
        for name in ("gitreal.py", "gitreal_mcp.py"):
            if (ROOT / name).read_bytes() != (private_source / name).read_bytes():
                failures.append(f"engine drift from private source: {name}")
    commands = [
        [sys.executable, "scripts/check_structure.py"],
        [sys.executable, "-m", "compileall", "-q", "gitreal.py", "gitreal_mcp.py", "setup_gitreal.py", "scripts", "tests"],
    ]
    commands.extend([sys.executable, str(path.relative_to(ROOT))] for path in sorted((ROOT / "tests").glob("test_*.py")))
    for command in commands:
        code, output = run(command)
        label = " ".join(command)
        if code != 0:
            failures.append(f"command failed: {label}\n{output}")
        else:
            print(f"PASS {label}")
    history_args = [sys.executable, "gitreal.py", ".", "--once", "--no-server", "--history", "--fail-on-secret"]
    if (ROOT / ".git").exists():
        code, output = run(history_args)
        if code != 0:
            failures.append("self secret/history scan failed:\n" + output)
        else:
            print("PASS self secret/history scan")
    else:
        print("SKIP self history scan: distribution directory is not a Git repository")
    if failures:
        for failure in failures:
            print("RELEASE_FAIL " + failure)
        return 1
    print("GIT_REAL_RELEASE_CHECK_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
