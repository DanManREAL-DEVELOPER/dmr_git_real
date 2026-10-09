#!/usr/bin/env python3
"""Fail-closed public release gate for GIT_REAL v1.3.1."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {
    ".git",
    ".git-real",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "venv",
}
TEXT_SUFFIXES = {
    "",
    ".py",
    ".md",
    ".txt",
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".css",
    ".sh",
    ".html",
}
GENERIC_PRIVATE_PATTERNS = (
    ("POSIX home path", re.compile(r"/(?:home|Users)/[A-Za-z0-9._-]+/")),
    (
        "Windows user path",
        re.compile(r"[A-Za-z]:\\+Users\\+[^\\\s]+", re.IGNORECASE),
    ),
    (
        "WSL user path",
        re.compile(r"\\\\wsl\$\\[^\\]+\\home\\[^\\]+", re.IGNORECASE),
    ),
    (
        "private key block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    (
        "embedded HTTP credential",
        re.compile(r"https?://[^\s/@:]+:[^\s/@]+@"),
    ),
)
EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])"
    r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"
    r"(?![A-Za-z0-9._%+-])"
)
FORBIDDEN_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    "id_rsa",
    "id_ed25519",
}
STALE_V11_TEXT = (
    "--fail-on-secret",
    "secrets_in_history",
    "list_secrets",
    "scan.truncated",
)


def run(command: list[str]) -> tuple[int, str]:
    try:
        result = subprocess.run(
            command,
            cwd=str(ROOT),
            text=True,
            capture_output=True,
            check=False,
            timeout=240,
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    return result.returncode, (result.stdout + result.stderr).strip()


def iter_public_files():
    """Inspect tracked plus nonignored candidates, never ignored local reports."""
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT, capture_output=True, check=False, timeout=30,
    )
    if result.returncode or (result.stdout and not result.stdout.endswith(b"\0")):
        raise ValueError("Public file inventory is unavailable or incomplete")
    for name in sorted(set(result.stdout.split(b"\0")) - {b""}):
        relative = Path(os.fsdecode(name))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Public file inventory contains an unsafe path")
        path = ROOT / relative
        if path.is_file() or path.is_symlink():
            yield path, relative


def privacy_failures() -> list[str]:
    failures: list[str] = []
    private_markers = [
        item.strip()
        for item in os.environ.get(
            "GIT_REAL_PRIVATE_MARKERS",
            "",
        ).split(",")
        if item.strip()
    ]
    try:
        files = list(iter_public_files())
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        return ["public file inventory failed: " + str(exc)]
    for path, relative in files:
        if path.is_symlink():
            failures.append(f"symlink in public release surface: {relative}")
            continue
        if (
            path.name in FORBIDDEN_NAMES
            or path.name.startswith(".env.")
            and path.name != ".env.example"
        ):
            failures.append(f"forbidden sensitive filename: {relative}")
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if path.stat().st_size > 2_000_000:
            failures.append(f"text exceeds bounded privacy inspection: {relative}")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            failures.append(
                f"non-text payload in release surface: {relative}"
            )
            continue
        for label, pattern in GENERIC_PRIVATE_PATTERNS:
            matches = list(pattern.finditer(text))
            if label == "embedded HTTP credential":
                matches = [
                    match
                    for match in matches
                    if "ghp_TOKEN" not in match.group(0)
                    and "***@" not in match.group(0)
                ]
            if matches:
                failures.append(f"{label}: {relative}")
        for line in text.splitlines():
            for email in EMAIL_RE.findall(line):
                allowed_example = email.lower().endswith(
                    "@example.invalid"
                )
                allowed_ssh_remote = (
                    email.startswith("git@")
                    and email + ":" in line
                )
                allowed_redaction_example = (
                    "http" in line
                    and (
                        "ghp_TOKEN@" in line
                        or "***@" in line
                    )
                )
                if not (
                    allowed_example
                    or allowed_ssh_remote
                    or allowed_redaction_example
                ):
                    failures.append(
                        f"non-example email address: {relative}"
                    )
        lowered = text.lower()
        for marker in private_markers:
            escaped = re.escape(marker.lower())
            pattern = re.compile(
                rf"(?<![a-z0-9]){escaped}(?![a-z0-9])"
            )
            if pattern.search(lowered):
                failures.append(
                    f"configured private marker: {relative}"
                )
        if relative not in {
            Path("scripts/release_check.py"),
        }:
            for stale in STALE_V11_TEXT:
                if stale in text:
                    failures.append(
                        f"stale v1.1 contract {stale!r}: {relative}"
                    )
    return sorted(set(failures))


def verify_engine_parity(
    failures: list[str],
) -> None:
    private_source_value = os.environ.get(
        "GIT_REAL_PRIVATE_SOURCE",
        "",
    ).strip()
    if not private_source_value:
        return
    try:
        private_source = (
            Path(private_source_value)
            .expanduser()
            .resolve()
        )
        is_directory = private_source.is_dir()
    except (OSError, RuntimeError, ValueError) as exc:
        failures.append(f"private source is unavailable: {exc}")
        return
    if not is_directory:
        failures.append(
            f"private source is not a directory: {private_source}"
        )
        return
    for name in ("gitreal.py", "gitreal_mcp.py"):
        try:
            public_bytes = (ROOT / name).read_bytes()
            private_bytes = (private_source / name).read_bytes()
        except (OSError, RuntimeError, ValueError) as exc:
            failures.append(f"engine parity unavailable for {name}: {exc}")
            continue
        if public_bytes != private_bytes:
            failures.append(
                f"engine drift from private source: {name}"
            )


def verify_fresh_self_state(
    failures: list[str],
) -> None:
    command = [
        sys.executable,
        "gitreal.py",
        ".",
        "--quick",
        "--json",
    ]
    code, output = run(command)
    if code != 0:
        failures.append(
            "fresh self-state failed:\n" + output
        )
        return
    try:
        state = json.loads(output)
    except json.JSONDecodeError:
        failures.append(
            "fresh self-state was not valid JSON"
        )
        return
    if not isinstance(state, dict):
        failures.append("fresh self-state was not a JSON object")
        return
    root_matches = False
    root_value = state.get("root")
    if isinstance(root_value, str) and root_value:
        try:
            observed_root = Path(root_value)
            root_matches = (
                observed_root.is_absolute()
                and observed_root.resolve() == ROOT.resolve()
            )
        except (OSError, RuntimeError, ValueError):
            root_matches = False
    read_errors = state.get("read_errors")
    actions = state.get("actions")
    commit_action = (
        actions.get("commit_index")
        if isinstance(actions, dict)
        else None
    )
    checks = {
        "version": state.get("version") == "1.3.1",
        "schema_version": state.get("schema_version") == 2,
        "is_repo": state.get("is_repo") is True,
        "read_complete": state.get("read_complete") is True,
        "read_errors": isinstance(read_errors, list) and not read_errors,
        "root": root_matches,
        "commit_index_action": (
            isinstance(commit_action, dict)
            and commit_action.get("operation") == "commit_index"
            and isinstance(commit_action.get("safe"), bool)
            and commit_action.get("decision")
            == ("ALLOW" if commit_action["safe"] else "BLOCK")
        ),
    }
    for label, passed in checks.items():
        if not passed:
            failures.append(
                f"fresh self-state check failed: {label}"
            )
    if all(checks.values()):
        print("PASS fresh v1.3.1 self-state")


def main() -> int:
    failures = privacy_failures()
    verify_engine_parity(failures)

    commands = [
        [sys.executable, "scripts/check_structure.py"],
        [
            sys.executable,
            "-m",
            "compileall",
            "-q",
            "gitreal.py",
            "gitreal_mcp.py",
            "setup_gitreal.py",
            "scripts",
            "tests",
        ],
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "tests",
        ],
    ]
    for command in commands:
        code, output = run(command)
        label = " ".join(command)
        if code != 0:
            failures.append(
                f"command failed: {label}\n{output}"
            )
        else:
            print(f"PASS {label}")
            if output:
                print(output)

    verify_fresh_self_state(failures)

    if failures:
        for failure in failures:
            print("RELEASE_FAIL " + failure)
        return 1
    print("GIT_REAL_RELEASE_CHECK_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
