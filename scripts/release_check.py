#!/usr/bin/env python3
"""Fail-closed public release gate for GIT_REAL v1.2."""

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
        re.compile(r"[A-Za-z]:\\\\Users\\\\[^\\\\\s]+", re.IGNORECASE),
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
    private_markers = [
        item.strip()
        for item in os.environ.get(
            "GIT_REAL_PRIVATE_MARKERS",
            "",
        ).split(",")
        if item.strip()
    ]
    for path, relative in iter_public_files():
        if (
            path.name in FORBIDDEN_NAMES
            or path.name.startswith(".env.")
            and path.name != ".env.example"
        ):
            failures.append(f"forbidden sensitive filename: {relative}")
        if (
            path.suffix.lower() not in TEXT_SUFFIXES
            or path.stat().st_size > 2_000_000
        ):
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
    private_source = (
        Path(private_source_value)
        .expanduser()
        .resolve()
    )
    if not private_source.is_dir():
        failures.append(
            f"private source is not a directory: {private_source}"
        )
        return
    for name in ("gitreal.py", "gitreal_mcp.py"):
        if (ROOT / name).read_bytes() != (
            private_source / name
        ).read_bytes():
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
    expected_root = ROOT.resolve()
    observed_root = Path(
        str(state.get("root") or "")
    ).resolve()
    checks = {
        "version": state.get("version") == "1.2.0",
        "schema_version": state.get("schema_version") == 2,
        "is_repo": state.get("is_repo") is True,
        "read_complete": state.get("read_complete") is True,
        "read_errors": not state.get("read_errors"),
        "root": observed_root == expected_root,
        "commit_index_action": (
            (state.get("actions") or {})
            .get("commit_index", {})
            .get("operation")
            == "commit_index"
        ),
    }
    for label, passed in checks.items():
        if not passed:
            failures.append(
                f"fresh self-state check failed: {label}"
            )
    if all(checks.values()):
        print("PASS fresh v1.2 self-state")


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
            "tests/test_setup_gitreal.py",
            "tests/test_adversarial_safety.py",
            "tests/test_wave43_grc.py",
        ],
        [sys.executable, "tests/test_mcp_status.py"],
        [sys.executable, "tests/test_v11_situational.py"],
        [sys.executable, "tests/test_verdict_scoring.py"],
        [sys.executable, "tests/test_wire_agents.py"],
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

    verify_fresh_self_state(failures)

    if failures:
        for failure in failures:
            print("RELEASE_FAIL " + failure)
        return 1
    print("GIT_REAL_RELEASE_CHECK_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
