#!/usr/bin/env python3
"""Safe, dependency-free installer for the GIT_REAL v1.3.1 drop-in tool."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone


HERE = Path(__file__).resolve().parent
RUNTIME_FILES = ("gitreal.py", "gitreal_mcp.py")
HOOK_BEGIN = "# GIT_REAL managed block: begin"
HOOK_END = "# GIT_REAL managed block: end"
AGENT_BEGIN = "<!-- GIT_REAL hook -->"
AGENT_END = "<!-- /GIT_REAL -->"


class SetupError(RuntimeError):
    """A setup problem with a direct, user-actionable message."""


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=str(cwd),
            text=True,
            capture_output=True,
            check=False,
            timeout=120,
        )
    except FileNotFoundError as exc:
        raise SetupError(f"Required command is unavailable: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SetupError(f"Command timed out: {' '.join(command)}") from exc


def require_runtime() -> None:
    if sys.version_info < (3, 10):
        raise SetupError("Python 3.10 or newer is required.")
    missing = [name for name in RUNTIME_FILES if not (HERE / name).is_file()]
    if missing:
        raise SetupError("Installer package is incomplete. Missing: " + ", ".join(missing))


def ensure_git_repo(target: Path, initialize: bool) -> None:
    probe = run(["git", "rev-parse", "--show-toplevel"], cwd=target)
    if probe.returncode == 0:
        if Path(probe.stdout.strip()).resolve() != target.resolve():
            raise SetupError("Target must be the actual repository root, not a nested directory.")
        return
    if not initialize:
        raise SetupError(
            "Target is not a Git repository. Re-run with --init only if creating one is intended."
        )
    created = run(["git", "init"], cwd=target)
    if created.returncode != 0:
        raise SetupError("git init failed: " + (created.stderr.strip() or "unknown error"))


def plain_file(path: Path) -> None:
    """Refuse aliases and special destinations before rewriting user bytes."""
    if path.is_symlink():
        raise SetupError(f"Refusing symlinked installation path: {path.name}")
    if path.exists():
        if not path.is_file():
            raise SetupError(f"Installation destination is not a regular file: {path}")
        if path.stat().st_nlink > 1:
            raise SetupError(f"Refusing multiply linked installation file: {path}")


def plain_directory(path: Path) -> None:
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise SetupError(f"Installation directory is not a local plain directory: {path}")


def runtime_preflight(target: Path, replace: bool) -> None:
    # Refuse every conflict before copying the first file.
    for name in RUNTIME_FILES:
        destination = target / name
        if destination.is_symlink():
            raise SetupError(f"Refusing symlinked runtime: {name}")
        plain_file(destination)
        if destination.exists() and not replace and digest(HERE / name) != digest(destination):
            raise SetupError(f"Refusing to overwrite {destination}. Re-run with --replace to create a backup first.")
    plain_directory(target / ".git-real")
    plain_directory(target / ".git-real" / "backups")


def copy_runtime(target: Path, replace: bool) -> list[str]:
    actions: list[str] = []
    backup_root = target / ".git-real" / "backups"
    runtime_preflight(target, replace)
    for name in RUNTIME_FILES:
        source = HERE / name
        destination = target / name
        if source.resolve() == destination.resolve():
            actions.append(f"UNCHANGED {name}")
            continue
        if destination.exists() and digest(source) == digest(destination):
            actions.append(f"UNCHANGED {name}")
            continue
        if destination.exists() and not replace:
            raise SetupError(
                f"Refusing to overwrite {destination}. Re-run with --replace to create a backup first."
            )
        if destination.exists():
            backup_root.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            descriptor, backup_name = tempfile.mkstemp(prefix=f"{name}.{stamp}.", suffix=".bak", dir=backup_root)
            backup = Path(backup_name)
            with os.fdopen(descriptor, "wb") as output, destination.open("rb") as original:
                shutil.copyfileobj(original, output)
            shutil.copystat(destination, backup)
            actions.append(f"BACKUP {name} -> {backup.relative_to(target)}")
        shutil.copy2(source, destination)
        actions.append(f"INSTALLED {name}")
    return actions


def ensure_gitignore(target: Path) -> str:
    path = target / ".gitignore"
    plain_file(path)
    existed = path.exists()
    original = path.read_bytes() if existed else b""
    if b".git-real/" in original.splitlines():
        return "UNCHANGED .gitignore"
    separator = b"" if not original or original.endswith(b"\n") else b"\n"
    with path.open("ab") as output:
        output.write(separator + b"# GIT_REAL local reports and backups\n.git-real/\n")
    return ("UPDATED" if existed else "CREATED") + " .gitignore"


def managed_span(data: bytes, begin: str, end: str) -> tuple[int, int] | None:
    first, last = begin.encode(), end.encode()
    if first not in data and last not in data:
        return None
    lines = data.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.rstrip(b"\r\n") == first]
    ends = [i for i, line in enumerate(lines) if line.rstrip(b"\r\n") == last]
    if (len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]
            or data.count(first) != 1 or data.count(last) != 1):
        raise SetupError("Managed block markers must be one ordered pair on their own lines; existing bytes were preserved.")
    return sum(map(len, lines[:starts[0]])), sum(map(len, lines[:ends[0]])) + len(last)


def agent_preflight(target: Path) -> None:
    for name in ("CLAUDE.md", "AGENTS.md", ".cursorrules"):
        path = target / name
        plain_file(path)
        if not path.exists():
            continue
        data = path.read_bytes()
        if managed_span(data, AGENT_BEGIN, AGENT_END) is not None:
            # Setup retains its narrower encoding contract even when the direct
            # wiring command supports byte-preserving updates for these inputs.
            try:
                data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise SetupError("Managed agent instructions need valid UTF-8; use --no-wire-agents to preserve them.") from exc
            if b"\r" in data:
                raise SetupError("Managed agent instructions with CR line endings need byte-preserving wiring; use --no-wire-agents.")


def wire_agents(target: Path) -> str:
    agent_preflight(target)
    result = run(
        [sys.executable, "gitreal.py", str(target), "--wire-agents"],
        cwd=target,
    )
    if result.returncode != 0:
        raise SetupError(
            "Agent wiring failed: " + (result.stderr.strip() or result.stdout.strip())
        )
    return "WIRED agent instructions"


def hook_block() -> str:
    return "\n".join(
        [
            HOOK_BEGIN,
            "if command -v python3 >/dev/null 2>&1; then GIT_REAL_PY=python3; else GIT_REAL_PY=python; fi",
            '"$GIT_REAL_PY" gitreal.py . --quick --json --operation commit_index >/dev/null || {',
            '  echo "GIT_REAL blocked this commit. Run the explicit commit_index check and read its reasons." >&2',
            "  exit 1",
            "}",
            HOOK_END,
        ]
    )


def hook_preflight(target: Path) -> Path:
    hook = target / ".git" / "hooks" / "pre-commit"
    plain_directory(target / ".git")
    plain_directory(hook.parent)
    if not hook.parent.is_dir():
        raise SetupError("Cannot install a hook because .git/hooks does not exist.")
    plain_file(hook)
    configured = run(["git", "config", "--get", "core.hooksPath"], cwd=target)
    if configured.returncode == 0:
        raise SetupError("core.hooksPath is configured; omit --with-hook or arrange the guard through the existing hook owner.")
    if configured.returncode != 1:
        raise SetupError("Could not determine the active hook configuration; no hook was installed.")
    if hook.exists():
        managed_span(hook.read_bytes(), HOOK_BEGIN, HOOK_END)
    return hook


def install_precommit_hook(target: Path) -> str:
    hook = hook_preflight(target)
    block = hook_block().encode()
    if hook.exists():
        original = hook.read_bytes()
        span = managed_span(original, HOOK_BEGIN, HOOK_END)
        if span is None:
            return "SKIPPED pre-commit hook: an unmanaged hook already exists"
        start, end = span
        hook.write_bytes(original[:start] + block + original[end:])
        action = "UPDATED pre-commit hook"
    else:
        hook.write_bytes(b"#!/bin/sh\nset -eu\n" + block + b"\n")
        action = "INSTALLED pre-commit hook"
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return action


def fresh_state(target: Path) -> dict:
    result = run(
        [
            sys.executable,
            "gitreal.py",
            str(target),
            "--quick",
            "--json",
        ],
        cwd=target,
    )
    if result.returncode != 0:
        raise SetupError(
            "GIT_REAL verification run failed: "
            + (result.stderr.strip() or result.stdout.strip())
        )
    try:
        state = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SetupError("Verification failed: stdout was not valid GIT_REAL JSON.") from exc

    if not isinstance(state, dict):
        raise SetupError("Verification failed: JSON must be an object.")

    required = {
        "version",
        "schema_version",
        "publication_id",
        "root",
        "is_repo",
        "read_complete",
        "read_errors",
        "actions",
    }
    missing = sorted(required.difference(state))
    if missing:
        raise SetupError("Verification failed: JSON keys missing: " + ", ".join(missing))
    if state.get("version") != "1.3.1" or type(state.get("schema_version")) is not int or state.get("schema_version") != 2:
        raise SetupError("Verification failed: expected GIT_REAL v1.3.1 schema 2.")
    if state.get("is_repo") is not True:
        raise SetupError("Verification failed: target was not recognized as a Git repository.")
    if state.get("read_complete") is not True or not isinstance(state.get("read_errors"), list) or state.get("read_errors"):
        raise SetupError("Verification failed: repository read was incomplete.")
    if not isinstance(state.get("publication_id"), str) or not state["publication_id"].strip():
        raise SetupError("Verification failed: publication identity is missing.")
    if not isinstance(state.get("root"), str) or not os.path.isabs(state["root"]):
        raise SetupError("Verification failed: JSON root must be an absolute path string.")
    try:
        observed_root = Path(str(state["root"])).resolve()
    except (TypeError, ValueError, RuntimeError, OSError) as exc:
        raise SetupError("Verification failed: JSON root is invalid.") from exc
    if observed_root != target.resolve():
        raise SetupError("Verification failed: JSON root does not match the target.")
    if not isinstance(state.get("actions"), dict):
        raise SetupError("Verification failed: actions must be an object.")
    commit_action = state["actions"].get("commit_index")
    if not isinstance(commit_action, dict) or commit_action.get("operation") != "commit_index":
        raise SetupError("Verification failed: commit_index action evidence is missing.")
    if (type(commit_action.get("safe")) is not bool
            or commit_action.get("decision") not in ("ALLOW", "BLOCK")
            or commit_action["safe"] != (commit_action["decision"] == "ALLOW")):
        raise SetupError("Verification failed: commit_index verdict is missing or inconsistent.")
    return state


def verify_install(target: Path, expect_agents: bool) -> dict:
    for name in RUNTIME_FILES:
        plain_file(target / name)
        if not (target / name).is_file():
            raise SetupError(f"Verification failed: {name} is missing from the target.")
    state = fresh_state(target)
    if expect_agents:
        candidates = [
            target / name
            for name in ("CLAUDE.md", "AGENTS.md", ".cursorrules")
        ]
        if not any(
            path.is_file()
            and managed_span(path.read_bytes(), AGENT_BEGIN, AGENT_END) is not None
            for path in candidates
        ):
            raise SetupError(
                "Verification failed: no managed agent instruction block was found."
            )
    commit_action = state["actions"]["commit_index"]
    return {
        "version": state["version"],
        "schema_version": state["schema_version"],
        "read_complete": state["read_complete"],
        "commit_index_decision": commit_action.get("decision"),
    }


def check_install(target: Path) -> None:
    problems: list[str] = []
    for name in RUNTIME_FILES:
        plain_file(target / name)
        if not (target / name).is_file():
            problems.append(f"missing {name}")
    ignore = target / ".gitignore"
    plain_file(ignore)
    if (
        not ignore.is_file()
        or b".git-real/" not in ignore.read_bytes().splitlines()
    ):
        problems.append(".git-real/ is not an exact .gitignore line")
    if problems:
        raise SetupError("CHECK_FAIL: " + "; ".join(problems))
    fresh_state(target)
    print("GIT_REAL_CHECK_PASS")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install and verify GIT_REAL v1.3.1 inside an existing project without network access."
    )
    parser.add_argument("target", nargs="?", default=".", help="project directory to protect")
    parser.add_argument("--init", action="store_true", help="initialize Git if the target is not a repository")
    parser.add_argument("--replace", action="store_true", help="back up and replace a different existing runtime")
    parser.add_argument("--with-hook", action="store_true", help="install a managed pre-commit guard when safe")
    parser.add_argument("--no-wire-agents", action="store_true", help="do not update agent instruction files")
    parser.add_argument("--no-verify", action="store_true", help="skip the post-install runtime verification")
    parser.add_argument("--check", action="store_true", help="check an existing installation without changing it")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        require_runtime()
        target = Path(args.target).expanduser().resolve()
        if not target.is_dir():
            raise SetupError(f"Target directory does not exist: {target}")
        if args.check:
            check_install(target)
            return 0
        runtime_preflight(target, args.replace)
        plain_file(target / ".gitignore")
        if not args.no_wire_agents:
            agent_preflight(target)
        if args.with_hook:
            plain_directory(target / ".git")
        ensure_git_repo(target, args.init)
        if args.with_hook:
            hook_preflight(target)
        actions = copy_runtime(target, args.replace)
        actions.append(ensure_gitignore(target))
        if not args.no_wire_agents:
            actions.append(wire_agents(target))
        if args.with_hook:
            actions.append(install_precommit_hook(target))
        receipt = None
        if not args.no_verify:
            receipt = verify_install(
                target,
                expect_agents=not args.no_wire_agents,
            )
        for action in actions:
            print(action)
        if receipt is not None:
            print("VERIFY " + json.dumps(receipt, sort_keys=True))
        print("GIT_REAL_SETUP_PASS" if receipt is not None else "GIT_REAL_SETUP_UNVERIFIED")
        return 0
    except SetupError as exc:
        print(f"GIT_REAL_SETUP_FAIL: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"GIT_REAL_SETUP_FAIL: filesystem operation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
