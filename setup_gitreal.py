#!/usr/bin/env python3
"""Safe, dependency-free installer for the GIT_REAL v1.2 drop-in tool."""

from __future__ import annotations

import argparse
import hashlib
import json
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
        return
    if not initialize:
        raise SetupError(
            "Target is not a Git repository. Re-run with --init only if creating one is intended."
        )
    created = run(["git", "init"], cwd=target)
    if created.returncode != 0:
        raise SetupError("git init failed: " + (created.stderr.strip() or "unknown error"))


def copy_runtime(target: Path, replace: bool) -> list[str]:
    actions: list[str] = []
    backup_root = target / ".git-real" / "backups"
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
            backup = backup_root / f"{name}.{stamp}.bak"
            shutil.copy2(destination, backup)
            actions.append(f"BACKUP {name} -> {backup.relative_to(target)}")
        shutil.copy2(source, destination)
        actions.append(f"INSTALLED {name}")
    return actions


def ensure_gitignore(target: Path) -> str:
    path = target / ".gitignore"
    line = ".git-real/"
    if path.exists():
        text = path.read_text(encoding="utf-8", errors="replace")
        existing = {item.strip() for item in text.splitlines()}
        if line in existing:
            return "UNCHANGED .gitignore"
        separator = "" if not text or text.endswith("\n") else "\n"
        path.write_text(
            text + separator + "# GIT_REAL local reports and backups\n" + line + "\n",
            encoding="utf-8",
        )
        return "UPDATED .gitignore"
    path.write_text(
        "# GIT_REAL local reports and backups\n" + line + "\n",
        encoding="utf-8",
    )
    return "CREATED .gitignore"


def wire_agents(target: Path) -> str:
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


def install_precommit_hook(target: Path) -> str:
    hook = target / ".git" / "hooks" / "pre-commit"
    if not hook.parent.is_dir():
        raise SetupError("Cannot install a hook because .git/hooks does not exist.")
    block = hook_block()
    if hook.exists():
        text = hook.read_text(encoding="utf-8", errors="replace")
        if HOOK_BEGIN not in text or HOOK_END not in text:
            return "SKIPPED pre-commit hook: an unmanaged hook already exists"
        start = text.index(HOOK_BEGIN)
        end = text.index(HOOK_END, start) + len(HOOK_END)
        hook.write_text(text[:start] + block + text[end:], encoding="utf-8")
        action = "UPDATED pre-commit hook"
    else:
        hook.write_text("#!/bin/sh\nset -eu\n" + block + "\n", encoding="utf-8")
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
    if state.get("version") != "1.2.0" or state.get("schema_version") != 2:
        raise SetupError("Verification failed: expected GIT_REAL v1.2 schema 2.")
    if state.get("is_repo") is not True:
        raise SetupError("Verification failed: target was not recognized as a Git repository.")
    if state.get("read_complete") is not True or state.get("read_errors"):
        raise SetupError("Verification failed: repository read was incomplete.")
    try:
        observed_root = Path(str(state["root"])).resolve()
    except (TypeError, OSError) as exc:
        raise SetupError("Verification failed: JSON root is invalid.") from exc
    if observed_root != target.resolve():
        raise SetupError("Verification failed: JSON root does not match the target.")
    commit_action = (state.get("actions") or {}).get("commit_index")
    if not isinstance(commit_action, dict) or commit_action.get("operation") != "commit_index":
        raise SetupError("Verification failed: commit_index action evidence is missing.")
    return state


def verify_install(target: Path, expect_agents: bool) -> dict:
    for name in RUNTIME_FILES:
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
            and AGENT_BEGIN
            in path.read_text(encoding="utf-8", errors="replace")
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
        if not (target / name).is_file():
            problems.append(f"missing {name}")
    ignore = target / ".gitignore"
    if (
        not ignore.is_file()
        or ".git-real/"
        not in ignore.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()
    ):
        problems.append(".git-real/ is not an exact .gitignore line")
    if problems:
        raise SetupError("CHECK_FAIL: " + "; ".join(problems))
    fresh_state(target)
    print("GIT_REAL_CHECK_PASS")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install and verify GIT_REAL v1.2 inside an existing project without network access."
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
        ensure_git_repo(target, args.init)
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
        print("GIT_REAL_SETUP_PASS")
        return 0
    except SetupError as exc:
        print(f"GIT_REAL_SETUP_FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
