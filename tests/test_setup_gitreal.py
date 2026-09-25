"""End-to-end tests for the dependency-free GIT_REAL v1.2 installer."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SETUP = ROOT / "setup_gitreal.py"


def run(*args: str, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SETUP), *args],
        cwd=str(cwd),
        text=True,
        capture_output=True,
        check=False,
        timeout=120,
    )


def git(target: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(target), *args],
        check=True,
        capture_output=True,
    )


def new_repo() -> Path:
    target = Path(tempfile.mkdtemp(prefix="git-real-setup-test-"))
    git(target, "init", "-q")
    git(target, "config", "user.name", "Example User")
    git(target, "config", "user.email", "developer@example.invalid")
    (target / "README.md").write_text(
        "# Synthetic project\n",
        encoding="utf-8",
    )
    git(target, "add", "README.md")
    git(target, "commit", "-qm", "initial synthetic commit")
    return target


def fresh_state(target: Path) -> dict:
    result = subprocess.run(
        [
            sys.executable,
            str(target / "gitreal.py"),
            str(target),
            "--quick",
            "--json",
        ],
        cwd=str(target),
        text=True,
        capture_output=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    return json.loads(result.stdout)


def test_install_check_and_hook_are_v12() -> None:
    target = new_repo()
    first = run(str(target), "--with-hook")
    assert first.returncode == 0, first.stderr
    assert "GIT_REAL_SETUP_PASS" in first.stdout
    assert (target / "gitreal.py").is_file()
    assert (target / "gitreal_mcp.py").is_file()
    assert (target / "AGENTS.md").is_file()

    hook = target / ".git/hooks/pre-commit"
    assert hook.is_file()
    hook_text = hook.read_text(encoding="utf-8")
    assert "--operation commit_index" in hook_text
    assert ("--fail-on-" + "secret") not in hook_text

    state = fresh_state(target)
    assert state["version"] == "1.2.0"
    assert state["schema_version"] == 2
    assert state["read_complete"] is True
    assert state["read_errors"] == []
    assert Path(state["root"]).resolve() == target.resolve()
    assert state["actions"]["commit_index"]["operation"] == "commit_index"

    second = run(str(target), "--with-hook")
    assert second.returncode == 0, second.stderr
    assert (
        (target / "AGENTS.md")
        .read_text(encoding="utf-8")
        .count("<!-- GIT_REAL hook -->")
        == 1
    )
    assert (
        hook.read_text(encoding="utf-8")
        .count("# GIT_REAL managed block: begin")
        == 1
    )

    checked = run(str(target), "--check")
    assert checked.returncode == 0, checked.stderr
    assert "GIT_REAL_CHECK_PASS" in checked.stdout


def test_different_runtime_requires_explicit_replace() -> None:
    target = new_repo()
    (target / "gitreal.py").write_text(
        "print('different local tool')\n",
        encoding="utf-8",
    )
    refused = run(str(target))
    assert refused.returncode != 0
    assert "Refusing to overwrite" in refused.stderr

    replaced = run(str(target), "--replace")
    assert replaced.returncode == 0, replaced.stderr
    backups = list(
        (target / ".git-real/backups").glob("gitreal.py.*.bak")
    )
    assert len(backups) == 1
    assert fresh_state(target)["version"] == "1.2.0"


def test_unmanaged_precommit_hook_is_preserved() -> None:
    target = new_repo()
    hook = target / ".git/hooks/pre-commit"
    hook.write_text("#!/bin/sh\necho existing\n", encoding="utf-8")

    result = run(str(target), "--with-hook")
    assert result.returncode == 0, result.stderr
    assert "SKIPPED pre-commit hook" in result.stdout
    assert hook.read_text(encoding="utf-8") == "#!/bin/sh\necho existing\n"
