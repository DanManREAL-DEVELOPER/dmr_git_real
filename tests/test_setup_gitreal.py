"""End-to-end tests for the dependency-free installer."""

from __future__ import annotations

import json
import os
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
    subprocess.run(["git", "-C", str(target), *args], check=True, capture_output=True)


def new_repo() -> Path:
    target = Path(tempfile.mkdtemp(prefix="git-real-setup-test-"))
    git(target, "init", "-q")
    git(target, "config", "user.name", "Example User")
    git(target, "config", "user.email", "developer@example.invalid")
    (target / "README.md").write_text("# Synthetic project\n", encoding="utf-8")
    git(target, "add", "README.md")
    git(target, "commit", "-qm", "initial synthetic commit")
    return target


def check(label: str, condition: object, failures: list[str]) -> None:
    if condition:
        print("PASS " + label)
    else:
        print("FAIL " + label)
        failures.append(label)


def main() -> int:
    failures: list[str] = []
    target = new_repo()
    first = run(str(target), "--with-hook")
    check("setup exits zero", first.returncode == 0, failures)
    check("setup emits receipt", "GIT_REAL_SETUP_PASS" in first.stdout, failures)
    check("runtime copied", (target / "gitreal.py").is_file(), failures)
    check("MCP adapter copied", (target / "gitreal_mcp.py").is_file(), failures)
    check("agent instructions created", (target / "AGENTS.md").is_file(), failures)
    check("pre-commit hook installed", (target / ".git/hooks/pre-commit").is_file(), failures)
    report = target / ".git-real/git-real.json"
    check("verification JSON created", report.is_file(), failures)
    if report.is_file():
        state = json.loads(report.read_text(encoding="utf-8"))
        check("verification recognizes repo", state.get("is_repo") is True, failures)
        check("verification reports no secrets", state.get("secrets") == [], failures)

    second = run(str(target), "--with-hook")
    check("second setup exits zero", second.returncode == 0, failures)
    agent_text = (target / "AGENTS.md").read_text(encoding="utf-8")
    hook_text = (target / ".git/hooks/pre-commit").read_text(encoding="utf-8")
    check("agent block is idempotent", agent_text.count("<!-- GIT_REAL hook -->") == 1, failures)
    check("hook block is idempotent", hook_text.count("# GIT_REAL managed block: begin") == 1, failures)

    checked = run(str(target), "--check")
    check("check mode exits zero", checked.returncode == 0, failures)
    check("check mode emits receipt", "GIT_REAL_CHECK_PASS" in checked.stdout, failures)

    conflict_target = new_repo()
    (conflict_target / "gitreal.py").write_text("print('different local tool')\n", encoding="utf-8")
    refused = run(str(conflict_target))
    check("different runtime is not overwritten", refused.returncode != 0, failures)
    check("overwrite refusal is explicit", "Refusing to overwrite" in refused.stderr, failures)
    replaced = run(str(conflict_target), "--replace")
    check("explicit replacement succeeds", replaced.returncode == 0, failures)
    backups = list((conflict_target / ".git-real/backups").glob("gitreal.py.*.bak"))
    check("replacement creates backup", len(backups) == 1, failures)

    hook_target = new_repo()
    hook = hook_target / ".git/hooks/pre-commit"
    hook.write_text("#!/bin/sh\necho existing\n", encoding="utf-8")
    preserved = run(str(hook_target), "--with-hook")
    check("unmanaged hook does not fail setup", preserved.returncode == 0, failures)
    check("unmanaged hook is reported", "SKIPPED pre-commit hook" in preserved.stdout, failures)
    check("unmanaged hook is preserved", hook.read_text(encoding="utf-8") == "#!/bin/sh\necho existing\n", failures)

    total = 22
    passed = total - len(failures)
    print(f"{passed}/{total} setup checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
