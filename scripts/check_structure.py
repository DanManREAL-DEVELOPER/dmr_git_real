#!/usr/bin/env python3
"""Cross-platform public-distribution structure check."""

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "gitreal.py",
    "gitreal_mcp.py",
    "setup_gitreal.py",
    "README.md",
    "SETUP_GUIDE.html",
    "AGENT_SETUP.md",
    "PRIVACY.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "requirements.txt",
    "requirements-mcp.txt",
    ".gitignore",
    ".gitrealallow",
    ".github/workflows/ci.yml",
    "scripts/release_check.py",
    "tests/test_setup_gitreal.py",
)
FORBIDDEN_LAYOUT_DIRS = ("frontend", "api", "engine", "data")


def main() -> int:
    failures: list[str] = []
    for relative in REQUIRED:
        if not (ROOT / relative).is_file():
            failures.append(f"missing required file: {relative}")
    for name in FORBIDDEN_LAYOUT_DIRS:
        if (ROOT / name).exists():
            failures.append(f"forbidden runtime layout directory: {name}/")
    workshop = ROOT.parent
    governance_check = workshop / "scripts" / "check_project_governance.sh"
    if governance_check.is_file():
        result = subprocess.run(
            ["bash", str(governance_check), ROOT.name],
            cwd=str(workshop),
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            failures.append("workshop governance check failed: " + (result.stdout + result.stderr).strip())
    if failures:
        for failure in failures:
            print("STRUCTURE_FAIL " + failure)
        return 1
    print("GIT_REAL_STRUCTURE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
