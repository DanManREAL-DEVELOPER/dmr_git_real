#!/usr/bin/env python3
"""Cross-platform public-distribution structure check for GIT_REAL v1.2."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "gitreal.py",
    "gitreal_mcp.py",
    "setup_gitreal.py",
    "README.md",
    "SETUP_GUIDE.html",
    "AGENT_SETUP.md",
    "SKILL.md",
    "PRIVACY.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "requirements.txt",
    "requirements-mcp.txt",
    ".gitignore",
    ".github/workflows/ci.yml",
    "scripts/release_check.py",
    "tests/test_setup_gitreal.py",
    "tests/test_adversarial_safety.py",
    "tests/test_wave43_grc.py",
)
FORBIDDEN_LAYOUT_DIRS = ("frontend", "api", "engine", "data")
FORBIDDEN_FILES = (
    ".gitrealallow",
    "tests/test_secret_detection.py",
    "tests/test_secret_history.py",
)


def main() -> int:
    failures: list[str] = []
    for relative in REQUIRED:
        if not (ROOT / relative).is_file():
            failures.append(f"missing required file: {relative}")
    for name in FORBIDDEN_LAYOUT_DIRS:
        if (ROOT / name).exists():
            failures.append(f"forbidden runtime layout directory: {name}/")
    for relative in FORBIDDEN_FILES:
        if (ROOT / relative).exists():
            failures.append(f"obsolete v1.1 surface remains: {relative}")
    parity_backups = sorted(
        str(path.relative_to(ROOT))
        for path in ROOT.rglob("*.pre-parity")
    )
    if parity_backups:
        failures.append(
            "parity rollback files remain in release surface: "
            + ", ".join(parity_backups)
        )

    workshop = ROOT.parent
    governance_check = workshop / "scripts/check_project_governance.sh"
    if governance_check.is_file():
        result = subprocess.run(
            ["bash", str(governance_check), ROOT.name],
            cwd=str(workshop),
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            failures.append(
                "workshop governance check failed: "
                + (result.stdout + result.stderr).strip()
            )

    if failures:
        for failure in failures:
            print("STRUCTURE_FAIL " + failure)
        return 1
    print("GIT_REAL_STRUCTURE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
