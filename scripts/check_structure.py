#!/usr/bin/env python3
"""Metadata-only public-package structure check for GIT_REAL v1.3.1.

PASS means the declared file/layout criteria and bounded rollback-file inventory
were satisfied. It does not assess file contents, engine parity, Git safety,
governance, publication permission or release readiness. Governance discovery is
a separate operator; this command never executes a sibling workshop helper.
"""

from pathlib import Path
import os
import stat


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

# Root-only operational metadata, local environments and Python test caches are
# not the public source package. Ordinary source, assets, dist and build remain
# in scope; this is not an arbitrary .gitignore interpreter or tracked-file scan.
LOCAL_ROOT_DIRS = (
    ".git", ".git-real", ".project-map", ".venv", "venv", "__pycache__", ".pytest_cache",
)
MAX_ENTRIES = 50_000
MAX_DEPTH = 64
MAX_FAILURES = 100


def _package_file(root: Path, path: Path) -> bool:
    """A regular file must resolve within the package, including its parents."""
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
        return stat.S_ISREG(resolved.stat().st_mode)
    except (OSError, RuntimeError, ValueError):
        return False


def _rollback_inventory(root: Path, failures: list[str]) -> None:
    """Bounded names/types only; never follow directory aliases or read bytes."""
    pending = [(root, 0)]
    observed = 0
    while pending:
        directory, depth = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    observed += 1
                    if observed > MAX_ENTRIES:
                        failures.append(f"package inventory exceeds {MAX_ENTRIES} entries; inspection incomplete")
                        return
                    path = directory / entry.name
                    relative = path.relative_to(root).as_posix()
                    # These exact top-level names are outside the source package.
                    # Do not traverse even a directory alias at such a local root.
                    if directory == root and entry.name in LOCAL_ROOT_DIRS:
                        continue
                    if entry.name.endswith(".pre-parity"):
                        failures.append(f"parity rollback entry remains in package: {relative!r}")
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                        if stat.S_ISLNK(metadata.st_mode):
                            if not _package_file(root, path):
                                failures.append(f"unresolved, external or directory link in package: {relative!r}")
                        elif stat.S_ISDIR(metadata.st_mode):
                            resolved = path.resolve(strict=True)
                            # Also avoid directory aliases such as Windows junctions.
                            if resolved != path:
                                failures.append(f"directory alias is outside package inventory: {relative!r}")
                            elif depth >= MAX_DEPTH:
                                failures.append(f"package inventory exceeds depth {MAX_DEPTH}: {relative!r}")
                            else:
                                pending.append((path, depth + 1))
                        elif not stat.S_ISREG(metadata.st_mode):
                            failures.append(f"nonregular entry is outside package inventory: {relative!r}")
                    except (OSError, RuntimeError, ValueError) as exc:
                        failures.append(f"cannot inspect package entry {relative!r}: {type(exc).__name__}")
                    if len(failures) >= MAX_FAILURES:
                        failures.append(f"reporting stopped after {MAX_FAILURES} failures; inspection incomplete")
                        return
        except (OSError, RuntimeError, ValueError) as exc:
            relative = directory.relative_to(root).as_posix()
            failures.append(f"cannot enumerate package directory {relative!r}: {type(exc).__name__}")
            if len(failures) >= MAX_FAILURES:
                failures.append(f"reporting stopped after {MAX_FAILURES} failures; inspection incomplete")
                return


def check_structure(root: Path) -> list[str]:
    """Inspect one package's metadata without invoking any other command."""
    failures: list[str] = []
    try:
        root = root.resolve(strict=True)
        if not root.is_dir():
            return ["package root is not a directory"]
    except (OSError, RuntimeError, ValueError) as exc:
        return [f"package root is unavailable: {type(exc).__name__}"]
    for relative in REQUIRED:
        if not _package_file(root, root / relative):
            failures.append(f"missing, unreadable or external required file: {relative}")
    for name in FORBIDDEN_LAYOUT_DIRS:
        try:
            (root / name).lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            failures.append(f"cannot inspect forbidden layout {name!r}: {type(exc).__name__}")
        else:
            failures.append(f"forbidden runtime layout entry: {name}/")
    for relative in FORBIDDEN_FILES:
        try:
            (root / relative).lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            failures.append(f"cannot inspect obsolete surface {relative!r}: {type(exc).__name__}")
        else:
            failures.append(f"obsolete v1.1 surface remains: {relative}")
    _rollback_inventory(root, failures)
    return failures


def main() -> int:
    failures = check_structure(ROOT)
    if failures:
        for failure in sorted(failures):
            print("STRUCTURE_FAIL " + failure)
        return 1
    print("GIT_REAL_STRUCTURE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
