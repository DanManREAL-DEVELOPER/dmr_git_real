"""Installer preservation and public release-surface regression coverage."""
from pathlib import Path
import importlib.util
import subprocess
import sys
from datetime import datetime, timezone

import pytest

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


setup = module('setup_boundary', 'setup_gitreal.py')
gate = module('gate_boundary', 'scripts/release_check.py')


def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True)


def test_nested_target_fails_before_any_install(tmp_path):
    git(tmp_path, 'init', '-q')
    child = tmp_path / 'nested'
    child.mkdir()
    result = subprocess.run([sys.executable, str(ROOT / 'setup_gitreal.py'), str(child)], capture_output=True, text=True)
    assert result.returncode == 1
    assert 'actual repository root' in result.stderr
    assert list(child.iterdir()) == []


def test_second_runtime_conflict_preserves_first_destination(tmp_path):
    (tmp_path / 'gitreal_mcp.py').write_text('local adapter')
    with pytest.raises(setup.SetupError, match='Refusing to overwrite'):
        setup.copy_runtime(tmp_path, False)
    assert not (tmp_path / 'gitreal.py').exists()
    assert (tmp_path / 'gitreal_mcp.py').read_text() == 'local adapter'


def test_repeated_replace_keeps_every_original(tmp_path, monkeypatch):
    class FixedTime:
        @staticmethod
        def now(tz):
            return datetime(2026, 1, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(setup, 'datetime', FixedTime)
    (tmp_path / 'gitreal.py').write_text('first original')
    setup.copy_runtime(tmp_path, True)
    (tmp_path / 'gitreal.py').write_text('second original')
    setup.copy_runtime(tmp_path, True)
    copies = list((tmp_path / '.git-real/backups').glob('gitreal.py.*.bak'))
    assert len(copies) == 2
    assert {p.read_text() for p in copies} == {'first original', 'second original'}


def test_symlinked_runtime_is_never_overwritten(tmp_path):
    target = tmp_path / 'target'
    target.mkdir()
    outside = tmp_path / 'outside.py'
    outside.write_text('preserve')
    try:
        (target / 'gitreal.py').symlink_to(outside)
    except OSError:
        pytest.skip('symlinks unavailable for this user')
    with pytest.raises(setup.SetupError, match='symlinked runtime'):
        setup.copy_runtime(target, True)
    assert outside.read_text() == 'preserve'


def test_windows_private_path_shapes_detected():
    pattern = next(p for label, p in gate.GENERIC_PRIVATE_PATTERNS if label == 'Windows user path')
    for separator in (chr(92), chr(92) * 2):
        assert pattern.search(separator.join(['C:', 'Users', 'Example', 'project']))


def test_ignored_local_artifacts_excluded_but_tracked_artifacts_checked(tmp_path, monkeypatch):
    git(tmp_path, 'init', '-q')
    (tmp_path / '.gitignore').write_text('/.project-map/\n')
    hidden = tmp_path / '.project-map'
    hidden.mkdir()
    artifact = hidden / 'report.md'
    artifact.write_text('/' + 'home' + '/example/project/')
    monkeypatch.setattr(gate, 'ROOT', tmp_path)
    assert gate.privacy_failures() == []
    git(tmp_path, 'add', '-f', str(artifact))
    assert any('POSIX home path' in x for x in gate.privacy_failures())


def test_oversize_text_is_refused_and_inventory_failure_is_not_empty(tmp_path, monkeypatch):
    git(tmp_path, 'init', '-q')
    (tmp_path / 'large.md').write_text('x' * 2_000_001)
    monkeypatch.setattr(gate, 'ROOT', tmp_path)
    assert any('bounded privacy inspection' in x for x in gate.privacy_failures())
    other = tmp_path / 'not-repo'
    other.mkdir()
    monkeypatch.setattr(gate, 'ROOT', Path('/nonexistent-public-fixture-root'))
    assert any('inventory failed' in x for x in gate.privacy_failures())


def test_skipped_verification_has_no_pass_receipt(tmp_path):
    git(tmp_path, 'init', '-q')
    result = subprocess.run([sys.executable, str(ROOT / 'setup_gitreal.py'), str(tmp_path), '--no-verify', '--no-wire-agents'], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert 'GIT_REAL_SETUP_UNVERIFIED' in result.stdout
    assert 'GIT_REAL_SETUP_PASS' not in result.stdout
