"""Installer checks with authored packages/targets and no real subprocesses."""
from __future__ import annotations
import ast
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get("PUBLIC_SETUP_TEST_SOURCE", ROOT / "setup_gitreal.py"))


def load():
    spec = importlib.util.spec_from_file_location("isolated_setup", SOURCE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def wiring_functions():
    tree = ast.parse((ROOT / "gitreal.py").read_text())
    names = {"WIRE_BEGIN", "WIRE_END", "WIRE_TARGETS", "WIRE_DEFAULT"}
    selected = [n for n in tree.body if isinstance(n, ast.FunctionDef) and
                (n.name.startswith("_wire_") or n.name in {"wire_block", "wire_agents"}) or
                isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in n.targets)]
    assert {n.name for n in selected if isinstance(n, ast.FunctionDef)} >= {"wire_block", "_wire_one", "wire_agents"}
    scope = {"os": os, "stat": stat, "tempfile": tempfile}
    exec(compile(ast.Module(body=selected, type_ignores=[]), "selected-wiring-functions", "exec"), scope)
    return scope


class InstallerBoundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="public-setup-authored-")
        self.addCleanup(self.temp.cleanup)
        # Canonical temp path: the installer resolves its target (macOS /private/var, Windows 8.3 names).
        self.area = Path(self.temp.name).resolve()
        self.target = self.area / "target"
        self.package = self.area / "package"
        self.target.mkdir()
        self.package.mkdir()
        for name in ("gitreal.py", "gitreal_mcp.py"):
            (self.package / name).write_text("# authored inert fixture " + name + "\n")
        self.mod = load()
        self.mod.HERE = self.package
        self.commands = []
        self.payload = {"version": "1.3.1", "schema_version": 2, "publication_id": "fixture-1",
                        "root": str(self.target), "is_repo": True, "read_complete": True,
                        "read_errors": [], "actions": {"commit_index": {
                            "operation": "commit_index", "decision": "BLOCK", "safe": False}}}
        self.hooks_path = None
        self.mod.run = self.fake_run
        for obj, attr in [(subprocess, "Popen"), (os, "system"), (socket.socket, "connect")]:
            guard = patch.object(obj, attr, side_effect=AssertionError("External effect forbidden in fixture"))
            guard.start()
            self.addCleanup(guard.stop)

    def fake_run(self, command, *, cwd):
        self.assertEqual(Path(cwd), self.target)
        self.commands.append(list(command))
        if command[:2] == ["git", "rev-parse"]:
            return subprocess.CompletedProcess(command, 0, str(self.target) + "\n", "")
        if command[:2] == ["git", "config"]:
            return subprocess.CompletedProcess(command, 1 if self.hooks_path is None else 0, self.hooks_path or "", "")
        if command[:2] == ["git", "init"]:
            return subprocess.CompletedProcess(command, 0, "fixture init", "")
        self.assertEqual(command[0], sys.executable)
        self.assertEqual(command[1], "gitreal.py")
        if "--wire-agents" in command:
            wiring_functions()["wire_agents"](str(self.target))
            return subprocess.CompletedProcess(command, 0, "fixture wiring", "")
        self.assertIn("--json", command)
        return subprocess.CompletedProcess(command, 0, json.dumps(self.payload), "")

    def main(self, *options):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", [str(SOURCE), str(self.target), *options]), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = self.mod.main()
        return code, out.getvalue(), err.getvalue()

    def hooks(self):
        p = self.target / ".git/hooks"
        p.mkdir(parents=True)
        return p / "pre-commit"

    def assert_no_runtime(self):
        self.assertFalse((self.target / "gitreal.py").exists())
        self.assertFalse((self.target / "gitreal_mcp.py").exists())

    def test_ignore_preserves_non_utf8_and_crlf_bytes(self):
        p = self.target / ".gitignore"
        before = b"# authored \xff\r\nkeep\r\n"
        p.write_bytes(before)
        self.mod.ensure_gitignore(self.target)
        self.assertTrue(p.read_bytes().startswith(before))
        after = p.read_bytes()
        self.mod.ensure_gitignore(self.target)
        self.assertEqual(p.read_bytes(), after)

    def test_ignore_requires_exact_line_not_leading_space(self):
        p = self.target / ".gitignore"
        p.write_bytes(b" .git-real/\n")
        self.mod.ensure_gitignore(self.target)
        self.assertIn(b".git-real/", p.read_bytes().splitlines())

    def test_symlinked_git_ancestor_refused_before_runtime_copy(self):
        other = self.area / "other-git"
        (other / "hooks").mkdir(parents=True)
        (self.target / ".git").symlink_to(other, target_is_directory=True)
        code, _, _ = self.main("--with-hook", "--no-wire-agents", "--no-verify")
        self.assertEqual(code, 1)
        self.assertFalse((other / "hooks/pre-commit").exists())
        self.assert_no_runtime()

    def test_custom_hook_path_is_not_claimed_installed(self):
        hook = self.hooks()
        self.hooks_path = "custom-hooks\n"
        code, out, _ = self.main("--with-hook", "--no-wire-agents", "--no-verify")
        self.assertEqual(code, 1)
        self.assertNotIn("INSTALLED pre-commit", out)
        self.assertFalse(hook.exists())
        self.assert_no_runtime()

    def test_managed_hook_preserves_unmanaged_bytes(self):
        hook = self.hooks()
        prefix, suffix = b"#!/bin/sh\r\n# authored \xff\r\n", b"\r\necho tail\r\n"
        hook.write_bytes(prefix + self.mod.HOOK_BEGIN.encode() + b"\r\necho old\r\n" + self.mod.HOOK_END.encode() + suffix)
        self.mod.install_precommit_hook(self.target)
        self.assertTrue(hook.read_bytes().startswith(prefix))
        self.assertTrue(hook.read_bytes().endswith(suffix))

    def test_reversed_hook_markers_fail_before_any_copy(self):
        hook = self.hooks()
        before = (self.mod.HOOK_END + "\n" + self.mod.HOOK_BEGIN + "\n").encode()
        hook.write_bytes(before)
        code, _, _ = self.main("--with-hook", "--no-wire-agents", "--no-verify")
        self.assertEqual(code, 1)
        self.assertEqual(hook.read_bytes(), before)
        self.assert_no_runtime()

    def test_duplicate_hook_blocks_fail_before_any_copy(self):
        hook = self.hooks()
        before = (self.mod.hook_block() + "\n") * 2
        hook.write_text(before)
        code, _, _ = self.main("--with-hook", "--no-wire-agents", "--no-verify")
        self.assertEqual(code, 1)
        self.assertEqual(hook.read_text(), before)
        self.assert_no_runtime()

    def test_unmanaged_hook_is_preserved(self):
        hook = self.hooks()
        hook.write_bytes(b"#!/bin/sh\necho preserve\n")
        before = hook.read_bytes()
        result = self.mod.install_precommit_hook(self.target)
        self.assertIn("SKIPPED", result)
        self.assertEqual(hook.read_bytes(), before)

    def test_linked_runtime_is_refused_without_changing_other_name(self):
        outside = self.area / "retained"
        outside.write_bytes(b"keep original")
        os.link(outside, self.target / "gitreal.py")
        code, _, _ = self.main("--replace", "--no-wire-agents", "--no-verify")
        self.assertEqual(code, 1)
        self.assertEqual(outside.read_bytes(), b"keep original")

    def test_nonregular_ignore_fails_before_copy(self):
        (self.target / ".gitignore").mkdir()
        code, _, _ = self.main("--no-wire-agents", "--no-verify")
        self.assertEqual(code, 1)
        self.assert_no_runtime()

    def test_unusable_backup_parent_fails_before_copy(self):
        (self.target / ".git-real").write_text("retained user file")
        code, _, _ = self.main("--no-wire-agents", "--no-verify")
        self.assertEqual(code, 1)
        self.assert_no_runtime()

    def test_managed_agent_non_utf8_refused_before_copy(self):
        p = self.target / "AGENTS.md"
        before = b"# authored \xff\n<!-- GIT_REAL hook -->\nold\n<!-- /GIT_REAL -->\n"
        p.write_bytes(before)
        code, _, _ = self.main("--no-verify")
        self.assertEqual(code, 1)
        self.assertEqual(p.read_bytes(), before)
        self.assert_no_runtime()

    def test_managed_agent_crlf_refused_before_copy(self):
        p = self.target / "AGENTS.md"
        before = b"# retained\r\n<!-- GIT_REAL hook -->\r\nold\r\n<!-- /GIT_REAL -->\r\n"
        p.write_bytes(before)
        code, _, _ = self.main("--no-verify")
        self.assertEqual(code, 1)
        self.assertEqual(p.read_bytes(), before)
        self.assert_no_runtime()

    def test_partial_agent_marker_refused_before_copy(self):
        p = self.target / "AGENTS.md"
        before = b"# retained\n<!-- GIT_REAL hook -->\nunfinished\n"
        p.write_bytes(before)
        code, _, _ = self.main("--no-verify")
        self.assertEqual(code, 1)
        self.assertEqual(p.read_bytes(), before)
        self.assert_no_runtime()

    def test_no_wire_option_does_not_touch_unselected_agent_symlink(self):
        outside = self.area / "other-agent.md"
        outside.write_text("preserved\n")
        (self.target / "AGENTS.md").symlink_to(outside)
        code, out, _ = self.main("--no-wire-agents", "--no-verify")
        self.assertEqual(code, 0)
        self.assertIn("GIT_REAL_SETUP_UNVERIFIED", out)
        self.assertEqual(outside.read_text(), "preserved\n")

    def test_verification_requires_object_and_typed_fields(self):
        original = self.payload
        malformed = [[], None, 7, {**original, "actions": ["bad"]},
                     {**original, "read_errors": {}}, {**original, "publication_id": None},
                     {**original, "root": None}, {**original, "root": "/authored\0path"},
                     {**original, "schema_version": 2.0}]
        for value in malformed:
            with self.subTest(payload=value):
                self.payload = value
                with self.assertRaises(self.mod.SetupError):
                    self.mod.fresh_state(self.target)

    def test_verification_requires_consistent_action_verdict(self):
        for action in [{"operation": "commit_index"},
                       {"operation": "commit_index", "decision": "ALLOW", "safe": False},
                       {"operation": "commit_index", "decision": "BLOCK", "safe": True},
                       {"operation": "commit_index", "decision": "UNKNOWN", "safe": False}]:
            with self.subTest(action=action):
                self.payload["actions"] = {"commit_index": action}
                with self.assertRaises(self.mod.SetupError):
                    self.mod.fresh_state(self.target)

    def test_complete_blocked_action_is_valid_installation_evidence(self):
        state = self.mod.fresh_state(self.target)
        self.assertEqual(state["actions"]["commit_index"]["decision"], "BLOCK")

    def test_full_fake_install_wiring_hook_and_readonly_check(self):
        hook = self.hooks()
        code, out, err = self.main("--with-hook")
        self.assertEqual(code, 0, err)
        self.assertTrue(out.rstrip().endswith("GIT_REAL_SETUP_PASS"))
        self.assertIn("--operation commit_index", hook.read_text())
        block = (self.target / "AGENTS.md").read_text()
        self.assertIn("Before a Git action", block)
        self.assertIn("follow the owner's authorization", block)
        snapshot = {str(p): p.read_bytes() for p in self.target.rglob("*") if p.is_file()}
        code, out, err = self.main("--check")
        self.assertEqual(code, 0, err)
        self.assertIn("GIT_REAL_CHECK_PASS", out)
        self.assertEqual(snapshot, {str(p): p.read_bytes() for p in self.target.rglob("*") if p.is_file()})

    def test_conflict_preflight_preserves_first_destination(self):
        (self.target / "gitreal_mcp.py").write_text("local adapter")
        code, _, _ = self.main("--no-wire-agents", "--no-verify")
        self.assertEqual(code, 1)
        self.assertFalse((self.target / "gitreal.py").exists())

    def test_repeated_replacements_preserve_distinct_originals(self):
        for data in [b"first original", b"second original"]:
            (self.target / "gitreal.py").write_bytes(data)
            self.mod.copy_runtime(self.target, True)
        copies = list((self.target / ".git-real/backups").glob("gitreal.py.*.bak"))
        self.assertEqual({p.read_bytes() for p in copies}, {b"first original", b"second original"})

    def test_filesystem_error_has_failure_receipt(self):
        with patch.object(self.mod, "copy_runtime", side_effect=OSError("authored disk failure")):
            code, out, err = self.main("--no-wire-agents", "--no-verify")
        self.assertEqual(code, 1)
        self.assertIn("GIT_REAL_SETUP_FAIL", err)
        self.assertNotIn("GIT_REAL_SETUP_PASS", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
