"""Public direct-wiring fixtures. No engine import, process, Git or client calls."""
from __future__ import annotations
import argparse
import ast
import contextlib
import io
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get("PUBLIC_WIRE_AGENT_TEST_SOURCE", ROOT / "gitreal.py"))


def load_wiring():
    tree = ast.parse(SOURCE.read_text())
    constants = {"WIRE_BEGIN", "WIRE_END", "WIRE_TARGETS", "WIRE_DEFAULT",
                 "DEFAULT_PORT", "DEFAULT_INTERVAL", "REF_ACTIONS"}
    selected = [n for n in tree.body if isinstance(n, ast.FunctionDef) and
                (n.name.startswith("_wire_") or n.name in ("wire_block", "wire_agents", "main")) or
                isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in constants for t in n.targets)]
    def forbidden(*args, **kwargs):
        raise AssertionError("A non-wiring engine path was reached")
    scope = {"os": os, "stat": stat, "tempfile": tempfile, "argparse": argparse, "sys": sys,
             "ACTION_SCOPES": {}, "GitRepo": forbidden, "App": forbidden, "build_state": forbidden,
             "run_fleet": forbidden, "stage_paths_state": forbidden}
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(SOURCE), "exec"), scope)
    return types.SimpleNamespace(**scope), scope


def deny_process_effects(test):
    targets = [(subprocess, name) for name in ("Popen", "run", "call", "check_call", "check_output", "getoutput", "getstatusoutput")]
    targets += [(os, name) for name in dir(os) if
                name.startswith(("exec", "spawn", "posix_spawn")) or
                name in {"system", "popen", "fork", "forkpty", "kill", "killpg", "abort", "_exit", "startfile"}]
    targets += [(socket.socket, "connect"), (socket.socket, "connect_ex")]
    for obj, name in targets:
        guard = patch.object(obj, name, side_effect=AssertionError("Process/network effect forbidden"))
        guard.start()
        test.addCleanup(guard.stop)


def load_setup_boundary():
    source = ROOT / "setup_gitreal.py"
    tree = ast.parse(source.read_text())
    funcs = {"plain_file", "managed_span", "agent_preflight", "wire_agents"}
    names = {"AGENT_BEGIN", "AGENT_END"}
    selected = [n for n in tree.body if
                isinstance(n, ast.FunctionDef) and n.name in funcs or
                isinstance(n, ast.ClassDef) and n.name == "SetupError" or
                isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in n.targets)]
    scope = {"Path": Path, "sys": sys}
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(source), "exec"), scope)
    return types.SimpleNamespace(**scope), scope


class WiringBoundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gitreal-wiring-authored-")
        self.addCleanup(self.temp.cleanup)
        self.area = Path(self.temp.name)
        self.root = self.area / "target"
        self.root.mkdir()
        self.g, self.scope = load_wiring()
        self.begin, self.end = self.g.WIRE_BEGIN.encode(), self.g.WIRE_END.encode()
        deny_process_effects(self)

    def wire(self):
        return self.g.wire_agents(str(self.root))

    def stale(self, path, newline=b"\n", prefix=b"prefix\n", suffix=b"\ntail\n"):
        data = prefix + self.begin + newline + b"old managed text" + newline + self.end + suffix
        path.write_bytes(data)
        return data

    def test_default_creation_and_idempotence(self):
        self.assertEqual(self.wire(), {"AGENTS.md": "created"})
        p = self.root / "AGENTS.md"
        before = p.read_bytes(), p.stat().st_mtime_ns
        self.assertEqual(self.wire(), {"AGENTS.md": "unchanged"})
        self.assertEqual((p.read_bytes(), p.stat().st_mtime_ns), before)

    def test_all_existing_files_and_unmanaged_bytes(self):
        for name in self.g.WIRE_TARGETS:
            (self.root / name).write_bytes(b"# authored \xff\r\n")
        result = self.wire()
        self.assertEqual(set(result), set(self.g.WIRE_TARGETS))
        for name in result:
            self.assertTrue((self.root / name).read_bytes().startswith(b"# authored \xff\r\n"))

    def test_managed_non_utf8_prefix_suffix_preserved(self):
        p = self.root / "AGENTS.md"
        self.stale(p, prefix=b"prefix \xff\n", suffix=b"\ntail \xfe\n")
        self.wire()
        self.assertTrue(p.read_bytes().startswith(b"prefix \xff\n"))
        self.assertTrue(p.read_bytes().endswith(b"\ntail \xfe\n"))

    def test_crlf_managed_bytes_and_style_preserved(self):
        p = self.root / "AGENTS.md"
        self.stale(p, newline=b"\r\n", prefix=b"prefix\r\n", suffix=b"\r\ntail\r\n")
        self.wire()
        data = p.read_bytes()
        self.assertTrue(data.startswith(b"prefix\r\n") and data.endswith(b"\r\ntail\r\n"))
        self.assertNotIn(b"\n", data.replace(b"\r\n", b""))

    def test_bom_before_managed_marker_preserved(self):
        p = self.root / "AGENTS.md"
        self.stale(p, prefix=b"\xef\xbb\xbf", suffix=b"\n")
        self.wire()
        self.assertTrue(p.read_bytes().startswith(b"\xef\xbb\xbf" + self.begin))

    def test_partial_marker_refused_without_mutation(self):
        p = self.root / "AGENTS.md"
        data = self.begin + b"\nunfinished\n"
        p.write_bytes(data)
        with self.assertRaises(OSError):
            self.wire()
        self.assertEqual(p.read_bytes(), data)

    def test_reversed_markers_refused_without_mutation(self):
        p = self.root / "AGENTS.md"
        data = self.end + b"\n" + self.begin + b"\n"
        p.write_bytes(data)
        with self.assertRaises(OSError):
            self.wire()
        self.assertEqual(p.read_bytes(), data)

    def test_duplicate_markers_refused_without_mutation(self):
        p = self.root / "AGENTS.md"
        data = (self.begin + b"\nold\n" + self.end + b"\n") * 2
        p.write_bytes(data)
        with self.assertRaises(OSError):
            self.wire()
        self.assertEqual(p.read_bytes(), data)

    def test_inline_reserved_markers_refused(self):
        p = self.root / "AGENTS.md"
        data = b"example: " + self.begin + b" inline " + self.end + b"\n"
        p.write_bytes(data)
        with self.assertRaises(OSError):
            self.wire()
        self.assertEqual(p.read_bytes(), data)

    def test_later_bad_file_preflight_preserves_first(self):
        first = self.root / "CLAUDE.md"
        first.write_bytes(b"preserve first\n")
        (self.root / "AGENTS.md").write_bytes(self.begin + b"\nunfinished\n")
        with self.assertRaises(OSError):
            self.wire()
        self.assertEqual(first.read_bytes(), b"preserve first\n")

    def test_later_symlink_preflight_preserves_first(self):
        first = self.root / "CLAUDE.md"
        first.write_bytes(b"preserve first\n")
        other = self.area / "other.md"
        other.write_bytes(b"preserve other\n")
        (self.root / "AGENTS.md").symlink_to(other)
        with self.assertRaises(OSError):
            self.wire()
        self.assertEqual(first.read_bytes(), b"preserve first\n")
        self.assertEqual(other.read_bytes(), b"preserve other\n")

    def test_dangling_selected_symlink_is_not_ignored(self):
        (self.root / "CLAUDE.md").symlink_to(self.area / "absent")
        with self.assertRaises(OSError):
            self.wire()
        self.assertFalse((self.root / "AGENTS.md").exists())

    def test_directory_at_reserved_name_is_refused(self):
        (self.root / "CLAUDE.md").mkdir()
        with self.assertRaises(OSError):
            self.wire()
        self.assertFalse((self.root / "AGENTS.md").exists())

    def test_hardlinked_file_refused(self):
        other = self.area / "retained.md"
        other.write_bytes(b"retain hardlinked content\n")
        os.link(other, self.root / "AGENTS.md")
        with self.assertRaises(OSError):
            self.wire()
        self.assertEqual(other.read_bytes(), b"retain hardlinked content\n")

    def test_existing_permissions_preserved(self):
        p = self.root / "AGENTS.md"
        self.stale(p)
        p.chmod(0o640)
        # POSIX keeps 0o640; Windows only models the read-only bit, so compare with the set mode.
        before = stat.S_IMODE(p.stat().st_mode)
        self.wire()
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), before)

    def test_failed_staged_write_preserves_original(self):
        p = self.root / "AGENTS.md"
        original = self.stale(p)
        with patch.object(tempfile, "mkstemp", side_effect=OSError("authored allocation failure")):
            with self.assertRaises(OSError):
                self.wire()
        self.assertEqual(p.read_bytes(), original)

    def test_failed_replace_preserves_original_and_cleans_owned_temp(self):
        p = self.root / "AGENTS.md"
        original = self.stale(p)
        with patch.object(os, "replace", side_effect=OSError("authored replace failure")):
            with self.assertRaises(OSError):
                self.wire()
        self.assertEqual(p.read_bytes(), original)
        self.assertEqual(sorted(x.name for x in self.root.iterdir()), ["AGENTS.md"])

    def test_cleanup_does_not_remove_a_reused_temporary_name(self):
        self.stale(self.root / "AGENTS.md")
        real_replace = os.replace
        def replace_then_reuse(source, destination):
            real_replace(source, destination)
            Path(source).write_bytes(b"new unrelated authored file\n")
        with patch.object(os, "replace", side_effect=replace_then_reuse):
            self.wire()
        retained = list(self.root.glob(".gitreal-wire-*"))
        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0].read_bytes(), b"new unrelated authored file\n")

    def test_fresh_default_uses_exclusive_creation(self):
        p = self.root / "AGENTS.md"
        real_open = os.open
        def appear(path, flags, *args, **kwargs):
            if str(path) == str(p) and flags & os.O_CREAT:
                p.write_bytes(b"concurrent authored file\n")
            return real_open(path, flags, *args, **kwargs)
        with patch.object(os, "open", side_effect=appear):
            with self.assertRaises(OSError):
                self.wire()
        self.assertEqual(p.read_bytes(), b"concurrent authored file\n")

    def test_changed_file_between_plan_and_apply_is_preserved(self):
        p = self.root / "AGENTS.md"
        self.stale(p)
        if "_wire_plan" not in self.scope:
            self.fail("No preflight/apply binding exists")
        plan = self.g._wire_plan(str(p), self.g.wire_block())
        p.write_bytes(b"new authored work\n")
        with self.assertRaises(OSError):
            self.g._wire_apply(str(p), plan)
        self.assertEqual(p.read_bytes(), b"new authored work\n")

    def test_focused_instruction_contract_is_unchanged(self):
        block = self.g.wire_block()
        self.assertIn("Before a Git action", block)
        self.assertIn("follow the owner's authorization", block)
        self.assertIn("read_complete=true", block)
        self.assertIn("safe=true", block)
        self.assertIn("Legacy scores are summaries only", block)

    def test_inert_cli_facade_exits_without_backend_calls(self):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", ["gitreal.py", str(self.root), "--wire-agents", "--init"]), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with self.assertRaises(SystemExit) as caught:
                self.g.main()
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("created", out.getvalue())
        self.assertFalse((self.root / ".git").exists())

    def test_inert_cli_failure_is_bounded_nonzero(self):
        (self.root / "AGENTS.md").write_bytes(self.begin + b"\npartial\n")
        err = io.StringIO()
        with patch.object(sys, "argv", ["gitreal.py", str(self.root), "--wire-agents"]), \
                contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                self.g.main()
        self.assertEqual(caught.exception.code, 1)
        self.assertIn("agent wiring failed", err.getvalue())


    def test_setup_keeps_non_utf8_refusal_while_direct_wiring_preserves_bytes(self):
        setup, _ = load_setup_boundary()
        p = self.root / "AGENTS.md"
        original = self.stale(p, prefix=b"authored \xff\n")
        with self.assertRaises(setup.SetupError):
            setup.agent_preflight(self.root)
        self.assertEqual(p.read_bytes(), original)
        self.wire()
        self.assertTrue(p.read_bytes().startswith(b"authored \xff\n"))

    def test_setup_keeps_crlf_refusal_while_direct_wiring_preserves_style(self):
        setup, _ = load_setup_boundary()
        p = self.root / "AGENTS.md"
        original = self.stale(p, newline=b"\r\n", prefix=b"authored\r\n", suffix=b"\r\ntail\r\n")
        with self.assertRaises(setup.SetupError):
            setup.agent_preflight(self.root)
        self.assertEqual(p.read_bytes(), original)
        self.wire()
        self.assertTrue(p.read_bytes().startswith(b"authored\r\n"))
        self.assertNotIn(b"\n", p.read_bytes().replace(b"\r\n", b""))

    def test_setup_delegation_reaches_public_helper_through_inert_run(self):
        setup, scope = load_setup_boundary()
        calls = []
        def inert_run(command, *, cwd):
            self.assertEqual(command, [sys.executable, "gitreal.py", str(self.root), "--wire-agents"])
            self.assertEqual(cwd, self.root)
            calls.append(command)
            self.wire()
            return subprocess.CompletedProcess(command, 0, "authored wiring result", "")
        scope["run"] = inert_run
        self.assertEqual(setup.wire_agents(self.root), "WIRED agent instructions")
        self.assertEqual(len(calls), 1)
        self.assertTrue((self.root / "AGENTS.md").is_file())
        self.assertFalse((self.root / "gitreal.py").exists())
        self.assertFalse((self.root / ".git").exists())

    def test_setup_reports_public_wiring_failure_without_success(self):
        setup, scope = load_setup_boundary()
        p = self.root / "AGENTS.md"
        p.write_bytes(b"authored retained file\n")
        scope["run"] = lambda command, **kwargs: subprocess.CompletedProcess(command, 1, "", "authored wiring failure")
        with self.assertRaisesRegex(setup.SetupError, "Agent wiring failed: authored wiring failure"):
            setup.wire_agents(self.root)
        self.assertEqual(p.read_bytes(), b"authored retained file\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
