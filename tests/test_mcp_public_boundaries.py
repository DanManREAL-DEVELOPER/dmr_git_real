"""Public MCP boundary checks: authored state, no Git, network or content scan.

The fixture extracts only named engine functions so adapter decisions use the
actual pure assessment/ignore implementation without importing a live backend.
"""
from __future__ import annotations

import ast
import asyncio
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = Path(os.environ.get("PUBLIC_MCP_TEST_SOURCE", ROOT / "gitreal_mcp.py"))


def make_backend():
    backend = types.ModuleType("gitreal")
    backend.__dict__.update(os=os, json=json, stat=stat)
    tree = ast.parse((ROOT / "gitreal.py").read_text())
    constants = {"SCHEMA_VERSION", "ACTION_SCOPES", "REF_ACTIONS"}
    functions = {"assess_action", "requested_action", "_read_gitignore_lines",
                 "add_to_gitignore", "load_registry_repo_paths"}
    selected = [node for node in tree.body if
                isinstance(node, ast.FunctionDef) and node.name in functions or
                isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id in constants for t in node.targets)]
    assert len(selected) == len(constants) + len(functions)
    exec(compile(ast.Module(body=selected, type_ignores=[]), "selected-engine-functions", "exec"), backend.__dict__)
    backend.calls = []
    backend.state = {
        "schema_version": 2, "version": "fixture", "engine_source_sha256": "fixture",
        "root": "/fixture", "root_name": "fixture", "is_repo": True,
        "generated_at": "2026-10-09T00:00:00Z", "publication_id": "fixture-1",
        "read_complete": True, "read_errors": [], "elapsed_ms": 1,
        "status": {"ok": True, "complete": True, "branch": "main", "staged": ["draft.txt"],
                   "modified": [], "conflicts": [], "untracked": [], "oid": "a" * 40},
        "topology": {"kind": "own_repo"}, "index_inventory": {"hidden_paths": [], "fingerprint": "fixture"},
        "object_storage": {}, "active_operations": [], "index_locked": False,
        "scores": {"safe_commit": 100, "safe_commit_band": "GO", "safe_delete": 100},
        "actions": {}, "closeout": {}, "main_equals_origin_main": None,
        "main_oid": None, "origin_main_oid": None, "remote_verification": "LOCAL_TRACKING_REFS_ONLY",
        "unpushed_count_scope": "ALL_LOCAL_REFS", "branch_ahead_commit_count": 0,
        "secret_scan_state": "NOT_APPLICABLE", "worktrees": [], "extra_worktree_count": 0,
        "stale_worktree_count": 0, "ignored_count": 0, "unpushed_commit_count": 0,
        "files": [], "side_branches": [], "stashes": [], "has_commits": False,
    }

    class FakeRepo:
        def __init__(self, path):
            self.root = path
        def _run(self, *args, **kwargs):
            raise AssertionError("Git execution is outside this fixture")

    def build_state(repo, config):
        backend.calls.append(("state", repo.root, copy.deepcopy(config)))
        state = copy.deepcopy(backend.state)
        state["root"] = repo.root
        state["request_id"] = config.get("request_id")
        return state

    def discover(root):
        backend.calls.append(("discover", root))
        return [os.path.join(root, "fixture-repo")]

    def fleet(root, paths, config, **kwargs):
        backend.calls.append(("fleet", list(paths), kwargs))
        return {"read_complete": bool(paths), "read_errors": [], "repos": [
            {"name": "fixture", "path": path, "read_complete": True,
             "actions": {"commit_index": {"safe": True, "decision": "ALLOW"}}}
            for path in paths], "totals": {"repos": len(paths)}}

    backend.GitRepo = FakeRepo
    backend.build_state = build_state
    backend.discover_repos = discover
    backend.registry_fleet_paths = lambda root, paths: {"present": paths}
    backend.build_fleet_state = fleet
    backend.compute_scores = lambda state: {"safe_commit": 0, "safe_delete": 0}
    backend.closeout_state = lambda state: {"read_complete": state["read_complete"]}
    backend.stash_committed_copy = lambda state, target: {"safe": False, "reasons": ["No authored stash proof"]}
    return backend


def load_adapter(backend, sdk_modules=None):
    spec = importlib.util.spec_from_file_location("public_adapter_fixture", ADAPTER)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"gitreal": backend, **(sdk_modules or {})}), patch.object(sys, "path", sys.path.copy()):
        spec.loader.exec_module(module)
    return module


class PublicBoundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="public-mcp-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.backend = make_backend()
        self.adapter = load_adapter(self.backend)
        self.no_process = patch("subprocess.Popen", side_effect=AssertionError("No process execution in logic fixtures"))
        self.no_process.start()
        self.addCleanup(self.no_process.stop)

    def registry(self, text=None, directory=False):
        p = self.root / "governance/generated/REPOSITORY_FLEET.json"
        p.parent.mkdir(parents=True)
        p.mkdir() if directory else p.write_text(text or "{}")
        return p

    def test_wrong_tool_commit_never_becomes_discard_approval(self):
        result = self.adapter.check_discard(str(self.root), "commit_index")
        self.assertFalse(result["safe"])
        self.assertEqual(result["recommendation"], "DO_NOT_DISCARD")
        self.assertEqual(self.backend.calls, [])

    def test_invalid_discard_shapes_do_not_inspect(self):
        for operation, target in [(None, None), ("unknown", None), ("reset_hard", None),
                                  ("reset_hard", " "), ("reset_hard", 7), ("drop_stash", ""),
                                  ("clean_untracked", "HEAD"), ("discard_tracked", "HEAD")]:
            with self.subTest(operation=operation, target=target):
                self.backend.calls.clear()
                result = self.adapter.check_discard(str(self.root), operation, target)
                self.assertFalse(result["safe"])
                self.assertEqual(self.backend.calls, [])

    def test_valid_discard_preserves_engine_verdict(self):
        self.assertTrue(self.adapter.check_discard(str(self.root), "discard_tracked")["safe"])
        self.backend.state["status"]["modified"] = ["work.txt"]
        self.assertFalse(self.adapter.check_discard(str(self.root), "discard_tracked")["safe"])

    def test_valid_targeted_discard_is_assessed(self):
        result = self.adapter.check_discard(str(self.root), "reset_hard", "HEAD")
        self.assertFalse(result["safe"])
        self.assertEqual(len(self.backend.calls), 1)
        self.assertTrue(any("No current HEAD" in r for r in result["reasons"]))

    def test_commit_uses_exact_engine_decision(self):
        self.assertTrue(self.adapter.check_commit(str(self.root))["safe"])
        self.backend.state["status"]["staged"] = []
        self.assertFalse(self.adapter.check_commit(str(self.root))["safe"])

    def test_invalid_status_assessment_does_not_inspect(self):
        result = self.adapter.get_status(str(self.root), operation="commit_index")
        self.assertFalse(result["read_complete"])
        self.assertFalse(result["requested_action"]["safe"])
        self.assertEqual(self.backend.calls, [])

    def test_status_preview_scope_and_truncation(self):
        self.backend.state.update(branch_ahead_commit_count=12, unpushed_commit_count=30,
                                  unpushed=[{"hash": str(n), "subject": "fixture"} for n in range(12)])
        result = self.adapter.get_status(str(self.root))
        self.assertEqual(result["unpushed_commit_count"], 30)
        self.assertEqual(result["unpushed_preview"]["total_count"], 12)
        self.assertEqual(result["unpushed_preview"]["returned_count"], 10)
        self.assertTrue(result["unpushed_preview"]["truncated"])

    def test_incomplete_status_does_not_invent_zero_counts(self):
        self.backend.state["read_complete"] = False
        result = self.adapter.get_status(str(self.root))
        self.assertIsNone(result["dirty_file_count"])
        self.assertIsNone(result["unpushed_preview"]["total_count"])

    def test_changed_adapter_blocks_state_decisions(self):
        self.backend.state["actions"] = {"commit_index": {"safe": True}}
        with patch.object(self.adapter, "_adapter_current", return_value=False):
            result = self.adapter.check_commit(str(self.root))
        self.assertFalse(result["read_complete"])
        self.assertFalse(result["safe"])

    def test_invalid_fleet_root_never_calls_backend(self):
        result = self.adapter.get_fleet(str(self.root / "absent"))
        self.assertFalse(result["read_complete"])
        self.assertEqual(self.backend.calls, [])

    def test_malformed_registry_is_incomplete_not_exception(self):
        self.registry('{"repos":')
        result = self.adapter.get_fleet(str(self.root))
        self.assertFalse(result["read_complete"])
        self.assertEqual(self.backend.calls, [])

    def test_invalid_registry_structure_is_incomplete(self):
        self.registry('{"unexpected": []}')
        result = self.adapter.get_fleet(str(self.root))
        self.assertFalse(result["read_complete"])
        self.assertEqual(self.backend.calls, [])

    def test_unreadable_registry_is_incomplete(self):
        self.registry('{"repos": []}')
        with patch.object(self.backend, "load_registry_repo_paths", side_effect=PermissionError("fixture")):
            result = self.adapter.get_fleet(str(self.root))
        self.assertFalse(result["read_complete"])
        self.assertEqual(self.backend.calls, [])

    def test_nonregular_registry_does_not_fallback(self):
        self.registry(directory=True)
        result = self.adapter.get_fleet(str(self.root))
        self.assertFalse(result["read_complete"])
        self.assertEqual(self.backend.calls, [])

    def test_dangling_registry_does_not_fallback(self):
        p = self.registry('{"repos": []}')
        p.unlink()
        p.symlink_to(self.root / "absent")
        result = self.adapter.get_fleet(str(self.root))
        self.assertFalse(result["read_complete"])
        self.assertEqual(self.backend.calls, [])

    def test_empty_authoritative_scope_never_uses_discovery(self):
        self.registry('{"repos": []}')
        result = self.adapter.get_fleet(str(self.root))
        self.assertFalse(result["read_complete"])
        self.assertEqual([c[0] for c in self.backend.calls], ["fleet"])

    def test_missing_registry_uses_only_fake_discovery(self):
        result = self.adapter.get_fleet(str(self.root))
        self.assertTrue(result["read_complete"])
        self.assertEqual([c[0] for c in self.backend.calls], ["discover", "fleet"])

    def test_source_change_during_fleet_drops_decisions(self):
        with patch.object(self.adapter, "_adapter_current", side_effect=[True, False]):
            result = self.adapter.get_fleet(str(self.root))
        self.assertFalse(result["read_complete"])
        self.assertEqual(result["repos"], [])

    def test_bad_ignore_patterns_do_not_inspect(self):
        for value in ["", " ", "one\ntwo", "one\rtwo", "one\0two", None, 7]:
            with self.subTest(value=value):
                self.backend.calls.clear()
                result = self.adapter.do_gitignore_add(str(self.root), value)
                self.assertFalse(result["ok"])
                self.assertEqual(self.backend.calls, [])

    def test_ignore_duplicate_and_existing_bytes(self):
        p = self.root / ".gitignore"
        p.write_bytes(b"# authored fixture\r\nkeep")
        self.assertTrue(self.adapter.do_gitignore_add(str(self.root), "build/")["ok"])
        after = p.read_bytes()
        self.assertEqual(after, b"# authored fixture\r\nkeep\nbuild/\n")
        self.assertTrue(self.adapter.do_gitignore_add(str(self.root), "build/")["ok"])
        self.assertEqual(p.read_bytes(), after)

    def test_ignore_symlink_and_incomplete_state_refused(self):
        outside = self.root / "other"
        outside.write_text("preserve\n")
        (self.root / ".gitignore").symlink_to(outside)
        self.assertFalse(self.adapter.do_gitignore_add(str(self.root), "build/")["ok"])
        self.assertEqual(outside.read_text(), "preserve\n")
        self.backend.state["read_complete"] = False
        self.assertFalse(self.adapter.do_gitignore_add(str(self.root), "build/")["ok"])

    def test_sdk_catalog_distinguishes_mutation(self):
        catalog = asyncio.run(self.adapter.mcp.list_tools())
        self.assertEqual(len(catalog), 5)
        for tool in catalog:
            self.assertIsNotNone(tool.annotations)
            self.assertEqual(tool.annotations.readOnlyHint, tool.name != "gitignore_add")

    def test_legacy_sdk_without_annotations_still_registers(self):
        class LegacyMCP:
            def __init__(self, name):
                self.names = []
            def tool(self):
                def register(fn):
                    self.names.append(fn.__name__)
                    return fn
                return register
        fast = types.ModuleType("mcp.server.fastmcp")
        fast.FastMCP = LegacyMCP
        legacy_types = types.ModuleType("mcp.types")
        adapter = load_adapter(self.backend, {"mcp.server.fastmcp": fast, "mcp.types": legacy_types})
        self.assertTrue(adapter._HAVE_MCP)
        self.assertEqual(len(adapter.mcp.names), 5)

    def test_sdk_annotation_type_without_keyword_still_registers(self):
        class LegacyMCP:
            def __init__(self, name):
                self.names = []
            def tool(self):
                return lambda fn: self.names.append(fn.__name__) or fn
        fast = types.ModuleType("mcp.server.fastmcp")
        fast.FastMCP = LegacyMCP
        adapter = load_adapter(self.backend, {"mcp.server.fastmcp": fast})
        self.assertTrue(adapter._HAVE_MCP)
        self.assertEqual(len(adapter.mcp.names), 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
