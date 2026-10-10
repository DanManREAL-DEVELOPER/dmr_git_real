"""Authored staging metadata only: no Git, indexes, processes or real env changes."""
from __future__ import annotations
import argparse
import ast
import copy
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get('PUBLIC_STAGE_PREVIEW_TEST_SOURCE', ROOT / 'gitreal.py'))
HEAD, OLD, NEW = 'a' * 40, 'b' * 40, 'c' * 40


def deny_effects(test):
    targets = [(subprocess, n) for n in ('Popen', 'run', 'call', 'check_call', 'check_output', 'getoutput', 'getstatusoutput')]
    targets += [(os, n) for n in dir(os) if n.startswith(('exec', 'spawn', 'posix_spawn')) or n in
                {'system', 'popen', 'fork', 'forkpty', 'kill', 'killpg', 'abort', '_exit', 'startfile'}]
    targets += [(socket.socket, 'connect'), (socket.socket, 'connect_ex')]
    for obj, name in targets:
        guard = patch.object(obj, name, side_effect=AssertionError('Process/network effect forbidden'))
        guard.start(); test.addCleanup(guard.stop)


def source_functions(scope):
    tree = ast.parse(SOURCE.read_text())
    names = {'stage_paths_state', '_absolute_git_path', '_index_entries', '_index_fingerprint', '_head_oid',
             '_reported_stage_pathspec', '_readonly_index_admission', 'assess_action', 'main'}
    constants = {'SCHEMA_VERSION', 'VERSION', 'ACTION_SCOPES', 'REF_ACTIONS', 'DEFAULT_PORT', 'DEFAULT_INTERVAL'}
    selected = [n for n in tree.body if
                isinstance(n, ast.FunctionDef) and (n.name in names or n.name.startswith('_stage_')) or
                isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and
                    (t.id in constants or t.id.startswith('STAGE_')) for t in n.targets)]
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(SOURCE), 'exec'), scope)
    return scope


class PublicStagePreviewBoundaries(unittest.TestCase):
    def setUp(self):
        deny_effects(self)
        self.temporary = tempfile.TemporaryDirectory(prefix='public-stage-preview-authored-')
        self.addCleanup(self.temporary.cleanup)
        # Canonical temp path: staging preview compares realpath roots (macOS /private/var, Windows 8.3 names).
        self.area = Path(self.temporary.name).resolve(); self.root = self.area / 'target'; self.root.mkdir()
        self.storage = self.area / 'authored-metadata'; self.storage.mkdir()
        self.index_file = self.storage / 'index-placeholder'; self.index_file.write_bytes(b'authored placeholder, not a Git index\n')
        self.objects = self.storage / 'objects-placeholder'; self.objects.mkdir()
        (self.objects / 'retained').write_bytes(b'authored retained object placeholder\n')
        self.original_index = self.index_file.read_bytes()
        self.before = {'tracked.txt': ('100644', OLD, '0')}
        self.after = {**self.before, 'new.txt': ('100644', NEW, '0')}
        self.head = HEAD; self.calls = []; self.build_calls = []; self.add_calls = []
        self.add_result = ('', 0, ''); self.add_hook = None; self.filter_error = None
        self.real_incomplete = False; self.sim_incomplete = False; self.topology = 'own_repo'
        self.real_snapshot_hook = None; self.candidate_snapshot_hook = None
        self.missing_size = False; self.size_reply = '7\n'; self.os_view = types.SimpleNamespace(**vars(os))
        self.split_index = False; self.add_configurations = []
        self.os_view.environ = {'AUTHORED_ENV': 'retained'}
        self.original_env = self.os_view.environ.copy()
        self.real_env_before = dict(os.environ)
        self.addCleanup(lambda: self.assertEqual(dict(os.environ), self.real_env_before))
        owner = self
        class FakeRepo:
            def __init__(self, root, *, git_environment=None):
                self.root = root
                self.git_environment = None if git_environment is None else dict(git_environment)
                self.read_errors = []
                self.copied_entries = copy.deepcopy(owner.before)
                self.added = False
            def env(self):
                return owner.os_view.environ if self.git_environment is None else self.git_environment
            def simulated(self):
                return self.env().get('GIT_INDEX_FILE') not in (None, str(owner.index_file))
            def _run(self, *args, **kwargs):
                env = dict(self.env()); simulated = self.simulated()
                owner.calls.append((args, simulated, env))
                local_config = []
                while args[:1] == ('-c',):
                    local_config.append(args[1]); args = args[2:]
                if args == ('config', '--bool', '--get', 'core.splitIndex'):
                    return ('true\n' if owner.split_index else 'false\n'), 0, ''
                if args[:2] == ('rev-parse', '--git-path'):
                    return str(owner.index_file if args[2] == 'index' else owner.objects) + '\n', 0, ''
                if args == ('rev-parse', '--verify', 'HEAD'):
                    return owner.head + '\n', 0, ''
                if args and args[0] == 'ls-files':
                    entries = (owner.after if self.added else self.copied_entries) if simulated else owner.before
                    tagged = '-v' in args
                    result = ''.join(('H ' if tagged else '') + ' '.join(v) + '\t' + k + '\0' for k, v in sorted(entries.items()))
                    return result, 0, ''
                if args[:2] == ('add', '--'):
                    self.added = True
                    owner.add_configurations.append(local_config)
                    owner.add_calls.append((args, env, dict(owner.os_view.environ)))
                    if owner.add_hook: owner.add_hook()
                    return owner.add_result
                if args[:2] == ('cat-file', '-s'):
                    return ('', 1, 'authored object disappeared') if owner.missing_size else (owner.size_reply, 0, '')
                raise AssertionError('Unexpected metadata request: ' + repr(args))
        self.FakeRepo = FakeRepo
        def state(repo, config):
            sim = repo.simulated(); self.build_calls.append((sim, config.copy()))
            staged = [{'path': k, 'x': 'A', 'mode': v[0], 'oid': v[1]} for k,v in self.after.items() if self.before.get(k) != v] if sim else []
            if sim:
                staged += [{'path': k, 'x': 'D'} for k in self.before if k not in self.after]
            fingerprint = self.fingerprint(self.after if sim else self.before)
            value = {'version': 'authored', 'schema_version': 2, 'root': str(self.root), 'is_repo': True,
                     'has_commits': True, 'read_complete': not (self.sim_incomplete if sim else self.real_incomplete),
                     'read_errors': [], 'request_id': config.get('request_id'),
                     'publication_id': 'candidate-publication' if sim else 'baseline-publication',
                     'status': {'oid': self.head, 'ok': True, 'complete': True, 'staged': staged},
                     'index_inventory': {'fingerprint': fingerprint, 'hidden_paths': []},
                     'topology': {'kind': self.topology, 'toplevel': str(self.root)}, 'index_locked': False,
                     'active_operations': [], 'object_storage': {'complete': True},
                     'scores': {'safe_commit_band': 'GO', 'safe_commit': 100}, 'actions': {}}
            callback = self.candidate_snapshot_hook if sim else self.real_snapshot_hook
            if callback: callback()
            return value
        def filters(repo, pathspecs):
            if self.filter_error: raise ValueError(self.filter_error)
        def forbidden(*args, **kwargs): raise AssertionError('Non-preview backend reached')
        self.scope = source_functions({'os': self.os_view, 'sys': sys, 'stat': __import__('stat'), 'tempfile': tempfile,
            'shutil': shutil, 'json': json, 'hashlib': hashlib, 're': re, 'argparse': argparse,
            'GitRepo': FakeRepo, 'build_state': state, '_status_filter_preflight': filters,
            'App': forbidden, 'run_fleet': forbidden, 'requested_action': forbidden})

    def fingerprint(self, entries):
        raw = ''.join('H ' + ' '.join(v) + '\t' + k + '\0' for k,v in sorted(entries.items()))
        return hashlib.sha256(raw.encode()).hexdigest()

    def preview(self, paths=None):
        return self.scope['stage_paths_state'](str(self.root), ['new.txt'] if paths is None else paths, quick=True, request_id='authored-request')

    def action(self, paths=None): return self.preview(paths)['requested_action']

    def test_valid_manifest_and_deterministic_digest(self):
        action = self.action()
        self.assertIs(action['safe'], True, action['reasons'])
        self.assertEqual(action['decision'], 'ALLOW')
        self.assertEqual(action['candidate_count'], 1); self.assertEqual(action['candidate_bytes'], 7)
        self.assertEqual(action['manifest'][0]['path'], 'new.txt')
        canonical = json.dumps(action['manifest'], sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
        self.assertEqual(action['manifest_digest'], 'sha256:' + hashlib.sha256(canonical).hexdigest())
        self.assertEqual(self.index_file.read_bytes(), self.original_index)
        self.assertEqual((self.objects / 'retained').read_bytes(), b'authored retained object placeholder\n')

    def test_action_publication_is_returned_state_and_baseline_is_explicit(self):
        value = self.preview(); action = value['requested_action']
        self.assertEqual(action['publication_id'], value['publication_id'])
        self.assertEqual(action['baseline_publication_id'], 'baseline-publication')
        self.assertEqual(action['index_fingerprint'], self.fingerprint(self.before))
        self.assertEqual(value['actions']['stage_paths'], action)

    def test_invalid_requests_rejected_before_repo_inventory(self):
        for paths in ([], [''], ['a\0b'], ['/absolute'], ['-A'], ['x' * 4097], [None]):
            with self.subTest(paths=repr(paths)[:40]):
                self.build_calls.clear(); self.add_calls.clear()
                action = self.action(paths)
                self.assertIs(action['safe'], False); self.assertEqual(self.build_calls, []); self.assertEqual(self.add_calls, [])

    def test_nonlist_request_is_structured_refusal(self):
        for value in ('new.txt', 3, {'new.txt': True}):
            with self.subTest(value=value):
                result = self.scope['stage_paths_state'](str(self.root), value)
                self.assertIs(result['requested_action']['safe'], False)
                self.assertEqual(self.build_calls, [])

    def test_unencodable_request_is_structured_refusal(self):
        self.assertIs(self.action(['bad\ud800'])['safe'], False)
        self.assertEqual(self.build_calls, [])

    def test_bounded_path_count_and_reporting(self):
        value = self.action(['new.txt'] * (self.scope['STAGE_MAX_REQUEST_PATHS'] + 1))
        self.assertIs(value['safe'], False)
        self.assertEqual(len(value['requested_pathspecs']), 128)
        self.assertGreater(value['requested_pathspecs_truncated'], 0)
        self.assertEqual(self.build_calls, [])

    def test_incomplete_real_read_stops_simulation(self):
        self.real_incomplete = True
        self.assertIs(self.action()['safe'], False); self.assertEqual(self.add_calls, [])

    def test_nonroot_admission_stops_simulation(self):
        self.topology = 'tracked_inside_parent'
        self.assertIs(self.action()['safe'], False); self.assertEqual(self.add_calls, [])

    def test_filter_refusal_stops_simulation(self):
        self.filter_error = 'authored active filter metadata'
        self.assertIs(self.action()['safe'], False); self.assertEqual(self.add_calls, [])

    def test_environment_is_per_instance_and_never_temporarily_global(self):
        self.action()
        _, env, observed = self.add_calls[0]
        self.assertEqual(observed, self.original_env)
        self.assertEqual(self.os_view.environ, self.original_env)
        self.assertNotIn('GIT_ALTERNATE_OBJECT_DIRECTORIES', env)
        self.assertNotEqual(env['GIT_OBJECT_DIRECTORY'], str(self.objects))
        self.assertFalse(Path(env['GIT_INDEX_FILE']).exists())

    def test_simulation_failure_restores_environment_and_returns_block(self):
        self.add_result = ('', 1, 'authored expansion failure')
        value = self.action()
        self.assertIs(value['safe'], False); self.assertEqual(self.os_view.environ, self.original_env)
        self.assertIn('authored expansion failure', ' '.join(value['reasons']))

    def test_changed_baseline_index_is_refused_before_add(self):
        self.real_snapshot_hook = lambda: self.before.update({'other.txt': ('100644', NEW, '0')})
        self.assertIs(self.action()['safe'], False); self.assertEqual(self.add_calls, [])

    def test_real_index_change_during_preview_is_refused(self):
        self.add_hook = lambda: self.before.update({'other.txt': ('100644', NEW, '0')})
        self.assertIs(self.action()['safe'], False)

    def test_head_change_during_preview_is_refused(self):
        self.add_hook = lambda: setattr(self, 'head', 'd' * 40)
        self.assertIs(self.action()['safe'], False)

    def test_candidate_change_after_snapshot_is_refused(self):
        self.candidate_snapshot_hook = lambda: self.after.update({'extra.txt': ('100644', NEW, '0')})
        self.assertIs(self.action()['safe'], False)

    def test_missing_candidate_size_is_not_allow_with_zero_bytes(self):
        self.missing_size = True
        self.assertIs(self.action()['safe'], False)

    def test_simulated_commit_read_failure_is_blocked(self):
        self.sim_incomplete = True
        self.assertIs(self.action()['safe'], False)

    def test_no_effect_is_blocked(self):
        self.after = dict(self.before)
        self.assertIs(self.action()['safe'], False)

    def test_synthetic_and_gitlink_candidates_are_blocked(self):
        for path, mode in [('.cache/item', '100644'), ('child', '160000')]:
            with self.subTest(path=path):
                self.after = {**self.before, path: (mode, NEW, '0')}
                self.assertIs(self.action()['safe'], False)

    def test_manifest_ceiling_is_blocked(self):
        self.scope['STAGE_MAX_MANIFEST_ENTRIES'] = 1
        self.after['second.txt'] = ('100644', NEW, '0')
        action = self.action(); self.assertIs(action['safe'], False); self.assertEqual(action['candidate_count'], 2)

    def test_temporary_allocation_failure_is_structured(self):
        with patch.object(tempfile, 'TemporaryDirectory', side_effect=OSError('authored allocation failure')):
            self.assertIs(self.action()['safe'], False)

    def test_copy_failure_is_structured_without_source_change(self):
        with patch.object(shutil, 'copy2', side_effect=OSError('authored copy failure')):
            self.assertIs(self.action()['safe'], False)
        self.assertEqual(self.index_file.read_bytes(), self.original_index)

    def test_deletion_manifest_is_explicit_and_has_zero_candidate_bytes(self):
        self.after = {}
        action = self.action(['tracked.txt'])
        self.assertIs(action['safe'], True, action['reasons'])
        self.assertEqual(action['candidate_bytes'], 0)
        self.assertEqual(action['manifest'], [{'path': 'tracked.txt', 'kind': 'delete', 'mode': None,
                                             'oid': None, 'index_status': 'D'}])

    def test_index_entry_parser_refuses_incomplete_or_malformed_metadata(self):
        valid = '100644 ' + NEW + ' 0\tnew.txt\0'
        for raw in [valid[:-1], 'bad ' + NEW + ' 0\tnew.txt\0', '100644 bad 0\tnew.txt\0',
                    '100644 ' + NEW + ' 9\tnew.txt\0', valid + valid, '100644 ' + NEW + ' 0\t../escape\0']:
            with self.subTest(raw=raw):
                repo = types.SimpleNamespace(_run=lambda *args: (raw, 0, ''))
                with self.assertRaises(RuntimeError): self.scope['_index_entries'](repo)

    def test_index_fingerprint_refuses_unterminated_metadata(self):
        repo = types.SimpleNamespace(_run=lambda *args: ('H 100644 ' + NEW + ' 0\tnew.txt', 0, ''))
        with self.assertRaises(RuntimeError): self.scope['_index_fingerprint'](repo)

    def test_inert_main_prints_actual_preview_json(self):
        output = io.StringIO()
        argv = ['gitreal.py', str(self.root), '--quick', '--json', '--operation', 'stage_paths', '--stage-path', 'new.txt']
        with patch.object(sys, 'argv', argv), contextlib.redirect_stdout(output):
            self.scope['main']()
        state = json.loads(output.getvalue())
        self.assertIs(state['requested_action']['safe'], True)
        self.assertEqual(state['requested_action']['publication_id'], state['publication_id'])
        self.assertFalse((self.root / '.git').exists())

    def test_inert_main_admission_failure_prints_json_and_exits_nonzero(self):
        output = io.StringIO()
        argv = ['gitreal.py', str(self.root), '--quick', '--json', '--operation', 'stage_paths', '--stage-path=-A']
        with patch.object(sys, 'argv', argv), contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as stopped: self.scope['main']()
        state = json.loads(output.getvalue())
        self.assertNotEqual(stopped.exception.code, 0)
        self.assertIs(state['requested_action']['safe'], False)
        self.assertEqual(self.build_calls, [])

    def test_enabled_split_index_is_refused_before_state_or_index_read(self):
        self.split_index = True
        action = self.action()
        self.assertIs(action['safe'], False)
        self.assertEqual(self.build_calls, []); self.assertEqual(self.add_calls, [])
        self.assertFalse(any(args[0] == 'ls-files' for args, _, _ in self.calls))

    def test_retained_shared_index_metadata_is_refused_before_state_read(self):
        p = self.storage / 'sharedindex.authored-retained'
        p.write_bytes(b'authored retained metadata placeholder\n')
        action = self.action()
        self.assertIs(action['safe'], False); self.assertEqual(self.build_calls, [])
        self.assertEqual(p.read_bytes(), b'authored retained metadata placeholder\n')
        self.assertFalse(any(args[0] == 'ls-files' for args, _, _ in self.calls))

    def test_isolated_add_overrides_hooks_and_split_index_with_local_config(self):
        observed = []
        def during_add():
            options = self.add_configurations[-1]
            self.assertIn('core.splitIndex=false', options)
            hook_path = next(v.split('=', 1)[1] for v in options if v.startswith('core.hooksPath='))
            self.assertTrue(Path(hook_path).is_dir())
            self.assertEqual(list(Path(hook_path).iterdir()), [])
            self.assertEqual(Path(hook_path).parent, Path(self.add_calls[-1][1]['GIT_INDEX_FILE']).parent)
            observed.append(hook_path)
        self.add_hook = during_add
        self.assertIs(self.action()['safe'], True)
        self.assertEqual(len(observed), 1); self.assertFalse(Path(observed[0]).exists())

    def test_copied_index_fingerprint_mismatch_stops_before_add(self):
        owner = self
        class MismatchRepo(self.FakeRepo):
            def __init__(self, root, *, git_environment=None):
                super().__init__(root, git_environment=git_environment)
                if self.simulated():
                    self.copied_entries['changed-during-copy.txt'] = ('100644', NEW, '0')
        self.scope['GitRepo'] = MismatchRepo
        self.assertIs(owner.action()['safe'], False)
        self.assertEqual(self.add_calls, [])

    def test_candidate_change_during_size_read_is_refused(self):
        owner = self
        class ChangeRepo(self.FakeRepo):
            def _run(self, *args, **kwargs):
                result = super()._run(*args, **kwargs)
                if args[:2] == ('cat-file', '-s'):
                    owner.after['later.txt'] = ('100644', NEW, '0')
                return result
        self.scope['GitRepo'] = ChangeRepo
        self.assertIs(self.action()['safe'], False)

    def test_index_directory_inventory_bound_refuses_before_state_read(self):
        self.scope['STAGE_MAX_METADATA_ENTRIES'] = 1
        self.assertIs(self.action()['safe'], False)
        self.assertEqual(self.build_calls, [])
        self.assertEqual(self.add_calls, [])

    def adapter_functions(self, names, scope):
        source = ROOT / 'gitreal_mcp.py'
        tree = ast.parse(source.read_text())
        nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
        self.assertEqual({n.name for n in nodes}, names)
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), 'exec'), scope)
        return scope

    def test_public_mcp_refuses_stage_assessment_without_state_or_git(self):
        def unexpected(*args, **kwargs):
            raise AssertionError('Public MCP must refuse before repository inspection')
        observed = []
        def requested(state, operation, target, expected):
            observed.append((operation, target, expected))
            state['requested_action'] = {'operation': operation, 'safe': False, 'decision': 'BLOCK'}
        backend = types.SimpleNamespace(REF_ACTIONS=self.scope['REF_ACTIONS'],
            SCHEMA_VERSION=self.scope['SCHEMA_VERSION'], requested_action=requested,
            GitRepo=unexpected, build_state=unexpected)
        adapter = self.adapter_functions({'_abs', 'get_status'},
            {'os': self.os_view, 'gitreal': backend, '_state': unexpected})
        state = adapter['get_status'](str(self.root), operation='stage_paths', request_id='public-fixture')
        self.assertEqual(observed, [('stage_paths', None, None)])
        self.assertIs(state['read_complete'], False)
        self.assertIs(state['is_repo'], None)
        self.assertIs(state['requested_action']['safe'], False)
        self.assertEqual(state['request_id'], 'public-fixture')
        self.assertIn('no Git inspection ran', state['read_errors'][0])

    def test_public_mcp_state_preserves_default_constructor_contract(self):
        def forbidden(*args, **kwargs):
            raise AssertionError('State compatibility fixture must not run Git')
        observed = []
        def build(repo, config):
            observed.append((repo, config))
            return {'read_complete': True, 'read_errors': []}
        backend = types.SimpleNamespace(GitRepo=self.git_class(forbidden), build_state=build)
        adapter = self.adapter_functions({'_abs', '_state'},
            {'os': self.os_view, 'gitreal': backend, '_CFG': {'quick': True}, '_adapter_current': lambda: True})
        result = adapter['_state'](str(self.root), {'request_id': 'public-fixture'})
        self.assertEqual(result, {'read_complete': True, 'read_errors': []})
        repo, config = observed[0]
        self.assertIs(getattr(repo, 'git_environment', None), None)
        self.assertEqual(repo.root, str(self.root))
        self.assertEqual(config, {'quick': True, 'request_id': 'public-fixture'})

    def git_class(self, runner):
        tree = ast.parse(SOURCE.read_text())
        original = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'GitRepo')
        original.body = [n for n in original.body if isinstance(n, ast.FunctionDef) and n.name in {'__init__', '_run'}]
        backend = types.SimpleNamespace(run=runner, TimeoutExpired=subprocess.TimeoutExpired)
        scope = {'os': self.os_view, 'subprocess': backend}
        exec(compile(ast.Module(body=[original], type_ignores=[]), str(SOURCE), 'exec'), scope)
        return scope['GitRepo']

    def test_default_git_environment_retains_inherited_call_time_behavior(self):
        observed = []
        def runner(command, **kwargs):
            observed.append((command, kwargs))
            return types.SimpleNamespace(stdout='authored', returncode=0, stderr='')
        repo = self.git_class(runner)(str(self.root))
        self.os_view.environ['AUTHORED_LATE'] = 'visible'
        self.assertEqual(repo._run('authored-metadata'), ('authored', 0, ''))
        self.assertEqual(observed[0][1]['env']['AUTHORED_LATE'], 'visible')
        self.assertEqual(observed[0][1]['env']['GIT_NO_LAZY_FETCH'], '1')
        self.assertEqual(observed[0][1]['env']['GIT_OPTIONAL_LOCKS'], '0')
        self.assertEqual(observed[0][0][0], 'git')
        self.assertEqual(self.os_view.environ['AUTHORED_LATE'], 'visible')

    def test_explicit_git_environment_is_copied_and_process_globals_untouched(self):
        observed = []
        def runner(command, **kwargs):
            observed.append(kwargs['env'])
            return types.SimpleNamespace(stdout='', returncode=0, stderr='')
        supplied = {'AUTHORED_INSTANCE': 'original', 'LC_ALL': 'authored-other'}
        repo = self.git_class(runner)(str(self.root), git_environment=supplied)
        supplied['AUTHORED_INSTANCE'] = 'caller changed'
        repo._run('authored-metadata')
        self.assertEqual(observed[0]['AUTHORED_INSTANCE'], 'original')
        self.assertEqual(observed[0]['LC_ALL'], 'C')
        self.assertNotIn('AUTHORED_ENV', observed[0])
        self.assertEqual(self.os_view.environ, self.original_env)

    def test_both_admission_loops_inspect_the_instance_environment(self):
        tree = ast.parse(SOURCE.read_text())
        build = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'build_state')
        start = next(i for i,n in enumerate(build.body) if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'allowed_environment' for t in n.targets))
        end = next(i for i,n in enumerate(build.body) if i > start and isinstance(n, ast.If) and isinstance(n.test, ast.Name) and n.test.id == 'redirected')
        helper = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_environment_matches')
        admission = copy.deepcopy(build.body[start:end+1])
        # Isolate the exact admission reads/error append; public core CLI
        # fixtures exercise the full builder's new terminal refusal return.
        admission[-1].body = [n for n in admission[-1].body if not isinstance(n, ast.Return)]
        code = compile(ast.Module(body=[helper, *admission], type_ignores=[]), str(SOURCE), 'exec')
        expected = {'GIT_DIR': str(self.storage), 'GIT_WORK_TREE': str(self.root), 'GIT_INDEX_FILE': str(self.index_file)}
        for key in ('GIT_DIR', 'GIT_OBJECT_DIRECTORY'):
            with self.subTest(key=key):
                explicit = {key: str(self.area / 'other')}
                repo = types.SimpleNamespace(git_environment=explicit, read_errors=[])
                scope = {'os': self.os_view, 'repo': repo, 'root': str(self.root), 'expected': expected, 'config': {}}
                exec(code, scope)
                self.assertEqual(scope['redirected'], [key])
                self.assertEqual(len(repo.read_errors), 1)
                repo.read_errors.clear(); scope['config'] = {'_allowed_git_environment': explicit}
                exec(code, scope)
                self.assertEqual(scope['redirected'], []); self.assertEqual(repo.read_errors, [])
        self.os_view.environ['GIT_DIR'] = str(self.area / 'bad-global')
        repo = types.SimpleNamespace(git_environment={}, read_errors=[])
        scope = {'os': self.os_view, 'repo': repo, 'root': str(self.root), 'expected': expected, 'config': {}}
        exec(code, scope); self.assertEqual(scope['redirected'], [])
        repo.git_environment = None
        exec(code, scope); self.assertEqual(scope['redirected'], ['GIT_DIR'])


if __name__ == '__main__': unittest.main(verbosity=2)
