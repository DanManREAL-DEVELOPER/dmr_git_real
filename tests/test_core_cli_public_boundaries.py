"""Exact CLI/state code with authored metadata; no Git, services or process effects."""
from __future__ import annotations
import argparse
import ast
import contextlib
import copy
from datetime import datetime, timezone
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
SOURCE=Path(os.environ.get('PUBLIC_CORE_CLI_TEST_SOURCE', ROOT/'gitreal.py'))
OID='a'*40

def deny_effects(test):
    names=('Popen','run','call','check_call','check_output','getoutput','getstatusoutput')
    targets=[(subprocess,n) for n in names]
    targets += [(os,n) for n in dir(os) if n.startswith(('exec','spawn','posix_spawn')) or n in
                {'system','popen','fork','forkpty','kill','killpg','abort','_exit','startfile'}]
    targets += [(socket.socket,n) for n in ('connect','connect_ex','bind','listen')]
    targets += [(threading.Thread,'start')]
    for obj,name in targets:
        guard=patch.object(obj,name,side_effect=AssertionError('Real process/thread/network effect denied'))
        guard.start();test.addCleanup(guard.stop)

def extracted(scope,names,classes=()):
    tree=ast.parse(SOURCE.read_text())
    nodes=[ast.ImportFrom(module='__future__',names=[ast.alias(name='annotations')],level=0)]
    for node in tree.body:
        if isinstance(node,ast.Assign):
            try:ast.literal_eval(node.value)
            except (ValueError,TypeError):continue
            nodes.append(node)
        elif isinstance(node,ast.FunctionDef) and node.name in names:nodes.append(node)
        elif isinstance(node,ast.ClassDef) and node.name in classes:nodes.append(node)
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),str(SOURCE),'exec'),scope)
    return scope

class PublicCoreCliBoundaries(unittest.TestCase):
    def setUp(self):
        deny_effects(self)
        area=tempfile.TemporaryDirectory(prefix='public-core-cli-authored-');self.addCleanup(area.cleanup)
        self.area=Path(area.name);self.root=self.area/'root';self.root.mkdir()
        self.metadata=self.area/'metadata';self.metadata.mkdir()
        self.index=self.metadata/'index-placeholder';self.index.write_bytes(b'authored, not a Git index\n')
        self.env=types.SimpleNamespace(**vars(os));self.env.environ={'AUTHORED':'only'}
        actual=dict(os.environ);self.addCleanup(lambda:self.assertEqual(dict(os.environ),actual))
        self.calls=[];self.split=False;self.repo_exists=True;self.top=str(self.root)
        self.status={'branch':'main','upstream':'origin/main','ahead':0,'behind':0,'oid':OID,
            'detached':False,'staged':[],'modified':[],'untracked':[],'conflicts':[],'renamed':[],
            'submodules':[],'ahead_behind_known':True,'ok':True,'complete':True,'error':None}
        self.index_inventory={'hidden_paths':[],'gitlinks':[],'unmerged_paths':[],'fingerprint':'authored-index'}
        self.storage={'complete':True,'errors':[],'loose_count':0,'loose_bytes':0,'maintenance_required':False,
            'inventory_fingerprint':'objects','config_fingerprint':'config','pending_maintenance':False}
        self.after_status=None;owner=self
        class FakeRepo:
            def __init__(self,root,*,git_environment=None):
                self.root=root;self.read_errors=[];self.git_environment=git_environment
            def record(self,name,value):owner.calls.append(name);return copy.deepcopy(value)
            def is_repo(self):return self.record('is_repo',owner.repo_exists)
            def toplevel(self):return self.record('toplevel',owner.top)
            def status(self):
                value=self.record('status',owner.status)
                if owner.after_status:owner.after_status()
                return value
            def index_inventory(self):return self.record('index_inventory',owner.index_inventory)
            def remotes(self):return self.record('remotes',[])
            def last_commit(self):return self.record('last_commit',None)
            def stashes(self):return self.record('stashes',[])
            def unpushed_commits(self,**kwargs):return self.record('unpushed_commits',[])
            def worktrees(self):return self.record('worktrees',[{'path':str(owner.root)}])
            def operation_markers(self):return self.record('operation_markers',{'index_locked':False,'active_operations':[],'merge_parents':[]})
            def refs_inventory(self):return self.record('refs_inventory',{'refs/heads/main':OID,'refs/remotes/origin/main':OID})
            def object_storage(self):return self.record('object_storage',owner.storage)
            def stash_details(self):return self.record('stash_details',[])
            def pack_size_bytes(self):return self.record('pack_size_bytes',0)
            def largest_tracked_blobs(self,count):return self.record('largest_tracked_blobs',[])
            def branches(self):return self.record('branches',[{'name':'main','upstream':'origin/main','track':'','oid':OID}])
            def default_branch(self):return self.record('default_branch','main')
            def merged_branches(self,branch):return self.record('merged_branches',{'main'})
            def ignored_entries(self):return self.record('ignored_entries',[])
            def untracked_entries(self):return self.record('untracked_entries',[])
            def staged_blob_sizes(self,rows):return self.record('staged_blob_sizes',{r['oid']:7 for r in rows if r.get('oid')})
            def _run(self,*args,**kwargs):
                owner.calls.append(args)
                if args==('config','--bool','--get','core.splitIndex'):return ('true\n' if owner.split else 'false\n'),0,''
                if args==('rev-parse','--git-path','index'):return str(owner.index)+'\n',0,''
                if args==('rev-parse','--git-path','info/grafts'):return str(owner.metadata/'absent-grafts')+'\n',0,''
                if args==('rev-list','--count','--all','--not','--remotes'):return '0\n',0,''
                raise AssertionError('Unexpected backend call: '+repr(args))
            _required=_run
        self.FakeRepo=FakeRepo
        def forbidden(*args,**kwargs):raise AssertionError('Out-of-scope backend reached')
        self.scope=extracted({'__file__':str(SOURCE),'ENGINE_SOURCE_SHA256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
            'os':self.env,'sys':sys,'argparse':argparse,'time':time,'datetime':datetime,'timezone':timezone,
            'hashlib':hashlib,'json':json,'re':re,'stat':stat,'math':math,'GitRepo':FakeRepo,
            'protected_commit_path':lambda path:False,'artifact_hint':lambda path:False,
            'resolve_remote_identity':forbidden,'_ref_inspection_preflight':forbidden,
            '_assess_ref_action':lambda *args,**kwargs:(['Authored ref proof not supplied'],{}),
            '_maintenance_hazards':lambda state:[], 'stash_committed_copy':forbidden,
            'classify_untracked':lambda root,path:'new','_read_gitignore_lines':lambda root:set(),
            'App':forbidden,'run_fleet':forbidden,'wire_agents':forbidden,'stage_paths_state':forbidden},
            {'main','build_state','compute_scores','resolved_merge_commit','assess_action','requested_action',
             'closeout_state','human_size','verdict_band','summarize_stashes','_absolute_git_path','_environment_matches',
             '_stage_storage_admission','_readonly_index_admission','_incomplete_state','start_polling'})

    def build(self,**config):
        return self.scope['build_state'](self.FakeRepo(str(self.root)),{'quick':True,'request_id':'authored-token',**config})

    def cli(self,args,scope=None):
        out,err=io.StringIO(),io.StringIO();code=0
        with patch.object(sys,'argv',['gitreal.py',str(self.root),*args]),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            try:(scope or self.scope)['main']()
            except SystemExit as exc:code=exc.code
        return code,out.getvalue(),err.getvalue()

    def assert_blocked(self,state):
        self.assertIs(state['read_complete'],False)
        self.assertEqual(state['scores']['safe_commit_band'],'STOP')
        self.assertTrue(state['actions'])
        self.assertTrue(all(a['safe'] is False and a['decision']=='BLOCK' for a in state['actions'].values()))
        self.assertEqual(state['closeout']['status'],'BLOCKED')

    def test_full_quick_state_and_exact_assessment(self):
        state=self.build();self.assertIs(state['read_complete'],True,state['read_errors'])
        self.assertEqual(state['request_id'],'authored-token');self.assertEqual(state['unpushed_commit_count'],0)
        self.assertIs(state['actions']['clean_untracked']['safe'],True)
        self.assertIs(state['actions']['commit_index']['safe'],False)
        self.assertNotIn('stash_details',self.calls);self.assertNotIn('pack_size_bytes',self.calls)

    def test_full_deep_state_invokes_authored_telemetry(self):
        state=self.build(quick=False);self.assertIs(state['read_complete'],True,state['read_errors'])
        self.assertIn('stash_details',self.calls);self.assertIn('pack_size_bytes',self.calls)
        self.assertTrue(state['push_weight']['assessed'])

    def test_observed_status_change_blocks_all_actions(self):
        self.after_status=lambda:self.status.update(branch='changed')
        self.assert_blocked(self.build())

    def test_json_route_uses_full_builder_without_app_or_output_files(self):
        code,out,err=self.cli(['--quick','--json','--request-id','cli-token'])
        self.assertEqual(code,0,err);state=json.loads(out);self.assertEqual(state['request_id'],'cli-token')
        self.assertFalse((self.root/'.git-real').exists())

    def test_json_operation_allow_and_block_exit_codes(self):
        for operation,code_expected in [('clean_untracked',0),('commit_index',1)]:
            with self.subTest(operation=operation):
                code,out,err=self.cli(['--quick','--json','--operation',operation])
                self.assertEqual(code,code_expected,err)
                action=json.loads(out)['requested_action'];self.assertEqual(action['operation'],operation)
                self.assertEqual(action['safe'],code_expected==0)

    def test_source_change_stops_before_any_repository_backend(self):
        self.scope['ENGINE_SOURCE_SHA256']='different-loaded-source'
        self.assert_blocked(self.build())
        self.assertEqual(self.calls,[])

    def test_redirected_environment_stops_before_index_or_status(self):
        self.env.environ['GIT_OBJECT_DIRECTORY']=str(self.area/'alternate-authored')
        self.assert_blocked(self.build())
        self.assertFalse(any(n in self.calls for n in ('status','index_inventory','refs_inventory','object_storage')))

    def test_split_index_configuration_refuses_before_inventory(self):
        self.split=True;self.assert_blocked(self.build(operation='clean_untracked'))
        self.assertFalse(any(n in self.calls for n in ('status','index_inventory','refs_inventory','object_storage')))

    def test_retained_shared_metadata_refuses_without_opening_it(self):
        p=self.metadata/'sharedindex.authored';p.write_bytes(b'preserve authored placeholder')
        self.assert_blocked(self.build());self.assertNotIn('status',self.calls)
        self.assertEqual(p.read_bytes(),b'preserve authored placeholder')

    def test_metadata_directory_bound_refuses_before_inventory(self):
        self.scope['STAGE_MAX_METADATA_ENTRIES']=0
        self.assert_blocked(self.build());self.assertNotIn('status',self.calls)

    def test_unreadable_admission_returns_structured_json(self):
        original=self.FakeRepo._run
        def unreadable(repo,*args,**kwargs):
            if args==('config','--bool','--get','core.splitIndex'):return '',2,'authored read failure'
            return original(repo,*args,**kwargs)
        self.FakeRepo._run=unreadable
        code,out,err=self.cli(['--quick','--json','--operation','clean_untracked'])
        self.assertEqual(code,2,err);self.assert_blocked(json.loads(out))
        self.assertNotIn('status',self.calls)

    def test_not_repository_returns_complete_blocked_shape(self):
        self.repo_exists=False;state=self.build(operation='clean_untracked')
        self.assert_blocked(state);self.assertIs(state['is_repo'],False)
        self.assertIs(state['requested_action']['safe'],False)
        self.assertEqual(self.calls,['is_repo'])

    def test_json_write_mode_conflicts_refuse_before_any_effect(self):
        for extra in (['--wire-agents'],['--init']):
            with self.subTest(extra=extra):
                code,out,err=self.cli(['--json',*extra])
                self.assertEqual(code,2);self.assertEqual(self.calls,[])

    def test_repos_file_requires_fleet_before_wiring(self):
        code,out,err=self.cli(['--wire-agents','--repos-file','authored.json'])
        self.assertEqual(code,2);self.assertEqual(self.calls,[])

    def test_invalid_interactive_interval_is_rejected_by_parser(self):
        for value in ('0','-1','nan','inf'):
            with self.subTest(value=value):
                code,out,err=self.cli(['--interval',value])
                self.assertEqual(code,2);self.assertEqual(self.calls,[])

    def test_existing_parser_rejects_ambiguous_assessment_inputs(self):
        for args in (['--json','--target','HEAD'],['--json','--expect-binding','x'],
                     ['--json','--stage-path','authored.txt'],['--operation','clean_untracked'],
                     ['--json','--operation','stage_paths'],['--fleet','--json'],
                     ['--json','--operation','clean_untracked','--init']):
            with self.subTest(args=args):
                self.assertEqual(self.cli(args)[0],2);self.assertEqual(self.calls,[])

    def test_polling_uses_guarded_rescan_without_raw_status(self):
        calls=[];stopped=[False]
        stop=types.SimpleNamespace(is_set=lambda:stopped[0],wait=lambda duration:stopped.__setitem__(0,True))
        class Thread:
            def __init__(self,*,target,daemon):self.target=target
            def start(self):self.target()
        self.scope['threading']=types.SimpleNamespace(Thread=Thread)
        def raw(*args,**kwargs):calls.append('raw');raise AssertionError('Raw status bypasses admission')
        app=types.SimpleNamespace(repo=types.SimpleNamespace(_run=raw),rescan=lambda:calls.append('rescan'),interval=1)
        self.scope['start_polling'](app,stop)
        self.assertEqual(calls,['rescan'])

    def interactive_scope(self,*,serve=True,watchdog_failure=False):
        events=[];owner=self
        class Handle:
            def stop(self):events.append('watcher.stop')
            def join(self,timeout=None):events.append(('watcher.join',timeout))
        handle=Handle()
        class Event:
            def __init__(self):self.stopped=False
            def is_set(self):return self.stopped
            def set(self):self.stopped=True;events.append('event.set')
            def wait(self,duration):raise AssertionError('No real wait')
        class Thread:
            def __init__(self,*,target,daemon):self.target=target;events.append('thread.create')
            def start(self):events.append('thread.start')
            def join(self,timeout=None):events.append(('thread.join',timeout))
        class App:
            def __init__(self,root,port,interval):
                self.root=root;self.port=port;self.interval=interval;self.config={};self.outdir='authored-output'
                self.repo=types.SimpleNamespace(is_repo=lambda:True,init=lambda:events.append('init'))
                self.state={'read_complete':True,'scores':{'safe_commit':100,'safe_commit_label':'authored','safe_delete':100}}
            def rescan(self):events.append('rescan')
            def _write_outputs(self):events.append('outputs')
        class Server:
            def __init__(self,address,handler):events.append(('server.address',address))
            def serve_forever(self):events.append('serve');raise KeyboardInterrupt()
            def shutdown(self):events.append('shutdown')
            def server_close(self):events.append('server.close')
        def watchdog(app):
            events.append('watchdog')
            if watchdog_failure:raise ImportError('authored missing watcher')
            return handle
        def sleep(seconds):raise KeyboardInterrupt()
        scope={**self.scope,'App':App,'threading':types.SimpleNamespace(Event=Event,Thread=Thread),
            'start_watchdog':watchdog,'start_polling':lambda app,stop:(events.append('polling') or handle),
            'ThreadingHTTPServer':Server,'make_handler':lambda app:'authored-handler','time':types.SimpleNamespace(sleep=sleep)}
        # main retains its extraction globals; re-extract it into this inert scope.
        extracted(scope,{'main'})
        return scope,events

    def test_interactive_server_interrupt_closes_owned_server_and_watcher(self):
        scope,events=self.interactive_scope()
        code,out,err=self.cli([],scope)
        self.assertEqual(code,0,err);self.assertIn('server.close',events)
        self.assertIn('watcher.stop',events)
        self.assertTrue(any(isinstance(x,tuple) and x[0]=='watcher.join' and 0<x[1]<=5 for x in events))

    def test_interactive_no_server_polling_cleanup_and_fallback(self):
        for args,failure in [(['--no-server','--poll'],False),(['--no-server'],True)]:
            with self.subTest(args=args):
                scope,events=self.interactive_scope(watchdog_failure=failure)
                self.assertEqual(self.cli(args,scope)[0],0);self.assertIn('polling',events)
                self.assertIn('event.set',events)
                self.assertTrue(any(isinstance(x,tuple) and x[0]=='watcher.join' for x in events))

    def test_once_route_does_not_start_watchers_or_server(self):
        scope,events=self.interactive_scope()
        self.assertEqual(self.cli(['--quick','--once'],scope)[0],0)
        self.assertEqual(events,['rescan'])

    def test_fleet_only_dispatches_to_separate_operator(self):
        seen=[];self.scope['run_fleet']=lambda args,root:seen.append((args.all,root))
        self.assertEqual(self.cli(['--fleet','--once'])[0],0)
        self.assertEqual(seen,[(True,str(self.root))]);self.assertEqual(self.calls,[])

    def test_blocked_state_serializes_through_exact_public_mcp_status(self):
        self.split=True
        path=ROOT/'gitreal_mcp.py';tree=ast.parse(path.read_text())
        nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in {'get_status','_abs'}]
        scope={'os':self.env,'gitreal':types.SimpleNamespace(REF_ACTIONS=self.scope['REF_ACTIONS']),
               '_state':lambda path,config:self.build(**config),'_UNPUSHED_PREVIEW':10}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),scope)
        result=scope['get_status'](str(self.root))
        self.assertIs(result['is_repo'],True);self.assertIs(result['read_complete'],False)
        self.assertIsNone(result['conflict_count']);self.assertIsNone(result['index_inventory']['fingerprint'])
        self.assertEqual(result['closeout']['status'],'BLOCKED')

    def filter_scope(self,*,child_split=False,active_filter=False):
        calls=[];owner=self
        child=self.root/'child';child.mkdir();(child/'.git').mkdir()
        class Repo:
            def __init__(self,root):self.root=root
            def _run(self,*args,**kwargs):
                is_child=self.root==str(child);calls.append((is_child,args))
                if args==('config','--bool','--get','core.splitIndex'):
                    return ('true\n' if child_split and is_child else 'false\n'),0,''
                if args==('rev-parse','--git-path','index'):return str(owner.index)+'\n',0,''
                if args==('config','--null','--list'):
                    return ('filter.authored.clean\nauthored-driver\0' if active_filter else ''),0,''
                if args==('ls-files','--stage','-z'):
                    if is_child:return '',0,''
                    return ('160000 '+OID+' 0\tchild\0' if child_split else '100644 '+OID+' 0\tfile.txt\0'),0,''
                if args==('check-attr','-z','--stdin','filter'):return 'file.txt\0filter\0authored\0',0,''
                raise AssertionError('Unexpected filter metadata: '+repr(args))
        scope={**self.scope,'GitRepo':Repo}
        extracted(scope,{'_status_filter_preflight','_trusted_filter_drivers','_ref_read'})
        return scope,Repo(str(self.root)),calls

    def test_filter_preflight_admits_parent_but_refuses_split_submodule_before_index(self):
        scope,repo,calls=self.filter_scope(child_split=True)
        with self.assertRaises(RuntimeError):scope['_status_filter_preflight'](repo)
        self.assertFalse(any(child and args[0]=='ls-files' for child,args in calls))

    def test_existing_active_filter_refusal_survives_storage_admission(self):
        scope,repo,calls=self.filter_scope(active_filter=True)
        with self.assertRaisesRegex(ValueError,'Active clean/process'):
            scope['_status_filter_preflight'](repo)
        self.assertFalse(any(args[0]=='status' for child,args in calls))

    def method_repo(self,raw):
        scope={**self.scope,'subprocess':subprocess,'_status_filter_preflight':lambda repo:None}
        extracted(scope,set(),{'GitRepo'})
        repo=scope['GitRepo'](str(self.root))
        repo._run=lambda *args,**kwargs:(raw,0,'')
        return repo

    def test_status_rejects_unterminated_stream_or_empty_rename_origin(self):
        headers='# branch.oid '+OID+'\0# branch.head main\0'
        rename='2 R. N... 100644 100644 100644 '+OID+' '+OID+' R100 destination\0\0'
        for raw in (headers[:-1],headers+rename):
            with self.subTest(raw=raw):self.assertIs(self.method_repo(raw).status()['complete'],False)

    def test_status_rejects_malformed_known_header_without_exception(self):
        for raw in ('# branch.head\0# branch.oid '+OID+'\0',
                    '# branch.head main\0# branch.oid not-an-oid\0'):
            with self.subTest(raw=raw):self.assertIs(self.method_repo(raw).status()['complete'],False)

    def test_index_inventory_rejects_unterminated_or_invalid_entries(self):
        valid='H 100644 '+OID+' 0\tfile.txt\0'
        for raw in (valid[:-1],valid.replace('100644','invalid'),valid.replace(OID,'bad'),
                    valid.replace(' 0\t',' 9\t'),valid.replace('file.txt','../outside'),valid+valid):
            with self.subTest(raw=raw):
                repo=self.method_repo(raw);repo.index_inventory();self.assertTrue(repo.read_errors)

    def test_valid_status_and_index_metadata_remain_accepted(self):
        headers='# branch.oid '+OID+'\0# branch.head main\0'
        self.assertIs(self.method_repo(headers).status()['complete'],True)
        repo=self.method_repo('H 100644 '+OID+' 0\tfile.txt\0')
        result=repo.index_inventory();self.assertEqual(repo.read_errors,[]);self.assertEqual(result['hidden_paths'],[])

    def test_interrupt_during_server_start_cleans_started_handles(self):
        scope,events=self.interactive_scope()
        def interrupted(*args,**kwargs):raise KeyboardInterrupt()
        scope['ThreadingHTTPServer']=interrupted
        try:result=self.cli([],scope)
        except KeyboardInterrupt:self.fail('Startup interruption escaped owned cleanup')
        self.assertEqual(result[0],0)
        self.assertIn('watcher.stop',events);self.assertIn('event.set',events)

    def watchdog_fixture(self):
        timers=[];events=[];observed={};owner=self
        class Timer:
            def __init__(self,delay,callback):self.callback=callback;self.cancelled=False;timers.append(self)
            def start(self):events.append('timer.start')
            def cancel(self):self.cancelled=True;events.append('timer.cancel')
            def join(self,timeout=None):events.append(('timer.join',timeout))
        class Observer:
            def schedule(self,handler,root,recursive):observed['handler']=handler
            def start(self):events.append('observer.start')
            def stop(self):events.append('observer.stop')
            def join(self,timeout=None):events.append(('observer.join',timeout))
        modules={'watchdog':types.ModuleType('watchdog'),'watchdog.observers':types.ModuleType('watchdog.observers'),
                 'watchdog.events':types.ModuleType('watchdog.events')}
        modules['watchdog.observers'].Observer=Observer
        modules['watchdog.events'].FileSystemEventHandler=object
        guard=patch.dict(sys.modules,modules);guard.start();self.addCleanup(guard.stop)
        scope={**self.scope,'threading':types.SimpleNamespace(Timer=Timer,Lock=threading.Lock,Event=threading.Event)}
        extracted(scope,{'start_watchdog','_should_ignore_event'})
        app=types.SimpleNamespace(root=str(self.root),rescan=lambda:events.append('rescan'))
        observer=scope['start_watchdog'](app)
        return observer,observed,timers,events,app

    def test_watchdog_stops_owned_timer_and_refuses_events_after_stop(self):
        observer,observed,timers,events,app=self.watchdog_fixture()
        event=types.SimpleNamespace(src_path=str(self.root/'authored.txt'))
        observed['handler'].on_any_event(event);self.assertEqual(len(timers),1)
        observer.stop();observer.join(timeout=2)
        self.assertTrue(timers[0].cancelled)
        observed['handler'].on_any_event(event);self.assertEqual(len(timers),1)
        timers[0].callback();self.assertNotIn('rescan',events)
        joins=[timeout for name,timeout in [x for x in events if isinstance(x,tuple)] if name.endswith('.join')]
        self.assertEqual(len(joins),2);self.assertTrue(all(0<=x<=2 for x in joins))

    def test_watchdog_already_entered_callback_can_finish_after_stop(self):
        observer,observed,timers,events,app=self.watchdog_fixture()
        def rescan():events.append('rescan.entered');observer.stop();events.append('rescan.finished')
        app.rescan=rescan
        observed['handler'].on_any_event(types.SimpleNamespace(src_path=str(self.root/'authored.txt')))
        timers[0].callback();self.assertIn('rescan.finished',events)
        before=list(events);timers[0].callback();self.assertEqual(events,before)

    def test_valid_porcelain_initial_detached_sha256_and_path_bytes(self):
        path=' spaced\tname-ü\n.txt '
        for oid,branch in [(OID,'main'),('b'*64,'(detached)'),('(initial)','new')]:
            with self.subTest(oid=oid,branch=branch):
                headers='# branch.oid '+oid+'\0# branch.head '+branch+'\0# future.extension data\0'
                raw=headers+'? '+path+'\0'
                result=self.method_repo(raw).status()
                self.assertIs(result['complete'],True,result['error'])
                self.assertEqual(result['untracked'],[path])
                self.assertEqual(result['detached'],branch=='(detached)')
        raw='# branch.oid '+OID+'\0# branch.head main\0'
        raw+='2 R. N... 100644 100644 100644 '+OID+' '+OID+' R100 '+path+'\0origin\tü\n.txt\0'
        self.assertEqual(self.method_repo(raw).status()['renamed'],[path])

    def test_valid_index_modes_unmerged_stages_and_non_ascii_paths(self):
        rows=[]
        for n,mode in enumerate(('100644','100755','120000','160000')):
            rows.append('H '+mode+' '+('b'*64)+' 0\t path-'+str(n)+'-ü\t\n.txt \0')
        for stage in ('1','2','3'):rows.append('M 100644 '+OID+' '+stage+'\tconflicted\0')
        rows.append('s 100644 '+OID+' 0\thidden\0')
        raw=''.join(rows);repo=self.method_repo(raw);result=repo.index_inventory()
        self.assertEqual(repo.read_errors,[])
        self.assertEqual(result['fingerprint'],hashlib.sha256(raw.encode()).hexdigest())
        self.assertEqual(result['unmerged_paths'],['conflicted']*3)
        self.assertEqual(result['hidden_paths'],[{'path':'hidden','flag':'s'}])

    def test_json_threshold_has_no_execution_side_effect(self):
        for threshold,expected in [('100',0),('101',1)]:
            self.assertEqual(self.cli(['--quick','--json','--fail-under',threshold])[0],expected)
        self.assertFalse((self.root/'.git-real').exists())

    def test_explicit_init_route_is_only_a_facade_call(self):
        scope,events=self.interactive_scope();original=scope['App']
        def app(*args,**kwargs):
            instance=original(*args,**kwargs);instance.repo.is_repo=lambda:False;return instance
        scope['App']=app
        self.assertEqual(self.cli(['--init','--once'],scope)[0],0)
        self.assertEqual(events,['init','rescan'])

    def app_scope(self):
        scope={**self.scope,'threading':threading,'tempfile':tempfile,
               'render_html':lambda *args:'<html>authored unused renderer</html>'}
        extracted(scope,{'main','atomic_write_text'},{'App'})
        return scope

    def test_actual_once_app_writes_authored_atomic_json_only(self):
        scope=self.app_scope()
        code,out,err=self.cli(['--quick','--once','--request-id','published-token'],scope)
        self.assertEqual(code,0,err)
        output=self.root/'.git-real/git-real.json';state=json.loads(output.read_text())
        self.assertEqual(state['request_id'],'published-token');self.assertTrue(state['read_complete'])
        self.assertFalse((self.root/'.git-real/git-real.html').exists())
        self.assertFalse(list((self.root/'.git-real').glob('.gitreal-*')))

    def test_actual_once_app_publishes_admission_refusal_with_exit_two(self):
        self.split=True;scope=self.app_scope()
        code,out,err=self.cli(['--quick','--once','--operation','clean_untracked'],scope)
        self.assertEqual(code,2,err)
        state=json.loads((self.root/'.git-real/git-real.json').read_text())
        self.assert_blocked(state);self.assertIs(state['requested_action']['safe'],False)

    def test_non_object_saved_config_uses_empty_configuration(self):
        config=self.root/'.git-real/config.json';config.parent.mkdir()
        for raw in ('[]','null','42','"text"','{broken'):
            with self.subTest(raw=raw):
                config.write_text(raw);scope=self.app_scope()
                code,out,err=self.cli(['--quick','--once'],scope)
                self.assertEqual(code,0,err)
                self.assertEqual(config.read_text(),raw)

    def test_server_bind_failure_falls_back_and_cleans_owned_handles(self):
        scope,events=self.interactive_scope()
        def bind_failure(*args,**kwargs):raise OSError('authored unavailable port')
        scope['ThreadingHTTPServer']=bind_failure
        code,out,err=self.cli([],scope)
        self.assertEqual(code,0,err);self.assertIn('could not bind port',out)
        self.assertIn('watcher.stop',events);self.assertIn('event.set',events)

    def test_targeted_cli_assessments_forward_exact_inputs_without_execution(self):
        observed=[]
        def state(repo,config):
            observed.append((repo.root,config.copy()))
            return {'read_complete':True,'requested_action':{'safe':False,'decision':'BLOCK','operation':config['operation']}}
        self.scope['build_state']=state
        for operation in (*self.scope['REF_ACTIONS'],'reset_hard','drop_stash'):
            with self.subTest(operation=operation):
                target='stash@{0}' if operation=='drop_stash' else 'refs/heads/authored'
                args=['--json','--operation',operation,'--target',target,'--request-id','exact-token']
                if operation in self.scope['REF_ACTIONS']:args+=['--expect-binding','sha256:'+'d'*64]
                code,out,err=self.cli(args);self.assertEqual(code,1,err)
                root,config=observed[-1];self.assertEqual(root,str(self.root));self.assertEqual(config['target'],target)
                self.assertEqual(config['request_id'],'exact-token');self.assertEqual(config['operation'],operation)
                self.assertEqual(json.loads(out)['requested_action']['operation'],operation)
        self.assertEqual(self.calls,[])

    def test_non_repository_json_returns_evidence_and_exit_two(self):
        self.repo_exists=False
        code,out,err=self.cli(['--quick','--json','--operation','commit_index'])
        self.assertEqual(code,2,err);state=json.loads(out)
        self.assertIs(state['is_repo'],False);self.assert_blocked(state)

    def installer_fresh_state(self):
        source=ROOT/'setup_gitreal.py';tree=ast.parse(source.read_text())
        nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='fresh_state']
        class SetupError(RuntimeError):pass
        def run(command,*,cwd):
            self.assertEqual(command[:3],[sys.executable,'gitreal.py',str(self.root)])
            self.assertEqual(cwd,self.root)
            code,out,err=self.cli(command[3:])
            return types.SimpleNamespace(returncode=code,stdout=out,stderr=err)
        scope={'Path':Path,'os':self.env,'sys':sys,'json':json,'SetupError':SetupError,'run':run}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),str(source),'exec'),scope)
        return scope['fresh_state'],SetupError

    def test_public_installer_consumes_current_complete_cli_json(self):
        fresh,error=self.installer_fresh_state();state=fresh(self.root)
        self.assertIs(state['read_complete'],True)
        self.assertEqual(state['actions']['commit_index']['decision'],'BLOCK')
        self.assertFalse((self.root/'.git-real').exists())

    def test_public_installer_rejects_cli_admission_refusal(self):
        self.split=True;fresh,error=self.installer_fresh_state()
        with self.assertRaisesRegex(error,'verification run failed'):fresh(self.root)
        self.assertNotIn('status',self.calls)

if __name__=='__main__':unittest.main(verbosity=2)
