"""Fleet source with authored files and inert repository/runtime adapters only."""
from __future__ import annotations
import ast, contextlib, copy, concurrent.futures, hashlib, html, http.server, io, json, os
from pathlib import Path
import re, socket, stat, subprocess, sys, tempfile, threading, time, types, unittest
from datetime import datetime, timezone
from unittest.mock import patch
SOURCE=Path(__file__).resolve().parents[1]/'gitreal.py'
MCP_SOURCE=SOURCE.parent/'gitreal_mcp.py'

def extract():
    tree=ast.parse(SOURCE.read_text());nodes=[ast.ImportFrom(module='__future__',names=[ast.alias(name='annotations')],level=0)]
    names={'load_registry_repo_paths','discover_all_git','registry_fleet_paths','discover_repos','repo_summary','_hook_verdict','_repo_is_verified_clean','build_fleet_state','render_fleet_html','make_fleet_handler','run_fleet','atomic_write_text','json_for_script','html_text','_fleet_failure_state'}
    for n in tree.body:
        if isinstance(n,ast.Assign):
            try:ast.literal_eval(n.value)
            except (ValueError,TypeError):continue
            nodes.append(n)
        elif isinstance(n,ast.FunctionDef) and n.name in names:nodes.append(n)
        elif isinstance(n,ast.ClassDef) and n.name=='FleetApp':nodes.append(n)
    env=types.SimpleNamespace(**vars(os));env.environ={'AUTHORED':'only'}
    s={'os':env,'threading':threading,'datetime':datetime,'timezone':timezone,'json':json,'re':re,'sys':sys,'time':time,'tempfile':tempfile,'http':http,'html':html,'stat':stat,'SKIP_WALK_DIRS':{'.git','.git-real','node_modules'},'GitRepo':lambda *a: (_ for _ in ()).throw(AssertionError('No repository backend'))}
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),str(SOURCE),'exec'),s)
    return s

class InlineExecutor:
    def __init__(self,**kwargs):pass
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def submit(self,fn,*args):
        class Future:
            def result(self):return fn(*args)
        return Future()

class PublicFleetBoundaries(unittest.TestCase):
    def setUp(self):
        targets=[(subprocess,n) for n in ('Popen','run','call','check_call','check_output','getoutput','getstatusoutput')]
        targets += [(os,n) for n in dir(os) if n.startswith(('exec','spawn','posix_spawn')) or n in {'system','popen','fork','forkpty','kill','killpg','abort','_exit','startfile'}]
        targets += [(socket.socket,n) for n in ('connect','connect_ex','bind','listen')]+[(threading.Thread,'start')]
        for obj,n in targets:
            x=patch.object(obj,n,side_effect=AssertionError('Native effect denied'));x.start();self.addCleanup(x.stop)
        for obj,n,val in [(concurrent.futures,'ThreadPoolExecutor',InlineExecutor),(concurrent.futures,'as_completed',lambda futures:list(futures))]:
            x=patch.object(obj,n,val);x.start();self.addCleanup(x.stop)
        actual=dict(os.environ);self.addCleanup(lambda:self.assertEqual(actual,dict(os.environ)))
        tmp=tempfile.TemporaryDirectory(prefix='public-fleet-authored-');self.addCleanup(tmp.cleanup);self.root=Path(tmp.name);self.s=extract();self.calls=[]
        self.s['repo_summary']=lambda p,c:self.row(p)
        self.s['discover_repos']=lambda root,**kw:self.calls.append(('discovery',kw)) or []
        self.s['registry_fleet_paths']=lambda root,paths,**kw:{'present':list(paths),'drift_missing':[],'drift_unregistered':[]}
    def row(self,path,**kw):
        r={'name':Path(path).name,'path':str(path),'is_repo':True,'read_complete':True,'error':None,'dirty_files':0,'hidden_path_count':0,'safe_delete':40,'safe_commit':90,'side_branches':0,'unpushed':0,'stashes':0,'closeout':{'local_state_complete':True},'object_storage':{'complete':True,'maintenance_required':False},'remotes_detail':[]};r.update(kw);return r
    def build(self,paths=None,**kw):return self.s['build_fleet_state'](str(self.root),paths or [str(self.root/'one')],{},**kw)
    def app(self,**kw):return self.s['FleetApp'](str(self.root),4567,4,**kw)
    def registry(self,data):
        p=self.root/'registry.json';p.write_text(json.dumps(data));return str(p)
    def args(self,**kw):
        a=dict(repos_file=None,port=4567,interval=4,quick=True,once=True,fail_under=None,no_server=True);a.update(kw);return types.SimpleNamespace(**a)
    def run_cli(self,args):
        out,err=io.StringIO(),io.StringIO();code=0
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            try:self.s['run_fleet'](args,str(self.root))
            except SystemExit as e:code=e.code
        return code,out.getvalue(),err.getvalue()
    def test_registry_valid_projection_deduplicates_and_disabled_is_not_adopted(self):
        p=self.registry({'repositories':[{'physical_location':'/authored/one','discovery_enabled':True},{'physical_location':'/authored/one'},{'physical_location':None,'discovery_enabled':False}]})
        self.assertEqual(self.s['load_registry_repo_paths'](p),['/authored/one'])
    def test_registry_rejects_malformed_rows_instead_of_silent_omission(self):
        for row in [4,None,{}, {'physical_location':False},{'physical_location':'/one','discovery_enabled':'false'}]:
            with self.subTest(row=row),self.assertRaises(ValueError):self.s['load_registry_repo_paths'](self.registry({'repositories':[row]}))
    def test_registry_rejects_coerced_empty_or_nul_paths(self):
        for raw in [None,4,True,{},'', 'x\0y']:
            with self.subTest(raw=raw),self.assertRaises(ValueError):self.s['load_registry_repo_paths'](self.registry({'repos':[raw]}))
    def test_empty_registry_is_authority_not_fallback(self):
        app=self.app(registry_paths=[]);state=app.rescan()
        self.assertEqual(self.calls,[]);self.assertIs(state['registry_authority'],True);self.assertFalse(state['read_complete'])
    def test_no_registry_uses_authored_discovery(self):
        app=self.app();app.rescan();self.assertTrue(self.calls)
    def test_run_empty_explicit_registry_does_not_discover(self):
        code,_,_=self.run_cli(self.args(repos_file=self.registry({'repos':[]})))
        self.assertEqual(code,2);self.assertEqual(self.calls,[])
    def test_existing_nonfile_default_registry_refuses_before_app(self):
        p=self.root/'governance/generated/REPOSITORY_FLEET.json';p.mkdir(parents=True)
        self.s['FleetApp']=lambda *a,**kw:self.fail('Must refuse before app/discovery')
        self.assertEqual(self.run_cli(self.args())[0],2)
    def test_broken_explicit_registry_refuses_without_traceback_or_fallback(self):
        p=self.root/'registry.json';p.write_text('{broken')
        self.assertEqual(self.run_cli(self.args(repos_file=str(p)))[0],2);self.assertEqual(self.calls,[])
    def test_invalid_pinned_document_refuses_before_discovery(self):
        d=self.root/'.git-real';d.mkdir();(d/'fleet.json').write_text('{"repos":"not-a-list"}')
        self.assertEqual(self.run_cli(self.args())[0],2);self.assertEqual(self.calls,[])
    def test_registry_missing_repo_blocks_and_publishes_drift(self):
        self.s['registry_fleet_paths']=lambda *a,**k:{'present':['/authored/one'],'drift_missing':['/authored/missing'],'drift_unregistered':['/authored/stray']}
        state=self.app(registry_paths=['/authored/one','/authored/missing']).rescan()
        self.assertFalse(state['read_complete']);self.assertEqual(state['totals']['drift_missing'],1);self.assertEqual(state['totals']['repos'],1)
    def test_discovery_error_replaces_prior_complete_snapshot(self):
        app=self.app(registry_paths=['/authored/one']);app.rescan()
        self.s['registry_fleet_paths']=lambda *a,**k:(_ for _ in ()).throw(PermissionError('authored unreadable'))
        state=app.rescan();self.assertFalse(state['read_complete']);self.assertTrue(state['read_errors']);self.assertEqual(state['repos'],[])
        self.assertFalse(json.loads((self.root/'.git-real/git-real-fleet.json').read_text())['read_complete'])
    def test_publication_error_is_visible_in_memory(self):
        app=self.app(registry_paths=['/authored/one']);app.rescan();old=(self.root/'.git-real/git-real-fleet.json').read_bytes()
        self.s['atomic_write_text']=lambda *a:(_ for _ in ()).throw(OSError('authored publication failure'))
        state=app.rescan();self.assertFalse(state['read_complete']);self.assertIn('publication',str(state['read_errors']).lower());self.assertEqual((self.root/'.git-real/git-real-fleet.json').read_bytes(),old)
    def test_repo_detail_admits_only_current_selected_paths(self):
        app=self.app(registry_paths=['/authored/one']);self.s['GitRepo']=lambda path:path;self.s['build_state']=lambda repo,c:{'path':repo}
        self.assertEqual(app.repo_state('/outside'),{'error':'unknown repo'});self.assertEqual(app.repo_state('/authored/one'),{'path':'/authored/one'})
    def test_output_symlink_refused_and_target_preserved(self):
        outside=self.root/'outside';outside.mkdir();(self.root/'.git-real').symlink_to(outside,target_is_directory=True)
        with self.assertRaises(OSError):self.app()
        self.assertEqual(list(outside.iterdir()),[])
    def test_summary_does_not_probe_hooks_after_refused_builder(self):
        s=extract();s['GitRepo']=lambda p:p;s['build_state']=lambda *a:{'root_name':'one','is_repo':True,'read_complete':False,'read_errors':['source mismatch'],'scores':{},'status':{}}
        s['_hook_verdict']=lambda p:self.fail('No backend after refusal')
        r=s['repo_summary']('/authored/one',{});self.assertFalse(r['read_complete']);self.assertIsNone(r['hidden_path_count']);self.assertFalse(r['hooks']['read_complete'])
    def test_summary_requires_explicit_read_complete(self):
        s=extract();s['GitRepo']=lambda p:p;s['build_state']=lambda *a:{'root_name':'one','is_repo':True,'scores':{},'status':{}};s['_hook_verdict']=lambda p:{}
        r=s['repo_summary']('/authored/one',{});self.assertFalse(r['read_complete']);self.assertIsNone(r['dirty_files']);self.assertTrue(r['error'])
    def test_verified_clean_requires_explicit_complete(self):
        r=self.row('/one');r.pop('read_complete');self.assertFalse(self.s['_repo_is_verified_clean'](r))
    def test_exception_is_unknown_not_clean(self):
        self.s['repo_summary']=lambda *a:(_ for _ in ()).throw(ValueError('authored error'))
        state=self.build();self.assertFalse(state['read_complete']);self.assertEqual(state['totals']['clean_repos'],0);self.assertIsNone(state['totals']['total_unpushed'])
    def test_duplicate_paths_not_double_counted(self):
        state=self.build(['/authored/one','/authored/./one']);self.assertEqual(state['totals']['repos'],1)
    def test_missing_root_refuses_before_repo_backend(self):
        seen=[];self.s['repo_summary']=lambda *a:seen.append(a) or self.row('/authored/one')
        state=self.s['build_fleet_state'](str(self.root/'missing'),['/authored/one'],{});self.assertFalse(state['read_complete']);self.assertTrue(state['read_errors']);self.assertEqual(seen,[])
    def test_external_owner_still_counts_dirty(self):
        self.s['repo_summary']=lambda p,c:self.row(p,dirty_files=2 if p.endswith('other') else 0,remotes_detail=[{'url':f'https://example.invalid/{"other" if p.endswith("other") else "owner"}/repo.git'}])
        state=self.build([str(self.root),str(self.root/'other')]);self.assertEqual(state['totals']['external_repos'],1);self.assertEqual(state['totals']['dirty_repos'],1);self.assertEqual(state['totals']['total_dirty_files'],2)
    def test_registry_controls_owner_classification(self):
        state=self.build(['/authored/one'],registry_paths=['/authored/one']);self.assertTrue(state['repos'][0]['governed_by_registry'])
    def test_once_exits_on_whole_state_incomplete(self):
        class App:
            state={'read_complete':False,'read_errors':['root unavailable'],'repos':[{'safe_commit':90}],'totals':{'repos':1,'unknown_repos':0}};config={};registry_paths=[];registry_authority=False;outdir='/authored/out'
            def __init__(self,*a,**kw):pass
            def rescan(self):return self.state
        self.s['FleetApp']=App;self.assertEqual(self.run_cli(self.args())[0],2)
    def test_once_valid_and_threshold_preserved(self):
        p=self.registry({'repos':['/authored/one']})
        self.assertEqual(self.run_cli(self.args(repos_file=p))[0],0)
        self.assertEqual(self.run_cli(self.args(repos_file=p,fail_under=95))[0],1)
    def runtime(self,*,bind_error=None,start_error=None,serve_error=KeyboardInterrupt()):
        calls=[];owner=self
        class Event:
            stopped=False
            def is_set(self):return self.stopped
            def set(self):self.stopped=True;calls.append('stop')
            def wait(self,n):self.stopped=True
        event=Event()
        class Thread:
            def __init__(self,target,**kw):self.target=target
            def start(self):
                calls.append('start')
                if start_error:raise start_error
            def join(self,timeout=None):calls.append(('join',timeout))
        class Server:
            server_port=4567
            def __init__(self,*a):
                if bind_error:raise bind_error
            def serve_forever(self):raise serve_error
            def shutdown(self):calls.append('shutdown')
            def server_close(self):calls.append('close')
        self.s['threading']=types.SimpleNamespace(Event=lambda:event,Thread=Thread,Lock=threading.Lock)
        self.s['ThreadingHTTPServer']=Server;self.s['make_fleet_handler']=lambda app:None
        self.s['time']=types.SimpleNamespace(sleep=lambda n:(_ for _ in ()).throw(KeyboardInterrupt()))
        return calls,event
    def test_runtime_closes_owned_server_and_joins_worker(self):
        calls,event=self.runtime();self.run_cli(self.args(once=False,no_server=False));self.assertTrue(event.stopped);self.assertIn('close',calls);self.assertIn(('join',2),calls)
    def test_runtime_startup_interrupt_still_cleans_worker(self):
        calls,event=self.runtime(bind_error=KeyboardInterrupt())
        try:self.run_cli(self.args(once=False,no_server=False))
        except KeyboardInterrupt:pass
        self.assertTrue(event.stopped);self.assertIn(('join',2),calls)
    def test_runtime_worker_start_failure_sets_stop(self):
        calls,event=self.runtime(start_error=RuntimeError('authored start failure'))
        with self.assertRaises(RuntimeError):self.run_cli(self.args(once=False))
        self.assertTrue(event.stopped)
    def test_runtime_no_server_and_bind_failure_have_owned_cleanup(self):
        for no_server in [True,False]:
            with self.subTest(no_server=no_server):
                calls,event=self.runtime(bind_error=OSError('authored occupied'));self.run_cli(self.args(once=False,no_server=no_server));self.assertTrue(event.stopped);self.assertIn(('join',2),calls)
    def handler(self,path,host='127.0.0.1:4567',origin=None):
        calls=[];app=types.SimpleNamespace(port=4567,interval=4,get_state=lambda:calls.append('fleet') or {'repos':[]},repo_state=lambda p:calls.append(p) or {'path':p})
        H=self.s['make_fleet_handler'](app);h=H.__new__(H);h.path=path;h.headers={'Host':host};h.server=types.SimpleNamespace(server_port=4567)
        if origin is not None:h.headers['Origin']=origin
        sent=[];h._send=lambda *a:sent.append(a);h.do_GET();return sent,calls
    def test_handler_exact_endpoints_and_query(self):
        self.assertEqual(self.handler('/api/fleet')[0][0][0],200)
        self.assertEqual(self.handler('/api/repo?path=%2Fauthored%2Fone')[1],['/authored/one'])
        for path in ['/api/fleet-extra','/api/repository','/else']:
            with self.subTest(path=path):self.assertEqual(self.handler(path)[0][0][0],404)
    def test_handler_refuses_nonlocal_host_and_origin_without_read(self):
        for host,origin in [('attacker.invalid:4567',None),('127.0.0.1:4567','https://attacker.invalid')]:
            with self.subTest(host=host,origin=origin):
                sent,calls=self.handler('/api/fleet',host,origin);self.assertEqual(sent[0][0],403);self.assertEqual(calls,[])
    def test_html_embedding_preserves_untrusted_text_as_data(self):
        content='</script><b>authored</b>__PORT__';doc=self.s['render_fleet_html']({'root':content,'totals':{'repos':1},'repos':[]},4567,4)
        script=re.search(r'const EMBEDDED=(.*?);const PORT=',doc).group(1);self.assertEqual(json.loads(script)['root'],content)
    def test_authored_walk_reports_os_errors(self):
        s=extract()
        def walk(root,**kw):
            if kw.get('onerror'):kw['onerror'](PermissionError('authored subtree denied'))
            return iter([])
        s['os'].walk=walk
        for name in ['discover_repos','discover_all_git']:
            with self.subTest(name=name),self.assertRaises(OSError):s[name](str(self.root))
    def test_authored_walk_depth_and_nested_rules(self):
        for name in ['discover_repos','discover_all_git']:
            s=extract();root=str(self.root);seen=[]
            def walk(path,**kw):
                a=['.git','child','node_modules'];yield root,a,[];seen.append(list(a))
                b=['.git','nested'];yield root+'/child',b,[];seen.append(list(b))
                if b:yield root+'/child/nested',['.git'],[]
                yield root+'/far/deep/outside',['.git'],[]
            s['os'].walk=walk;paths=s[name](root,max_depth=2)
            self.assertEqual(paths,[root,root+'/child']+([root+'/child/nested'] if name=='discover_all_git' else []));self.assertNotIn('node_modules',seen[0])

    def test_loader_regular_file_admission_and_path_whitespace(self):
        with self.assertRaises((OSError,ValueError)):self.s['load_registry_repo_paths'](str(self.root))
        self.assertEqual(self.s['load_registry_repo_paths'](self.registry({'repos':[' /legal space ','/two']})),[os.path.abspath(' /legal space '),'/two'])
    def test_relative_pins_select_from_fleet_root(self):
        d=self.root/'.git-real';d.mkdir();(d/'fleet.json').write_text('{"repos":["child"]}')
        child=self.root/'child';child.mkdir();(child/'.git').write_text('authored marker, not a Git repository')
        isolated=extract();isolated['os'].walk=lambda *a,**k:iter([])
        self.s['discover_repos']=isolated['discover_repos']
        self.assertEqual(self.run_cli(self.args())[0],0)
        state=json.loads((d/'git-real-fleet.json').read_text());self.assertEqual([r['path'] for r in state['repos']],[str(child)])
    def test_discovery_success_after_failure_recovers(self):
        app=self.app(registry_paths=['/authored/one']);app.config['quick']=True
        original=self.s['registry_fleet_paths'];self.s['registry_fleet_paths']=lambda *a,**k:(_ for _ in ()).throw(OSError('authored denial'))
        self.assertFalse(app.rescan()['read_complete']);self.s['registry_fleet_paths']=original;self.assertTrue(app.rescan()['read_complete'])
    def test_hook_metadata_failure_is_unknown_without_fallback_probe(self):
        for replies in [[('',128,'authored config refusal')],[('',1,''),('',128,'authored resolution refusal')]]:
            with self.subTest(replies=replies):
                s=extract();calls=[];responses=iter(replies)
                class Repo:
                    def __init__(self,path):pass
                    def _run(self,*args):calls.append(args);return next(responses)
                s['GitRepo']=Repo;r=s['_hook_verdict']('/authored/one');self.assertFalse(r['read_complete']);self.assertIsNone(r['pre_commit']);self.assertTrue(r['read_errors']);self.assertEqual(len(calls),len(replies))
    def test_hook_metadata_valid_unset_and_configured_paths(self):
        for configured in [False,True]:
            with self.subTest(configured=configured):
                s=extract();hooks=self.root/'hooks';hooks.mkdir(exist_ok=True);p=hooks/'pre-commit';p.write_text('authored inert text');p.chmod(0o700)
                replies=iter([('hooks',0,'') if configured else ('',1,''),(str(hooks),0,'')])
                class Repo:
                    def __init__(self,path):pass
                    def _run(self,*a):return next(replies)
                s['GitRepo']=Repo;r=s['_hook_verdict'](str(self.root));self.assertTrue(r['read_complete']);self.assertTrue(r['pre_commit']);self.assertFalse(r['pre_push'])
    def test_exact_mcp_discovery_exception_uses_incomplete_shape(self):
        path=MCP_SOURCE;tree=ast.parse(path.read_text());n=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='get_fleet')
        for error in [PermissionError('authored inaccessible'),ValueError('authored invalid')]:
            with self.subTest(error=error):
                engine=types.SimpleNamespace(SCHEMA_VERSION=2,discover_repos=lambda *a:(_ for _ in ()).throw(error),build_fleet_state=lambda *a,**k:self.fail('No build after discovery failure'))
                scope={'gitreal':engine,'_abs':lambda p:p,'_adapter_current':lambda:True,'os':self.s['os'],'_CFG':{}}
                exec(compile(ast.Module(body=[n],type_ignores=[]),str(path),'exec'),scope);r=scope['get_fleet'](str(self.root));self.assertIs(r['read_complete'],False);self.assertEqual(r['repos'],[]);self.assertTrue(r['read_errors'])
    def test_exact_mcp_empty_registry_does_not_fall_back(self):
        path=MCP_SOURCE;tree=ast.parse(path.read_text());n=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='get_fleet')
        p=self.root/'governance/generated/REPOSITORY_FLEET.json';p.parent.mkdir(parents=True);p.write_text('{"repos":[]}')
        engine=types.SimpleNamespace(SCHEMA_VERSION=2,discover_repos=lambda *a:self.fail('No fallback'),load_registry_repo_paths=self.s['load_registry_repo_paths'],registry_fleet_paths=lambda *a:{'present':[]},build_fleet_state=self.s['build_fleet_state'])
        scope={'gitreal':engine,'_abs':lambda p:p,'_adapter_current':lambda:True,'os':self.s['os'],'_CFG':{}}
        exec(compile(ast.Module(body=[n],type_ignores=[]),str(path),'exec'),scope);r=scope['get_fleet'](str(self.root));self.assertIs(r['read_complete'],False);self.assertEqual(r['repos'],[])
    def test_handler_localhost_and_same_origin_admitted(self):
        sent,calls=self.handler('/api/fleet','localhost:4567','http://localhost:4567');self.assertEqual(sent[0][0],200);self.assertEqual(calls,['fleet'])

    def test_malformed_projection_does_not_use_secondary_repos_key(self):
        with self.assertRaises(ValueError):self.s['load_registry_repo_paths'](self.registry({'repositories':None,'repos':['/authored/one']}))
    def test_dangling_ignore_symlink_preserved_without_creating_target(self):
        out=self.root/'.git-real';out.mkdir();target=self.root/'authored-missing-target';(out/'.gitignore').symlink_to(target)
        self.app();self.assertTrue((out/'.gitignore').is_symlink());self.assertFalse(target.exists())

if __name__=='__main__':unittest.main()
