"""Pure release admission with neutral authored inputs; scanner code never loaded."""
from __future__ import annotations
import ast,contextlib,io,json,os,socket,subprocess,sys,tempfile,threading,types,unittest
from pathlib import Path
from unittest.mock import patch
SOURCE=Path(__file__).resolve().parents[1]/'scripts/release_check.py'

class ReleaseAdmissionBoundaries(unittest.TestCase):
    def setUp(self):
        targets=[(subprocess,n) for n in ('Popen','run','call','check_call','check_output','getoutput','getstatusoutput')]
        targets += [(os,n) for n in dir(os) if n.startswith(('exec','spawn','posix_spawn')) or n in {'system','popen','fork','forkpty','kill','killpg','abort','_exit','startfile'}]
        targets += [(socket.socket,n) for n in ('connect','connect_ex','bind','listen')]+[(threading.Thread,'start')]
        for obj,name in targets:
            p=patch.object(obj,name,side_effect=AssertionError('Native effect denied'));p.start();self.addCleanup(p.stop)
        actual=dict(os.environ);self.addCleanup(lambda:self.assertEqual(actual,dict(os.environ)))
        area=tempfile.TemporaryDirectory(prefix='release-admission-authored-');self.addCleanup(area.cleanup);self.area=Path(area.name);self.root=self.area/'public';self.root.mkdir();self.private=self.area/'comparison';self.private.mkdir();self.calls=[]
        allowed={'run','verify_engine_parity','verify_fresh_self_state'}
        nodes=[ast.ImportFrom(module='__future__',names=[ast.alias(name='annotations')],level=0)]
        nodes += [n for n in ast.parse(SOURCE.read_text()).body if isinstance(n,ast.FunctionDef) and n.name in allowed]
        self.env=types.SimpleNamespace(environ={});self.process=types.SimpleNamespace(run=lambda *a,**kw:self.fail('Unconfigured inert process'),TimeoutExpired=subprocess.TimeoutExpired)
        self.s={'Path':Path,'ROOT':self.root,'os':self.env,'subprocess':self.process,'sys':types.SimpleNamespace(executable='authored-python'),'json':json}
        exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),str(SOURCE),'exec'),self.s)
        self.run_function=self.s['run'];self.s['run']=lambda command:self.calls.append(command) or (0,json.dumps(self.state()))
    def state(self):return {'version':'1.3.1','schema_version':2,'root':str(self.root),'is_repo':True,'read_complete':True,'read_errors':[],'actions':{'commit_index':{'operation':'commit_index','safe':False,'decision':'BLOCK'}}}
    def verify(self,state):
        self.s['run']=lambda command:self.calls.append(command) or (0,json.dumps(state));errors=[];out=io.StringIO()
        with contextlib.redirect_stdout(out):self.s['verify_fresh_self_state'](errors)
        return errors,out.getvalue()
    def parity(self):
        errors=[];out=io.StringIO()
        with contextlib.redirect_stdout(out):self.s['verify_engine_parity'](errors)
        return errors,out.getvalue()
    def files(self):
        for root in [self.root,self.private]:
            for name in ['gitreal.py','gitreal_mcp.py']:(root/name).write_bytes(b'authored neutral runtime\n')
        self.env.environ['GIT_REAL_PRIVATE_SOURCE']=str(self.private)
    def test_valid_blocked_and_allowed_actions_are_contracts_not_permission(self):
        for safe,decision in [(False,'BLOCK'),(True,'ALLOW')]:
            with self.subTest(safe=safe):
                state=self.state();state['actions']['commit_index'].update(safe=safe,decision=decision);errors,_=self.verify(state);self.assertEqual(errors,[])
    def test_nonobject_json_reports_failure_without_exception(self):
        for state in [None,[],4,True,'authored']:
            with self.subTest(state=state):self.assertTrue(self.verify(state)[0])
    def test_nested_action_shapes_report_failure_without_exception(self):
        for actions in [[],['authored'],4,True,'authored',{'commit_index':None},{'commit_index':[]},{'commit_index':'authored'}]:
            with self.subTest(actions=actions):
                state=self.state();state['actions']=actions;self.assertTrue(self.verify(state)[0])
    def test_read_errors_must_be_present_empty_list(self):
        for value in [None,False,'',{},['authored incomplete']]:
            with self.subTest(value=value):
                state=self.state();state['read_errors']=value;self.assertTrue(self.verify(state)[0])
        state=self.state();state.pop('read_errors');self.assertTrue(self.verify(state)[0])
    def test_missing_root_is_not_implicitly_current_directory(self):
        # Model a child launched with cwd=ROOT without mutating process cwd.
        self.s['Path']=lambda value:self.root if value in ('','.') else Path(value)
        state=self.state();state.pop('root');self.assertTrue(self.verify(state)[0])
    def test_root_must_be_explicit_absolute_string(self):
        for value in [None,False,4,[],'.']:
            with self.subTest(value=value):
                state=self.state();state['root']=value;self.assertTrue(self.verify(state)[0])
    def test_action_requires_safe_decision_consistency(self):
        for action in [{'operation':'commit_index'},{'operation':'commit_index','safe':True,'decision':'BLOCK'},{'operation':'commit_index','safe':False,'decision':'ALLOW'},{'operation':'commit_index','safe':1,'decision':'ALLOW'},{'operation':'other','safe':False,'decision':'BLOCK'}]:
            with self.subTest(action=action):
                state=self.state();state['actions']['commit_index']=action;self.assertTrue(self.verify(state)[0])
    def test_root_resolution_error_is_reported(self):
        class BadPath:
            def is_absolute(self):return True
            def resolve(self):raise OSError('authored inaccessible root')
        self.s['Path']=lambda value:BadPath();self.assertTrue(self.verify(self.state())[0])
    def test_version_schema_repository_and_read_completeness_refused(self):
        for key,value in [('version','old'),('schema_version',1),('is_repo',False),('read_complete',False),('root',str(self.private))]:
            with self.subTest(key=key):
                state=self.state();state[key]=value;self.assertTrue(self.verify(state)[0])
    def test_child_error_and_nonjson_are_reported(self):
        for code,output in [(1,'authored child failure'),(0,'authored not JSON')]:
            with self.subTest(code=code):
                self.s['run']=lambda command:(code,output);errors=[];self.s['verify_fresh_self_state'](errors);self.assertTrue(errors)
    def test_fresh_command_is_observed_without_execution(self):
        self.verify(self.state());self.assertEqual(self.calls,[['authored-python','gitreal.py','.','--quick','--json']])
    def test_optional_parity_is_unverified_without_comparison_source(self):
        self.s['Path']=lambda value:self.fail('No source should be opened when unconfigured');self.assertEqual(self.parity()[0],[])
    def test_exact_authored_runtime_parity_and_drift(self):
        self.files();self.assertEqual(self.parity()[0],[]);(self.private/'gitreal_mcp.py').write_bytes(b'authored different runtime\n');errors,_=self.parity();self.assertEqual(len(errors),1);self.assertIn('gitreal_mcp.py',errors[0])
    def test_missing_private_runtime_is_reported(self):
        self.files();(self.private/'gitreal_mcp.py').unlink();self.assertTrue(self.parity()[0])
    def test_nonfile_public_runtime_is_reported(self):
        self.files();(self.root/'gitreal.py').unlink();(self.root/'gitreal.py').mkdir();self.assertTrue(self.parity()[0])
    def test_absent_comparison_directory_is_reported(self):
        self.env.environ['GIT_REAL_PRIVATE_SOURCE']=str(self.area/'absent');self.assertTrue(self.parity()[0])
    def test_unresolvable_comparison_source_is_reported(self):
        class BadPath:
            def expanduser(self):return self
            def resolve(self):raise RuntimeError('authored unresolved source')
        self.env.environ['GIT_REAL_PRIVATE_SOURCE']='authored-source';self.s['Path']=lambda value:BadPath();self.assertTrue(self.parity()[0])
    def test_both_unavailable_runtime_files_are_reported(self):
        self.env.environ['GIT_REAL_PRIVATE_SOURCE']=str(self.private);errors,_=self.parity();self.assertEqual(len(errors),2);self.assertIn('gitreal.py',errors[0]);self.assertIn('gitreal_mcp.py',errors[1])
    def test_run_preserves_code_output_and_bounded_command_contract(self):
        seen=[];self.process.run=lambda *a,**kw:seen.append((a,kw)) or types.SimpleNamespace(returncode=7,stdout='authored output\n',stderr='authored diagnostic')
        self.assertEqual(self.run_function(['authored-command']),(7,'authored output\nauthored diagnostic'));self.assertEqual(seen[0][1]['timeout'],240);self.assertEqual(seen[0][1]['cwd'],str(self.root));self.assertIs(seen[0][1]['check'],False)
    def test_run_reports_os_timeout_and_decode_failures(self):
        for error in [OSError('authored unavailable'),subprocess.TimeoutExpired(['authored-command'],240),UnicodeDecodeError('utf-8',b'\xff',0,1,'authored decode failure')]:
            with self.subTest(error=type(error).__name__):
                self.process.run=lambda *a,**kw:(_ for _ in ()).throw(error);code,output=self.run_function(['authored-command']);self.assertNotEqual(code,0);self.assertTrue(output)

if __name__=='__main__':unittest.main()
