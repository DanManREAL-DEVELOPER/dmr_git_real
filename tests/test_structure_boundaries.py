"""Authored tiny-tree checks; no release tree, Git, governance child or scanner."""
from __future__ import annotations
import argparse,ast,contextlib,hashlib,io,json,os,stat,sys,tempfile,types,unittest
from pathlib import Path

SOURCE=Path(__file__).resolve().parents[1]/'scripts/check_structure.py'

def deny(*args,**kwargs):
    raise AssertionError('Native child execution is not admitted')

def audit(event,args):
    if event in {'subprocess.Popen','os.system','os.exec','os.posix_spawn','os.fork','socket.__new__','socket.connect','socket.bind'}:
        raise AssertionError('Forbidden native effect: '+event)
if __name__ == "__main__":
    sys.addaudithook(audit)

def load(source,root):
    tree=ast.parse(source.read_text())
    selected=[ast.ImportFrom(module='__future__',names=[ast.alias(name='annotations')],level=0)]
    selected.extend(n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) or (isinstance(n,ast.Assign) and all(isinstance(t,ast.Name) and t.id in {'REQUIRED','FORBIDDEN_LAYOUT_DIRS','FORBIDDEN_FILES','LOCAL_ROOT_DIRS','MAX_ENTRIES','MAX_DEPTH','MAX_FAILURES'} for t in n.targets)))
    facade=types.SimpleNamespace(scandir=os.scandir,path=os.path)
    ns={'__name__':'inert_structure','ROOT':root,'Path':Path,'os':facade,'stat':stat,'subprocess':types.SimpleNamespace(run=deny),'MAX_ENTRIES':50000,'MAX_DEPTH':64,'MAX_FAILURES':100}
    exec(compile(ast.fix_missing_locations(ast.Module(selected,[])),str(source),'exec'),ns)
    return ns

class StructureBoundaries(unittest.TestCase):
    source=SOURCE
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='structure-authored-'); self.base=Path(self.temp.name); self.root=self.base/'package';self.root.mkdir()
        self.ns=load(self.source,self.root)
        for name in self.ns['REQUIRED']:
            path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('# authored empty package fixture\n')
    def tearDown(self):self.temp.cleanup()
    def run_main(self):
        output=io.StringIO()
        with contextlib.redirect_stdout(output): code=self.ns['main']()
        return code,output.getvalue()
    def test_complete_authored_package(self):
        self.assertEqual(self.run_main(),(0,'GIT_REAL_STRUCTURE_PASS\n'))
    def test_missing_required_file(self):
        (self.root/'README.md').unlink();code,out=self.run_main();self.assertEqual(code,1);self.assertIn('README.md',out)
    def test_required_external_file_link(self):
        external=self.base/'external.py';external.write_text('authored')
        path=self.root/'gitreal.py';path.unlink();path.symlink_to(external)
        code,out=self.run_main();self.assertEqual(code,1);self.assertIn('gitreal.py',out)
    def test_required_internal_file_link(self):
        path=self.root/'README.md';path.unlink();path.symlink_to(self.root/'PRIVACY.md')
        self.assertEqual(self.run_main()[0],0)
    def test_required_external_parent_link(self):
        # Required workflow exists only through an external directory alias.
        path=self.root/'.github/workflows/ci.yml';path.unlink();path.parent.rmdir()
        external=self.base/'workflows';external.mkdir();(external/'ci.yml').write_text('authored')
        path.parent.symlink_to(external,target_is_directory=True)
        self.assertEqual(self.run_main()[0],1)
    def test_dangling_forbidden_layout(self):
        (self.root/'frontend').symlink_to(self.root/'absent',target_is_directory=True)
        code,out=self.run_main();self.assertEqual(code,1);self.assertIn('frontend',out)
    def test_dangling_forbidden_file(self):
        # Filename policy only; no file contents or secret-shaped values.
        (self.root/self.ns['FORBIDDEN_FILES'][0]).symlink_to(self.root/'absent')
        code,out=self.run_main();self.assertEqual(code,1);self.assertIn(self.ns['FORBIDDEN_FILES'][0],out)
    def test_parent_governance_never_invoked(self):
        helper=self.base/'scripts/check_project_governance.sh';helper.parent.mkdir();helper.write_text('# authored inert sibling\n')
        self.assertEqual(self.run_main(),(0,'GIT_REAL_STRUCTURE_PASS\n'))
    def test_package_backup_refused(self):
        path=self.root/'assets'/'retained.pre-parity';path.parent.mkdir();path.write_text('authored')
        code,out=self.run_main();self.assertEqual(code,1);self.assertIn('assets/retained.pre-parity',out)
    def test_local_metadata_backup_excluded(self):
        for dirname in ['.git','.git-real','.project-map','.venv','venv','__pycache__','.pytest_cache']:
            with self.subTest(directory=dirname):
                directory=self.root/dirname;directory.mkdir();(directory/'retained.pre-parity').write_text('authored')
                self.assertEqual(self.run_main()[0],0)
    def test_nested_package_metadata_name_not_excluded(self):
        path=self.root/'assets'/'.project-map'/'retained.pre-parity';path.parent.mkdir(parents=True);path.write_text('authored')
        self.assertEqual(self.run_main()[0],1)
    def test_backup_diagnostic_escapes_newline(self):
        (self.root/'line\nGIT_REAL_STRUCTURE_PASS\nname.pre-parity').write_text('authored')
        code,out=self.run_main();self.assertEqual(code,1)
        self.assertTrue(all(line.startswith('STRUCTURE_FAIL ') for line in out.splitlines()))
    def test_directory_symlink_not_inventory_pass(self):
        external=self.base/'external';external.mkdir();(external/'retained.pre-parity').write_text('authored')
        (self.root/'assets').symlink_to(external,target_is_directory=True)
        code,out=self.run_main();self.assertEqual(code,1);self.assertIn('assets',out)
    def test_missing_root_fails_without_traceback(self):
        self.ns['ROOT']=self.base/'missing'
        self.assertEqual(self.run_main()[0],1)


    def test_required_directory_or_broken_file_fails(self):
        path=self.root/'gitreal.py';path.unlink();path.mkdir()
        self.assertEqual(self.run_main()[0],1)
        path.rmdir();path.symlink_to(self.root/'missing')
        self.assertEqual(self.run_main()[0],1)
    def test_forbidden_existing_entries_retained(self):
        path=self.root/'api';path.write_text('authored neutral fixture')
        obsolete=self.root/self.ns['FORBIDDEN_FILES'][0];obsolete.write_text('authored neutral fixture')
        before=(path.read_bytes(),obsolete.read_bytes()); code,out=self.run_main()
        self.assertEqual(code,1);self.assertIn('api/',out)
        self.assertEqual((path.read_bytes(),obsolete.read_bytes()),before)
    def test_dist_build_and_assets_remain_in_scope(self):
        for name in ['dist','build','assets']:
            with self.subTest(name=name):
                path=self.root/name/'copy.pre-parity';path.parent.mkdir();path.write_text('authored')
                self.assertEqual(self.run_main()[0],1)
                path.unlink();path.parent.rmdir()
    def test_root_only_exclusions_exact(self):
        self.assertEqual(set(self.ns['LOCAL_ROOT_DIRS']),{'.git','.git-real','.project-map','.venv','venv','__pycache__','.pytest_cache'})
        for name in ['.venv-copy','venv-extra','.project-map-copy']:
            path=self.root/name/'copy.pre-parity';path.parent.mkdir();path.write_text('authored')
            code,out=self.run_main();self.assertEqual(code,1);self.assertIn(name,out)
            path.unlink();path.parent.rmdir()
    def test_symlink_directory_never_enumerated(self):
        external=self.base/'external';external.mkdir();(external/'copy.pre-parity').write_text('authored')
        (self.root/'alias').symlink_to(external,target_is_directory=True)
        calls=[]
        def scan(path):
            resolved=Path(path).resolve();resolved.relative_to(self.root);calls.append(resolved)
            return os.scandir(path)
        self.ns['os'].scandir=scan
        self.assertEqual(self.run_main()[0],1)
        self.assertNotIn(external,calls)
    def test_symlink_loop_is_failure_not_traceback(self):
        (self.root/'one').symlink_to('two');(self.root/'two').symlink_to('one')
        self.assertEqual(self.run_main()[0],1)
    def test_unreadable_inventory_is_failure(self):
        def scan(path):raise PermissionError('authored refusal')
        self.ns['os'].scandir=scan;code,out=self.run_main()
        self.assertEqual(code,1);self.assertIn('cannot enumerate',out);self.assertNotIn('GIT_REAL_STRUCTURE_PASS',out)
    def test_partial_iterator_failure_is_failure(self):
        class Interrupted:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def __iter__(self):return self
            def __next__(self):raise OSError('authored interrupted enumeration')
        self.ns['os'].scandir=lambda path:Interrupted()
        code,out=self.run_main();self.assertEqual(code,1);self.assertIn('cannot enumerate',out)
    def test_entry_stat_failure_is_failure(self):
        class Entry:
            name='authored.txt'
            def stat(self,**kwargs):raise PermissionError('authored inaccessible metadata')
        class Entries:
            def __enter__(self):return iter([Entry()])
            def __exit__(self,*args):pass
        self.ns['os'].scandir=lambda path:Entries();code,out=self.run_main()
        self.assertEqual(code,1);self.assertIn('cannot inspect package entry',out)
    def test_entry_and_depth_bounds(self):
        self.ns['MAX_ENTRIES']=1
        code,out=self.run_main();self.assertEqual(code,1);self.assertIn('inspection incomplete',out)
        self.ns['MAX_ENTRIES']=50000;self.ns['MAX_DEPTH']=1
        (self.root/'nested'/'too-deep'/'tail').mkdir(parents=True)
        code,out=self.run_main();self.assertEqual(code,1);self.assertIn('exceeds depth',out)
    def test_failure_reporting_bound(self):
        self.ns['MAX_FAILURES']=2
        for i in range(5):(self.root/f'{i}.pre-parity').write_text('authored')
        code,out=self.run_main();self.assertEqual(code,1)
        self.assertLessEqual(len(out.splitlines()),3);self.assertIn('reporting stopped',out)
    def test_nonregular_metadata_refused_without_open(self):
        class Entry:
            name='authored-pipe'
            def stat(self,**kwargs):return types.SimpleNamespace(st_mode=stat.S_IFIFO)
        class Entries:
            def __enter__(self):return iter([Entry()])
            def __exit__(self,*args):pass
        self.ns['os'].scandir=lambda path:Entries()
        code,out=self.run_main();self.assertEqual(code,1);self.assertIn('nonregular',out)
    def test_local_metadata_alias_not_followed(self):
        external=self.base/'local-state';external.mkdir();(external/'copy.pre-parity').write_text('authored')
        (self.root/'.git-real').symlink_to(external,target_is_directory=True)
        def scan(path):Path(path).resolve().relative_to(self.root);return os.scandir(path)
        self.ns['os'].scandir=scan;self.assertEqual(self.run_main()[0],0)
    def test_plain_root_file_refused(self):
        self.ns['ROOT']=self.root/'README.md';self.assertEqual(self.run_main()[0],1)
    def test_unicode_and_space_package_names(self):
        path=self.root/'assets'/'sp ace café.pre-parity';path.parent.mkdir();path.write_text('authored')
        code,out=self.run_main();self.assertEqual(code,1);self.assertIn('sp ace café.pre-parity',out)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--source',type=Path,default=SOURCE);parser.add_argument('--json',type=Path);args=parser.parse_args();StructureBoundaries.source=args.source
    stream=io.StringIO();outcome=unittest.TextTestRunner(stream=stream,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(StructureBoundaries))
    data={'source':str(args.source),'source_sha256':hashlib.sha256(args.source.read_bytes()).hexdigest(),'test_groups':outcome.testsRun,'failures':len(outcome.failures),'errors':len(outcome.errors),'passed':outcome.wasSuccessful(),'details':stream.getvalue(),'boundary':'Exact AST functions/constants only, ROOT replaced with authored tiny tree. Native process/network APIs denied; no release-tree check, Git, governance child or inherited scanner.'}
    if args.json:args.json.write_text(json.dumps(data,indent=2)+'\n')
    print(json.dumps({k:v for k,v in data.items() if k!='details'},indent=2))
    if not outcome.wasSuccessful():print(stream.getvalue())
    raise SystemExit(0 if outcome.wasSuccessful() else 1)
