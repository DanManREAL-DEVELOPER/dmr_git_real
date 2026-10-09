"""Ordinary dashboard handler with authored HTTP messages and no listening server."""
from __future__ import annotations
import ast,html,http.server,io,json,os,socket,subprocess,threading,types,unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch
SOURCE=Path(__file__).resolve().parents[1]/'gitreal.py'

class PublicHttpHandlerBoundaries(unittest.TestCase):
    def setUp(self):
        targets=[(subprocess,n) for n in ('Popen','run','call','check_call','check_output','getoutput','getstatusoutput')]
        targets += [(os,n) for n in dir(os) if n.startswith(('exec','spawn','posix_spawn')) or n in {'system','popen','fork','forkpty','kill','killpg','abort','_exit','startfile'}]
        targets += [(socket.socket,n) for n in ('connect','connect_ex','bind','listen')]+[(threading.Thread,'start')]
        for obj,name in targets:
            p=patch.object(obj,name,side_effect=AssertionError('Native effect denied'));p.start();self.addCleanup(p.stop)
        actual=dict(os.environ);self.addCleanup(lambda:self.assertEqual(actual,dict(os.environ)))
        tree=ast.parse(SOURCE.read_text());n=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='make_handler')
        self.calls=[];self.render=[];self.state={'root':'/authored/A&B','schema_version':2,'read_complete':False,'read_errors':['authored incomplete']}
        self.app=types.SimpleNamespace(port=0,interval=4,get_state=lambda:self.calls.append('read') or self.state)
        def render(state,port,interval):self.render.append((state,port,interval));return 'authored HTML'
        scope={'http':http,'App':object,'json':json,'render_html':render}
        exec(compile(ast.Module(body=[n],type_ignores=[]),str(SOURCE),'exec'),scope);self.H=scope['make_handler'](self.app)
    def request(self,path='/api/state',headers=None,port=4567):
        h=self.H.__new__(self.H);h.path=path;h.headers=Message();h.server=types.SimpleNamespace(server_port=port)
        for k,v in ([('Host','127.0.0.1:4567')] if headers is None else headers):h.headers[k]=v
        result=[];h._send=lambda *args:result.append(args);h.do_GET();return result[0]
    def refused(self,*args,**kwargs):
        count=len(self.calls);r=self.request(*args,**kwargs);self.assertIn(r[0],(400,403,404));self.assertEqual(len(self.calls),count)
    def test_exact_state_route_and_query_preserve_json(self):
        for path in ['/api/state','/api/state?request=authored']:
            with self.subTest(path=path):
                r=self.request(path);self.assertEqual(r[0],200);self.assertEqual(json.loads(r[1]),self.state)
    def test_html_routes_use_owned_server_port(self):
        for path in ['/','/index.html','/?v=1','/index.html?v=1']:
            with self.subTest(path=path):
                r=self.request(path);self.assertEqual(r,(200,'authored HTML','text/html; charset=utf-8'));self.assertEqual(self.render[-1],(self.state,4567,4))
    def test_prefix_and_unknown_paths_refused_before_state_read(self):
        for path in ['/api/state-extra','/api/state/','/api/states','/api/repo','/else']:
            with self.subTest(path=path):self.refused(path)
    def test_missing_empty_and_duplicate_host_refused(self):
        for headers in [[],[('Host','')],[('Host','127.0.0.1:4567'),('Host','127.0.0.1:4567')],[('Host','127.0.0.1:4567'),('Host','attacker.invalid')]]:
            with self.subTest(headers=headers):self.refused(headers=headers)
    def test_nonlocal_malformed_and_wrong_port_hosts_refused(self):
        for host in ['attacker.invalid:4567','127.0.0.1.attacker.invalid:4567','127.0.0.1:4568','localhost','localhost:4567@example.invalid','http://localhost:4567','[::1]:4567','127.0.0.1:4567,attacker.invalid']:
            with self.subTest(host=host):self.refused(headers=[('Host',host)])
    def test_local_host_and_ordinary_client_without_origin_admitted(self):
        for host in ['127.0.0.1:4567','localhost:4567','LOCALHOST:4567']:
            with self.subTest(host=host):self.assertEqual(self.request(headers=[('Host',host)])[0],200)
    def test_local_origin_admitted(self):
        for origin in ['http://127.0.0.1:4567','http://localhost:4567']:
            with self.subTest(origin=origin):self.assertEqual(self.request(headers=[('Host','localhost:4567'),('Origin',origin)])[0],200)
    def test_foreign_null_empty_wrong_port_and_duplicate_origins_refused(self):
        for values in [['https://attacker.invalid'],['null'],[''],['http://localhost:4568'],['http://localhost:4567/path'],['http://localhost:4567','http://localhost:4567']]:
            with self.subTest(values=values):self.refused(headers=[('Host','localhost:4567')]+[('Origin',v) for v in values])
    def test_http_default_port_hosts_and_origins(self):
        for host in ['localhost','127.0.0.1','localhost:80']:
            with self.subTest(host=host):self.assertEqual(self.request(headers=[('Host',host),('Origin','http://localhost')],port=80)[0],200)
    def test_absolute_fragment_and_malformed_targets_refused(self):
        for path in ['http://localhost:4567/api/state','//localhost:4567/api/state','http://[','/api/state#fragment']:
            with self.subTest(path=path):self.refused(path)
    def test_send_is_no_store_with_correct_utf8_length(self):
        h=self.H.__new__(self.H);responses=[];headers=[];h.send_response=lambda code:responses.append(code);h.send_header=lambda *args:headers.append(args);h.end_headers=lambda:None;h.wfile=io.BytesIO()
        h._send(200,'authored café');self.assertEqual(responses,[200]);self.assertIn(('Cache-Control','no-store'),headers);self.assertIn(('Content-Length',str(len('authored café'.encode()))),headers);self.assertEqual(h.wfile.getvalue(),'authored café'.encode())
    def test_no_mutating_http_methods_added(self):
        for name in ['do_POST','do_PUT','do_PATCH','do_DELETE']:self.assertFalse(hasattr(self.H,name))

if __name__=='__main__':unittest.main()
