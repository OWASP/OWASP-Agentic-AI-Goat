"""Controlled V03 prerequisite admission, process debt and output limits; no Docker/model."""
import contextlib,hashlib,io,json,pathlib,sys,types,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[2]
SOURCE=ROOT/'tests/postgres/run-secureshop-bound-upload-journal-main.py'
def module(text):
 ns={'__name__':'v03_test_only','__file__':str(SOURCE)}
 exec(compile(text,str(SOURCE),'exec'),ns);return ns
class Integration(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.new=module(SOURCE.read_text())
 def plan(self,ns,args):
  out=io.StringIO()
  with contextlib.redirect_stdout(out):self.assertEqual(ns['main'](args),0)
  return out.getvalue()
 def fields(self):
  return {'current-host-profile':'goat-q','node':str(ROOT/'tasks/runtime/node/node_modules/node/bin/node'),
   'node-sha256':'1'*64,'docker':str(ROOT/'tasks/runtime/container/bin/docker'),
   'docker-sha256':'2'*64,'docker-host':'unix://'+str(ROOT/'.qualification/goat-q/docker.sock'),
   'docker-daemon':'test-daemon','image-id':'sha256:'+'3'*64,'evidence-parent':str(ROOT/'tasks/qualification')}
 def argv(self):
  return ['--suite','v03',*[v for k,x in self.fields().items() for v in ('--v03-'+k,x)]]
 def admission(self,deny=False):
  seen=[]
  def validate(**kw):
   seen.append(kw)
   if deny:raise RuntimeError('mock exact authority denied')
  def parent(root,requested):
   self.assertEqual(root,ROOT);self.assertEqual(requested,str(ROOT/'tasks/qualification'))
   return ROOT/'tasks/qualification'
  return types.SimpleNamespace(validate_current_host=validate,evidence_parent=parent),seen
 def test_all_legacy_suite_plans_exact(self):
  for suite in self.new['SUITES']:
   with self.subTest(suite=suite):
    plan=json.loads(self.plan(self.new,['--suite',suite,'--plan']))
    self.assertEqual(plan['fixture'],self.new['SUITES'][suite]['fixture'])
    self.assertEqual(plan['stores'],[s for s,r in self.new['SUITES'][suite]['stores']])
    self.assertEqual(plan['runCommand'],[str(SOURCE),'--suite',suite,'--run'])
    self.assertEqual(plan['dockerHost'],'unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock')
    self.assertEqual(plan['expectedTests'],2)
    for flag in ('actualModel','browser','judgeOrCredit','sourceCopies'):self.assertFalse(plan[flag])
 def test_current_plan_exact_forwarding_roundtrip(self):
  helper,seen=self.admission()
  with patch.dict(sys.modules,{'secureshop_current_host_admission':helper}),patch('subprocess.Popen',side_effect=AssertionError('no allocation')),patch('subprocess.run',side_effect=AssertionError('no unmocked probe')):
   result=json.loads(self.plan(self.new,self.argv()+['--plan']))
  f=self.fields();self.assertEqual(seen,[dict(workspace=ROOT,profile=f['current-host-profile'],docker_host=f['docker-host'],node=f['node'],node_sha256=f['node-sha256'],docker=f['docker'],docker_sha256=f['docker-sha256'],daemon_id=f['docker-daemon'],image_id=f['image-id'])])
  self.assertEqual(result['dockerHost'],f['docker-host']);self.assertEqual(result['dockerBinary'],f['docker'])
  self.assertEqual(result['daemonId'],f['docker-daemon']);self.assertEqual(result['postgresImage'],f['image-id'])
  parsed=self.new['arguments'](result['runCommand'][1:])
  for k,v in f.items():self.assertEqual(getattr(parsed,'v03_'+k.replace('-','_')),v)
  self.assertTrue(parsed.run);self.assertEqual(result['expectedTests'],2)
  self.assertEqual(result['stores'],['AGENTS_FRESH','AGENTS_POPULATED','REVIEW_FRESH','REVIEW_POPULATED'])
  for k in ['sourceCopies','actualModel','browser','judgeOrCredit','actualNetworkEffects']:self.assertFalse(result[k])
 def test_partial_each_field_rejected(self):
  for key in self.fields():
   a=self.argv();at=a.index('--v03-'+key);del a[at:at+2]
   with self.subTest(key=key),contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):self.new['arguments'](a+['--plan'])
 def test_wrong_suite_rejected(self):
  for suite in self.new['SUITES']:
   if suite=='v03':continue
   a=self.argv();a[1]=suite
   with self.subTest(suite=suite),contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):self.new['arguments'](a+['--plan'])
 def test_mixed_polyglot_rejected(self):
  with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):self.new['arguments'](self.argv()+['--upload-polyglot','--plan'])
 def test_invalid_authority_propagates(self):
  helper,seen=self.admission(True)
  with patch.dict(sys.modules,{'secureshop_current_host_admission':helper}),self.assertRaisesRegex(RuntimeError,'authority denied'):
   self.plan(self.new,self.argv()+['--plan'])
  self.assertEqual(len(seen),1)
 def test_live_closed_before_allocation(self):
  helper,seen=self.admission()
  with patch.dict(self.new,{'V03_CURRENT_HOST_LIVE':False}),patch.dict(sys.modules,{'secureshop_current_host_admission':helper}),patch('subprocess.Popen',side_effect=AssertionError('allocation')),patch('tempfile.mkdtemp',side_effect=AssertionError('directory allocation')),self.assertRaisesRegex(RuntimeError,'live admission remains closed'):
   self.new['main'](self.argv()+['--run'])
 def test_enabled_gate_requires_explicit_admission_before_allocation(self):
  self.assertTrue(self.new['V03_CURRENT_HOST_LIVE'])
  helper,seen=self.admission()
  with patch.dict(sys.modules,{'secureshop_current_host_admission':helper}),patch('subprocess.Popen',side_effect=AssertionError('allocation')),patch('tempfile.mkdtemp',side_effect=AssertionError('directory allocation')),self.assertRaisesRegex(RuntimeError,'Explicit V03 prerequisite admission required'):
   self.new['main'](self.argv()+['--run'])


import ast,hashlib,json,os,pathlib,signal,subprocess,sys,tempfile,textwrap,time,types,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[2]
class Controls(unittest.TestCase):
 def run_case(self,mode,check=True):
  actual=SOURCE.read_text()
  nodes=[n for n in ast.walk(ast.parse(actual)) if isinstance(n,ast.FunctionDef) and n.name=='owned_call']
  self.assertEqual(len(nodes),1)
  code=textwrap.dedent(ast.get_source_segment(actual,nodes[0]))
  with tempfile.TemporaryDirectory(dir=ROOT/'tasks/tmp',prefix='v03-review-') as directory:
   evidence=pathlib.Path(directory);records=[];signals=[];identity_calls=[];spawns=[]
   live=mode in ('unknown_live','changed','timeout','kill_failure','group_failure')
   class Child:
    pid=12345
    returncode=None if live else (2 if mode=='nonzero' else 0)
    def poll(self):return self.returncode
    def wait(self,timeout):
     if self.returncode is None:raise subprocess.TimeoutExpired(['mock'],timeout)
     return self.returncode
   child=Child()
   def spawn(command,**kw):
    spawns.append(command)
    if mode=='late_work':lease.work_end=time.monotonic()-1
    if mode=='spawn_failure':raise OSError('mock spawn')
    kw['stdout'].write(b'x'*(8*1024*1024+1) if mode=='overflow' else b'ok')
    kw['stdout'].flush();return child
   def identity(pid):
    identity_calls.append(pid)
    if mode in ('fast','unknown_live'):return None
    tick=2 if mode=='changed' and len(identity_calls)>1 else 1
    return types.SimpleNamespace(pid=pid,ppid=1,pgid=pid,uid=os.getuid(),start_sec=tick,start_usec=1)
   def groups(pid):
    if mode=='group_failure':raise OSError('mock inventory')
    return [pid] if child.returncode is None else []
   def kill(pid,sig):
    signals.append((pid,sig))
    if mode=='kill_failure':raise PermissionError('mock kill')
    child.returncode=-sig
   def writer(path,value):
    if path.name.endswith('-terminal.json') and mode=='writer_failure':raise OSError('mock writer')
    path.write_text(json.dumps({} if path.name.endswith('-terminal.json') and mode=='readback_failure' else value))
   def sha(path):
    if mode=='hash_failure' and path.name.endswith('-terminal.json'):raise OSError('mock hash')
    return hashlib.sha256(path.read_bytes()).hexdigest()
   lease=module(actual)['V03Lease']()
   def wrapped(command,*args):
    if mode=='slow_hash':lease.work_end=time.monotonic()-1
    return command
   def open_log(p):
    if mode=='slow_open':lease.work_end=time.monotonic()-1
    return p.open('xb')
   ns=dict(lease=lease,executables={},python_pin=(),wrapper_pin='pin',v03_wrapped=wrapped,private_json=writer,ROOT=ROOT,evidence=evidence,owned_records=records,env={},time=time,json=json,hashlib=hashlib,sha=sha,signal=signal,
    os=types.SimpleNamespace(killpg=kill),subprocess=types.SimpleNamespace(Popen=spawn,DEVNULL=subprocess.DEVNULL,TimeoutExpired=subprocess.TimeoutExpired,CompletedProcess=subprocess.CompletedProcess),
    lifecycle=types.SimpleNamespace(helpers=types.SimpleNamespace(open_private_log=open_log,write_private_json=writer)))
   fake=types.SimpleNamespace(LibProc=lambda:types.SimpleNamespace(identity=identity,group_pids=groups))
   with patch.dict(sys.modules,{'darwin_process_inventory':fake}):
    exec(code,ns)
    if mode=='fast' or (mode=='nonzero' and not check):ns['owned_call'](['mock'],timeout=0,check=check)
    else:
     with self.assertRaises(RuntimeError):ns['owned_call'](['mock'],timeout=0,check=check)
   row=records[0]
   if mode in ('slow_hash','slow_open'):self.assertEqual(spawns,[])
   if mode in ('writer_failure','readback_failure','hash_failure'):
    self.assertTrue(row['evidenceDebt']);self.assertFalse(row['terminalPublished'])
   else:
    terminal=json.loads((evidence/'owned-command-0-terminal.json').read_text())
    self.assertEqual(terminal['overflow'],mode=='overflow')
    if mode=='overflow':self.assertIn('output-limit-exceeded',terminal['errors']);self.assertEqual(terminal['output'][0]['capturedBytes'],8*1024*1024)
    if mode=='nonzero' and check:self.assertIn('nonzero-exit',terminal['errors'])
   if mode in ('fast','unknown_live','changed'):self.assertEqual(signals,[])
   if mode in ('unknown_live','changed','kill_failure','group_failure','writer_failure','readback_failure','hash_failure'):
    self.assertTrue(any(not r['closed'] or not r['groupAbsent'] or r['evidenceDebt'] or not r['terminalPublished'] for r in records))
 def test_fast_exit(self):self.run_case('fast')
 def test_fast_overflow(self):self.run_case('overflow')
 def test_nonzero(self):self.run_case('nonzero')
 def test_readiness_nonzero(self):self.run_case('nonzero',False)
 def test_unknown_live(self):self.run_case('unknown_live')
 def test_changed_identity(self):self.run_case('changed')
 def test_timeout(self):self.run_case('timeout')
 def test_kill_failure(self):self.run_case('kill_failure')
 def test_group_failure(self):self.run_case('group_failure')
 def test_spawn_failure(self):self.run_case('spawn_failure')
 def test_writer_failure(self):self.run_case('writer_failure')
 def test_readback_failure(self):self.run_case('readback_failure')
 def test_hash_failure(self):self.run_case('hash_failure')
 def test_late_work_fast_completion_fails(self):self.run_case('late_work')
 def test_slow_hash_never_spawns_after_deadline(self):self.run_case('slow_hash')
 def test_slow_log_open_never_spawns_after_deadline(self):self.run_case('slow_open')


import hashlib,json,os,pathlib,resource,subprocess,sys,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[2]
WRAPPER=ROOT/'tests/postgres/secureshop_v03_fsize_exec.py'
PYTHON=pathlib.Path(sys.executable).resolve()
PIN=hashlib.sha256(PYTHON.read_bytes()).hexdigest()
class FileSize(unittest.TestCase):
 def run_child(self,code,pin=PIN):
  with tempfile.TemporaryDirectory(dir=ROOT/'tasks/tmp',prefix='v03-fsize-') as tmp:
   p=pathlib.Path(tmp);out=p/'out';err=p/'err'
   before=resource.getrlimit(resource.RLIMIT_FSIZE)
   with out.open('xb') as o,err.open('xb') as e:
    child=subprocess.Popen([str(PYTHON),'-B',str(WRAPPER),pin,'--',str(PYTHON),'-B','-c',code],stdin=subprocess.DEVNULL,stdout=o,stderr=e,start_new_session=True)
    child.wait(timeout=15)
   self.assertEqual(resource.getrlimit(resource.RLIMIT_FSIZE),before)
   return child.pid,child.returncode,out.stat().st_size,err.stat().st_size,out.read_bytes()[:512]
 def test_normal_same_pid_limit_and_parent_unchanged(self):
  pid,code,n,e,raw=self.run_child('import os,resource,json;print(json.dumps([os.getpid(),resource.getrlimit(resource.RLIMIT_FSIZE)]))')
  self.assertEqual(code,0);self.assertEqual(json.loads(raw),[pid,[8388608,8388608]])
 def test_stdout_overflow_hard_bounded(self):
  pid,code,n,e,raw=self.run_child('import os; b=b"x"*1048576\nfor i in range(10): os.write(1,b)')
  self.assertNotEqual(code,0);self.assertLessEqual(n,8388608);self.assertGreater(n,0)
 def test_stderr_overflow_hard_bounded(self):
  pid,code,n,e,raw=self.run_child('import os; b=b"x"*1048576\nfor i in range(10): os.write(2,b)')
  self.assertNotEqual(code,0);self.assertLessEqual(e,8388608);self.assertGreater(e,0)
 def test_wrong_executable_pin_never_executes(self):
  pid,code,n,e,raw=self.run_child('print("SHOULD_NOT_RUN")','0'*64)
  self.assertNotEqual(code,0);self.assertNotIn(b'SHOULD_NOT_RUN',raw)

class Admission(unittest.TestCase):
 def setUp(self):self.ns=module(SOURCE.read_text())
 def test_absolute_phase_reserves_no_renewal(self):
  tick=[10.];lease=self.ns['V03Lease'](lambda:tick[0])
  self.assertEqual(lease.end,1565);self.assertEqual(lease.command(300),300)
  tick[0]=1344;self.assertEqual(lease.command(30),1)
  tick[0]=1345
  with self.assertRaises(RuntimeError):lease.command(1)
  self.assertEqual(lease.retirement(30),20)
  tick[0]=1365;lease.cleanup();self.assertEqual(lease.work_end,1545)
  with self.assertRaises(RuntimeError):lease.cleanup()
  self.assertEqual(lease.work_end,1545)
  tick[0]=1544;self.assertEqual(lease.command(30),1)
  tick[0]=1545
  with self.assertRaises(RuntimeError):lease.command(1)
  self.assertEqual(lease.retirement(30),20)
  tick[0]=1565
  with self.assertRaises(RuntimeError):lease.retirement(1)
  with self.assertRaises(RuntimeError):lease.check()
 def test_command_counts(self):
  lease=self.ns['V03Lease'](lambda:0)
  for _ in range(118):lease.command(1)
  with self.assertRaises(RuntimeError):lease.command(1)
  lease.cleanup()
  for _ in range(6):lease.command(1)
  with self.assertRaises(RuntimeError):lease.command(1)
 def test_packet_exact_private_binding(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'tasks/qualification',prefix='v03-admission-test-') as tmp:
   p=pathlib.Path(tmp)/'admission.json';value={'schema':'test','run':'a'*32}
   p.write_text(json.dumps(value));p.chmod(0o600);pin=hashlib.sha256(p.read_bytes()).hexdigest()
   self.assertEqual(self.ns['v03_packet'](str(p),pin,value),value)
   for expected,digest in [({'schema':'wrong'},pin),(value,'0'*64)]:
    with self.assertRaises(RuntimeError):self.ns['v03_packet'](str(p),digest,expected)
   p.chmod(0o644)
   with self.assertRaises(RuntimeError):self.ns['v03_packet'](str(p),pin,value)
   p.chmod(0o600);link=p.parent/'alias';link.symlink_to(p)
   with self.assertRaises(RuntimeError):self.ns['v03_packet'](str(link),pin,value)
   with self.assertRaises(RuntimeError):self.ns['v03_packet'](str(p.parent/'..'/p.parent.name/p.name),pin,value)
   p.write_bytes(b'x'*65537)
   with self.assertRaises(RuntimeError):self.ns['v03_packet'](str(p),hashlib.sha256(p.read_bytes()).hexdigest(),value)
 def test_original_assertion_titles_counts(self):
  tap='\n'.join('ok '+str(i+1)+' - '+t for i,t in enumerate(self.ns['V03_TITLES']))+'\n# tests 2\n# pass 2\n# fail 0\n# cancelled 0\n# skipped 0\n'
  self.assertEqual(self.ns['v03_assertions'](tap),list(self.ns['V03_TITLES']))
  for altered in (tap.replace('ok 1 - ','ok 1 - WRONG '),tap.replace('# skipped 0','# skipped 1'),tap+'# pass 2\n'):
   with self.assertRaises(RuntimeError):self.ns['v03_assertions'](altered)
 def test_wrapper_forwarding_and_binding_denials(self):
  ns=self.ns;ns['sha']=lambda p:'a'*64;command=['/exact/node','--test','fixture']
  self.assertEqual(ns['v03_wrapped'](command,{'/exact/node':'a'*64},('/physical/python','a'*64),'a'*64),
   ['/physical/python','-B',str(ns['V03_WRAPPER']),'a'*64,'--',*command])
  for executables,python,wrapper in [({},('/physical/python','a'*64),'a'*64),({'/exact/node':'b'*64},('/physical/python','a'*64),'a'*64),({'/exact/node':'a'*64},('/physical/python','b'*64),'a'*64),({'/exact/node':'a'*64},('/physical/python','a'*64),'b'*64)]:
   with self.assertRaises(RuntimeError):ns['v03_wrapped'](command,executables,python,wrapper)
 def test_each_retirement_debt_blocks(self):
  clean={'closed':True,'groupAbsent':True,'terminalPublished':True,'evidenceDebt':False}
  self.assertTrue(self.ns['v03_settled']([clean]))
  for key in clean:
   self.assertFalse(self.ns['v03_settled']([{**clean,key:not clean[key]}]))
 def test_bounded_metadata_before_writer(self):
  source=SOURCE.read_text();node=next(n for n in ast.walk(ast.parse(source)) if isinstance(n,ast.FunctionDef) and n.name=='private_json')
  writes=[];ns={'admitted_parent':ROOT,'V03_LIMITS':{'metadataBytes':16},'json':json,
   'lifecycle':types.SimpleNamespace(helpers=types.SimpleNamespace(write_private_json=lambda *args:writes.append(args)))}
  exec(textwrap.dedent(ast.get_source_segment(source,node)),ns)
  with self.assertRaises(RuntimeError):ns['private_json']('unused',{'large':'x'*16})
  self.assertEqual(writes,[])
 def test_partial_admission_flags(self):
  base=Integration().argv()
  for tail in (['--v03-run-id','a'*32],['--v03-run-id','wrong','--v03-admission','/p','--v03-admission-sha256','a'*64]):
   with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):self.ns['arguments'](base+tail+['--plan'])
 def test_admission_argv_positional_collision_order_duplicates(self):
  ns=self.ns
  command=['launcher','--keep','collision','--v03-admission','collision','--other','digest','--v03-admission-sha256','digest']
  expected=['launcher','--keep','collision','--other','digest']
  self.assertEqual(ns['v03_admission_argv'](command),expected)
  self.assertEqual(ns['v03_admission_argv'](['--v03-admission-sha256','digest',*command[:-2]]),expected)
  with self.assertRaises(RuntimeError):ns['v03_admission_argv'](command+['--v03-admission','collision'])
  with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):ns['arguments'](Integration().argv()+['--v03-node','duplicate','--plan'])

class Composed(unittest.TestCase):
 def run_main(self,mode):
  ns=module(SOURCE.read_text());ns['V03_CURRENT_HOST_LIVE']=True
  tick=[time.monotonic()];lease=ns['V03Lease'](lambda:tick[0]);ns['V03Lease']=lambda:lease
  with tempfile.TemporaryDirectory(dir=ROOT/'tasks/qualification',prefix='v03-composed-') as tmp:
   parent=pathlib.Path(tmp);calls=[];writes=[];owner='a'*32;cid='b'*64;name='owasp-ai-goat-v03-optimize-'+owner[:12]
   args=Integration().argv()+['--v03-run-id',owner,'--v03-admission',str(parent/'admission.json'),'--v03-admission-sha256','a'*64,'--run']
   for flag in ('--v03-node-sha256','--v03-docker-sha256'):args[args.index(flag)+1]='a'*64
   def writer(path,value):
    if mode=='terminal_failure' and path.name.endswith('-terminal.json'):raise OSError('terminal fault')
    if mode=='late_save_downgrade_failure' and path.name=='result.json' and value.get('passed') is False:raise OSError('late downgrade failed')
    path.write_text(json.dumps(value));writes.append(path)
    if mode in ('late_save','late_save_downgrade_failure') and path.name=='result.json' and value.get('passed') is True:tick[0]=lease.end+1
   def environment(evidence,node):
    (evidence/'runtime').mkdir();return {}
   helpers=types.SimpleNamespace(write_private_json=writer,open_private_log=lambda p:p.open('xb'),__file__=str(SOURCE))
   lifecycle=types.SimpleNamespace(helpers=helpers,owned_environment=environment)
   inventory_calls=[]
   def inventory(extra):
    inventory_calls.append(extra)
    return {'fixed':'drift' if mode=='source_drift' and len(inventory_calls)>1 else 'pin'}
   def load(name,path):
    if name=='bound_upload_lifecycle':return lifecycle
    if name=='bound_upload_source_inventory':return types.SimpleNamespace(source_inventory=inventory)
    return types.SimpleNamespace(inventory=lambda path:{})
   ns['load']=load;ns['sha']=lambda p:'a'*64
   def packet(*a):
    if mode=='packet_denied':raise RuntimeError('packet denied')
    return a[2]
   ns['v03_packet']=packet
   ns['v03_wrapped']=lambda command,*a:command
   def spawn(command,**kw):
    calls.append(command);stdout='';code=0
    if '--test' in command:
     stdout='\n'.join('ok '+str(i+1)+' - '+t for i,t in enumerate(ns['V03_TITLES']))+'\n# tests 2\n# pass 2\n# fail 0\n# cancelled 0\n# skipped 0\n'
     if mode=='fixture_failure':code=1
    elif 'info' in command:stdout='test-daemon'
    elif 'image' in command:stdout='sha256:'+'3'*64
    elif 'ps' in command:
     created=any('run' in c for c in calls);removed=any('rm' in c for c in calls)
     stdout=cid if created and not removed else ''
    elif 'inspect' in command:
     stdout=json.dumps([{'Id':cid,'Name':'/'+name,'Image':'sha256:'+'3'*64,
      'Config':{'Labels':{'owasp-ai-goat.test.owner':'foreign' if mode=='foreign' else owner}},
      'HostConfig':{'PortBindings':{'5432/tcp':[{'HostIp':'127.0.0.1'}]},'Memory':536870912,'NanoCpus':2000000000,
       'PidsLimit':256,'Tmpfs':{'/var/lib/postgresql':'rw,size=536870912'}},'Mounts':[]}])
    elif 'port' in command:stdout='127.0.0.1:55555'
    if mode=='create_failure' and 'run' in command:code=1
    if mode=='cleanup_failure' and 'rm' in command:code=1
    kw['stdout'].write(stdout.encode());kw['stdout'].flush()
    return types.SimpleNamespace(pid=999999,returncode=code,poll=lambda:code,wait=lambda timeout:code)
   helper=types.SimpleNamespace(validate_current_host=lambda **kw:None,evidence_parent=lambda *a:parent)
   proc=types.SimpleNamespace(LibProc=lambda:types.SimpleNamespace(identity=lambda pid:None,group_pids=lambda pid:[]))
   with patch.dict(sys.modules,{'secureshop_current_host_admission':helper,'darwin_process_inventory':proc}),patch('subprocess.Popen',side_effect=spawn),contextlib.redirect_stdout(io.StringIO()):
    if mode=='packet_denied':
     with patch('tempfile.mkdtemp',side_effect=AssertionError('allocation before admission')),self.assertRaisesRegex(RuntimeError,'packet denied'):ns['main'](args)
     self.assertEqual(calls,[]);return
    if mode=='late_save_downgrade_failure':
     with self.assertRaisesRegex(OSError,'late downgrade failed'):ns['main'](args)
     code='uncaught-OSError-nonzero-terminal'
    else:code=ns['main'](args)
   result=json.loads(next(parent.glob('*/result.json')).read_text())
   return code,result,calls
 def test_original_composition_success(self):
  code,result,calls=self.run_main('success');self.assertEqual(code,0)
  self.assertTrue(result['qualificationComplete']);self.assertTrue(result['containerAbsent'])
  self.assertEqual(result['schema'],'v03-prerequisite-current-host-v1')
  self.assertEqual(len(result['observedAssertions']),2);self.assertFalse(result['actualModel'])
 def test_failed_fixture_keeps_failure_but_retires(self):
  code,result,calls=self.run_main('fixture_failure');self.assertEqual(code,1)
  self.assertFalse(result['qualificationComplete']);self.assertTrue(result['containerAbsent'])
  self.assertTrue(any('rm' in c for c in calls))
 def test_foreign_container_not_removed(self):
  code,result,calls=self.run_main('foreign');self.assertEqual(code,1)
  self.assertFalse(any('rm' in c for c in calls))
 def test_terminal_debt_not_removed(self):
  code,result,calls=self.run_main('terminal_failure');self.assertEqual(code,1)
  self.assertFalse(any('rm' in c for c in calls));self.assertFalse(result['qualificationComplete'])
 def test_packet_denial_no_allocation(self):self.run_main('packet_denied')
 def test_source_drift_no_external_allocation(self):
  code,result,calls=self.run_main('source_drift');self.assertEqual(code,1);self.assertEqual(calls,[])
 def test_failed_create_recovered_by_exact_identity(self):
  code,result,calls=self.run_main('create_failure');self.assertEqual(code,1)
  self.assertTrue(result['containerAbsent']);self.assertTrue(any('rm' in c for c in calls))
 def test_cleanup_failure_cannot_pass(self):
  code,result,calls=self.run_main('cleanup_failure');self.assertEqual(code,1)
  self.assertFalse(result['qualificationComplete']);self.assertTrue(result['cleanupErrors'])
 def test_late_final_save_downgraded(self):
  code,result,calls=self.run_main('late_save');self.assertEqual(code,1);self.assertFalse(result['passed'])
 def test_late_final_save_failed_downgrade_requires_nonzero_terminal(self):
  code,result,calls=self.run_main('late_save_downgrade_failure')
  self.assertEqual(code,'uncaught-OSError-nonzero-terminal')
  # A stale receipt alone is never native authority: outer terminal and FULL
  # must be joined by any future consumer, especially on publication failure.
  self.assertTrue(result['passed'])

if __name__=='__main__':unittest.main()



