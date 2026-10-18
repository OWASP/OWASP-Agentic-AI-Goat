import importlib.util,json,os,pathlib,signal,subprocess,tempfile,unittest
from types import SimpleNamespace
from unittest.mock import patch
PATH=pathlib.Path(__file__).with_name('run-owned-mcp-invocation-os-isolated.py')
spec=importlib.util.spec_from_file_location('invocation_os',PATH);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Contracts(unittest.TestCase):
 def test_attestation_private_artifacts_survive_failed_probe_without_exposing_bytes(self):
  with tempfile.TemporaryDirectory() as directory:
   root=pathlib.Path(directory);folder=root/'attestation-controls';folder.mkdir();path=folder/'bootstrap-metadata.stderr';path.write_text('PRIVATE_DIAGNOSTIC');path.chmod(0o600)
   result=m.capture_attestation_artifacts(root);self.assertEqual(len(result),1);self.assertNotIn('PRIVATE_DIAGNOSTIC',json.dumps(result));self.assertEqual(result[0]['sha256'],m.sha(path))
   path.unlink();path.symlink_to(root/'missing')
   with self.assertRaises(OSError):m.capture_attestation_artifacts(root)
 def test_native_attestation_closed_results_and_selection(self):
  self.assertEqual(m.parse_attestation_asset('a'*64+'  /usr/local/libexec/dvaia-invocation-attestation-controls\n'),'a'*64)
  for invalid in ['a'*64+'  /tmp/other\n','bad','a'*64+'  /usr/local/libexec/dvaia-invocation-attestation-controls\nextra']:
   with self.assertRaises(ValueError):m.parse_attestation_asset(invalid)
  valid={'version':1,'diagnosticOnly':True,'passedCases':6,'expectedCases':6,'maxRights':253}
  self.assertEqual(m.parse_attestation_result(json.dumps(valid)),valid)
  for value in [{**valid,'passedCases':5},{**valid,'version':True},{**valid,'unexpected':1},{**valid,'maxRights':254},[]]:
   with self.assertRaises(ValueError):m.parse_attestation_result(json.dumps(value))
  argv=['probe','--run','--docker-host',m.M.HOST,'--source-sha256','x','--dependency-sha256','y','--compile-only','--attestation-controls']
  with patch('sys.argv',argv),patch.object(m,'verify',side_effect=AssertionError('must not verify or launch')):
   with self.assertRaisesRegex(RuntimeError,'require kernel-only'):m.main()
 def test_native_attestation_qualification_asset_separate_from_default_runtime(self):
  root=PATH.parents[2];docker=(root/'sidecars/sandbox-runner/owned-mcp-registry/Dockerfile.invocation').read_text();assets=(root/'sidecars/sandbox-runner/owned-mcp-registry/invocation-build-assets.js').read_text();source=PATH.read_text()
  self.assertTrue(docker.rstrip().endswith('FROM runtime AS default-runtime'))
  self.assertNotIn('dvaia-invocation-attestation-controls',assets)
  self.assertIn("'attestation-qualification' if a.attestation_controls else 'runtime'",source)
  self.assertIn("state['attestationControlAttempt']=attempt;persist()",source)
  self.assertLess(source.index("state['attestationControlAttempt']=attempt;persist()"),source.index("state['attestationControlResult']=parse_attestation_result"))
 def test_metadata_mountinfo_multiline_short_reads_eof_and_limit(self):
  harness=r"""
const vm=require('vm');const input=JSON.parse(process.argv[1]),bytes=Buffer.from(input.data);let offset=0,reads=0,closed=false,output='',stderr='';const processStub={stdout:{write:value=>{output+=value;}},stderr:{write:value=>{stderr+=value;}},exitCode:0};
const fs={readFileSync:()=> {if(input.fail==='kernel')throw Error('PRIVATE_SECRET');return '6.12-test';},openSync:()=>{if(input.fail==='mountinfo')throw Error('PRIVATE_SECRET');return 3;},closeSync:()=>{closed=true;},readSync:(fd,b,start,size)=>{reads++;const count=Math.min(size,input.chunk,bytes.length-offset);bytes.copy(b,start,offset,offset+count);offset+=count;return count;}};
const cp={spawnSync:path=> {if(input.fail==='package_signal'&&path.includes('dpkg'))return {status:null,signal:'SIGTERM',error:{code:'ETIMEDOUT'},stdout:'',stderr:'x'.repeat(5000)};if(input.fail===(path.includes('dpkg')?'package':'version'))return {status:23,signal:null,error:{code:'EACCES'},stdout:'',stderr:'PRIVATE_SECRET'};return {status:0,signal:null,stdout:input.version||'0.11.0',stderr:''};}};let error=null;
try{vm.runInNewContext(input.code,{Buffer,require:name=>name==='fs'?fs:cp,process:processStub});}catch(e){error=e.message;}
console.log(JSON.stringify({output,stderr,exitCode:processStub.exitCode,error,closed,reads,offset}));
"""
  def probe(data,chunk,fail=None,version=None):
   result=subprocess.run([str(m.M.NODE),'-e',harness,json.dumps({'code':m.bootstrap_metadata_code(),'data':data,'chunk':chunk,'fail':fail,'version':version})],capture_output=True,text=True,check=True,timeout=5)
   return json.loads(result.stdout)
  lines=['1 0 0:1 / /proc rw - proc proc rw','2 1 0:2 / /proc/sys ro - proc proc ro','3 1 0:3 / /process rw - tmpfs tmpfs rw','4 1 0:4 / /tmp rw - tmpfs tmpfs rw']
  result=probe('\n'.join(lines)+'\n',7)
  self.assertIsNone(result['error']);self.assertEqual(json.loads(result['output'])['procMounts'],lines[:2]);self.assertTrue(result['closed']);self.assertGreater(result['reads'],2)
  result=probe('',1);self.assertEqual(json.loads(result['output'])['procMounts'],[]);self.assertEqual(result['reads'],1)
  result=probe('x'*65536,31);self.assertIsNone(result['error']);self.assertTrue(result['closed'])
  result=probe('x'*65537,31);self.assertIsNone(result['error']);self.assertEqual(result['exitCode'],70);self.assertEqual(json.loads(result['stderr'])['stage'],'mountinfo');self.assertEqual(json.loads(result['stderr'])['category'],'limit');self.assertEqual(result['output'],'');self.assertTrue(result['closed'])
  for stage in ['version','package','kernel','mountinfo']:
   result=probe('',7,stage);self.assertEqual(result['exitCode'],70);failure=json.loads(result['stderr']);self.assertEqual(failure['stage'],stage);self.assertEqual(failure['category'],'command' if stage in ['version','package'] else 'io');self.assertNotIn('PRIVATE_SECRET',json.dumps(result))
   if stage in ['version','package']:
    self.assertEqual(failure['commandEvidence'][-1]['status'],23);self.assertEqual(failure['commandEvidence'][-1]['errorCode'],'EACCES')
  result=probe('',7,'package_signal');failure=json.loads(result['stderr']);evidence=failure['commandEvidence'][-1];self.assertEqual(evidence['signal'],'SIGTERM');self.assertEqual(evidence['errorCode'],'ETIMEDOUT');self.assertTrue(evidence['outputTruncated']);self.assertEqual(len(__import__('base64').b64decode(evidence['stderrBase64'])),4096)
  for version in ['0.11.0-2~deb13u1','1:0.11.0+dfsg-2']:
   result=probe('',7,version=version);self.assertEqual(result['exitCode'],0);self.assertEqual(json.loads(result['output'])['packageVersion'],version)
  result=probe('',7,version='invalid package version');failure=json.loads(result['stderr']);self.assertEqual(failure['stage'],'package');self.assertEqual(failure['category'],'validation');self.assertEqual(failure['commandEvidence'][-1]['status'],0)
 def test_metadata_command_preserves_private_status_timeout_and_limit(self):
  import sys
  for code,timeout,expected in [("import sys;sys.stderr.write('PRIVATE_SECRET');sys.exit(23)",2,'nonzero'),("import time;time.sleep(5)",0.05,'timeout'),("import os;os.write(2,b'x'*10000)",2,'limit')]:
   with tempfile.TemporaryDirectory() as root:
    result=m.run_metadata_command([sys.executable,'-c',code],root,timeout=timeout,limit=1024)
    self.assertNotIn('PRIVATE_SECRET',json.dumps(result));self.assertEqual(len(result['artifacts']),2)
    for row in result['artifacts']:
     path=pathlib.Path(root)/row['name'];self.assertEqual(path.stat().st_mode&0o777,0o600);self.assertLessEqual(path.stat().st_size,1024)
    if expected=='nonzero':self.assertEqual(result['returncode'],23)
    if expected=='timeout':self.assertTrue(result['timedOut']);self.assertEqual(result['returncode'],-signal.SIGKILL)
    if expected=='limit':self.assertTrue(result['truncated'])
 def test_bootstrap_metadata_closed_optin_without_ptrace(self):
  source=PATH.read_text();supervisor=(PATH.parents[2]/'sidecars/sandbox-runner/owned-mcp-registry/invocation-supervisor.c').read_text()
  self.assertIn("p.add_argument('--bootstrap-diagnostic',action='store_true')",source)
  self.assertIn('if a.bootstrap_diagnostic:',source)
  self.assertNotIn('strace',supervisor);self.assertNotIn('BOOTSTRAP_TRACE',source)
  self.assertIn('"--tmpfs","/proc","--remount-ro","/proc"',supervisor);self.assertIn('r->state=attested&&!forced',supervisor);self.assertIn('"--seccomp","3"',supervisor)
  self.assertIn("['MaskedPaths','ReadonlyPaths','SecurityOpt','CapDrop','Privileged','PidMode','UsernsMode']",source)
  self.assertIn('O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600',source)
 def test_private_artifact_rejects_oversize(self):
  with tempfile.TemporaryDirectory() as root:
   def command(argv):
    if argv[0]=='cp':
     p=pathlib.Path(argv[-1]);p.write_bytes(b'x'*65537);p.chmod(0o600)
    return SimpleNamespace(returncode=0)
   with self.assertRaisesRegex(RuntimeError,'Unsafe'):m.retain_native_failure(command,root,'owned')
 def test_private_failure_cleanup_is_exact_and_unconditional(self):
  source=PATH.read_text()
  start=source.index("for rel in ['state/first-worker-failure.bin'")
  end=source.index("for rel in ['state','secrets']",start)
  self.assertIn("clean_ssh(['sudo','rm','-f','--',remote+'/'+rel])",source[start:end])
  self.assertNotIn("privateFailureArtifact",source[start:end])
  self.assertLess(source.index("if clean_ssh(['cat',remote+'/owner'])"),start)
  self.assertLess(source.index('if not containers_clean:'),start)
 def test_native_private_failure_hash_only_and_missing(self):
  import hashlib
  with tempfile.TemporaryDirectory() as root:
   calls=[]
   def command(argv):
    calls.append(argv)
    if argv[0]=='cp':
     p=pathlib.Path(argv[-1]);p.write_bytes(b'PRIVATE_UNTRUSTED_CHILD_DATA');p.chmod(0o600)
    return SimpleNamespace(returncode=0)
   result=m.retain_native_failure(command,root,'owned-id')
   self.assertEqual(result['sha256'],hashlib.sha256(b'PRIVATE_UNTRUSTED_CHILD_DATA').hexdigest())
   self.assertNotIn('PRIVATE_UNTRUSTED',json.dumps(result));self.assertEqual(calls[0][-1],'/var/lib/dvaia-invocation/first-worker-failure.bin')
   with self.assertRaisesRegex(RuntimeError,'collision'):m.retain_native_failure(command,root,'owned-id')
   self.assertEqual(m.retain_native_failure(lambda _:SimpleNamespace(returncode=1),root,'owned-id'),{'status':'absent'})
 def test_private_capture_c_disabled_collision_symlink_bound_and_silence(self):
  header=PATH.parents[2]/'sidecars/sandbox-runner/owned-mcp-registry/invocation-private-diagnostic.h'
  code=r'''#include <assert.h>
#include <string.h>
#include "HEADER"
int main(int argc,char **argv){(void)argc;int d=open(argv[1],O_RDONLY|O_DIRECTORY);assert(d>=0);
assert(retain_private_failure(0,d,"SECRET",6)==0);assert(faccessat(d,"first-worker-failure.bin",F_OK,0)<0);
assert(retain_private_failure(1,d,"SECRET",65537)==-1);assert(faccessat(d,"first-worker-failure.bin",F_OK,0)<0);
assert(symlinkat("target",d,"first-worker-failure.bin")==0);assert(retain_private_failure(1,d,"SECRET",6)==0);assert(faccessat(d,"target",F_OK,0)<0);assert(unlinkat(d,"first-worker-failure.bin",0)==0);
assert(retain_private_failure(1,d,"SECRET",6)==1);assert(retain_private_failure(1,d,"REPLACEMENT",11)==0);
int f=openat(d,"first-worker-failure.bin",O_RDONLY);char b[7]={0};assert(read(f,b,7)==6);assert(!strcmp(b,"SECRET"));struct stat st;assert(!fstat(f,&st));assert((st.st_mode&0777)==0600);close(f);close(d);return 0;}
'''.replace('HEADER',str(header))
  with tempfile.TemporaryDirectory() as root:
   source=pathlib.Path(root)/'check.c';source.write_text(code);binary=pathlib.Path(root)/'check'
   subprocess.run(['cc','-Wall','-Wextra','-Werror',str(source),'-o',str(binary)],check=True,capture_output=True)
   result=subprocess.run([str(binary),root],check=True,capture_output=True)
   self.assertEqual(result.stdout,b'');self.assertEqual(result.stderr,b'')
 def test_optional_claim_receipt_private_hash_and_absence(self):
  import hashlib
  with tempfile.TemporaryDirectory() as root:
   self.assertEqual(m.capture_claim_receipt(root),{'status':'absent'})
   p=pathlib.Path(root)/'candidate-result.json.claim-receipt.json';payload=b'PRIVATE_RECEIPT_CONTENT'
   p.write_bytes(payload);p.chmod(0o600)
   result=m.capture_claim_receipt(root)
   self.assertEqual(result['sha256'],hashlib.sha256(payload).hexdigest());self.assertNotIn(payload.decode(),json.dumps(result))
   p.chmod(0o644)
   with self.assertRaises(ValueError):m.capture_claim_receipt(root)
   p.unlink();p.symlink_to('/dev/null')
   with self.assertRaises(OSError):m.capture_claim_receipt(root)
 def test_invocation_endpoint_keeps_discovery_default_and_rejects_published_or_foreign(self):
  import copy
  identifier='a'*64;network={'Id':'b'*64,'Name':'owned','Driver':'bridge','Internal':True,'Labels':{'dvaia.owner':'fixture'},'IPAM':{'Config':[{'Subnet':'172.28.0.0/16'}]},'Containers':{identifier:{'IPv4Address':'172.28.0.2/16'}}}
  container={'Id':identifier,'HostConfig':{'PortBindings':{}},'NetworkSettings':{'Networks':{'owned':{'NetworkID':network['Id'],'IPAddress':'172.28.0.2'}}}}
  self.assertEqual(m.M.validate_internal_endpoint(container,network,'owned','fixture',identifier,binding_mode='invocation'),'172.28.0.2')
  with self.assertRaisesRegex(RuntimeError,'binding'):m.M.validate_internal_endpoint(container,network,'owned','fixture',identifier)
  for bindings in ({'8095/tcp':[{'HostIp':'0.0.0.0','HostPort':'8095'}]},{'8094/tcp':[{'HostIp':'127.0.0.1','HostPort':''}]}):
   bad=copy.deepcopy(container);bad['HostConfig']['PortBindings']=bindings
   with self.assertRaisesRegex(RuntimeError,'binding'):m.M.validate_internal_endpoint(bad,network,'owned','fixture',identifier,binding_mode='invocation')
  bad=copy.deepcopy(network);bad['Internal']=False
  with self.assertRaisesRegex(RuntimeError,'identity'):m.M.validate_internal_endpoint(container,bad,'owned','fixture',identifier,binding_mode='invocation')
  argv=m.M.tunnel_argv('172.28.0.2',32001,remote_port=8095)
  for option in ['ControlMaster=no','ControlPath=none','ExitOnForwardFailure=yes','GatewayPorts=no','BatchMode=yes','127.0.0.1:32001:172.28.0.2:8095']:self.assertIn(option,argv)
  with self.assertRaises(ValueError):m.M.tunnel_argv('172.28.0.2',32001,remote_port=22)
 def test_tunnel_cleanup_requires_exact_group_listener_and_refusal_proof(self):
  import errno
  def refused(*args,**kw):raise ConnectionRefusedError(errno.ECONNREFUSED,'closed')
  absent=lambda argv:SimpleNamespace(returncode=1,stdout='',stderr='')
  self.assertTrue(m.M.verify_tunnel_closed(32001,123,absent,members=lambda _:[],connect=refused)['listenerAbsent'])
  with self.assertRaisesRegex(RuntimeError,'group remains'):m.M.verify_tunnel_closed(32001,123,absent,members=lambda _:[123],connect=refused)
  with self.assertRaisesRegex(RuntimeError,'absence unverified'):m.M.verify_tunnel_closed(32001,123,lambda argv:SimpleNamespace(returncode=1,stdout='',stderr='permission denied'),members=lambda _:[],connect=refused)
 def test_diagnostics_scrub_all_secrets_before_truncation_without_config(self):
  calls=[];token='private-token';key='b'*64
  def command(argv):
   calls.append(argv);return SimpleNamespace(returncode=0,stdout='x'*4080+token+key,stderr=key)
  result=m.M.startup_diagnostics(command,'owned',token,extra_secrets=(key,),service_port=8095)
  for row in result.values():
   self.assertNotIn(token,row['stdout']);self.assertNotIn(key,row['stdout']);self.assertEqual(row['stderr'],'[REDACTED]');self.assertLessEqual(len(row['stdout']),4096)
  self.assertIn(['port','owned','8095/tcp'],calls);self.assertFalse(any('Config' in str(argv) for argv in calls))
 def test_process_cleanup_deadline_exhaustion_never_starts_ps(self):
  with patch.object(m.M.time,'monotonic',return_value=100),patch.object(m.M.subprocess,'run') as run:
   with self.assertRaisesRegex(TimeoutError,'cleanup deadline'):m.M.group_members(123,deadline=99)
   run.assert_not_called()
  with patch.object(m.M.time,'monotonic',return_value=99.75),patch.object(m.M.subprocess,'run',return_value=SimpleNamespace(stdout='')) as run:
   self.assertEqual(m.M.group_members(123,deadline=100),[]);self.assertEqual(run.call_args.kwargs['timeout'],.25)
 def test_remote_create_timeout_retains_pending_intent_and_never_deletes(self):
  for fail_stage in ('mkdir','tee'):
   state={};saved=[];calls=[]
   def ssh(argv,**kw):
    calls.append(argv)
    if argv[0]==fail_stage:raise subprocess.TimeoutExpired('ssh',1)
   with self.assertRaises(subprocess.TimeoutExpired):m.create_remote_root(ssh,'/tmp/owned','owner',state,lambda:saved.append(dict(state)))
   self.assertEqual(state['pendingRemoteCreate'],'/tmp/owned');self.assertNotIn('remoteRootOwned',state)
   self.assertEqual(saved[0]['pendingRemoteCreate'],'/tmp/owned');self.assertFalse(any(x[0] in ('rm','rmdir') for x in calls))
  state={};calls=[]
  self.assertTrue(m.create_remote_root(lambda argv,**kw:calls.append((argv,kw)),'/tmp/owned','owner',state,lambda:None))
  self.assertEqual(state,{'remoteRootOwned':True});self.assertEqual(calls[-1],(['tee','/tmp/owned/owner'],{'input':'owner\n'}))
 def test_remote_collision_does_not_mint_cleanup_authority(self):
  state={}
  def collision(argv,**kw):raise RuntimeError('exists')
  with self.assertRaises(RuntimeError):m.create_remote_root(collision,'/tmp/unowned','owner',state,lambda:None)
  self.assertEqual(state,{})
 def test_compile_and_kernel_modes_are_mutually_exclusive_before_admission(self):
  result=subprocess.run(['python3','-B',str(PATH),'--source-sha256','a'*64,'--dependency-sha256','b'*64,'--docker-host',m.M.HOST,'--run','--compile-only','--kernel-only'],capture_output=True,text=True,timeout=5)
  self.assertNotEqual(result.returncode,0);self.assertIn('not allowed with argument',result.stderr)
 def test_unreviewed_full_mode_denies_before_resources(self):
  r=subprocess.run(['python3','-B',str(PATH),'--source-sha256','a'*64,'--dependency-sha256','b'*64,'--docker-host',m.M.HOST,'--run'],capture_output=True,text=True,timeout=5)
  self.assertNotEqual(r.returncode,0);self.assertIn('Full kernel launcher remains unqualified',r.stderr)
 def test_ambiguous_build_reconciles_owned_tag_without_captured_id(self):
  identifier='sha256:'+'a'*64;calls=[]
  def command(argv):
   calls.append(argv)
   return SimpleNamespace(returncode=0,stdout=m.M.DAEMON_ID if argv[0]=='info' else '',stderr='')
  with patch.object(m.M,'inspect_resource',side_effect=[{'Id':identifier,'Config':{'Labels':{'dvaia.owner':'owner'}}},None,None]):
   proof=m.cleanup_image(command,'owned:tag','owner')
  self.assertTrue(proof['tagAbsent']);self.assertTrue(proof['imageIdAbsent']);self.assertIn(['image','rm','owned:tag'],calls)
 def test_cleanup_refuses_foreign_replaced_and_unknown_resources(self):
  command=lambda argv:SimpleNamespace(returncode=0,stdout=m.M.DAEMON_ID,stderr='')
  for row in [{'Id':'sha256:'+'b'*64,'Config':{'Labels':{'dvaia.owner':'foreign'}}},{'Id':'sha256:'+'b'*64,'Config':{'Labels':{'dvaia.owner':'owner'}}}]:
   with patch.object(m.M,'inspect_resource',return_value=row),self.assertRaisesRegex(RuntimeError,'identity mismatch'):m.cleanup_image(command,'owned:tag','owner','sha256:'+'a'*64)
  with patch.object(m.M,'inspect_resource',side_effect=RuntimeError('daemon unavailable')),self.assertRaisesRegex(RuntimeError,'daemon unavailable'):m.cleanup_image(command,'owned:tag','owner')
 def test_sigterm_runs_finally_and_reaps_owned_process_group(self):
  with tempfile.TemporaryDirectory() as temp:
   marker=pathlib.Path(temp)/'cleanup'
   code="""import importlib.util,sys,subprocess,time,pathlib
s=importlib.util.spec_from_file_location('candidate',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
m.install_cancellation();child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],start_new_session=True)
print('READY',flush=True)
try:time.sleep(30)
finally:
 m.M.stop_process(child)
 pathlib.Path(sys.argv[2]).write_text(str(m.M.group_members(child.pid)))
"""
   p=subprocess.Popen(['python3','-B','-c',code,str(PATH),str(marker)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,cwd=PATH.parent)
   try:
    self.assertEqual(p.stdout.readline().strip(),'READY');p.send_signal(signal.SIGTERM);p.communicate(timeout=10);self.assertEqual(marker.read_text(),'[]');self.assertNotEqual(p.returncode,0)
   finally:
    if p.poll() is None:p.kill();p.communicate(timeout=5)
if __name__=='__main__':unittest.main()
