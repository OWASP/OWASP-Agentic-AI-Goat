import importlib.util,io,json,pathlib,tarfile,tempfile,unittest,hashlib,uuid,subprocess,copy,os,stat
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('listing',ROOT/'tests/postgres/run-listing-template-native-isolated.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
NODE='/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node'
class TestListingTemplateNativeLauncher(unittest.TestCase):
 def test_closed_twelve_file_no_copy_plan(self):
  p=m.plan(ROOT,'a'*12);self.assertEqual(len(m.FILES),12);self.assertFalse(p['sourceCopy']);self.assertEqual(set(p['files']),set(m.FILES));self.assertEqual(p['profile'],'dvaia-owned-listing-template-'+'a'*12);self.assertIn('command-effect-witness',p['checks']);self.assertNotIn('fixed-workflow-denial',p['checks'])
 def test_streamed_context_has_only_pinned_sandbox_relative_members(self):
  pins=m.manifest(ROOT);raw=m.context_bytes(ROOT,pins)
  with tarfile.open(fileobj=io.BytesIO(raw)) as a:
   names=a.getnames();self.assertEqual(len(names),12);self.assertIn('listing-template/Dockerfile',names);self.assertFalse(any(n.startswith('/') or '..' in pathlib.PurePosixPath(n).parts for n in names))
 def test_nonce_identity_is_not_installed_name(self):
  p=m.plan(ROOT,'b'*12);self.assertTrue(p['container'].startswith('dvaia-listing-template-qual-'));self.assertNotEqual(p['container'],'dvaia-listing-template-'+'b'*12)
 def test_canonical_contract_validator_accepts_bound_inert_receipt(self):
  source='Hello {{ title }}';req={'version':1,'operationId':str(uuid.uuid4()),'productId':1,'sourceSha256':hashlib.sha256(source.encode()).hexdigest(),'templateSource':source,'title':'world','description':'','price':0}
  with tempfile.TemporaryDirectory() as d:
   q=pathlib.Path(d)/'q.json';q.write_text(json.dumps(req));program="const c=require('./server/services/secureshopListingTemplateExecutorContract'),x=require('node:crypto'),fs=require('node:fs'),r=JSON.parse(fs.readFileSync(process.argv[1]));const v='Hello world';process.stdout.write(JSON.stringify({version:1,operationId:r.operationId,productId:r.productId,requestSha256:c.listingTemplateExecutionDigest(r),sourceSha256:r.sourceSha256,isolation:c.ISOLATION,rendered:v,renderedSha256:x.createHash('sha256').update(v).digest('hex'),exitCode:0,timedOut:false,truncated:false,drained:true,workerAttested:true,commandEffectObserved:false,effectSha256:null}))"
   receipt=json.loads(subprocess.run([NODE,'-e',program,str(q)],cwd=ROOT,capture_output=True,text=True,check=True).stdout);m.assert_contract(ROOT,NODE,req,receipt,False)
class TestCommandWitness(unittest.TestCase):
 def test_exact_pinned_compiler_dispatches_real_command_payload(self):
  # Intercept the module capability: this is syntax/dispatch proof only, never
  # host command execution or a substitute for the isolated native witness.
  program="""const assert=require('node:assert/strict'),n=require('./sidecars/sandbox-runner/policy-render/assets/nunjucks-3.2.4');let calls=0;const env=new n.Environment(null,{autoescape:false});env.addGlobal('process',{mainModule:{require(name){assert.equal(name,'child_process');return {execSync(command){assert.equal(command,'umask 077 && cp /owned-source/effect-canary /owned-effect/command-effect');calls++;return Buffer.alloc(0)}}}}});assert.equal(env.renderString(process.argv[1]),'');assert.equal(calls,1);"""
  subprocess.run([NODE,'-e',program,m.COMMAND_WITNESS_TEMPLATE],cwd=ROOT,capture_output=True,text=True,check=True)
 def test_real_observer_rejects_default_mode_and_accepts_private_canary(self):
  program="""const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),s=require('./sidecars/sandbox-runner/listing-template/strict-helpers'),dir=process.argv[1],canary=Buffer.alloc(32,7),file=path.join(dir,'command-effect');fs.writeFileSync(file,canary,{mode:0o644});fs.chmodSync(file,0o644);assert.equal(s.observeEffect(dir,canary).commandEffectObserved,false);fs.chmodSync(file,0o600);assert.equal(s.observeEffect(dir,canary).commandEffectObserved,true);"""
  with tempfile.TemporaryDirectory() as d:subprocess.run([NODE,'-e',program,d],cwd=ROOT,capture_output=True,text=True,check=True)
 def test_failed_response_diagnostics_are_private_bounded_and_not_proof(self):
  request={'version':1,'operationId':str(uuid.uuid4()),'productId':1,'sourceSha256':'a'*64,'templateSource':'never log this'}
  response={'exitCode':70,'commandEffectObserved':False,'effectSha256':None,'workerAttested':True,'drained':True,'rendered':'private output','other':'never log this'}
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);m.record_response(p,'command-witness',200,request,response);f=p/'command-witness-response.json';value=json.loads(f.read_text())
   self.assertEqual(value['unvalidatedResponse']['exitCode'],70);self.assertFalse(value['unvalidatedResponse']['commandEffectObserved']);self.assertNotIn('private output',f.read_text());self.assertNotIn('never log this',f.read_text());self.assertEqual(value['renderedBytes'],14);self.assertEqual(stat.S_IMODE(f.stat().st_mode),0o600)

class LifecycleFixture:
 def __init__(self):
  self.state={'labels':{'dvaia.qualification':'listing-template','dvaia.qualification.nonce':'a'*12,'dvaia.qualification.owner':'owned'},
   'image':'owned:candidate','imageId':'sha256:'+'1'*64,'container':'owned','containerId':'2'*64,'network':'owned-bridge','networkId':'3'*64,
   'profile':{'name':'dvaia-owned-listing-template-'+'a'*12},'port':31000,'attempted':['profile','image','network','container']}
  labels=self.state['labels'];bindings={'8090/tcp':[{'HostIp':'127.0.0.1','HostPort':'31000'}]}
  self.rows={
   'image':{'Id':self.state['imageId'],'RepoTags':['owned:candidate'],'Architecture':'arm64','Config':{'Labels':labels,'User':'10001:10001'}},
   'network':{'Id':'3'*64,'Name':'owned-bridge','Labels':labels,'Driver':'bridge','Internal':False,'Options':{},'Containers':{'2'*64:{}}},
   'container':{'Id':'2'*64,'Name':'/owned','Config':{'Labels':labels,'User':'10001:10001'},'Image':self.state['imageId'],'AppArmorProfile':self.state['profile']['name'],
    'State':{'Running':True},'Mounts':[],
    'HostConfig':{'NetworkMode':'owned-bridge','ReadonlyRootfs':True,'Privileged':False,'Memory':536870912,'NanoCpus':1000000000,'PidsLimit':128,
     'CapDrop':['ALL'],'CapAdd':None,'SecurityOpt':['apparmor='+self.state['profile']['name'],'seccomp=unconfined'],
     'Tmpfs':{'/tmp':'rw,nosuid,nodev,noexec,mode=1777,size=128m'},'PortBindings':bindings},
    'NetworkSettings':{'Networks':{'owned-bridge':{'NetworkID':'3'*64}},'Ports':bindings}}}
  self.removals=[];self.profiles=[];self.foreign=None;self.daemon_failure=False;self.lost_remove=False
 def inspect(self,docker,host,kind,name,env):
  row=self.rows.get(kind)
  if row and name in (self.state[kind],row['Id']):return copy.deepcopy(row)
  if self.foreign and kind=='container' and name==self.foreign['Id']:return copy.deepcopy(self.foreign)
  return None
 def run(self,cmd,args,env,**kwargs):
  if args==['ps','-aq','--no-trunc']:
   identifiers=([self.rows['container']['Id']] if self.rows.get('container') else [])+([self.foreign['Id']] if self.foreign else [])
   return subprocess.CompletedProcess(args,0,'\n'.join(identifiers).encode(),b'')
  self.removals.append(args)
  kind='container' if args[0]=='rm' else args[0]
  assert args[-1]==self.rows[kind]['Id']
  self.rows[kind]=None
  if kind=='container' and self.rows.get('network'):self.rows['network']['Containers']={}
  if self.lost_remove:raise subprocess.TimeoutExpired(args,1)
  return subprocess.CompletedProcess(args,0,b'',b'')
 def daemon(self,*args):
  if self.daemon_failure:raise RuntimeError('wrong daemon')
 def cleanup(self):
  with patch.object(m,'inspect',side_effect=self.inspect),patch.object(m,'run',side_effect=self.run),patch.object(m,'daemon_ok',side_effect=self.daemon):
   return m.cleanup_resources('docker','host','daemon',self.state,{},lambda:None,lambda *args:self.profiles.append(args))

class TestExactLifecycle(unittest.TestCase):
 def test_exact_ids_removed_and_all_absence_verified(self):
  f=LifecycleFixture();self.assertTrue(all(f.cleanup().values()))
  self.assertEqual(f.removals,[['rm','-f','2'*64],['network','rm','3'*64],['image','rm','sha256:'+'1'*64]]);self.assertEqual(len(f.profiles),1)
 def test_lost_create_ack_recovers_only_exact_named_resources(self):
  f=LifecycleFixture();del f.state['containerId'];self.assertTrue(all(f.cleanup().values()));self.assertEqual(f.state['containerId'],'2'*64)
 def test_lost_network_create_ack_recovers_empty_owned_bridge(self):
  f=LifecycleFixture();f.rows['container']=None;f.rows['network']['Containers']={};f.state['attempted'].remove('container');del f.state['containerId'];del f.state['networkId']
  self.assertTrue(all(f.cleanup().values()));self.assertEqual(f.state['networkId'],'3'*64)
 def test_lost_remove_ack_requires_exact_absence(self):
  f=LifecycleFixture();f.lost_remove=True;self.assertTrue(all(f.cleanup().values()))
 def test_replacements_retain_every_resource_before_cleanup(self):
  for kind in ('container','network','image'):
   with self.subTest(kind=kind):
    f=LifecycleFixture();f.rows[kind]['Id']=('sha256:' if kind=='image' else '')+'f'*64
    with self.assertRaisesRegex(RuntimeError,'replaced'):f.cleanup()
    self.assertEqual(f.removals,[]);self.assertEqual(f.profiles,[])
 def test_renamed_captured_container_is_not_absence(self):
  f=LifecycleFixture();base=f.inspect
  def inspect(d,h,k,n,e):
   if k=='container' and n=='owned':return None
   return base(d,h,k,n,e)
  f.inspect=inspect
  with self.assertRaisesRegex(RuntimeError,'lost its admitted name'):f.cleanup()
  self.assertEqual(f.removals,[])
 def test_foreign_labels_and_config_block_lost_ack_adoption(self):
  for modify in (lambda f:f.rows['container']['Config'].update(Labels={}),lambda f:f.rows['container']['HostConfig'].update(Privileged=True)):
   f=LifecycleFixture();del f.state['containerId'];modify(f)
   with self.assertRaises(RuntimeError):f.cleanup()
   self.assertEqual(f.removals,[])
 def test_foreign_network_endpoint_blocks_all_removal(self):
  f=LifecycleFixture();f.rows['network']['Containers']['f'*64]={}
  with self.assertRaisesRegex(RuntimeError,'foreign network'):f.cleanup()
  self.assertEqual(f.removals,[])
 def test_foreign_profile_child_retains_profile_and_resources(self):
  f=LifecycleFixture();f.foreign={'Id':'f'*64,'Image':'other','AppArmorProfile':f.state['profile']['name']+'//bwrap','NetworkSettings':{'Networks':{}},'HostConfig':{}}
  with self.assertRaisesRegex(RuntimeError,'foreign resource attachment'):f.cleanup()
  self.assertEqual(f.removals,[]);self.assertEqual(f.profiles,[])
 def test_daemon_mismatch_never_removes(self):
  f=LifecycleFixture();f.daemon_failure=True
  with self.assertRaisesRegex(RuntimeError,'wrong daemon'):f.cleanup()
  self.assertEqual(f.removals,[])
 def test_never_attempted_resources_have_no_removal(self):
  f=LifecycleFixture();f.rows={};f.state={'labels':{},'container':'unique','network':'unique-net','image':'unique:candidate','attempted':[]}
  self.assertTrue(all(f.cleanup().values()));self.assertEqual(f.removals,[]);self.assertEqual(f.profiles,[])
 def test_daemon_change_after_container_removal_retains_remaining_resources(self):
  f=LifecycleFixture();original=f.run
  def command(*args,**kwargs):
   result=original(*args,**kwargs)
   if f.removals:f.daemon_failure=True
   return result
  f.run=command
  with self.assertRaisesRegex(RuntimeError,'wrong daemon'):f.cleanup()
  self.assertEqual(f.removals,[['rm','-f','2'*64]]);self.assertIsNotNone(f.rows['network']);self.assertEqual(f.profiles,[])
 def test_unconfirmed_removal_does_not_advance_to_profile(self):
  f=LifecycleFixture();original=f.run
  def command(cmd,args,env,**kwargs):
   if args[0]=='rm':return subprocess.CompletedProcess(args,1,b'',b'rejected')
   return original(cmd,args,env,**kwargs)
  f.run=command
  with self.assertRaisesRegex(RuntimeError,'removal unconfirmed'):f.cleanup()
  self.assertIsNotNone(f.rows['container']);self.assertEqual(f.profiles,[])
 def test_missing_inspect_is_exact_not_transport_error(self):
  for kind,message in [('network','Error response from daemon: network owned not found'),('container','Error: No such object: owned'),('image','Error: No such image: owned')]:
   with patch.object(m,'run',return_value=subprocess.CompletedProcess([],1,b'',message.encode())):self.assertIsNone(m.inspect('d','h',kind,'owned',{}))
  for message in ('permission denied: Error: No such object: owned','Error: No such object: another','Cannot connect to the Docker daemon'):
   with patch.object(m,'run',return_value=subprocess.CompletedProcess([],1,b'',message.encode())):
    with self.assertRaises(RuntimeError):m.inspect('d','h','container','owned',{})
 def test_primary_and_cleanup_failure_both_persist_private_false_receipt(self):
  with tempfile.TemporaryDirectory() as d:
   evidence=pathlib.Path(d);result={'passed':True,'error':{'type':'RuntimeError','message':'primary'}}
   def fail():raise RuntimeError('cleanup mismatch')
   self.assertFalse(m.finalize(evidence,result,{'attempted':['image']},fail,lambda:True))
   saved=json.loads((evidence/'result.json').read_text());self.assertEqual(saved['error']['message'],'primary');self.assertEqual(saved['cleanupError']['message'],'cleanup mismatch');self.assertFalse(saved['passed']);self.assertFalse(any(saved['cleanup'].values()));self.assertEqual(stat.S_IMODE((evidence/'result.json').stat().st_mode),0o600)
 def test_false_cleanup_or_source_drift_cannot_publish_pass(self):
  for drift in (True,False):
   with tempfile.TemporaryDirectory() as d:
    cleanup={k:True for k in ('containerAbsent','networkAbsent','imageAbsent','profileAbsent')}
    if not drift:cleanup['networkAbsent']=False
    self.assertFalse(m.finalize(pathlib.Path(d),{'passed':True},{},lambda:cleanup,lambda:not drift))
 def test_private_build_config_only_exposes_pinned_vendor_plugin(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);env=m.build_environment(root,'/vendor/docker','/runtime/node',{'path':'/vendor/docker-buildx'})
   self.assertEqual(env['DOCKER_BUILDKIT'],'1');self.assertEqual(json.loads((root/'docker-config/config.json').read_text()),{'cliPluginsExtraDirs':['/vendor']})
   self.assertEqual(env['HOME'],str(root/'home'));self.assertEqual(stat.S_IMODE((root/'docker-config/config.json').stat().st_mode),0o600)
 def test_vendor_buildx_hash_and_owner_rechecked_by_shared_admission(self):
  with tempfile.TemporaryDirectory() as d:
   executable=pathlib.Path(d)/'docker-buildx';executable.write_text('not the qualified plugin');executable.chmod(0o755)
   with self.assertRaisesRegex(RuntimeError,'Pinned root-owned vendor Buildx'):
    m.buildx_identity(m.SimpleNamespace(digest=m.digest),m.SimpleNamespace(docker=str(pathlib.Path(d)/'docker')))

if __name__=='__main__':unittest.main()
