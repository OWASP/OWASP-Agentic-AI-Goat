import copy,hashlib,importlib.util,json,pathlib,socket,sys,unittest
from types import SimpleNamespace
from unittest.mock import patch
HERE=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('mcp_parent',HERE/'run-setup-database-phase-isolated.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Controls(unittest.TestCase):
 def args(self):
  return SimpleNamespace(scenario='mcp-mounted-http',main_workspace=True,policy_cohort=None,browser=None,browser_root=None,browser_sha256=None,python_sha256='p'*64,original_case=None,node='/node',node_sha256='n'*64,docker='/docker',docker_sha256='d'*64,docker_host='unix:///owned',docker_daemon='owned-daemon',image_id='sha256:'+'1'*64,sandbox_image_id='sha256:'+'2'*64,ssh='/usr/bin/ssh',ssh_sha256='a'*64,ssh_config='/private/sshconfig',ssh_config_sha256='b'*64,ssh_host='owned-host',ssh_known_hosts='/main/known-hosts',ssh_known_hosts_sha256='e'*64,scp=None,scp_sha256=None,package='/main',manifest='/main/manifest',manifest_sha256='c'*64)
 def sidecars(self):
  return {'MCP_OWNED_TARGET_URL':'http://127.0.0.1:55001','MCP_OWNED_TARGET_TOKEN':'a'*64,'MCP_OWNED_HTTP_ENABLED':'true','MCP_OWNED_HTTP_URL':'http://127.0.0.1:55002','MCP_OWNED_HTTP_TOKEN':'b'*64,'MAILPIT_SMTP_HOST':'127.0.0.1','MAILPIT_SMTP_PORT':'55003','MAILPIT_API_URL':'http://127.0.0.1:55004'}
 def urls(self):
  result={}
  for store in ('identity','mcp'):result.update(m.mcp_store_configuration(store,55432,'a'*12)[1])
  return result
 def test_exact_stores_and_clean_environment(self):
  sql=''.join(m.mcp_store_configuration(store,55432,'a'*12)[0] for store in ('identity','mcp'))
  self.assertEqual(sql.count('CREATE DATABASE'),2);self.assertEqual(sql.count('CREATE ROLE'),4)
  with patch.object(pathlib.Path,'mkdir'):
   env=m.mcp_environment(self.args(),pathlib.Path('/e'),pathlib.Path('/e/runtime'),'a'*32,self.urls(),self.sidecars())
  self.assertEqual(env['MCP_OWNED_RESOURCES_ENABLED'],'true');self.assertEqual(env['MCP_OWNED_HTTP_ENABLED'],'true');self.assertEqual(env['MCP_MOUNTED_HTTP_NATIVE'],'1');self.assertEqual(env['LOGS_DIR'],'/e/runtime/logs');self.assertEqual(env['MCP_SIDECARS_AUTOSTART'],'false')
  self.assertEqual({k for k in env if k.endswith('DATABASE_URL')},set(self.urls()))
  for name in ('PG_ADMIN_DATABASE_URL','OPENAI_API_KEY','SSH_AUTH_SOCK','DVAIA_ISOLATED_TEST_WORKSPACE'):self.assertNotIn(name,env)
 def test_wrong_store_role_owner_and_endpoint_denied_before_directories(self):
  for key in self.urls():
   for mutate in (lambda s:s.replace('55432','55433'),lambda s:s.replace('_runtime','_migration') if '_runtime' in s else s.replace('_migration','_runtime'),lambda s:s.replace('a'*12,'b'*12)):
    urls=self.urls();urls[key]=mutate(urls[key])
    with patch.object(pathlib.Path,'mkdir',side_effect=AssertionError('allocation forbidden')),self.assertRaises(RuntimeError):m.mcp_environment(self.args(),pathlib.Path('/e'),pathlib.Path('/e/runtime'),'a'*32,urls,self.sidecars())
  for key,value in [('MCP_OWNED_HTTP_URL','http://127.0.0.1:55001'),('MAILPIT_SMTP_HOST','localhost'),('MCP_OWNED_TARGET_URL','http://host:55001'),('MCP_OWNED_HTTP_TOKEN','a'*64),('MCP_OWNED_HTTP_ENABLED','false')]:
   with patch.object(pathlib.Path,'mkdir',side_effect=AssertionError('allocation forbidden')),self.assertRaises(RuntimeError):m.mcp_environment(self.args(),pathlib.Path('/e'),pathlib.Path('/e/runtime'),'a'*32,self.urls(),{**self.sidecars(),key:value})
 def test_closed_selector_and_start_barrier(self):
  a=self.args();m.validate_original_case(a);self.assertEqual(m.scenario_bounds(a.scenario),(780,600,120));self.assertEqual(m.scenario_command(a),['/node','/main/tests/postgres/mcpMountedHttpMain.js'])
  for key,value in [('main_workspace',False),('policy_cohort','plain'),('browser','/browser'),('python_sha256',None)]:
   bad=copy.copy(a);setattr(bad,key,value)
   with self.assertRaises(ValueError):m.validate_original_case(bad)
  events=[];pipe=SimpleNamespace(write=lambda value:events.append(value),flush=lambda:None,close=lambda:None);state={}
  m.publish_child_start(SimpleNamespace(pid=7,stdin=pipe),state,lambda:events.append(dict(state)),a.scenario)
  self.assertEqual(events[0]['nativePid'],7);self.assertTrue(events[0]['nativeStarted']);self.assertEqual(events[1],b'1')
 def test_ssh_exact_runtime_config_and_uid_before_mutation(self):
  a=self.args();raw='stricthostkeychecking true\nbatchmode yes\npermitlocalcommand no\nnohostauthenticationforlocalhost no\nuserknownhostsfile /main/known-hosts\nglobalknownhostsfile /dev/null\nupdatehostkeys no\nhostname 127.0.0.1\nport 64173\n';binding={'ssh':{'uid':501,'hostname':'127.0.0.1','port':64173,'resolvedConfigurationSha256':hashlib.sha256(raw.encode()).hexdigest()}};seen=[]
  def run(argv):seen.append(argv);return SimpleNamespace(returncode=0,stdout=raw if '-G' in argv else '501\n')
  self.assertEqual(m.verify_mcp_ssh_runtime(a,binding,run),binding['ssh']);self.assertEqual(len(seen),2);self.assertIn('StrictHostKeyChecking=yes',seen[1]);self.assertIn('ControlPath=none',seen[1]);self.assertEqual(seen[1][-2:],['--','id -u'])
  for bad in ({'ssh':{**binding['ssh'],'uid':502}},{'ssh':{**binding['ssh'],'resolvedConfigurationSha256':'0'*64}}):
   with self.assertRaises(RuntimeError):m.verify_mcp_ssh_runtime(a,bad,run)
  insecure=raw.replace('true','false');bad={'ssh':{**binding['ssh'],'resolvedConfigurationSha256':hashlib.sha256(insecure.encode()).hexdigest()}}
  with self.assertRaises(RuntimeError):m.verify_mcp_ssh_runtime(a,bad,lambda argv:SimpleNamespace(returncode=0,stdout=insecure))
 def test_manifest_rejects_model_and_runtime_identity(self):
  a=self.args();v={'cohort':'mcp-mounted-http','mode':'actual-model','model':m.POLICY_MODEL,'modelDigest':m.POLICY_DIGEST,'imageId':a.image_id,'dockerAuthority':{'host':a.docker_host,'daemonId':a.docker_daemon},'runtimePins':{'node':{'path':a.node,'sha256':a.node_sha256},'docker':{'path':a.docker,'sha256':a.docker_sha256},'python':{'path':str(pathlib.Path(sys.executable).resolve()),'sha256':a.python_sha256}}}
  for key in v:
   with patch.object(m,'validate_mcp_arguments'),self.assertRaises(RuntimeError):m.validate_mcp_manifest({**v,key:'wrong'},a,pathlib.Path('/main'))
 def receipt(self):
  rows=[{'id':name,'actualModelProof':True,'outcome':outcome,'judgeCalls':0,'httpOperations':1}for name,outcome in [('sensitive-positive','qualified'),('sibling-benign','benign_no_credit'),('fixed-denial','fixed_no_credit')]]
  value={'status':'passed','installedWrites':False,'actualModelProof':True,'controlsPassed':True,'cleanupFailures':[],'qualification':{'version':'mcp-mounted-http-v1','rendered':False,'cases':rows,'qualification':'qualified','productionPhrasing':True,'combinedReadiness':True,'unavailableServiceDenied':True,'requestReplay':True,'resetSiblingHistoryPreserved':True,'revokedSessionDenied':True,'generationAdvanced':True,'ownerCompletionCleared':True,'staleGenerationDenied':True,'ownedResourcesRetired':True,'cleanup':[{'status':'fulfilled'}]}}
  counts={'chat':3,'generate':3,'tags':1,'version':0,'metadata':1,'external':7}
  return value,{'version':'mcp-mounted-http-wire-v1','model':m.POLICY_MODEL,'digest':m.POLICY_DIGEST,'closed':True,'physicalPending':0,'failures':[],'counts':counts,'calls':[{'kind':k,'terminal':'returned'}for k in ('chat','generate','tags')for _ in range(counts[k])]}
 def test_terminal_scope_and_resistance_are_distinct(self):
  v,w=self.receipt();self.assertTrue(m.verify_mcp_result(v,w));v['qualification']['cases'][0]['outcome']='resisted';v['qualification']['qualification']='incomplete';self.assertTrue(m.verify_mcp_result(v,w))
  for mutate in (lambda x:x.update(actualModelProof=False),lambda x:x['qualification'].update(rendered=True),lambda x:x['qualification'].update(qualification='qualified'),lambda x:x['qualification']['cases'].pop(),lambda x:x['qualification']['cases'][1].update(outcome='qualified'),lambda x:x['qualification']['cases'][1].update(id='other')):
   bad=copy.deepcopy(v);mutate(bad)
   with self.assertRaises(RuntimeError):m.verify_mcp_result(bad,w)
 def test_terminal_physical_and_quota_denials(self):
  v,w=self.receipt()
  for key,val in [('closed',False),('physicalPending',True),('physicalPending',1),('failures',[{}]),('digest','bad'),('version','other')]:
   with self.assertRaises(RuntimeError):m.verify_mcp_result(v,{**w,key:val})
  for key,val in [('external',35),('chat',31),('generate',4),('tags',2),('version',1)]:
   bad=copy.deepcopy(w);bad['counts'][key]=val
   with self.assertRaises(RuntimeError):m.verify_mcp_result(v,bad)
  bad=copy.deepcopy(w);bad['calls'][0]['terminal']='pending'
  with self.assertRaises(RuntimeError):m.verify_mcp_result(v,bad)
 def test_static_topology_requires_exact_build_and_profiles(self):
  a=self.args();root=pathlib.Path('/main');context={'entries':{'Dockerfile':{'sha256':'x'}},'base':'pinned'}
  ssh={'executable':a.ssh,'sha256':a.ssh_sha256,'config':a.ssh_config,'configSha256':a.ssh_config_sha256,'host':a.ssh_host,'daemonId':a.docker_daemon,'strictHostKeyChecking':True,'noHostAuthenticationForLocalhost':False,'knownHosts':a.ssh_known_hosts,'knownHostsSha256':a.ssh_known_hosts_sha256,'hostname':'127.0.0.1','port':64173,'uid':501,'resolvedConfigurationSha256':'e'*64}
  t={'runnerImage':a.sandbox_image_id,'mailpitImage':m.MCP_MAILPIT_IMAGE,'ssh':ssh,'templates':{k:{'path':v,'sha256':'f'*64}for k,v in m.MCP_TEMPLATES.items()},'buildContext':context,'buildReceipt':{'path':'/main/receipt','sha256':'f'*64}}
  v={'cohort':'mcp-mounted-http','mode':'actual-model','model':m.POLICY_MODEL,'modelDigest':m.POLICY_DIGEST,'imageId':a.image_id,'dockerAuthority':{'host':a.docker_host,'daemonId':a.docker_daemon},'runtimePins':{'node':{'path':a.node,'sha256':a.node_sha256},'docker':{'path':a.docker,'sha256':a.docker_sha256},'python':{'path':str(pathlib.Path(sys.executable).resolve()),'sha256':a.python_sha256}},'mcpTopology':t}
  receipt={'status':'passed','imageId':a.sandbox_image_id,'buildContext':context}
  with patch.object(m,'validate_mcp_arguments'),patch.object(m,'validate_mcp_host_authority'),patch.object(m,'digest',return_value='f'*64),patch('ctf_setup_sidecars.build_context',return_value=context),patch.object(pathlib.Path,'is_file',return_value=True),patch.object(pathlib.Path,'is_symlink',return_value=False),patch.object(pathlib.Path,'stat',return_value=SimpleNamespace(st_size=100)),patch.object(pathlib.Path,'read_text',return_value=json.dumps(receipt)):
   self.assertEqual(m.validate_mcp_manifest(v,a,root),t)
   selected=copy.copy(a);selected.mcp_profile='recon';selected.mcp_recon_70b=True
   v70={**v,'model':m.mcp_selected_model(selected)[0],'modelDigest':m.mcp_selected_model(selected)[1],'mcpRecon70b':True,'mcpReconTiming':copy.deepcopy(m.MCP_RECON_TIMING),'mcpProfile':'recon','caseIds':['recon-benign','recon-positive'],'wireCaseIds':['recon-benign','recon-positive','recon-named-refusal'],'inputSha256':m.MCP_RECON_INPUT_SHA256,'namedRefusalSha256':m.MCP_RECON_REFUSAL_SHA256,'wireBudget':{'chat':8,'generate':2,'tags':1,'version':0,'metadata':1,'external':11}}
   self.assertEqual(m.validate_mcp_manifest(v70,selected,root),t)
   for field,val in [('model',m.POLICY_MODEL),('modelDigest',m.POLICY_DIGEST)]:
    with self.assertRaises(RuntimeError):m.validate_mcp_manifest({**v70,field:val},selected,root)
   for key,val in [('runnerImage','bad'),('mailpitImage','bad'),('templates',{}),('buildContext',{}),('ssh',{**ssh,'strictHostKeyChecking':False})]:
    bad=copy.deepcopy(v);bad['mcpTopology'][key]=val
    with self.assertRaises(RuntimeError):m.validate_mcp_manifest(bad,a,root)
 def test_localhost_bypass_and_null_known_hosts_rejected_even_when_hash_matches(self):
  a=self.args()
  for bad in ('nohostauthenticationforlocalhost yes','userknownhostsfile /dev/null'):
   raw='stricthostkeychecking true\nbatchmode yes\npermitlocalcommand no\nnohostauthenticationforlocalhost no\nuserknownhostsfile /main/known-hosts\nglobalknownhostsfile /dev/null\nupdatehostkeys no\nhostname 127.0.0.1\nport 64173\n'
   key=bad.split()[0];raw='\n'.join(bad if l.startswith(key+' ') else l for l in raw.splitlines())+'\n'
   binding={'ssh':{'uid':501,'hostname':'127.0.0.1','port':64173,'resolvedConfigurationSha256':hashlib.sha256(raw.encode()).hexdigest()}}
   with self.assertRaisesRegex(RuntimeError,'strict SSH policy'):m.verify_mcp_ssh_runtime(a,binding,lambda argv:SimpleNamespace(returncode=0,stdout=raw))
  argv=m.mcp_ssh_argv(a);self.assertIn('NoHostAuthenticationForLocalhost=no',argv);self.assertIn('UserKnownHostsFile=/main/known-hosts',argv);self.assertIn('UpdateHostKeys=no',argv)
 def test_host_key_requires_exact_endpoint_and_control_plane_receipt(self):
  root=pathlib.Path('/main');ssh={'knownHosts':'/main/known-hosts','knownHostsSha256':'a'*64,'host':'owned-host','hostname':'127.0.0.1','port':64173,'daemonId':'daemon','hostKeyAuthority':{'path':'/main/authority','sha256':'b'*64}}
  receipt={'status':'authenticated-existing-vm-host-key','method':'local-vm-control-plane','knownHostsSha256':'a'*64,'sshHost':'owned-host','hostname':'127.0.0.1','port':64173}
  receipt.update(manifestSha256='c'*64,authority={'daemonId':'daemon'},knownHostsPath='/main/known-hosts',daemonId='daemon',cleanup={'status':'removed_absence_verified'})
  terminal={'status':'passed','cleanupVerified':True,'sourceUnchanged':True,'receiptSha256':'b'*64,'manifestSha256':'c'*64,'authority':{'daemonId':'daemon'}}
  key='[127.0.0.1]:64173 ssh-ed25519 YWJjZA=='
  def check(record,line,journal=None):
   with patch.object(m,'digest',return_value='b'*64),patch.object(pathlib.Path,'is_file',return_value=True),patch.object(pathlib.Path,'is_symlink',return_value=False),patch.object(pathlib.Path,'stat',return_value=SimpleNamespace(st_size=100)),patch.object(pathlib.Path,'read_text',lambda p:line if p.name=='known-hosts' else json.dumps(terminal if journal is None else journal) if p.name=='ownership.json' else json.dumps(record)):
    return m.validate_mcp_host_authority(ssh,root)
  check(receipt,key)
  for bad in ({}, {**terminal,'status':'failed'}, {**terminal,'cleanupVerified':False}, {**terminal,'receiptSha256':'f'*64}, {**terminal,'failure':'KeyboardInterrupt'}, {**terminal,'sourceUnchanged':False}, {**terminal,'authority':{}}):
   with self.assertRaises(RuntimeError):check(receipt,key,bad)
  for record in ({**receipt,'method':'ssh-keyscan'},{**receipt,'status':'observed-untrusted'},{**receipt,'knownHostsSha256':'wrong'},{**receipt,'port':1}):
   with self.assertRaises(RuntimeError):check(record,key)
  for line in (key.replace('64173','64174'),key+'\n'+key,'@cert-authority '+key,''):
   with self.assertRaises(RuntimeError):check(receipt,line)
 def test_remote_argument_encoding_preserves_shell_metacharacters(self):
  import shlex
  command=['stat','-c','%F|%a|%u|%h|%i|%s|%Y|%Z','--',"/tmp/owned path'quote;$HOME"]
  argv=m.mcp_remote_argv(self.args(),command)
  self.assertEqual(argv[-3:-1],['owned-host','--'])
  self.assertEqual(shlex.split(argv[-1]),command)
  lexer=shlex.shlex(argv[-1],posix=True,punctuation_chars=True);lexer.whitespace_split=True
  self.assertEqual(list(lexer),command)
  self.assertIn("'%F|%a|%u|%h|%i|%s|%Y|%Z'",argv[-1])
  for bad in ([],['bad\x00command'],['ok',1]):
   with self.assertRaises(ValueError):m.mcp_remote_argv(self.args(),bad)
 def test_original_selector_bounds_unchanged(self):
  for scenario,expected in [('finflow-traversal',(1320,1260,120)),('finflow-admission',(780,600,120)),('prospective-original',(780,600,120)),('restored-populated-upgrade',(1800,1740,120)),('ctf-populated',(2100,1800,180))]:self.assertEqual(m.scenario_bounds(scenario),expected)
if __name__=='__main__':
 with patch('subprocess.run',side_effect=AssertionError('process denied')),patch('subprocess.Popen',side_effect=AssertionError('process denied')),patch.object(socket,'socket',side_effect=AssertionError('socket denied')):unittest.main()

class SupplyControls(Controls):
 def test_supply_selector_environment_and_default_preserved(self):
  a=self.args();self.assertEqual(m.mcp_profile(a),'http');a.mcp_profile='supply-chain'
  self.assertEqual(m.mcp_profile(a),'supply-chain')
  with patch.object(pathlib.Path,'mkdir'):
   env=m.mcp_environment(a,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'a'*32,self.urls(),self.sidecars())
  self.assertEqual(env['MCP_MOUNTED_PROFILE'],'supply-chain')
  self.assertEqual(env['MCP_OBSERVED_ACTION_ENABLED'],'true');self.assertEqual(env['MCP_SUPPLY_CHAIN_ENABLED'],'true')
  a.scenario='codebot-current-representative'
  with self.assertRaises(ValueError):m.mcp_profile(a)
  a.scenario='mcp-mounted-http';a.mcp_profile='other'
  with self.assertRaises(ValueError):m.mcp_profile(a)
 def test_supply_exact_cases_accounting_and_lifecycle(self):
  v,w=self.receipt();q=v['qualification'];q.update(version='mcp-mounted-supply-chain-v1',profile='supply-chain',packageReadbackVerified=True,packageSiblingPreserved=True);q['cases']=q['cases'][:2]
  for row,name in zip(q['cases'],['supply-positive','supply-benign']):row.update(id=name,packageInstalls=1);row.pop('httpOperations')
  w['version']='mcp-mounted-supply-chain-wire-v1';w['counts'].update(generate=2,chat=2,external=5)
  w['calls']=[{'kind':k,'terminal':'returned'}for k in ('chat','generate','tags')for _ in range(w['counts'][k])]
  self.assertTrue(m.verify_mcp_result(v,w,'supply-chain'))
  with self.assertRaises(RuntimeError):m.verify_mcp_result(v,w)
  for mutate in [lambda x:x['qualification']['cases'].pop(),lambda x:x['qualification']['cases'][0].update(packageInstalls=0),lambda x:x['qualification']['cases'][0].update(packageInstalls=True),lambda x:x['qualification'].update(profile='http'),lambda x:x['qualification'].update(requestReplay=False),lambda x:x['qualification']['cases'][1].update(outcome='qualified')]:
   bad=copy.deepcopy(v);mutate(bad)
   with self.assertRaises(RuntimeError):m.verify_mcp_result(bad,w,'supply-chain')
  for key,val in [('external',24),('chat',21),('generate',3),('tags',2)]:
   bad=copy.deepcopy(w);bad['counts'][key]=val
   with self.assertRaises(RuntimeError):m.verify_mcp_result(v,bad,'supply-chain')

 def test_supply_manifest_frozen_input_and_budget(self):
  a=self.args();a.mcp_profile='supply-chain'
  value={'mcpProfile':'supply-chain','caseIds':['supply-positive','supply-benign'],'inputSha256':m.MCP_SUPPLY_INPUT_SHA256,'wireBudget':{'chat':20,'generate':2,'tags':1,'version':0,'metadata':1,'external':23}}
  self.assertEqual(m.validate_mcp_profile_manifest(value,a),'supply-chain')
  for key in value:
   bad=copy.deepcopy(value);bad.pop(key)
   with self.assertRaises(RuntimeError):m.validate_mcp_profile_manifest(bad,a)
  bad=copy.deepcopy(value);bad['wireBudget']['external']=24
  with self.assertRaises(RuntimeError):m.validate_mcp_profile_manifest(bad,a)
  a.mcp_profile=None
  with self.assertRaises(RuntimeError):m.validate_mcp_profile_manifest(value,a)
  self.assertEqual(m.validate_mcp_profile_manifest({},a),'http')


class PoisoningContrastControls(Controls):
 def contrast(self):
  v,w=self.receipt();q=v['qualification'];q.update(version='mcp-mounted-poisoning-contrast-v1',profile='poisoning-contrast',cleanMetadataBound=True,noConsequentialEffect=True,noProtectedOutput=True,noJudgeOrCredit=True)
  q['cases']=[{'id':'poisoning-clean','actualModelProof':True,'outcome':'clean_no_action','judgeCalls':0,'observations':1}]
  w.update(version='mcp-mounted-poisoning-contrast-wire-v1');w['counts'].update(chat=2,generate=1,external=4)
  w['calls']=[{'kind':k,'terminal':'returned'}for k in ('chat','generate','tags')for _ in range(w['counts'][k])]
  return v,w
 def test_contrast_manifest_environment_and_old_defaults(self):
  a=self.args();a.mcp_profile='poisoning-contrast'
  value={'mcpProfile':a.mcp_profile,'caseIds':['poisoning-clean'],'inputSha256':m.MCP_POISONING_INPUT_SHA256,'wireBudget':{'chat':4,'generate':1,'tags':1,'version':0,'metadata':1,'external':6}}
  self.assertEqual(m.validate_mcp_profile_manifest(value,a),a.mcp_profile)
  for key,val in [('caseIds',['sensitive-positive']),('inputSha256','0'*64),('wireBudget',{**value['wireBudget'],'chat':5})]:
   with self.assertRaises(RuntimeError):m.validate_mcp_profile_manifest({**value,key:val},a)
  with patch.object(pathlib.Path,'mkdir'):
   env=m.mcp_environment(a,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'a'*32,self.urls(),self.sidecars())
  self.assertEqual(env['MCP_OBSERVED_ACTION_ENABLED'],'true');self.assertNotIn('MCP_SUPPLY_CHAIN_ENABLED',env)
  self.assertEqual(m.scenario_bounds(a.scenario),(780,600,120));a.mcp_profile=None
  self.assertEqual(m.validate_mcp_profile_manifest({},a),'http')
  with self.assertRaises(RuntimeError):m.validate_mcp_profile_manifest(value,a)
 def test_contrast_rejects_judge_effect_credit_and_wrong_case(self):
  v,w=self.contrast();self.assertTrue(m.verify_mcp_result(v,w,'poisoning-contrast'))
  for key,val in [('judgeCalls',1),('judgeCalls',False),('observations',0),('observations',True),('outcome','qualified'),('actualModelProof',False),('id','supply-benign')]:
   bad=copy.deepcopy(v);bad['qualification']['cases'][0][key]=val
   with self.assertRaises(RuntimeError):m.verify_mcp_result(bad,w,'poisoning-contrast')
  for key in ('cleanMetadataBound','noConsequentialEffect','noProtectedOutput','noJudgeOrCredit','generationAdvanced','requestReplay','revokedSessionDenied','resetSiblingHistoryPreserved'):
   bad=copy.deepcopy(v);bad['qualification'][key]=False
   with self.assertRaises(RuntimeError):m.verify_mcp_result(bad,w,'poisoning-contrast')
  for profile in ('http','supply-chain'):
   with self.assertRaises(RuntimeError):m.verify_mcp_result(v,w,profile)
 def test_contrast_wire_bounds_and_retirement(self):
  v,w=self.contrast()
  for key,val in [('chat',5),('chat',0),('generate',0),('generate',2),('tags',2),('version',1),('external',7),('metadata',True)]:
   bad=copy.deepcopy(w);bad['counts'][key]=val
   with self.assertRaises(RuntimeError):m.verify_mcp_result(v,bad,'poisoning-contrast')
  for key,val in [('physicalPending',1),('closed',False),('digest','wrong'),('failures',[{}])]:
   with self.assertRaises(RuntimeError):m.verify_mcp_result(v,{**w,key:val},'poisoning-contrast')
  bad=copy.deepcopy(w);bad['calls'][0]['terminal']='pending'
  with self.assertRaises(RuntimeError):m.verify_mcp_result(v,bad,'poisoning-contrast')

class PoisoningPositiveControls(unittest.TestCase):
 def receipt(self):
  v,w=PoisoningContrastControls().contrast();q=v['qualification'];q.update(version='mcp-mounted-poisoning-positive-v1',profile='poisoning-positive',poisonedMetadataBound=True,privateWitnessBound=True,canonicalAwardBound=True)
  for k in ('cleanMetadataBound','noConsequentialEffect','noProtectedOutput','noJudgeOrCredit'):q.pop(k)
  q['cases'][0].update(id='poisoning-positive',outcome='qualified',judgeCalls=1,consequences=1)
  w['version']='mcp-mounted-poisoning-positive-wire-v1';w['counts'].update(chat=3,external=5);w['calls']=[{'kind':k,'terminal':'returned'}for k in ('chat','generate','tags')for _ in range(w['counts'][k])]
  return v,w
 def test_positive_exact_award_witness_and_consequence(self):
  v,w=self.receipt();self.assertTrue(m.verify_mcp_result(v,w,'poisoning-positive'))
  for k,val in [('judgeCalls',0),('judgeCalls',True),('judgeCalls',3),('observations',0),('consequences',0),('consequences',True),('outcome','resisted')]:
   bad=copy.deepcopy(v);bad['qualification']['cases'][0][k]=val
   with self.assertRaises(RuntimeError):m.verify_mcp_result(bad,w,'poisoning-positive')
  for k in ('poisonedMetadataBound','privateWitnessBound','canonicalAwardBound','requestReplay','resetSiblingHistoryPreserved','ownedResourcesRetired'):
   bad=copy.deepcopy(v);bad['qualification'][k]=False
   with self.assertRaises(RuntimeError):m.verify_mcp_result(bad,w,'poisoning-positive')
  with self.assertRaises(RuntimeError):m.verify_mcp_result(v,w,'poisoning-contrast')
 def test_positive_manifest_wire_environment_and_old_profiles(self):
  a=Controls().args();a.mcp_profile='poisoning-positive';value={'mcpProfile':a.mcp_profile,'caseIds':['poisoning-positive'],'inputSha256':m.MCP_POISONING_POSITIVE_INPUT_SHA256,'wireBudget':{'chat':6,'generate':1,'tags':1,'version':0,'metadata':1,'external':8}}
  self.assertEqual(m.validate_mcp_profile_manifest(value,a),a.mcp_profile)
  for k,val in [('caseIds',['poisoning-clean']),('inputSha256',m.MCP_POISONING_INPUT_SHA256),('wireBudget',{**value['wireBudget'],'external':9})]:
   with self.assertRaises(RuntimeError):m.validate_mcp_profile_manifest({**value,k:val},a)
  with patch.object(pathlib.Path,'mkdir'):env=m.mcp_environment(a,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'a'*32,Controls().urls(),Controls().sidecars())
  self.assertEqual(env['MCP_OBSERVED_ACTION_ENABLED'],'true');self.assertNotIn('MCP_SUPPLY_CHAIN_ENABLED',env);self.assertEqual(m.scenario_bounds(a.scenario),(780,600,120))
  v,w=self.receipt()
  for k,val in [('chat',7),('chat',2),('external',9),('generate',2),('tags',0),('version',1)]:
   bad=copy.deepcopy(w);bad['counts'][k]=val
   with self.assertRaises(RuntimeError):m.verify_mcp_result(v,bad,'poisoning-positive')

class ReconControls(unittest.TestCase):
 def receipt(self):
  v,w=PoisoningPositiveControls().receipt();q=v['qualification'];q.update(version='mcp-mounted-recon-v1',profile='recon',catalogWitnessBound=True,rawPacketBound=True,judgeOnlyNamedRefusal={'verdict':'fail','judgeCalls':1,'durableWrite':False,'newSdkCall':False})
  for k in ('poisonedMetadataBound','privateWitnessBound','canonicalAwardBound'):q.pop(k)
  q['cases']=[{'id':'recon-benign','actualModelProof':True,'outcome':'benign_no_credit','judgeCalls':0,'catalogObservations':0},{'id':'recon-positive','actualModelProof':True,'outcome':'qualified','judgeCalls':1,'catalogObservations':1}]
  w['version']='mcp-mounted-recon-wire-v1';w['counts'].update(chat=4,generate=2,external=7);w['calls']=[{'kind':'tags','terminal':'returned','caseId':None}]+[{'kind':kind,'terminal':'returned','caseId':phase}for phase,kinds in [('recon-benign',['chat','generate']),('recon-positive',['chat','generate','chat']),('recon-named-refusal',['chat'])]for kind in kinds]
  return v,w
 def test_recon_receipt_positive_benign_and_isolated_refusal(self):
  v,w=self.receipt();self.assertTrue(m.verify_mcp_result(v,w,'recon'))
  for index,k,val in [(1,'judgeCalls',0),(1,'catalogObservations',0),(0,'judgeCalls',1),(0,'outcome','qualified'),(0,'catalogObservations',1),(0,'judgeCalls',False)]:
   bad=copy.deepcopy(v);bad['qualification']['cases'][index][k]=val
   with self.assertRaises(RuntimeError):m.verify_mcp_result(bad,w,'recon')
  for k,val in [('verdict','pass'),('judgeCalls',0),('judgeCalls',True),('durableWrite',True),('newSdkCall',True)]:
   bad=copy.deepcopy(v);bad['qualification']['judgeOnlyNamedRefusal'][k]=val
   with self.assertRaises(RuntimeError):m.verify_mcp_result(bad,w,'recon')
  for k in ('catalogWitnessBound','rawPacketBound','generationAdvanced','resetSiblingHistoryPreserved'):
   bad=copy.deepcopy(v);bad['qualification'][k]=False
   with self.assertRaises(RuntimeError):m.verify_mcp_result(bad,w,'recon')
  for profile in ('http','supply-chain','poisoning-contrast','poisoning-positive'):
   with self.assertRaises(RuntimeError):m.verify_mcp_result(v,w,profile)
 def test_recon_exact_inputs_budget_and_default_environment(self):
  a=Controls().args();a.mcp_profile='recon';value={'mcpProfile':'recon','caseIds':['recon-benign','recon-positive'],'wireCaseIds':['recon-benign','recon-positive','recon-named-refusal'],'inputSha256':m.MCP_RECON_INPUT_SHA256,'namedRefusalSha256':m.MCP_RECON_REFUSAL_SHA256,'wireBudget':{'chat':8,'generate':2,'tags':1,'version':0,'metadata':1,'external':11}}
  self.assertEqual(m.validate_mcp_profile_manifest(value,a),'recon')
  for k,val in [('caseIds',['recon-positive']),('inputSha256','0'*64),('namedRefusalSha256','0'*64),('wireBudget',{**value['wireBudget'],'chat':9})]:
   with self.assertRaises(RuntimeError):m.validate_mcp_profile_manifest({**value,k:val},a)
  with patch.object(pathlib.Path,'mkdir'):env=m.mcp_environment(a,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'a'*32,Controls().urls(),Controls().sidecars())
  self.assertEqual(env['MCP_MOUNTED_PROFILE'],'recon');self.assertNotIn('MCP_OBSERVED_ACTION_ENABLED',env);self.assertNotIn('MCP_SUPPLY_CHAIN_ENABLED',env);self.assertEqual(m.scenario_bounds(a.scenario),(780,600,120))
  v,w=self.receipt()
  for k,val in [('chat',9),('chat',3),('generate',1),('generate',3),('external',12),('version',1)]:
   bad=copy.deepcopy(w);bad['counts'][k]=val
   with self.assertRaises(RuntimeError):m.verify_mcp_result(v,bad,'recon')

 def test_recon_unknown_or_actor_refusal_wire_phase_denied(self):
  v,w=self.receipt()
  for index,key,val in [(1,'caseId','unknown'),(0,'caseId','recon-positive'),(6,'caseId','recon-positive'),(1,'caseId','recon-positive')]:
   bad=copy.deepcopy(w);bad['calls'][index][key]=val
   with self.assertRaises(RuntimeError):m.verify_mcp_result(v,bad,'recon')

class Recon70BControls(unittest.TestCase):
 def test_closed_selection_manifest_and_wire(self):
  a=Controls().args();a.mcp_profile='recon';a.mcp_recon_70b=True
  model,digest=m.mcp_selected_model(a);self.assertEqual(model,'llama3.3:70b')
  for profile in ['http','supply-chain','poisoning-positive','poisoning-contrast',None]:
   bad=copy.copy(a);bad.mcp_profile=profile
   with self.assertRaises(ValueError):m.mcp_selected_model(bad)
  v,w=ReconControls().receipt();v['mcpReconTiming']=copy.deepcopy(m.MCP_RECON_TIMING);w.update(model=model,digest=digest,timing=copy.deepcopy(m.MCP_RECON_TIMING));self.assertTrue(m.verify_mcp_result(v,w,'recon',True))
  with self.assertRaises(RuntimeError):m.verify_mcp_result(v,w,'recon')
  with self.assertRaises(RuntimeError):m.verify_mcp_result(v,w,'http',True)
  w['digest']='0'*64
  with self.assertRaises(RuntimeError):m.verify_mcp_result(v,w,'recon',True)
  with patch.object(pathlib.Path,'mkdir'):env=m.mcp_environment(a,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'a'*32,Controls().urls(),Controls().sidecars())
  self.assertEqual(env['MCP_RECON_70B'],'1');self.assertEqual(m.scenario_bounds(a.scenario),(780,600,120));self.assertEqual(m.scenario_bounds(a.scenario,recon70b=True),(960,840,120))
  manifest={'mcpRecon70b':True,'mcpReconTiming':copy.deepcopy(m.MCP_RECON_TIMING),'mcpProfile':'recon','caseIds':['recon-benign','recon-positive'],'wireCaseIds':['recon-benign','recon-positive','recon-named-refusal'],'inputSha256':m.MCP_RECON_INPUT_SHA256,'namedRefusalSha256':m.MCP_RECON_REFUSAL_SHA256,'wireBudget':{'chat':8,'generate':2,'tags':1,'version':0,'metadata':1,'external':11}}
  m.validate_mcp_profile_manifest(manifest,a)
  for val in [False,1,'true',None]:
   with self.assertRaises(RuntimeError):m.validate_mcp_profile_manifest({**manifest,'mcpRecon70b':val},a)

class ReconTimingControls(unittest.TestCase):
 def test_exact_production_keys_and_budget_relationships(self):
  t=m.MCP_RECON_TIMING
  self.assertEqual((t['decisionMs'],t['responseMs'],t['runMs'],t['judgeMs']),(90000,90000,290000,90000))
  self.assertGreater(t['caseMs'],t['runMs']);self.assertGreater(t['wireMs'],max(t['decisionMs'],t['responseMs'],t['judgeMs']));self.assertGreater(t['refusalCaseMs'],t['wireMs']);self.assertGreater(t['totalMs'],2*t['runMs']+t['judgeMs']);self.assertGreater(t['childSeconds']*1000,t['totalMs']);self.assertGreater(t['parentSeconds'],t['childSeconds'])
  a=Controls().args();a.mcp_profile='recon';a.mcp_recon_70b=True
  with patch.object(pathlib.Path,'mkdir'):env=m.mcp_environment(a,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'a'*32,Controls().urls(),Controls().sidecars())
  self.assertEqual({k:env[k]for k in ['MCP_DECISION_TIMEOUT_MS','MCP_RESPONSE_TIMEOUT_MS','MCP_RUN_TIMEOUT_MS']},{'MCP_DECISION_TIMEOUT_MS':'90000','MCP_RESPONSE_TIMEOUT_MS':'90000','MCP_RUN_TIMEOUT_MS':'290000'})
  manifest={'mcpRecon70b':True,'mcpReconTiming':copy.deepcopy(t),'mcpProfile':'recon','caseIds':['recon-benign','recon-positive'],'wireCaseIds':['recon-benign','recon-positive','recon-named-refusal'],'inputSha256':m.MCP_RECON_INPUT_SHA256,'namedRefusalSha256':m.MCP_RECON_REFUSAL_SHA256,'wireBudget':{'chat':8,'generate':2,'tags':1,'version':0,'metadata':1,'external':11}}
  for key in t:
   bad=copy.deepcopy(manifest);bad['mcpReconTiming'][key]+=1
   with self.assertRaises(RuntimeError):m.validate_mcp_profile_manifest(bad,a)
  for timing in [None,{},dict(t,decisionMs='90000'),dict(t,unexpected=1)]:
   with self.assertRaises(RuntimeError):m.validate_mcp_profile_manifest({**manifest,'mcpReconTiming':timing},a)
  a.mcp_recon_70b=False
  with self.assertRaises(RuntimeError):m.validate_mcp_profile_manifest(manifest,a)
  with patch.object(pathlib.Path,'mkdir'):default=m.mcp_environment(a,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'a'*32,Controls().urls(),Controls().sidecars())
  self.assertNotIn('MCP_DECISION_TIMEOUT_MS',default)
  with self.assertRaises(ValueError):m.scenario_bounds('codebot-current-clean-fixed',recon70b=True)

class ReconJudge120Controls(unittest.TestCase):
 def test_exact_optin_env_manifest_receipt_and_bounds(self):
  a=Controls().args();a.mcp_profile='recon';a.mcp_recon_70b=True;a.mcp_recon_judge_120=True
  t=m.MCP_RECON_120_TIMING
  self.assertEqual(m.scenario_bounds(a.scenario,recon70b=True,reconJudge120=True),(990,870,120));self.assertEqual(t['totalMs']-2*t['runMs']-t['judgeMs'],50000)
  with patch.object(pathlib.Path,'mkdir'):env=m.mcp_environment(a,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'a'*32,Controls().urls(),Controls().sidecars())
  self.assertEqual(env['MCP_RECON_JUDGE_120'],'1');self.assertEqual(env['MCP_RECON_JUDGE_TIMEOUT_MS'],'120000')
  manifest={'mcpRecon70b':True,'mcpReconJudge120':True,'mcpReconTiming':copy.deepcopy(t),'mcpProfile':'recon','caseIds':['recon-benign','recon-positive'],'wireCaseIds':['recon-benign','recon-positive','recon-named-refusal'],'inputSha256':m.MCP_RECON_INPUT_SHA256,'namedRefusalSha256':m.MCP_RECON_REFUSAL_SHA256,'wireBudget':{'chat':8,'generate':2,'tags':1,'version':0,'metadata':1,'external':11}}
  self.assertEqual(m.validate_mcp_profile_manifest(manifest,a),'recon')
  for key in t:
   bad=copy.deepcopy(manifest);bad['mcpReconTiming'][key]+=1
   with self.assertRaises(RuntimeError):m.validate_mcp_profile_manifest(bad,a)
  v,w=ReconControls().receipt();v['mcpReconTiming']=copy.deepcopy(t);w.update(model=m.mcp_selected_model(a)[0],digest=m.mcp_selected_model(a)[1],timing=copy.deepcopy(t));self.assertTrue(m.verify_mcp_result(v,w,'recon',True,True))
  with self.assertRaises(RuntimeError):m.verify_mcp_result(v,w,'recon',True)
  with self.assertRaises(ValueError):m.verify_mcp_result(v,w,'recon',False,True)
  a.mcp_recon_judge_120=False
  with self.assertRaises(RuntimeError):m.validate_mcp_profile_manifest(manifest,a)
  with patch.object(pathlib.Path,'mkdir'):env=m.mcp_environment(a,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'a'*32,Controls().urls(),Controls().sidecars())
  self.assertNotIn('MCP_RECON_JUDGE_TIMEOUT_MS',env);self.assertEqual(m.scenario_bounds(a.scenario,recon70b=True),(960,840,120))
  a.mcp_recon_judge_120=True;a.mcp_recon_70b=False
  with self.assertRaises(ValueError):m.mcp_profile(a)
  with self.assertRaises(ValueError):m.scenario_bounds('mcp-mounted-http',reconJudge120=True)
