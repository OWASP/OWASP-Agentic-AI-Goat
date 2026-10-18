"""Pure CodeBot parent admission controls; no resource creation."""
import copy, json, pathlib, sys, unittest, hashlib
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import mcp_mounted_http_launcher_test as existing
m=existing.m
class Controls(unittest.TestCase):
 def args(self):
  a=existing.Controls().args();a.scenario='codebot-current-representative';return a
 def urls(self):
  values={}
  for store in ('identity','supply_chain'):values.update(m.codebot_current_store_configuration(store,55432,'a'*12)[1])
  return values
 def test_exact_two_stores_private_environment(self):
  sql=''.join(m.codebot_current_store_configuration(store,55432,'a'*12)[0]for store in ('identity','supply_chain'))
  self.assertEqual(sql.count('CREATE DATABASE'),2);self.assertEqual(sql.count('CREATE ROLE'),4)
  with patch.object(pathlib.Path,'mkdir'):
   env=m.codebot_current_environment(self.args(),pathlib.Path('/e'),pathlib.Path('/e/runtime'),'a'*32,self.urls(),{'SANDBOX_RUNNER_URL':'http://127.0.0.1:55001'})
  self.assertEqual(env['CODEBOT_SANDBOX_RUNNER_URL'],env['SANDBOX_RUNNER_URL']);self.assertEqual(env['CODEBOT_OWNED_EXECUTION_ENABLED'],'true');self.assertEqual(env['LOGS_DIR'],'/e/runtime/logs')
  self.assertEqual({k for k in env if k.endswith('DATABASE_URL')},set(self.urls()))
  for key in ('PG_ADMIN_DATABASE_URL','OPENAI_API_KEY','SSH_AUTH_SOCK','MCP_OWNED_HTTP_URL','MAILPIT_API_URL','DVAIA_ISOLATED_TEST_WORKSPACE'):self.assertNotIn(key,env)
 def test_wrong_urls_and_unowned_endpoint_fail_before_allocation(self):
  for key in self.urls():
   for old,new in [('55432','55433'),('a'*12,'b'*12),('_runtime','_migration')if '_runtime' in self.urls()[key]else('_migration','_runtime')]:
    bad=self.urls();bad[key]=bad[key].replace(old,new)
    with patch.object(pathlib.Path,'mkdir',side_effect=AssertionError('allocation')),self.assertRaises(RuntimeError):m.codebot_current_environment(self.args(),pathlib.Path('/e'),pathlib.Path('/e/runtime'),'a'*32,bad,{'SANDBOX_RUNNER_URL':'http://127.0.0.1:55001'})
  for endpoint in ('http://host:55001','http://127.0.0.1:55432','http://127.0.0.1:55001/path','http://user:secret@127.0.0.1:55001'):
   with patch.object(pathlib.Path,'mkdir',side_effect=AssertionError('allocation')),self.assertRaises(RuntimeError):m.codebot_current_environment(self.args(),pathlib.Path('/e'),pathlib.Path('/e/runtime'),'a'*32,self.urls(),{'SANDBOX_RUNNER_URL':endpoint})
 def test_closed_selector_bounds_and_journal_before_stdin(self):
  a=self.args();m.validate_original_case(a);self.assertEqual(m.scenario_bounds(a.scenario),(780,420,120));self.assertEqual(m.scenario_command(a),['/node','/main/tests/postgres/codeBotCurrentMain.js'])
  for key,value in [('main_workspace',False),('policy_cohort','plain'),('browser','/browser'),('python_sha256',None)]:
   bad=copy.copy(a);setattr(bad,key,value)
   with self.assertRaises(ValueError):m.validate_original_case(bad)
  seen=[];pipe=SimpleNamespace(write=lambda v:seen.append(v),flush=lambda:None,close=lambda:None);state={}
  m.publish_child_start(SimpleNamespace(pid=17,stdin=pipe),state,lambda:seen.append(dict(state)),a.scenario)
  self.assertEqual(seen,[{'nativeStarted':True,'nativePid':17},b'1'])
 def test_current_manifest_requires_cli_only_authenticated_topology(self):
  a=self.args();root=pathlib.Path('/main');context={'entries':{'Dockerfile':{'sha256':'x'}}}
  ssh={'executable':a.ssh,'sha256':a.ssh_sha256,'config':a.ssh_config,'configSha256':a.ssh_config_sha256,'host':a.ssh_host,'daemonId':a.docker_daemon,'strictHostKeyChecking':True,'noHostAuthenticationForLocalhost':False,'knownHosts':a.ssh_known_hosts,'knownHostsSha256':a.ssh_known_hosts_sha256,'uid':501,'resolvedConfigurationSha256':'e'*64}
  topology={'runnerImage':a.sandbox_image_id,'mailpitImage':None,'ssh':ssh,'templates':{'cli':{'path':m.MCP_TEMPLATES['cli'],'sha256':'f'*64}},'buildContext':context,'buildReceipt':{'path':'/main/receipt','sha256':'f'*64}}
  v={'cohort':a.scenario,'mode':'actual-model','model':m.POLICY_MODEL,'modelDigest':m.POLICY_DIGEST,'imageId':a.image_id,'dockerAuthority':{'host':a.docker_host,'daemonId':a.docker_daemon},'runtimePins':{'node':{'path':a.node,'sha256':a.node_sha256},'docker':{'path':a.docker,'sha256':a.docker_sha256},'python':{'path':str(pathlib.Path(sys.executable).resolve()),'sha256':a.python_sha256}},'mcpTopology':topology}
  receipt={'status':'passed','imageId':a.sandbox_image_id,'buildContext':context}
  with patch.object(m,'validate_mcp_arguments'),patch.object(m,'validate_mcp_host_authority')as authority,patch.object(m,'digest',return_value='f'*64),patch('ctf_setup_sidecars.build_context',return_value=context),patch.object(pathlib.Path,'is_file',return_value=True),patch.object(pathlib.Path,'is_symlink',return_value=False),patch.object(pathlib.Path,'stat',return_value=SimpleNamespace(st_size=100)),patch.object(pathlib.Path,'read_text',return_value=json.dumps(receipt)):
   self.assertEqual(m.validate_mcp_manifest(v,a,root),topology);authority.assert_called_once_with(ssh,root)
   for key,val in [('cohort','mcp-mounted-http'),('model','other'),('modelDigest','bad'),('mode','model-free'),('runtimePins',{})]:
    with self.assertRaises(RuntimeError):m.validate_mcp_manifest({**v,key:val},a,root)
   for key,val in [('mailpitImage',m.MCP_MAILPIT_IMAGE),('templates',{}),('buildContext',{}),('ssh',{**ssh,'noHostAuthenticationForLocalhost':True})]:
    bad=copy.deepcopy(v);bad['mcpTopology'][key]=val
    with self.assertRaises(RuntimeError):m.validate_mcp_manifest(bad,a,root)
 def history(self,full=False):
  if full and hasattr(self,'_full_history'):return self._full_history
  raw=json.dumps({'effects':[{'status':'completed'}]*(3 if full else 1),'requests':[{'status':'completed'}]*(7 if full else 2),'judgments':[],'packets':[]}).encode();return {'before':raw,'after':raw}
 def receipt(self):
  value={'status':'passed','installedWrites':False,'actualModelProof':True,'controlsPassed':True,'cleanupFailures':[],'cleanup':[{'resource':k,'status':'fulfilled'}for k in ('http','shared-pools','pool-0','pool-1','pool-2','pool-3')],'qualification':{'version':'codebot-current-representative-v1','cases':['rce_cmd','clean_request'],'rendered':False,'allSixQualification':False,'semanticFailures':[],'skippedDependencies':[]}}
  calls=[{'kind':'tags','terminal':'returned','status':200,'responseComplete':True,'responseCaptureTruncated':False}];captures=[]
  for i,case in enumerate(('rce_cmd','clean_request')):
   owner=i+1;run='run-'+case;evaluation='evaluation-'+case
   calls.extend({'kind':'chat','caseId':case,'request':json.dumps({'options':{'num_predict':predict}}),'terminal':'returned','status':200,'responseComplete':True,'responseCaptureTruncated':False}for predict in (1024,900))
   captures.append({'userId':owner,'wireBinding':{'actorCalls':1,'judgeCalls':1,'runId':run,'evaluationIds':[evaluation]},'body':{'run':{'runId':run},'judgments':[{'evaluationId':evaluation}]},'runs':[{'run_id':run,'owner_key':json.dumps(['CodeBot',str(owner)],separators=(',',':'))}],'judgments':[{'evaluation_id':evaluation,'run_id':run}],'packets':[{'evaluation_id':evaluation,'user_id':owner}]})
  wire={'version':'codebot-current-wire-v1','model':m.POLICY_MODEL,'digest':m.POLICY_DIGEST,'closed':True,'physicalPending':0,'failures':[],'counts':{'external':5,'chat':4,'generate':0,'tags':1,'version':0,'metadata':1},'calls':calls}
  value['qualification'].update(completedEffectCount=1,completedJournalCount=2,immutableHistoryPreserved=True,immutableHistory={k:{'sha256':hashlib.sha256(v).hexdigest(),'bytes':len(v)}for k,v in self.history().items()})
  return value,wire,captures
 def test_exact_terminal_cleanup_and_provenance(self):
  value,wire,captures=self.receipt();self.assertTrue(m.verify_codebot_current_result(value,wire,captures,history=self.history()))
  for mutate in (lambda x:x['cleanup'].pop(),lambda x:x['qualification'].update(allSixQualification=True),lambda x:x['qualification']['cases'].reverse(),lambda x:x['qualification']['semanticFailures'].append({}),lambda x:x['qualification']['skippedDependencies'].append({'check':'reset:sibling_progress_preservation'}),lambda x:x.update(actualModelProof=False)):
   bad=copy.deepcopy(value);mutate(bad)
   with self.assertRaises(RuntimeError):m.verify_codebot_current_result(bad,wire,captures,history=self.history())
  for mutate in (lambda x:x[0]['wireBinding'].update(actorCalls=0),lambda x:x[0]['runs'][0].update(owner_key='other'),lambda x:x[0]['packets'].clear(),lambda x:x[0]['judgments'][0].update(run_id='other'),lambda x:x.pop()):
   bad=copy.deepcopy(captures);mutate(bad)
   with self.assertRaises(RuntimeError):m.verify_codebot_current_result(value,wire,bad,history=self.history())
 def test_exact_physical_wire_and_quota(self):
  value,wire,captures=self.receipt()
  for mutate in (lambda x:x.update(closed=False),lambda x:x.update(physicalPending=1),lambda x:x['calls'][0].update(status=503),lambda x:x['calls'][1].update(caseId='other'),lambda x:x['counts'].update(chat=41,external=42),lambda x:x.update(digest='other'),lambda x:x['calls'][1].update(request=json.dumps({'options':{'num_predict':1500}}))):
   bad=copy.deepcopy(wire);mutate(bad)
   with self.assertRaises(RuntimeError):m.verify_codebot_current_result(value,bad,captures,history=self.history())
 def test_other_selectors_unchanged(self):
  self.assertEqual(m.scenario_bounds('mcp-mounted-http'),(780,600,120));self.assertEqual(m.scenario_bounds('finflow-traversal'),(1320,1260,120));self.assertEqual(m.scenario_fixture('codebot-rendered-parity'),'tests/postgres/codeBotRenderedParityMainV1.js')
class FullSixControls(Controls):
 def args(self):
  a=super().args();a.scenario='codebot-current-full-six';return a
 def test_full_scope_environment_and_limits(self):
  a=self.args();m.validate_original_case(a)
  self.assertEqual(m.scenario_bounds(a.scenario),(780,420,120))
  with patch.object(pathlib.Path,'mkdir'):
   env=m.codebot_current_environment(a,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'a'*32,self.urls(),{'SANDBOX_RUNNER_URL':'http://127.0.0.1:55001'})
  self.assertEqual(env['CODEBOT_LIVE_SCOPE'],'all')
  self.assertEqual(m.scenario_command(a),['/node','/main/tests/postgres/codeBotCurrentMain.js'])
 def full_receipt(self):
  value,wire,old=self.receipt();cases=['tool_list','pkg_discover','clean_request','rce_env','rce_ssh','rce_cmd','sibling:clean_request']
  value['qualification'].update(version='codebot-current-full-six-v1',cases=cases,allSixQualification=True,completedEffectCount=3,completedJournalCount=7,primaryCompletionIds=sorted(cases[:6]),immutableHistory={k:{'sha256':hashlib.sha256(v).hexdigest(),'bytes':len(v)}for k,v in self.history(full=True).items()})
  captures=[];calls=wire['calls'][:1]
  for i,case in enumerate(cases):
   c=copy.deepcopy(old[0]);owner=2 if i==6 else 1;run='run-'+case;evaluation='evaluation-'+case
   c.update(caseId=case,userId=owner);c['body']={'run':{'runId':run},'judgments':[{'evaluationId':evaluation}]}
   c['wireBinding'].update(runId=run,evaluationIds=[evaluation]);c['runs']=[{'run_id':run,'owner_key':json.dumps(['CodeBot',str(owner)],separators=(',',':'))}]
   c['judgments']=[{'evaluation_id':evaluation,'run_id':run}];c['packets']=[{'evaluation_id':evaluation,'user_id':owner}]
   c['requests']=[{'run_id':run,'user_id':owner,'status':'completed'}]
   c['effects']=[{'run_id':run,'owner_key':json.dumps(['CodeBot',str(owner)],separators=(',',':')),'status':'completed'}] if case in ('rce_env','rce_ssh','rce_cmd') else []
   c['completions']=[{'objective_id':k,'user_id':1,'workshop_key':'supply_chain_rce'}for k in cases[:6]] if i==5 else []
   captures.append(c)
   calls.extend({**row,'caseId':case}for row in wire['calls'][1:3])
  wire.update(version='codebot-current-full-six-wire-v1',calls=calls,counts={'external':15,'chat':14,'generate':0,'tags':1,'version':0,'metadata':1})
  # Match production cumulative owner snapshots at the final primary case.
  for key in ('effects','requests','judgments','packets'):
   captures[5][key]=[row for c in captures[:6]for row in c[key]]
  self.bind_full_history(value,captures)
  return value,wire,captures
 def bind_full_history(self,value,captures):
  raw=json.dumps({k:captures[5][k]+captures[6][k]for k in ('effects','requests','judgments','packets')},sort_keys=True).encode()
  self._full_history={'before':raw,'after':raw}
  value['qualification']['immutableHistory']={k:{'sha256':hashlib.sha256(v).hexdigest(),'bytes':len(v)}for k,v in self._full_history.items()}
 def test_full_scope_rejects_partial_reordered_and_wrong_owner_receipts(self):
  v,w,c=self.full_receipt();self.assertTrue(m.verify_codebot_current_result(v,w,c,self.args().scenario,history=self.history(full=True)))
  for mutate in (lambda x:x.pop(),lambda x:x.reverse(),lambda x:x[2].update(caseId='rce_cmd'),lambda x:x[3].update(userId=3),lambda x:x[-1].update(userId=1),lambda x:x[3]['effects'].clear(),lambda x:x[0]['requests'].clear(),lambda x:x[5]['completions'].pop()):
   bad=copy.deepcopy(c);mutate(bad)
   with self.assertRaises(RuntimeError):m.verify_codebot_current_result(v,w,bad,self.args().scenario,history=self.history(full=True))
  with self.assertRaises(RuntimeError):m.verify_codebot_current_result(v,w,c,history=self.history())
  with self.assertRaises(RuntimeError):m.verify_codebot_current_result(*self.receipt(),self.args().scenario,history=self.history(full=True))
 def test_history_and_effect_counts_are_bound(self):
  v,w,c=self.full_receipt()
  for key,val in [('primaryCompletionIds',[]),('completedEffectCount',2),('completedJournalCount',6),('immutableHistoryPreserved',False),('immutableHistory',{})]:
   bad=copy.deepcopy(v);bad['qualification'][key]=val
   with self.assertRaises(RuntimeError):m.verify_codebot_current_result(bad,w,c,self.args().scenario,history=self.history(full=True))
  for history in (None,{'before':b'{}','after':b'{"changed":true}'}):
   with self.assertRaises(RuntimeError):m.verify_codebot_current_result(v,w,c,self.args().scenario,history=history)
 def test_repeated_completion_retains_original_bound_award(self):
  v,w,c=self.full_receipt();old=c[3];later=c[5]
  old['judgments'][0].update(objective_id='rce_cmd',disposition='awarded',verdict='pass',generation=1)
  original={'objective_id':'rce_cmd','user_id':1,'workshop_key':'supply_chain_rce','completed_at':'retained-original'}
  old['completions']=[copy.deepcopy(original)]
  later['judgments']=[copy.deepcopy(old['judgments'][0]) if j['run_id']==old['wireBinding']['runId'] else j for j in later['judgments']]
  next(j for j in later['judgments']if j['run_id']==later['wireBinding']['runId']).update(objective_id='rce_cmd',disposition='already_complete',verdict='pass',generation=1)
  later['completions']=[copy.deepcopy(original)if x['objective_id']=='rce_cmd' else x for x in later['completions']]
  self.bind_full_history(v,c)
  self.assertTrue(m.verify_codebot_current_result(v,w,c,self.args().scenario,history=self.history(full=True)))
  for mutate in (lambda x:x[3]['judgments'][0].update(disposition='failed'),lambda x:x[5]['judgments'][0].update(generation=2),lambda x:x[5]['completions'][-1].update(completed_at='rewritten'),lambda x:x[5]['judgments'].pop()):
   bad=copy.deepcopy(c);mutate(bad)
   with self.assertRaises(RuntimeError):m.verify_codebot_current_result(v,w,bad,self.args().scenario,history=self.history(full=True))
 def test_full_scope_retains_closed_wire_cap(self):
  v,w,c=self.full_receipt()
  for mutate in (lambda x:x['counts'].update(chat=141,external=142),lambda x:x.update(version='codebot-current-wire-v1'),lambda x:x['calls'][1].update(caseId='unknown')):
   bad=copy.deepcopy(w);mutate(bad)
   with self.assertRaises(RuntimeError):m.verify_codebot_current_result(v,bad,c,self.args().scenario,history=self.history(full=True))
class CleanFixedControls(unittest.TestCase):
 def test_closed_main_environment_and_routing(self):
  helper=Controls();a=helper.args();a.scenario='codebot-current-clean-fixed'
  m.validate_original_case(a)
  self.assertEqual(m.scenario_fixture(a.scenario),'tests/postgres/codeBotCurrentMain.js')
  self.assertEqual(m.scenario_bounds(a.scenario),(780,420,120))
  with patch.object(pathlib.Path,'mkdir'):
   env=m.codebot_current_environment(a,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'a'*32,helper.urls(),{'SANDBOX_RUNNER_URL':'http://127.0.0.1:55001'})
  self.assertEqual(env['CODEBOT_LIVE_SCOPE'],'clean-fixed');self.assertNotIn('CODEBOT_LIVE_FIXED_CONTROL',env)
  a.main_workspace=False
  with self.assertRaises(ValueError):m.validate_original_case(a)
 def test_exact_fixed_receipt_and_foreign_owner_denial(self):
  value,wire,captures=Controls().receipt();cases=['clean_request','fixed:transform-denial'];owner=1
  award={'evaluation_id':'positive','run_id':'positive-run','objective_id':'clean_request','verdict':'pass','disposition':'awarded'}
  completion={'objective_id':'clean_request','user_id':owner,'workshop_key':'supply_chain_rce'}
  requests=[];packets=[{'evaluation_id':'positive','user_id':owner}]
  for i,c in enumerate(captures):
   run='positive-run' if i==0 else 'negative-run';requests.append({'run_id':run,'user_id':owner,'status':'completed'})
   c.update(caseId=cases[i],userId=owner,runs=[{'run_id':run,'owner_key':'["CodeBot","1"]'}],judgments=[award],packets=packets,effects=[],requests=copy.deepcopy(requests),completions=[completion])
   c['body']={'run':{'runId':run},'judgments':[{'evaluationId':'positive','verdict':'pass'}]if i==0 else [],'newlyCompletedObjectives':['clean_request']if i==0 else []}
   c['wireBinding'].update(runId=run,evaluationIds=['positive']if i==0 else [],judgeCalls=1 if i==0 else 0)
  wire['calls']=[wire['calls'][0],*wire['calls'][1:4]]
  for i,row in enumerate(wire['calls'][1:]):row['caseId']=cases[0 if i<2 else 1]
  wire.update(version='codebot-current-clean-fixed-wire-v1',counts={'external':4,'chat':3,'generate':0,'tags':1,'version':0,'metadata':1})
  raw=json.dumps({key:captures[-1][key]for key in ('effects','requests','judgments','packets')}).encode();history={'before':raw,'after':raw}
  value['qualification'].update(version='codebot-current-clean-fixed-v1',cases=cases,completedEffectCount=0,primaryCompletionIds=['clean_request'],immutableHistory={k:{'sha256':hashlib.sha256(v).hexdigest(),'bytes':len(v)}for k,v in history.items()})
  self.assertTrue(m.verify_codebot_current_result(value,wire,captures,'codebot-current-clean-fixed',history))
  for mutate in (lambda c:c[1].update(userId=2),lambda c:c[1]['body'].update(newlyCompletedObjectives=['clean_request']),lambda c:c[1].update(completions=[]),lambda c:c[1].update(effects=[{}]),lambda c:c[1].update(judgments=[])):
   bad=copy.deepcopy(captures);mutate(bad)
   with self.assertRaises(RuntimeError):m.verify_codebot_current_result(value,wire,bad,'codebot-current-clean-fixed',history)
if __name__=='__main__':unittest.main()
