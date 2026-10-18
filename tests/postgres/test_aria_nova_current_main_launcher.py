import importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
p=Path(__file__).with_name('run-aria-nova-current-main.py');spec=importlib.util.spec_from_file_location('aria_nova_launcher',p);m=importlib.util.module_from_spec(spec)
with patch('subprocess.run',side_effect=AssertionError('No resources')),patch('subprocess.Popen',side_effect=AssertionError('No resources')),patch('tempfile.mkdtemp',side_effect=AssertionError('No allocation')):spec.loader.exec_module(m)
class Controls(unittest.TestCase):
 def test_plan_no_allocation(self):
  args=type('Args',(),{'plan':True})()
  with patch.object(m,'parse_main',return_value=args),patch.object(m,'validate_main',return_value=(Path('/main'),{})),patch.object(m.importlib.util,'spec_from_file_location',side_effect=AssertionError('No helper import')),patch.object(m.tempfile,'mkdtemp',side_effect=AssertionError('No allocation')):self.assertEqual(m.main_current([]),0)
 def test_closed_parser(self):
  with self.assertRaises(ValueError):m.parse_main(['--input','x','--input','x'])
  with self.assertRaises(SystemExit):m.parse_main(['--mode','actual'])
 def test_exact_store_nonce_roles(self):
  from urllib.parse import urlparse
  for label in ['identity','aria','nova']:
   sql,urls=m.store_configuration(label,54321,'a'*12);self.assertEqual(len(urls),2);self.assertNotIn('SUPERUSER;',sql);self.assertIn('REVOKE CONNECT',sql)
   for key,value in urls.items():
    u=urlparse(value);self.assertEqual(u.hostname,'127.0.0.1');self.assertEqual(u.port,54321);self.assertEqual(u.path,'/dvaia_test_aria_nova_'+'a'*12+'_'+label);self.assertEqual(u.username,'dvaia_'+label+('_migration'if '_MIGRATION_'in key else'_runtime'))
  for values in [('other',54321,'a'*12),('identity',0,'a'*12),('nova',54321,'not-owned')]:
   with self.assertRaises(ValueError):m.store_configuration(*values)
 def test_environment_no_inherited_secrets(self):
  args=type('Args',(),dict(main_workspace='/main',manifest='/manifest',manifest_sha256='a'*64,input='/frozen',input_sha256=m.ACTUAL_INPUT_SHA256,browser='/chrome',browser_sha256='b'*64))()
  with patch.dict(os.environ,{'OPENAI_API_KEY':'private','IDENTITY_DATABASE_URL':'installed','NODE_OPTIONS':'unsafe'}):env=m.child_environment({'PATH':'/pinned'},Path('/evidence'),Path('/evidence/runtime'),'owner',args)
  for key in ['OPENAI_API_KEY','IDENTITY_DATABASE_URL','NODE_OPTIONS','DVAIA_ISOLATED_TEST_WORKSPACE']:self.assertNotIn(key,env)
  self.assertEqual(env['DVAIA_APP_DATA_ROOT'],'/evidence/runtime/appdata');self.assertEqual(env['ARIA_NOVA_INPUTS_SHA256'],m.ACTUAL_INPUT_SHA256)
 def test_frozen_input_pin_and_log_aggregate(self):
  root=Path('/main');args=type('Args',(),{'input':str(root/m.ACTUAL_INPUT),'input_sha256':m.ACTUAL_INPUT_SHA256})()
  with patch.object(m.Path,'is_symlink',return_value=False),patch.object(m.Path,'resolve',return_value=root/m.ACTUAL_INPUT),patch.object(m,'digest',return_value=m.ACTUAL_INPUT_SHA256):
   m.validate_actual_input(args,root,{'sourcePins':{m.ACTUAL_INPUT:m.ACTUAL_INPUT_SHA256}})
   with self.assertRaises(RuntimeError):m.validate_actual_input(args,root,{'sourcePins':{}})
  with tempfile.TemporaryDirectory()as d:
   root=Path(d)
   for name in ['one.log','two.tap']:
    with(root/name).open('wb')as f:f.truncate(33*1024**2)
   with self.assertRaises(RuntimeError):m.check_logs(root)
 def test_all_evidence_links_denied(self):
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);(root/'link').symlink_to('/nonexistent')
   with self.assertRaisesRegex(RuntimeError,'Owned evidence link'):m.check_logs(root)
class RemainingControls(unittest.TestCase):
 def args(self,profile):return type('Args',(),{'profile':profile})()
 def test_closed_profile_and_original_limits(self):
  original=m.profile_contract(self.args('current'))
  self.assertEqual((original['cohort'],original['childSeconds'],original['workSeconds']),(m.COHORT,600,780))
  with self.assertRaises(ValueError):m.profile_contract(self.args('other'))
  with patch.dict(m.REMAINING_INPUT_SHA256,{'aria-remaining':'a'*64,'nova-remaining':'b'*64}):
   for profile,omitted,chat,total in [('aria-remaining','sqli_3',96,178),('nova-remaining','nosqli_2',88,170)]:
    c=m.profile_contract(self.args(profile));self.assertEqual(len(c['cases']),9);self.assertNotIn(omitted,c['cases'])
    self.assertEqual((c['generate'],c['chat'],c['tags'],c['external']),(81,chat,1,total))
    self.assertEqual((c['childSeconds'],c['workSeconds']),(1260,1440))
 def test_wrong_cohort_profile_model_or_digest_denied(self):
  for profile in ['aria-remaining','nova-remaining']:
   args=self.args(profile);value={'cohort':profile,'profile':profile,'model':m.MODEL,'modelDigest':m.MODEL_DIGEST}
   m.validate_profile_manifest(args,value)
   for key,bad in [('cohort',m.COHORT),('profile','current'),('model','other'),('modelDigest','0'*64)]:
    with self.assertRaises(RuntimeError):m.validate_profile_manifest(args,{**value,key:bad})
 def test_remaining_plan_never_imports_ownership_or_allocates(self):
  with patch.dict(m.REMAINING_INPUT_SHA256,{'aria-remaining':'a'*64,'nova-remaining':'b'*64}):
   for profile in ['aria-remaining','nova-remaining']:
    args=self.args(profile);args.plan=True
    with patch.object(m,'parse_main',return_value=args),patch.object(m,'validate_main',return_value=(Path('/main'),{})),patch.object(m.importlib.util,'spec_from_file_location',side_effect=AssertionError('No helper import')),patch.object(m.tempfile,'mkdtemp',side_effect=AssertionError('No allocation')):self.assertEqual(m.main_current([]),0)
 def test_remaining_input_cannot_borrow_representative_or_other_profile(self):
  root=Path('/main')
  with patch.dict(m.REMAINING_INPUT_SHA256,{'aria-remaining':'a'*64,'nova-remaining':'b'*64}):
   for profile in ['aria-remaining','nova-remaining']:
    args=self.args(profile);c=m.profile_contract(args);args.input=str(root/c['input']);args.input_sha256=c['inputSha256']
    with patch.object(m.Path,'is_symlink',return_value=False),patch.object(m.Path,'resolve',return_value=root/c['input']),patch.object(m,'digest',return_value=c['inputSha256']):
     m.validate_actual_input(args,root,{'sourcePins':{c['input']:c['inputSha256']}})
     args.input_sha256=m.ACTUAL_INPUT_SHA256
     with self.assertRaises(RuntimeError):m.validate_actual_input(args,root,{'sourcePins':{c['input']:c['inputSha256']}})
class ReceiptControls(unittest.TestCase):
 def fixture(self,profile='aria-remaining'):
  import copy,hashlib
  c=m.profile_contract(type('Args',(),{'profile':profile})());calls=[];evidence=[];turns=[]
  def wire(kind,case=None):
   text='{}';index=len(calls);h=hashlib.sha256(text.encode()).hexdigest()
   calls.append(dict(index=index,kind=kind,caseId=case,terminal='returned',status=200,responseComplete=True,responseCaptureTruncated=False,request=text,response=text,requestSha256=h,responseSha256=h,requestBytes=2,responseBytes=2));return index
  wire('tags')
  for number,case in enumerate(c['cases']):
   actor=wire('generate',case);judge=wire('chat',case);run='run-'+str(number);owner='owner-'+str(number);evaluation='evaluation-'+str(number)
   binding={'caseId':case,'runId':run,'actorIndexes':[actor],'formatterComplete':True,'judgments':[{'evaluationId':evaluation,'objectiveId':case,'wireIndexes':[judge]}]}
   turns.append({'id':case,'runId':run,'wireBinding':binding,'outcome':'qualified'})
   canonical={'evaluation_id':evaluation,'run_id':run,'objective_id':case,'verdict':'pass','disposition':'awarded','result_json':{'attempts':1}}
   evidence.append({'id':case,'outcome':'qualified','status':'verified','httpStatus':200,'wireBinding':copy.deepcopy(binding),'run':{'run_id':run,'owner_key':owner,'generation':0},'body':{'run':{'runId':run},'judgments':[{'objectiveId':case,'evaluationId':evaluation,'verdict':'pass'}],'completedObjectives':[case]},'records':[{'judgment':canonical,'owner_key':owner,'owner_generation':0}],'effectKeys':[run+':effect'],'effects':[{'effect_key':run+':effect','run_id':run,'owner_key':owner,'generation':0}]})
  for summary,captured in zip(turns,evidence):
   narrative={'text':'controlled narrative','source':'model','errorCode':None,'sha256':hashlib.sha256(b'controlled narrative').hexdigest()};presentation={'version':'workshop-result-presentation-v1','runId':captured['run']['run_id'],'narrative':narrative,'responseSha256':hashlib.sha256(b'controlled display').hexdigest(),'blocks':[]}
   captured['body'].update(response='controlled display',presentation=presentation);captured['body']['run']['responseComposition']=presentation['version']
   pb={'version':presentation['version'],'narrativeSha256':narrative['sha256'],'responseSha256':presentation['responseSha256'],'blockCount':0,'historyVerified':True,'durableSnapshotVerified':True}
   summary['wireBinding']['presentationBinding']=pb;captured['wireBinding']['presentationBinding']=copy.deepcopy(pb)
   captured['historyRows']=[{'message_type':'user','message':'controlled request'},{'message_type':'assistant','message':'controlled display'}]
   captured['events']=[{'run_id':captured['run']['run_id'],'owner_key':captured['run']['owner_key'],'node':'presentation','event_type':'node_end','metadata':{'presentationSnapshot':{'version':presentation['version'],'narrativeSource':'model','errorCode':None,'narrativeSha256':narrative['sha256'],'responseSha256':presentation['responseSha256'],'blocks':[]}}}]
  counts={'external':19,'incoming':18,'metadata':1,'tags':1,'version':0,'generate':9,'chat':9}
  wiredata={'version':'aria-nova-current-wire-v1','profile':profile,'model':m.MODEL,'digest':m.MODEL_DIGEST,'closed':True,'physicalPending':0,'failures':[],'counts':counts,'calls':calls}
  result={'status':'passed','qualification':'qualified','cleanupFailures':[],'installedWrites':False,'profile':profile,'actualModelProof':True,'fullApplicationQualification':False,'siblingPreserved':True,'completedToolObjectives':c['cases'],'cleanup':[{'name':x,'status':'fulfilled'} for x in ['http','pools','transport']],'turns':turns,'formatterOutputLimited':[],'formatterQualificationComplete':True}
  return c,result,wiredata,evidence
 def test_exact_nine_case_receipts_and_limited_formatter_scope(self):
  for profile in ['aria-remaining','nova-remaining']:
   c,r,w,e=self.fixture(profile);m.verify_remaining_result(c,r,w,e)
   r['turns'][0]['wireBinding']['formatterComplete']=False;e[0]['wireBinding']['formatterComplete']=False
   r['formatterOutputLimited']=[c['cases'][0]];r['formatterQualificationComplete']=False;m.verify_remaining_result(c,r,w,e)
 def test_missing_wrong_or_unbound_receipts_deny(self):
  mutations=[lambda r,w,e:r.update(qualification='incomplete'),lambda r,w,e:r.update(completedToolObjectives=[]),lambda r,w,e:r.update(cleanup=[]),lambda r,w,e:r.update(actualModelProof=False),lambda r,w,e:r.update(fullApplicationQualification=True),lambda r,w,e:w.update(profile='current'),lambda r,w,e:w.update(closed=False),lambda r,w,e:w.update(physicalPending=1),lambda r,w,e:w['calls'][1].update(response='tampered'),lambda r,w,e:e[0]['records'][0].update(owner_key='sibling'),lambda r,w,e:e[0]['records'][0]['judgment'].update(disposition='not_pass'),lambda r,w,e:e[0]['effects'][0].update(generation=1),lambda r,w,e:e[1]['run'].update(owner_key=e[0]['run']['owner_key']),lambda r,w,e:r['turns'].pop()]
  for mutate in mutations:
   c,r,w,e=self.fixture();mutate(r,w,e)
   with self.assertRaises(RuntimeError):m.verify_remaining_result(c,r,w,e)
 def test_presentation_history_and_durable_snapshot_mismatch_deny(self):
  for mutate in [lambda e:e[0]['historyRows'][1].update(message='other'),lambda e:e[0]['events'][0].update(owner_key='sibling'),lambda e:e[0]['body']['presentation']['narrative'].update(text='invented'),lambda e:e[0]['wireBinding']['presentationBinding'].update(historyVerified=False)]:
   c,r,w,e=self.fixture();mutate(e)
   with self.assertRaises(RuntimeError):m.verify_remaining_result(c,r,w,e)
 def test_zero_attempt_retained_failure_cannot_supply_target_judge_proof(self):
  c,r,w,e=self.fixture();extra={'evaluation_id':'zero','run_id':e[0]['run']['run_id'],'objective_id':'other','verdict':'inconclusive','disposition':'not_pass','result_json':{'attempts':0}}
  e[0]['records'].append({'judgment':extra,'owner_key':e[0]['run']['owner_key'],'owner_generation':0})
  binding={'evaluationId':'zero','objectiveId':'other','wireIndexes':[]}
  r['turns'][0]['wireBinding']['judgments'].append(binding);e[0]['wireBinding']['judgments'].append(dict(binding))
  m.verify_remaining_result(c,r,w,e)
  extra.update(objective_id=c['cases'][0],verdict='pass',disposition='awarded');binding['objectiveId']=c['cases'][0];e[0]['wireBinding']['judgments'][-1]['objectiveId']=c['cases'][0]
  e[0]['body']['judgments'][0]['evaluationId']='zero'
  with self.assertRaises(RuntimeError):m.verify_remaining_result(c,r,w,e)
 def test_technical_incomplete_is_retained_but_never_qualified(self):
  c,r,w,e=self.fixture();r['qualification']='incomplete'
  m.verify_incomplete_technical_receipt(c,r,w)
  with self.assertRaises(RuntimeError):m.verify_remaining_result(c,r,w,e)
  w['physicalPending']=1
  with self.assertRaises(RuntimeError):m.verify_incomplete_technical_receipt(c,r,w)
 def test_reset_receipts_bind_nonempty_history_and_seeded_sibling(self):
  import copy
  for profile in ['aria-remaining','nova-remaining']:
   c,r,w,e=self.fixture(profile);r.update(resetPreserved=True,revocation={'status':401,'noModelCalls':True});resets=[]
   for captured in e:
    captured['run'].update(started_at='2026-09-28T01:02:03.123456Z',finished_at='2026-09-28T01:02:04.123456Z')
    for effect in captured['effects']:effect['updated_at']='2026-09-28T01:02:03.123456Z'
    captured['events']=[{'run_id':captured['run']['run_id'],'created_at':'2026-09-28T01:02:03.123456Z'}]
    immutable={key:[{'row':{}}] for key in ['objective_evidence','packets']}
    immutable.update(graph_runs=[{'row':captured['run']}],graph_events=[{'row':event} for event in captured['events']])
    immutable.update(runIds=[captured['run']['run_id']],objective_judgments=[{'row':x['judgment']} for x in captured['records']],graph_effects=[{'row':x} for x in captured['effects']])
    sibling={key:[] for key in ['user_state','user_modes','completions','time_tracking','objective_judgments','objective_evidence','chat_history']}
    if profile=='aria-remaining':sibling.update(cart=[{'row':{'user_id':'sibling'}}],orders=[])
    else:sibling['reading_lists']=[{'row':{'user_id':'sibling'}}]
    before={'generation':0,'immutable':immutable,'sibling':sibling};after={**copy.deepcopy(before),'generation':1,'completed':0,'mutable':0,'history':0}
    resets.append({'id':captured['id'],'status':200,'verified':True,'before':before,'after':after})
   m.verify_remaining_resets(c,r,resets,e)
   for change in [lambda x:x[0]['after'].update(generation=0),lambda x:x[0]['after'].update(completed=1),lambda x:x[0]['before'].update(immutable={}),lambda x:x[0]['after'].update(sibling={}),lambda x:x.pop()]:
    bad=copy.deepcopy(resets);change(bad)
    with self.assertRaises(RuntimeError):m.verify_remaining_resets(c,r,bad,e)
   for value in [{},'2026-09-28T01:02:03.123Z','2026-09-28T01:02:03.123457Z']:
    bad=copy.deepcopy(resets)
    for side in ['before','after']:bad[0][side]['immutable']['graph_effects'][0]['row']['updated_at']=value
    with self.assertRaises(RuntimeError):m.verify_remaining_resets(c,r,bad,e)
   with self.assertRaises(RuntimeError):m.verify_remaining_resets(c,{**r,'revocation':{'status':401,'noModelCalls':False}},resets,e)
if __name__=='__main__':unittest.main()
