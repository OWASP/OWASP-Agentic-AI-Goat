import importlib.util,pathlib,unittest,sys
from types import SimpleNamespace
from unittest.mock import patch
P=pathlib.Path(__file__).with_name('run-rag-whole-evidence-v5-main.py')
spec=importlib.util.spec_from_file_location('watchdog',P);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Controls(unittest.TestCase):
 def test_release_follows_publication(self):
  events=[];state={};pipe=SimpleNamespace(write=lambda x:events.append(x),flush=lambda:None,close=lambda:events.append('closed'))
  m.release_child(SimpleNamespace(pid=99,stdin=pipe),state,lambda:events.append(dict(state)))
  self.assertEqual(events,[{'nativePid':99,'nativeStarted':True},b'1','closed'])
 def test_failed_publication_never_releases(self):
  pipe=SimpleNamespace(write=lambda _:self.fail('released'))
  with self.assertRaises(RuntimeError):m.release_child(SimpleNamespace(pid=99,stdin=pipe),{},lambda:(_ for _ in ()).throw(RuntimeError()))
 def test_plan_is_nonallocating_after_admission(self):
  with patch.object(m,'admit') as admit,patch.object(m.tempfile,'mkdtemp',side_effect=AssertionError('allocation')):
   args=sum((['--'+k,'controlled']for k in ['manifest','manifest-sha256','node','node-sha256','python-sha256','supervisor-sha256','helper-sha256']),[])+['--plan']
   self.assertEqual(m.main(args),0);admit.assert_called_once()
 def test_source_technique_profile_is_bounded_and_pins_separate_labels(self):
  cfg=m.profile(SimpleNamespace(profile='dpi-selected-source-technique4'))
  self.assertEqual((cfg['calls'],cfg['seconds'],cfg['childProfile']),(4,840,'semantic-selected-source-technique-v11'))
  self.assertEqual(m.digest(m.ROOT/cfg['input']),cfg['sha'])
  self.assertEqual(m.digest(m.ROOT/cfg['expectations']),cfg['expectationsSha'])
  self.assertNotIn(cfg['expectations'],cfg['required'])
  self.assertIn('server/agent-runtime/dpiSelectedSourceTechniqueCandidate.js',cfg['required'])
 def test_source_technique_requires_exact_explicit_judge(self):
  args=SimpleNamespace(profile='dpi-selected-source-technique4')
  with self.assertRaises(ValueError):m.judge_selection(args,{})
  args.judge_model=m.STRONG_JUDGE['model'];args.judge_model_digest=m.STRONG_JUDGE['digest']
  self.assertEqual(m.judge_selection(args,{'judgeIdentity':dict(m.STRONG_JUDGE)}),m.STRONG_JUDGE)
  args.judge_model='llama3.1:8b'
  with self.assertRaises(ValueError):m.judge_selection(args,{'judgeIdentity':dict(m.STRONG_JUDGE)})
 def test_source_technique_admission_rejects_budget_and_candidate_substitution(self):
  cfg=m.profile(SimpleNamespace(profile='dpi-selected-source-technique4'));candidate='server/agent-runtime/dpiSelectedSourceTechniqueCandidate.js';pin=m.digest(m.ROOT/candidate)
  admission={'version':'dpi-selected-source-technique-calibration-v1','inputSha256':cfg['sha'],'protocol':'dpi-selected-source-technique-v11','candidatePath':candidate,'candidateSha256':pin,'contextTokens':20480,'providerTimeoutMs':180000,'transportTimeoutMs':180000,'sourceOnly':True,'labelsExternal':True}
  manifest={'files':[{'path':candidate,'sha256':pin}],'sourceTechniqueAdmission':admission}
  m.validate_regression_admission(manifest,cfg)
  for key,value in [('contextTokens',32768),('providerTimeoutMs',120000),('candidateSha256','0'*64),('labelsExternal',1)]:
   bad={**manifest,'sourceTechniqueAdmission':{**admission,key:value}}
   with self.assertRaises(ValueError):m.validate_regression_admission(bad,cfg)
 def test_role_successor_preserves_four_case_budget_and_binds_its_own_candidate(self):
  cfg=m.profile(SimpleNamespace(profile='dpi-selected-role-technique4'));base=m.profile(SimpleNamespace(profile='dpi-selected-source-technique4'))
  self.assertEqual((cfg['calls'],cfg['seconds'],cfg['input'],cfg['sha']),(base['calls'],base['seconds'],base['input'],base['sha']))
  self.assertEqual(cfg['childProfile'],'semantic-selected-role-technique-v12')
  candidate='server/agent-runtime/dpiSelectedRoleTechniqueCandidate.js';pin='1'*64
  admission={'version':'dpi-selected-source-technique-calibration-v1','inputSha256':cfg['sha'],'protocol':'dpi-selected-role-technique-v12','candidatePath':candidate,'candidateSha256':pin,'contextTokens':20480,'providerTimeoutMs':180000,'transportTimeoutMs':180000,'sourceOnly':True,'labelsExternal':True}
  manifest={'files':[{'path':candidate,'sha256':pin}],'sourceTechniqueAdmission':admission}
  m.validate_regression_admission(manifest,cfg)
  manifest['sourceTechniqueAdmission']={**admission,'protocol':'dpi-selected-source-technique-v11'}
  with self.assertRaises(ValueError):m.validate_regression_admission(manifest,cfg)
  with self.assertRaises(ValueError):m.judge_selection(SimpleNamespace(profile='dpi-selected-role-technique4'),{})
 def test_objective_scoped_8b_profile_requires_pinned_default_and_no_override(self):
  args=SimpleNamespace(profile='dpi-selected-objective-technique4-8b');cfg=m.profile(args)
  self.assertEqual((cfg['calls'],cfg['seconds'],cfg['childProfile']),(4,840,'semantic-selected-objective-technique-v13-8b'))
  identity={'model':'llama3.1:8b','digest':'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'}
  self.assertIsNone(m.judge_selection(args,{'defaultJudgeIdentity':identity}))
  with self.assertRaises(ValueError):m.judge_selection(args,{})
  with self.assertRaises(ValueError):m.judge_selection(args,{'defaultJudgeIdentity':m.STRONG_JUDGE})
  with self.assertRaises(ValueError):m.judge_selection(args,{'defaultJudgeIdentity':identity,'judgeIdentity':identity})
  args.judge_model='llama3.1:8b'
  with self.assertRaises(ValueError):m.judge_selection(args,{'defaultJudgeIdentity':identity})
 def test_response_consistency_8b_preserves_budget_and_requires_own_protocol(self):
  args=SimpleNamespace(profile='dpi-selected-response-consistency4-8b');cfg=m.profile(args)
  base=m.profile(SimpleNamespace(profile='dpi-selected-objective-technique4-8b'))
  for key in ('calls','seconds','input','sha','expectations','expectationsSha'):self.assertEqual(cfg[key],base[key])
  self.assertEqual(cfg['childProfile'],'semantic-selected-response-consistency-v14-8b')
  candidate='server/agent-runtime/dpiSelectedResponseConsistencyCandidate.js';pin='2'*64
  self.assertTrue(base['required']|{candidate}==cfg['required'])
  admission={'version':'dpi-selected-source-technique-calibration-v1','inputSha256':cfg['sha'],'protocol':'dpi-selected-response-consistency-v14','candidatePath':candidate,'candidateSha256':pin,'contextTokens':20480,'providerTimeoutMs':180000,'transportTimeoutMs':180000,'sourceOnly':True,'labelsExternal':True}
  manifest={'files':[{'path':candidate,'sha256':pin}],'sourceTechniqueAdmission':admission,'defaultJudgeIdentity':{'model':'llama3.1:8b','digest':'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'}}
  m.validate_regression_admission(manifest,cfg);self.assertIsNone(m.judge_selection(args,manifest))
  for key,value in [('protocol','dpi-selected-objective-technique-v13'),('candidatePath','server/agent-runtime/dpiSelectedObjectiveTechniqueCandidate.js')]:
   with self.assertRaises(ValueError):m.validate_regression_admission({**manifest,'sourceTechniqueAdmission':{**admission,key:value}},cfg)
  with self.assertRaises(ValueError):m.judge_selection(args,{**manifest,'judgeIdentity':m.STRONG_JUDGE})
 def test_response_regression_8b_has_fixed_eight_case_budget_and_external_labels(self):
  args=SimpleNamespace(profile='dpi-selected-response-regression8-8b');cfg=m.profile(args)
  self.assertEqual((cfg['calls'],cfg['seconds'],cfg['childProfile']),(8,1560,'semantic-selected-response-regression-v14-8b'))
  self.assertEqual(m.digest(m.ROOT/cfg['input']),cfg['sha']);self.assertEqual(m.digest(m.ROOT/cfg['expectations']),cfg['expectationsSha'])
  import json
  rows=json.loads((m.ROOT/cfg['input']).read_text())['cases'];labels=json.loads((m.ROOT/cfg['expectations']).read_text())['cases']
  self.assertEqual(len(rows),8);self.assertEqual([r['id'] for r in rows],[r['id'] for r in labels]);self.assertTrue(all(set(r)=={'id','objective','request','response'} for r in rows))
  self.assertNotIn(cfg['expectations'],cfg['required'])
  with self.assertRaises(ValueError):m.judge_selection(args,{'defaultJudgeIdentity':m.STRONG_JUDGE})
 def test_simple_assessment_binds_unchanged_twelve_case_inputs_and_new_contract(self):
  args=SimpleNamespace(profile='dpi-simple-assessment12-8b');cfg=m.profile(args)
  self.assertEqual((cfg['calls'],cfg['seconds'],cfg['childProfile']),(12,2280,'semantic-simple-assessment-v1-8b'))
  self.assertEqual(m.digest(m.ROOT/cfg['input']),cfg['sha']);self.assertEqual(m.digest(m.ROOT/cfg['expectations']),cfg['expectationsSha'])
  import json
  rows=json.loads((m.ROOT/cfg['input']).read_text())['cases'];labels=json.loads((m.ROOT/cfg['expectations']).read_text())['cases']
  self.assertEqual(len(rows),12);self.assertEqual([r['id'] for r in rows],[r['id'] for r in labels])
  old=[];expected=[]
  for stem in ('dpi-selected-source-technique-four','dpi-selected-response-regression-eight'):
   old+=json.loads((m.ROOT/'tests/release-inputs'/f'{stem}-input-v1.json').read_text())['cases']
   expected+=[r['expected']['verdict'] for r in json.loads((m.ROOT/'tests/release-inputs'/f'{stem}-expectations-v1.json').read_text())['cases']]
  self.assertEqual(rows,old);self.assertEqual([r['expectedVerdict'] for r in labels],expected)
  candidate='server/agent-runtime/dpiSimpleAssessmentCandidate.js';pin='3'*64
  admission={'version':'dpi-selected-source-technique-calibration-v1','inputSha256':cfg['sha'],'protocol':'dpi-simple-assessment-v1','candidatePath':candidate,'candidateSha256':pin,'contextTokens':20480,'providerTimeoutMs':180000,'transportTimeoutMs':180000,'sourceOnly':True,'labelsExternal':True}
  manifest={'files':[{'path':candidate,'sha256':pin}],'sourceTechniqueAdmission':admission}
  m.validate_regression_admission(manifest,cfg)
  with self.assertRaises(ValueError):m.validate_regression_admission({**manifest,'sourceTechniqueAdmission':{**admission,'protocol':'dpi-selected-response-consistency-v14'}},cfg)
 def test_source_response_keeps_twelve_cases_with_two_call_budget(self):
  args=SimpleNamespace(profile='dpi-source-response-assessment12-8b');cfg=m.profile(args);base=m.profile(SimpleNamespace(profile='dpi-simple-assessment12-8b'))
  self.assertEqual((cfg['calls'],cfg['seconds'],cfg['childProfile']),(24,3720,'semantic-source-response-assessment-v1-8b'))
  for key in ('input','sha'):self.assertEqual(cfg[key],base[key])
  self.assertEqual(m.digest(m.ROOT/cfg['expectations']),cfg['expectationsSha'])
  candidate='server/agent-runtime/dpiSourceResponseAssessmentCandidate.js';pin='4'*64
  admission={'version':'dpi-selected-source-technique-calibration-v1','inputSha256':cfg['sha'],'protocol':'dpi-source-response-assessment-v1','candidatePath':candidate,'candidateSha256':pin,'contextTokens':20480,'providerTimeoutMs':180000,'transportTimeoutMs':180000,'sourceOnly':True,'labelsExternal':True}
  manifest={'files':[{'path':candidate,'sha256':pin}],'sourceTechniqueAdmission':admission}
  m.validate_regression_admission(manifest,cfg)
  with self.assertRaises(ValueError):m.validate_regression_admission({**manifest,'sourceTechniqueAdmission':{**admission,'protocol':'dpi-simple-assessment-v1'}},cfg)
  with self.assertRaises(ValueError):m.judge_selection(args,{'defaultJudgeIdentity':m.STRONG_JUDGE})
 def test_source_response_v2_keeps_frozen_cases_labels_and_call_budget(self):
  args=SimpleNamespace(profile='dpi-source-response-assessment-v2-12-8b');cfg=m.profile(args);base=m.profile(SimpleNamespace(profile='dpi-source-response-assessment12-8b'))
  for key in ('calls','seconds','input','sha','expectations','expectationsSha'):self.assertEqual(cfg[key],base[key])
  self.assertEqual(cfg['childProfile'],'semantic-source-response-assessment-v2-8b')
  candidate='server/agent-runtime/dpiSourceResponseAssessmentV2Candidate.js';pin='5'*64
  admission={'version':'dpi-selected-source-technique-calibration-v1','inputSha256':cfg['sha'],'protocol':'dpi-source-response-assessment-v2','candidatePath':candidate,'candidateSha256':pin,'contextTokens':20480,'providerTimeoutMs':180000,'transportTimeoutMs':180000,'sourceOnly':True,'labelsExternal':True}
  manifest={'files':[{'path':candidate,'sha256':pin}],'sourceTechniqueAdmission':admission}
  m.validate_regression_admission(manifest,cfg)
  with self.assertRaises(ValueError):m.validate_regression_admission({**manifest,'sourceTechniqueAdmission':{**admission,'protocol':'dpi-source-response-assessment-v1'}},cfg)
  with self.assertRaises(ValueError):m.judge_selection(args,{'defaultJudgeIdentity':m.STRONG_JUDGE})
if __name__=='__main__':unittest.main()
