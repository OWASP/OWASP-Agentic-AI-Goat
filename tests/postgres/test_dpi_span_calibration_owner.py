import importlib.util, pathlib, types, unittest
p=pathlib.Path(__file__).with_name('run-rag-whole-evidence-v5-main.py')
s=importlib.util.spec_from_file_location('owner',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Controls(unittest.TestCase):
 def test_closed_profile(self):
  v=m.profile(types.SimpleNamespace(profile='dpi-span'))
  self.assertEqual((v['seconds'],v['calls'],v['folder'],v['prefix']),(7380,96,'dpi-span-calibration','DPI_SPAN'))
  self.assertEqual(v['sha'],'d54c97ec7940df24ac949d96155a93994c2e0a2b8d24d30b3c3c9b81a99c2c62')
  with self.assertRaises(ValueError):m.profile(types.SimpleNamespace(profile='other'))
 def test_compact_profile_is_separate_and_smaller(self):
  v=m.profile(types.SimpleNamespace(profile='dpi-semantic-compact'))
  self.assertEqual((v['seconds'],v['calls'],v['folder'],v['prefix']),(6120,56,'dpi-span-calibration','DPI_SPAN'))
  self.assertEqual(v['childProfile'],'semantic-compact-v1')
  self.assertEqual(v['sha'],'ed88a5688b7ea001505c5b797a545429d79f8d1d40ea6f1e24e66a95bab518ec')
  self.assertIn('server/agent-runtime/dpiSemanticCompactCandidate.js',v['required'])
 def test_default_unchanged(self):
  v=m.profile(types.SimpleNamespace());self.assertEqual((v['seconds'],v['calls'],v['entry']),(780,12,m.ENTRY))
 def test_schema_visible_profile_keeps_caps_and_owns_fresh_input(self):
  old=m.profile(types.SimpleNamespace(profile='dpi-semantic-compact'));new=m.profile(types.SimpleNamespace(profile='dpi-semantic-schema-visible'))
  self.assertEqual(new['childProfile'],'semantic-schema-visible-v1')
  self.assertEqual(new['sha'],'0045f70f8b9b2a3ea45b9bfef310f4eabd142c6b5dfb4b626d2d2de907af6631')
  self.assertNotEqual(new['input'],old['input'])
  for key in ['entry','prefix','folder','seconds','calls','required']:self.assertEqual(new[key],old[key])
 def test_direct_reuses_visible_input_and_preserves_all_budgets(self):
  old=m.profile(types.SimpleNamespace(profile='dpi-semantic-schema-visible'));new=m.profile(types.SimpleNamespace(profile='dpi-semantic-direct-witness'))
  self.assertEqual(new['childProfile'],'semantic-direct-witness-v1')
  for key in ['input','sha','entry','prefix','folder','seconds','calls']:self.assertEqual(new[key],old[key])
  self.assertEqual(new['required']-old['required'],{'server/agent-runtime/dpiDirectWitnessCandidate.js'})
 def test_direct_authority_is_closed_and_matches_manifest_pin(self):
  import copy
  cfg=m.profile(types.SimpleNamespace(profile='dpi-semantic-direct-witness'));candidate='server/agent-runtime/dpiDirectWitnessCandidate.js'
  receipt={'version':'dpi-direct-witness-regression-v1','inputSha256':cfg['sha'],'sourceProtocol':'dpi-semantic-compact-candidate-v2-schema-visible','protocol':'dpi-direct-witness-candidate-v1','candidatePath':candidate,'candidateSha256':'a'*64,'reusedEvidence':True,'heldOut':False}
  manifest={'files':[{'path':candidate,'sha256':'a'*64}],'regressionAdmission':receipt}
  m.validate_regression_admission(manifest,cfg)
  for key,value in [('candidateSha256','b'*64),('heldOut',True),('heldOut',0),('reusedEvidence',1),('protocol','other'),('sourceProtocol','other'),('inputSha256','b'*64),('extra',True)]:
   bad=copy.deepcopy(manifest);bad['regressionAdmission'][key]=value
   with self.assertRaises(ValueError):m.validate_regression_admission(bad,cfg)
  for bad in [{'files':[],'regressionAdmission':receipt},{'files':manifest['files']}]:
   with self.assertRaises(ValueError):m.validate_regression_admission(bad,cfg)
 def test_stronger_judge_is_explicit_closed_and_manifest_bound(self):
  a=types.SimpleNamespace(profile='dpi-semantic-direct-witness',judge_model=m.STRONG_JUDGE['model'],judge_model_digest=m.STRONG_JUDGE['digest'])
  self.assertEqual(m.judge_selection(a,{'judgeIdentity':dict(m.STRONG_JUDGE)}),m.STRONG_JUDGE)
  self.assertIsNone(m.judge_selection(types.SimpleNamespace(),{}))
  for changes,manifest in [({'profile':'dpi-span'},{'judgeIdentity':m.STRONG_JUDGE}),({'judge_model_digest':None},{'judgeIdentity':m.STRONG_JUDGE}),({},{}),({'judge_model':'other'},{'judgeIdentity':m.STRONG_JUDGE})]:
   bad=types.SimpleNamespace(**{**vars(a),**changes})
   with self.assertRaises(ValueError):m.judge_selection(bad,manifest)
  with self.assertRaises(ValueError):m.judge_selection(types.SimpleNamespace(),{'judgeIdentity':m.STRONG_JUDGE})
 def test_source_first_is_bounded_and_separately_admitted(self):
  cfg=m.profile(types.SimpleNamespace(profile='dpi-semantic-source-first-side'))
  self.assertEqual((cfg['calls'],cfg['seconds'],cfg['childProfile']),(8,1080,'semantic-source-first-side-v1'))
  candidate='server/agent-runtime/dpiSourceFirstServerIdsCandidate.js'
  self.assertIn(candidate,cfg['required'])
  receipt={'version':'dpi-server-ids-regression-v1','inputSha256':cfg['sha'],'sourceProtocol':'dpi-semantic-compact-candidate-v2-schema-visible','protocol':'dpi-source-first-server-ids-v1','candidatePath':candidate,'candidateSha256':'a'*64,'reusedEvidence':True,'heldOut':False}
  manifest={'files':[{'path':candidate,'sha256':'a'*64}],'regressionAdmission':receipt}
  m.validate_regression_admission(manifest,cfg)
  receipt['protocol']='dpi-direct-witness-server-ids-v6'
  with self.assertRaises(ValueError):m.validate_regression_admission(manifest,cfg)
 def test_release_after_publication(self):
  seen=[]
  class Stream:
   def write(self,b):seen.append(('write',b))
   def flush(self):seen.append('flush')
   def close(self):seen.append('close')
  state={};m.release_child(types.SimpleNamespace(pid=91,stdin=Stream()),state,lambda:seen.append(dict(state)))
  self.assertEqual(seen[0],{'nativePid':91,'nativeStarted':True});self.assertEqual(seen[1],('write',b'1'))
if __name__=='__main__':unittest.main()
