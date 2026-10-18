import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
import tempfile
import shutil
from unittest.mock import patch
p=Path(__file__).with_name('run-setup-database-phase-isolated.py')
s=importlib.util.spec_from_file_location('auth_launcher',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)

def ux_receipt():
 return {'scope':'rendered_platform_workshop_ux','passed':True,'actualModelProof':False,'controlledProjectionOnly':True,'checks':dict.fromkeys(m.UX_RENDERED_CHECKS,True)}

class Auth(unittest.TestCase):
 def test_closed_main_profile(self):
  self.assertEqual(m.scenario_fixture('main-backend-auth'),'tests/postgres/mainBackendAuth.integration.test.js')
  self.assertEqual(m.scenario_bounds('main-backend-auth'),(600,480,120))
  m.validate_original_case(SimpleNamespace(scenario='main-backend-auth',main_workspace=True,entry_case=None,original_case=None))
  for main,entry,original in [(False,None,None),(True,'success',None),(True,None,'success')]:
   with self.assertRaises(ValueError):m.validate_original_case(SimpleNamespace(scenario='main-backend-auth',main_workspace=main,entry_case=entry,original_case=original))
 def test_historical_bounds_and_selection(self):
  self.assertEqual(m.scenario_bounds('prospective-original'),(780,600,120))
  m.validate_original_case(SimpleNamespace(scenario='prospective-original',main_workspace=True,entry_case=None,original_case=None))
 def test_publication_precedes_release_and_no_copy_sentinel(self):
  text=p.read_text();self.assertLess(text.index("state['nativePid']=child.pid;record()"),text.index("child.stdin.write(b'1')"))
  self.assertIn("env.pop('DVAIA_ISOLATED_TEST_WORKSPACE',None)",text)
class Logs(unittest.TestCase):
 def test_aggregate_includes_backend_logs_after_exit(self):
  evidence=Path('/owned/evidence')
  with patch.object(m.os,'walk',return_value=[(str(evidence),[],['result.tap']),(str(evidence/'runtime'),[],['0.log'])]),patch.object(Path,'is_symlink',return_value=False),patch.object(Path,'exists',return_value=True),patch.object(Path,'stat',return_value=SimpleNamespace(st_size=33*1024**2)):
   with self.assertRaisesRegex(RuntimeError,'Aggregate'):m.check_native_logs(evidence,'main-backend-auth')
   self.assertEqual(m.check_native_logs(evidence,'prospective-original'),33*1024**2)
 def test_cache_admission_is_explicit_and_nonempty(self):
  text=p.read_text();self.assertIn("not isinstance(expected,dict) or not expected",text);self.assertIn("inventory(cache)!=expected",text)
class Preservation(unittest.TestCase):
 def test_exact_data_preserved_before_remove(self):
  with tempfile.TemporaryDirectory() as evidence:
   row=m.create_private_installation(Path(__file__).resolve().parents[2]);root=Path(row['path'])
   (root/'sample').write_bytes(b'synthetic private runtime data')
   result=m.preserve_auth_data(row,Path(evidence));self.assertTrue(result['preservedBeforeRemoval']);self.assertFalse(root.exists());self.assertTrue(Path(result['archive']).is_file())
 def test_changed_identity_retains_data(self):
  with tempfile.TemporaryDirectory() as evidence:
   row=m.create_private_installation(Path(__file__).resolve().parents[2]);root=Path(row['path'])
   try:
    with self.assertRaises(RuntimeError):m.preserve_auth_data({**row,'inode':row['inode']+1},Path(evidence))
    self.assertTrue(root.exists())
   finally:shutil.rmtree(root)
 def test_rendered_platform_closed_selector(self):
  row=SimpleNamespace(scenario='main-backend-auth',main_workspace=True,entry_case=None,original_case=None,auth_profile='rendered-platform',browser='/browser',browser_root='/browser-root',browser_sha256='a'*64,python_sha256='b'*64)
  m.validate_original_case(row)
  for key,value in [('scenario','main-capacity-200'),('auth_profile','other'),('browser',None)]:
   bad=SimpleNamespace(**vars(row));setattr(bad,key,value)
   with self.assertRaises(ValueError):m.validate_original_case(bad)
 def test_platform_receipt_requires_each_independent_flow(self):
  value={'scope':'rendered_full_backend_auth_projection','stage':'complete','passed':True,'actualModelProof':False,'ux':ux_receipt(),'checks':{'R03':dict.fromkeys(['created','edited','inactiveDenied','reactivatedLogin','populatedDeletion','deletedSessionDenied','levelOneDenied','siblingPreserved'],True),'R06':dict.fromkeys(['populatedAdminDetail','populatedLearnerDetail','privatePacketExcluded','foreignDenied'],True)}}
  m.verify_platform_rendered_result(value)
  import copy
  missing=copy.deepcopy(value);missing.pop('ux')
  with self.assertRaises(RuntimeError):m.verify_platform_rendered_result(missing)
  for key in m.UX_RENDERED_CHECKS:
   for replacement in [False,1,None]:
    bad=copy.deepcopy(value);bad['ux']['checks'][key]=replacement
    with self.assertRaises(RuntimeError):m.verify_platform_rendered_result(bad)
  for key,replacement in [('actualModelProof',True),('controlledProjectionOnly',False)]:
   bad=copy.deepcopy(value);bad['ux'][key]=replacement
   with self.assertRaises(RuntimeError):m.verify_platform_rendered_result(bad)
  for group,row in value['checks'].items():
   for key in row:
    for replacement in [False,1,None]:
     bad=copy.deepcopy(value);bad['checks'][group][key]=replacement
     with self.assertRaises(RuntimeError):m.verify_platform_rendered_result(bad)
class BoundSessions(unittest.TestCase):
 def test_closed_profile_and_strict_extra_receipt(self):
  self.assertTrue(m.rendered_platform(SimpleNamespace(auth_profile='rendered-bound-session',scenario='main-backend-auth')))
  with self.assertRaises(ValueError):m.rendered_platform(SimpleNamespace(auth_profile='rendered-bound-session',scenario='main-capacity-200'))
  value={'scope':'rendered_full_backend_auth_projection','stage':'complete','passed':True,'actualModelProof':False,'ux':ux_receipt(),'checks':{'R03':{k:True for k in ['created','edited','inactiveDenied','reactivatedLogin','populatedDeletion','deletedSessionDenied','levelOneDenied','siblingPreserved']},'R06':{k:True for k in ['populatedAdminDetail','populatedLearnerDetail','privatePacketExcluded','foreignDenied']},'R02':{k:True for k in ['reloadStatusRestored','boundRenewal','crossOwnerDenied','cookieOnlyDenied','platformLogoutFencesBound','siblingPreserved']}}}
  m.verify_platform_rendered_result(value,True)
  with self.assertRaises(RuntimeError):m.verify_platform_rendered_result(value)
  value['checks']['R02']['boundRenewal']=False
  with self.assertRaises(RuntimeError):m.verify_platform_rendered_result(value,True)

class StandaloneCore(unittest.TestCase):
 def test_closed_model_free_profile(self):
  row=SimpleNamespace(scenario='main-backend-auth',main_workspace=True,entry_case=None,original_case=None,auth_profile='standalone-core')
  m.validate_original_case(row)
  self.assertTrue(m.standalone_core(row));self.assertFalse(m.rendered_platform(row))
  for changes in ({'scenario':'main-capacity-200'},{'main_workspace':False},{'browser':'/browser'},{'python_sha256':'a'*64}):
   bad=SimpleNamespace(**{**vars(row),**changes})
   with self.assertRaises(ValueError):m.validate_original_case(bad)
 def test_exact_receipt_rejects_partial_or_overclaimed_result(self):
  import copy
  value={'scope':'standalone-core','passed':True,'modelCalls':0,'sourceCopy':False,'checks':dict.fromkeys(m.STANDALONE_CORE_CHECKS,True)}
  m.verify_standalone_core_result(value)
  for key in m.STANDALONE_CORE_CHECKS:
   for replacement in (False,1,None):
    bad=copy.deepcopy(value);bad['checks'][key]=replacement
    with self.assertRaises(RuntimeError):m.verify_standalone_core_result(bad)
  for changes in ({'modelCalls':False},{'modelCalls':1},{'sourceCopy':True},{'scope':'rendered-platform'},{'unexpected':True}):
   with self.assertRaises(RuntimeError):m.verify_standalone_core_result({**value,**changes})
  for key in m.STANDALONE_CORE_CHECKS:
   bad=copy.deepcopy(value);bad['checks'].pop(key)
   with self.assertRaises(RuntimeError):m.verify_standalone_core_result(bad)
 def test_standalone_manifest_pins_renderer_and_runtime_without_copy(self):
  text=p.read_text()
  self.assertIn("current = standalone_core_source_pins(root)",text)
  self.assertIn("pins.get(rel) != pin",text)
  self.assertIn("state['standaloneCore']={'profile':args.auth_profile,'modelCalls':0,'sourceCopy':False}",text)
  self.assertIn("st.st_nlink!=1 or st.st_uid!=os.getuid() or st.st_mode&0o777!=0o600",text)
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory).resolve()
   (root/'package.json').write_text('{}');(root/'package-lock.json').write_text('{}')
   for rel in ['tests/postgres/run-setup-database-phase-isolated.py','tests/postgres/test_main_backend_auth_launcher.py','tests/secureshopStandaloneBootstrapQualification.test.js','server/applicationServer.js','client/src/pages/secureshop/components/ReviewCard.jsx','client/build/secureshop-review-renderer/manifest.json']:
    file=root/rel;file.parent.mkdir(parents=True,exist_ok=True);file.write_text('synthetic')
   pins=m.standalone_core_source_pins(root)
   self.assertIn('server/applicationServer.js',pins)
   self.assertIn('client/build/secureshop-review-renderer/manifest.json',pins)
   bad=root/'server/linked.js';bad.symlink_to(root/'server/applicationServer.js')
   with self.assertRaisesRegex(RuntimeError,'link denied'):m.standalone_core_source_pins(root)

class StandaloneCoreRendered(unittest.TestCase):
 def test_closed_rendered_selector_requires_captured_browser(self):
  row=SimpleNamespace(scenario='main-backend-auth',main_workspace=True,entry_case=None,original_case=None,auth_profile='standalone-core-rendered',browser='/browser',browser_root='/browser-root',browser_sha256='a'*64,python_sha256='b'*64)
  m.validate_original_case(row)
  self.assertTrue(m.standalone_core(row));self.assertTrue(m.standalone_core_rendered(row));self.assertTrue(m.captured_auth_browser(row));self.assertFalse(m.rendered_platform(row))
  for key in ('browser','browser_root','browser_sha256','python_sha256'):
   bad=SimpleNamespace(**{**vars(row),key:None})
   with self.assertRaises(ValueError):m.validate_original_case(bad)
  with self.assertRaises(ValueError):m.validate_original_case(SimpleNamespace(**{**vars(row),'scenario':'main-capacity-200'}))
 def test_rendered_timeout_is_profile_specific(self):
  self.assertEqual(m.scenario_bounds('main-backend-auth',auth_profile='standalone-core-rendered'),(1200,1080,120))
  for profile in (None,'standalone-core','rendered-platform','rendered-bound-session'):
   self.assertEqual(m.scenario_bounds('main-backend-auth',auth_profile=profile),(600,480,120))
  with self.assertRaises(ValueError):m.scenario_bounds('main-capacity-200',auth_profile='standalone-core-rendered')
  with self.assertRaises(ValueError):m.scenario_bounds('main-backend-auth',auth_profile='unknown')
 def test_exact_rendered_receipt_rejects_missing_or_false_check(self):
  import copy
  value={'scope':'standalone-core-rendered','passed':True,'modelCalls':0,'sourceCopy':False,'checks':dict.fromkeys(m.STANDALONE_CORE_RENDERED_CHECKS,True)}
  self.assertEqual(m.STANDALONE_CORE_RENDERED_CHECKS-m.STANDALONE_CORE_CHECKS,{
   'renderedCoexistence','shopExpiry','platformExpiry','documentedDefaults','repeatSeedPreserved',
   'renderedDefaultReadback','customerRegistration','merchantRegistration','adminRegistrationDenied',
   'authorityFieldsDenied','workshopAuthorityAbsent'})
  m.verify_standalone_core_rendered_result(value)
  with self.assertRaises(RuntimeError):m.verify_standalone_core_result(value)
  for key in m.STANDALONE_CORE_RENDERED_CHECKS:
   bad=copy.deepcopy(value);bad['checks'].pop(key)
   with self.assertRaises(RuntimeError):m.verify_standalone_core_rendered_result(bad)
   bad=copy.deepcopy(value);bad['checks'][key]=False
   with self.assertRaises(RuntimeError):m.verify_standalone_core_rendered_result(bad)
  for changes in ({'scope':'standalone-core'},{'modelCalls':1},{'sourceCopy':True},{'unexpected':True}):
   with self.assertRaises(RuntimeError):m.verify_standalone_core_rendered_result({**value,**changes})

if __name__=='__main__':unittest.main()
