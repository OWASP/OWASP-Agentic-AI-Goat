import importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
p=Path(__file__).with_name('run-finflow-backup-browser-main.py');spec=importlib.util.spec_from_file_location('finflow_launcher',p);m=importlib.util.module_from_spec(spec)
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
  for label in ['identity','finflow']:
   sql,urls=m.store_configuration(label,54321,'a'*12);self.assertEqual(len(urls),2);self.assertNotIn('SUPERUSER;',sql);self.assertIn('REVOKE CONNECT',sql)
   for key,value in urls.items():
    u=urlparse(value);self.assertEqual(u.hostname,'127.0.0.1');self.assertEqual(u.port,54321);self.assertEqual(u.path,'/owasp_ai_goat_test_finflow_browser_'+'a'*12+'_'+label);self.assertEqual(u.username,'dvaia_'+label+('_migration'if '_MIGRATION_'in key else'_runtime'))
  for values in [('other',54321,'a'*12),('identity',0,'a'*12),('finflow',54321,'not-owned')]:
   with self.assertRaises(ValueError):m.store_configuration(*values)
 def test_dpi_profile_uses_closed_sixteen_store_manifest_and_one_case(self):
  from urllib.parse import urlparse
  self.assertEqual(len(m.DPI_STORES),16)
  self.assertEqual(m.DPI_STORES[0],('identity','IDENTITY'))
  self.assertEqual(m.DPI_STORES[-1],('secureshop_review','SECURESHOP_REVIEW'))
  for label,prefix in m.DPI_STORES:
   sql,urls=m.store_configuration(label,54321,'a'*12,'actual-dpi-system-prompt')
   self.assertEqual(set(urls),{prefix+'_DATABASE_URL',prefix+'_MIGRATION_DATABASE_URL'}|({'CTF_DELIVERY_DATABASE_URL'} if label=='ctf' else set()))
   self.assertIn('REVOKE CONNECT',sql)
   self.assertEqual({urlparse(value).path for value in urls.values()},{'/owasp_ai_goat_test_dpi_browser_'+'a'*12+'_'+label})
   if label=='ctf':
    self.assertIn('CREATE ROLE dvaia_ctf_delivery LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',sql)
    self.assertEqual(urlparse(urls['CTF_DELIVERY_DATABASE_URL']).username,'dvaia_ctf_delivery')
  with self.assertRaises(ValueError):m.store_configuration('unknown',54321,'a'*12,'actual-dpi-system-prompt')
  args=type('Args',(),dict(profile='actual-dpi-system-prompt',main_workspace='/main',manifest='/manifest',manifest_sha256='a'*64,input='/fixed',input_sha256=m.DPI_INPUT_SHA256,browser='/chrome',browser_sha256='b'*64))()
  with patch.dict(os.environ,{'OPENAI_API_KEY':'private','IDENTITY_DATABASE_URL':'installed','NODE_OPTIONS':'unsafe'}):env=m.child_environment({'PATH':'/pinned'},Path('/evidence'),Path('/evidence/runtime'),'owner',args)
  self.assertEqual(env['DPI_ACTUAL_SYSTEM_PROMPT_RENDERED'],'1')
  self.assertEqual(env['DPI_ACTUAL_BROWSER_INPUT_SHA256'],m.DPI_INPUT_SHA256)
  self.assertEqual(env['OLLAMA_MODEL'],'llama3.1:8b')
  self.assertEqual(env['OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE'],'/main')
  self.assertEqual(env['DPI_BROWSER_RUNTIME_CWD'],'/evidence/runtime')
  self.assertEqual(env['OWASP_AI_GOAT_APP_DATA_ROOT'],'/evidence/runtime/appdata')
  for key in ['OPENAI_API_KEY','IDENTITY_DATABASE_URL','NODE_OPTIONS']:self.assertNotIn(key,env)
 def test_dpi_boot_preflight_is_closed_and_reports_no_browser_as_expected(self):
  args=type('Args',(),{'plan':True,'profile':'backup','dpi_boot_preflight':True})()
  with patch.object(m,'parse_main',return_value=args):
   with self.assertRaisesRegex(RuntimeError,'DPI boot preflight requires'):m.main_current([])
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);state={'profile':'actual-dpi-system-prompt','evidenceRoot':str(root),'bootPreflight':True,'exitCode':0,'browserSha256':'a'*64}
   self.assertEqual(m.verify_browser_absence(root,state,[]),{'started':False,'bootOnly':True,'profileRetained':False})
   state.update(bootPreflight=False,exitCode=1)
   self.assertEqual(m.verify_browser_absence(root,state,[]),{'started':False,'failureBeforeBrowser':True,'profileRetained':False})
   (root/'browser-launch-intent.json').write_text(json.dumps({'profile':'actual-dpi-system-prompt','root':str(root),'runtime':str(root)}))
   (root/'browser-launch-intent.json').chmod(0o600)
   with self.assertRaisesRegex(RuntimeError,'DPI browser ownership evidence missing'):m.verify_browser_absence(root,state,[])
 def test_dpi_health_preflight_requires_exact_rendered_profile(self):
  for profile,boot in [('backup',False),('actual-dpi-system-prompt',True)]:
   args=type('Args',(),{'plan':True,'profile':profile,'dpi_boot_preflight':boot,'dpi_health_preflight':True})()
   with patch.object(m,'parse_main',return_value=args):
    with self.assertRaisesRegex(RuntimeError,'DPI rendered health preflight requires'):m.main_current([])
 def test_environment_no_inherited_secrets(self):
  args=type('Args',(),dict(main_workspace='/main',manifest='/manifest',manifest_sha256='a'*64,input='/frozen',input_sha256=m.ACTUAL_INPUT_SHA256,browser='/chrome',browser_sha256='b'*64))()
  with patch.dict(os.environ,{'OPENAI_API_KEY':'private','IDENTITY_DATABASE_URL':'installed','NODE_OPTIONS':'unsafe'}):env=m.child_environment({'PATH':'/pinned'},Path('/evidence'),Path('/evidence/runtime'),'owner',args)
  for key in ['OPENAI_API_KEY','IDENTITY_DATABASE_URL','NODE_OPTIONS','OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE']:self.assertNotIn(key,env)
  self.assertEqual(env['ANALYTICS_BROWSER_EXECUTABLE'],env['FINFLOW_BROWSER_CHROME'])
  appdata=Path(env['OWASP_AI_GOAT_APP_DATA_ROOT'])
  self.assertEqual(Path(env['FINFLOW_BACKUP_ROOT']),appdata/'finflow-backups')
  self.assertEqual(Path(env['FINFLOW_TRAVERSAL_TARGET_ROOT']),appdata/'finflow-traversal-targets')
  self.assertNotEqual(env['FINFLOW_BACKUP_ROOT'],env['FINFLOW_TRAVERSAL_TARGET_ROOT']);self.assertEqual(env['OWASP_AI_GOAT_APP_DATA_ROOT'],'/evidence/runtime/appdata');self.assertEqual(env['FINFLOW_BROWSER_INPUTS_SHA256'],m.ACTUAL_INPUT_SHA256)
 def test_browser_absence_retains_profile_and_denies_wrong_identity(self):
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);(root/'browser-profile').mkdir();state={'nativePid':20,'browserSha256':'a'*64,'exitCode':0};row={**{k:20 for k in ['pgid','sessionId','qualificationPid','qualificationPgid','qualificationSessionId','workerPid']},'pid':21,'uid':os.getuid(),'profile':str(root/'browser-profile'),'executableSha256':'a'*64};p=root/'browser-process.json';p.write_text(json.dumps(row));p.chmod(0o600)
   self.assertTrue(m.verify_browser_absence(root,state,[])['profileRetained']);self.assertTrue((root/'browser-profile').exists())
   with self.assertRaises(RuntimeError):m.verify_browser_absence(root,state,[(22,20,os.getuid())])
   row['pgid']=30;p.write_text(json.dumps(row))
   with self.assertRaises(RuntimeError):m.verify_browser_absence(root,state,[])
 def test_build_requires_successful_source_dependency_binding(self):
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);manifest={k:{'file':{'sha256':'a'}}for k in ['clientSourceInventory','clientPublicInventory','clientDependencyInventory','clientBuildInventory']};manifest['dependencyInventory']={'dep':{'sha256':'b'}};manifest.update(buildReport='build.json',sourcePins={'build.json':'pin',**{p:'pin'for p in ['client/package.json','client/package-lock.json','client/vite.config.mjs','client/index.html']}})
   report={'qualified':True,'workspace':str(root),'buildInputInventorySha256':'bound','exitCode':0,'beforeAfterInputsEqual':True,'rootDependencyInventorySha256':m.inventory_sha(manifest['dependencyInventory']),'clientBuildConfigPins':{p:'pin'for p in ['client/package.json','client/package-lock.json','client/vite.config.mjs','client/index.html']},**{k+'Sha256':m.inventory_sha(manifest[k])for k in ['clientSourceInventory','clientPublicInventory','clientDependencyInventory','clientBuildInventory']}};(root/'build.json').write_text(json.dumps(report))
   with patch.object(m,'inventory',return_value={'file':{'sha256':'a'}}),patch.object(m,'current_build_fingerprint',return_value='bound'):
    m.validate_build_provenance(root,manifest)
    report['clientSourceInventorySha256']='wrong';(root/'build.json').write_text(json.dumps(report))
    with self.assertRaises(RuntimeError):m.validate_build_provenance(root,manifest)
 def test_frozen_input_pin_and_log_aggregate(self):
  root=Path('/main');args=type('Args',(),{'input':str(root/m.ACTUAL_INPUT),'input_sha256':m.ACTUAL_INPUT_SHA256})()
  with patch.object(m.Path,'is_symlink',return_value=False),patch.object(m.Path,'resolve',return_value=root/m.ACTUAL_INPUT),patch.object(m,'private_input_digest',return_value=m.ACTUAL_INPUT_SHA256):
   m.validate_actual_input(args,root,{'sourcePins':{m.ACTUAL_INPUT:m.ACTUAL_INPUT_SHA256}})
   with self.assertRaises(RuntimeError):m.validate_actual_input(args,root,{'sourcePins':{}})
  with tempfile.TemporaryDirectory()as d:
   root=Path(d)
   for name in ['one.log','two.tap']:
    with(root/name).open('wb')as f:f.truncate(33*1024**2)
   with self.assertRaises(RuntimeError):m.check_logs(root)
 def test_profile_links_are_opaque_inside_owned_boundary(self):
  with tempfile.TemporaryDirectory()as d:
   root=Path(d).resolve();profile=root/'runtime'/'browser-profile';profile.mkdir(parents=True)
   for name in ['SingletonSocket','SingletonCookie','SingletonLock','RunningChromeVersion']:(profile/name).symlink_to('/nonexistent/opaque-chrome-target')
   (profile/'nested').mkdir();(profile/'nested'/'arbitrary-link').symlink_to('/nonexistent/opaque-target')
   (root/'child.log').write_text('log');self.assertEqual(m.check_logs(root),3)
   for foreign in [root/'runtime'/'OtherLink',root/'SingletonLock']:
    foreign.parent.mkdir(exist_ok=True);foreign.symlink_to('/nonexistent/opaque-target')
    with self.assertRaisesRegex(RuntimeError,'Owned evidence link'):m.check_logs(root)
    foreign.unlink()
   with patch.object(m.os,'getuid',return_value=os.getuid()+1):
    with self.assertRaisesRegex(RuntimeError,'Owned evidence link'):m.check_logs(root)
   with(root/'large.log').open('wb')as f:f.truncate(64*1024**2)
   with self.assertRaisesRegex(RuntimeError,'Aggregate log cap'):m.check_logs(root)
 def test_disappearing_profile_entry_is_sampled_without_following(self):
  with tempfile.TemporaryDirectory()as d:
   root=Path(d).resolve();profile=root/'runtime'/'browser-profile';profile.mkdir(parents=True);gone=profile/'transient.log';gone.write_text('x')
   original=Path.lstat
   def sample(p,*args,**kwargs):
    if p==gone:raise FileNotFoundError()
    return original(p,*args,**kwargs)
   with patch.object(Path,'lstat',sample):self.assertEqual(m.check_logs(root),0)
 def test_linked_browser_profile_rejected(self):
  with tempfile.TemporaryDirectory()as d:
   root=Path(d).resolve();(root/'runtime').mkdir();(root/'target').mkdir();(root/'runtime'/'browser-profile').symlink_to(root/'target',target_is_directory=True)
   with self.assertRaisesRegex(RuntimeError,'Owned evidence link'):m.check_logs(root)
class StatementControls(unittest.TestCase):
 def receipt(self):
  return dict(profile='controlled-statement',scope='controlled-statement-download',actualModelProof=False,modelWireVerified=False,modelCalls=0,genuineCredit=0,installedWrites=False,ownerBound=True,resetAdvanced=True,staleDenied=True,siblingPreserved=True,revocationDenied=True,controlledCalls=7,apiRequests=8,browserRequests=100,downloads=[dict(sha256='a'*64,byteLength=2000,objects=5,pages=1,filename='statement_FF-001_2024.pdf') for _ in range(3)])
 def test_statement_receipt_denies_missing_fences_credit_and_bad_download(self):
  value=self.receipt();m.verify_statement_result(value)
  for key in value:
   broken=dict(value);del broken[key]
   with self.assertRaises((RuntimeError,TypeError)):m.verify_statement_result(broken)
  for patch in [dict(actualModelProof=True),dict(genuineCredit=1),dict(controlledCalls=9),dict(browserRequests=401),dict(profile='backup'),dict(downloads=value['downloads'][:2]),dict(staleDenied=1)]:
   with self.assertRaises(RuntimeError):m.verify_statement_result({**value,**patch})
  broken=self.receipt();broken['downloads'][0]['filename']='../statement.pdf'
  with self.assertRaises(RuntimeError):m.verify_statement_result(broken)
 def test_closed_statement_input_is_independent_of_original_backup(self):
  root=Path('/main');args=type('Args',(),dict(profile='controlled-statement',input=str(root/m.STATEMENT_INPUT),input_sha256=m.STATEMENT_INPUT_SHA256))()
  with patch.object(m.Path,'is_symlink',return_value=False),patch.object(m.Path,'resolve',return_value=root/m.STATEMENT_INPUT),patch.object(m,'private_input_digest',return_value=m.STATEMENT_INPUT_SHA256):
   m.validate_actual_input(args,root,{'sourcePins':{m.STATEMENT_INPUT:m.STATEMENT_INPUT_SHA256}})
   args.input=str(root/m.ACTUAL_INPUT)
   with self.assertRaises(RuntimeError):m.validate_actual_input(args,root,{'sourcePins':{m.STATEMENT_INPUT:m.STATEMENT_INPUT_SHA256}})
 def test_statement_plan_preserves_deadlines_without_allocating(self):
  args=type('Args',(),dict(profile='controlled-statement',plan=True))()
  with patch.object(m,'parse_main',return_value=args),patch.object(m,'validate_main',return_value=(Path('/main'),{})),patch.object(m.tempfile,'mkdtemp',side_effect=AssertionError('No resources')):self.assertEqual(m.main_current([]),0)


class TraversalContent(unittest.TestCase):
 def test_closed_content_receipt_preserves_original_profiles(self):
  from types import SimpleNamespace
  self.assertEqual(m.selected_cohort(SimpleNamespace()),'finflow-backup-browser-main')
  self.assertEqual(m.selected_cohort(SimpleNamespace(profile='controlled-statement')),'finflow-statement-browser-main')
  self.assertEqual(m.selected_cohort(SimpleNamespace(profile='controlled-traversal-content')),'finflow-traversal-content-browser-main')
  good={'profile':'controlled-traversal-content','scope':'three-objective-controlled-rendered-parity','actualModelProof':False,'modelWireVerified':False,'modelCalls':0,'genuineCredit':0,'installedWrites':False,'projection':'controlled-existing-completion-shape','siblingPreserved':True,'configurationRestored':True,'projectionRowsPreserved':True,'dashboardParity':True,'apiRequests':40,'browserRequests':400,'cases':[{'id':id,'learnerContent':True,'adminPreview':True,'independentGates':True,'completedProjection':True} for id in ['traversal_secrets','traversal_passwd','traversal_llm']]}
  m.verify_traversal_content_result(good)
  import copy
  for mutate in [lambda x:x.update(modelCalls=True),lambda x:x.update(actualModelProof=True),lambda x:x.update(apiRequests=41),lambda x:x.update(configurationRestored=False),lambda x:x['cases'].pop(),lambda x:x['cases'][0].update(id='admin_backup')]:
   bad=copy.deepcopy(good);mutate(bad)
   with self.assertRaises(RuntimeError):m.verify_traversal_content_result(bad)

class BackupContent(unittest.TestCase):
 def test_exact_input_and_closed_receipt(self):
  from types import SimpleNamespace
  import copy
  root=p.resolve().parents[2]
  args=SimpleNamespace(profile='controlled-backup-content',input=str(root/m.BACKUP_CONTENT_INPUT),input_sha256=m.BACKUP_CONTENT_INPUT_SHA256)
  manifest={'sourcePins':{m.BACKUP_CONTENT_INPUT:m.BACKUP_CONTENT_INPUT_SHA256}}
  self.assertEqual(m.selected_cohort(args),'finflow-backup-content-browser-main');m.validate_actual_input(args,root,manifest)
  bad=copy.copy(args);bad.input=str(root/m.TRAVERSAL_INPUT)
  with self.assertRaises(RuntimeError):m.validate_actual_input(bad,root,manifest)
  good={'profile':'controlled-backup-content','scope':'two-objective-controlled-backup-rendered-parity','actualModelProof':False,'modelWireVerified':False,'modelCalls':0,'genuineCredit':0,'installedWrites':False,'projection':'controlled-existing-completion-shape','siblingPreserved':True,'configurationRestored':True,'projectionRowsPreserved':True,'dashboardParity':True,'apiRequests':40,'browserRequests':400,'cases':[{'id':id,'learnerContent':True,'adminPreview':True,'independentGates':True,'completedProjection':True} for id in ['admin_backup','admin_dl_backup']]}
  m.verify_traversal_content_result(good,args.profile)
  with self.assertRaises(RuntimeError):m.verify_traversal_content_result(good)
  for mutate in [lambda x:x.update(modelCalls=True),lambda x:x.update(actualModelProof=True),lambda x:x.update(browserRequests=401),lambda x:x.update(apiRequests=41),lambda x:x.update(configurationRestored=False),lambda x:x['cases'].reverse(),lambda x:x['cases'].pop(),lambda x:x['cases'][0].update(id='traversal_secrets')]:
   bad=copy.deepcopy(good);mutate(bad)
   with self.assertRaises(RuntimeError):m.verify_traversal_content_result(bad,args.profile)

 def test_backup_content_plan_is_nonallocating(self):
  from types import SimpleNamespace
  args=SimpleNamespace(profile='controlled-backup-content',plan=True)
  with patch.object(m,'parse_main',return_value=args),patch.object(m,'validate_main',return_value=(Path('/main'),{})),patch.object(m.importlib.util,'spec_from_file_location',side_effect=AssertionError('No helper import')),patch.object(m.tempfile,'mkdtemp',side_effect=AssertionError('No allocation')):self.assertEqual(m.main_current([]),0)

class SsrfContent(unittest.TestCase):
 def test_ssrf_input_and_full_seed_receipt(self):
  from types import SimpleNamespace
  import copy
  root=p.resolve().parents[2];args=SimpleNamespace(profile='controlled-ssrf-content',input=str(root/m.SSRF_CONTENT_INPUT),input_sha256=m.SSRF_CONTENT_INPUT_SHA256)
  m.validate_actual_input(args,root,{'sourcePins':{m.SSRF_CONTENT_INPUT:m.SSRF_CONTENT_INPUT_SHA256}})
  self.assertEqual(m.selected_cohort(args),'finflow-ssrf-content-browser-main')
  ids=['ssrf_oob','ssrf_internal','ssrf_ollama']
  seed=dict(version='finflow-ssrf-seed-v1',objectiveIds=ids,exactSecondSeeds=4,**{key:True for key in ['freshDefaults','managedPriorUpgrade','instructorCustomPreserved','explicitNullPreserved','independentGatesPreserved','siblingCatalogPreserved','rollbackRestored']})
  good=dict(profile=args.profile,scope='three-objective-controlled-ssrf-rendered-parity',actualModelProof=False,modelWireVerified=False,modelCalls=0,genuineCredit=0,installedWrites=False,projection='controlled-existing-completion-shape',siblingPreserved=True,configurationRestored=True,projectionRowsPreserved=True,dashboardParity=True,apiRequests=40,browserRequests=400,seedQualification=seed,cases=[dict(id=id,learnerContent=True,adminPreview=True,independentGates=True,completedProjection=True)for id in ids])
  m.verify_traversal_content_result(good,args.profile)
  for key in seed:
   bad=copy.deepcopy(good);del bad['seedQualification'][key]
   with self.assertRaises(RuntimeError):m.verify_traversal_content_result(bad,args.profile)
  for change in [lambda x:x['seedQualification'].update(exactSecondSeeds=True),lambda x:x['seedQualification'].update(instructorCustomPreserved=1),lambda x:x['cases'].pop(),lambda x:x.update(browserRequests=401),lambda x:x.update(modelCalls=1)]:
   bad=copy.deepcopy(good);change(bad)
   with self.assertRaises(RuntimeError):m.verify_traversal_content_result(bad,args.profile)

class ReconContent(unittest.TestCase):
 def test_recon_closed_input_and_receipt(self):
  from types import SimpleNamespace
  import copy
  root=p.resolve().parents[2];args=SimpleNamespace(profile='controlled-recon-content',input=str(root/m.RECON_CONTENT_INPUT),input_sha256=m.RECON_CONTENT_INPUT_SHA256)
  m.validate_actual_input(args,root,{'sourcePins':{m.RECON_CONTENT_INPUT:m.RECON_CONTENT_INPUT_SHA256}});self.assertEqual(m.selected_cohort(args),'finflow-recon-content-browser-main')
  ids=['tool_enum','llm_identify','tool_version','error_leak'];good=dict(profile=args.profile,scope='four-objective-controlled-recon-rendered-parity',actualModelProof=False,modelWireVerified=False,modelCalls=0,genuineCredit=0,installedWrites=False,projection='controlled-existing-completion-shape',siblingPreserved=True,configurationRestored=True,projectionRowsPreserved=True,dashboardParity=True,apiRequests=40,browserRequests=500,cases=[dict(id=id,learnerContent=True,adminPreview=True,independentGates=True,completedProjection=True)for id in ids]);m.verify_traversal_content_result(good,args.profile)
  for change in [lambda x:x['cases'].pop(),lambda x:x['cases'][3].update(id='admin_enum'),lambda x:x['cases'][3].update(independentGates=False),lambda x:x.update(modelCalls=1),lambda x:x.update(apiRequests=41),lambda x:x.update(browserRequests=501)]:
   bad=copy.deepcopy(good);change(bad)
   with self.assertRaises(RuntimeError):m.verify_traversal_content_result(bad,args.profile)

class AdminLogContent(unittest.TestCase):
 def test_admin_log_pair_input_receipt_and_unchanged_cap(self):
  from types import SimpleNamespace
  import copy
  root=p.resolve().parents[2];args=SimpleNamespace(profile='controlled-admin-log-content',input=str(root/m.ADMIN_LOG_CONTENT_INPUT),input_sha256=m.ADMIN_LOG_CONTENT_INPUT_SHA256)
  m.validate_actual_input(args,root,{'sourcePins':{m.ADMIN_LOG_CONTENT_INPUT:m.ADMIN_LOG_CONTENT_INPUT_SHA256}});self.assertEqual(m.selected_cohort(args),'finflow-admin-log-content-browser-main')
  ids=['admin_read_logs','admin_llm_logs'];good=dict(profile=args.profile,scope='two-objective-controlled-admin-log-rendered-parity',actualModelProof=False,modelWireVerified=False,modelCalls=0,genuineCredit=0,installedWrites=False,projection='controlled-existing-completion-shape',siblingPreserved=True,configurationRestored=True,projectionRowsPreserved=True,dashboardParity=True,apiRequests=40,browserRequests=400,cases=[dict(id=id,learnerContent=True,adminPreview=True,independentGates=True,completedProjection=True)for id in ids]);m.verify_traversal_content_result(good,args.profile)
  for change in [lambda x:x['cases'].pop(),lambda x:x['cases'].reverse(),lambda x:x['cases'][1].update(id='admin_modify_logs'),lambda x:x['cases'][0].update(independentGates=False),lambda x:x.update(modelCalls=1),lambda x:x.update(apiRequests=41),lambda x:x.update(browserRequests=401),lambda x:x.update(configurationRestored=False)]:
   bad=copy.deepcopy(good);change(bad)
   with self.assertRaises(RuntimeError):m.verify_traversal_content_result(bad,args.profile)

class AdminArtifactContent(unittest.TestCase):
 def test_admin_artifact_pair_input_receipt_and_unchanged_cap(self):
  from types import SimpleNamespace
  import copy
  root=p.resolve().parents[2];args=SimpleNamespace(profile='controlled-admin-artifact-content',input=str(root/m.ADMIN_ARTIFACT_CONTENT_INPUT),input_sha256=m.ADMIN_ARTIFACT_CONTENT_INPUT_SHA256)
  m.validate_actual_input(args,root,{'sourcePins':{m.ADMIN_ARTIFACT_CONTENT_INPUT:m.ADMIN_ARTIFACT_CONTENT_INPUT_SHA256}});self.assertEqual(m.selected_cohort(args),'finflow-admin-artifact-content-browser-main')
  ids=['admin_secrets','admin_dirlist'];good=dict(profile=args.profile,scope='two-objective-controlled-admin-artifact-rendered-parity',actualModelProof=False,modelWireVerified=False,modelCalls=0,genuineCredit=0,installedWrites=False,projection='controlled-existing-completion-shape',siblingPreserved=True,configurationRestored=True,projectionRowsPreserved=True,dashboardParity=True,apiRequests=40,browserRequests=400,cases=[dict(id=id,learnerContent=True,adminPreview=True,independentGates=True,completedProjection=True)for id in ids]);m.verify_traversal_content_result(good,args.profile)
  for change in [lambda x:x['cases'].pop(),lambda x:x['cases'].reverse(),lambda x:x['cases'][1].update(id='admin_modify_logs'),lambda x:x['cases'][0].update(independentGates=False),lambda x:x.update(modelCalls=1),lambda x:x.update(apiRequests=41),lambda x:x.update(browserRequests=401),lambda x:x.update(configurationRestored=False)]:
   bad=copy.deepcopy(good);change(bad)
   with self.assertRaises(RuntimeError):m.verify_traversal_content_result(bad,args.profile)

class AdminMutationContent(unittest.TestCase):
 def test_admin_mutation_single_input_receipt_and_unchanged_cap(self):
  from types import SimpleNamespace
  import copy
  root=p.resolve().parents[2];args=SimpleNamespace(profile='controlled-admin-mutation-content',input=str(root/m.ADMIN_MUTATION_CONTENT_INPUT),input_sha256=m.ADMIN_MUTATION_CONTENT_INPUT_SHA256)
  m.validate_actual_input(args,root,{'sourcePins':{m.ADMIN_MUTATION_CONTENT_INPUT:m.ADMIN_MUTATION_CONTENT_INPUT_SHA256}});self.assertEqual(m.selected_cohort(args),'finflow-admin-mutation-content-browser-main')
  ids=['admin_modify_logs'];good=dict(profile=args.profile,scope='one-objective-controlled-admin-mutation-rendered-parity',actualModelProof=False,modelWireVerified=False,modelCalls=0,genuineCredit=0,installedWrites=False,projection='controlled-existing-completion-shape',siblingPreserved=True,configurationRestored=True,projectionRowsPreserved=True,dashboardParity=True,apiRequests=40,browserRequests=400,cases=[dict(id=id,learnerContent=True,adminPreview=True,independentGates=True,completedProjection=True)for id in ids]);m.verify_traversal_content_result(good,args.profile)
  for change in [lambda x:x['cases'].pop(),lambda x:x['cases'].append(dict(x['cases'][0])),lambda x:x['cases'][0].update(id='admin_secrets'),lambda x:x['cases'][0].update(independentGates=False),lambda x:x.update(modelCalls=1),lambda x:x.update(apiRequests=41),lambda x:x.update(browserRequests=401),lambda x:x.update(configurationRestored=False)]:
   bad=copy.deepcopy(good);change(bad)
   with self.assertRaises(RuntimeError):m.verify_traversal_content_result(bad,args.profile)


class AdminEnumContent(unittest.TestCase):
 def test_closed_enum_input_and_lifecycle_receipt(self):
  from types import SimpleNamespace
  import copy
  root=p.resolve().parents[2];profile='controlled-admin-enum-content';args=SimpleNamespace(profile=profile,input=str(root/m.ADMIN_ENUM_CONTENT_INPUT),input_sha256=m.ADMIN_ENUM_CONTENT_INPUT_SHA256)
  m.validate_actual_input(args,root,{'sourcePins':{m.ADMIN_ENUM_CONTENT_INPUT:m.ADMIN_ENUM_CONTENT_INPUT_SHA256}})
  self.assertEqual(m.selected_cohort(args),'finflow-admin-enum-content-browser-main')
  reset=dict(status='completed',fromGeneration=0,toGeneration=1,operationId='owned-operation')
  good=dict(profile=profile,scope='one-objective-controlled-admin-enum-content-lifecycle',nonemptyPreservationFixtures=True,preservationFixtureScope='Controlled nonempty owner other-family and sibling canonical/time/local rows; no genuine credit',actualModelProof=False,modelWireVerified=False,modelCalls=0,judgeCalls=0,genuineCredit=0,installedWrites=False,projection='controlled-existing-completion-shape',controlledProjectionCount=1,siblingPreserved=True,configurationRestored=True,projectionRowsPreserved=False,dashboardParity=True,projectionRetired=True,resetTimeRetired=True,resetReplayExact=True,sessionDenied=True,adminProgress=True,untouchedFamiliesPreserved=True,immutableEvidencePreserved=False,immutableEvidenceScope='Empty content fixture; native immutable reset evidence is separate',apiRequests=40,browserRequests=400,cases=[dict(id='admin_enum',learnerContent=True,adminPreview=True,independentGates=True,completedProjection=True)],lifecycle=dict(resetBefore={},resetAfter={},replayAfter={},reset=reset,replay=dict(reset)))
  m.verify_traversal_content_result(good,profile)
  changes=[lambda x:x['cases'][0].update(id='tool_enum'),lambda x:x.update(projectionRowsPreserved=True),lambda x:x.update(judgeCalls=1),lambda x:x.update(genuineCredit=1),lambda x:x.update(immutableEvidencePreserved=True),lambda x:x.update(browserRequests=401),lambda x:x.update(apiRequests=41),lambda x:x.pop('lifecycle'),lambda x:x['lifecycle']['replay'].update(toGeneration=2)]
  for key in ['nonemptyPreservationFixtures','projectionRetired','resetTimeRetired','resetReplayExact','sessionDenied','adminProgress','untouchedFamiliesPreserved']:
   changes.append(lambda x,k=key:x.update({k:False}))
  for change in changes:
   bad=copy.deepcopy(good);change(bad)
   with self.assertRaises(RuntimeError):m.verify_traversal_content_result(bad,profile)

class DpiBaselineLanguageProfile(unittest.TestCase):
 def test_controlled_tail_plan_is_zero_generation_and_profile_bound(self):
  from types import SimpleNamespace
  args=SimpleNamespace(profile='actual-dpi-baseline-language',dpi_tail_preflight=True,plan=True)
  with patch.object(m,'parse_main',return_value=args),patch.object(m,'validate_main',return_value=(Path('/main'),{})),patch.object(m.tempfile,'mkdtemp',side_effect=AssertionError('No resources')):
   with patch('sys.stdout',new_callable=__import__('io').StringIO) as output:
    self.assertEqual(m.main_current([]),0)
  value=json.loads(output.getvalue());self.assertEqual(value['mode'],'controlled-tail');self.assertEqual(value['maxModelCalls'],0);self.assertEqual(len(value['stores']),16);self.assertFalse(value['allocation'])
  args.profile='actual-dpi-system-prompt'
  with patch.object(m,'parse_main',return_value=args),self.assertRaisesRegex(RuntimeError,'exact baseline/language profile'):m.main_current([])
 def test_closed_five_turn_profile_isolated_from_installed_configuration(self):
  from types import SimpleNamespace
  from urllib.parse import urlparse
  args=SimpleNamespace(profile='actual-dpi-baseline-language',main_workspace='/main',manifest='/manifest',manifest_sha256='a'*64,input='/main/'+m.DPI_BASELINE_LANGUAGE_INPUT,input_sha256=m.DPI_BASELINE_LANGUAGE_INPUT_SHA256,browser='/chrome',browser_sha256='b'*64)
  self.assertEqual(m.selected_cohort(args),'dpi-baseline-language-browser-main')
  self.assertEqual(len(m.DPI_STORES),16)
  for label,prefix in m.DPI_STORES:
   sql,urls=m.store_configuration(label,54321,'a'*12,args.profile)
   self.assertEqual({urlparse(value).path for value in urls.values()},{'/owasp_ai_goat_test_dpi_browser_'+'a'*12+'_'+label})
   self.assertEqual(set(urls),{prefix+'_DATABASE_URL',prefix+'_MIGRATION_DATABASE_URL'}|({'CTF_DELIVERY_DATABASE_URL'} if label=='ctf' else set()))
   self.assertIn('REVOKE CONNECT',sql)
  with patch.object(m,'private_input_digest',return_value=m.DPI_BASELINE_LANGUAGE_INPUT_SHA256):
   m.validate_actual_input(args,Path('/main'),{'sourcePins':{m.DPI_BASELINE_LANGUAGE_INPUT:m.DPI_BASELINE_LANGUAGE_INPUT_SHA256}})
   with self.assertRaises(RuntimeError):m.validate_actual_input(args,Path('/main'),{'sourcePins':{}})
  with patch.dict(os.environ,{'IDENTITY_DATABASE_URL':'installed','OPENAI_API_KEY':'private','PORT':'8081','NODE_OPTIONS':'unsafe'}):
   env=m.child_environment({'PATH':'/pinned'},Path('/evidence'),Path('/private/tmp/owned-dpi'),'owner',args)
  self.assertEqual(env['DPI_ACTUAL_BASELINE_LANGUAGE_RENDERED'],'1')
  self.assertNotIn('DPI_ACTUAL_SYSTEM_PROMPT_RENDERED',env)
  self.assertEqual(env['DPI_ACTUAL_BROWSER_INPUT_SHA256'],m.DPI_BASELINE_LANGUAGE_INPUT_SHA256)
  self.assertEqual(env['DPI_BROWSER_RUNTIME_CWD'],'/private/tmp/owned-dpi')
  self.assertEqual(env['OWASP_AI_GOAT_APP_DATA_ROOT'],'/private/tmp/owned-dpi/appdata')
  for key in ['IDENTITY_DATABASE_URL','OPENAI_API_KEY','PORT','NODE_OPTIONS']:self.assertNotIn(key,env)

class PrivateInputAdmission(unittest.TestCase):
 def test_private_read_contract(self):
  import hashlib
  with tempfile.TemporaryDirectory() as directory:
   f=Path(directory)/'input';f.write_bytes(b'bounded');f.chmod(0o400)
   self.assertEqual(m.private_input_digest(f),hashlib.sha256(b'bounded').hexdigest())
   for mode in [0o644,0o640,0o404]:
    f.chmod(mode)
    with self.assertRaises(RuntimeError):m.private_input_digest(f)
   f.chmod(0o600)
   with patch.object(m.os,'getuid',return_value=os.getuid()+1):
    with self.assertRaises(RuntimeError):m.private_input_digest(f)
   link=Path(directory)/'link';link.symlink_to(f)
   with self.assertRaises(OSError):m.private_input_digest(link)
   hard=Path(directory)/'hard';os.link(f,hard)
   with self.assertRaises(RuntimeError):m.private_input_digest(f)
 def test_startup_diagnostic_is_bounded(self):
  import subprocess
  source="const m=require('./tests/postgres/finflowBackupBrowser.integration.test');const d=m.failureDiagnostic(Error('password=secret postgresql://secret'),'startup');if(JSON.stringify(d).includes('secret'))process.exit(1);"
  subprocess.run(['node','-e',source],cwd=p.resolve().parents[2],check=True,capture_output=True)

class ActualAdminEnum(unittest.TestCase):
 def receipt(self):
  import hashlib
  sha=lambda x:hashlib.sha256(x.encode()).hexdigest()
  sequence=json.loads((p.resolve().parents[2]/m.ADMIN_ENUM_ACTUAL_INPUT).read_text())['successfulSequence']
  result=dict(profile='actual-admin-enum',scope='eight-turn-admin-enum-actual-native',status='passed',installedWrites=False,actualModelProof=True,modelWireVerified=True,model='llama3.1:8b',modelDigest='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e',failures=[],cleanupFailures=[],sequenceSha256=[sha(x) for x in sequence],cases=[])
  captures=dict(profile='actual-admin-enum',cases=[]);calls=[dict(index=0,kind='tags',caseId=None,terminal='returned',responseComplete=True,responseCaptureTruncated=False,status=200,request='',response='{}',requestSha256=sha(''),responseSha256=sha('{}'),requestBytes=0,responseBytes=2)]
  owners=['fresh-owner-1','fresh-owner-2','fresh-owner-3','fixed']
  for n,name in enumerate(owners):
   checks={k:True for k in ['initialized','benign_first_turn_no_credit','generated_history_used','fixed_mode_set','fixed_catalog_unavailable','fixed_denied_credit','fresh_catalog_selected','authoritative_catalog_received','eight_names','real_judge_pass','canonical_credit']};turns=[]
   for turn in [1,2]:
    for suffix in ['http','actual_model','judge_provenance','persisted_receipt','packet_wire_binding']:checks[f'turn_{turn}_{suffix}']=True
    case=f'{name}:turn-{turn}';indices=[]
    for kind in ['generate','generate','chat']:
     indices.append(len(calls));calls.append(dict(index=len(calls),kind=kind,caseId=case,terminal='returned',responseComplete=True,responseCaptureTruncated=False,status=200,request='{"model":"llama3.1:8b"}',response='{}',requestSha256=sha('{"model":"llama3.1:8b"}'),responseSha256=sha('{}'),requestBytes=23,responseBytes=2))
    packet=dict(rubric=dict(objectiveId='admin_enum',version='finflow-admin-catalog-v2'));raw=json.dumps(packet);run=f'run-{n}-{turn}';positive=n<3 and turn==2
    captures['cases'].append(dict(caseId=case,ownerId=n+1,request=dict(objectiveId='admin_enum',userMessage=sequence[turn-1],conversationHistory=[] if turn==1 else [dict(role='user',content=sequence[0]),dict(role='assistant',content='response')]),response=dict(status=200,body=dict(run=dict(runId=run),response='response')),run=dict(run_id=run,owner_key=json.dumps(['FinFlow',str(n+1)],separators=(',',':'))),judgment=dict(run_id=run,user_id=n+1,evaluation_id=run,evidence_digest=sha(raw),verdict='pass' if positive else 'fail',disposition='awarded' if positive else 'not_pass'),packetRecord=dict(user_id=n+1,evaluation_id=run,packet=raw),packet=packet,trace=[{}],wireIndexes=indices));turns.append(dict(turn=turn))
   result['cases'].append(dict(name=name,checks=checks,turns=turns))
  result['cases'].append(dict(name='owner-reset',checks=dict(reset_success=True,siblings_preserved=True,sibling_credit_nonempty=True)))
  before=[dict(generation=0,rows=[{'objective_id':'admin_enum'}]) for _ in range(3)]+[dict(generation=0,rows=[])];captures['reset']=dict(before=before,after=[dict(generation=1,rows=[])]+json.loads(json.dumps(before[1:])),response=dict(status=200))
  counts=dict(generate=16,chat=8,tags=1,version=0,metadata=1,external=25);result['counts']=counts
  wire=dict(version='admin-enum-wire-v1',profile='admin-enum',model=result['model'],digest=result['modelDigest'],closed=True,physicalPending=0,failures=[],counts=counts,calls=calls)
  return result,wire,captures
 def test_exact_cohort_wire_and_negative_binding(self):
  import copy
  good=self.receipt();m.verify_admin_enum_actual_result(*good)
  changes=[lambda r,w,c:r.update(actualModelProof=False),lambda r,w,c:w.update(closed=False),lambda r,w,c:w['calls'][0].update(response='changed'),lambda r,w,c:c['cases'][1]['request'].update(conversationHistory=[]),lambda r,w,c:c['cases'][0]['judgment'].update(verdict='pass'),lambda r,w,c:c['cases'][1]['packetRecord'].update(packet='{}'),lambda r,w,c:c['cases'].pop(),lambda r,w,c:c['reset']['after'][1].update(generation=1)]
  for mutate in changes:
   value=copy.deepcopy(good);mutate(*value)
   with self.assertRaises(RuntimeError):m.verify_admin_enum_actual_result(*value)
 def test_selection_protocol_is_closed_and_packet_bound(self):
  import copy,hashlib
  good=self.receipt()
  for capture in good[2]['cases']:
   capture['packet']['rubric'].update(version='finflow-admin-catalog-v3',finflowAdminCatalogSelection='finflow-admin-catalog-selection-v1')
   raw=json.dumps(capture['packet']);digest=hashlib.sha256(raw.encode()).hexdigest()
   capture['packetRecord']['packet']=raw;capture['judgment']['evidence_digest']=digest
   capture['judgment']['result_json']={'finflowCatalogSelection':dict(version='finflow-admin-catalog-selection-v1',evidenceId='response',evidenceDigest=digest,responseSha256=hashlib.sha256(capture['response']['body']['response'].encode()).hexdigest())}
  m.verify_admin_enum_actual_result(*good)
  for key,value in [('version','finflow-admin-catalog-v4'),('finflowAdminCatalogSelection','other-protocol')]:
   bad=copy.deepcopy(good);capture=bad[2]['cases'][1];capture['packet']['rubric'][key]=value
   raw=json.dumps(capture['packet']);digest=hashlib.sha256(raw.encode()).hexdigest();capture['packetRecord']['packet']=raw;capture['judgment']['evidence_digest']=digest;capture['judgment']['result_json']['finflowCatalogSelection']['evidenceDigest']=digest
   with self.assertRaises(RuntimeError):m.verify_admin_enum_actual_result(*bad)
  for key in ['version','evidenceId','evidenceDigest','responseSha256']:
   bad=copy.deepcopy(good);bad[2]['cases'][1]['judgment']['result_json']['finflowCatalogSelection'][key]='forged'
   with self.assertRaises(RuntimeError):m.verify_admin_enum_actual_result(*bad)
  bad=copy.deepcopy(good);bad[2]['cases'][1]['judgment'].pop('result_json')
  with self.assertRaises(RuntimeError):m.verify_admin_enum_actual_result(*bad)
 def test_only_enum_allows_no_browser_and_extended_deadline(self):
  from types import SimpleNamespace
  with tempfile.TemporaryDirectory() as d:
   self.assertFalse(m.verify_browser_absence(Path(d),dict(exitCode=0,profile='actual-admin-enum'),[])['started'])
   for profile in ['backup','controlled-admin-enum-content']:
    with self.assertRaises(RuntimeError):m.verify_browser_absence(Path(d),dict(exitCode=0,profile=profile),[])
  args=SimpleNamespace(profile='actual-admin-enum',plan=True)
  with patch.object(m,'parse_main',return_value=args),patch.object(m,'validate_main',return_value=(Path('/main'),{})),patch.object(m.tempfile,'mkdtemp',side_effect=AssertionError('No allocation')):self.assertEqual(m.main_current([]),0)

if __name__=='__main__':unittest.main()
