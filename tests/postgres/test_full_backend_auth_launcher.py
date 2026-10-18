"""Controlled launcher orchestration only; no child, Docker, Node, or database."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from contextlib import ExitStack

PATH=Path(__file__).with_name('run-full-backend-auth-isolated.py')

class LauncherFailures(unittest.TestCase):
 def exercise(self, failure, rendered=False):
  spec=importlib.util.spec_from_file_location('owned_launcher_test',PATH)
  module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  events=[];child=object()
  class Processes:
   def __init__(self,*args):pass
   def install(self):pass
   def mask_cleanup_signals(self):pass
   def restore(self):pass
   def launch(self,*args,**kwargs):
    events.append('launch')
    class Child:
     pid=43210
     def poll(self):return 0
     def wait(self,timeout):
      if rendered:(root/'runtime/browser-process.json').write_text('{}')
      if failure=='timeout':raise subprocess.TimeoutExpired('controlled',timeout)
      return 1 if failure=='nonzero' else 0
    return Child()
   def finish(self,child):events.append('finish')
   def cleanup(self):events.append('process_cleanup')
  def run(command,**kwargs):
   if 'run' in command:
    events.append('create')
    if failure=='uncertain':raise subprocess.TimeoutExpired('controlled',30)
    return subprocess.CompletedProcess(command,0,'a'*64+'\n','')
   return subprocess.CompletedProcess(command,0,'','')
  def cleanup(*args,**kwargs):
   events.append('docker_cleanup')
   if failure=='cleanup':raise RuntimeError('controlled')
   return {'status':'removed_absence_verified'}
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory)
   argv=['launcher']
   if rendered:argv.extend(['--rendered','--browser','/controlled/browser','--browser-sha256','e'*64])
   for name,value in [('docker-host','unix:///controlled'),('docker-daemon-id','controlled'),('postgres-image-id','sha256:'+'b'*64),('package',str(root/'source')),('manifest',str(root/'manifest.json')),('manifest-sha256','c'*64),('node','/controlled/node'),('node-sha256','d'*64),('evidence-root',str(root))]:argv.extend(['--'+name,value])
   def browser_cleanup(runtime,qualification,successful,role):
    self.assertEqual(role,"rendered")
    self.assertIn('process_cleanup',events);self.assertEqual(successful,failure=='cleanup');events.append('browser_cleanup')
    return {'status':'controlled_outer_cleanup'}
   with patch.object(module.sys,'argv',argv),patch.object(module,'validate_package',side_effect=lambda *a:events.append('validate')),patch.object(module,'validate_rendered'),patch.object(module,'digest',return_value='same'),patch.object(module,'prepare_evidence_root',return_value=root),patch.object(module,'OwnedProcesses',Processes),patch.object(module,'verify_daemon'),patch.object(module,'verify_image'),patch.object(module,'inspect_owned',return_value={}),patch.object(module,'validate_fullboot_layout',return_value=12345),patch.object(module,'cleanup_owned',side_effect=cleanup),patch.object(module,'cleanup_browser_profile',side_effect=browser_cleanup),patch.object(module,'read_private_json',return_value={'controlled':'qualification'}),patch.object(module.subprocess,'run',side_effect=run),patch.object(module.time,'sleep'):
    with self.assertRaises((RuntimeError,subprocess.TimeoutExpired)):module.main()
   terminal=json.loads((root/'terminal.json').read_text())
   self.assertEqual(terminal['status'],'failed')
   self.assertEqual(events.count('validate'),2,'postflight runs after failure')
   self.assertIn('process_cleanup',events);self.assertIn('docker_cleanup',events)
   if failure=='timeout':self.assertIn('finish',events)
   if failure=='uncertain':self.assertNotIn('launch',events)
   if failure=='cleanup':
    self.assertIn('container_cleanup',terminal['failures'])
    self.assertEqual(json.loads((root/'container-cleanup.json').read_text())['status'],'cleanup_unverified')
   if rendered:
    self.assertIn('browser_cleanup',events)
    self.assertEqual(json.loads((root/'browser-outer-cleanup.json').read_text()),{'status':'controlled_outer_cleanup'})
 def test_nonzero(self):self.exercise('nonzero')
 def test_uncertain_creation(self):self.exercise('uncertain')
 def test_timeout(self):self.exercise('timeout')
 def test_cleanup_failure(self):self.exercise('cleanup')
 def test_rendered_timeout(self):self.exercise('timeout',rendered=True)
 def test_rendered_cleanup_failure(self):self.exercise('cleanup',rendered=True)

class ComposedMcpLauncher(unittest.TestCase):
 def exercise(self, failure=None, external=False):
  import full_backend_auth_contract as contract
  import mcp_connected_baseline_contract as pins
  import full_backend_mcp_resources as resources
  spec=importlib.util.spec_from_file_location('composed_launcher_test',PATH)
  module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  events=[]; captured={}
  endpoints={'version':1, **{name:{'host':'127.0.0.1','port':port} for name,port in [('postgres',23451),('runner',23452),('smtp',23453),('mailpit',23454),('model',11434)]}}
  if external:endpoints['runner']['host']='example.invalid'
  class Resources:
   def __init__(self,**kwargs):events.append('sidecar_intent')
   def launch(self,port):
    captured['pg_port']=port;events.append('sidecar_launch')
    if failure=='uncertain':raise subprocess.TimeoutExpired('controlled',30)
    return endpoints,'owned-controlled-token'
   def cleanup(self):
    events.append('sidecar_cleanup')
    if failure=='sidecar_cleanup':raise RuntimeError('controlled')
  class Processes:
   def __init__(self,*args):pass
   def install(self):pass
   def mask_cleanup_signals(self):pass
   def restore(self):pass
   def launch(self,command,**kwargs):
    captured['command']=command;captured['env']=kwargs['env'];events.append('child')
    class Child:
     pid=43210
     def poll(self):return 0
     def wait(self,timeout):
      captured['timeout']=timeout
      if failure=='timeout':raise subprocess.TimeoutExpired('controlled',timeout)
      return 1 if failure=='child' else 0
    return Child()
   def finish(self,child):events.append('finish')
   def cleanup(self):events.append('process_cleanup')
  def run(command,**kwargs):
   return subprocess.CompletedProcess(command,0,'a'*64+'\n' if 'run' in command else '', '')
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory).resolve();receipt=root/'receipt.json';receipt.write_text('{}')
   argv=['launcher','--rendered','--mcp-indirect']
   values={'docker-host':'unix:///controlled','docker-daemon-id':'controlled','postgres-image-id':'sha256:'+'b'*64,
    'package':str(root/'source'),'manifest':str(root/'manifest.json'),'manifest-sha256':'c'*64,
    'node':'/controlled/node','node-sha256':'d'*64,'evidence-root':str(root),'browser':'/controlled/browser','browser-sha256':'e'*64,
    'docker-cli':'/controlled/docker','docker-cli-sha256':'f'*64,'mailpit-image-id':'sha256:'+'1'*64,
    'ssh':'/controlled/ssh','ssh-sha256':'2'*64,'ssh-config':'/controlled/config','ssh-config-sha256':'3'*64,'ssh-host':'controlled',
    'runner-image-id':'sha256:'+'4'*64,'runner-build-receipt':str(receipt),'runner-build-receipt-sha256':'same',
    'runner-context-sha256':'5'*64,'model-digest':contract.MCP_MODEL_DIGEST,'control':'/controlled/grant','owner-handle':'12345'}
   for key,value in values.items():argv.extend(['--'+key,value])
   with ExitStack() as stack:
    patches=[patch.object(module.sys,'argv',argv),patch.object(module,'validate_package',side_effect=lambda *a:events.append('validate')),
     patch.object(module,'validate_rendered'),patch.object(module,'validate_mcp_rendered_manifest'),patch.object(module,'digest',return_value='same'),
     patch.object(module,'prepare_evidence_root',return_value=root),patch.object(module,'OwnedProcesses',Processes),
     patch.object(module,'verify_daemon'),patch.object(module,'verify_image'),patch.object(module,'inspect_owned',return_value={}),
     patch.object(module,'validate_fullboot_layout',return_value=23451),
     patch.object(module,'cleanup_owned',side_effect=lambda *a,**k:events.append('pg_cleanup') or {'status':'removed_absence_verified'}),
     patch.object(module.subprocess,'run',side_effect=run),patch.object(module.time,'sleep'),
     patch.object(pins,'validate_docker_cli',return_value='/controlled/docker'),patch.object(pins,'validate_ssh',return_value=['/controlled/ssh']),
     patch.object(contract,'consume_full_mcp_control',side_effect=lambda *a:events.append('grant')),
     patch.object(resources,'FullBackendMcpResources',Resources)]
    for item in patches:stack.enter_context(item)
    if failure or external:
     with self.assertRaises((RuntimeError,subprocess.TimeoutExpired)):module.main()
    else:module.main()
   terminal=json.loads((root/'terminal.json').read_text())
   self.assertEqual(terminal['status'],'failed' if failure or external else 'passed_cleaned')
   self.assertEqual(terminal['ownerHandle'],12345)
   self.assertEqual(events.count('validate'),2)
   for event in ['grant','process_cleanup','sidecar_cleanup','pg_cleanup']:self.assertIn(event,events)
   self.assertEqual(captured['pg_port'],23451)
   if external or failure=='uncertain':self.assertNotIn('child',events)
   else:
    self.assertIn('finish',events);self.assertEqual(captured['timeout'],3600)
    env=captured['env'];self.assertEqual(env['PG_FULL_BACKEND_MCP_INDIRECT'],'1')
    self.assertEqual(env['PG_FULL_BACKEND_AUTH'],'1');self.assertEqual(env['MCP_OWNED_TARGET_TOKEN'],'owned-controlled-token')
    self.assertEqual(json.loads(env['PG_FULL_BACKEND_MCP_ENDPOINTS_JSON']),endpoints)
    self.assertEqual(env['MCP_OWNED_TARGET_URL'],'http://127.0.0.1:23452')
    self.assertEqual(env['MAILPIT_SMTP_PORT'],'23453');self.assertEqual(env['MAILPIT_API_URL'],'http://127.0.0.1:23454')
    for family,prefix in contract.STORES:
     for suffix in ['_DATABASE_URL','_MIGRATION_DATABASE_URL']:self.assertIn('@127.0.0.1:23451/',env[prefix+suffix])
    self.assertEqual(captured['command'][0],'/controlled/node')
    self.assertEqual(captured['command'][-1],'tests/postgres/fullApplicationBackendAuth.integration.test.js')
   if failure=='sidecar_cleanup':self.assertIn('mcp_resources_cleanup',terminal['failures'])
 def test_owned_manifest_environment_and_budget(self):self.exercise()
 def test_external_endpoint_rejected_before_child(self):self.exercise(external=True)
 def test_uncertain_sidecar_creation_cleans_all(self):self.exercise('uncertain')
 def test_child_failure_cleans_all(self):self.exercise('child')
 def test_timeout_cleans_all(self):self.exercise('timeout')
 def test_sidecar_cleanup_failure_preserves_pg_and_postflight(self):self.exercise('sidecar_cleanup')

class ComposedSecureShopLauncher(unittest.TestCase):
 def exercise(self, failure=None, bad_pin=None, review_outcome='attack_success'):
  import full_backend_auth_contract as base
  import full_backend_secureshop_contract as contract
  import full_backend_secureshop_resources as resources
  import mcp_connected_baseline_contract as pins
  spec=importlib.util.spec_from_file_location('secureshop_launcher_test',PATH)
  module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  events=[];captured={}
  endpoints={'version':1,'postgres':{'host':'127.0.0.1','port':23451},'agentHost':{'host':'127.0.0.1','port':23452},'model':{'host':'127.0.0.1','port':11434},'fixtures':[]}
  class Resources:
   def __init__(self,**kwargs):captured['resource_args']=kwargs;events.append('resource_init')
   def prepare(self,port):
    captured['pg_port']=port;events.append('prepare')
    if failure=='prepare':raise RuntimeError('controlled prepare failure')
    if failure=='external':endpoints['agentHost']['host']='external.invalid'
    return endpoints
   def release_for_launch(self):
    events.append('release')
    if failure=='release':raise RuntimeError('controlled release failure')
   def cleanup(self):
    captured['resource_args']['assert_processes_absent']()
    events.append('resource_cleanup')
    if failure=='cleanup':raise RuntimeError('controlled cleanup failure')
  class Processes:
   def __init__(self,*args):self.children=[]
   def install(self):events.append('install')
   def mask_cleanup_signals(self):pass
   def restore(self):events.append('restore')
   def launch(self,command,**kwargs):
    captured['env']=kwargs['env'];captured['command']=command;events.append('child')
    class Child:
     pid=43210
     def poll(self):return 0
     def wait(self,timeout):
      captured['timeout']=timeout
      if failure!='missing_assessment_journal':(root/'runtime/assessment-browser-process.json').write_text('{}')
      if failure=='timeout':raise subprocess.TimeoutExpired('controlled',timeout)
      return 1 if failure=='child' else 0
    child=Child();self.children.append(('qualification',child))
    if failure in ['launch_journal','launch_interrupt']:raise RuntimeError('Controlled registered launch interruption')
    return child
   def finish(self,child):events.append('finish')
   def cleanup(self):events.append('process_cleanup');self.children=[]
  def run(command,**kwargs):
   if command[0]=='/bin/ps':
    events.append('absence_roster');return subprocess.CompletedProcess(command,0,'','')
   events.append('docker')
   return subprocess.CompletedProcess(command,0,'a'*64+'\n' if 'run' in command else '', '')
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory).resolve()
   values={'docker-host':'unix:///controlled','docker-daemon-id':'controlled','postgres-image-id':'sha256:'+'b'*64,'package':str(root/'source'),'manifest':str(root/'manifest.json'),'manifest-sha256':'c'*64,'node':'/controlled/node','node-sha256':'d'*64,'evidence-root':str(root),'browser':'/controlled/browser','browser-sha256':'e'*64,'docker-cli':'/controlled/docker','docker-cli-sha256':'f'*64,'model-digest':contract.SECURESHOP_MODEL_DIGEST,'renderer-root':str(root/'renderer'),'renderer-manifest-sha256':'a'*64,'control':'/controlled/grant','owner-handle':'12345','secureshop-review-outcome':review_outcome}
   flags=['--rendered','--secureshop','--secureshop-private-failure-artifact']
   if bad_pin=='model':values['model-digest']='0'*64
   if bad_pin=='renderer':values.pop('renderer-manifest-sha256')
   if bad_pin=='docker':values.pop('docker-cli-sha256')
   if bad_pin=='review_outcome':values.pop('secureshop-review-outcome')
   if bad_pin=='unrelated':values['mailpit-image-id']='sha256:'+'1'*64
   if bad_pin=='exclusive':flags.append('--mcp-indirect')
   if bad_pin=='rendered':flags.remove('--rendered')
   argv=['launcher']+flags
   for key,value in values.items():argv.extend(['--'+key,value])
   with ExitStack() as stack:
    for item in [patch.object(module.sys,'argv',argv),patch.object(module,'validate_package',side_effect=lambda *a:events.append('validate')),
     patch.object(module,'validate_rendered'),patch.object(module,'validate_mcp_rendered_manifest'),patch.object(base,'validate_secureshop_rendered_manifest'),
     patch.object(module,'digest',return_value='same'),patch.object(module,'prepare_evidence_root',return_value=root),patch.object(module,'OwnedProcesses',Processes),
     patch.object(module,'read_private_json',return_value={'controlled':'qualification'}),
     patch.object(module,'cleanup_browser_profile',side_effect=lambda *a,**k:events.append('assessment_cleanup') or {'status':'controlled_cleanup'}),
     patch.object(module,'verify_daemon'),patch.object(module,'verify_image'),patch.object(module,'inspect_owned',return_value={}),patch.object(module,'validate_fullboot_layout',return_value=23451),
     patch.object(module,'cleanup_owned',side_effect=lambda *a,**k:events.append('pg_cleanup') or {'status':'removed_absence_verified'}),
     patch.object(module.subprocess,'run',side_effect=run),patch.object(module.time,'sleep'),patch.object(pins,'validate_docker_cli',return_value='/controlled/docker'),
     patch.object(resources,'validate_renderer_bundle',side_effect=lambda **k:events.append('renderer_validate')),
     patch.object(contract,'consume_full_secureshop_control',side_effect=lambda *a:events.append('grant')),
     patch.object(resources,'FullBackendSecureShopResources',Resources)]:stack.enter_context(item)
    if failure or bad_pin:
     with self.assertRaises((RuntimeError,subprocess.TimeoutExpired)):module.main()
    else:module.main()
   if bad_pin:
    self.assertNotIn('grant',events);self.assertNotIn('docker',events);self.assertNotIn('install',events);return
   terminal=json.loads((root/'terminal.json').read_text())
   self.assertEqual(terminal['status'],'failed' if failure else 'passed_cleaned')
   if not failure:
    self.assertIn('assessment_cleanup',events)
    self.assertTrue((root/'assessment-browser-outer-cleanup.json').is_file())
   self.assertEqual(terminal['ownerHandle'],12345);self.assertEqual(terminal['modelDigest'],contract.SECURESHOP_MODEL_DIGEST)
   self.assertEqual(terminal['admittedReviewOutcome'],review_outcome)
   self.assertEqual(events.count('validate'),2)
   for event in ['resource_cleanup','process_cleanup','pg_cleanup','restore']:self.assertIn(event,events)
   self.assertLess(events.index('grant'),events.index('docker'));self.assertLess(events.index('process_cleanup'),events.index('resource_cleanup'))
   self.assertEqual(captured['pg_port'],23451)
   if failure in ['prepare','external','release']:self.assertNotIn('child',events)
   elif failure in ['launch_journal','launch_interrupt']:
    self.assertIn('child',events);self.assertIn('absence_roster',events)
   else:
    self.assertLess(events.index('release'),events.index('child'));self.assertEqual(captured['timeout'],3600);self.assertIn('finish',events)
    env=captured['env'];self.assertEqual(env['PG_FULL_BACKEND_SECURESHOP'],'1');self.assertNotIn('PG_FULL_BACKEND_MCP_INDIRECT',env)
    self.assertEqual(env['PG_FULL_BACKEND_SECURESHOP_PRIVATE_FAILURE_ARTIFACT'],'1')
    for name in ['PLATFORM_DATABASE_ENGINE','WORKSHOP_DATABASE_ENGINE']:self.assertEqual(env[name],'postgres')
    for name in ['SS_ENABLE','SS_BOUND_REVIEWS_ENABLED','SS_PERSONA_INBOX_READY','SS_MCP_TRUST_READY','SS_CONTROLLED_SSRF_READY']:self.assertEqual(env[name],'true')
    self.assertEqual(env['SS_ENABLE_REAL_MCP_SPAWN'],'false');self.assertEqual(env['SS_AGENT_HOST_PORT'],'23452')
    self.assertEqual(env['PG_FULL_BACKEND_SECURESHOP_MODEL_DIGEST'],contract.SECURESHOP_MODEL_DIGEST)
    self.assertEqual(env['PG_FULL_BACKEND_SECURESHOP_REVIEW_OUTCOME'],review_outcome)
    for name in ['AI_PROVIDER','JUDGE_PROVIDER']:self.assertEqual(env[name],'ollama')
    for name in ['OLLAMA_MODEL','JUDGE_MODEL']:self.assertEqual(env[name],'llama3.1:8b')
    self.assertEqual(env['OLLAMA_BASE_URL'],'http://127.0.0.1:11434')
    self.assertEqual(json.loads(env['PG_FULL_BACKEND_SECURESHOP_ENDPOINTS_JSON']),endpoints)
    self.assertEqual(env['SECURESHOP_REVIEW_RENDERER_ROOT'],values['renderer-root'])
    self.assertEqual(env['PG_FULL_BACKEND_SECURESHOP_RENDERER_MANIFEST_SHA256'],values['renderer-manifest-sha256'])
    for family,prefix in base.STORES:
     for suffix in ['_DATABASE_URL','_MIGRATION_DATABASE_URL']:self.assertIn('@127.0.0.1:23451/',env[prefix+suffix])
    self.assertEqual(env['SS_MCP_TRUST_FIXTURE_ROOT'],str(root/'runtime/secureshop-mcp-trust'))
    self.assertEqual(env['SS_CONTROLLED_SSRF_FIXTURE_ROOT'],str(root/'runtime/secureshop-ssrf'))
    self.assertEqual(captured['command'][0],'/controlled/node')
    self.assertFalse(any(key.startswith(('MCP_','MAILPIT_','OPENAI_','ANTHROPIC_')) and key not in ['MCP_WORKSHOP_DATABASE_URL','MCP_WORKSHOP_MIGRATION_DATABASE_URL'] for key in env))
   if failure=='missing_assessment_journal':self.assertIn('assessment-browser_cleanup',terminal['failures'])
   if failure=='cleanup':self.assertIn('secureshop_resources_cleanup',terminal['failures'])
 def test_missing_assessment_journal_rejects_success(self):self.exercise('missing_assessment_journal')
 def test_exact_environment_and_resource_order(self):self.exercise()
 def test_observed_outcome_environment_round_trip(self):self.exercise(review_outcome='observed_outcome')
 def test_pin_admission_before_resources(self):
  for pin in ['model','renderer','docker','review_outcome','unrelated','exclusive','rendered']:
   with self.subTest(pin=pin):self.exercise(bad_pin=pin)
 def test_registered_launch_journal_failure_retains_absence_identity(self):self.exercise('launch_journal')
 def test_registered_launch_interrupt_retains_absence_identity(self):self.exercise('launch_interrupt')
 def test_prepare_failure_cleanup(self):self.exercise('prepare')
 def test_external_endpoint_denied(self):self.exercise('external')
 def test_release_failure_cleanup(self):self.exercise('release')
 def test_child_failure_cleanup(self):self.exercise('child')
 def test_timeout_cleanup(self):self.exercise('timeout')
 def test_resource_cleanup_failure_postflight(self):self.exercise('cleanup')


class OwnedAbsenceChecks(unittest.TestCase):
 def load(self):
  spec=importlib.util.spec_from_file_location('absence_launcher_test',PATH)
  module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
 def test_real_harmless_child_must_exit_before_absence(self):
  import sys
  module=self.load()
  child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],start_new_session=True)
  try:
   with self.assertRaisesRegex(RuntimeError,'not terminated'):module.assert_owned_children_absent([child])
  finally:
   child.terminate()
   try:child.wait(timeout=2)
   except subprocess.TimeoutExpired:child.kill();child.wait(timeout=2)
  module.assert_owned_children_absent([child])
 def test_reused_pid_group_and_malformed_roster_fail_closed(self):
  module=self.load()
  class Child:
   pid=43210
   def poll(self):return 0
  for output in ['43210 5 999\n','3 43210 999\n','malformed\n']:
   with patch.object(module.subprocess,'run',return_value=subprocess.CompletedProcess([],0,output,'')):
    with self.assertRaises(RuntimeError):module.assert_owned_children_absent([Child()])
  with patch.object(module.subprocess,'run',side_effect=RuntimeError('ps failed')):
   with self.assertRaises(RuntimeError):module.assert_owned_children_absent([Child()])
  with patch.object(module.subprocess,'run') as run:
   module.assert_owned_children_absent([]);run.assert_not_called()

if __name__ == '__main__':
    unittest.main()
