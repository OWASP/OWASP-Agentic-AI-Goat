"""Controlled launcher orchestration only; no child, Docker, Node, or database."""
from contextlib import ExitStack
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

PATH=Path(__file__).with_name('run-mcp-connected-baseline-isolated.py')

class LauncherFailures(unittest.TestCase):
 def exercise(self, failure, observed=False, indirect=False, public=False):
  spec=importlib.util.spec_from_file_location('owned_launcher_test',PATH)
  module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  events=[];child=object();self_case=self
  class Processes:
   def __init__(self,*args):pass
   def install(self):pass
   def mask_cleanup_signals(self):pass
   def restore(self):pass
   def launch(self,*args,**kwargs):
    events.append('launch')
    env=kwargs['env']
    self_case.assertEqual(env['MCP_CONNECTED_PG_PORT'],'12345')
    self_case.assertEqual(env['MCP_CONNECTED_SMTP_PORT'],'12346')
    self_case.assertEqual(env['MCP_CONNECTED_API_PORT'],'12347')
    self_case.assertEqual(env['MAILPIT_API_URL'],'http://127.0.0.1:12347')
    self_case.assertEqual(env['MCP_CONNECTED_SOURCE_ROOT'],kwargs['cwd'].as_posix())
    self_case.assertNotIn('HOME',env)
    self_case.assertEqual(env['OLLAMA_BASE_URL'],'http://127.0.0.1:11434')
    self_case.assertEqual(env['MCP_BASELINE_PRODUCTION'],'yes')
    for name in ['MCP_PROTECTED_STATE_CANDIDATE','MCP_OBSERVED_ACTION_CANDIDATE','MCP_INDIRECT_INJECTION_CANDIDATE',
                 'MCP_CATALOG_RECON_CANDIDATE','MCP_CATALOG_RECON_PRODUCTION']:
     self_case.assertEqual(env[name], 'yes' if (observed and name == 'MCP_OBSERVED_ACTION_CANDIDATE') or (indirect and name == 'MCP_INDIRECT_INJECTION_CANDIDATE') else 'no')
    self_case.assertEqual(env['MCP_CONNECTED_COHORT'], 'indirect_injection_production' if public else ('indirect_injection' if indirect else ('observed_action' if observed else 'baseline')))
    self_case.assertEqual(env['MCP_INDIRECT_INJECTION_PRODUCTION'], 'yes' if public else 'no')
    for key in ['MCP_OBSERVED_ACTION_ENABLED','MCP_INDIRECT_INJECTION_ENABLED']:
     self_case.assertEqual(env[key], 'true' if public else 'false')
    self_case.assertEqual(env['MCP_SUPPLY_CHAIN_ENABLED'], 'false')
    self_case.assertEqual(env['MCP_CONNECTED_RUNNER_PORT'],'12348')
    self_case.assertEqual(env['MCP_CONNECTED_MODEL_DIGEST'],'b'*64)
    class Child:
     def wait(self,timeout):
      self_case.assertEqual(timeout, 2460 if (indirect or public) else 780)
      if failure=='timeout':raise subprocess.TimeoutExpired('controlled',timeout)
      return 1 if failure=='nonzero' else 0
    return Child()
   def finish(self,child):events.append('finish')
   def cleanup(self):events.append('process_cleanup')
  def run(command,**kwargs):
   if command[-2:]==['/usr/local/bin/node','--version']:
    return subprocess.CompletedProcess(command,0,'v18.0.0\n' if failure=='runtime' else 'v26.8.2\n','')
   if 'run' in command:
    events.append('create')
    if failure=='uncertain' or (failure=='uncertain_mailpit' and events.count('create')==2):raise subprocess.TimeoutExpired('controlled',30)
    return subprocess.CompletedProcess(command,0,'a'*64+'\n','')
   return subprocess.CompletedProcess(command,0,'','')
  class Strict:
   profile='controlled';directory='/tmp/controlled';captured='a'*64
   def __init__(self,**kwargs):pass
   def prepare_policy(self):events.append('policy')
   def launch(self,token):return 12348
   def cleanup(self):
    events.append('runner_cleanup')
    if failure=='runner_cleanup':raise RuntimeError('controlled runner cleanup failure')
  class HTTP:
   def __init__(self,host,port,**kwargs):self.port=port
   def request(self,*args,**kwargs):pass
   def getresponse(self):return self
   status=200
   def read(self):return json.dumps({'models':[{'name':'llama3.1:8b','digest':'b'*64}]}).encode() if self.port==11434 else b'{}'
   def close(self):pass
  def cleanup(*args,**kwargs):
   events.append('docker_cleanup')
   if failure=='cleanup':raise RuntimeError('controlled')
   return {'status':'removed_absence_verified'}
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory)
   (root/'source/sidecars/sandbox-runner/apparmor').mkdir(parents=True)
   (root/'source/sidecars/sandbox-runner/apparmor/owasp-ai-goat-mcp-sandbox.apparmor.in').write_text('@@SUPERVISOR_PROFILE@@')
   (root/'receipt.json').write_text('{}')
   argv=['launcher','--indirect-injection-production' if public else ('--indirect-injection-candidate' if indirect else ('--observed-action-candidate' if observed else '--baseline-production'))]
   for name,value in [('docker-cli','/controlled/docker'),('docker-cli-sha256','f'*64),('docker-host','unix:///controlled'),('docker-daemon-id','controlled'),('postgres-image-id','sha256:'+'b'*64),('package',str(root/'source')),('manifest',str(root/'manifest.json')),('manifest-sha256','c'*64),('node','/controlled/node'),('node-sha256','d'*64),('evidence-root',str(root)),('mailpit-image-id','sha256:'+'e'*64),('control',str(root.parent/'control.json')),('owner-handle','123'),('ssh','/usr/bin/ssh'),('ssh-sha256','a'*64),('ssh-config','/controlled/config'),('ssh-config-sha256','b'*64),('ssh-host','controlled'),('runner-image-id','sha256:'+'f'*64),('runner-build-receipt',str(root/'receipt.json')),('runner-build-receipt-sha256','same'),('runner-context-sha256','a'*64),('model-digest','b'*64)]:argv.extend(['--'+name,value])
   with ExitStack() as stack:
    for manager in [patch.object(module.sys,'argv',argv),patch.object(module,'validate_package',side_effect=lambda *a:events.append('validate')),patch.object(module,'digest',return_value='same'),patch.object(module,'validate_docker_cli',return_value='/controlled/docker'),patch.object(module,'prepare_evidence_root',return_value=root),patch.object(module,'OwnedProcesses',Processes),patch.object(module,'StrictRunner',Strict),patch.object(module,'validate_ssh',return_value=['/controlled/ssh']),patch.object(module,'validate_health'),patch.object(module.http.client,'HTTPConnection',HTTP),patch.object(module,'consume_control',side_effect=lambda control, expected: self_case.assertEqual((expected['baseline_production'], expected.get('observed_action_candidate',False), expected.get('indirect_injection_candidate',False),expected.get('indirect_injection_production',False)), (not (observed or indirect or public),observed,indirect,public))),patch.object(module,'wait_mailpit'),patch.object(module,'validate_mailpit_layout',return_value=(12346,12347)),patch.object(module,'verify_daemon'),patch.object(module,'verify_image'),patch.object(module,'inspect_owned',return_value={}),patch.object(module,'validate_container_layout',return_value=12345),patch.object(module,'cleanup_owned',side_effect=cleanup),patch.object(module.subprocess,'run',side_effect=run),patch.object(module.time,'sleep')]: stack.enter_context(manager)
    if failure is None:module.main()
    else:
     with self.assertRaises((RuntimeError,subprocess.TimeoutExpired)):module.main()
   terminal=json.loads((root/'terminal.json').read_text())
   self.assertEqual(terminal['status'],'passed_cleaned' if failure is None else 'failed')
   self.assertEqual(events.count('validate'),2,'postflight runs after failure')
   self.assertIn('process_cleanup',events);self.assertIn('docker_cleanup',events)
   if failure is None:
    self.assertEqual(terminal['failures'],[])
    self.assertLess(events.index('process_cleanup'),events.index('runner_cleanup'))
    self.assertLess(events.index('runner_cleanup'),events.index('docker_cleanup'))
    self.assertEqual(events.count('docker_cleanup'),2)
   if failure=='timeout':self.assertIn('finish',events)
   if failure in ['uncertain','uncertain_mailpit']:self.assertNotIn('launch',events)
   if failure=='runtime':
    self.assertNotIn('launch',events)
    self.assertEqual(events.count('docker_cleanup'),2)
    self.assertIn('runner_cleanup',events)
   if failure=='uncertain_mailpit':self.assertEqual(events.count('docker_cleanup'),2)
   if failure=='runner_cleanup':
    self.assertEqual(events.count('docker_cleanup'),2)
    self.assertIn('runner_cleanup',terminal['failures'])
   if failure=='cleanup':
    self.assertEqual(events.count('docker_cleanup'),2)
    self.assertIn('postgres_cleanup',terminal['failures']);self.assertIn('mailpit_cleanup',terminal['failures'])
    self.assertEqual(json.loads((root/'postgres-cleanup.json').read_text())['status'],'cleanup_unverified')
 def test_rejected_package_cannot_consume_control_or_create_resources(self):
  spec=importlib.util.spec_from_file_location('mcp_rejected',PATH)
  module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  names=['docker-cli','docker-cli-sha256','docker-host','docker-daemon-id','postgres-image-id','mailpit-image-id','package','manifest','manifest-sha256','node','node-sha256','evidence-root','control','ssh','ssh-sha256','ssh-config','ssh-config-sha256','ssh-host','runner-image-id','runner-build-receipt','runner-build-receipt-sha256','runner-context-sha256','model-digest']
  argv=['launcher','--baseline-production','--owner-handle','123']+[v for name in names for v in ['--'+name,('b'*64 if name=='model-digest' else '/controlled')]]
  with patch.object(module.sys,'argv',argv),patch.object(module,'validate_package',side_effect=RuntimeError('rejected package')),patch.object(module,'consume_control') as consume,patch.object(module.subprocess,'run') as run:
   with self.assertRaisesRegex(RuntimeError,'rejected package'):module.main()
   consume.assert_not_called();run.assert_not_called()
 def test_native_timeout_is_scoped_to_indirect(self):
  source=PATH.with_name('mcpOwnedConnected.integration.test.js').read_text()
  self.assertIn('skip: !enabled, timeout: indirectQualification ? 2400000 : 720000,',source)
 def test_public_indirect_success(self):self.exercise(None, public=True)
 def test_public_indirect_timeout(self):self.exercise('timeout', public=True)
 def test_public_indirect_cleanup_failure(self):self.exercise('cleanup', public=True)
 def test_indirect_success(self):self.exercise(None, indirect=True)
 def test_indirect_timeout(self):self.exercise('timeout', indirect=True)
 def test_indirect_cleanup_failure(self):self.exercise('cleanup', indirect=True)
 def test_observed_success(self):self.exercise(None, observed=True)
 def test_observed_timeout(self):self.exercise('timeout', observed=True)
 def test_observed_cleanup_failure(self):self.exercise('cleanup', observed=True)
 def test_nonzero(self):self.exercise('nonzero')
 def test_wrong_runner_runtime_cleans_up_before_qualification(self):self.exercise('runtime')
 def test_success_still_requires_ordered_cleanup_and_postflight(self):self.exercise(None)
 def test_uncertain_creation(self):self.exercise('uncertain')
 def test_uncertain_second_creation(self):self.exercise('uncertain_mailpit')
 def test_timeout(self):self.exercise('timeout')
 def test_runner_cleanup_failure(self):self.exercise('runner_cleanup')
 def test_cleanup_failure(self):self.exercise('cleanup')

if __name__=='__main__':unittest.main()
