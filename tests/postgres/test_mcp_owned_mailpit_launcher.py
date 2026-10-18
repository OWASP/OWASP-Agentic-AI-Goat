"""Controlled launcher orchestration only; no child, Docker, Node, or database."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

PATH=Path(__file__).with_name('run-mcp-owned-resources-mailpit-isolated.py')

class LauncherFailures(unittest.TestCase):
 def exercise(self, failure):
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
    self_case.assertEqual(env['MCP_OWNED_RESOURCES_PG_PORT'],'12345')
    self_case.assertEqual(env['MCP_OWNED_RESOURCES_SMTP_PORT'],'12346')
    self_case.assertEqual(env['MCP_OWNED_RESOURCES_API_PORT'],'12347')
    self_case.assertEqual(env['MAILPIT_API_URL'],'http://127.0.0.1:12347')
    self_case.assertEqual(env['MCP_OWNED_RESOURCES_SOURCE_ROOT'],kwargs['cwd'].as_posix())
    self_case.assertNotIn('HOME',env)
    self_case.assertNotIn('OLLAMA_BASE_URL',env)
    class Child:
     def wait(self,timeout):
      if failure=='timeout':raise subprocess.TimeoutExpired('controlled',timeout)
      return 1 if failure=='nonzero' else 0
    return Child()
   def finish(self,child):events.append('finish')
   def cleanup(self):events.append('process_cleanup')
  def run(command,**kwargs):
   if 'run' in command:
    events.append('create')
    if failure=='uncertain' or (failure=='uncertain_mailpit' and events.count('create')==2):raise subprocess.TimeoutExpired('controlled',30)
    return subprocess.CompletedProcess(command,0,'a'*64+'\n','')
   return subprocess.CompletedProcess(command,0,'','')
  def cleanup(*args,**kwargs):
   events.append('docker_cleanup')
   if failure=='cleanup':raise RuntimeError('controlled')
   return {'status':'removed_absence_verified'}
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory)
   argv=['launcher']
   for name,value in [('docker-cli','/controlled/docker'),('docker-cli-sha256','f'*64),('docker-host','unix:///controlled'),('docker-daemon-id','controlled'),('postgres-image-id','sha256:'+'b'*64),('package',str(root/'source')),('manifest',str(root/'manifest.json')),('manifest-sha256','c'*64),('node','/controlled/node'),('node-sha256','d'*64),('evidence-root',str(root)),('mailpit-image-id','sha256:'+'e'*64),('control',str(root.parent/'control.json')),('owner-handle','123')]:argv.extend(['--'+name,value])
   with patch.object(module.sys,'argv',argv),patch.object(module,'validate_package',side_effect=lambda *a:events.append('validate')),patch.object(module,'digest',return_value='same'),patch.object(module,'validate_docker_cli',return_value='/controlled/docker'),patch.object(module,'prepare_evidence_root',return_value=root),patch.object(module,'OwnedProcesses',Processes),patch.object(module,'consume_control'),patch.object(module,'wait_mailpit'),patch.object(module,'validate_mailpit_layout',return_value=(12346,12347)),patch.object(module,'verify_daemon'),patch.object(module,'verify_image'),patch.object(module,'inspect_owned',return_value={}),patch.object(module,'validate_container_layout',return_value=12345),patch.object(module,'cleanup_owned',side_effect=cleanup),patch.object(module.subprocess,'run',side_effect=run),patch.object(module.time,'sleep'):
    with self.assertRaises((RuntimeError,subprocess.TimeoutExpired)):module.main()
   terminal=json.loads((root/'terminal.json').read_text())
   self.assertEqual(terminal['status'],'failed')
   self.assertEqual(events.count('validate'),2,'postflight runs after failure')
   self.assertIn('process_cleanup',events);self.assertIn('docker_cleanup',events)
   if failure=='timeout':self.assertIn('finish',events)
   if failure in ['uncertain','uncertain_mailpit']:self.assertNotIn('launch',events)
   if failure=='uncertain_mailpit':self.assertEqual(events.count('docker_cleanup'),2)
   if failure=='cleanup':
    self.assertEqual(events.count('docker_cleanup'),2)
    self.assertIn('postgres_cleanup',terminal['failures']);self.assertIn('mailpit_cleanup',terminal['failures'])
    self.assertEqual(json.loads((root/'postgres-cleanup.json').read_text())['status'],'cleanup_unverified')
 def test_rejected_package_cannot_consume_control_or_create_resources(self):
  spec=importlib.util.spec_from_file_location('mcp_rejected',PATH)
  module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  names=['docker-cli','docker-cli-sha256','docker-host','docker-daemon-id','postgres-image-id','mailpit-image-id','package','manifest','manifest-sha256','node','node-sha256','evidence-root','control']
  argv=['launcher','--owner-handle','123']+[v for name in names for v in ['--'+name,'/controlled']]
  with patch.object(module.sys,'argv',argv),patch.object(module,'validate_package',side_effect=RuntimeError('rejected package')),patch.object(module,'consume_control') as consume,patch.object(module.subprocess,'run') as run:
   with self.assertRaisesRegex(RuntimeError,'rejected package'):module.main()
   consume.assert_not_called();run.assert_not_called()
 def test_nonzero(self):self.exercise('nonzero')
 def test_uncertain_creation(self):self.exercise('uncertain')
 def test_uncertain_second_creation(self):self.exercise('uncertain_mailpit')
 def test_timeout(self):self.exercise('timeout')
 def test_cleanup_failure(self):self.exercise('cleanup')

if __name__=='__main__':unittest.main()
