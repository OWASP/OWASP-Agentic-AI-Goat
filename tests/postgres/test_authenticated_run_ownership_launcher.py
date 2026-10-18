"""Controlled launcher orchestration only; no child, Docker, Node, or database."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

PATH=Path(__file__).with_name('run-authenticated-agent-run-ownership-isolated.py')

class LauncherFailures(unittest.TestCase):
 def exercise(self, failure):
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
     def wait(self,timeout):
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
   for name,value in [('docker-host','unix:///controlled'),('docker-daemon-id','controlled'),('postgres-image-id','sha256:'+'b'*64),('package',str(root/'source')),('manifest',str(root/'manifest.json')),('manifest-sha256','c'*64),('node','/controlled/node'),('node-sha256','d'*64),('evidence-root',str(root))]:argv.extend(['--'+name,value])
   with patch.object(module.sys,'argv',argv),patch.object(module,'validate_package',side_effect=lambda *a:events.append('validate')),patch.object(module,'digest',return_value='same'),patch.object(module,'prepare_evidence_root',return_value=root),patch.object(module,'OwnedProcesses',Processes),patch.object(module,'verify_daemon'),patch.object(module,'verify_image'),patch.object(module,'inspect_owned',return_value={}),patch.object(module,'validate_container_layout',return_value=12345),patch.object(module,'cleanup_owned',side_effect=cleanup),patch.object(module.subprocess,'run',side_effect=run),patch.object(module.time,'sleep'):
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
 def test_nonzero(self):self.exercise('nonzero')
 def test_uncertain_creation(self):self.exercise('uncertain')
 def test_timeout(self):self.exercise('timeout')
 def test_cleanup_failure(self):self.exercise('cleanup')

if __name__=='__main__':unittest.main()
