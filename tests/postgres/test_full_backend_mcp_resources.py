"""Controlled full-backend MCP resource lifecycle tests; no native resources."""
import importlib
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

resources = importlib.import_module('full_backend_mcp_resources')
SOURCE = Path(__file__).resolve().parents[2]

class FakeRunner:
 def __init__(self, **_kwargs):
  self.profile = 'owasp-ai-goat-mcp-sandbox-' + '1' * 12; self.directory = '/tmp/' + self.profile
  self.captured = 'b' * 64; self.prepared = False; self.cleaned = False
 def prepare_policy(self): self.prepared = True
 def launch(self, _token): return 38091
 def cleanup(self): self.cleaned = True

class FakeHttp:
 def __init__(self, *_args, **_kwargs): pass
 def request(self, *_args, **_kwargs): pass
 def getresponse(self):
  return SimpleNamespace(status=200, read=lambda: b'{"ready":true,"version":"mcp-owned-target-http.v1","isolation":"bwrap-seccomp-v1","supervisorProfile":"owasp-ai-goat-mcp-sandbox-111111111111 (enforce)","protectedStateCapability":"mcp-owned-protected-state-transition.v2","observedActionCapability":"mcp-owned-observed-action.v1","packageInstallCapability":"mcp-owned-package-install.v1","ticketReadCapability":"mcp-owned-ticket-read.v2"}')
 def close(self): pass

class ResourceLifecycle(unittest.TestCase):
 def setUp(self):
  self.receipts = []; self.command_calls = []
  def command(args):
   self.command_calls.append(args)
   if args[:2] == ['run', '--detach']: return SimpleNamespace(returncode=0, stdout='a' * 64 + '\n')
   if args and args[0] == 'exec': return SimpleNamespace(returncode=0, stdout='v26.8.2\n')
   return SimpleNamespace(returncode=0, stdout='')
  self.command = command; self.record = lambda name, value: self.receipts.append((name, value))
  self.receipt = {'version': 1, 'imageId': 'sha256:' + 'a' * 64, 'contextSha256': 'b' * 64,
                  'policyTemplateSha256': 'c' * 64, 'nodeVersion': 'v26.8.2'}
 def make(self):
  return resources.FullBackendMcpResources(command=self.command, remote=lambda *_a, **_k: None,
   record=self.record, source=SOURCE, daemon_id='daemon', mailpit_image=self.receipt['imageId'],
   runner_image=self.receipt['imageId'], nonce='1' * 32, build_receipt=self.receipt,
   context_sha256='b' * 64, model_digest='d' * 64)
 def patches(self, inventory=None, runner_launch=None, command=None):
  stack = ExitStack(); stack.enter_context(patch.object(resources, 'StrictRunner', FakeRunner))
  stack.enter_context(patch.object(resources, 'verify_image')); stack.enter_context(patch.object(resources, 'verify_daemon'))
  stack.enter_context(patch.object(resources, 'inspect_owned', return_value={'HostConfig': {'ReadonlyRootfs': True}, 'Mounts': [],
   'NetworkSettings': {'Ports': {'1025/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '38092'}], '8025/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '38093'}]}}}))
  stack.enter_context(patch.object(resources, 'validate_mailpit_layout', return_value=(38092, 38093)))
  stack.enter_context(patch.object(resources, 'cleanup_owned', return_value={'status': 'removed_absence_verified'}))
  stack.enter_context(patch.object(resources.http.client, 'HTTPConnection', FakeHttp))
  if isinstance(inventory, list): stack.enter_context(patch.object(resources.FullBackendMcpResources, 'inventory_model', side_effect=inventory))
  else: stack.enter_context(patch.object(resources.FullBackendMcpResources, 'inventory_model'))
  if runner_launch: stack.enter_context(patch.object(FakeRunner, 'launch', side_effect=runner_launch))
  if command: stack.enter_context(patch.object(self, 'command', side_effect=command))
  return stack
 @patch.object(resources, 'StrictRunner', FakeRunner)
 @patch.object(resources, 'verify_image')
 @patch.object(resources, 'verify_daemon')
 @patch.object(resources, 'inspect_owned', return_value={'HostConfig': {'ReadonlyRootfs': True}, 'Mounts': [],
   'NetworkSettings': {'Ports': {'1025/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '38092'}],
                                 '8025/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '38093'}]}}})
 @patch.object(resources, 'validate_mailpit_layout', return_value=(38092, 38093))
 @patch.object(resources.FullBackendMcpResources, 'inventory_model')
 @patch.object(resources.http.client, 'HTTPConnection', FakeHttp)
 def test_owned_launch_returns_manifest_and_generated_token(self, _inventory, _layout, _inspect, _daemon, _image):
  runner = self.make(); manifest, token = runner.launch(38090)
  self.assertEqual(set(manifest), {'version', 'postgres', 'runner', 'smtp', 'mailpit', 'model'})
  self.assertEqual(manifest['model'], {'host': '127.0.0.1', 'port': 11434})
  self.assertRegex(token, r'^[A-Za-z0-9_-]{64}$'); self.assertTrue(runner.runner.prepared)
  self.assertTrue(any(name == 'mcp-endpoints.json' for name, _value in self.receipts))
 @patch.object(FakeRunner, 'cleanup', side_effect=RuntimeError('controlled'))
 @patch.object(resources, 'StrictRunner', FakeRunner)
 @patch.object(resources, 'cleanup_owned', side_effect=RuntimeError('controlled'))
 def test_cleanup_reports_both_owned_cleanup_failures(self, _container_cleanup, _runner_cleanup):
  runner = self.make(); runner.mail['intended'] = True; runner.mail['captured'] = 'a' * 64
  with self.assertRaisesRegex(RuntimeError, 'runner_cleanup,mailpit_cleanup'): runner.cleanup()
  self.assertTrue(any(name == 'mcp-cleanup-debt.json' for name, _value in self.receipts))

 def test_uncertain_mailpit_creation_cleans_with_unknown_id(self):
  with self.patches():
   runner = self.make(); self.assertFalse(runner.mail['intended'])
   runner.command = lambda _args: (_ for _ in ()).throw(RuntimeError('create'))
   with self.assertRaises(RuntimeError): runner.launch(38090)
   self.assertTrue(runner.mail['intended'])
   with patch.object(resources, 'cleanup_owned') as cleanup:
    runner.cleanup()
   self.assertIsNone(cleanup.call_args.kwargs['captured_id'])

 def test_runner_failure_still_cleans_mailpit(self):
  with self.patches(runner_launch=RuntimeError('runner')):
   runner = self.make()
   with self.assertRaises(RuntimeError): runner.launch(38090)
   
   runner.cleanup()
  self.assertTrue(any(name == 'mailpit-cleanup.json' for name, _value in self.receipts))

 def test_runtime_mismatch_still_cleans_both_resources(self):
  original = self.command
  def command(args):
   if args and args[0] == 'exec': return SimpleNamespace(returncode=0, stdout='wrong\n')
   return original(args)
  with self.patches(command=command):
   runner = self.make()
   with self.assertRaisesRegex(RuntimeError, 'runtime mismatch'): runner.launch(38090)
   runner.cleanup()
  self.assertTrue(any(name == 'mailpit-cleanup.json' for name, _value in self.receipts))

 def test_model_postflight_drift_is_reported_after_resource_cleanup(self):
  with self.patches(inventory=[None, RuntimeError('model drift')]):
   runner = self.make(); runner.launch(38090)
   with self.assertRaisesRegex(RuntimeError, 'model_postflight'): runner.cleanup()
  self.assertTrue(any(name == 'mailpit-cleanup.json' for name, _value in self.receipts))

if __name__ == '__main__': unittest.main()
