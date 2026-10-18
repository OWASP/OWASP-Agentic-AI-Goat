"""Offline connected manifest/SSH binding checks; never reads actual SSH config."""
import unittest
from unittest.mock import patch
import tempfile
from pathlib import Path
from mcp_connected_baseline_contract import REQUIRED,MIGRATIONS,SCOPE,validate_manifest,validate_ssh,digest
class Contract(unittest.TestCase):
 def test_closure_and_reserved_migration_denial(self):
  value=dict(version=1,scope=SCOPE,files={p:'a'*64 for p in REQUIRED},symlinks={},directories=[])
  validate_manifest(value)
  for name in REQUIRED:
   subset={**value,'files':{p:h for p,h in value['files'].items() if p!=name}}
   with self.assertRaises(RuntimeError):validate_manifest(subset)
  value['files']['db/postgres/identity-migrations/0062_reserved.sql']='b'*64
  with self.assertRaises(RuntimeError):validate_manifest(value)
 def test_ssh_config_hash_and_safe_host_argv(self):
  with tempfile.TemporaryDirectory() as directory:
   config=Path(directory).resolve()/'config';config.write_text('Host controlled\n')
   with patch('mcp_connected_baseline_contract.validate_docker_cli'):
    argv=validate_ssh('/usr/bin/ssh','a'*64,str(config),digest(config),'owned-host')
    self.assertEqual(argv[-2:],['owned-host','--'])
    for host in ['-oProxyCommand=x','host;echo x','host name']:
     with self.assertRaises(RuntimeError):validate_ssh('/usr/bin/ssh','a'*64,str(config),digest(config),host)
    with self.assertRaises(RuntimeError):validate_ssh('/usr/bin/ssh','a'*64,str(config),'b'*64,'owned-host')
    with self.assertRaises(RuntimeError):validate_ssh('/other/ssh','a'*64,str(config),digest(config),'owned-host')
if __name__=='__main__':unittest.main()
