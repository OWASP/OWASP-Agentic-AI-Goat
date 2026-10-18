"""Pure launcher contracts; no Docker, database, child or source staging."""
import ast
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('embedding_selective_main',HERE/'run-embedding-selective-isolated.py')
m=importlib.util.module_from_spec(spec)
with patch('subprocess.run',side_effect=AssertionError('No process')),patch('subprocess.Popen',side_effect=AssertionError('No process')),patch('tempfile.mkdtemp',side_effect=AssertionError('No allocation')):
 spec.loader.exec_module(m)
class Contracts(unittest.TestCase):
 def test_group_requires_uid_and_session(self):
  from types import SimpleNamespace
  output=SimpleNamespace(stdout=f'42 42 {m.os.getuid()}\n')
  with patch.object(m.subprocess,'run',return_value=output),patch.object(m.os,'getsid',return_value=42):self.assertEqual(m.owned_group_members(42,42,{}),[42])
  with patch.object(m.subprocess,'run',return_value=output),patch.object(m.os,'getsid',return_value=99):
   with self.assertRaises(RuntimeError):m.owned_group_members(42,42,{})
  with patch.object(m.subprocess,'run',return_value=SimpleNamespace(stdout=f'42 42 {m.os.getuid()+1}\n')):
   with self.assertRaises(RuntimeError):m.owned_group_members(42,42,{})
 def test_pinned_canonical_node(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp).resolve();node=root/'node';node.write_bytes(b'synthetic executable identity');pin=hashlib.sha256(node.read_bytes()).hexdigest()
   self.assertEqual(m.validate_node(str(node),pin),node)
   with self.assertRaises(RuntimeError):m.validate_node(str(node),'0'*64)
   alias=root/'alias';alias.symlink_to(node)
   with self.assertRaises(RuntimeError):m.validate_node(str(alias),pin)
 def test_wrong_host_rejected_before_allocation(self):
  with patch.object(m,'validate_node',return_value=Path('/synthetic/node')),patch.object(m,'source_inventory',return_value={}),patch.object(m.tempfile,'mkdtemp',side_effect=AssertionError('No allocation')):
   with self.assertRaises(SystemExit):m.main(['--docker-host','unix:///wrong','--node','/synthetic/node','--node-sha256','0'*64])
 def test_inventory_rejects_symlink_and_observes_changes(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp).resolve()
   names=['package.json','package-lock.json','tests/postgres/secureshopEmbeddingSelective.integration.test.js','tests/postgres/run-embedding-selective-isolated.py','tests/postgres/sql_nosql_process_ownership.py']
   for n in names:
    p=root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('synthetic')
   before=m.source_inventory(root);(root/names[0]).write_text('changed');self.assertNotEqual(before,m.source_inventory(root))
   folder=root/'shared';folder.mkdir();(folder/'alias').symlink_to(root/names[0])
   with self.assertRaises(RuntimeError):m.source_inventory(root)
 def test_existing_integration_assertions_retained(self):
  root=HERE.parent.parent
  old=json.loads((root/'tests/release-inputs/embedding-selective-main-predecessors-v1.json').read_text())
  import base64
  before=base64.b64decode(old['tests/postgres/secureshopEmbeddingSelective.integration.test.js']['base64']).decode()
  after=(HERE/'secureshopEmbeddingSelective.integration.test.js').read_text()
  for line in before.splitlines():
   if 'assert.' in line:
    if line == "    await assert.rejects(service.reindexSelective(input(onlyProducts, 'policies')), { code: 'EMBEDDING_REINDEX_UNSUPPORTED' }); record('no-source reviews and unsupported policies rejected');":
     # Policies became a supported corpus; retain both no-source and closed-enum rejection.
     self.assertIn("input(onlyProducts, 'policies')), { code: 'EMBEDDING_REINDEX_NO_SOURCE' }",after)
     self.assertIn("input(onlyProducts, 'unsupported-corpus')), { code: 'EMBEDDING_REINDEX_UNSUPPORTED' }",after)
     self.assertEqual(after.count('assert.equal(embeds.length, noSourceOffset); assert.deepEqual(await targetState(onlyProducts), noSourceBefore);'),3)
    elif line == '    assert.equal((await repo.readHead(a)).revisionId, repaired.revisionId);':
     self.assertIn('    const repairedHead = await repo.readHead(a);',after)
     self.assertIn('    assert.equal(repairedHead.revisionId, repaired.revisionId);',after)
     self.assertIn('    assert.equal(repairedHead.runtimeFingerprint, fingerprintA);',after)
    else:self.assertIn(line,after)
  self.assertIn("flag: 'wx'",after)
  self.assertNotIn("path.resolve(__dirname, '../../embedding-selective-result.json')",after)
 def test_absolute_main_child_private_cwd_no_copy(self):
  source=(HERE/'run-embedding-selective-isolated.py').read_text();ast.parse(source)
  self.assertNotIn('copyIsolatedSource',source);self.assertNotIn('symlink_to',source)
  self.assertIn("str(SOURCE/test_file)],name='selective',cwd=runtime",source)
  self.assertIn("'HOME':str(runtime/'home')",source)
  self.assertIn('source_inventory(SOURCE)!=source_before',source)
  self.assertIn('owned=OwnedProcesses(stop_group)',source)
  tree=ast.parse(source)
  assigned=[n for n in ast.walk(tree) if isinstance(n,ast.Name) and isinstance(n.ctx,ast.Store) and n.id=='runtime']
  self.assertEqual(len(assigned),1, 'Runtime directory cannot be overwritten by database role')
if __name__=='__main__':unittest.main()
