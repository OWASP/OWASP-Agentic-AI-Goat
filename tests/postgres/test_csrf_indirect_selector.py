import unittest,json,tempfile,hashlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import csrf_indirect_selector as selector
class IndirectTests(unittest.TestCase):
 def args(self,**kw):
  args=dict(csrf_full_app='actual-indirect-chain',node_binary='/owned/node',node_sha256='a'*64,node_version='v26.10.0',dependency_root='/owned/deps',csrf_indirect_dependency_byte_sha256='c'*64,dependency_hashes=json.dumps(dict.fromkeys(['package.json','package-lock.json','node_modules/.package-lock.json','client/package.json','client/package-lock.json','client/node_modules/.package-lock.json'],'b'*64)));args.update(kw);return SimpleNamespace(**args)
 def test_cleanup_failure_does_not_reset_shared_deadline(self):
  from mail_disclosure_cleanup_budget import CleanupBudget
  ticks=[0];budget=CleanupBudget(120,clock=lambda:ticks[0]);seen=[]
  def failed():
   ticks[0]=119;raise RuntimeError('owned cleanup failure')
  with self.assertRaises(RuntimeError):budget.run(failed)
  budget.run(lambda:seen.append('remaining cleanup attempted'))
  ticks[0]=120
  with self.assertRaises(TimeoutError):budget.run(lambda:seen.append('must not execute'))
  self.assertEqual(seen,['remaining cleanup attempted'])
 def test_actual_frontend_build_argv_uses_native_loader_for_indirect(self):
  import ast
  from owned_dependency_overlay import vite_config_arguments
  tree=ast.parse(Path(__file__).with_name('run-listings-integrated-isolated.py').read_text())
  call=next(n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='run' and n.args and isinstance(n.args[0],ast.List) and any(isinstance(x,ast.Starred) and isinstance(x.value,ast.Call) and getattr(x.value.func,'id',None)=='vite_config_arguments' for x in n.args[0].elts) and len(n.args[0].elts)==4)
  for mode,expected in [('actual-indirect-chain',['--configLoader','native']),('actual-g2',[])]:
   args=SimpleNamespace(dpi_containment_rendered=False,mail_disclosure_rendered=None,csrf_full_app=mode)
   argv=eval(compile(ast.Expression(call.args[0]),'<actual-build-argv>','eval'),{'NODE':Path('/owned/node'),'DEPENDENCIES':Path('/owned/deps'),'args':args,'vite_config_arguments':vite_config_arguments})
   self.assertEqual(argv[3:],expected)
 def test_exclusive_pinned_selector(self):
  selector.validate(self.args())
  for kw in [dict(mail_disclosure_rendered='vuln'),dict(mail_disclosure_catalog=True),dict(full_app=True),dict(actual8b=True),dict(node_version='v26.9.0'),dict(dependency_hashes='{}')]:
   with self.subTest(kw=kw),self.assertRaises(ValueError):selector.validate(self.args(**kw))
 def test_unrelated_modes_preserved(self):
  for mode in ['actual-g2','actual-get-chain','actual-post-chain','catalog',None]:selector.validate(SimpleNamespace(csrf_full_app=mode))
 def test_cache_exact_missing_tamper_symlink(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d).resolve();pins={f'{i}.bin':hashlib.sha256(bytes([i])).hexdigest() for i in range(4)}
   for i in range(4):(root/f'{i}.bin').write_bytes(bytes([i]))
   with patch.object(selector,'EMBEDDING_ASSETS',pins):
    self.assertEqual(selector.verify_cache(root),pins)
    (root/'0.bin').write_bytes(b'bad')
    with self.assertRaises(ValueError):selector.verify_cache(root)
    (root/'0.bin').unlink();(root/'0.bin').symlink_to(root/'1.bin')
    with self.assertRaises(ValueError):selector.verify_cache(root)
    (root/'0.bin').unlink()
    with self.assertRaises(ValueError):selector.verify_cache(root)
 def test_new_digest_cannot_be_used_by_other_modes(self):
  with self.assertRaises(ValueError):selector.validate(self.args(csrf_full_app='catalog'))
 def test_qualified_cache_four_constants(self):
  self.assertEqual(len(selector.EMBEDDING_ASSETS),4)
  self.assertIn('tests/fixtures/fullBackendModelCache/Xenova/all-MiniLM-L6-v2/onnx/model_quantized.onnx',selector.EMBEDDING_ASSETS)

 def test_actual_full_byte_donor_verification_rejects_drift(self):
  import coupon_dependency_integrity as integrity
  with tempfile.TemporaryDirectory() as d:
   root=Path(d).resolve();donor=root/'donor';donor.mkdir();source=root/'source';source.mkdir()
   for name in integrity.IDENTITIES:
    p=donor/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('{}')
   identities={name:integrity.sha(donor/name) for name in integrity.IDENTITIES};digest=integrity.digest(integrity.inventory(donor))
   args=self.args(dependency_root=str(donor),dependency_hashes=json.dumps(identities),csrf_indirect_dependency_byte_sha256=digest)
   self.assertEqual(selector.verify_dependencies(args,source)['digest'],digest)
   (donor/'node_modules/extra.js').write_text('drift')
   with self.assertRaisesRegex(RuntimeError,'byte drift'):selector.verify_dependencies(args,source)
 def test_readonly_copy_directories_become_owned_writable_without_changing_files_or_donor(self):
  import shutil,stat
  from owned_dependency_overlay import prepare_owned_runtime_directories
  with tempfile.TemporaryDirectory() as d:
   root=Path(d).resolve();frozen=root/'frozen';frozen.mkdir();(frozen/'file').write_text('exact');(frozen/'file').chmod(0o444);frozen.chmod(0o555)
   evidence=root/'evidence';evidence.mkdir(mode=0o700);copy=evidence/'source';shutil.copytree(frozen,copy)
   try:
    prepare_owned_runtime_directories(frozen,copy,evidence)
    (copy/'node_modules').symlink_to(root/'donor')
    self.assertEqual(stat.S_IMODE(frozen.stat().st_mode),0o555)
    self.assertEqual(stat.S_IMODE((copy/'file').stat().st_mode),0o444)
    self.assertEqual((copy/'file').read_text(),'exact')
   finally:frozen.chmod(0o700)
