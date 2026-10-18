import ast,json,unittest
from pathlib import Path
from owned_dependency_overlay import vite_config_arguments
from types import SimpleNamespace
from mail_disclosure_rendered_selector import validate

class SelectorTests(unittest.TestCase):
 def valid(self,**updates):
  keys=['package.json','package-lock.json','node_modules/.package-lock.json','client/package.json','client/package-lock.json','client/node_modules/.package-lock.json']
  value=dict(mail_disclosure_rendered='vuln',node_binary='/owned/node',node_sha256='a'*64,node_version='v26.10.0',dependency_root='/owned/deps',dependency_hashes=json.dumps(dict.fromkeys(keys,'b'*64)),mail_disclosure_dependency_byte_sha256='c'*64);value.update(updates);return SimpleNamespace(**value)
 def test_modes(self):
  for mode in ['vuln','fixed']:validate(self.valid(mail_disclosure_rendered=mode))
  validate(SimpleNamespace(mail_disclosure_rendered=None))
 def test_incompatible(self):
  for key in ['actual8b','saved_evidence','production_assembly','actual_grading','actual_grading_browser','catalog_candidate','rendered_catalog','full_app','full_app_retry','dpi_rendered','dpi_containment_rendered','dpi_containment_visual','inventory_rendered','inventory_catalog','inventory_grading','mail_header_rendered','mail_header_catalog','mail_header_readiness','mail_reply_rendered','mail_reply_seed_only','coupon_rendered','csrf_full_app']:
   with self.subTest(key=key),self.assertRaises(ValueError):validate(self.valid(**{key:True}))
 def test_pins(self):
  for key in ['node_binary','node_sha256','node_version','dependency_root','dependency_hashes','mail_disclosure_dependency_byte_sha256']:
   with self.subTest(key=key),self.assertRaises(ValueError):validate(self.valid(**{key:None}))
  with self.assertRaises(ValueError):validate(self.valid(dependency_hashes='{}'))
class BuildArgumentsTests(unittest.TestCase):
 def test_actual_launcher_build_arguments_use_native_for_all_disclosure_configs(self):
  tree=ast.parse(Path(__file__).with_name('run-listings-integrated-isolated.py').read_text())
  lists=[call.args[0] for call in ast.walk(tree) if isinstance(call,ast.Call) and isinstance(call.func,ast.Name) and call.func.id=='run' and call.args and isinstance(call.args[0],ast.List) and any(isinstance(x,ast.Constant) and x.value=='build' for x in call.args[0].elts)]
  self.assertEqual(len(lists),2,'Main build and both renderer configs share these two actual call sites')
  for mode,containment,csrf in [('vuln',False,None),('fixed',False,None),(None,False,None),(None,True,None),(None,False,'actual-indirect-chain'),(None,False,'actual-g2'),(None,False,'controlled-diagnostic')]:
   for expression in lists:
    for config in ['vite.review-renderer.config.mjs','vite.product-description-renderer.config.mjs']:
     argv=eval(compile(ast.Expression(expression),'<actual launcher argv>','eval'),{'str':str,'NODE':Path('/owned/node'),'DEPENDENCIES':Path('/frozen/deps'),'config':config,'args':SimpleNamespace(mail_disclosure_rendered=mode,dpi_containment_rendered=containment,csrf_full_app=csrf),'vite_config_arguments':vite_config_arguments})
     renderer='--config' in argv
     expected=bool(mode) or ((containment or csrf=='actual-indirect-chain') and not renderer)
     self.assertEqual('--configLoader' in argv,expected)
     if expected:self.assertEqual(argv[-2:],['--configLoader','native'])
     self.assertEqual(argv[1],'/frozen/deps/client/node_modules/vite/bin/vite.js')

if __name__=='__main__':unittest.main()

class InitializerDiagnosticTests(unittest.TestCase):
 def test_requires_same_disclosure_admission(self):
  with self.assertRaises(ValueError):validate(SimpleNamespace(mail_disclosure_rendered=None,mail_disclosure_initialize_only=True))
  for mode in ['vuln','fixed']:validate(SelectorTests().valid(mail_disclosure_rendered=mode,mail_disclosure_initialize_only=True))
 def test_actual_launcher_skips_build_executor_only_for_diagnostic(self):
  tree=ast.parse(Path(__file__).with_name('run-listings-integrated-isolated.py').read_text())
  guards=[]
  for node in ast.walk(tree):
   if isinstance(node,ast.If) and any(isinstance(x,ast.Attribute) and x.attr=='mail_disclosure_initialize_only' for x in ast.walk(node.test)):
    guards.append(ast.unparse(node.test))
  self.assertTrue(any('rendered_catalog' in x and 'not args.mail_disclosure_initialize_only' in x for x in guards))
  self.assertTrue(any('mail_reply_seed_only' in x and 'args.mail_disclosure_initialize_only' in x and 'not (' in x for x in guards))
  for expr in guards:
   if 'rendered_catalog' not in expr:continue
   values=dict(rendered_catalog=False,full_app=True,csrf_full_app=None,mail_reply_seed_only=False,mail_disclosure_initialize_only=True)
   self.assertFalse(eval(expr,{}, {'args':SimpleNamespace(**values)}));values['mail_disclosure_initialize_only']=False
   self.assertTrue(eval(expr,{}, {'args':SimpleNamespace(**values)}))

class DisclosureCatalogTests(unittest.TestCase):
 def test_closed_catalog_combinations(self):
  validate(SelectorTests().valid(mail_disclosure_catalog=True))
  for updates in [dict(mail_disclosure_rendered=None),dict(mail_disclosure_rendered='fixed'),dict(mail_disclosure_initialize_only=True),dict(mail_header_catalog=True),dict(actual8b=True)]:
   with self.subTest(updates=updates),self.assertRaises(ValueError):validate(SelectorTests().valid(mail_disclosure_catalog=True,**updates))
 def test_actual_launcher_admits_before_resources_and_sets_only_catalog_flag(self):
  tree=ast.parse(Path(__file__).with_name('run-listings-integrated-isolated.py').read_text())
  source=ast.unparse(tree)
  self.assertLess(source.index('validate_disclosure(args)'),source.index('tempfile.mkdtemp('))
  self.assertLess(source.index('Reviewed disclosure catalog fixture closure required'),source.index('tempfile.mkdtemp('))
  assignments=[n for n in ast.walk(tree) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Subscript) and isinstance(t.slice,ast.Constant) and t.slice.value=='MAIL_DISCLOSURE_CATALOG_RENDERED' for t in n.targets)]
  self.assertEqual(len(assignments),1)
  block=next(n for n in ast.walk(tree) if isinstance(n,ast.If) and assignments[0] in n.body)
  self.assertEqual(ast.unparse(block.test),'args.mail_disclosure_catalog')
  for selected in [False,True]:
   env={};exec(compile(ast.Module(body=[block],type_ignores=[]),'<catalog env>','exec'),{'args':SimpleNamespace(mail_disclosure_catalog=selected),'env':env})
   self.assertEqual(env,{'MAIL_DISCLOSURE_CATALOG_RENDERED':'1'} if selected else {})
 def test_exact_catalog_helper_closure_and_existing_bounds(self):
  from mail_disclosure_rendered_selector import CATALOG_FILES
  self.assertIn('tests/fixtures/secureshopMailDisclosureCatalog.js',CATALOG_FILES)
  self.assertEqual(len(CATALOG_FILES),len(set(CATALOG_FILES)))
  root=Path(__file__).resolve().parents[2]
  for name in CATALOG_FILES:self.assertTrue((root/name).is_file())
  tree=ast.parse(Path(__file__).with_name('run-listings-integrated-isolated.py').read_text())
  bound=next(n.value for n in ast.walk(tree) if isinstance(n,ast.Assign) and isinstance(n.value,ast.Dict) and 'browserSeconds' in [x.value for x in n.value.keys if isinstance(x,ast.Constant)] and ast.literal_eval(n.value).get('cleanupSeconds')==120 and ast.literal_eval(n.value).get('parentSeconds')==1440)
  self.assertEqual(ast.literal_eval(bound),{'parentSeconds':1440,'childSeconds':960,'browserSeconds':180,'buildSeconds':180,'cleanupSeconds':120,'maxModelHttp':4,'stores':16,'postgresMiB':1024})
