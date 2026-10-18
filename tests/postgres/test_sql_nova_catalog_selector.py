import importlib.util, pathlib, sys, unittest
from types import SimpleNamespace
sys.path.insert(0,str(pathlib.Path(__file__).parent))
spec=importlib.util.spec_from_file_location('full_catalog_launcher',pathlib.Path(__file__).with_name('run-full-backend-auth-isolated.py'))
launcher=importlib.util.module_from_spec(spec);spec.loader.exec_module(launcher)
class Selector(unittest.TestCase):
 def args(self,**changes):return SimpleNamespace(**dict(dict(sql_nova_catalog=True,rendered=True,capacity_200=False,mcp_indirect=False,secureshop=False,model_digest=None),**changes))
 def test_exclusive(self):
  for change in [dict(rendered=False),dict(capacity_200=True),dict(mcp_indirect=True),dict(secureshop=True),dict(model_digest='actual')]:
   with self.assertRaises(ValueError):launcher.validate_sql_nova_catalog(self.args(**change))
 def test_closed_bounds(self):
  self.assertEqual(launcher.validate_sql_nova_catalog(self.args()),dict(workSeconds=1200,childSeconds=1080,cleanupSeconds=120,http=4000,renderSeconds=900))
  self.assertIsNone(launcher.validate_sql_nova_catalog(self.args(sql_nova_catalog=False)))
 def test_missing_closure(self):
  with self.assertRaises(ValueError):launcher.validate_sql_nova_catalog(self.args(),{'files':{}})
if __name__=='__main__':unittest.main()
