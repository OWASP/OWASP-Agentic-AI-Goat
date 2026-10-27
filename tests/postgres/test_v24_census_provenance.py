import importlib.util
import json
from pathlib import Path
import types
import unittest
ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/'tests/postgres/ownedSystemOriginalBrowserOwner.js'
class p:
 @staticmethod
 def transform():return SOURCE.read_text()
 NEW=None
p.NEW=p.transform().split('CENSUS_DIAGNOSTICS=0',1)[1].split('def profiles_absent():',1)[0]
p.NEW='CENSUS_DIAGNOSTICS=0'+p.NEW
class Tests(unittest.TestCase):
 def environment(self):
  rows=[]
  env={'CONF':{'temporary':'/private/owned'},'journal':rows.append,
       'require':lambda ok,code:None if ok else (_ for _ in ()).throw(RuntimeError(code))}
  exec(p.NEW,env)
  return env,rows
 def test_primary_errno_and_no_secrets(self):
  env,rows=self.environment();primary=RuntimeError('SECRET argv credential');primary.__cause__=PermissionError(13,'SECRET')
  def fail(**kw):raise primary
  for unused in range(7):
   with self.assertRaises(RuntimeError) as caught:env['browser_absent'](types.SimpleNamespace(process_records=fail),'child-retirement')
   self.assertIs(caught.exception,primary)
  self.assertEqual(len(rows),4)
  self.assertEqual(rows[0],dict(stage='browser-census-failure',operation='process-records',phase='child-retirement',errno='EACCES'))
  self.assertNotIn('SECRET',json.dumps(rows));self.assertLess(len(json.dumps(rows)),1024)
 def test_journal_failure_preserves_primary_and_unknown(self):
  env,rows=self.environment();primary=RuntimeError('private')
  def fail(**kw):raise primary
  def broken(row):raise OSError('secondary')
  env['journal']=broken
  with self.assertRaises(RuntimeError) as caught:env['browser_absent'](types.SimpleNamespace(process_records=fail),'profile-retirement')
  self.assertIs(caught.exception,primary)
  env['journal']=rows.append
  with self.assertRaises(RuntimeError):env['browser_absent'](types.SimpleNamespace(process_records=fail),'final-retirement')
  self.assertEqual(rows[0]['errno'],'unknown')
 def test_original_absence_and_all_stage_bindings(self):
  env,rows=self.environment()
  for arguments,expected in (([],True),(['--user-data-dir=/private/owned/profile'],False)):
   inventory=types.SimpleNamespace(process_records=lambda **kw:[{'arguments':arguments}])
   self.assertIs(env['browser_absent'](inventory,'preflight'),expected)
  self.assertEqual(rows,[])
  source=p.transform()
  for stage in ('preflight','no-child','child-retirement','profile-retirement','final-retirement'):
   self.assertEqual(source.count("browser_absent(inventory,'"+stage+"')"),1)
  self.assertIn("except BaseException:errors.append('BROWSER_PROFILE_UNPROVEN')",source)
  self.assertIn("controller.abort(error);return new Promise(()=>{});",source)
if __name__=='__main__':unittest.main()
