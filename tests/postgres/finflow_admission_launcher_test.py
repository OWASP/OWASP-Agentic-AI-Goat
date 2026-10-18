import importlib.util,pathlib,sys,unittest,copy
from types import SimpleNamespace
from unittest.mock import patch
HERE=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('admission_parent',HERE/'run-setup-database-phase-isolated.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Controls(unittest.TestCase):
 def test_store_and_environment(self):
  sql,urls=m.finflow_admission_store_configuration(55432,'abcdef012345');self.assertEqual(sql.count('CREATE DATABASE '),1);self.assertEqual(sql.count('CREATE ROLE '),2);self.assertEqual(set(urls),{'IDENTITY_DATABASE_URL','IDENTITY_MIGRATION_DATABASE_URL'})
  args=SimpleNamespace(node='/node',package='/main',manifest='/main/m',manifest_sha256='a'*64)
  with patch.object(pathlib.Path,'mkdir'):
   env=m.finflow_admission_environment(args,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'owner',urls)
   with self.assertRaises(RuntimeError):m.finflow_admission_environment(args,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'owner',{**urls,'PG_ADMIN_DATABASE_URL':'bad'})
  self.assertEqual({k for k in env if k.endswith('_URL')},set(urls));self.assertGreater(len(env['JWT_SECRET']),40);self.assertEqual(env['LOGS_DIR'],'/e/runtime/logs')
  for port,nonce in [(True,'abcdef012345'),(5432,'../bad')]:
   with self.assertRaises(ValueError):m.finflow_admission_store_configuration(port,nonce)
 def test_barrier_and_bounds(self):
  events=[];state={'parentPid':122,'manifestSha256':'a'*64};pipe=SimpleNamespace(write=lambda b:events.append(b),flush=lambda:None,close=lambda:None)
  m.publish_child_start(SimpleNamespace(pid=123,stdin=pipe),state,lambda:events.append(dict(state)),'finflow-admission');self.assertEqual(events[0]['nativePid'],123);self.assertEqual(events[1],b'1');self.assertEqual(m.scenario_bounds('finflow-admission'),(780,600,120));self.assertEqual(m.scenario_command(SimpleNamespace(node='/node',package='/main',scenario='finflow-admission')),['/node','/main/tests/postgres/finflowAdmissionMain.js'])
 def test_receipt_exact(self):
  scope='controlled actor/store; real authenticated live catalog; no model proof';q={'scope':scope,'actorCalls':2,'creditWrites':0,'enabled':200,'disabled':409,'hiddenSelected':403,'hiddenGeneral':403,'reenabled':200,'storageUnavailable':503,'canonicalCompletions':0,'canonicalJudgments':0};v={'status':'passed','scope':scope,'installedWrites':False,'modelCalls':0,'cleanupFailures':[],'sharedPoolsClosed':True,'poolCleanup':[{'index':i,'status':'closed'} for i in range(2)],'qualification':q};self.assertTrue(m.verify_finflow_admission_result(v))
  wrong=copy.deepcopy(v);wrong['sharedPoolsClosed']=False
  with self.assertRaises(RuntimeError):m.verify_finflow_admission_result(wrong)
  for k in q:
   wrong=copy.deepcopy(v);wrong['qualification'].pop(k)
   with self.assertRaises(RuntimeError):m.verify_finflow_admission_result(wrong)
   wrong=copy.deepcopy(v);wrong['qualification'][k]=False
   with self.assertRaises(RuntimeError):m.verify_finflow_admission_result(wrong)
if __name__=='__main__':
 import socket
 with patch('subprocess.run',side_effect=AssertionError('denied')),patch('subprocess.Popen',side_effect=AssertionError('denied')),patch.object(socket,'socket',side_effect=AssertionError('denied')):unittest.main()
