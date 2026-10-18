import importlib.util
import pathlib
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch
HERE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('setup_finflow0055',HERE/'run-setup-database-phase-isolated.py')
launcher=importlib.util.module_from_spec(spec);spec.loader.exec_module(launcher)
class Controls(unittest.TestCase):
    def test_two_databases_two_roles_four_urls(self):
        urls={};sqls=[]
        for case in ('fresh','populated'):
            sql,pairs=launcher.finflow0055_store_configuration(case,54321,'abcdef012345');sqls.append(sql);urls.update(pairs)
            self.assertIn('REVOKE CONNECT',sql)
            for value in pairs.values():self.assertTrue(value.endswith('_'+case))
        self.assertEqual(''.join(sqls).count('CREATE ROLE '),2)
        self.assertEqual(''.join(sqls).count('CREATE DATABASE '),2)
        self.assertEqual(len(urls),4)
        for args in [('installed',54321,'abcdef012345'),('fresh',True,'abcdef012345'),('fresh',54321,'../x')]:
            with self.assertRaises(ValueError):launcher.finflow0055_store_configuration(*args)
    def test_private_closed_environment(self):
        args=SimpleNamespace(node='/node',package='/main',manifest='/main/manifest',manifest_sha256='a'*64)
        urls={}
        for case in ('fresh','populated'):urls.update(launcher.finflow0055_store_configuration(case,54321,'abcdef012345')[1])
        with patch.object(pathlib.Path,'mkdir'):
            env=launcher.finflow0055_environment(args,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'owner',urls)
            with self.assertRaises(RuntimeError):launcher.finflow0055_environment(args,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'owner',{**urls,'PG_ADMIN_DATABASE_URL':'bad'})
        self.assertEqual({k for k in env if k.endswith('_URL')},set(urls))
        self.assertEqual(env['HOME'],'/e/runtime/home');self.assertNotIn('DVAIA_ISOLATED_TEST_WORKSPACE',env)
    def test_journal_barrier_and_command(self):
        events=[];state={'parentPid':122,'manifestSha256':'a'*64}
        pipe=SimpleNamespace(write=lambda x:events.append(x),flush=lambda:None,close=lambda:None)
        launcher.publish_child_start(SimpleNamespace(pid=123,stdin=pipe),state,lambda:events.append(dict(state)),'finflow-0055')
        self.assertEqual(events[0],{'parentPid':122,'manifestSha256':'a'*64,'nativePid':123,'nativeStarted':True});self.assertEqual(events[1],b'1')
        self.assertEqual(launcher.scenario_bounds('finflow-0055'),(780,600,120))
        self.assertEqual(launcher.scenario_command(SimpleNamespace(node='/node',package='/main',scenario='finflow-0055')),['/node','/main/tests/postgres/finflow0055Main.js'])
    def test_exact_terminal_qualification_required(self):
        import copy
        scope='0055 historical-default qualification; no actor/Judge proof'
        value={'status':'passed','scope':scope,'installedWrites':False,'modelCalls':0,'cleanupFailures':[],'poolCleanup':[{'index':i,'status':'closed'} for i in range(4)],'qualification':{'freshManagedFields':4,'populatedLegacyUnknownFields':4,'customHintPreserved':True,'nullSolutionPreserved':True,'fieldRollbackCases':4,'secondMigrationNoop':True,'siblingPreserved':True,'failedLoaderRollback':True,'scope':scope}}
        self.assertTrue(launcher.verify_finflow0055_result(value))
        for key in value['qualification']:
            invalid=copy.deepcopy(value);invalid['qualification'].pop(key)
            with self.assertRaises(RuntimeError):launcher.verify_finflow0055_result(invalid)
            invalid=copy.deepcopy(value);invalid['qualification'][key]=False
            with self.assertRaises(RuntimeError):launcher.verify_finflow0055_result(invalid)
        for key,bad in [('installedWrites',True),('modelCalls',1),('poolCleanup',[]),('scope','wrong'),('cleanupFailures',['unsettled'])]:
            invalid=copy.deepcopy(value);invalid[key]=bad
            with self.assertRaises(RuntimeError):launcher.verify_finflow0055_result(invalid)
    def test_foreign_root_denied_before_manifest(self):
        with self.assertRaises(RuntimeError):launcher.validate_finflow0055_main(SimpleNamespace(package='/foreign',main_workspace=True))
if __name__=='__main__':
    import socket
    with patch('subprocess.run',side_effect=AssertionError('process denied')),patch('subprocess.Popen',side_effect=AssertionError('process denied')),patch.object(socket,'socket',side_effect=AssertionError('socket denied')):unittest.main()
