import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PATH=Path(__file__).with_name('run-ctf-stage9-main.py')
spec=importlib.util.spec_from_file_location('ctf_stage9_launcher',PATH)
module=importlib.util.module_from_spec(spec)
with patch('subprocess.run',side_effect=AssertionError('No resource')),patch('subprocess.Popen',side_effect=AssertionError('No resource')),patch('tempfile.mkdtemp',side_effect=AssertionError('No allocation')):
    spec.loader.exec_module(module)

class Controls(unittest.TestCase):
    def test_import_inert_and_duplicates(self):
        with self.assertRaises(ValueError):module.parse_main(['--main-workspace','x','--main-workspace','y'])
    def test_plan_does_not_allocate_or_import_helpers(self):
        args=type('Args',(),{'plan':True,'mode':'controlled'})()
        with patch.object(module,'parse_main',return_value=args),patch.object(module,'validate_main',return_value=(Path('/controlled'),{})),patch.object(module.importlib.util,'spec_from_file_location',side_effect=AssertionError('No dynamic import')),patch.object(module.tempfile,'mkdtemp',side_effect=AssertionError('No allocation')):
            self.assertEqual(module.main_current([]),0)
    def test_controlled_only_and_unknown_options(self):
        required=[]
        for key in ['main-workspace','manifest','manifest-sha256','node','node-sha256','python-sha256','docker','docker-sha256','docker-host','docker-daemon','image-id']:
            required.extend(['--'+key,'controlled-value'])
        self.assertEqual(module.parse_main(required+['--mode','controlled']).mode,'controlled')
        for extra in [['--mode','actual'],['--mode','unknown'],['--mode','controlled','--input','x'],['--mode','controlled','--unknown'],['--mode','controlled','--mode','controlled']]:
            with self.assertRaises((SystemExit,ValueError)):module.parse_main(required+extra)
    def test_actual_budget_and_frozen_input_binding(self):
        self.assertEqual(module.budgets('actual'),(660,600));self.assertEqual(module.budgets('controlled'),(360,240))
        root=Path('/controlled/main');expected=root/module.ACTUAL_INPUT
        args=type('Args',(),{'mode':'actual','input':str(expected),'input_sha256':module.ACTUAL_INPUT_SHA256,'manifest':'/manifest','manifest_sha256':'a'*64})()
        manifest={'sourcePins':{module.ACTUAL_INPUT:module.ACTUAL_INPUT_SHA256}}
        with patch.object(module.Path,'is_symlink',return_value=False),patch.object(module.Path,'resolve',return_value=expected),patch.object(module,'digest',return_value=module.ACTUAL_INPUT_SHA256):
            module.validate_actual_input(args,root,manifest)
            with self.assertRaises(RuntimeError):module.validate_actual_input(args,root,{'sourcePins':{}})
            args.input='/unrelated'
            with self.assertRaises(RuntimeError):module.validate_actual_input(args,root,manifest)
        args.input=str(expected)
        env=module.child_environment({},Path('/owned'),Path('/owned/runtime'),'owner',args)
        self.assertEqual(env['CTF_STAGE9_MODE'],'actual');self.assertEqual(env['CTF_STAGE9_INPUT'],str(expected));self.assertEqual(env['CTF_STAGE9_INPUT_SHA256'],module.ACTUAL_INPUT_SHA256)
    def test_exact_two_store_roles_and_delivery_scope(self):
        all_urls={}
        for label in ['identity','ctf']:
            sql,urls=module.store_configuration(label,55432);all_urls.update(urls)
            self.assertIn('NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',sql)
            self.assertIn('REVOKE CONNECT ON DATABASE dvaia_test_ctf_stage9_'+label+' FROM PUBLIC',sql)
            self.assertNotIn('BEGIN',sql)
            self.assertEqual('CREATE ROLE dvaia_ctf_delivery' in sql,label=='ctf')
        self.assertEqual(len(all_urls),5)
        from urllib.parse import urlparse
        for key,value in all_urls.items():
            url=urlparse(value);self.assertEqual(url.hostname,'127.0.0.1');self.assertEqual(url.port,55432)
            self.assertIn(url.path,['/dvaia_test_ctf_stage9_identity','/dvaia_test_ctf_stage9_ctf'])
        for label,port in [('other',55432),('ctf',0),('identity',True)]:
            with self.assertRaises(ValueError):module.store_configuration(label,port)
    def test_private_env_does_not_inherit_application_or_provider_settings(self):
        args=type('Args',(),{'mode':'controlled','manifest':'/main/manifest.json','manifest_sha256':'a'*64})()
        with patch.dict(module.os.environ,{'IDENTITY_DATABASE_URL':'private','OPENAI_API_KEY':'private','OLLAMA_BASE_URL':'http://installed','NODE_OPTIONS':'private'}):
            env=module.child_environment({'PATH':'/pinned:/usr/bin:/bin','HOME':'/owned/home'},Path('/owned'),Path('/owned/runtime'),'owner',args)
        for denied in ['IDENTITY_DATABASE_URL','OPENAI_API_KEY','OLLAMA_BASE_URL','NODE_OPTIONS','DVAIA_ISOLATED_TEST_WORKSPACE']:
            self.assertNotIn(denied,env)
        self.assertEqual(env['CTF_STAGE9_MAIN_ISOLATED'],'1')
        self.assertEqual(env['LOGS_DIR'],'/owned/runtime/logs')
        self.assertEqual(env['CTF_STAGE9_OWNER'],'owner')
    def test_aggregate_log_includes_multiple_files(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'a.log').touch();(root/'b.tap').touch()
            with (root/'a.log').open('wb') as f:f.truncate(33*1024**2)
            with (root/'b.tap').open('wb') as f:f.truncate(33*1024**2)
            with self.assertRaises(RuntimeError):module.check_logs(root)
    def test_child_then_cleanup_log_growth_is_denied(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);p=root/'result.tap';p.write_text('pass')
            self.assertLess(module.check_logs(root),100)
            with p.open('wb') as f:f.truncate(65*1024**2)
            with self.assertRaises(RuntimeError):module.check_logs(root)
    def test_running_chrome_version_link_is_bounded_to_owned_profile_and_pin(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);profile=root/'ctfsubmit-profile';profile.mkdir(mode=0o700)
            link=profile/'RunningChromeVersion';link.symlink_to('153.0.8010.36:1')
            self.assertEqual(module.check_logs(root),0)
            link.unlink();link.symlink_to('153.0.8010.37:1')
            with self.assertRaisesRegex(RuntimeError,'^BROWSER_RUNNING_VERSION_SHAPE$'):module.check_logs(root)
            link.unlink();link.symlink_to('153.0.8010.36:1/escape')
            with self.assertRaisesRegex(RuntimeError,'^BROWSER_RUNNING_VERSION_SHAPE$'):module.check_logs(root)
            link.unlink();link.symlink_to('153.0.8010.36:1')
            (profile/'OtherLink').symlink_to('153.0.8010.36:1')
            with self.assertRaisesRegex(RuntimeError,'^BROWSER_PROFILE_EXTRA_LINK$'):module.check_logs(root)
            (profile/'OtherLink').unlink();link.unlink()
            (root/'RunningChromeVersion').symlink_to('153.0.8010.36:1')
            with self.assertRaisesRegex(RuntimeError,'^EVIDENCE_LINK_UNEXPECTED$'):module.check_logs(root)
    def test_readiness_and_admin_commands_require_final_owned_tcp(self):
        for argv in [module.owned_ready_args('owned'),module.owned_psql_args('owned'),module.owned_psql_args('owned',True)]:
            self.assertEqual(argv[argv.index('-h')+1],'127.0.0.1')
            self.assertEqual(argv[argv.index('-p')+1],'5432')
        self.assertIn('VERBOSITY=sqlstate',module.owned_psql_args('owned'))
    def test_failure_projection_retains_stage_and_state_without_raw_data(self):
        response=type('Response',(),{'returncode':1,'stdout':'private-row','stderr':'ERROR:  25001\npassword=private-secret'})()
        state={'stage':'provision-agents'}
        with self.assertRaisesRegex(RuntimeError,'STORE_PROVISION_FAILED'):
            module.checked_command(response,'STORE_PROVISION_FAILED',state)
        self.assertEqual(state['lastCommand']['sqlStates'],['25001'])
        self.assertEqual(state['stage'],'provision-agents')
        self.assertNotIn('private',module.json.dumps(state))
    def test_running_python_alias_resolves_to_pinned_binary(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);binary=root/'cellar-python';binary.write_bytes(b'controlled executable')
            alias=root/'opt-python';alias.symlink_to(binary)
            with patch.object(module.sys,'executable',str(alias)):
                self.assertEqual(module.validate_running_python(module.digest(binary)),binary.resolve())
                with self.assertRaises(RuntimeError):module.validate_running_python('0'*64)
            with patch.object(module.sys,'executable','relative-python'):
                with self.assertRaises(RuntimeError):module.validate_running_python(module.digest(binary))
    def test_ownership_publication_atomic_private(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'ownership.json';module.publish(p,{'nativeStarted':False});module.publish(p,{'nativeStarted':True,'nativePid':42})
            self.assertEqual(module.json.loads(p.read_text())['nativePid'],42)
            self.assertEqual(p.stat().st_mode&0o777,0o600)
            self.assertEqual([x.name for x in Path(d).iterdir()],['ownership.json'])
if __name__=='__main__':unittest.main()
