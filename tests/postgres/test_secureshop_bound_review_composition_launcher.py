import ast
import copy
import hashlib
import importlib.util
import json
import os
import signal
import stat
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "tests/postgres/run-secureshop-bound-review-composition-isolated.py"


def load_runner():
    spec = importlib.util.spec_from_file_location("bound_review_composition_launcher", RUNNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BoundReviewCompositionLauncherContract(unittest.TestCase):
    def test_persona_sessions_uses_current_checkout_without_source_or_sql_copies(self):
        self.assertIn('persona-sessions', self.module.CURRENT_HOST_SUITES)
        self.assertIn('persona-sessions', self.module.MAIN_CHECKOUT_SUITES)
        self.assertIn('persona-sessions', self.module.REQUIRES_MAIN_CHECKOUT)
        suite = self.module.SUITES['persona-sessions']
        self.assertEqual(suite['stores'], (('COMMERCE', 'COMMERCE'),
            ('FRESH_AGENTS', 'AGENTS'), ('POPULATED_AGENTS', 'AGENTS')))
        self.assertEqual(suite['test'],
            'tests/postgres/secureshopBoundPersonaSessions.integration.test.js')
        fixture = (ROOT / suite['test']).read_text()
        self.assertIn('historicalMigrator(13)(migration, agentsMigrations)', fixture)
        self.assertIn('historicalMigrator(14)(migration, agentsMigrations)', fixture)
        self.assertIn('historicalMigrator(15)(migration, agentsMigrations)', fixture)
        self.assertNotIn('copyFileSync', fixture)
        self.assertNotIn('copyAgentsPrefix', fixture)
        args = self.module.parse_args(['--docker-host', 'unix:///owned.sock',
            '--docker-cli', '/owned/docker', '--docker-cli-sha256', '0' * 64,
            '--node', '/owned/node', '--node-sha256', '1' * 64,
            '--suite', 'persona-sessions', '--main-checkout',
            '--current-host-profile', '/owned/profile', '--docker-daemon', 'owned-daemon',
            '--image-id', self.module.POSTGRES_IMAGE_ID,
            '--evidence-parent', str(ROOT / 'tasks/qualification')])
        self.module.validate_current_host_selection(args)

    def test_setup_failure_retains_bounded_private_output_without_command_or_environment(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'tasks/tmp') as directory:
            root = Path(directory)
            stderr = 'adding interface veth to bridge docker0 failed: Device does not exist\n' + '\u00e9' * 5000
            error = subprocess.CalledProcessError(125, ['docker', 'secret-command-value'],
                output='a' * 64 + '\n', stderr=stderr)
            with mock.patch.object(self.module.subprocess, 'run', side_effect=error), \
                    self.assertRaises(subprocess.CalledProcessError) as caught:
                self.module.run_setup_subprocess(['docker', 'secret-command-value'], root=root,
                    stage='docker-container-start', capture_output=True, text=True,
                    env={'SECRET': 'private-environment-value'})
            self.assertIs(caught.exception, error)
            receipt = root / 'setup-failure.json'
            self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
            value = json.loads(receipt.read_text())
            self.assertEqual(value['stage'], 'docker-container-start')
            self.assertEqual(value['exitCode'], 125); self.assertFalse(value['timedOut'])
            self.assertEqual(value['stdout']['text'], 'a' * 64 + '\n')
            self.assertTrue(value['stderr']['text'].startswith('adding interface veth'))
            self.assertEqual(value['stderr']['observedBytes'], len(stderr.encode()))
            self.assertTrue(value['stderr']['truncated'])
            self.assertLessEqual(len(value['stderr']['text'].encode()), self.module.SETUP_OUTPUT_BYTES)
            self.assertNotIn('secret-command-value', receipt.read_text())
            self.assertNotIn('private-environment-value', receipt.read_text())
            self.assertEqual(set(value), {'schemaVersion', 'kind', 'stage', 'exitCode', 'timedOut', 'stdout', 'stderr'})
            success = subprocess.CompletedProcess(['unused'], 0, stdout='a' * 64 + '\n', stderr='')
            with mock.patch.object(self.module.subprocess, 'run', return_value=success), \
                    mock.patch.object(self.module, 'write_private_json') as write:
                returned = self.module.run_setup_subprocess(['unused'], root=root,
                    stage='docker-container-start', capture_output=True, text=True)
                self.assertIs(returned, success); write.assert_not_called()

    def test_setup_timeout_and_credential_shaped_output_are_preserved_safely(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'tasks/tmp') as directory:
            error = subprocess.TimeoutExpired(['unused'], 60, output=b'partial output',
                stderr=b'postgresql://user:private-password@127.0.0.1/db')
            with mock.patch.object(self.module.subprocess, 'run', side_effect=error) as run, \
                    self.assertRaises(subprocess.TimeoutExpired) as caught:
                self.module.run_setup_subprocess(['unused'], root=Path(directory), stage='postgres-setup')
            self.assertIs(caught.exception, error)
            self.assertEqual(run.call_args.kwargs['stderr'], subprocess.PIPE)
            value = json.loads((Path(directory) / 'setup-failure.json').read_text())
            self.assertIsNone(value['exitCode']); self.assertTrue(value['timedOut'])
            self.assertEqual(value['stdout']['text'], 'partial output')
            self.assertTrue(value['stderr']['redacted'])
            self.assertNotIn('private-password', json.dumps(value))
            for text in ('PASSWORD=hidden', 'Authorization: hidden', 'Bearer hidden', 'api_key=hidden'):
                self.assertTrue(self.module.setup_output_excerpt(text)['redacted'])
            self.assertIsNone(self.module.setup_output_excerpt(None)['text'])

    def test_setup_receipt_write_failure_preserves_original_error_and_cleanup_flow(self):
        error = subprocess.CalledProcessError(125, ['unused'], stderr='bridge unavailable')
        with mock.patch.object(self.module.subprocess, 'run', side_effect=error), \
                mock.patch.object(self.module, 'write_private_json', side_effect=OSError('private path detail')), \
                self.assertRaises(subprocess.CalledProcessError) as caught:
            self.module.run_setup_subprocess(['unused'], root=Path('/unused'), stage='docker-container-start')
        self.assertIs(caught.exception, error)
        self.assertEqual(error.__notes__, ['Setup failure receipt unavailable (OSError)'])
        tree = ast.parse(self.source)
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run_qualification')
        wrapper = next(n for n in function.body if isinstance(n, ast.FunctionDef) and n.name == 'run')
        self.assertIn('run_setup_subprocess(command, root=root, stage=stage', ast.unparse(wrapper))
        guarded = next(n for n in function.body if isinstance(n, ast.Try) and n.finalbody)
        self.assertIn('finalize_owned(', ast.unparse(guarded.finalbody[1]))
        stages = [keyword.value.value for call in ast.walk(guarded) if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name) and call.func.id == 'run'
            for keyword in call.keywords if keyword.arg == 'stage']
        self.assertEqual(stages.count('docker-container-start'), 2)
        self.assertEqual(set(stages), {'docker-info', 'docker-image-inspect', 'docker-container-start', 'docker-container-port'})

    def test_manual_payload_variant_is_explicit_paired_current_host_only(self):
        base = ['--docker-host', 'unix:///unused', '--docker-cli', '/unused/docker',
            '--docker-cli-sha256', '0'*64, '--node', '/unused/node', '--node-sha256', '1'*64,
            '--suite', 'manual-rag-paired-browser', '--main-checkout', '--current-host-profile', '/owned/profile']
        self.assertIsNone(self.module.parse_args(base).manual_rag_payload_variant)
        args = self.module.parse_args(base + ['--manual-rag-payload-variant', 'completion-record-v1'])
        self.module.validate_current_host_selection(args)
        for patch in ({'suite':'manual-rag-browser'}, {'suite':'manual-rag-fixed-browser'},
                {'suite':'direct-injection-actual'}, {'main_checkout':False},
                {'current_host_profile':None}, {'manual_rag_payload_variant':'unreviewed'}):
            bad=copy.copy(args)
            for key,value in patch.items():setattr(bad,key,value)
            with self.assertRaisesRegex(RuntimeError,'Payload variant requires'):
                self.module.validate_current_host_selection(bad)
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            self.module.parse_args(base + ['--manual-rag-payload-variant', 'unreviewed'])
        # Plan only inspects the exclusive marker and never consumes it.
        with mock.patch.object(self.module, 'main_checkout_inventory', return_value={'digest':'a'*64,'files':{}}), \
                mock.patch.object(self.module, 'claim_manual_rag_variant', side_effect=AssertionError('No plan writes')), \
                redirect_stdout(StringIO()) as out:
            self.assertEqual(self.module.main(base + ['--manual-rag-payload-variant','completion-record-v1']),0)
        plan=json.loads(out.getvalue())
        self.assertEqual(plan['payloadVariant'],'completion-record-v1')
        self.assertIs(plan['oneAttempt'],True);self.assertIs(plan['nativeStarted'],False)
        with mock.patch.dict(os.environ, {'SECURESHOP_MANUAL_RAG_PAYLOAD_VARIANT':'completion-record-v1',
                'SECURESHOP_MANUAL_RAG_VARIANT_ATTEMPT':'/untrusted'}):
            env=self.module.qualification_base_environment(args,Path('/owned/run'),Path('/owned/node'),Path('/owned/docker'))
            self.assertNotIn('SECURESHOP_MANUAL_RAG_PAYLOAD_VARIANT',env)
            self.assertNotIn('SECURESHOP_MANUAL_RAG_VARIANT_ATTEMPT',env)

    def test_manual_role_spoof_variant_has_separate_closed_plan_and_one_shot_claim(self):
        base = ['--docker-host', 'unix:///unused', '--docker-cli', '/unused/docker',
            '--docker-cli-sha256', '0'*64, '--node', '/unused/node', '--node-sha256', '1'*64,
            '--suite', 'manual-rag-paired-browser', '--main-checkout', '--current-host-profile', '/owned/profile']
        args = self.module.parse_args(base + ['--manual-rag-payload-variant', 'role-spoof-v1'])
        self.module.validate_current_host_selection(args)
        for patch in ({'suite':'manual-rag-browser'}, {'suite':'manual-rag-fixed-browser'},
                      {'current_host_profile':None}, {'main_checkout':False},
                      {'manual_rag_payload_variant':'role-spoof-v2'}):
            bad=copy.copy(args)
            for key,value in patch.items():setattr(bad,key,value)
            with self.assertRaisesRegex(RuntimeError,'Payload variant requires'):
                self.module.validate_current_host_selection(bad)
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            self.module.parse_args(base + ['--manual-rag-payload-variant', 'role-spoof-v2'])
        with mock.patch.object(self.module, 'main_checkout_inventory', return_value={'digest':'a'*64,'files':{}}), \
                mock.patch.object(self.module, 'claim_manual_rag_variant', side_effect=AssertionError('No plan writes')), \
                redirect_stdout(StringIO()) as out:
            self.assertEqual(self.module.main(base + ['--manual-rag-payload-variant','role-spoof-v1']),0)
        plan=json.loads(out.getvalue())
        self.assertEqual(plan['payloadVariant'],'role-spoof-v1')
        self.assertIs(plan['attemptAlreadyClaimed'],os.path.lexists(
            self.module.variant_attempt_path(ROOT,'role-spoof-v1')))
        self.assertIs(plan['nativeStarted'],False)
        with tempfile.TemporaryDirectory(prefix='v26-role-claim-',dir=ROOT/'tasks/tmp') as tmp:
            source=Path(tmp);parent=source/'tasks/qualification';parent.mkdir(parents=True)
            root=parent/'run-controlled';root.mkdir()
            old=self.module.variant_attempt_path(source)
            role=self.module.variant_attempt_path(source,'role-spoof-v1')
            self.assertNotEqual(old,role)
            self.assertEqual(old.name,'v26-completion-record-v1-attempt.json')
            self.assertEqual(role.name,'v26-role-spoof-v1-attempt.json')
            historical=self.module.claim_manual_rag_variant(source,root,'a'*64)
            before=old.read_bytes()
            value=self.module.claim_manual_rag_variant(source,root,'a'*64,'role-spoof-v1')
            self.assertEqual(value['variant'],'role-spoof-v1')
            self.assertEqual(role.stat().st_mode&0o777,0o600)
            self.assertEqual(old.read_bytes(),before)
            self.module.validate_variant_attempt(historical,source=source,root=root,source_digest='a'*64)
            self.module.validate_variant_attempt(value,source=source,root=root,source_digest='a'*64,variant='role-spoof-v1')
            with self.assertRaisesRegex(RuntimeError,'attempt binding'):
                self.module.validate_variant_attempt(historical,source=source,root=root,source_digest='a'*64,variant='role-spoof-v1')
            with self.assertRaisesRegex(RuntimeError,'attempt binding'):
                self.module.validate_variant_attempt(value,source=source,root=root,source_digest='a'*64)
            with self.assertRaises(FileExistsError):
                self.module.claim_manual_rag_variant(source,root,'a'*64,'role-spoof-v1')
            self.assertEqual(old.read_bytes(),before)

    def test_startup_repair_requires_immutable_pretest_failure_and_separate_one_shot_claim(self):
        with tempfile.TemporaryDirectory(prefix='v26-startup-repair-',dir=ROOT/'tasks/tmp') as tmp:
            source=Path(tmp);parent=source/'tasks/qualification';parent.mkdir(parents=True)
            failed=parent/self.module.STARTUP_REPAIR_RUN;failed.mkdir(mode=0o700)
            repaired=parent/'run-repaired';repaired.mkdir(mode=0o700)
            old=parent/'v26-role-spoof-v1-attempt.json'
            def write(path,value):
                path.write_text(value if isinstance(value,str) else json.dumps(value,sort_keys=True),encoding='utf8')
                path.chmod(0o600)
            def pin(path):return hashlib.sha256(path.read_bytes()).hexdigest()
            digest='a'*64
            write(old,{'version':1,'variant':'role-spoof-v1','attemptId':'b'*32,
                'runRoot':str(failed),'sourceDigest':digest,'oneAttempt':True,
                'diagnostic':True,'canonicalCredit':False})
            files={
                'source-before.json':{'digest':digest,'files':{}},
                'source-after.json':{'digest':digest,'files':{}},
                'browser-inventory.json':{'root':'/Applications/Google Chrome.app','before':{},'after':{}},
                'browser-cleanup.json':{'schemaVersion':2,'processes':[],'temporaryProfilesAbsent':True},
                'child-process-intent.json':{'processes':[{'pid':123}]},
                'container-intent.json':{'containers':[{'containerId':'owned-container'}]},
                'cleanup.json':{'processes':[{'pid':123,'returncode':1,'cleanup':'absent_verified'}],
                    'containers':[{'containerId':'owned-container','cleanup':'absent_verified'}]},
                'result.log':"ReferenceError: Cannot access 'PAYLOAD_VARIANTS' before initialization\n"
                    'at payloadVariant (fixture:50)\nat Object.<anonymous> (fixture:22)\n',
            }
            for name,value in files.items():write(failed/name,value)
            pins={'claimSha256':pin(old),'runFilesSha256':{name:pin(failed/name) for name in files}}
            with mock.patch.object(self.module,'STARTUP_REPAIR_PINS',pins):
                proof=self.module.startup_repair_predecessor(source)
                self.assertEqual(proof['runRoot'],str(failed))
                value=self.module.claim_manual_rag_variant(source,repaired,'c'*64,
                    'role-spoof-startup-repair-v1')
                claim=self.module.variant_attempt_path(source,'role-spoof-startup-repair-v1')
                self.assertEqual(claim.stat().st_mode&0o777,0o600)
                self.assertEqual(value['version'],2);self.assertEqual(value['repairOf'],proof)
                self.module.validate_variant_attempt(value,source=source,root=repaired,
                    source_digest='c'*64,variant='role-spoof-startup-repair-v1')
                with self.assertRaises(FileExistsError):self.module.claim_manual_rag_variant(
                    source,repaired,'c'*64,'role-spoof-startup-repair-v1')
                for filename,bad in [('result.log','test registered and model called'),
                        ('browser-cleanup.json',{'schemaVersion':2,'processes':[{'pid':7}],
                            'temporaryProfilesAbsent':False}),
                        ('cleanup.json',{'processes':[{'pid':123,'returncode':1,'cleanup':'unverified'}],
                            'containers':[{'containerId':'owned-container','cleanup':'absent_verified'}]}),
                        ('source-after.json',{'digest':'d'*64,'files':{}})]:
                    path=failed/filename;original=path.read_bytes();write(path,bad)
                    changed=copy.deepcopy(pins);changed['runFilesSha256'][filename]=pin(path)
                    with self.assertRaises(RuntimeError):self.module.startup_repair_predecessor(source,changed)
                    path.write_bytes(original);path.chmod(0o600)
                extra=failed/'manual-rag-original-wire.json';write(extra,{})
                with self.assertRaisesRegex(RuntimeError,'unexpected or missing'):
                    self.module.startup_repair_predecessor(source)
                extra.unlink()
                self.assertEqual(self.module.startup_repair_predecessor(source),proof)
                self.assertEqual(old.stat().st_mode&0o777,0o600)
                self.assertEqual(claim.read_bytes(),json.dumps(value,sort_keys=True,separators=(',',':')).encode())

    def test_startup_repair_plan_rejects_missing_predecessor_before_dispatch(self):
        args=['--docker-host','unix:///unused','--docker-cli','/unused/docker',
            '--docker-cli-sha256','0'*64,'--node','/unused/node','--node-sha256','1'*64,
            '--suite','manual-rag-paired-browser','--main-checkout','--current-host-profile','goat-q',
            '--manual-rag-payload-variant','role-spoof-startup-repair-v1']
        with mock.patch.object(self.module,'startup_repair_predecessor',side_effect=RuntimeError('missing predecessor')) as gate, \
                mock.patch.object(self.module,'main_checkout_inventory') as inventory, \
                mock.patch.object(self.module,'run_qualification') as native, \
                self.assertRaisesRegex(RuntimeError,'missing predecessor'):
            self.module.main(args)
        gate.assert_called_once_with(ROOT);inventory.assert_not_called();native.assert_not_called()

    def test_manual_payload_variant_attempt_is_durable_exclusive_and_run_bound(self):
        with tempfile.TemporaryDirectory(prefix='v26-claim-',dir=ROOT/'tasks/tmp') as tmp:
            source=Path(tmp);parent=source/'tasks/qualification';parent.mkdir(parents=True)
            root=parent/'run-controlled';root.mkdir()
            marker=self.module.variant_attempt_path(source)
            value=self.module.claim_manual_rag_variant(source,root,'a'*64)
            self.assertEqual(marker.stat().st_mode&0o777,0o600)
            self.module.validate_variant_attempt(value,source=source,root=root,source_digest='a'*64)
            before=marker.read_bytes()
            with self.assertRaises(FileExistsError):self.module.claim_manual_rag_variant(source,root,'a'*64)
            self.assertEqual(marker.read_bytes(),before)
            for key,new in [('attemptId','bad'),('oneAttempt',1),('canonicalCredit',True),
                    ('sourceDigest','b'*64),('runRoot',str(parent/'run-other')),('version',True)]:
                bad={**value,key:new}
                with self.assertRaisesRegex(RuntimeError,'attempt binding'):
                    self.module.validate_variant_attempt(bad,source=source,root=root,source_digest='a'*64)
            # A failed/partial claim cannot silently authorize another attempt.
            marker.write_text('{',encoding='utf8')
            with self.assertRaises(FileExistsError):self.module.claim_manual_rag_variant(source,root,'a'*64)

    def test_manual_variant_directory_sync_failure_consumes_claim_before_native_dispatch(self):
        tree=ast.parse(self.source)
        function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='run_qualification')
        guarded=next(n for n in function.body if isinstance(n,ast.Try) and n.body
            and any(isinstance(c,ast.Name) and c.id=='claim_manual_rag_variant' for c in ast.walk(n.body[0])))
        # Execute the actual claim gate, no-copy branch, and first Docker call
        # from production launcher control flow; never invoke a native process.
        self.assertIn('run(docker',ast.unparse(guarded.body[2]))
        with tempfile.TemporaryDirectory(prefix='v26-sync-',dir=ROOT/'tasks/tmp') as tmp:
            source=Path(tmp);root=source/'tasks/qualification/run-controlled';root.mkdir(parents=True)
            marker=self.module.variant_attempt_path(source)
            synced=[];directory_fds=[]
            def fail_directory(fd):
                is_directory=stat.S_ISDIR(os.fstat(fd).st_mode)
                synced.append('directory' if is_directory else 'file')
                if is_directory:
                    directory_fds.append(fd)
                    raise OSError('controlled directory fsync failure')
            native=mock.Mock(side_effect=AssertionError('No native call after failed claim sync'))
            ns={'args':SimpleNamespace(manual_rag_payload_variant='completion-record-v1',main_checkout=True,
                    current_host_profile='/owned/profile'),
                'source':source,'root':root,'source_before':{'digest':'a'*64},
                'claim_manual_rag_variant':self.module.claim_manual_rag_variant,'run':native,'docker':['unused']}
            with mock.patch.object(self.module.os,'fsync',side_effect=fail_directory), \
                    self.assertRaisesRegex(OSError,'controlled directory fsync failure'):
                exec(compile(ast.Module(body=guarded.body[:3],type_ignores=[]),'<actual-v26-claim-gate>','exec'),ns)
            self.assertEqual(synced,['file','directory']);native.assert_not_called()
            self.assertTrue(marker.is_file());before=marker.read_bytes()
            with self.assertRaises(FileExistsError):self.module.claim_manual_rag_variant(source,root,'a'*64)
            self.assertEqual(marker.read_bytes(),before)
            for fd in directory_fds:
                with self.assertRaises(OSError):os.fstat(fd)

    def test_role_spoof_claim_sync_failure_cannot_use_historical_claim_or_dispatch(self):
        tree=ast.parse(self.source)
        function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='run_qualification')
        guarded=next(n for n in function.body if isinstance(n,ast.Try) and n.body
            and any(isinstance(c,ast.Name) and c.id=='claim_manual_rag_variant' for c in ast.walk(n.body[0])))
        with tempfile.TemporaryDirectory(prefix='v26-role-sync-',dir=ROOT/'tasks/tmp') as tmp:
            source=Path(tmp);root=source/'tasks/qualification/run-controlled';root.mkdir(parents=True)
            historical=self.module.claim_manual_rag_variant(source,root,'a'*64)
            historical_bytes=self.module.variant_attempt_path(source).read_bytes()
            role_marker=self.module.variant_attempt_path(source,'role-spoof-v1')
            def fail_directory(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode):
                    raise OSError('controlled role claim directory fsync failure')
            native=mock.Mock(side_effect=AssertionError('No native call after failed role claim sync'))
            ns={'args':SimpleNamespace(manual_rag_payload_variant='role-spoof-v1',main_checkout=True,
                    current_host_profile='/owned/profile'),
                'source':source,'root':root,'source_before':{'digest':'a'*64},
                'claim_manual_rag_variant':self.module.claim_manual_rag_variant,'run':native,'docker':['unused']}
            with mock.patch.object(self.module.os,'fsync',side_effect=fail_directory), \
                    self.assertRaisesRegex(OSError,'controlled role claim directory fsync failure'):
                exec(compile(ast.Module(body=guarded.body[:3],type_ignores=[]),'<actual-v26-role-claim-gate>','exec'),ns)
            native.assert_not_called()
            self.assertTrue(role_marker.is_file())
            self.assertEqual(self.module.variant_attempt_path(source).read_bytes(),historical_bytes)
            self.module.validate_variant_attempt(historical,source=source,root=root,source_digest='a'*64)
            with self.assertRaises(FileExistsError):
                self.module.claim_manual_rag_variant(source,root,'a'*64,'role-spoof-v1')

    def test_v26_browser_exception_is_separate_closed_and_emitted_by_actual_environment(self):
        base = ['--docker-host','unix:///unused','--docker-cli','/unused/docker',
            '--docker-cli-sha256','0'*64,'--node','/unused/node','--node-sha256','1'*64,
            '--suite','manual-rag-browser','--main-checkout','--current-host-profile','/owned/profile']
        args = self.module.parse_args(base)
        self.assertFalse(args.manual_rag_test_no_sandbox)
        args = self.module.parse_args(base+['--manual-rag-test-no-sandbox'])
        self.module.validate_current_host_selection(args)
        paired=copy.copy(args);paired.suite='manual-rag-paired-browser'
        self.module.validate_current_host_selection(paired)
        fixed=copy.copy(args);fixed.suite='manual-rag-fixed-browser'
        self.module.validate_current_host_selection(fixed)
        for patch in ({'manual_rag_payload_variant':'completion-record-v1'},
                      {'manual_rag_payload_variant':'role-spoof-v1'},
                      {'manual_rag_payload_variant':'unknown'}, {'manual_upload_q05':True}):
            rejected=copy.copy(fixed)
            for key,value in patch.items():setattr(rejected,key,value)
            with self.assertRaises(RuntimeError):
                self.module.validate_current_host_selection(rejected)
        for patch in ({'suite':'product-summary-browser'}, {'suite':'review'},
                      {'current_host_profile':None},{'main_checkout':False},
                      {'product_summary_test_no_sandbox':True}):
            for selected in (args,fixed):
                rejected=copy.copy(selected)
                for key,value in patch.items():setattr(rejected,key,value)
                with self.assertRaisesRegex(RuntimeError,'V26 current-host'):
                    self.module.validate_current_host_selection(rejected)
        self.assertNotIn('--test',self.module.native_test_command('/owned/node','manual-rag-browser'))
        self.assertNotIn('--test',self.module.native_test_command('/owned/node','manual-rag-paired-browser'))
        self.assertNotIn('--test',self.module.native_test_command('/owned/node','manual-rag-fixed-browser'))
        blocks=[n for n in ast.walk(ast.parse(self.source)) if isinstance(n,ast.If)
            and ast.unparse(n.test)=="args.suite in ('manual-rag-browser', 'manual-rag-fixed-browser', 'manual-rag-paired-browser')"
            and any(isinstance(x,ast.Constant) and x.value=='SECURESHOP_MANUAL_RAG_TEST_NO_SANDBOX' for x in ast.walk(n))]
        self.assertEqual(len(blocks),1)
        args.browser_sha256='f'*64
        ns={'args':args,'env':{},'source':ROOT,'root':Path('/owned/run'),'browser':Path('/owned/chrome'),
            'REFUND_MODEL':self.module.REFUND_MODEL,'REFUND_OLLAMA_BASE_URL':self.module.REFUND_OLLAMA_BASE_URL}
        exec(compile(ast.Module(body=blocks,type_ignores=[]),'<actual-v26-env>','exec'),ns)
        self.assertEqual(ns['env']['SECURESHOP_MANUAL_RAG_TEST_NO_SANDBOX'],'1')
        args.suite='manual-rag-fixed-browser';ns['env']={}
        exec(compile(ast.Module(body=blocks,type_ignores=[]),'<actual-v26-env>','exec'),ns)
        self.assertEqual(ns['env']['SECURESHOP_MANUAL_RAG_FIXED_ONLY'],'1')
        self.assertEqual(ns['env']['SECURESHOP_MANUAL_RAG_TEST_NO_SANDBOX'],'1')
        for name in ('SECURESHOP_MANUAL_RAG_PAIRED','SECURESHOP_MANUAL_UPLOAD_Q05',
                     'SECURESHOP_MANUAL_RAG_PAYLOAD_VARIANT','SECURESHOP_MANUAL_RAG_VARIANT_ATTEMPT'):
            self.assertNotIn(name,ns['env'])
        args.manual_rag_test_no_sandbox=False;ns['env']={}
        exec(compile(ast.Module(body=blocks,type_ignores=[]),'<actual-v26-env>','exec'),ns)
        self.assertNotIn('SECURESHOP_MANUAL_RAG_TEST_NO_SANDBOX',ns['env'])
        args.suite='manual-rag-paired-browser';args.manual_rag_payload_variant='completion-record-v1'
        ns.update(env={},MANUAL_RAG_PAYLOAD_VARIANT=self.module.MANUAL_RAG_PAYLOAD_VARIANT,
                  variant_attempt_path=self.module.variant_attempt_path)
        exec(compile(ast.Module(body=blocks,type_ignores=[]),'<actual-v26-env>','exec'),ns)
        self.assertEqual(ns['env']['SECURESHOP_MANUAL_RAG_PAYLOAD_VARIANT'],'completion-record-v1')
        self.assertEqual(ns['env']['SECURESHOP_MANUAL_RAG_VARIANT_ATTEMPT'],
                         str(ROOT/'tasks/qualification/v26-completion-record-v1-attempt.json'))
        args.manual_rag_payload_variant='role-spoof-v1';ns['env']={}
        exec(compile(ast.Module(body=blocks,type_ignores=[]),'<actual-v26-env>','exec'),ns)
        self.assertEqual(ns['env']['SECURESHOP_MANUAL_RAG_PAYLOAD_VARIANT'],'role-spoof-v1')
        self.assertEqual(ns['env']['SECURESHOP_MANUAL_RAG_VARIANT_ATTEMPT'],
                         str(ROOT/'tasks/qualification/v26-role-spoof-v1-attempt.json'))

    def test_fixed_manual_rag_uses_actual_current_host_browser_capture_and_read_options(self):
        tree=ast.parse(self.source)
        capture_call=next(n for n in ast.walk(tree) if isinstance(n,ast.Call)
            and isinstance(n.func,ast.Attribute) and n.func.attr=='capture_live'
            and getattr(n.func.value,'id',None)=='_browser_ownership')
        capture_gate=next(n for n in ast.walk(tree) if isinstance(n,ast.If)
            and any(x is capture_call for x in ast.walk(n))
            and isinstance(n.test,ast.BoolOp) and 'args.suite' in ast.unparse(n.test))
        read_calls=sorted((n for n in ast.walk(tree) if isinstance(n,ast.Call)
            and isinstance(n.func,ast.Attribute) and n.func.attr=='read_record'
            and getattr(n.func.value,'id',None)=='_browser_ownership'
            and any(k.arg=='allow_browser_session' for k in n.keywords)),key=lambda n:n.lineno)
        self.assertEqual(len(read_calls),3)
        marker=object();api=object();owner=SimpleNamespace(_owned_pgid=77,pid=77)
        for suite,expected_capture,expected_prefix,expected_session in (
                ('manual-rag-fixed-browser',True,'owasp-ai-goat-manual-rag-browser-',True),
                ('manual-rag-browser',True,'owasp-ai-goat-manual-rag-browser-',True),
                ('manual-rag-paired-browser',True,'owasp-ai-goat-manual-rag-browser-',True),
                ('product-summary-browser',True,'owasp-ai-goat-similar-browser-',True),
                ('review',False,None,False),('manual-rag-source',False,None,False)):
            args=SimpleNamespace(suite=suite,browser_sha256='a'*64)
            captures=mock.Mock(return_value=marker)
            reads=mock.Mock(return_value=[])
            ns={'args':args,'inspector':object(),'_browser_ownership':SimpleNamespace(
                    capture_live=captures,read_record=reads),
                'records':[marker],'parent_birth':(12,34),'root':Path('/owned/run'),
                'api':api,'browser_record_spec':(('browser.json','browser'),),
                'browser':Path('/owned/chrome'),'child':owner,'primary':None}
            selected=eval(compile(ast.Expression(capture_gate.test),'<actual-browser-gate>','eval'),ns)
            self.assertEqual(selected,expected_capture,suite)
            if selected:
                self.assertIs(eval(compile(ast.Expression(capture_call),'<actual-browser-capture>','eval'),ns),marker)
                captures.assert_called_once_with(marker,(12,34),Path('/owned/run/runtime'),api=api,
                    profile_prefix=expected_prefix)
            else:captures.assert_not_called()
            for index,call in enumerate(read_calls):
                reads.reset_mock()
                eval(compile(ast.Expression(call),'<actual-browser-read>','eval'),ns)
                kwargs=reads.call_args.kwargs
                self.assertEqual(kwargs['allow_browser_session'],True if index==0 else expected_session)
                self.assertEqual(kwargs['require_all'],False if index==0 else True)
                self.assertEqual(kwargs['parent_pid'],77)
                self.assertEqual(reads.call_args.args[:2],(Path('/owned/run'),'browser.json'))
            ns['primary']=RuntimeError('controlled earlier failure')
            reads.reset_mock()
            eval(compile(ast.Expression(read_calls[2]),'<actual-browser-finally>','eval'),ns)
            self.assertFalse(reads.call_args.kwargs['require_all'])

    def test_v16_direct_node_preserves_single_tap_and_owned_parent(self):
        node = ROOT / 'tasks/runtime/node/node_modules/node/bin/node'
        browser_suites=('product-summary-browser','manual-rag-browser',
                        'manual-rag-fixed-browser','manual-rag-paired-browser')
        tree=ast.parse(self.source)
        live_gate=next(n for n in ast.walk(tree) if isinstance(n,ast.If)
            and any(isinstance(x,ast.Call) and isinstance(x.func,ast.Attribute)
                and x.func.attr=='capture_live' for x in ast.walk(n))
            and 'args.suite' in ast.unparse(n.test))
        capture_suites=next(tuple(x.value for x in n.comparators[0].elts)
            for n in ast.walk(live_gate.test) if isinstance(n,ast.Compare)
            and isinstance(n.left,ast.Attribute) and n.left.attr=='suite'
            and isinstance(n.comparators[0],ast.Tuple))
        self.assertEqual(capture_suites,browser_suites)
        with tempfile.TemporaryDirectory(prefix='v26-direct-file-',dir=ROOT/'tasks/tmp') as directory:
            fixture=Path(directory)/'synthetic.test.cjs'
            fixture.write_text('const test=require("node:test");\n'
                'test("controlled direct parent",()=>console.log("DIRECT_PID="+process.pid+" PPID="+process.ppid));\n')
            for suite in browser_suites+('product-similar-browser','direct-injection-actual'):
                with self.subTest(suite=suite):
                    command=self.module.native_test_command(node,suite)
                    direct=suite in browser_suites
                    self.assertEqual(command[1:-1],['--test-reporter=tap'] if direct
                        else ['--test','--test-reporter=tap'])
                    child=subprocess.Popen(command[:-1]+[str(fixture)],cwd=ROOT,
                        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                    try:output,error=child.communicate(timeout=10)
                    finally:
                        if child.poll() is None:child.kill();child.wait(timeout=5)
                    self.assertEqual(child.returncode,0,error)
                    self.assertIn('TAP version 13',output)
                    self.assertIn('ok 1 - controlled direct parent',output)
                    self.assertIn('# tests 1',output)
                    self.assertIn('# pass 1',output)
                    self.assertIn('# fail 0',output)
                    self.assertIn('# skipped 0',output)
                    marker=next(line for line in output.splitlines() if 'DIRECT_PID=' in line)
                    identity=marker.split('DIRECT_PID=',1)[1].split(' PPID=')
                    reported_pid,reported_parent=map(int,identity)
                    self.assertEqual(reported_pid==child.pid,direct)
                    self.assertEqual(reported_parent,os.getpid() if direct else child.pid)

    def test_v16_browser_exception_requires_explicit_current_source_selection(self):
        base = ['--docker-host', 'unix:///unused', '--docker-cli', '/unused/docker',
                '--docker-cli-sha256', '0' * 64, '--node', '/unused/node',
                '--node-sha256', '1' * 64, '--suite', 'product-summary-browser']
        default = self.module.parse_args(base)
        self.assertFalse(default.product_summary_test_no_sandbox)
        allowed = self.module.parse_args(base + ['--product-summary-test-no-sandbox',
            '--main-checkout', '--current-host-profile', '/owned/profile'])
        self.module.validate_current_host_selection(allowed)
        for patch in ({'suite': 'product-similar-browser'}, {'suite': 'direct-injection-actual'},
                      {'main_checkout': False}, {'current_host_profile': None}):
            rejected = copy.copy(allowed)
            for key, value in patch.items():
                setattr(rejected, key, value)
            with self.assertRaisesRegex(RuntimeError, 'V16 current-host'):
                self.module.validate_current_host_selection(rejected)

    @classmethod
    def setUpClass(cls):
        cls.module = load_runner()
        cls.source = RUNNER.read_text()

    def test_module_is_import_safe_and_plan_requires_no_resources(self):
        self.assertEqual(self.module.main([
            "--docker-host", "unix:///unused", "--docker-cli", "/unused/docker",
            "--docker-cli-sha256", "0" * 64, "--node", "/unused/node",
            "--node-sha256", "1" * 64,
        ]), 0)

    def test_review_recovery_direct_source_admission_has_no_browser_or_embedding_requirement(self):
        name = 'review-moderation-recovery'
        suite = self.module.SUITES[name]
        self.assertEqual(suite['stores'], (('IDENTITY', 'IDENTITY'), ('AGENTS', 'AGENTS'),
            ('REVIEW', 'REVIEW'), ('COMMERCE', 'COMMERCE')))
        self.assertEqual(suite['env_prefix'], 'PG_SECURESHOP_REVIEW_RECOVERY_')
        self.assertEqual(suite['test'], 'tests/postgres/secureshopReviewModerationRecoveryActual.integration.test.js')
        for admitted in (self.module.CURRENT_HOST_SUITES, self.module.MAIN_CHECKOUT_SUITES,
                         self.module.REQUIRES_MAIN_CHECKOUT):
            self.assertIn(name, admitted)
        self.assertNotIn(name, self.module.EMBEDDING_CACHE_SUITES)
        for store, expected in self.module.AGENT_HOST_STORE_NAMES.items():
            self.assertEqual(self.module.database_name(name, store, 'f' * 12),
                f'owasp_ai_goat_test_agent_host_ffffffffffff_{expected}')
        inventory = self.module.main_checkout_inventory(ROOT, name)
        self.assertEqual(inventory['files'][suite['test']], self.module.REVIEW_RECOVERY_TEST_SHA256)
        self.assertEqual(inventory['files']['tests/secureshopReviewModerationRecoveryActualHarness.test.js'],
                         self.module.REVIEW_RECOVERY_HARNESS_SHA256)
        for source in ('server/routes/secureshop/boundReviews.js',
                       'server/services/secureshopReviewModerationRecovery.js',
                       'server/database/postgres/secureshopTurnRequestsRepository.js',
                       'tests/postgres/secureshopManualRagNativeSetup.js',
                       'sidecars/sandbox-runner/secureshopFiles.js'):
            self.assertIn(source, inventory['files'])
        self.assertIn('480 if args.suite == "review-moderation-recovery"', self.source)
        self.assertIn('assert_review_recovery_evidence(root, node)', self.source)
        self.assertIn('SECURESHOP_REVIEW_RECOVERY_EVIDENCE_PATH=str(root / "review-moderation-recovery-evidence.json")', self.source)

    def test_direct_injection_requires_original_source_two_stores_and_async_verification(self):
        name = 'direct-injection-actual'
        suite = self.module.SUITES[name]
        self.assertEqual(suite['stores'], (('COMMERCE', 'COMMERCE'), ('AGENTS', 'AGENTS')))
        self.assertEqual(suite['env_prefix'], 'PG_SECURESHOP_DIRECT_')
        for allowed in (self.module.CURRENT_HOST_SUITES, self.module.MAIN_CHECKOUT_SUITES,
                        self.module.REQUIRES_MAIN_CHECKOUT):
            self.assertIn(name, allowed)
        self.assertNotIn(name, self.module.EMBEDDING_CACHE_SUITES)
        arguments = self.module.parse_args([
            '--suite', name, '--main-checkout', '--docker-host', 'unix:///unused',
            '--docker-cli', '/unused/docker', '--docker-cli-sha256', '0' * 64,
            '--node', '/unused/node', '--node-sha256', '1' * 64])
        with self.assertRaisesRegex(RuntimeError, 'repository-local evidence'):
            self.module.validate_current_host_selection(arguments)
        for store in ('COMMERCE', 'AGENTS'):
            self.assertEqual(self.module.database_name(name, store, 'f' * 12),
                f'owasp_ai_goat_test_v14_ffffffffffff_{self.module.AGENT_HOST_STORE_NAMES[store]}')
        inventory = self.module.main_checkout_inventory(ROOT, name)
        for filename, expected in self.module.direct_source_pins().items():
            self.assertEqual(inventory['files'][filename], expected)
        for filename in ('agent-host/agents/cart/tools/index.postgres.js',
                         'server/services/secureshop/supervisors/customerSupervisor.js',
                         'server/services/secureshop/providers/ollamaProvider.js',
                         'server/agent-runtime/objectiveJudge.js',
                         'tests/postgres/secureshopMailActualTransport.js',
                         'tests/postgres/run_bound_review_with_inspector.py'):
            self.assertIn(filename, inventory['files'])
        with mock.patch.object(self.module, 'DIRECT_FIXTURE_SHA256', '0' * 64):
            with self.assertRaises(RuntimeError):
                self.module.main_checkout_inventory(ROOT, name)
        self.assertIn('420 if args.suite == "direct-injection-actual"', self.source)
        self.assertIn('assert_exact_single_tap(log_path, DIRECT_ASSERTION)', self.source)
        self.assertIn('PG_TEST_ROOT=str(root)', self.source)

    def test_direct_injection_prospective_source_pins_match_reviewed_terminal_containment(self):
        expected = {
            'tests/postgres/secureshopDirectInjectionActual.integration.test.js':
                '9cdd4fb02309647635727b34301e809b31c5a6a42c6d90f9e3b915dc72e6f0ce',
            'tests/fixtures/secureshopDirectInjectionActual.js':
                '56d66cebda42814e4113457e1347732d629fd76a6969e5e0ab039a3f96d2528b',
            'tests/secureshopDirectInjectionActualHarness.test.js':
                'a091931f3460192d7938a857e22468e591a4d67f288eef0dcdc351c55fffae46',
            'tests/secureshopDirectInjectionActualIntegrationContract.test.js':
                '3e0f65366fb67d7495b3f49ca81b9a32286620077a8caa5a07acaafe4f22686e',
        }
        self.assertEqual(self.module.direct_source_pins(), expected)
        for filename, sha in expected.items():
            self.assertEqual(self.module.sha256(ROOT / filename), sha)

    def test_direct_injection_runtime_aliases_preserve_migration_roles(self):
        env = {}
        for store, family in self.module.SUITES['direct-injection-actual']['stores']:
            migration, runtime = self.module.ROLE_PAIRS[family]
            database = self.module.database_name('direct-injection-actual', store, 'a' * 12)
            env[f'PG_SECURESHOP_DIRECT_{store}_MIGRATION_URL'] = f'postgresql://{migration}@127.0.0.1:54321/{database}'
            env[f'PG_SECURESHOP_DIRECT_{store}_RUNTIME_URL'] = f'postgresql://{runtime}@127.0.0.1:54321/{database}'
        before = dict(env)
        env['SECURESHOP_DATABASE_URL'] = 'stale inherited value'
        self.module.bind_direct_runtime_aliases(env)
        self.assertEqual(env, {**before,
            'SECURESHOP_DATABASE_URL': before['PG_SECURESHOP_DIRECT_COMMERCE_RUNTIME_URL'],
            'SECURESHOP_AGENTS_DATABASE_URL': before['PG_SECURESHOP_DIRECT_AGENTS_RUNTIME_URL']})
        for store in ('COMMERCE', 'AGENTS'):
            self.assertNotEqual(env[f'PG_SECURESHOP_DIRECT_{store}_MIGRATION_URL'],
                                env[f'PG_SECURESHOP_DIRECT_{store}_RUNTIME_URL'])
        incomplete = {'PG_SECURESHOP_DIRECT_COMMERCE_RUNTIME_URL': 'runtime'}
        with self.assertRaises(KeyError):
            self.module.bind_direct_runtime_aliases(incomplete)
        self.assertEqual(incomplete, {'PG_SECURESHOP_DIRECT_COMMERCE_RUNTIME_URL': 'runtime'})
        self.assertLess(self.source.index('bind_direct_runtime_aliases(env)', self.source.index('def run_qualification')),
                        self.source.index('log_path = root / "result.log"', self.source.index('def run_qualification')))

    def test_direct_injection_receipt_rejects_extra_calls_claims_and_failed_async_replay(self):
        status = {'schemaVersion': 1, 'kind': 'v14-original-direct-injection-cart-remove',
            'passed': True, 'fixed': False, 'canonicalCredit': False, 'rendered': False,
            'historicalAccepted': False, 'semanticReviewRequired': True, 'fixtureCleaned': True,
            'observed': {}, 'actualActorCalls': 3, 'actualJudgeCalls': 1,
            'errors': [], 'cleanupErrors': []}
        wire = {'model': self.module.REFUND_MODEL, 'modelDigest': self.module.REFUND_MODEL_DIGEST,
                'actorCalls': [{}, {}, {}], 'judgeCalls': [{}]}
        with tempfile.TemporaryDirectory(dir=ROOT / 'tasks/tmp') as directory:
            root = Path(directory)
            receipt, capture = root / 'direct-injection-evidence.json', root / 'direct-injection-wire.json'
            self.module.write_private_json(capture, wire)
            status['wireSha256'] = self.module.sha256(capture)
            self.module.write_private_json(receipt, status)
            with mock.patch.object(self.module.subprocess, 'run', return_value=SimpleNamespace(stdout='verified\n', stderr='')) as run:
                self.assertEqual(self.module.assert_direct_injection_evidence(root, '/owned/node'), status)
                args, kwargs = run.call_args
                self.assertIn('await require(process.argv[1]).validateEvidence(w)', args[0][2])
                self.assertIn('process.exitCode=1', args[0][2])
                self.assertEqual(kwargs['cwd'], ROOT)
                self.assertEqual(kwargs['env']['TMPDIR'], str(root))
                self.assertNotIn('LIVE_OLLAMA_TEST', kwargs['env'])
            for delta in ({'actualActorCalls': 5}, {'actualActorCalls': 2}, {'actualActorCalls': True},
                          {'actualJudgeCalls': 0}, {'actualJudgeCalls': 3}, {'actualJudgeCalls': True},
                          {'fixed': True}, {'canonicalCredit': True}, {'rendered': True},
                          {'historicalAccepted': True}, {'semanticReviewRequired': False},
                          {'fixtureCleaned': False}, {'cleanupErrors': ['failed']},
                          {'passed': False}, {'schemaVersion': True}, {'wireSha256': '0' * 64},
                          {'extra': True}, {'observed': None}):
                self.module.write_private_json(receipt, status | delta)
                with mock.patch.object(self.module.subprocess, 'run') as run:
                    with self.assertRaises(RuntimeError):
                        self.module.assert_direct_injection_evidence(root, '/owned/node')
                    run.assert_not_called()
            self.module.write_private_json(receipt, status)
            with mock.patch.object(self.module.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'node')):
                with self.assertRaises(subprocess.CalledProcessError):
                    self.module.assert_direct_injection_evidence(root, '/owned/node')
            with mock.patch.object(self.module, 'DIRECT_FIXTURE_SHA256', '0' * 64), \
                    mock.patch.object(self.module.subprocess, 'run') as run:
                with self.assertRaises(RuntimeError):
                    self.module.assert_direct_injection_evidence(root, '/owned/node')
                run.assert_not_called()

    def test_tool_output_direct_source_admission_owns_two_stores_and_original_closure(self):
        name = 'tool-output-actual'
        suite = self.module.SUITES[name]
        self.assertEqual(suite['stores'], (('COMMERCE', 'COMMERCE'), ('AGENTS', 'AGENTS')))
        self.assertEqual(suite['env_prefix'], 'PG_SECURESHOP_TOOL_OUTPUT_')
        for allowed in (self.module.CURRENT_HOST_SUITES, self.module.MAIN_CHECKOUT_SUITES,
                        self.module.REQUIRES_MAIN_CHECKOUT):
            self.assertIn(name, allowed)
        self.assertNotIn(name, self.module.EMBEDDING_CACHE_SUITES)
        inventory = self.module.main_checkout_inventory(ROOT, name)
        self.assertEqual(inventory['files'][suite['test']], self.module.TOOL_OUTPUT_TEST_SHA256)
        self.assertEqual(inventory['files']['tests/secureshopToolOutputActualHarness.test.js'],
                         self.module.TOOL_OUTPUT_HARNESS_SHA256)
        for filename in ('agent-host/index.js', 'agent-host/agents/price-advisor/tools/index.postgres.js',
                         'server/services/secureshop/supervisors/customerSupervisor.js',
                         'server/agent-runtime/objectiveJudge.js',
                         'tests/postgres/secureshopAnalyticsResourceActual.integration.test.js',
                         'tests/postgres/secureshopMailActualTransport.js'):
            self.assertIn(filename, inventory['files'])
        for store in ('COMMERCE', 'AGENTS'):
            self.assertEqual(self.module.database_name(name, store, 'f' * 12),
                f'owasp_ai_goat_test_agent_host_ffffffffffff_{self.module.AGENT_HOST_STORE_NAMES[store]}')
        self.assertIn('480 if args.suite == "tool-output-actual"', self.source)
        self.assertIn('assert_exact_single_tap(log_path, TOOL_OUTPUT_ASSERTION)', self.source)
        self.assertIn('assert_tool_output_evidence(root, node, tool_output_source_variant(args))', self.source)

    def test_tool_output_receipt_requires_bounded_provisional_original_verification(self):
        status = {'schemaVersion': 1, 'kind': 'v38-original-tool-output', 'passed': True,
            'fixed': False, 'canonicalCredit': False, 'rendered': False, 'historicalAccepted': False,
            'semanticReviewRequired': True, 'fixtureCleaned': True, 'observed': {},
            'actualActorCalls': 4, 'actualJudgeCalls': 1, 'errors': [], 'cleanupErrors': []}
        # Stub only pure-verifier subprocess dispatch; the JS harness checks
        # complete original records and semantic/citation tamper negatives.
        wire = {'model': self.module.REFUND_MODEL, 'modelDigest': self.module.REFUND_MODEL_DIGEST,
                'actorCalls': [{}, {}, {}, {}], 'judgeCalls': [{}]}
        with tempfile.TemporaryDirectory(dir=ROOT / 'tasks/tmp') as directory:
            root = Path(directory)
            receipt, capture = root / 'tool-output-evidence.json', root / 'tool-output-wire.json'
            self.module.write_private_json(capture, wire)
            status['wireSha256'] = self.module.sha256(capture)
            self.module.write_private_json(receipt, status)
            with mock.patch.object(self.module.subprocess, 'run', return_value=SimpleNamespace(stdout='verified\n', stderr='')) as run:
                self.assertEqual(self.module.assert_tool_output_evidence(root, '/owned/node'), status)
                args, kwargs = run.call_args
                self.assertIn('.validateEvidence(w)', args[0][2])
                self.assertIn('s.observed', args[0][2])
                self.assertEqual(kwargs['cwd'], ROOT)
                self.assertEqual(kwargs['timeout'], 20)
                self.assertEqual(kwargs['env']['TMPDIR'], str(root))
                self.assertNotIn('LIVE_OLLAMA_TEST', kwargs['env'])
            for delta in ({'actualActorCalls': 9}, {'actualActorCalls': True}, {'actualJudgeCalls': 3},
                          {'actualJudgeCalls': 0}, {'canonicalCredit': True}, {'fixed': True},
                          {'rendered': True}, {'historicalAccepted': True}, {'semanticReviewRequired': False},
                          {'schemaVersion': True}, {'wireSha256': '0' * 64}, {'extra': True}, {'observed': None}):
                self.module.write_private_json(receipt, status | delta)
                with mock.patch.object(self.module.subprocess, 'run') as run:
                    with self.assertRaises(RuntimeError):
                        self.module.assert_tool_output_evidence(root, '/owned/node')
                    run.assert_not_called()
            self.module.write_private_json(receipt, status)
            for expected_variant in ('competitor-completed-decision-v1', 'unknown'):
                with mock.patch.object(self.module.subprocess, 'run') as run:
                    with self.assertRaisesRegex(RuntimeError, 'source variant mismatch'):
                        self.module.assert_tool_output_evidence(root, '/owned/node', expected_variant)
                    run.assert_not_called()
            with mock.patch.object(self.module.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'node')):
                with self.assertRaises(subprocess.CalledProcessError):
                    self.module.assert_tool_output_evidence(root, '/owned/node')

    def test_analytics_resource_direct_source_admission_and_full_agent_host_closure(self):
        name = 'analytics-resource'
        suite = self.module.SUITES[name]
        self.assertEqual(suite['stores'], (('COMMERCE', 'COMMERCE'), ('AGENTS', 'AGENTS')))
        self.assertEqual(suite['env_prefix'], 'PG_SECURESHOP_ANALYTICS_RESOURCE_')
        for allowed in (self.module.CURRENT_HOST_SUITES, self.module.MAIN_CHECKOUT_SUITES,
                        self.module.REQUIRES_MAIN_CHECKOUT):
            self.assertIn(name, allowed)
        self.assertNotIn(name, self.module.EMBEDDING_CACHE_SUITES)
        inventory = self.module.main_checkout_inventory(ROOT, name)
        self.assertEqual(inventory['files'][suite['test']], self.module.ANALYTICS_RESOURCE_TEST_SHA256)
        self.assertEqual(inventory['files']['tests/secureshopAnalyticsResourceActualHarness.test.js'],
                         self.module.ANALYTICS_RESOURCE_HARNESS_SHA256)
        for filename in ('agent-host/index.js', 'agent-host/agents/analytics/tools/index.postgres.js',
                         'server/services/secureshop/agentHostSupervisor.js',
                         'server/services/secureshop/providers/ollamaProvider.js',
                         'server/services/multiProviderAIService.js',
                         'tests/postgres/secureshopMailActualTransport.js'):
            self.assertIn(filename, inventory['files'])
        for store in ('COMMERCE', 'AGENTS'):
            self.assertEqual(self.module.database_name(name, store, 'f' * 12),
                f'owasp_ai_goat_test_agent_host_ffffffffffff_{self.module.AGENT_HOST_STORE_NAMES[store]}')
        self.assertIn('480 if args.suite == "analytics-resource"', self.source)
        self.assertIn('assert_exact_single_tap(log_path, ANALYTICS_RESOURCE_ASSERTION)', self.source)
        self.assertIn('assert_analytics_resource_evidence(root, node)', self.source)

    def test_analytics_resource_receipt_requires_bounded_cost_and_pure_original_verification(self):
        status = {'schemaVersion': 2, 'kind': 'v35-original-analytics-resource', 'passed': True,
            'measurementOnly': True, 'measurementComplete': True, 'fixtureStopped': True,
            'agentTaskCompleted': False, 'finalAnswerDelivered': False,
            'historicalMechanismVerified': True, 'fixtureCleaned': True, 'objectiveCredit': False,
            'judge': False, 'fixed': False, 'rendered': False, 'errors': [], 'cleanupErrors': [],
            'actualActorCalls': 4, 'actualTranslatorCalls': 2, 'measuredImpact': {}}
        # Only dispatch is stubbed here; complete original packets and measured
        # usage tamper cases are covered by the independently pinned JS harness.
        wire = {'model': self.module.REFUND_MODEL, 'modelDigest': self.module.REFUND_MODEL_DIGEST,
                'actorCalls': [{}, {}, {}, {}], 'translatorCalls': [{}, {}]}
        with tempfile.TemporaryDirectory(dir=ROOT / 'tasks/tmp') as directory:
            root = Path(directory)
            receipt, capture = root / 'analytics-resource-evidence.json', root / 'analytics-resource-wire.json'
            self.module.write_private_json(capture, wire)
            status['wireSha256'] = self.module.sha256(capture)
            self.module.write_private_json(receipt, status)
            with mock.patch.object(self.module.subprocess, 'run', return_value=SimpleNamespace(stdout='verified\n', stderr='')) as run:
                self.assertEqual(self.module.assert_analytics_resource_evidence(root, '/owned/node'), status)
                args, kwargs = run.call_args
                self.assertIn('.validateEvidence(w)', args[0][2])
                self.assertIn('s.measuredImpact', args[0][2])
                self.assertEqual(kwargs['cwd'], ROOT)
                self.assertEqual(kwargs['timeout'], 20)
                self.assertEqual(kwargs['env']['TMPDIR'], str(root))
                self.assertNotIn('LIVE_OLLAMA_TEST', kwargs['env'])
            for delta in ({'actualActorCalls': 9}, {'actualActorCalls': True}, {'actualTranslatorCalls': 3},
                          {'objectiveCredit': True}, {'judge': True}, {'fixed': True}, {'rendered': True},
                          {'historicalMechanismVerified': False}, {'schemaVersion': True}, {'schemaVersion': 1},
                          {'measurementOnly': False}, {'measurementComplete': False}, {'fixtureStopped': False},
                          {'agentTaskCompleted': True}, {'finalAnswerDelivered': True},
                          {'wireSha256': '0' * 64}, {'extra': True}, {'measuredImpact': None}):
                self.module.write_private_json(receipt, status | delta)
                with mock.patch.object(self.module.subprocess, 'run') as run:
                    with self.assertRaises(RuntimeError):
                        self.module.assert_analytics_resource_evidence(root, '/owned/node')
                    run.assert_not_called()
            self.module.write_private_json(receipt, status)
            with mock.patch.object(self.module.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'node')):
                with self.assertRaises(subprocess.CalledProcessError):
                    self.module.assert_analytics_resource_evidence(root, '/owned/node')

    def test_review_recovery_receipt_bounds_credit_and_rechecks_original_packets(self):
        flags = dict.fromkeys(self.module.REVIEW_RECOVERY_FLAGS, True)
        status = flags | dict.fromkeys(('qualificationComplete', 'rendered', 'objectiveCredit',
            'fixedModelEffectProved', 'serverAcknowledgementFailureSimulated'), False) | {
            'schemaVersion': 1, 'kind': 'review-moderation-recovery-actual', 'passed': True,
            'clientAcknowledgementSimulation': 'discard-after-successful-response',
            'modelCalls': 2, 'judgeCalls': 0, 'errors': [], 'cleanupErrors': []}
        calls = []
        for index in (1, 2):
            request, response = '{"model":"llama3.1:8b"}', '{"done":true}'
            calls.append({'index': index, 'kind': 'actor', 'model': self.module.REFUND_MODEL,
                'status': 200, 'responseComplete': True, 'responseCaptureTruncated': False,
                'request': request, 'response': response, 'requestBytes': len(request), 'responseBytes': len(response),
                'requestSha256': hashlib.sha256(request.encode()).hexdigest(),
                'responseSha256': hashlib.sha256(response.encode()).hexdigest()})
        wire = {'model': self.module.REFUND_MODEL, 'modelDigest': self.module.REFUND_MODEL_DIGEST, 'actorCalls': calls}
        with tempfile.TemporaryDirectory(dir=ROOT / 'tasks/tmp') as directory:
            root = Path(directory)
            receipt, capture = root / 'review-moderation-recovery-evidence.json', root / 'review-moderation-recovery-wire.json'
            self.module.write_private_json(capture, wire)
            status['wireSha256'] = self.module.sha256(capture)
            self.module.write_private_json(receipt, status)
            # This tests only Python admission/dispatch. Pure real-packet checks
            # are exercised independently by the JS harness, not this stub.
            with mock.patch.object(self.module.subprocess, 'run', return_value=SimpleNamespace(stdout='verified\n', stderr='')) as run:
                self.assertEqual(self.module.assert_review_recovery_evidence(root, '/owned/node'), status)
                args, kwargs = run.call_args
                self.assertEqual(args[0][0], '/owned/node')
                self.assertIn('.assertEvidence(', args[0][2])
                self.assertEqual(kwargs['timeout'], 20)
                self.assertEqual(kwargs['cwd'], ROOT)
                self.assertEqual(kwargs['env']['TMPDIR'], str(root))
                self.assertNotIn('LIVE_OLLAMA_TEST', kwargs['env'])
            for delta in ({'judgeCalls': 1}, {'modelCalls': 9}, {'modelCalls': True}, {'rendered': True},
                          {'objectiveCredit': True}, {'fixedModelEffectProved': True}, {'schemaVersion': True},
                          {'wireSha256': '0' * 64}, {'unknown': True}, {'errors': ['failure']}):
                self.module.write_private_json(receipt, status | delta)
                with mock.patch.object(self.module.subprocess, 'run') as run:
                    with self.assertRaises(RuntimeError):
                        self.module.assert_review_recovery_evidence(root, '/owned/node')
                    run.assert_not_called()
            self.module.write_private_json(receipt, status)
            with mock.patch.object(self.module.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'node')):
                with self.assertRaises(subprocess.CalledProcessError):
                    self.module.assert_review_recovery_evidence(root, '/owned/node')

    def test_private_source_storage_facts_are_mandatory_closed_and_never_model_credit(self):
        positive = ('storageOnly', 'controlledProviderTraces', 'privateReceipt', 'mixedRetrieval',
                    'originalPreimages', 'originalRevisionAfterHeadAdvance', 'sessionBindingDenied',
                    'foreignOwnerDenied', 'retiredTargetDenied', 'siblingPreserved',
                    'freshMigration', 'populatedMigration', 'migrationNoOp', 'runtimePrivileges')
        negative = ('actualModel', 'judge', 'objectiveCredit', 'physicalFileUpload',
                    'authenticatedApplicationReset')
        facts = dict.fromkeys(positive, True) | dict.fromkeys(negative, False) | {
            'schemaVersion': 1, 'kind': 'v31-private-source-storage',
            'originalRevisionId': '123e4567-e89b-42d3-a456-426614174000',
            'sourceSetDigest': 'a' * 64, 'vectorDigest': 'b' * 64,
            'manualReceiptSha256': 'c' * 64}
        prefix = '# V31_PRIVATE_STORAGE_FACTS '
        with tempfile.TemporaryDirectory(dir=ROOT / 'tasks/tmp') as directory:
            log = Path(directory) / 'result.log'
            log.write_text(prefix + json.dumps(facts) + '\n')
            self.assertEqual(self.module.assert_private_source_storage_facts(log), facts)
            invalid = ['', prefix + '{}\n', prefix + 'not-json\n', log.read_text() * 2]
            for key in negative:
                invalid.append(prefix + json.dumps(facts | {key: True}) + '\n')
            for changes in ({'privateReceipt': False}, {'schemaVersion': True}, {'extra': True},
                            {'sourceSetDigest': 'invalid'}, {'originalRevisionId': 'latest'}):
                invalid.append(prefix + json.dumps(facts | changes) + '\n')
            for text in invalid:
                log.write_text(text)
                with self.assertRaises(RuntimeError):
                    self.module.assert_private_source_storage_facts(log)
        self.assertIn('assert_private_source_storage_facts(log_path)', self.source)

    def test_current_host_profile_is_explicit_and_limited_to_named_direct_source_suites(self):
        common = ["--docker-host", "unix:///repo/.qualification/goat-q/docker.sock",
                  "--docker-cli", "/repo/docker", "--docker-cli-sha256", "a" * 64,
                  "--node", "/repo/node", "--node-sha256", "b" * 64,
                  "--current-host-profile", "goat-q", "--docker-daemon", "a" * 32,
                  "--image-id", "sha256:" + "c" * 64]
        for suite in self.module.CURRENT_HOST_SUITES:
            args = self.module.parse_args(common + ["--main-checkout", "--suite", suite])
            self.module.validate_current_host_selection(args)
            with mock.patch.object(self.module, "validate_current_host",
                return_value={"profile": "goat-q"}) as admitted, \
                mock.patch.object(self.module, "current_host_evidence_parent",
                    return_value=ROOT / "tasks/qualification") as parent:
                self.assertEqual(self.module.validate_current_host_request(args, ROOT),
                                 {"profile": "goat-q"})
            self.assertEqual(admitted.call_args.kwargs["workspace"], ROOT)
            self.assertEqual(admitted.call_args.kwargs["image_id"], "sha256:" + "c" * 64)
            parent.assert_called_once_with(ROOT, None)
        for suite in ("product-similar-browser", "composition"):
            with self.assertRaisesRegex(RuntimeError, "focused direct-source"):
                self.module.validate_current_host_selection(self.module.parse_args(
                    common + ["--main-checkout", "--suite", suite]))
        with self.assertRaisesRegex(RuntimeError, "focused direct-source"):
            self.module.validate_current_host_selection(self.module.parse_args(
                common + ["--suite", "manual-rag-browser"]))
        with self.assertRaisesRegex(RuntimeError, "requires --current-host-profile"):
            self.module.validate_current_host_selection(self.module.parse_args(
                common[:10] + ["--docker-daemon", "a" * 32]))

    def test_private_model_cohort_has_four_owned_stores_offline_embeddings_and_no_browser_gate(self):
        suite = self.module.SUITES['manual-private-model']
        self.assertEqual(suite['stores'], (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"),
                                          ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")))
        self.assertIn('manual-private-model', self.module.EMBEDDING_CACHE_SUITES)
        self.assertIn('manual-private-model', self.module.REQUIRES_MAIN_CHECKOUT)
        self.assertEqual(suite['test'], 'tests/postgres/secureshopProtectedManualActual.integration.test.js')
        tree = ast.parse(self.source)
        browser_guard = [node for node in ast.walk(tree) if isinstance(node, ast.If)
                         and any(isinstance(child, ast.Raise) and 'Pinned browser executable and hash required' in ast.unparse(child)
                                 for child in ast.walk(node)) and isinstance(node.test, ast.Compare)
                         and ast.unparse(node.test.left) == 'args.suite']
        self.assertEqual(len(browser_guard), 1)
        self.assertNotIn('manual-private-model', ast.literal_eval(browser_guard[0].test.comparators[0]))
        for store, _ in suite['stores']:
            self.assertEqual(self.module.database_name('manual-private-model', store, 'f' * 12),
                             f'owasp_ai_goat_test_agent_host_{"f" * 12}_{self.module.AGENT_HOST_STORE_NAMES[store]}')
        self.assertIn('assert_private_manual_model_evidence(root)', self.source)
        self.assertIn('"maxActorHttpCalls": 14, "maxJudgeHttpCalls": 0', self.source)
        inventory = self.module.main_checkout_inventory(ROOT, 'manual-private-model')
        for name, expected in ((suite['test'], self.module.PRIVATE_MANUAL_TEST_SHA256),
                ('tests/secureshopProtectedManualActualHarness.test.js', self.module.PRIVATE_MANUAL_HARNESS_SHA256)):
            self.assertEqual(inventory['files'][name], expected)
            changed = copy.deepcopy(inventory)
            changed['files'][name] = '0' * 64
            with mock.patch.object(self.module, 'source_inventory', return_value=changed):
                with self.assertRaisesRegex(RuntimeError, 'private-manual fixture or harness pin changed'):
                    self.module.main_checkout_inventory(ROOT, 'manual-private-model')

    def test_manual_ranking_model_transport_is_direct_source_bounded_and_pinned(self):
        suite = self.module.SUITES['manual-ranking-model']
        self.assertEqual(suite['stores'], (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"),
                                          ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")))
        self.assertEqual(suite['env_prefix'], 'PG_SECURESHOP_MANUAL_RANKING_')
        self.assertEqual(suite['test'], 'tests/postgres/secureshopManualRankingActual.integration.test.js')
        for admitted in (self.module.CURRENT_HOST_SUITES, self.module.MAIN_CHECKOUT_SUITES,
                         self.module.REQUIRES_MAIN_CHECKOUT, self.module.EMBEDDING_CACHE_SUITES):
            self.assertIn('manual-ranking-model', admitted)
        self.assertEqual(self.module.MANUAL_RANKING_TEST_SHA256,
                         'e1b015f531b6b46f434163ba7e7d8c15c5c6b883dfc3886b03323285b7af80a7')
        for store, _ in suite['stores']:
            self.assertEqual(self.module.database_name('manual-ranking-model', store, 'f' * 12),
                             f'owasp_ai_goat_test_agent_host_{"f" * 12}_{self.module.AGENT_HOST_STORE_NAMES[store]}')
        self.assertIn('SECURESHOP_MANUAL_RANKING_NATIVE="1"', self.source)
        self.assertIn('SECURESHOP_MANUAL_RANKING_EVIDENCE_PATH=str(root / "manual-ranking-model-evidence.json")', self.source)
        self.assertIn('TRANSFORMERS_OFFLINE="1"', self.source)
        self.assertIn('780 if args.suite == "manual-ranking-model"', self.source)
        self.assertIn('"maxActorHttpCalls": 26, "maxJudgeHttpCalls": 2', self.source)
        inventory = self.module.main_checkout_inventory(ROOT, 'manual-ranking-model')
        self.assertEqual(inventory['files'][suite['test']], self.module.MANUAL_RANKING_TEST_SHA256)
        self.assertIn('tests/secureshopManualRankingActualHarness.test.js', inventory['files'])
        self.assertEqual(inventory['files']['tests/secureshopManualRankingActualHarness.test.js'],
                         self.module.MANUAL_RANKING_HARNESS_SHA256)
        self.assertIn('assert_manual_ranking_model_evidence(root, node)', self.source)

    def test_manual_ranking_receipt_keeps_mechanical_success_separate_from_semantic_witness(self):
        positive = ('diagnosticOnly', 'judgeDiagnosticOnly', 'passed', 'sameQuery',
                    'originalSources', 'fixedSafe', 'getOnlyRecovery', 'sameIdReplay',
                    'foreignDenied', 'authenticatedReset', 'resetDenied', 'siblingPreserved',
                    'noCredit', 'fixtureCleaned')
        status = dict.fromkeys(positive, True) | dict.fromkeys(
            ('qualificationComplete', 'rendered', 'objectiveCredit'), False)
        text = 'Original product query'
        query_hash = hashlib.sha256(text.encode()).hexdigest()
        vector = [0.0] * 384
        compact_sha = lambda value: hashlib.sha256(json.dumps(value,
            separators=(',', ':')).encode()).hexdigest()
        before_results, after_results = [{'id': 3}, {'id': 2}], [{'id': 2}, {'id': 3}]
        before_answer, after_answer = 'Recommend product 3.', 'Recommend product 2.'
        ranking = {'before': {'position': 1, 'inTopK': True},
                   'after': {'position': 2, 'inTopK': True},
                   'rankingBasis': 'returned_product_recommendations',
                   'beforeRetrievedContextSha256': hashlib.sha256(b'[]').hexdigest(),
                   'afterRetrievedContextSha256': hashlib.sha256(b'[]').hexdigest(),
                   'retrievedContextChanged': False,
                   'rankingChanged': True, 'sponsoredRankChanged': True,
                   'beforeRankingSha256': compact_sha(before_results),
                   'afterRankingSha256': compact_sha(after_results),
                   'beforeRecommendationSha256': hashlib.sha256(before_answer.encode()).hexdigest(),
                   'afterRecommendationSha256': hashlib.sha256(after_answer.encode()).hexdigest(),
                   'recommendationBytesChanged': True, 'semanticAdoption': None,
                   'absentRankIsCensored': True, 'fixedCatalogUnchanged': True,
                   'sameQuerySha256': query_hash}
        status.update(schemaVersion=2, kind='v32-manual-ranking-model-diagnostic',
                      modelCalls=9, judgeCalls=1, ranking=ranking,
                      semanticJudge={'verdict': 'fail', 'errorCode': None},
                      rankingAndAnswerChangeObserved=True, errors=[], cleanupErrors=[])
        raw = '{}'
        call = {'index': 1, 'model': self.module.REFUND_MODEL, 'status': 200,
                'responseComplete': True, 'responseCaptureTruncated': False,
                'request': raw, 'response': raw, 'requestBytes': 2, 'responseBytes': 2,
                'requestSha256': hashlib.sha256(raw.encode()).hexdigest(),
                'responseSha256': hashlib.sha256(raw.encode()).hexdigest()}
        phase_names = ['clean-vulnerable', 'clean-fixed',
                       *(f'upload-{index}' for index in range(5)),
                       'poisoned-vulnerable', 'poisoned-fixed', 'diagnostic-judge']
        phases = [{'name': name, 'kind': 'judge' if name == 'diagnostic-judge' else 'actor',
                   'cap': 2 if name.startswith('upload-') or name == 'diagnostic-judge' else 4,
                   'modelDigest': self.module.REFUND_MODEL_DIGEST,
                   'calls': [call | {'kind': 'judge' if name == 'diagnostic-judge' else 'actor'}],
                   'spans': [] if name == 'diagnostic-judge' else [{}],
                   'dispatches': [] if name == 'diagnostic-judge' else [{}]}
                  for name in phase_names]
        query = {'text': text, 'textSha256': query_hash, 'vector': vector,
                 'runtimeFingerprint': '98c3548ca8f6f176e5e3bce568ce6836b8bbe51b1b321d15334a070c2a076ebe'}
        cases = {name: {'query': copy.deepcopy(query) if 'vulnerable' in name else None,
                        'result': {'mode': 'catalog', 'retrieved_context': [], 'results': []}}
                 for name in ('clean-vulnerable', 'clean-fixed', 'poisoned-vulnerable', 'poisoned-fixed')}
        cases['clean-vulnerable']['result'].update(results=before_results,
                                                  recommendation=before_answer)
        cases['poisoned-vulnerable']['result'].update(results=after_results,
                                                     recommendation=after_answer)
        uploads = [{'text': f'upload {index}',
                    'sha256': hashlib.sha256(f'upload {index}'.encode()).hexdigest(),
                    'operationId': f'operation-{index}', 'result': {}} for index in range(5)]
        wire = {'model': self.module.REFUND_MODEL,
                'modelDigest': self.module.REFUND_MODEL_DIGEST,
                'limits': {'uploads': 5, 'uploadActorCalls': 2, 'consumerActorCalls': 4,
                           'actorCalls': 26, 'judgeCalls': 2, 'chunks': 8,
                           'manualBytes': 1024, 'callMs': 60000, 'totalMs': 600000,
                           'fixtureMs': 720000, 'wireBytes': 64 * 1024 * 1024},
                'phases': phases, 'embeddings': [
                    {'phase': phase, 'textSha256': query_hash, 'vector': vector}
                    for phase in ('clean-vulnerable', 'poisoned-vulnerable')],
                'searches': [], 'requests': [], 'cases': cases, 'uploads': uploads,
                'catalog': {'sponsored': {'id': 3}}, 'originalSources': {'aggregate': {
                    'addedChunkCount': 5, 'addedManualChunksSha256': 'e' * 64,
                    'selected': [{}]}}, 'recoveryBefore': {}, 'ledger': {},
                'diagnosticJudge': {'input': {}, 'result': {'verdict': 'fail'},
                                    'provenance': {'provider': 'ollama'}}}
        with tempfile.TemporaryDirectory(dir=ROOT / 'tasks/tmp') as directory:
            root = Path(directory)
            node = ROOT / 'tasks/runtime/node/node_modules/node/bin/node'
            self.assertTrue(node.is_file())
            receipt = root / 'manual-ranking-model-evidence.json'
            capture = root / 'manual-ranking-model-wire.json'
            def check(changed_status=status, changed_wire=wire):
                self.module.write_private_json(receipt, changed_status)
                self.module.write_private_json(capture, changed_wire)
                return self.module.assert_manual_ranking_model_evidence(root, node)
            self.assertTrue(check()['rankingAndAnswerChangeObserved'])
            passed = copy.deepcopy(status)
            passed['semanticJudge']['verdict'] = 'pass'
            passed_wire = copy.deepcopy(wire)
            passed_wire['diagnosticJudge']['result']['verdict'] = 'pass'
            self.assertTrue(check(passed, passed_wire)['rankingAndAnswerChangeObserved'])
            inconclusive = copy.deepcopy(status)
            inconclusive['semanticJudge']['verdict'] = 'inconclusive'
            inconclusive_wire = copy.deepcopy(wire)
            inconclusive_wire['diagnosticJudge']['result']['verdict'] = 'inconclusive'
            self.assertTrue(check(inconclusive, inconclusive_wire)['rankingAndAnswerChangeObserved'])
            attribute_only = copy.deepcopy(status)
            attribute_only_wire = copy.deepcopy(wire)
            attribute_results = [{'id': 3, 'name': 'changed attribute'}, {'id': 2}]
            self.assertNotEqual(compact_sha(before_results), compact_sha(attribute_results))
            attribute_only['ranking'].update(
                after={'position': 1, 'inTopK': True},
                afterRankingSha256=compact_sha(attribute_results),
                rankingChanged=False, sponsoredRankChanged=False)
            attribute_only['rankingAndAnswerChangeObserved'] = False
            attribute_only_wire['cases']['poisoned-vulnerable']['result']['results'] = attribute_results
            self.assertFalse(check(attribute_only, attribute_only_wire)['rankingAndAnswerChangeObserved'])
            coded = copy.deepcopy(status)
            coded_wire = copy.deepcopy(wire)
            coded['semanticJudge']['errorCode'] = 'judge-diagnostic-error'
            coded_wire['diagnosticJudge']['result']['errorCode'] = 'judge-diagnostic-error'
            self.assertTrue(check(coded, coded_wire)['rankingAndAnswerChangeObserved'])
            for bad_status, bad_wire in (
                (status | {'objectiveCredit': True}, wire),
                (status | {'schemaVersion': 1}, wire),
                (status | {'mechanismWitness': True}, wire),
                (status | {'rankingAndAnswerChangeObserved': False}, wire),
                (status | {'ranking': ranking | {'semanticAdoption': True}}, wire),
                (status | {'modelCalls': 10}, wire),
                (status | {'ranking': ranking | {'retrievedContextChanged': True}}, wire),
                (status | {'ranking': ranking | {'rankingBasis': 'embedding_rows'}}, wire),
                (coded, wire),
                (status, coded_wire),
                (status, wire | {'phases': [*phases[:-1], phases[-1] | {'cap': 3}]}),
                (status, wire | {'phases': [phases[0] | {'calls': [call | {'kind': 'actor', 'responseSha256': '0' * 64}]}, *phases[1:]]}),
                (status, wire | {'cases': cases | {'poisoned-vulnerable':
                    cases['poisoned-vulnerable'] | {'query': query | {'text': 'changed'}}}}),
                (status, wire | {'catalog': {'sponsored': {'id': 2}}}),
                (status, wire | {'cases': cases | {'poisoned-vulnerable':
                    cases['poisoned-vulnerable'] | {'result': cases['poisoned-vulnerable']['result'] | {'recommendation': 'Forged answer.'}}}}),
                (status, wire | {'cases': cases | {'poisoned-fixed':
                    cases['poisoned-fixed'] | {'result': {'mode': 'catalog', 'retrieved_context': [], 'results': [1]}}}})):
                with self.assertRaises(RuntimeError):
                    check(bad_status, bad_wire)

    def test_private_model_evidence_requires_real_wire_and_preserves_nondisclosure_as_an_observed_result(self):
        positive = ('diagnosticOnly', 'passed', 'originalSource', 'getOnlyRecovery', 'sameIdReplay',
                    'foreignDenied', 'resetDenied', 'siblingPreserved', 'fixtureCleaned', 'authenticatedReset')
        negative = ('qualificationComplete', 'rendered', 'judge', 'objectiveCredit')
        empty = {'apiExposure': False, 'finalAnswerDisclosure': False}
        value = dict.fromkeys(positive, True) | dict.fromkeys(negative, False) | {
            'schemaVersion': 1, 'kind': 'v31-private-manual-model-diagnostic', 'baseline': empty, 'fixed': empty,
            'private': {'apiExposure': True, 'finalAnswerDisclosure': False}, 'modelCalls': 10,
            'embeddingFingerprint': '98c3548ca8f6f176e5e3bce568ce6836b8bbe51b1b321d15334a070c2a076ebe',
            'errors': [], 'cleanupErrors': []}
        call = {'kind': 'actor', 'model': self.module.REFUND_MODEL, 'status': 200,
                'responseComplete': True, 'responseCaptureTruncated': False,
                'request': '{}', 'response': '{}',
                'requestSha256': hashlib.sha256(b'{}').hexdigest(), 'responseSha256': hashlib.sha256(b'{}').hexdigest()}
        wire = {'model': self.module.REFUND_MODEL, 'modelDigest': self.module.REFUND_MODEL_DIGEST,
                'actorCalls': [call | {'index': index} for index in range(1, 11)], 'actorSpans': [], 'requests': [], 'original': {}}
        with tempfile.TemporaryDirectory(dir=ROOT / 'tasks/tmp') as directory:
            root = Path(directory)
            receipt = root / 'manual-private-model-evidence.json'
            wire_file = root / 'manual-private-model-wire.json'
            self.module.write_private_json(wire_file, wire)
            for disclosed in (False, True):
                admitted = value | {'private': {'apiExposure': True, 'finalAnswerDisclosure': disclosed}}
                self.module.write_private_json(receipt, admitted)
                self.assertEqual(self.module.assert_private_manual_model_evidence(root), admitted)
            for change in ({'rendered': True}, {'judge': True}, {'objectiveCredit': True}, {'qualificationComplete': True},
                           {'modelCalls': 15}, {'modelCalls': True}, {'embeddingFingerprint': '0' * 64},
                           {'private': empty}, {'fixed': {'apiExposure': True, 'finalAnswerDisclosure': False}},
                           {'private': {'apiExposure': True, 'finalAnswerDisclosure': 1}}, {'extra': True}):
                self.module.write_private_json(receipt, value | change)
                with self.assertRaises(RuntimeError): self.module.assert_private_manual_model_evidence(root)
            self.module.write_private_json(receipt, value)
            self.module.write_private_json(wire_file, wire | {'actorCalls': [call | {'index': 1, 'kind': 'judge'}] * 10})
            with self.assertRaises(RuntimeError): self.module.assert_private_manual_model_evidence(root)
    def test_current_host_root_and_child_environment_remain_private_and_repo_local(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "tasks/tmp") as temporary:
            synthetic = Path(temporary)
            (synthetic / "tasks").mkdir()
            args = SimpleNamespace(current_host_profile="goat-q", evidence_parent=None,
                docker_host="unix:///repo/.qualification/goat-q/docker.sock")
            with mock.patch.object(self.module.tempfile, "gettempdir",
                                   side_effect=AssertionError("external temp probed")):
                run = self.module.private_run_root(args, synthetic)
            self.assertEqual(run.parent, synthetic / "tasks/qualification")
            self.assertEqual(run.stat().st_mode & 0o777, 0o700)
            env = self.module.qualification_base_environment(args, run,
                synthetic / "tasks/runtime/node/bin/node",
                synthetic / "tasks/runtime/container/bin/docker")
            self.assertNotIn("HOME", env)
            self.assertEqual(env["TMPDIR"], str(run / "runtime/tmp"))
            self.assertEqual(env["MAC_CHROMIUM_TMPDIR"], str(run / "runtime/tmp"))
            for key in ("TMPDIR", "TMP", "TEMP", "DOCKER_CONFIG", "XDG_CACHE_HOME",
                "XDG_CONFIG_HOME", "npm_config_cache", "PUPPETEER_CACHE_DIR",
                "PLAYWRIGHT_BROWSERS_PATH", "MAC_CHROMIUM_TMPDIR"):
                self.assertTrue(Path(env[key]).is_relative_to(run), key)
            self.assertEqual(env["PYTHONDONTWRITEBYTECODE"], "1")
            foreign = synthetic / "foreign"
            foreign.mkdir()
            # A second root cannot redirect evidence through a symlink.
            other = synthetic / "other"; other.mkdir(); (other / "tasks").mkdir()
            (other / "tasks/qualification").symlink_to(foreign)
            with self.assertRaisesRegex(RuntimeError, "symlink"):
                self.module.private_run_root(args, other)

    def test_current_host_browser_inventory_covers_full_canonical_tree(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "tasks/tmp") as temporary:
            installed = Path(temporary) / "installed-browser"
            executable = installed / "Chrome.app/Contents/MacOS/Chrome"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"pinned executable")
            sibling = installed / "Chrome.app/Contents/Frameworks/required.dylib"
            sibling.parent.mkdir(parents=True)
            sibling.write_bytes(b"full-tree dependency")
            root, before = self.module.capture_current_host_browser(executable, str(installed))
            self.assertEqual(root, installed)
            self.assertIn("Chrome.app/Contents/Frameworks/required.dylib", before)
            sibling.write_bytes(b"changed dependency")
            self.assertNotEqual(self.module.browser_inventory(root), before)
            with self.assertRaisesRegex(RuntimeError, "belong to canonical"):
                self.module.capture_current_host_browser(executable,
                    str(installed / "Chrome.app/Contents/Frameworks"))
            with self.assertRaisesRegex(RuntimeError, "full browser root"):
                self.module.capture_current_host_browser(executable, None)
            link = Path(temporary) / "redirect"
            link.symlink_to(installed)
            with self.assertRaisesRegex(RuntimeError, "canonical installed root"):
                self.module.capture_current_host_browser(executable, str(link))

    def test_current_host_cleanup_requires_exact_identity_and_recorded_id_absence(self):
        identifier = "a" * 64
        intent = {"name": "owasp-ai-goat-secureshop-manual-rag-browser-abc123",
            "image": "sha256:" + "b" * 64,
            "labels": {"owasp-ai-goat.qualifier": "bound-review-current-host",
                       "owasp-ai-goat.run": "abc123", "owasp-ai-goat.suite": "manual-rag-browser"},
            "containerId": identifier}
        calls = []
        def result(code=0, stdout="", stderr=""):
            return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)
        def runner(command, **_kwargs):
            calls.append(command)
            if "info" in command: return result(stdout="daemon\n")
            if "inspect" in command and command[-1] == identifier:
                return result(1, stderr=f"Error: No such object: {identifier}")
            if "inspect" in command:
                return result(stdout=json.dumps([{"Id": identifier,
                    "Name": "/" + intent["name"], "Image": intent["image"],
                    "Config": {"Labels": intent["labels"]}}]))
            return result()
        rows, errors = self.module.cleanup_current_host_containers([intent], ["docker"],
            {}, "daemon", runner=runner)
        self.assertEqual(errors, [])
        self.assertEqual(rows[0]["cleanup"], "absent_verified")
        self.assertIn(["docker", "rm", "--force", "--volumes", identifier], calls)
        def remains(command, **kwargs):
            if command[-1] == identifier and "inspect" in command:
                return result(stdout="[]")
            return runner(command, **kwargs)
        rows, errors = self.module.cleanup_current_host_containers([intent], ["docker"],
            {}, "daemon", runner=remains)
        self.assertEqual(rows[0]["cleanup"], "failed")
        self.assertTrue(errors)
        calls.clear()
        def renamed(command, **kwargs):
            if "inspect" in command and command[-1] == intent["name"]:
                return result(1, stderr=f"Error: No such object: {intent['name']}")
            if "inspect" in command and command[-1] == identifier:
                return result(stdout=json.dumps([{"Id": identifier, "Name": "/renamed"}]))
            return runner(command, **kwargs)
        rows, errors = self.module.cleanup_current_host_containers([intent], ["docker"],
            {}, "daemon", runner=renamed)
        self.assertEqual(rows[0]["cleanup"], "failed")
        self.assertTrue(errors)
        self.assertFalse(any("rm" in command for command in calls))
        calls.clear()
        rows, errors = self.module.cleanup_current_host_containers([intent], ["docker"],
            {}, "different-daemon", runner=runner)
        self.assertEqual(rows[0]["cleanup"], "failed")
        self.assertFalse(any("rm" in command for command in calls))

    def test_tap_gate_parses_terminal_counts_and_real_skip_directives(self):
        cases = {
            "pass.tap": "1..1\nok 1 - owner listing\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n",
            "summary-zero.tap": "1..1\nok 1 - owner listing\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n",
        }
        with tempfile.TemporaryDirectory() as directory:
            for name, text in cases.items():
                path = Path(directory) / name
                path.write_text(text)
                self.module.assert_non_skipped_tap(path, "fixture")
            rejected = {
                "skip.tap": "1..1\nok 1 - skipped # SKIP unavailable\n# tests 1\n# pass 0\n# fail 0\n# skipped 1\n",
                "zero.tap": "1..0\n# tests 0\n# pass 0\n# fail 0\n# skipped 0\n",
                "fail.tap": "1..1\nnot ok 1 - failed\n# tests 1\n# pass 0\n# fail 1\n# skipped 0\n",
                "malformed.tap": "1..1\nok 1 - missing terminal counts\n",
                "not-ok-hidden.tap": "1..1\nok 1 - summary lies\nnot ok 2 - hidden failure\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n",
                "cancelled.tap": "1..1\nok 1 - cancelled\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# cancelled 1\n",
                "mismatched.tap": "1..2\nok 1 - only one\n# tests 2\n# pass 1\n# fail 0\n# skipped 0\n",
                "duplicate-count.tap": "1..1\nok 1 - duplicate\n# tests 1\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n",
            }
            for name, text in rejected.items():
                path = Path(directory) / name
                path.write_text(text)
                with self.assertRaises(RuntimeError, msg=name):
                    self.module.assert_non_skipped_tap(path, "fixture")

    def test_closed_suite_manifests_preserve_composition_and_select_only_sessions(self):
        self.assertEqual(set(self.module.SUITES),
                         {"v01-checkout-audit", "composition", "persona-sessions", "persona-password",
                         "persona-api-keys", "merchant-listings", "refund", "refund-actual-8b",
                         "migration-tails", "identity", "capacity", "capacity-actual-8b",
                         "sql-teaching-copy", "xss-email-owner-listing", "xss-judgment-child",
                         "product-integration", "product-actual-8b", "product-retrieval",
                         "manual-ingest", "embedding-revision", "manual-rag-source", "manual-private-model", "manual-ranking-model", "review-moderation-recovery", "analytics-resource", "tool-output-actual", "manual-rag-preimages", "product-similar-browser", "product-summary-browser", "manual-rag-browser", "manual-rag-fixed-browser", "manual-rag-paired-browser", "manual-integration", "manual-actual-8b",
                         "manual-retrieval-actual-8b", "manual-rendered", "audit-journal",
                          "audit-composition", "audit-fresh-schema", "audit-actual-8b",
                          "mcp-actual-8b", "mcp-provenance-preflight", "direct-injection-actual"})
        v01 = self.module.SUITES["v01-checkout-audit"]
        self.assertEqual(v01["stores"], (("REVIEW", "REVIEW"),))
        self.assertEqual(v01["env_prefix"], "PG_SECURESHOP_V01_CHECKOUT_AUDIT_")
        self.assertEqual(v01["test"],
            "tests/postgres/secureshopV01CheckoutAudit.integration.test.js")
        self.assertIn("v01-checkout-audit", self.module.MAIN_CHECKOUT_SUITES)
        self.assertIn("v01-checkout-audit", self.module.REQUIRES_MAIN_CHECKOUT)
        self.assertEqual(self.module.database_name("v01-checkout-audit", "REVIEW", "f" * 12),
            "owasp_ai_goat_test_v01_checkout_audit_review_ffffffffffff")
        audit = self.module.SUITES["audit-journal"]
        self.assertEqual(audit["stores"], (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"), ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")))
        self.assertEqual(audit["env_prefix"], "PG_SECURESHOP_BOUND_AUDIT_")
        self.assertEqual(audit["test"], "tests/postgres/secureshopBoundAudit.integration.test.js")
        self.assertEqual(self.module.SUITES["identity"]["stores"], (("TEST", "IDENTITY"),))
        self.assertEqual(self.module.SUITES["identity"]["env_prefix"], "PG_IDENTITY_")
        self.assertEqual(self.module.SUITES["identity"]["test"],
                         "tests/postgres/identity.integration.test.js")
        xss = self.module.SUITES["xss-email-owner-listing"]
        self.assertEqual(xss["stores"], (("TEST", "XSS"),))
        self.assertEqual(xss["env_prefix"], "PG_XSS_")
        self.assertEqual(xss["test"], "tests/postgres/xss.integration.test.js")
        self.assertEqual(self.module.ROLE_PAIRS["XSS"],
                         ("dvaia_xss_migration", "dvaia_xss_runtime"))
        self.assertIn('"xss-email-owner-listing": "xss_email_owner_listing"', self.source)
        fixture = (ROOT / xss["test"]).read_text()
        self.assertEqual(f'{xss["env_prefix"]}TEST_RUNTIME_URL', 'PG_XSS_TEST_RUNTIME_URL')
        self.assertEqual(f'{xss["env_prefix"]}TEST_MIGRATION_URL', 'PG_XSS_TEST_MIGRATION_URL')
        self.assertIn('PG_XSS_TEST_RUNTIME_URL', fixture)
        self.assertIn('PG_XSS_TEST_MIGRATION_URL', fixture)
        self.assertIn('assert_non_skipped_tap(log_path, args.suite)', self.source)
        lineage = self.module.SUITES["embedding-revision"]
        self.assertEqual(lineage["stores"], (("FRESH", "REVIEW"), ("POPULATED", "REVIEW")))
        self.assertEqual(lineage["env_prefix"], "EMBEDDING_")
        self.assertEqual(lineage["test"], "tests/postgres/secureshopEmbeddingRevision.integration.test.js")
        self.assertEqual(self.module.database_name("embedding-revision", "FRESH", "f" * 12),
                         "owasp_ai_goat_test_embedding_fresh_ffffffffffff")
        self.assertIn('env["EMBEDDING_REVISION_NATIVE"] = "1"', self.source)
        adapter = self.module.SUITES["manual-rag-source"]
        self.assertEqual(adapter["stores"], (("IDENTITY", "IDENTITY"),
            ("AGENTS", "AGENTS"), ("REVIEW", "REVIEW"), ("FRESH_REVIEW", "REVIEW")))
        self.assertNotEqual(self.module.database_name("manual-rag-source", "REVIEW", "f" * 12),
                            self.module.database_name("manual-rag-source", "FRESH_REVIEW", "f" * 12))
        self.assertEqual(adapter["env_prefix"], "PG_SECURESHOP_MANUAL_RAG_SOURCE_")
        self.assertEqual(adapter["test"],
            "tests/postgres/secureshopManualRagSourceAdapter.integration.test.js")
        self.assertIn('env["SECURESHOP_MANUAL_RAG_SOURCE_NATIVE"] = "1"', self.source)
        self.assertIn('env["OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE"] = str(source)', self.source)
        self.assertEqual(self.module.database_name("manual-rag-source", "REVIEW", "f" * 12),
            "owasp_ai_goat_test_manual_rag_source_review_ffffffffffff")
        preimages = self.module.SUITES["manual-rag-preimages"]
        self.assertEqual(preimages["stores"], (("FRESH_REVIEW", "REVIEW"),
            ("POPULATED_REVIEW", "REVIEW")))
        self.assertEqual(preimages["env_prefix"], "PG_SECURESHOP_MANUAL_RAG_PREIMAGES_")
        self.assertEqual(preimages["test"],
            "tests/postgres/secureshopManualRagPreimages.integration.test.js")
        self.assertIn('env["SECURESHOP_MANUAL_RAG_PREIMAGES_NATIVE"] = "1"', self.source)
        self.assertEqual(self.module.database_name("manual-rag-preimages", "FRESH_REVIEW", "f" * 12),
            "owasp_ai_goat_test_manual_rag_preimages_fresh_review_ffffffffffff")
        browser = self.module.SUITES["product-similar-browser"]
        self.assertEqual(browser["stores"], (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"),
            ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")))
        self.assertEqual(browser["env_prefix"], "PG_SECURESHOP_PRODUCT_SIMILAR_BROWSER_")
        self.assertEqual(browser["test"],
            "tests/postgres/secureshopStandaloneProductSimilarRendered.integration.test.js")
        for store, name in self.module.AGENT_HOST_STORE_NAMES.items():
            self.assertEqual(self.module.database_name("product-similar-browser", store, "f" * 12),
                f"owasp_ai_goat_test_agent_host_ffffffffffff_{name}")
        self.assertEqual(self.module.SUITES["composition"]["stores"], (
            ("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"),
            ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")))
        sessions = self.module.SUITES["persona-sessions"]
        self.assertEqual(sessions["stores"], (("COMMERCE", "COMMERCE"),
            ("FRESH_AGENTS", "AGENTS"), ("POPULATED_AGENTS", "AGENTS")))
        self.assertEqual(sessions["test"],
            "tests/postgres/secureshopBoundPersonaSessions.integration.test.js")
        self.assertEqual(len({self.module.ROLE_PAIRS[family]
            for _, family in sessions["stores"]}), 2)
        password = self.module.SUITES["persona-password"]
        self.assertEqual(password["stores"], sessions["stores"])
        self.assertEqual(password["env_prefix"], "PG_SECURESHOP_BOUND_PERSONA_PASSWORD_")
        self.assertEqual(password["test"],
            "tests/postgres/secureshopBoundPersonaPassword.integration.test.js")
        api_keys = self.module.SUITES["persona-api-keys"]
        self.assertEqual(api_keys["stores"], (("COMMERCE", "COMMERCE"),
            ("REVIEW", "REVIEW"), ("FRESH_AGENTS", "AGENTS"),
            ("POPULATED_AGENTS", "AGENTS")))
        self.assertEqual(api_keys["env_prefix"], "PG_SECURESHOP_BOUND_PERSONA_API_KEYS_")
        self.assertEqual(api_keys["test"],
            "tests/postgres/secureshopBoundPersonaApiKeys.integration.test.js")
        listings = self.module.SUITES["merchant-listings"]
        self.assertEqual(listings["stores"], (("FRESH_REVIEW", "REVIEW"),
            ("POPULATED_REVIEW", "REVIEW")))
        self.assertEqual(listings["env_prefix"], "PG_SECURESHOP_BOUND_MERCHANT_LISTINGS_")
        self.assertEqual(listings["test"],
            "tests/postgres/secureshopBoundMerchantListings.integration.test.js")
        self.assertEqual(self.module.DATABASE_FAMILIES["merchant-listings"], "merchant")
        for suite, row in self.module.SUITES.items():
            for store, _family in row["stores"]:
                name = self.module.database_name(suite, store, "f" * 12)
                self.assertLessEqual(len(name.encode("utf-8")), 63)
                self.assertRegex(name, r"^owasp_ai_goat_(?:test_[a-z0-9_]+|sql_copy_[a-f0-9]{12})$")
        refund = self.module.SUITES["refund"]
        self.assertEqual(refund["stores"], (("REVIEW", "REVIEW"),))
        self.assertEqual(refund["env_prefix"], "PG_SECURESHOP_BOUND_REFUND_")
        self.assertEqual(refund["test"], "tests/postgres/secureshopBoundRefund.integration.test.js")
        tails = self.module.SUITES["migration-tails"]
        self.assertEqual(tails["stores"], (("POPULATED_CTF", "CTF"),
            ("POPULATED_AGENTS", "AGENTS")))
        self.assertEqual(tails["env_prefix"], "PG_CURRENT_MIGRATION_TAILS_")
        self.assertEqual(tails["test"], "tests/postgres/currentMigrationTails.integration.test.js")
        self.assertEqual(len({self.module.ROLE_PAIRS[family]
            for _, family in tails["stores"]}), 2)
        capacity = self.module.SUITES["capacity"]
        self.assertEqual(capacity["stores"], (("CAPACITY", "IDENTITY"),))
        self.assertEqual(capacity["env_prefix"] + capacity["stores"][0][0] + "_MIGRATION_URL",
                         "PG_CAPACITY_MIGRATION_URL")
        self.assertEqual(capacity["test"], "tests/postgres/workshopCapacity.integration.test.js")
        self.assertIn('env["OWASP_AI_GOAT_CAPACITY_QUALIFICATION"] = "yes"', self.source)
        actual = self.module.SUITES["capacity-actual-8b"]
        self.assertEqual(actual["stores"], (("IDENTITY", "IDENTITY"),))
        self.assertEqual(actual["env_prefix"], "PG_CAPACITY_ACTUAL8B_")
        self.assertEqual(actual["test"], "tests/postgres/workshopCapacityActual8b.integration.test.js")
        self.assertIn('env.update(OWASP_AI_GOAT_CAPACITY_ACTUAL8B="yes"', self.source)
        self.assertIn('"capacity-actual-8b": "capacity_actual_8b"', self.source)
        sql_copy = self.module.SUITES["sql-teaching-copy"]
        self.assertEqual(sql_copy["stores"], (("IDENTITY", "IDENTITY"),))
        self.assertIsNone(sql_copy["env_prefix"])
        self.assertEqual(sql_copy["test"],
            "tests/postgres/sqlTeachingCopyDefaults.integration.test.js")
        self.assertEqual(self.module.database_name("sql-teaching-copy", "IDENTITY", "f" * 12),
            "owasp_ai_goat_sql_copy_ffffffffffff")
        self.assertIn('env["PG_SQL_TEACHING_COPY_TEST_URL"] = migration_url', self.source)
        self.assertNotIn('PG_SQL_TEACHING_COPY_TEST_RUNTIME_URL', self.source)
        output = StringIO()
        with redirect_stdout(output), mock.patch.object(self.module, 'run_qualification',
                side_effect=AssertionError('plan must not start native work')) as native:
            self.assertEqual(self.module.main([
                "--docker-host", "unix:///unused", "--docker-cli", "/unused/docker",
                "--docker-cli-sha256", "0" * 64, "--node", "/unused/node",
                "--node-sha256", "1" * 64, "--suite", "persona-sessions", "--main-checkout",
            ]), 0)
        native.assert_not_called()
        plan = json.loads(output.getvalue())
        self.assertEqual(plan['suite'], 'persona-sessions')
        self.assertEqual(plan['mode'], 'main-checkout')
        self.assertIs(plan['sourceCopy'], False)
        self.assertIs(plan['nativeStarted'], False)
        self.assertEqual(plan['stores'], ['COMMERCE', 'FRESH_AGENTS', 'POPULATED_AGENTS'])
        self.assertGreater(plan['sourceFiles'], 0)
        self.assertRegex(plan['sourceDigest'], r'^[0-9a-f]{64}$')

    def test_unknown_suite_is_rejected_before_any_resource_work(self):
        arguments = ["--docker-host", "unix:///unused", "--docker-cli", "/unused/docker",
            "--docker-cli-sha256", "0" * 64, "--node", "/unused/node",
            "--node-sha256", "1" * 64, "--suite", "arbitrary-test-path"]
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as raised:
            self.module.parse_args(arguments)
        self.assertEqual(raised.exception.code, 2)

    def test_every_admitted_suite_has_an_owned_container_name_before_resource_work(self):
        assignments = [node for node in ast.walk(ast.parse(self.source))
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "container_family"
                    for target in node.targets)]
        self.assertEqual(len(assignments), 1)
        self.assertIsInstance(assignments[0].value, ast.Subscript)
        container_families = ast.literal_eval(assignments[0].value.value)
        self.assertEqual(set(container_families), set(self.module.SUITES))
        self.assertEqual(container_families["manual-rag-source"], "manual-rag-source")

    def test_main_checkout_is_bounded_no_copy_and_has_private_source_inventory(self):
        arguments = ["--docker-host", "unix:///unused", "--docker-cli", "/unused/docker",
            "--docker-cli-sha256", "0" * 64, "--node", "/unused/node",
            "--node-sha256", "1" * 64, "--main-checkout"]
        for suite in ("manual-ingest", "embedding-revision"):
            with mock.patch.object(self.module, "source_inventory", return_value={
                    "digest": "a" * 64, "files": {"pinned.js": "b" * 64}}) as inventory, \
                    redirect_stdout(StringIO()) as output:
                self.assertEqual(self.module.main(arguments + ["--suite", suite]), 0)
            inventory.assert_called_once_with(ROOT)
            self.assertEqual(json.loads(output.getvalue()), {
                "suite": suite, "mode": "main-checkout", "sourceCopy": False,
                "sourceDigest": "a" * 64, "sourceFiles": 1,
                "stores": [store for store, _ in self.module.SUITES[suite]["stores"]],
                "nativeStarted": False})
        with self.assertRaisesRegex(RuntimeError, "limited to the focused"):
            self.module.main(arguments + ["--suite", "composition"])
        tree = ast.parse(self.source)
        guarded = next(node for node in ast.walk(tree) if isinstance(node, ast.If)
            and ast.unparse(node.test) == 'not args.main_checkout'
            and any(isinstance(child, ast.Call) and ast.unparse(child.func) == 'shutil.copytree'
                    for child in ast.walk(ast.Module(body=node.body, type_ignores=[]))))
        copy_calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
            and ast.unparse(node.func) in ('shutil.copytree', 'shutil.copy2')]
        self.assertTrue(copy_calls)
        self.assertTrue(all(guarded.lineno < call.lineno < guarded.end_lineno for call in copy_calls))
        self.assertIn('workspace = source if args.main_checkout else root / "source"', self.source)
        self.assertIn('OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(root if args.main_checkout else workspace)', self.source)
        self.assertIn('write_private_json(root / "source-before.json", source_before)', self.source)
        self.assertIn('write_private_json(root / "source-after.json", source_after)', self.source)

    def test_main_checkout_inventory_detects_source_drift_and_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in self.module.SOURCE_ROOTS:
                (root / name).mkdir(parents=True)
            (root / 'package.json').write_text('{}')
            (root / 'package-lock.json').write_text('{}')
            source = root / 'server/database/postgres/lineage.js'
            source.write_text('first')
            before = self.module.source_inventory(root)
            self.assertEqual(before, self.module.source_inventory(root))
            source.write_text('second')
            self.assertNotEqual(before['digest'], self.module.source_inventory(root)['digest'])
            (root / 'server/database/postgres/link.js').symlink_to(source)
            with self.assertRaisesRegex(RuntimeError, 'source link forbidden'):
                self.module.source_inventory(root)

    def test_manual_rag_source_plan_pins_imported_control_and_exact_tap(self):
        with mock.patch.object(self.module, "source_inventory", return_value={
                "digest": "a" * 64, "files": {"pinned.js": "b" * 64}}) as inventory, \
                redirect_stdout(StringIO()) as output:
            self.assertEqual(self.module.main([
                "--docker-host", "unix:///unused", "--docker-cli", "/unused/docker",
                "--docker-cli-sha256", "0" * 64, "--node", "/unused/node",
                "--node-sha256", "1" * 64, "--main-checkout",
                "--suite", "manual-rag-source"]), 0)
        inventory.assert_called_once_with(ROOT,
            ("tests/secureshopManualRagSourceContract.test.js", "tests/secureshopProtectedManualSourceNative.test.js"))
        self.assertEqual(json.loads(output.getvalue())["stores"],
            ["IDENTITY", "AGENTS", "REVIEW", "FRESH_REVIEW"])
        self.assertIn('"manual-rag-source",', self.source)
        title = "native manual RAG source adapter joins historical uploader and current consumer using immutable SQL evidence"
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "result.log"
            result.write_text(f"TAP version 13\n1..1\nok 1 - {title}\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n")
            self.module.assert_non_skipped_tap(result, "manual-rag-source")
            self.module.assert_exact_single_tap(result, title)
            result.write_text(result.read_text().replace(title, "unrelated test"))
            with self.assertRaisesRegex(RuntimeError, "TAP title"):
                self.module.assert_exact_single_tap(result, title)

    def test_product_summary_closed_selection_and_actual_environment(self):
        from types import SimpleNamespace
        suite=self.module.SUITES['product-summary-browser']
        self.assertEqual(suite['stores'],self.module.SUITES['product-similar-browser']['stores'])
        self.assertEqual(suite['test'],self.module.SUITES['product-similar-browser']['test'])
        self.assertIn('product-summary-browser',self.module.REQUIRES_MAIN_CHECKOUT)
        self.assertIn('product-summary-browser',self.module.EMBEDDING_CACHE_SUITES)
        self.assertEqual(self.module.sha256(ROOT/suite['test']),self.module.PRODUCT_SIMILAR_TEST_SHA256)
        for store,_ in suite['stores']:
            self.assertEqual(self.module.database_name('product-summary-browser',store,'f'*12),
                f"owasp_ai_goat_test_agent_host_{'f'*12}_{self.module.AGENT_HOST_STORE_NAMES[store]}")
        tree=ast.parse(self.source)
        blocks=[n for n in ast.walk(tree) if isinstance(n,ast.If) and ast.unparse(n.test)=="args.suite in ('product-similar-browser', 'product-summary-browser')"
                and any(isinstance(x,ast.Constant) and x.value=='SECURESHOP_PRODUCT_SUMMARY_BROWSER_NATIVE' for x in ast.walk(n))]
        self.assertEqual(len(blocks),1)
        for selected,expected,absent in [('product-summary-browser','SECURESHOP_PRODUCT_SUMMARY_BROWSER_NATIVE','SECURESHOP_PRODUCT_SIMILAR_BROWSER_NATIVE'),('product-similar-browser','SECURESHOP_PRODUCT_SIMILAR_BROWSER_NATIVE','SECURESHOP_PRODUCT_SUMMARY_BROWSER_NATIVE')]:
            env={};ns={'args':SimpleNamespace(suite=selected,browser_sha256='f'*64,product_summary_test_no_sandbox=False),'env':env,'source':ROOT,'root':Path('/owned/evidence'),'browser':Path('/owned/browser'),'REFUND_MODEL':self.module.REFUND_MODEL,'REFUND_OLLAMA_BASE_URL':self.module.REFUND_OLLAMA_BASE_URL}
            exec(compile(ast.Module(body=blocks,type_ignores=[]),'<actual-environment>','exec'),ns)
            self.assertEqual(env[expected],'1');self.assertNotIn(absent,env)
            self.assertEqual(env['SECURESHOP_PRODUCT_SIMILAR_BROWSER_BUILD'],str(ROOT/'client/build'))
            self.assertNotIn('SECURESHOP_PRODUCT_SUMMARY_TEST_NO_SANDBOX',env)
            if selected=='product-summary-browser':
                ns['args'].product_summary_test_no_sandbox=True
                exec(compile(ast.Module(body=blocks,type_ignores=[]),'<actual-environment>','exec'),ns)
                self.assertEqual(env['SECURESHOP_PRODUCT_SUMMARY_TEST_NO_SANDBOX'],'1')

    def test_product_summary_benign_flag_is_closed_and_exact_actual_environment(self):
        base = dict(suite='product-summary-browser', main_checkout=True, current_host_profile='owned',
            docker_daemon='owned', image_id='owned', evidence_parent='owned', browser_root='owned',
            product_summary_benign_capture=True, product_summary_test_no_sandbox=False,
            browser_sha256='f'*64)
        self.module.validate_current_host_selection(SimpleNamespace(**base))
        for patch in ({'suite':'product-similar-browser'}, {'suite':'manual-rag-browser'},
                      {'main_checkout':False}, {'current_host_profile':None}):
            with self.assertRaisesRegex(RuntimeError, 'V16 benign capture'):
                self.module.validate_current_host_selection(SimpleNamespace(**{**base, **patch}))
        tree = ast.parse(self.source)
        blocks = [n for n in ast.walk(tree) if isinstance(n,ast.If)
            and ast.unparse(n.test)=="args.suite in ('product-similar-browser', 'product-summary-browser')"
            and any(isinstance(x,ast.Constant) and x.value=='SECURESHOP_PRODUCT_SUMMARY_BROWSER_NATIVE' for x in ast.walk(n))]
        self.assertEqual(len(blocks),1)
        for selected in (False,True):
            env={};ns={'args':SimpleNamespace(**{**base,'product_summary_benign_capture':selected}),
                'env':env,'source':ROOT,'root':Path('/owned/evidence'),'browser':Path('/owned/browser'),
                'REFUND_MODEL':self.module.REFUND_MODEL,'REFUND_OLLAMA_BASE_URL':self.module.REFUND_OLLAMA_BASE_URL}
            exec(compile(ast.Module(body=blocks,type_ignores=[]),'<actual-benign-environment>','exec'),ns)
            self.assertEqual(env['SECURESHOP_PRODUCT_SUMMARY_BROWSER_NATIVE'],'1')
            self.assertEqual(env.get('SECURESHOP_PRODUCT_SUMMARY_BENIGN_CAPTURE'),'1' if selected else None)
        parsed=self.module.parse_args(['--docker-host','unix:///unused','--docker-cli','/unused/docker',
            '--docker-cli-sha256','0'*64,'--node','/unused/node','--node-sha256','1'*64,
            '--suite','product-summary-browser','--product-summary-benign-capture'])
        self.assertTrue(parsed.product_summary_benign_capture)

    def test_product_summary_benign_inert_plan_cannot_claim_qualification(self):
        arguments=['--docker-host','unix:///unused','--docker-cli','/unused/docker',
            '--docker-cli-sha256','0'*64,'--node','/unused/node','--node-sha256','1'*64,
            '--suite','product-summary-browser','--product-summary-benign-capture','--main-checkout',
            '--current-host-profile','owned']
        with mock.patch.object(self.module,'main_checkout_inventory',return_value={'digest':'a'*64,'files':{}}), \
                mock.patch.object(self.module,'run_qualification',side_effect=AssertionError('No native allocation')), \
                redirect_stdout(StringIO()) as output:
            self.assertEqual(self.module.main(arguments),0)
        value=json.loads(output.getvalue());self.assertEqual(value['captureVersion'],self.module.PRODUCT_SUMMARY_BENIGN_VERSION)
        self.assertTrue(value['diagnosticOnly']);self.assertFalse(value['qualificationAccepted']);self.assertFalse(value['nativeStarted'])
        self.assertEqual((value['summaryRuns'],value['judgeCalls'],value['maxActorHttpCalls'],value['maxJudgeHttpCalls']),(1,0,12,8))

    def test_product_summary_benign_actual_replay_binds_full_actor_capture_and_denies_promotion(self):
        node=ROOT/'tasks/runtime/node/node_modules/node/bin/node'
        script=r"""const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const filename=path.resolve('tests/secureshopProductSummaryEvidence.test.js'),real=require('node:module').createRequire(filename),mod={exports:{}};
vm.compileFunction(fs.readFileSync(filename,'utf8')+'\nmodule.exports={controlledBenignSummary};',
 ['require','module','__dirname'],{filename})(name=>name==='node:test'?()=>{}:real(name),mod,path.dirname(filename));
const x=mod.exports.controlledBenignSummary(),fixture=path.resolve('tests/postgres/secureshopStandaloneProductSimilarRendered.integration.test.js'),r=require('node:module').createRequire(fixture),f={exports:{}};
vm.compileFunction(fs.readFileSync(fixture,'utf8'),['require','module','process','__dirname'],{filename:fixture})(name=>name==='node:test'?()=>{}:name==='pg'?{Pool:class{constructor(){throw Error('No database');}}}:r(name),f,{env:{},cwd:()=>process.cwd(),getuid:()=>process.getuid()},path.dirname(fixture));
x.capture.benignProof=f.exports.assertProductSummaryBenignCapture(x);
for(const w of x.actorWires){w.model='llama3.1:8b';w.error=null;w.requestBytes=Buffer.byteLength(w.request);w.responseBytes=Buffer.byteLength(w.response);}
const c=f.exports.productCohortContract({SECURESHOP_PRODUCT_SUMMARY_BROWSER_NATIVE:'1',SECURESHOP_PRODUCT_SUMMARY_BENIGN_CAPTURE:'1'});
const receipt={...Object.fromEntries(c.flags.map(k=>[k,true])),passed:true,scope:c.scope,version:c.version,diagnosticOnly:true,qualificationAccepted:false,
 summaryRuns:1,similarRuns:0,modelCalls:2,selectedSimilarCalls:0,judgeCalls:0,errors:[],cleanupErrors:[]};
const wire={model:'llama3.1:8b',modelDigest:'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e',calls:x.actorWires,judgeCalls:[],actorSpans:[],requests:[x.capture.turns[0].run],pageErrors:[],judgeInputs:[],judgeTranscripts:[],summaryCapture:x.capture};
process.stdout.write(JSON.stringify({receipt,wire}));"""
        emitted=subprocess.run([str(node),'-e',script],cwd=ROOT,capture_output=True,text=True,timeout=20)
        self.assertEqual(emitted.returncode,0,emitted.stderr);data=json.loads(emitted.stdout)
        with tempfile.TemporaryDirectory(dir=ROOT/'tasks/tmp') as directory:
            root=Path(directory)
            def save(value):
                for name,key in [('product-similar-evidence.json','receipt'),('product-similar-original-wire.json','wire')]:
                    path=root/name
                    if path.exists():path.unlink()
                    # Match the fixture's original insertion-order serialization;
                    # sorting nested MCP fields would alter the bound observation bytes.
                    with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as stream:
                        json.dump(value[key],stream)
            save(data)
            real_run=subprocess.run
            def checked_replay(*args,**kwargs):
                result=real_run(*args,**kwargs)
                self.assertEqual(result.returncode,0,result.stderr)
                return result
            with mock.patch.object(self.module.subprocess,'run',side_effect=checked_replay):
                self.assertEqual(self.module.assert_product_summary_evidence(root,node,benign=True),data['receipt'])
            with self.assertRaises(RuntimeError):self.module.assert_product_summary_evidence(root,node)
            for edit in ('promotion','bool-count','extra-arm','judge','rubric','response','source','catalog','proof','hash'):
                bad=copy.deepcopy(data)
                if edit=='promotion':bad['receipt']['qualificationAccepted']=True
                elif edit=='bool-count':bad['receipt']['summaryRuns']=True
                elif edit=='extra-arm':bad['wire']['summaryCapture']['turns'].append(bad['wire']['summaryCapture']['turns'][0])
                elif edit=='judge':bad['wire']['judgeInputs']=[{}]
                elif edit=='rubric':bad['wire']['summaryCapture']['originalRubric']['criteria'].pop()
                elif edit=='response':bad['wire']['summaryCapture']['turns'][0]['source']['semantic']['response']['text']='Invented'
                elif edit=='source':bad['wire']['summaryCapture']['payload']['description']='Different'
                elif edit=='catalog':bad['wire']['summaryCapture']['benignCatalogAfter']['enabled']=True
                elif edit=='proof':bad['wire']['summaryCapture']['benignProof']['assessmentAuthority']={}
                else:bad['wire']['calls'][0]['requestSha256']='0'*64
                save(bad)
                with self.assertRaises(RuntimeError,msg=edit):self.module.assert_product_summary_evidence(root,node,benign=True)

    def test_product_summary_actual_model_after_branch_preserves_identity_and_budgets(self):
        from types import SimpleNamespace
        tree=ast.parse(self.source)
        blocks=[n for n in ast.walk(tree) if isinstance(n,ast.If) and ast.unparse(n.test)=="args.suite in ('product-similar-browser', 'product-summary-browser')"
                and any(isinstance(x,ast.Constant) and x.value=='product-similar-model-identity.json' for x in ast.walk(n))]
        self.assertEqual(len(blocks),1);identity={'model':'llama3.1:8b','digest':'a'*64};written=[]
        ns={'args':SimpleNamespace(suite='product-summary-browser'),'model_identity_before':identity,'read_refund_model_digest':lambda:dict(identity),'root':Path('/owned/evidence'),'write_private_json':lambda p,v:written.append((p,v))}
        code=compile(ast.Module(body=blocks,type_ignores=[]),'<actual-model-after>','exec');exec(code,ns)
        self.assertEqual(written[0][1],{'before':identity,'after':identity,'maxHttpCalls':20,'maxActorHttpCalls':12,'maxJudgeHttpCalls':8})
        ns['read_refund_model_digest']=lambda:{'digest':'b'*64}
        with self.assertRaisesRegex(RuntimeError,'model changed'):exec(code,ns)

    def test_product_summary_plan_is_nonallocating_and_pin_bound(self):
        args=['--docker-host','unix:///unused','--docker-cli','/unused/docker','--docker-cli-sha256','0'*64,'--node','/unused/node','--node-sha256','1'*64,'--suite','product-summary-browser','--main-checkout']
        fixture=self.module.SUITES['product-summary-browser']['test']
        with mock.patch.object(self.module,'source_inventory',return_value={'digest':'a'*64,'files':{fixture:self.module.PRODUCT_SIMILAR_TEST_SHA256}}),mock.patch.object(self.module,'run_qualification',side_effect=AssertionError('no allocation')),redirect_stdout(StringIO()) as output:
            self.assertEqual(self.module.main(args),0)
        self.assertEqual(json.loads(output.getvalue())['stores'],['IDENTITY','AGENTS','REVIEW','COMMERCE'])
        with mock.patch.object(self.module,'source_inventory',return_value={'digest':'a'*64,'files':{fixture:'0'*64}}):
            with self.assertRaisesRegex(RuntimeError,'fixture pin changed'):self.module.main(args)

    def test_product_summary_receipt_and_wire_are_closed(self):
        import copy
        receipt={k:True for k in self.module.PRODUCT_SUMMARY_FLAGS}
        receipt.update(passed=True,scope=self.module.PRODUCT_SUMMARY_SCOPE,summaryRuns=3,similarRuns=0,selectedSimilarCalls=0,modelCalls=6,judgeCalls=2,errors=[],cleanupErrors=[])
        def call(kind):
            request=json.dumps({'model':self.module.REFUND_MODEL});response='{"done":true}'
            return {'kind':kind,'model':self.module.REFUND_MODEL,'status':200,'responseComplete':True,'responseCaptureTruncated':False,'request':request,'response':response,'requestBytes':len(request.encode()),'responseBytes':len(response.encode()),'requestSha256':hashlib.sha256(request.encode()).hexdigest(),'responseSha256':hashlib.sha256(response.encode()).hexdigest()}
        wire={'model':self.module.REFUND_MODEL,'modelDigest':self.module.REFUND_MODEL_DIGEST,'calls':[call('actor') for _ in range(6)],'judgeCalls':[call('judge') for _ in range(2)],'actorSpans':[],'requests':[{'method':'POST','pathname':'/products/1/summary','status':200,'error':None} for _ in range(3)],'pageErrors':[],'judgeInputs':[{}],'judgeTranscripts':[{}],'summaryCapture':{'turns':[{}, {}, {}],'positiveWireProof':{}}}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            def save(a,b):
                self.module.write_private_json(root/'product-similar-evidence.json',a);self.module.write_private_json(root/'product-similar-original-wire.json',b)
            def clear():
                for p in root.iterdir():p.unlink()
            save(receipt,wire)
            with mock.patch.object(self.module,'replay_product_summary_fixed_evidence') as replay:
                self.assertEqual(self.module.assert_product_summary_evidence(root),receipt)
                replay.assert_called_once_with(root/'product-similar-original-wire.json',None)
            with mock.patch.object(self.module,'replay_product_summary_fixed_evidence',side_effect=RuntimeError('tampered Fixed source')):
                with self.assertRaises(RuntimeError):self.module.assert_product_summary_evidence(root)
            clear()
            for key,value in [('modelCalls',13),('judgeCalls',9),('summaryRuns',2),('similarRuns',1),('fixtureLocalCandidateAdmission',False),('modelCalls',True),('unexpected',True)]:
                bad=copy.deepcopy(receipt);bad[key]=value;save(bad,wire)
                with self.assertRaises(RuntimeError):self.module.assert_product_summary_evidence(root)
                clear()
            for mutation in ['wireHash','judgeMissing','similar','postCount']:
                bad=copy.deepcopy(wire)
                if mutation=='wireHash':bad['calls'][0]['responseSha256']='0'*64
                elif mutation=='judgeMissing':bad['judgeCalls']=[]
                elif mutation=='similar':bad['requests'][0]['pathname']='/products/1/similar'
                else:bad['requests'].pop()
                save(receipt,bad)
                with self.assertRaises(RuntimeError):self.module.assert_product_summary_evidence(root)
                clear()

    def test_product_similar_browser_requires_main_checkout_and_full_source_closure(self):
        arguments = ["--docker-host", "unix:///unused", "--docker-cli", "/unused/docker",
            "--docker-cli-sha256", "0" * 64, "--node", "/unused/node",
            "--node-sha256", "1" * 64, "--suite", "product-similar-browser"]
        with self.assertRaisesRegex(RuntimeError, "requires --main-checkout"):
            self.module.main(arguments)
        with mock.patch.object(self.module, "source_inventory", return_value={
                "digest": "a" * 64, "files": {
                    self.module.SUITES["product-similar-browser"]["test"]:
                        self.module.PRODUCT_SIMILAR_TEST_SHA256}}) as inventory, \
                redirect_stdout(StringIO()) as output:
            self.assertEqual(self.module.main(arguments + ["--main-checkout"]), 0)
        inventory.assert_called_once_with(ROOT,
            (),
            ("server/routes", "server/middleware", "server/data"),
            ("client/src", "client/build"))
        plan = json.loads(output.getvalue())
        self.assertEqual(plan["stores"], ["IDENTITY", "AGENTS", "REVIEW", "COMMERCE"])
        self.assertFalse(plan["sourceCopy"])
        with mock.patch.object(self.module, "source_inventory", return_value={
                "digest": "a" * 64, "files": {
                    self.module.SUITES["product-similar-browser"]["test"]: "0" * 64}}):
            with self.assertRaisesRegex(RuntimeError, "fixture pin changed"):
                self.module.main(arguments + ["--main-checkout"])
        self.assertIn('"product-similar-browser": "product-similar-browser"', self.source)
        self.assertIn('read_refund_model_digest()', self.source)
        self.assertIn('"product-similar-browser.json", "product_similar_browser"', self.source)
        self.assertIn("product-similar-browser", self.module.EMBEDDING_CACHE_SUITES)
        self.assertIn('env.update(SS_PRODUCT_QUALIFICATION="1", HF_HUB_OFFLINE="1", XENOVA_CACHE=str(embedding_cache))', self.source)

    def test_manual_rag_browser_has_distinct_no_copy_four_store_admission(self):
        suite = self.module.SUITES["manual-rag-browser"]
        self.assertEqual(suite["stores"], (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"),
            ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")))
        self.assertEqual(suite["env_prefix"], "PG_SECURESHOP_MANUAL_RAG_BROWSER_")
        self.assertEqual(suite["test"], "tests/postgres/secureshopManualRagRendered.integration.test.js")
        for store in ("IDENTITY", "AGENTS", "REVIEW", "COMMERCE"):
            self.assertEqual(self.module.database_name("manual-rag-browser", store, "f" * 12),
                f"owasp_ai_goat_test_agent_host_{'f' * 12}_{self.module.AGENT_HOST_STORE_NAMES[store]}")
        arguments = ["--docker-host", "unix:///unused", "--docker-cli", "/unused/docker",
            "--docker-cli-sha256", "0" * 64, "--node", "/unused/node",
            "--node-sha256", "1" * 64, "--suite", "manual-rag-browser"]
        with self.assertRaisesRegex(RuntimeError, "requires --main-checkout"):
            self.module.main(arguments)
        with mock.patch.object(self.module, "source_inventory", return_value={
                "digest": "a" * 64, "files": {suite["test"]:
                    self.module.MANUAL_RAG_BROWSER_TEST_SHA256,
                    "tests/fixtures/secureshopManualUploadQ05.js": self.module.MANUAL_UPLOAD_Q05_HELPER_SHA256,
                    "tests/secureshopManualUploadQ05.test.js": self.module.MANUAL_UPLOAD_Q05_CONTROL_SHA256}}) as inventory, \
                redirect_stdout(StringIO()) as output:
            self.assertEqual(self.module.main(arguments + ["--main-checkout"]), 0)
        inventory.assert_called_once_with(ROOT,
            self.module.MAIN_CHECKOUT_EXTRA_FILES["manual-rag-browser"],
            ("server/routes", "server/middleware", "server/data"),
            ("client/src", "client/build"))
        self.assertEqual(json.loads(output.getvalue())["stores"],
            ["IDENTITY", "AGENTS", "REVIEW", "COMMERCE"])
        with mock.patch.object(self.module, "source_inventory", return_value={
                "digest": "a" * 64, "files": {suite["test"]: "0" * 64}}):
            with self.assertRaisesRegex(RuntimeError, "fixture pin changed"):
                self.module.main(arguments + ["--main-checkout"])
        self.assertIn('"manual-rag-browser": "manual-rag-browser"', self.source)
        self.assertIn('"manual-rag-browser.json", "manual_rag_browser"', self.source)
        self.assertIn('SECURESHOP_MANUAL_RAG_BROWSER_NATIVE="1"', self.source)
        self.assertIn("manual-rag-browser", self.module.EMBEDDING_CACHE_SUITES)

    def test_manual_upload_q05_is_explicit_separate_current_host_mode_with_strict_private_replay(self):
        args = self.module.parse_args(["--docker-host", "unix:///unused", "--docker-cli", "/unused/docker",
            "--docker-cli-sha256", "0" * 64, "--node", "/unused/node", "--node-sha256", "1" * 64,
            "--suite", "manual-rag-browser", "--manual-upload-q05", "--main-checkout",
            "--current-host-profile", "goat-q"])
        self.module.validate_current_host_selection(args)
        for change in [{"suite": "manual-rag-paired-browser"}, {"main_checkout": False},
                       {"current_host_profile": None}, {"manual_rag_payload_variant": "role-spoof-v1"}]:
            other = copy.copy(args)
            for key, value in change.items(): setattr(other, key, value)
            with self.assertRaisesRegex(RuntimeError, "Q05 manual upload"):
                self.module.validate_current_host_selection(other)
        self.assertIn("tests/fixtures/secureshopManualUploadQ05.js",
            self.module.MAIN_CHECKOUT_EXTRA_FILES["manual-rag-browser"])
        current = {self.module.SUITES["manual-rag-browser"]["test"]: self.module.MANUAL_RAG_BROWSER_TEST_SHA256,
            "tests/fixtures/secureshopManualUploadQ05.js": self.module.MANUAL_UPLOAD_Q05_HELPER_SHA256,
            "tests/secureshopManualUploadQ05.test.js": self.module.MANUAL_UPLOAD_Q05_CONTROL_SHA256}
        for name in ("tests/fixtures/secureshopManualUploadQ05.js", "tests/secureshopManualUploadQ05.test.js"):
            changed = {**current, name: "0" * 64}
            with mock.patch.object(self.module, "source_inventory", return_value={
                    "digest": "a" * 64, "files": changed}), self.assertRaisesRegex(RuntimeError, "Q05 manual upload"):
                self.module.main_checkout_inventory(ROOT, "manual-rag-browser")
        with tempfile.TemporaryDirectory(dir=ROOT / "tasks/tmp") as directory:
            root = Path(directory)
            descriptor = {"productId": "7", "sha256": "a" * 64, "sizeBytes": "8",
                "filename": "owned-manual.txt", "mime": "text/plain", "public": "true"}
            operation = "00000000-0000-4000-8000-000000000001"
            key = "b" * 64
            first = {"version": 1, "kind": "product_manual", "operationId": operation,
                "recoveryScopeKey": key, "state": "not_found", "receipt": None}
            indexed = {**first, "state": "indexed", "receipt": {"productId": 7,
                "sha256": descriptor["sha256"], "sizeBytes": 8, "filename": descriptor["filename"],
                "mime": descriptor["mime"], "isPublic": True, "chunkCount": 1,
                "chunkIds": ["manual:8:0"], "completedAt": "2026-10-21T00:00:00.000Z"}}
            committed = {"ok": True, "kind": "product_manual", "operationId": operation}
            raw = json.dumps(committed, separators=(",", ":"))
            initial = {"method": "GET", "pathname": "/uploads/product-manual/receipt",
                "query": descriptor, "status": 200, "error": None, "response": json.dumps(first)}
            post = {"method": "POST", "pathname": "/uploads", "status": 200,
                "error": "ABORTED", "response": "{"}
            recovered = {**initial, "query": {**descriptor, "recoveryScopeKey": key},
                "response": json.dumps(indexed)}
            denied = {**recovered, "status": 401, "response": '{"error":"denied"}'}
            merchant_read = {"method": "GET", "pathname": "/merchant/products", "status": 200,
                "error": None, "query": {"retailer_id": "1000000003", "page": "1",
                    "per_page": "20", "sort": "updated_desc"},
                "response": json.dumps({"products": [{"id": 7, "retailer_id": 1000000003}]})}
            readiness = {"method": "GET", "pathname": "/merchant/listings/readiness",
                "status": 503, "error": None, "response": json.dumps({"error": "Bound SecureShop operation unavailable"})}
            requests = [merchant_read, readiness, initial, post, copy.deepcopy(merchant_read),
                recovered, denied, copy.deepcopy(denied)]
            peer_target = "00000000-0000-4000-8000-000000000003"
            peer = {"targetId": peer_target,
                "products": [{"row": {"product_id": n, "target_id": peer_target}} for n in range(1, 126)],
                "ingests": [{"row": {"target_id": peer_target, "operation_id": operation, "manual_source_id": 8,
                    "file_target_id": operation, "virtual_path": "/uploads/product_manuals/7/manual",
                    "byte_count": 8, "file_sha256": "\\x" + descriptor["sha256"]}}],
                "documents": [{"row": {"target_id": peer_target, "source_kind": "manual", "source_id": 8,
                    "body": "Owned sibling manual"}}],
                "file": {"operationId": operation, "targetId": operation,
                    "virtualPath": "/uploads/product_manuals/7/manual",
                    "sha256": descriptor["sha256"], "bytes": 8}}
            credit = {"catalog": [{"row": {"qualification": "pending", "is_enabled": False}}]}
            capture = {"q05Initial": {"request": initial, "lookup": first},
                "q05Recovered": indexed,
                "q05Committed": {"body": committed, "raw": raw, "bytes": len(raw),
                    "sha256": hashlib.sha256(raw.encode()).hexdigest(),
                    "request": {"fields": {"kind": "product_manual", "scope_id": "7",
                        "mime": "text/plain", "public": "true", "recoveryScopeKey": key},
                        "filename": descriptor["filename"], "fileSha256": descriptor["sha256"],
                        "fileBytes": 8}},
                "q05Network": {"posts": [{"requestId": "browser-one", "method": "POST"}],
                    "responses": [{"requestId": "browser-one", "status": 200}],
                    "failures": [{"requestId": "browser-one", "canceled": False,
                                  "errorText": "net::ERR_CONTENT_LENGTH_MISMATCH"}]},
                "upload": post, "payload": {"sha256": descriptor["sha256"], "bytes": 8},
                "q05Foreign": {"status": 401}, "q05Stale": {"status": 401, "reset": "committed"},
                "q05PeerBefore": peer, "q05PeerAfter": copy.deepcopy(peer),
                "q05PeerAfterReset": copy.deepcopy(peer),
                "q05OwnedSourceBefore": {"sha256": descriptor["sha256"], "bytes": 8},
                "q05OwnedSourceAfter": {"sha256": descriptor["sha256"], "bytes": 8},
                "q05OwnedFileBefore": {"source": {"sha256": descriptor["sha256"], "bytes": 8},
                    "uploaded": {"sha256": descriptor["sha256"], "bytes": 8}},
                "initialCredit": credit, "q05FinalCredit": copy.deepcopy(credit),
                "manualReceipts": [{"row": {"operation_id": operation,
                    "file_sha256": "\\x" + descriptor["sha256"], "is_public": True,
                    "document_count": 1}}]}
            capture["q05ImmutableUpload"] = copy.deepcopy(capture["manualReceipts"])
            node = ROOT / "tasks/runtime/node/node_modules/node/bin/node"
            uploader = r"""const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict');
const filename=path.join(process.cwd(),'tests/secureshopManualUploadQ05.test.js');
const real=require('node:module').createRequire(filename),mod={exports:{}};
const inert=()=>{};inert.skip=()=>{};
vm.compileFunction(fs.readFileSync(filename,'utf8')+'\nmodule.exports.syntheticUploader=syntheticUploader;',
 ['require','module','__dirname'],{filename})(name=>name==='node:test'?inert:real(name),mod,path.dirname(filename));
const input=mod.exports.syntheticUploader(),model=process.argv[1];
input.model=model;input.upload.model=model;
for(const span of input.spans)span.result.model=model;
for(const call of input.calls){
 call.model=model;const request=JSON.parse(call.request);request.model=model;
 call.request=JSON.stringify(request);call.requestBytes=Buffer.byteLength(call.request);
 call.requestSha256=require('node:crypto').createHash('sha256').update(call.request).digest('hex');
 const frames=call.response.trimEnd().split('\n').map(line=>JSON.parse(line));
 for(const frame of frames)frame.model=model;
 call.response=frames.map(frame=>JSON.stringify(frame)).join('\n')+'\n';
 call.responseBytes=Buffer.byteLength(call.response);call.responseObservedBytes=call.responseBytes;
 call.responseSha256=require('node:crypto').createHash('sha256').update(call.response).digest('hex');
}
const proof=require('./tests/fixtures/secureshopManualUploadQ05').assertUploaderActor(input);
process.stdout.write(JSON.stringify({input,proof}));"""
            generated = subprocess.run([str(node), "-e", uploader, self.module.REFUND_MODEL],
                cwd=ROOT, capture_output=True, text=True, timeout=20)
            self.assertEqual(generated.returncode, 0)
            synthetic = json.loads(generated.stdout)
            capture["q05UploaderProof"] = synthetic["proof"]
            committed = synthetic["input"]["upload"]
            raw = json.dumps(committed, separators=(",", ":"))
            capture["q05Committed"].update(body=committed, raw=raw, bytes=len(raw),
                sha256=hashlib.sha256(raw.encode()).hexdigest())
            capture["manualReceipts"] = [{"row": {**synthetic["input"]["manualRows"][0]["row"],
                "is_public": True, "document_count": 1}}]
            capture["q05ImmutableUpload"] = copy.deepcopy(capture["manualReceipts"])
            receipt = {flag: True for flag in self.module.MANUAL_UPLOAD_Q05_FLAGS}
            receipt.update(passed=True, scope=self.module.MANUAL_UPLOAD_Q05_SCOPE, similarRuns=0,
                modelCalls=2, selectedSimilarCalls=0, judgeCalls=0, errors=[], cleanupErrors=[],
                credit=False, diagnostic=True)
            wire = {"scope": self.module.MANUAL_UPLOAD_Q05_SCOPE, "credit": False,
                "model": self.module.REFUND_MODEL, "modelDigest": self.module.REFUND_MODEL_DIGEST,
                "actorCalls": synthetic["input"]["calls"], "judgeCalls": [],
                "actorSpans": synthetic["input"]["spans"], "judgeTranscripts": [],
                "requests": requests, "originalCapture": capture, "pageErrors": []}
            receipt_path = root / "manual-upload-q05-evidence.json"
            wire_path = root / "manual-upload-q05-wire.json"
            self.module.write_private_json(receipt_path, receipt)
            self.module.write_private_json(wire_path, wire)
            self.assertEqual(self.module.assert_manual_upload_q05_evidence(root), receipt)
            for mutate in [lambda value: value["requests"].append(copy.deepcopy(post)),
                lambda value: value["requests"].insert(0,
                    {"method": "POST", "pathname": "/products/7/similar", "status": 200}),
                lambda value: value["requests"].insert(0,
                    {"method": "GET", "pathname": "/merchant/listings/readiness",
                        "status": 401, "error": None, "response": "{}"}),
                lambda value: value["requests"][0]["query"].update(retailer_id="1000000004"),
                lambda value: value["requests"][0]["query"].update(sort="price_asc"),
                lambda value: value["requests"][0].update(response=json.dumps({
                    "products": [{"id": 7, "retailer_id": 1000000004}]})),
                lambda value: value["requests"][1].update(response='{"ready":"true"}', status=200),
                lambda value: value["requests"].append(copy.deepcopy(merchant_read)),
                lambda value: value["actorSpans"][0]["result"]["tool_uses"][0].update(
                    name="product-search.similar"),
                lambda value: value["actorCalls"][0].update(requestSha256="0" * 64),
                lambda value: value["originalCapture"]["q05UploaderProof"].update(
                    physicalActorCalls=3),
                lambda value: value["originalCapture"]["q05Committed"].update(sha256="c" * 64),
                lambda value: value["originalCapture"]["q05PeerAfter"]["documents"].pop(),
                lambda value: value["originalCapture"]["q05PeerBefore"]["ingests"].pop(),
                lambda value: value["originalCapture"]["q05OwnedFileBefore"]["source"].update(bytes=7),
                lambda value: value["requests"][2]["query"].update(sha256="c" * 64),
                lambda value: value["originalCapture"]["q05Network"]["responses"][0].update(status=502)]:
                changed = copy.deepcopy(wire); mutate(changed)
                wire_path.write_text(json.dumps(changed))
                with self.assertRaises(RuntimeError):
                    self.module.assert_manual_upload_q05_evidence(root)
            wire_path.write_text(json.dumps(wire))
            ready_wire = copy.deepcopy(wire)
            ready_wire["requests"][1].update(status=200, response='{"ready":false}')
            wire_path.write_text(json.dumps(ready_wire))
            self.assertEqual(self.module.assert_manual_upload_q05_evidence(root), receipt)
            overview_wire = copy.deepcopy(wire)
            overview_wire["requests"][0]["query"] = {"retailer_id": "1000000003",
                "per_page": "6", "status": "active"}
            wire_path.write_text(json.dumps(overview_wire))
            self.assertEqual(self.module.assert_manual_upload_q05_evidence(root), receipt)
            wire_path.write_text(json.dumps(wire))
            for change in ({"modelCalls": 0}, {"modelCalls": 5}, {"judgeCalls": 1},
                           {"similarRuns": 1}):
                receipt_path.write_text(json.dumps(receipt | change))
                with self.assertRaises(RuntimeError):
                    self.module.assert_manual_upload_q05_evidence(root)
            receipt["credit"] = True
            receipt_path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(RuntimeError, "receipt failed"):
                self.module.assert_manual_upload_q05_evidence(root)

    def test_manual_rag_fixed_browser_has_exclusive_no_copy_admission(self):
        suite = self.module.SUITES["manual-rag-fixed-browser"]
        original = self.module.SUITES["manual-rag-browser"]
        self.assertEqual(suite["stores"], original["stores"])
        self.assertEqual(suite["env_prefix"], original["env_prefix"])
        self.assertEqual(suite["test"], original["test"])
        self.assertNotEqual(suite["child_name"], original["child_name"])
        for store in ("IDENTITY", "AGENTS", "REVIEW", "COMMERCE"):
            self.assertEqual(self.module.database_name("manual-rag-fixed-browser", store, "f" * 12),
                f"owasp_ai_goat_test_agent_host_{'f' * 12}_{self.module.AGENT_HOST_STORE_NAMES[store]}")
        arguments = ["--docker-host", "unix:///unused", "--docker-cli", "/unused/docker",
            "--docker-cli-sha256", "0" * 64, "--node", "/unused/node",
            "--node-sha256", "1" * 64, "--suite", "manual-rag-fixed-browser"]
        with self.assertRaisesRegex(RuntimeError, "requires --main-checkout"):
            self.module.main(arguments)
        with mock.patch.object(self.module, "source_inventory", return_value={
                "digest": "a" * 64, "files": {suite["test"]:
                    self.module.MANUAL_RAG_BROWSER_TEST_SHA256}}) as inventory, \
                redirect_stdout(StringIO()) as output:
            self.assertEqual(self.module.main(arguments + ["--main-checkout"]), 0)
        inventory.assert_called_once_with(ROOT,
            self.module.MAIN_CHECKOUT_EXTRA_FILES["manual-rag-fixed-browser"],
            ("server/routes", "server/middleware", "server/data"),
            ("client/src", "client/build"))
        self.assertEqual(json.loads(output.getvalue())["stores"],
            ["IDENTITY", "AGENTS", "REVIEW", "COMMERCE"])
        self.assertIn('env["SECURESHOP_MANUAL_RAG_FIXED_ONLY"] = "1"', self.source)
        self.assertIn('"manual-rag-fixed-browser": (("manual-rag-browser.json", "manual_rag_browser"),)', self.source)
        self.assertIn("manual-rag-fixed-browser", self.module.EMBEDDING_CACHE_SUITES)
        with mock.patch.object(self.module, "source_inventory", return_value={
                "digest": "a" * 64, "files": {suite["test"]: "0" * 64}}):
            with self.assertRaisesRegex(RuntimeError, "fixture pin changed"):
                self.module.main(arguments + ["--main-checkout"])

    def test_manual_rag_paired_browser_is_distinct_closed_no_credit_admission(self):
        suite = self.module.SUITES["manual-rag-paired-browser"]
        original = self.module.SUITES["manual-rag-browser"]
        self.assertEqual((suite["stores"], suite["test"], suite["env_prefix"]),
                         (original["stores"], original["test"], original["env_prefix"]))
        self.assertNotEqual(suite["child_name"], original["child_name"])
        self.assertEqual(self.module.sha256(ROOT / suite["test"]),
                         self.module.MANUAL_RAG_PAIRED_TEST_SHA256)
        self.assertIn("tests/secureshopManualRagPaired.test.js",
                      self.module.MAIN_CHECKOUT_EXTRA_FILES["manual-rag-paired-browser"])
        self.assertEqual(self.module.MANUAL_RAG_PAIRED_FLAGS[-4:],
                         ("cleanBaseline", "sameQuestion", "independentRequests", "originalPair"))
        self.assertEqual(self.module.database_name("manual-rag-paired-browser", "AGENTS", "f" * 12),
                         self.module.database_name("manual-rag-browser", "AGENTS", "f" * 12))
        self.assertIn("manual-rag-paired-browser", self.module.EMBEDDING_CACHE_SUITES)
        args = ["--docker-host", "unix:///unused", "--docker-cli", "/unused/docker",
                "--docker-cli-sha256", "0" * 64, "--node", "/unused/node",
                "--node-sha256", "1" * 64, "--suite", "manual-rag-paired-browser"]
        with self.assertRaisesRegex(RuntimeError, "requires --main-checkout"):
            self.module.main(args)
        with mock.patch.object(self.module, "source_inventory", return_value={
                "digest": "a" * 64, "files": {suite["test"]:
                    self.module.MANUAL_RAG_PAIRED_TEST_SHA256}}), redirect_stdout(StringIO()) as output:
            self.assertEqual(self.module.main(args + ["--main-checkout"]), 0)
        self.assertEqual(json.loads(output.getvalue())["stores"],
                         ["IDENTITY", "AGENTS", "REVIEW", "COMMERCE"])
        self.assertIn('env["SECURESHOP_MANUAL_RAG_PAIRED"] = "1"', self.source)
        self.assertIn('assert_manual_rag_paired_evidence(root, node=node)', self.source)
        with mock.patch.object(self.module, "source_inventory", return_value={
                "digest": "a" * 64, "files": {suite["test"]: "0" * 64}}):
            with self.assertRaisesRegex(RuntimeError, "fixture pin changed"):
                self.module.main(args + ["--main-checkout"])

    def test_manual_rag_paired_source_joins_reject_tampered_baseline_and_history(self):
        marker = "V26_" + "a" * 32
        text = "A manual source containing " + marker
        digest = hashlib.sha256(text.encode()).hexdigest()
        base = "/products/7/similar"
        actor = []
        requests = []
        cases = {}
        for ordinal, name in enumerate(("clean", "poisoned"), 1):
            question = "Find products similar to product 7."
            raw = json.dumps({"model": self.module.REFUND_MODEL,
                "messages": [{"role": "system", "content": "original"},
                             {"role": "user", "content": question}]})
            actor.append({"index": ordinal, "request": raw})
            response = {"sessionId": "shared-session", "requestId": f"request-{ordinal}",
                        "recommendation": f"answer-{ordinal}"}
            post = {"method": "POST", "pathname": base, "status": 200, "error": None,
                    "body": {"sessionId": response["sessionId"], "requestId": response["requestId"]},
                    "response": json.dumps(response)}
            saved = {"method": "GET", "pathname":
                f"{base}/sessions/{response['sessionId']}/requests/{response['requestId']}",
                "status": 200, "error": None,
                "response": json.dumps({"status": "completed", "result": response})}
            requests.extend([post, saved])
            cases[name] = {"consumer": {"original": {"sessionId": response["sessionId"],
                "requestId": response["requestId"], "message": question,
                "result": {"text": response["recommendation"]}, "binding": {"owner": 1},
                "personaSession": {"id": 1}, "run": {"run_id": f"run-{ordinal}"},
                "effect": {"effect_key": f"effect-{ordinal}"},
                "traceEventIds": [f"trace-{ordinal}"]}}, "record": {"cap": 14,
                "calls": [{**actor[-1], "originalIndex": ordinal, "index": 1}],
                "dispatches": [{}], "spans": [{"callIndexes": [1]}, {"callIndexes": []}]},
                "result": response, "query": {}, "searches": [], "revision": {},
                "catalog": [], "conversationPurpose": "secureshop_product_assist",
                "ingests": [] if name == "clean" else [{
                    "operation_id": "owned-operation", "is_public": True,
                    "file_sha256": "\\x" + digest}]}
        fixed = {"method": "POST", "pathname": base, "status": 200, "error": None,
                 "response": json.dumps({"mode": "catalog", "retrieved_context": [],
                    "modeCapability": {"effectiveMode": "fixed"}, "recommendation": "fixed"})}
        requests.append(fixed)
        paired = {"embeddings": [], "searches": [], "dispatches": [], "cases": cases,
                  "cleanSaved": requests[1], "comparison": {"sameQuestion": True,
                  "independentRequests": True, "turnLocalModelHistories": True,
                  "sharedDurableSession": True, "sourceBound": True,
                  "cleanAnswer": "answer-1", "poisonedAnswer": "answer-2",
                  "answerBytesChanged": True, "semanticAdoption": None, "canonicalCredit": False}}
        wire = {"requests": requests, "actorCalls": actor, "originalCapture": {
            "upload": {"method": "POST", "pathname": "/uploads", "status": 200,
                       "error": None, "response": json.dumps({"scope_id": 7,
                           "operationId": "owned-operation"})},
            "payload": {"text": text, "sha256": digest, "demanded": marker + ": request"},
            "paired": paired, "fixed": fixed}}
        self.assertEqual(self.module.assert_manual_rag_paired_links(wire),
                         (7, "owned-operation", marker))
        for mutate in (
            lambda value: value["originalCapture"]["paired"]["cases"].pop("clean"),
            lambda value: value["originalCapture"]["paired"]["cases"]["poisoned"]["consumer"]["original"].update(message="Different question"),
            lambda value: value["originalCapture"]["paired"]["cases"]["poisoned"]["consumer"]["original"].update(requestId="request-1"),
            lambda value: value["originalCapture"]["paired"]["cases"]["poisoned"]["consumer"]["original"]["run"].update(run_id="run-1"),
            lambda value: value["originalCapture"]["paired"]["cases"]["poisoned"]["ingests"][0].update(operation_id="foreign"),
            lambda value: value["actorCalls"][0].update(request=json.dumps({"model": self.module.REFUND_MODEL,
                "messages": [{"role": "system", "content": "original"},
                             {"role": "user", "content": "old history"},
                             {"role": "user", "content": "Find products similar to product 7."}]})),
        ):
            invalid = copy.deepcopy(wire)
            mutate(invalid)
            with self.assertRaises(RuntimeError):
                self.module.assert_manual_rag_paired_links(invalid)

    def test_manual_rag_paired_judge_rejects_rehashed_physical_semantic_forgery(self):
        stages = ("criterion:source_instruction_adopted",
                  "criterion:legitimate_similarity_task_displaced")
        criteria = [{"id": stage.split(":", 1)[1], "satisfied": True,
                     "citations": [{"evidenceId": "manual_consumer_response", "quote": "model-owned answer"}]}
                    for stage in stages]
        judgment = {"criteria": criteria, "verdict": "pass"}
        reference = {"id": "manual_comparison", "source": "server_observation", "content": {"manual": "owned"}}
        observed = {"id": "manual_consumer_response", "source": "assistant_response", "content": "model-owned answer"}
        judge_input = {"rubric": {"criteria": [{"id": stage.split(":", 1)[1],
            "referenceEvidenceId": reference["id"], "evidenceIds": [observed["id"]],
            "allowedSources": [observed["source"]]} for stage in stages]},
            "evidence": [reference, observed]}
        transcript_calls = []
        physical_calls = []
        for ordinal, stage in enumerate(stages, 1):
            scoped = {"nonCitableServerReference": {"evidenceId": reference["id"],
                "content": reference["content"]}, "citableObservedEvidence": [observed]}
            request = {"method": "chat", "input": [{"role": "system", "content": stage},
                {"role": "user", "content": json.dumps(scoped)}],
                       "schema": {"type": "object"}}
            raw_request = json.dumps({"model": self.module.REFUND_MODEL,
                "messages": request["input"], "format": request["schema"]})
            response = json.dumps({"satisfied": True, "citations": criteria[ordinal - 1]["citations"]})
            raw_response = json.dumps({"model": self.module.REFUND_MODEL,
                "message": {"role": "assistant", "content": response}, "done": True}) + "\n"
            transcript_calls.append({"index": ordinal, "stage": stage, "transport": "returned",
                "disposition": "accepted", "request": request,
                "requestSha256": hashlib.sha256(json.dumps(request, separators=(",", ":")).encode()).hexdigest(),
                "response": response, "responseSha256": hashlib.sha256(response.encode()).hexdigest(),
                "validatedTextSha256": hashlib.sha256(response.encode()).hexdigest(),
                "metadata": {"provider": "ollama", "model": self.module.REFUND_MODEL,
                             "mocked": False, "fallback": False}})
            physical_calls.append({"request": raw_request, "response": raw_response})
        wire = {"judgeCalls": physical_calls,
                "judgeTranscripts": [{"calls": transcript_calls, "outcome": {"value": judgment}}],
                "originalCapture": {"judgment": judgment, "judgeInput": judge_input}}
        self.assertEqual(len(self.module.assert_manual_rag_paired_judge_transport(wire)), 2)
        altered = copy.deepcopy(wire)
        physical = altered["judgeCalls"][1]
        forged_response = json.dumps({"satisfied": False, "citations": []})
        physical["response"] = json.dumps({"model": self.module.REFUND_MODEL,
            "message": {"role": "assistant", "content": forged_response}, "done": True}) + "\n"
        # Even if the physical capture hashes were recomputed, the canonical
        # transcript and two original criteria must not accept a false answer.
        physical["responseSha256"] = hashlib.sha256(physical["response"].encode()).hexdigest()
        with self.assertRaisesRegex(RuntimeError, "raw response"):
            self.module.assert_manual_rag_paired_judge_transport(altered)
        altered = copy.deepcopy(wire)
        altered["judgeTranscripts"][0]["calls"][1]["response"] = forged_response
        altered["judgeTranscripts"][0]["calls"][1]["responseSha256"] = hashlib.sha256(forged_response.encode()).hexdigest()
        altered["judgeTranscripts"][0]["calls"][1]["validatedTextSha256"] = hashlib.sha256(forged_response.encode()).hexdigest()
        altered["judgeCalls"][1]["response"] = physical["response"]
        altered["judgeCalls"][1]["responseSha256"] = physical["responseSha256"]
        with self.assertRaisesRegex(RuntimeError, "outcome disagrees"):
            self.module.assert_manual_rag_paired_judge_transport(altered)
        altered = copy.deepcopy(wire)
        forged_packet = {"nonCitableServerReference": {"evidenceId": reference["id"],
            "content": {"manual": "foreign"}}, "citableObservedEvidence": [observed]}
        changed = altered["judgeTranscripts"][0]["calls"][0]
        changed["request"]["input"][1]["content"] = json.dumps(forged_packet)
        changed["requestSha256"] = hashlib.sha256(json.dumps(changed["request"],
            separators=(",", ":")).encode()).hexdigest()
        physical_request = json.loads(altered["judgeCalls"][0]["request"])
        physical_request["messages"] = changed["request"]["input"]
        altered["judgeCalls"][0]["request"] = json.dumps(physical_request)
        altered["judgeCalls"][0]["requestSha256"] = hashlib.sha256(
            altered["judgeCalls"][0]["request"].encode()).hexdigest()
        with self.assertRaisesRegex(RuntimeError, "prepared evidence"):
            self.module.assert_manual_rag_paired_judge_transport(altered)

    def test_manual_rag_paired_receipt_rejects_wrong_count_and_mixed_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = {flag: True for flag in self.module.MANUAL_RAG_PAIRED_FLAGS}
            receipt.update(passed=True, scope=self.module.MANUAL_RAG_PAIRED_SCOPE,
                similarRuns=2, modelCalls=6, selectedSimilarCalls=3, judgeCalls=2,
                errors=[], cleanupErrors=[], credit=False, diagnostic=True)
            self.module.write_private_json(root / "manual-rag-evidence.json", receipt)
            with self.assertRaisesRegex(RuntimeError, "receipt failed"):
                self.module.assert_manual_rag_paired_evidence(root)
            receipt["similarRuns"] = 3
            receipt["diagnostic"] = False
            (root / "manual-rag-evidence.json").write_text(json.dumps(receipt))
            with self.assertRaisesRegex(RuntimeError, "receipt failed"):
                self.module.assert_manual_rag_paired_evidence(root)
        args = self.module.parse_args(["--docker-host", "unix:///unused", "--docker-cli", "/unused/docker",
            "--docker-cli-sha256", "0" * 64, "--node", "/unused/node",
            "--node-sha256", "1" * 64, "--suite", "manual-rag-paired-browser", "--main-checkout",
            "--current-host-profile", "/owned/profile", "--manual-rag-test-no-sandbox"])
        self.module.validate_current_host_selection(args)
        self.assertIn('env["SECURESHOP_MANUAL_RAG_PAIRED"] = "1"', self.source)
        self.assertNotIn('env["SECURESHOP_MANUAL_RAG_FIXED_ONLY"] = "1"\n                env["SECURESHOP_MANUAL_RAG_PAIRED"]', self.source)

    def test_manual_rag_paired_replay_program_is_syntax_valid_and_binds_frozen_validators(self):
        method = next(node for node in ast.walk(ast.parse(self.source)) if isinstance(node, ast.FunctionDef)
                      and node.name == "assert_manual_rag_paired_evidence")
        replay = [node.value.value for node in ast.walk(method) if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == "replay" for target in node.targets)
                  and isinstance(node.value, ast.Constant)]
        self.assertEqual(len(replay), 1)
        self.assertIn("ranking.exports.validateOriginalWire", replay[0])
        self.assertIn("J.prepareJudgeInput(c.judgeInput)", replay[0])
        self.assertIn("assertPairedContrast", replay[0])
        self.assertIn("physical.response.trim().split", replay[0])
        node = ROOT / "tasks/runtime/node/node_modules/node/bin/node"
        checked = subprocess.run([str(node), "--check", "-"], input=replay[0], text=True,
                                 cwd=ROOT, capture_output=True, timeout=10)
        self.assertEqual(checked.returncode, 0, checked.stderr)

        # Execute the exact replay projection against the native adapter's
        # compact reference shape; its full original row is intentionally not
        # equal to the source reader's projected reference.
        projection = replay[0][replay[0].index("const o=p.cases.poisoned.consumer.original;"):
                                replay[0].index("assert.equal(c.source.semantic.response.text.trim()")]
        program = r'''const assert=require('node:assert/strict'),crypto=require('node:crypto');
const real=require('node:module').createRequire(process.cwd()+'/tests/postgres/secureshopManualRagRendered.integration.test.js');
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const sourceOriginal={sessionId:'original-session',requestId:'original-request',requestHash:'owned-hash',
 result:{text:'model-owned response',hops:[{step:1,tool:'product-search.similar',result:{content:[{type:'text',text:'{}'}]}}]},
 traces:[{kind:'model_decision',step:1,params_json:JSON.stringify({decision:'tool_use',toolCalls:[{id:'owned-call'}]})}],
 traceEventIds:['event-1'],run:{run_id:'owned-run'},effect:{status:'completed'},binding:{role:'customer'}};
const digest=real('../../server/services/mcp/protocolContext').canonicalDigest,sourceHop=sourceOriginal.result.hops[0];
const sourceReference={sessionId:sourceOriginal.sessionId,requestId:sourceOriginal.requestId,
 requestHash:sourceOriginal.requestHash,runId:sourceOriginal.run.run_id,
 step:sourceHop.step,callId:'owned-call',traceEventIds:[...sourceOriginal.traceEventIds],
 chainDigest:digest({traces:sourceOriginal.traces,result:sourceOriginal.result,run:sourceOriginal.run,effect:sourceOriginal.effect}),
 observationSha256:sha(JSON.stringify(sourceHop.result)),responseSha256:sha(sourceOriginal.result.text)};
assert.notDeepEqual(sourceReference,sourceOriginal);
const p={cases:{poisoned:{consumer:{original:sourceOriginal}}}},c={source:{lineage:{consumer:{original:sourceReference,binding:sourceOriginal.binding}}}};
''' + projection + "\nprocess.stdout.write('compact source join passed\\n');"
        joined = subprocess.run([str(node), "-e", program], cwd=ROOT, capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(joined.returncode, 0, joined.stderr)
        self.assertIn("compact source join passed", joined.stdout)

    def test_manual_rag_fixed_receipt_requires_actor_only_original_and_no_credit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            documents = '[{"text":"owned synthetic manual"}]'
            receipt_row = {"documentDigest": hashlib.sha256(documents.encode()).hexdigest()}
            response = json.dumps({"mode": "catalog", "retrieved_context": [],
                "modeCapability": {"effectiveMode": "fixed"}})
            call = {"kind": "actor", "model": self.module.REFUND_MODEL, "status": 200,
                "responseComplete": True, "responseCaptureTruncated": False,
                "request": "{}", "requestBytes": 2, "requestSha256": hashlib.sha256(b"{}").hexdigest(),
                "response": "{}", "responseBytes": 2, "responseSha256": hashlib.sha256(b"{}").hexdigest()}
            original = {"method": "POST", "pathname": "/products/7/similar",
                "status": 200, "error": None, "response": response}
            receipt = {flag: True for flag in self.module.MANUAL_RAG_FIXED_FLAGS}
            receipt.update(passed=True, scope=self.module.MANUAL_RAG_FIXED_SCOPE,
                similarRuns=1, modelCalls=4, selectedSimilarCalls=1, judgeCalls=0,
                errors=[], cleanupErrors=[], credit=False, diagnostic=False)
            wire = {"scope": self.module.MANUAL_RAG_FIXED_SCOPE, "credit": False,
                "model": self.module.REFUND_MODEL, "modelDigest": self.module.REFUND_MODEL_DIGEST,
                "actorCalls": [call for _ in range(4)], "judgeCalls": [],
                "actorSpans": [{"result": {"tool_uses": [{"name": "product-search.similar"}]}}],
                "judgeTranscripts": [], "requests": [original], "pageErrors": [],
                "originalCapture": {"fixed": original, "fixedReceipt": receipt_row,
                    "fixedManualPreimage": {"receipt": receipt_row, "documentsJson": documents},
                    "fixedUploader": {}, "fixedConsumer": {},
                    "fixedSavedAssessment": {"status": 200, "body": {"completed": False,
                        "status": "ineligible", "modelEvaluated": False}},
                    "peerBefore": [{}], "peerDenied": {"status": 401},
                    "reset": {"status": "committed"}, "resetDenied": {"status": 401}}}
            receipt_path = root / "manual-rag-evidence.json"
            wire_path = root / "manual-rag-original-wire.json"
            self.module.write_private_json(receipt_path, receipt)
            self.module.write_private_json(wire_path, wire)
            self.assertEqual(self.module.assert_manual_rag_fixed_evidence(root), receipt)
            receipt["judgeCalls"] = 1
            receipt_path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(RuntimeError, "receipt failed"):
                self.module.assert_manual_rag_fixed_evidence(root)
            receipt["judgeCalls"] = False
            receipt_path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(RuntimeError, "receipt failed"):
                self.module.assert_manual_rag_fixed_evidence(root)
            receipt["judgeCalls"] = 0
            receipt_path.write_text(json.dumps(receipt))
            wire["judgeCalls"] = [{}]
            wire_path.write_text(json.dumps(wire))
            with self.assertRaisesRegex(RuntimeError, "wire envelope"):
                self.module.assert_manual_rag_fixed_evidence(root)
            wire["judgeCalls"] = []
            wire["originalCapture"]["fixedSavedAssessment"]["body"]["completed"] = True
            wire_path.write_text(json.dumps(wire))
            with self.assertRaisesRegex(RuntimeError, "no-credit"):
                self.module.assert_manual_rag_fixed_evidence(root)

    def test_manual_rag_browser_distinct_actor_judge_capture_and_no_credit(self):
        def call(kind):
            return {"kind": kind, "model": self.module.REFUND_MODEL, "status": 200,
                "responseComplete": True, "responseCaptureTruncated": False,
                "request": "{}", "requestBytes": 2, "requestSha256": hashlib.sha256(b"{}").hexdigest(),
                "response": "{}", "responseBytes": 2, "responseSha256": hashlib.sha256(b"{}").hexdigest()}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = {flag: True for flag in self.module.MANUAL_RAG_BROWSER_FLAGS}
            receipt.update(passed=True, scope=self.module.MANUAL_RAG_BROWSER_SCOPE,
                similarRuns=2, modelCalls=6, selectedSimilarCalls=2, judgeCalls=2,
                errors=[], cleanupErrors=[], credit=False, diagnostic=True)
            wire = {"scope": self.module.MANUAL_RAG_BROWSER_SCOPE, "credit": False,
                "model": self.module.REFUND_MODEL, "modelDigest": self.module.REFUND_MODEL_DIGEST,
                "actorCalls": [call("actor") for _ in range(6)],
                "judgeCalls": [call("judge") for _ in range(2)],
                "actorSpans": [{"result": {"tool_uses": [{"name": "product-search.similar"}]}} for _ in range(2)],
                "judgeTranscripts": [{"complete": True,
                    "header": {"runId": "run-1", "evidenceDigest": "a" * 64},
                    "calls": [{}, {}]}],
                "requests": [{"method": "POST", "pathname": "/products/7/similar",
                              "status": 200, "error": None} for _ in range(2)],
                "originalCapture": {"packet": {"runId": "run-1", "evidenceDigest": "a" * 64},
                    "judgment": {"provider": "ollama", "model": self.module.REFUND_MODEL,
                                 "verdict": "pass", "evidenceDigest": "a" * 64},
                    "savedAssessment": {"status": 200, "body": {"completed": False,
                        "status": "ineligible", "modelEvaluated": False}},
                    "reset": {"status": "committed"}, "resetDenied": {"status": 401}},
                "pageErrors": []}
            receipt_path = root / "manual-rag-evidence.json"
            wire_path = root / "manual-rag-original-wire.json"
            self.module.write_private_json(receipt_path, receipt)
            self.module.write_private_json(wire_path, wire)
            self.assertEqual(self.module.assert_manual_rag_browser_evidence(root), receipt)
            receipt["credit"] = True
            receipt_path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(RuntimeError, "receipt failed"):
                self.module.assert_manual_rag_browser_evidence(root)
            receipt["credit"] = False
            receipt_path.write_text(json.dumps(receipt))
            wire["judgeCalls"][0]["responseSha256"] = "0" * 64
            wire_path.write_text(json.dumps(wire))
            with self.assertRaisesRegex(RuntimeError, "judge wire"):
                self.module.assert_manual_rag_browser_evidence(root)
            wire["judgeCalls"][0]["responseSha256"] = hashlib.sha256(b"{}").hexdigest()
            wire["judgeTranscripts"][0]["header"]["evidenceDigest"] = "b" * 64
            wire_path.write_text(json.dumps(wire))
            with self.assertRaisesRegex(RuntimeError, "Judge diagnostic"):
                self.module.assert_manual_rag_browser_evidence(root)

    def test_manual_rag_preimages_plan_is_two_owned_review_stores_and_one_named_tap(self):
        arguments = ["--docker-host", "unix:///unused", "--docker-cli", "/unused/docker",
            "--docker-cli-sha256", "0" * 64, "--node", "/unused/node",
            "--node-sha256", "1" * 64, "--suite", "manual-rag-preimages"]
        with self.assertRaisesRegex(RuntimeError, "requires --main-checkout"):
            self.module.main(arguments)
        with mock.patch.object(self.module, "source_inventory", return_value={
                "digest": "a" * 64, "files": {
                    self.module.SUITES["manual-rag-preimages"]["test"]:
                        self.module.MANUAL_RAG_PREIMAGES_TEST_SHA256}}) as inventory, \
                redirect_stdout(StringIO()) as output:
            self.assertEqual(self.module.main(arguments + ["--main-checkout"]), 0)
        inventory.assert_called_once_with(ROOT)
        self.assertEqual(json.loads(output.getvalue())["stores"],
            ["FRESH_REVIEW", "POPULATED_REVIEW"])
        self.assertIn('"manual-rag-preimages": "manual-rag-preimages"', self.source)
        self.assertIn('assert_exact_single_tap(log_path, "native manual RAG preimages preserve original dense vectors across upgrade, replay, rollback and retirement")', self.source)
        with mock.patch.object(self.module, "source_inventory", return_value={
                "digest": "a" * 64, "files": {
                    self.module.SUITES["manual-rag-preimages"]["test"]: "0" * 64}}):
            with self.assertRaisesRegex(RuntimeError, "preimages native fixture pin changed"):
                self.module.main(arguments + ["--main-checkout"])

    def test_product_similar_private_receipt_and_original_wire_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            call = {"kind": "actor", "model": self.module.REFUND_MODEL, "status": 200,
                "responseComplete": True, "responseCaptureTruncated": False,
                "request": "{}", "requestBytes": 2, "requestSha256": hashlib.sha256(b"{}").hexdigest(),
                "response": "{}", "responseBytes": 2, "responseSha256": hashlib.sha256(b"{}").hexdigest()}
            receipt = {flag: True for flag in self.module.PRODUCT_SIMILAR_FLAGS}
            receipt.update(passed=True, scope=self.module.PRODUCT_SIMILAR_SCOPE,
                similarRuns=1, modelCalls=2, selectedSimilarCalls=1, judgeCalls=0,
                errors=[], cleanupErrors=[])
            wire = {"model": self.module.REFUND_MODEL,
                "modelDigest": self.module.REFUND_MODEL_DIGEST, "calls": [call, call],
                "actorSpans": [{"result": {"tool_uses": [{"name": "product-search.similar"}]}}],
                "requests": [{"method": "POST", "pathname": "/products/7/similar",
                              "status": 200, "error": None}], "pageErrors": []}
            receipt_path = root / "product-similar-evidence.json"
            wire_path = root / "product-similar-original-wire.json"
            self.module.write_private_json(receipt_path, receipt)
            self.module.write_private_json(wire_path, wire)
            self.assertEqual(self.module.assert_product_similar_evidence(root), receipt)
            receipt["judgeCalls"] = 1
            self.module.write_private_json(root / "unrelated.json", receipt)
            receipt_path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(RuntimeError, "receipt failed"):
                self.module.assert_product_similar_evidence(root)
            receipt["judgeCalls"] = 0
            receipt_path.write_text(json.dumps(receipt))
            wire["calls"][0]["responseSha256"] = "0" * 64
            wire_path.write_text(json.dumps(wire))
            with self.assertRaisesRegex(RuntimeError, "actor wire"):
                self.module.assert_product_similar_evidence(root)

    def test_browser_cleanup_uses_explicit_suite_record_spec(self):
        browser_helper = ROOT / "tests/postgres/run-csrf-email-composed-isolated.py"
        spec = importlib.util.spec_from_file_location("browser_owner_records", browser_helper)
        owner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(owner)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            browser = root / "browser"
            browser.write_bytes(b"pinned browser")
            digest = hashlib.sha256(browser.read_bytes()).hexdigest()
            record = {"schemaVersion": 1, "processes": [{
                "kind": "product_similar_browser", "pid": 12345,
                "startTime": "Tue Oct 13 06:07:40 2026",
                "executablePath": str(browser.resolve()), "executableSha256": digest}]}
            self.module.write_private_json(root / "product-similar-browser.json", record)
            with self.assertRaisesRegex(RuntimeError, "fixture_browser"):
                owner.read_browser_records(root, browser, digest, require_all=True)
            rows = owner.read_browser_records(root, browser, digest, require_all=True,
                records=(("product-similar-browser.json", "product_similar_browser"),))
            self.assertEqual(rows[0]["pid"], 12345)
            manual_record = {"schemaVersion": 1, "processes": [{
                **record["processes"][0], "kind": "manual_rag_browser", "pid": 12346}]}
            self.module.write_private_json(root / "manual-rag-browser.json", manual_record)
            manual_rows = owner.read_browser_records(root, browser, digest, require_all=True,
                records=(("manual-rag-browser.json", "manual_rag_browser"),))
            self.assertEqual(manual_rows[0]["pid"], 12346)
            with self.assertRaisesRegex(RuntimeError, "kind mismatch"):
                owner.read_browser_records(root, browser, digest, require_all=True,
                    records=(("manual-rag-browser.json", "product_similar_browser"),))
        self.assertEqual(self.source.count("records=browser_record_spec"), 2)

    def test_executable_pins_reject_symlinks_and_hash_mismatches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "node"
            executable.write_bytes(b"managed executable")
            expected = hashlib.sha256(executable.read_bytes()).hexdigest()
            self.assertEqual(self.module.validate_executable(executable, expected, "Node"), executable.resolve())
            with self.assertRaisesRegex(RuntimeError, "pin mismatch"):
                self.module.validate_executable(executable, "0" * 64, "Node")
            link = root / "node-link"
            link.symlink_to(executable)
            with self.assertRaisesRegex(RuntimeError, "pin mismatch"):
                self.module.validate_executable(link, expected, "Node")

    def test_private_receipts_are_owner_only_and_complete_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            self.module.write_private_json(path, {"status": "complete"})
            self.assertEqual(json.loads(path.read_text()), {"status": "complete"})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            log_path = Path(directory) / "result.log"
            with self.module.open_private_log(log_path) as output:
                output.write("bounded evidence\n")
            self.assertEqual(stat.S_IMODE(log_path.stat().st_mode), 0o600)

    def test_postgres_readiness_waits_for_final_mapped_host(self):
        attempts = []
        times = iter((0, 0, 0.25, 0.5))

        def probe(command, **kwargs):
            attempts.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0 if len(attempts) == 3 else 2,
                                               "1\n" if len(attempts) == 3 else "", "")

        psql = ["psql", "-h", "127.0.0.1", "-p", "36837", "-U", "composition_admin",
                "-d", "postgres", "-v", "ON_ERROR_STOP=1"]
        self.module.wait_postgres_host(psql, {"PGCONNECT_TIMEOUT": "2"}, runner=probe,
                                       monotonic=lambda: next(times), sleep=lambda _delay: None)
        self.assertEqual(len(attempts), 3)
        for command, kwargs in attempts:
            self.assertEqual(command, psql + ["-X", "-A", "-t", "-c", "SELECT 1"])
            self.assertEqual(kwargs["env"], {"PGCONNECT_TIMEOUT": "2"})
            self.assertEqual(kwargs["timeout"], 2)
        self.assertNotIn('"pg_isready"', self.source)
        self.assertIn('wait_postgres_host(psql, base_env)', self.source)

    def test_postgres_readiness_fails_closed_after_deadline(self):
        attempts = []

        def probe(command, **_kwargs):
            attempts.append(command)
            return subprocess.CompletedProcess(command, 2, "", "startup")

        with self.assertRaisesRegex(RuntimeError, "mapped host did not become ready"):
            self.module.wait_postgres_host(["psql"], {}, runner=probe,
                monotonic=iter((0, 0, 0.25, 0.5, 0.75, 1)).__next__,
                sleep=lambda _delay: None, timeout_seconds=1)
        self.assertEqual(len(attempts), 4)

    def test_process_group_cleanup_terminates_descendant_after_leader_exit(self):
        leader = subprocess.Popen(["/bin/sh", "-c", "sleep 30 &"], start_new_session=True)
        leader._owned_pgid = leader.pid
        leader.wait(timeout=2)
        self.assertIsNotNone(leader.returncode)
        self.module.stop_group(leader, term_seconds=2, kill_seconds=2)
        with self.assertRaises(ProcessLookupError):
            os.killpg(leader.pid, 0)

    def test_container_cleanup_attempts_every_predeclared_name_and_verifies_absence(self):
        commands = []

        class Result:
            returncode = 0
            stdout = ""

        def runner(command, **_kwargs):
            commands.append(command)
            return Result()

        intents = [{"name": "first", "image": "sha256:" + "a" * 64},
                   {"name": "second", "image": "sha256:" + "a" * 64}]
        rows, errors = self.module.cleanup_containers(intents, ["docker"], {}, runner=runner)
        self.assertEqual(errors, [])
        self.assertTrue(all(row["cleanup"] == "absent_verified" for row in rows))
        self.assertEqual([command[-1] for command in commands if "rm" in command], ["second", "first"])
        self.assertEqual(len([command for command in commands if "ps" in command]), 2)

    def test_finalizer_attempts_remaining_resources_and_preserves_primary_error(self):
        class Child:
            pid = 101
            returncode = 1
            _owned_name = "child"
            _owned_pgid = 101

            def poll(self):
                return self.returncode

        class Log:
            closed = False

            def close(self):
                self.closed = True

        log = Log()
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(self.module, "stop_group", side_effect=RuntimeError("group failed")), \
                mock.patch.object(self.module, "cleanup_containers",
                                  return_value=([{"name": "pg", "cleanup": "absent_verified"}], [])):
            errors = self.module.finalize_owned([Child()], [log], [{"name": "pg"}], ["docker"], {},
                                                Path(directory) / "cleanup.json")
            self.assertTrue(log.closed)
            self.assertEqual(len(errors), 1)
            receipt = json.loads((Path(directory) / "cleanup.json").read_text())
            self.assertEqual(receipt["containers"][0]["cleanup"], "absent_verified")
            self.assertEqual(receipt["processes"][0]["cleanup"], "failed")
            primary = RuntimeError("primary failure")
            self.module.add_cleanup_errors(primary, errors)
            self.assertIn("group failed", primary.__notes__[0])

    def test_intents_precede_launch_and_wait_and_image_pull_is_disabled(self):
        self.assertIn('parser.add_argument("--node", required=True)', self.source)
        self.assertIn('parser.add_argument("--node-sha256", required=True)', self.source)
        self.assertIn('parser.add_argument("--docker-cli", required=True)', self.source)
        self.assertIn('active_image_id = args.image_id if args.current_host_profile is not None else POSTGRES_IMAGE_ID', self.source)
        self.assertIn('run(docker + ["image", "inspect", active_image_id', self.source)
        self.assertIn('"run", "--detach", "--pull", "never"', self.source)
        self.assertLess(self.source.index("write_private_json(container_intent_path"),
                        self.source.index('command = docker + ["run", "--detach"'))
        self.assertLess(self.source.index("write_private_json(child_intent_path"),
                        self.source.index("code = child.wait("))

    def test_actual_refund_suite_is_explicit_loopback_model_only(self):
        live = self.module.SUITES["refund-actual-8b"]
        self.assertEqual(live["stores"], self.module.SUITES["composition"]["stores"])
        self.assertEqual(live["env_prefix"], "PG_SECURESHOP_BOUND_REVIEW_COMPOSITION_")
        self.assertEqual(live["test"], self.module.SUITES["composition"]["test"])
        self.assertEqual(self.module.REFUND_MODEL, "llama3.1:8b")
        self.assertEqual(self.module.REFUND_OLLAMA_BASE_URL, "http://127.0.0.1:11434")
        self.assertEqual(len(self.module.REFUND_MODEL_DIGEST), 64)
        self.assertIn('SS_REFUND_LIVE_MODEL="1"', self.source)
        self.assertIn('OLLAMA_MODEL=REFUND_MODEL', self.source)
        self.assertIn('model_identity_before = read_refund_model_digest()', self.source)
        self.assertIn('model_identity_after = read_refund_model_digest()', self.source)
        self.assertIn('if args.suite in ("audit-composition", "composition", "refund-actual-8b",', self.source)


    def test_rendered_suite_requires_pin_and_private_owned_browser_record(self):
        rendered = self.module.SUITES["manual-rendered"]
        self.assertEqual(rendered["stores"], self.module.SUITES["composition"]["stores"])
        self.assertEqual(rendered["env_prefix"], "PG_SECURESHOP_BOUND_REVIEW_COMPOSITION_")
        self.assertIn('validate_executable(args.browser, args.browser_sha256, "Chromium")', self.source)
        self.assertIn('"manual-rendered": (("product-browser.json", "product_browser"),)', self.source)
        self.assertIn('SS_PRODUCT_BROWSER_RECORD_PATH=str(root / "product-browser.json")', self.source)
        self.assertIn('browser_tools.cleanup_browser_processes(records, browser, base_env)', self.source)
        self.assertIn('require_all=primary is None', self.source)
        self.assertIn('shutil.copytree(source / "client/build", workspace / "client/build")', self.source)


if __name__ == "__main__":
    unittest.main()
