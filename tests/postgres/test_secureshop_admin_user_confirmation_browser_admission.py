"""Controlled mail-actions admission; never starts a model, browser or database."""
import argparse
import ast
import contextlib
import importlib.util
import io
import json
import os
import re
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


def module(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


L = module('run-secureshop-admin-user-confirmation-browser.py', 'mail_actions_controlled')
C = module('run_admin_user_confirmation_with_inspector.py', 'mail_actions_outer_controlled')


def arguments(mode='--plan'):
    values = {key: 'controlled' for key in C.REQUIRED}
    values.update({'--main-workspace': str(C.ROOT), '--cohort': C.COHORT,
        '--evidence-parent': str(C.ROOT / 'tasks/qualification'),
        '--ollama-model-sha256': C.MODEL_SHA256,
        '--build-report': str(C.ROOT / 'tasks/qualification/frontend-build-controlled/report.json'),
        '--build-report-sha256': '1' * 64,
        '--build-input-sha256': '2' * 64,
        '--build-output-sha256': '3' * 64,
        '--build-recorder-sha256': '4' * 64})
    if mode == '--run':
        values['--expected-snapshot-sha256'] = 'a' * 64
    return [mode, C.OPT_IN, *(item for key, value in sorted(values.items())
                              for item in (key, value))]


def parsed():
    return SimpleNamespace(node='/controlled/node', browser='/controlled/chrome',
                           browser_sha256='b' * 64, browser_root='/controlled/browser',
                           plan=False, policy_renderer_admission=None)


def environment():
    run = L.ROOT / 'tasks/qualification/run-mail-controlled'
    return {
        L.NATIVE_ENV: '1', L.EVIDENCE_ENV: str(run / L.RECEIPT),
        'LIVE_OLLAMA_TEST': '1', 'PG_TEST_DISPOSABLE': 'yes', 'NODE_ENV': 'test',
        'LAB_MODE': 'vuln', 'TMPDIR': str(run / 'runtime/tmp'),
        'OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE': str(L.ROOT),
        'OLLAMA_BASE_URL': 'http://127.0.0.1:11434', 'OLLAMA_MODEL': 'llama3.1:8b',
        'PUPPETEER_EXECUTABLE_PATH': parsed().browser,
        'SECURESHOP_ADMIN_USER_CHAT_BROWSER_BUILD': str(L.ROOT / 'client/build'),
        'PG_SECURESHOP_ADMIN_USER_CHAT_BROWSER_IDENTITY_RUNTIME_URL': 'preserved',
    }


class Admission(unittest.TestCase):
    def test_plan_never_starts_owner_or_claims_execution(self):
        options = parsed()
        options.plan = True
        shared = SimpleNamespace(ADMIN_USER_CHAT_TEST=L.TEST, ADMIN_USER_CHAT_ASSERTION=L.TITLE,
            parse=Mock(return_value=options), validate_static=Mock())
        helpers = SimpleNamespace(inventory=Mock(return_value={'build': {}}),
            assert_reviewed_snapshot=Mock(), syntax_check=Mock(), browser_owner=Mock())
        output = io.StringIO()
        with patch.object(L, 'validate_pins'), patch.object(L, 'load', return_value=shared), \
                patch.object(L, 'lifecycle_helpers', return_value=helpers), \
                patch.object(L, 'consume_environment') as inspector, contextlib.redirect_stdout(output):
            self.assertEqual(L.main(arguments()), 0)
        value = json.loads(output.getvalue())
        self.assertFalse(value['nativeStarted'])
        self.assertFalse(value['qualificationAccepted'])
        self.assertIsNone(value['actualModelCalls'])
        self.assertEqual(value['limits'], L.LIMITS)
        inspector.assert_not_called()
        helpers.browser_owner.assert_not_called()

    def test_actual_main_build_gate_preserves_disclosure_mode(self):
        tree = ast.parse((L.ROOT / L.MAIN).read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'validate_static')
        index = next(i for i,n in enumerate(function.body) if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == 'build_keys' for t in n.targets))
        code = compile(ast.Module(body=function.body[index:index+2], type_ignores=[]), '<actual-main-build-gate>', 'exec')
        shared = L.load(L.MAIN, 'admin_confirmation_build_gate')
        def check(disclosure, build):
            options = SimpleNamespace(cohort=L.COHORT, current_host_profile='current', user_lookup_disclosure=disclosure)
            for field in ('build_report', 'build_report_sha256', 'build_input_sha256', 'build_output_sha256', 'build_recorder_sha256'):
                setattr(options, field, 'a'*64 if build else None)
            exec(code, {**vars(shared), 'args': options})
        check(False, True)
        check(True, False)
        with self.assertRaises(RuntimeError): check(False, False)
        with self.assertRaises(RuntimeError): check(True, True)

    def result_case(self, mutate=None, retirement=None, source_changed=False):
        shared = L.load(L.MAIN, 'admin_confirmation_original_receipt')
        with tempfile.TemporaryDirectory(prefix='run-admin-contract-', dir=L.ROOT / 'tasks/qualification') as folder:
            evidence = Path(folder)
            cleanup = dict(containerNameAbsent=True, containerIdAbsent=True,
                browserProcessesAbsent=True, browserProfilesAbsent=True, errors=[])
            receipt = dict.fromkeys(shared.ADMIN_USER_CHAT_FLAGS, True)
            receipt.update(scope=shared.ADMIN_USER_CHAT_SCOPE, actorCalls=4, roleTurns=4, judgeCalls=0, errors=[])
            terminal = dict(evidence=str(evidence), passed=True, cleanup=cleanup)
            durable = dict(cohort=shared.ADMIN_USER_CHAT_COHORT, passed=True, primaryError=None,
                sourceCopy=False, cleanup=cleanup, testExitCodes={L.COHORT: 0},
                adminUserChatReceipt=receipt, modelPin=dict(baseURL=shared.OLLAMA_BASE_URL,
                    model=shared.OLLAMA_MODEL, sha256=C.MODEL_SHA256))
            if mutate:
                mutate(receipt, durable, terminal)
            L.safety.private_json(evidence / L.RECEIPT, receipt)
            durable.setdefault('adminUserChatReceiptSha256', L.digest(evidence / L.RECEIPT))
            L.safety.private_json(evidence / 'result.json', durable)
            record = dict(kind=L.KIND, pid=123, birth=[1, 2])
            owner = SimpleNamespace(error=None, evidence=evidence,
                captured=SimpleNamespace(record=record), retired=None)
            helper = L.lifecycle_helpers()
            helpers = SimpleNamespace(browser_owner=Mock(return_value=owner),
                inventory=Mock(return_value={'changed': True} if source_changed else {'build': {}}),
                exact_profile_retirement=helper.exact_profile_retirement)
            retired = [dict(**record, absent=True)] if retirement is None else retirement
            ownership = SimpleNamespace(_browser_modules=lambda: (None, None, None, None, lambda records: retired))
            original = Mock()
            def main(values):
                print(json.dumps(terminal))
                return 0
            shared.subprocess = SimpleNamespace(Popen=original)
            shared.main = main
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    code = L.run(shared, [], parsed(), ownership, {'build': {}}, helpers)
                report = L.safety.read_private(evidence / 'admin-user-confirmation-adapter-report.json')
                self.assertEqual(report['actualModelCalls'], receipt['actorCalls'])
                self.assertFalse(report['canonicalCredit'])
                self.assertFalse(report['fullQ05Qualification'])
                return code
            finally:
                self.assertIs(shared.subprocess.Popen, original)

    def test_actual_original_receipt_and_adapter_success(self):
        self.assertEqual(self.result_case(), 0)
        self.assertEqual(self.result_case(lambda r, d, t: r.update(actorCalls=20)), 0)

    def test_strict_original_counts_flags_and_durable_joins(self):
        for field, values in {'actorCalls': (3, 21, True, '4'), 'roleTurns': (3, 5, True, '4'),
                              'judgeCalls': (1, False, '0')}.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises((RuntimeError, ValueError)):
                    self.result_case(lambda r,d,t: r.update({field:value}))
        shared = L.load(L.MAIN, 'admin_confirmation_flags')
        for flag in shared.ADMIN_USER_CHAT_FLAGS:
            with self.subTest(flag=flag), self.assertRaises(RuntimeError):
                self.result_case(lambda r,d,t: r.update({flag:False}))
        changes = [lambda r,d,t: r.pop('actorCalls'), lambda r,d,t: r.update(extra=True),
            lambda r,d,t: r.update(errors=['debt']), lambda r,d,t: d.update(cohort='user-lookup'),
            lambda r,d,t: d.update(adminUserChatReceiptSha256='0'*64),
            lambda r,d,t: d.update(modelPin={}), lambda r,d,t: d.update(testExitCodes={L.COHORT:False}),
            lambda r,d,t: t.update(evidence='/foreign'), lambda r,d,t: t.update(passed=False),
            lambda r,d,t: t['cleanup'].update(browserProfilesAbsent=False)]
        for change in changes:
            with self.assertRaises((RuntimeError, ValueError)):
                self.result_case(change)

    def test_retirement_and_source_debt_never_pass(self):
        for retired in ([], [dict(kind=L.KIND,pid=123,birth=[1,2],absent=False)],
                        [dict(kind='foreign',pid=123,birth=[1,2],absent=True)],
                        [dict(kind=L.KIND,pid=123,birth=[1,3],absent=True)]):
            with self.assertRaises(RuntimeError):
                self.result_case(retirement=retired)
        with self.assertRaises(RuntimeError):
            self.result_case(source_changed=True)

    def test_user_lookup_modes_are_not_confirmation(self):
        for flag in ('--user-lookup-disclosure', '--user-lookup-benign-capture'):
            with self.assertRaises(RuntimeError):
                C.validate_arguments(arguments('--run') + [flag])
        for flag in ('SECURESHOP_USER_LOOKUP_DISCLOSURE_BROWSER_NATIVE',
                     'SECURESHOP_USER_LOOKUP_BENIGN_CAPTURE'):
            with self.assertRaises(RuntimeError):
                L.owned_environment({**environment(), flag: '1'}, parsed(), {'build': {}})

    def test_original_main_build_admission_and_source_closure(self):
        shared = L.load(L.MAIN, 'admin_confirmation_main_contract')
        values = L.arguments(arguments())
        options = shared.parse(values)
        self.assertEqual(options.cohort, L.COHORT)
        self.assertFalse(options.user_lookup_disclosure)
        self.assertFalse(options.user_lookup_benign_capture)
        self.assertEqual(shared.ADMIN_USER_CHAT_TEST, L.TEST)
        self.assertEqual(shared.ADMIN_USER_CHAT_ASSERTION, L.TITLE)
        self.assertEqual(shared.ADMIN_USER_CHAT_FLAGS, (
            'passed', 'isolatedStores', 'registeredTargetSelected',
            'roleProposalNoEffect', 'physicalRoleConfirmLostAck', 'roleReceiptRecoveredOnce',
            'targetSessionRevokedOnRole', 'banProposalNoEffect', 'physicalBanConfirmed',
            'targetSessionRevokedOnBan', 'siblingPreserved', 'controlledAuthorityFences',
            'directPanelCancelNoEffect', 'directPanelRoleConfirmed', 'directPanelBanConfirmed',
            'zeroJudge', 'fixtureCleaned'))

    def test_closed_model_and_cohort_no_optional_executor_authority(self):
        run = C.validate_arguments(arguments('--run'))
        self.assertNotIn('--run', run)
        self.assertNotIn('--expected-snapshot-sha256', L.arguments(run))
        for key, value in (('--cohort', 'merchant-mail-browser'),
                           ('--cohort', 'standalone-commerce-browser'),
                           ('--ollama-model-sha256', 'b' * 64),
                           ('--build-output-sha256', 'not-a-sha'),
                           ('--main-workspace', '/foreign'),
                           ('--evidence-parent', '/foreign'),
                           ('--expected-snapshot-sha256', 'invalid')):
            candidate = arguments('--run')
            candidate[candidate.index(key) + 1] = value
            with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                C.validate_arguments(candidate)
        for field in ('--build-report', '--build-report-sha256', '--build-input-sha256',
                      '--build-output-sha256', '--build-recorder-sha256'):
            missing = arguments('--run')
            offset = missing.index(field)
            del missing[offset:offset + 2]
            with self.subTest(missing=field), self.assertRaises(RuntimeError):
                C.validate_arguments(missing)
        for extra in (['--embedding-cache', '/foreign'], ['--run'], ['--timeout', '1800'],
                      ['--maximum-actor-calls', '50'],
                      ['--commerce-test-no-sandbox'], ['--policy-output-browser']):
            with self.assertRaises(RuntimeError):
                C.validate_arguments(arguments('--run') + extra)
        with self.assertRaises(RuntimeError):
            C.validate_arguments(arguments() + ['--expected-snapshot-sha256', 'a' * 64],
                                 planning=True)

    def test_fixed_wrapper_command(self):
        value = C.child_command(arguments('--run'))
        self.assertEqual(value[:2], ['/bin/bash', str(L.ROOT / 'tasks/run-in-repository.sh')])
        self.assertIn(str(L.ROOT / C.ADAPTER), value)
        self.assertNotIn('--run', value)
        self.assertNotIn('run-secureshop-standalone-commerce-browser.py', ' '.join(value))

    def test_exact_original_environment_keeps_store_and_model_authority(self):
        before = {'build': {'index.html': 'c' * 64}}
        original = environment()
        env, run = L.owned_environment(original, parsed(), before)
        self.assertEqual({key: env[key] for key in original}, original)
        self.assertEqual(env[L.PREFIX + 'BROWSER_RECORD_PATH'], str(run / L.RECORD))
        self.assertEqual(env[L.PREFIX + 'BROWSER_ACK_PATH'], str(run / L.ACK))
        self.assertEqual(env[L.PREFIX + 'SNAPSHOT_SHA256'], L.safety.encoded(before))
        self.assertEqual(env['MAC_CHROMIUM_TMPDIR'], env['TMPDIR'])
        self.assertFalse(any(key.startswith('SECURESHOP_COMMERCE_') for key in env))
        for change in ({'LIVE_OLLAMA_TEST': '0'}, {'TMPDIR': '/private/tmp'},
                       {'OLLAMA_BASE_URL': 'https://external.invalid'},
                       {'SECURESHOP_USER_LOOKUP_BENIGN_CAPTURE': '1'},
                       {L.EVIDENCE_ENV: str(run / 'standalone-commerce-browser.json')},
                       {'SECURESHOP_STANDALONE_COMMERCE_NATIVE': '1'},
                       {'SECURESHOP_MERCHANT_MAIL_BROWSER_NATIVE': '1'},
                       {'LAB_MODE': 'fixed'}, {'PUPPETEER_EXECUTABLE_PATH': '/substitute'}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                L.owned_environment({**original, **change}, parsed(), before)

    def test_grant_exact_mail_worker_path_build_and_source_no_commerce_default(self):
        before = {'build': {}}
        first = L.admission_grant(parsed(), before, environment(), 123)
        second = L.admission_grant(parsed(), before, environment(), 123)
        self.assertEqual(set(first), {'version', 'cohort', 'launcherPid', 'workerPid',
            'nonce', 'workspace', 'evidencePath', 'buildSha256', 'snapshotSha256',
            'outerSandbox', 'chromium', 'chromiumSha256'})
        self.assertEqual(first['cohort'], L.COHORT)
        self.assertEqual(first['evidencePath'], environment()[L.EVIDENCE_ENV])
        self.assertEqual(first['workerPid'], 123)
        self.assertEqual(first['launcherPid'], os.getpid())
        self.assertNotEqual(first['nonce'], second['nonce'])
        self.assertNotIn('commerce', first['evidencePath'])

    def test_fixed_parent_birth_sandbox_and_physical_interpreter(self):
        parent = os.getppid()
        api = Mock()
        api.identity.return_value = SimpleNamespace(uid=os.getuid(), ruid=os.getuid(),
                                                    start_sec=10, start_usec=20)
        original = arguments('--run')
        argv = C.validate_arguments(original)
        api.arguments.return_value = ['/physical/python', '-B', str(L.ROOT / L.OUTER), *original]
        denied = lambda path: str(path) == '/private/tmp'
        with patch.object(L.safety, 'physical_python', return_value=Path('/physical/python')):
            L.verify_outer_boundary(argv, SimpleNamespace(parent=parent), api=api, denied=denied)
            with self.assertRaises(RuntimeError):
                L.verify_outer_boundary(argv, SimpleNamespace(parent=parent + 1), api=api, denied=denied)
            with self.assertRaises(RuntimeError):
                L.verify_outer_boundary(argv, SimpleNamespace(parent=parent), api=api, denied=lambda _: False)
            api.arguments.return_value[2] = str(L.ROOT / 'tests/postgres/run_standalone_commerce_with_inspector.py')
            with self.assertRaises(RuntimeError):
                L.verify_outer_boundary(argv, SimpleNamespace(parent=parent), api=api, denied=denied)


    def test_private_bindings_do_not_modify_original_modules(self):
        helpers = L.lifecycle_helpers()
        for field in ('COHORT', 'TEST', 'HELPER', 'CONTRACT', 'MAIN', 'OWNER', 'OWNERSHIP',
                      'RECORD', 'ACK', 'KIND', 'PROFILE', 'FD_ENV', 'CONTROL_SOURCES'):
            self.assertEqual(getattr(helpers, field), getattr(L, field))
        self.assertIs(helpers.owned_environment, L.owned_environment)
        self.assertIs(helpers.admission_grant, L.admission_grant)
        original = L.load(L.REUSE, 'mail_original_commerce_unmodified')
        self.assertEqual(original.COHORT, 'standalone-commerce-browser')
        self.assertNotEqual(original.TEST, helpers.TEST)
        self.assertNotEqual(original.PROFILE, helpers.PROFILE)
        self.assertEqual(helpers.direct_command([parsed().node, '--test', '--test-reporter=tap',
            '--test-concurrency=1', L.TEST], parsed()), [parsed().node, '--test-reporter=tap', L.TEST])
        with self.assertRaises(RuntimeError):
            helpers.direct_command([parsed().node, '--test', '--test-reporter=tap',
                '--test-concurrency=1', original.TEST], parsed())

    def test_owner_uses_mail_birth_ack_kind_and_live_retirement_implementation(self):
        helpers = L.lifecycle_helpers()
        owner = helpers.browser_owner(Mock(), parsed(), Mock(), {'build': {}})
        constants = owner.__call__.__func__.__globals__
        for field in ('TEST', 'RECORD', 'ACK', 'KIND'):
            self.assertEqual(constants[field], getattr(L, field))
        self.assertIs(owner.original.__class__, helpers.GrantSpawner)
        self.assertEqual(owner.original.__call__.__func__.__globals__['FD_ENV'], L.FD_ENV)
        self.assertEqual(helpers.install_profile_cleanup.__globals__['PROFILE'], L.PROFILE)

    def test_inventory_uses_full_original_mail_closure_and_omits_only_plan(self):
        helpers = L.lifecycle_helpers()
        shared = SimpleNamespace(source_snapshot=Mock(return_value={'server': 'original'}))
        options = parsed()
        with patch.object(helpers.safety, 'files', return_value={'index.html': 'c' * 64}), \
                patch.object(helpers.safety, 'validate_modern_build_receipt',
                             return_value={'qualified': True}) as provenance, \
                patch.object(helpers.safety, 'physical_python', return_value=Path('/physical/python')), \
                patch.object(helpers, 'digest', return_value='d' * 64):
            before = helpers.inventory(shared, options)
            options.plan = True
            after = helpers.inventory(shared, options)
        provenance.assert_called_with(L.ROOT, options)
        shared.source_snapshot.assert_called_with(L.ROOT, options.node, L.COHORT,
                                                  browser_root=Path(options.browser_root), policy_renderer=False)
        self.assertEqual(before, after)
        self.assertNotIn('plan', before['executionArguments'])
        self.assertEqual(before['originalSource'], {'server': 'original'})
        self.assertIn(C.ADAPTER, before['files'])
        self.assertIn(L.CONTRACT, before['files'])

    def test_uncaptured_browser_cannot_authorize_retirement_or_profile_deletion(self):
        helpers = L.lifecycle_helpers()
        api = Mock(identity=Mock(return_value=None))
        retire = Mock()
        ownership = SimpleNamespace(_browser_modules=Mock(return_value=(
            Mock(return_value=api), 5, None, Mock(), Mock())), retire_live_v36=retire)
        owner = helpers.browser_owner(Mock(), parsed(), ownership, {'build': {}})
        child = SimpleNamespace(pid=111, wait=Mock(return_value=0))
        # Grant delivery has its own real-FIFO tests; isolate the next live-owner boundary.
        owner.original = Mock(return_value=child)
        with patch.object(helpers.shutil, 'rmtree') as remove:
            result = owner([parsed().node, '--test', '--test-reporter=tap',
                '--test-concurrency=1', L.TEST], env=environment(), start_new_session=True)
            self.assertIs(result, child)
            with self.assertRaisesRegex(RuntimeError, 'birth unavailable'):
                result.wait()
            self.assertEqual(result.wait(), 0)
            self.assertIsNone(owner.captured)
            retire.assert_not_called()
            remove.assert_not_called()

    def test_mail_profile_cleanup_rejects_other_mail_or_commerce_prefix(self):
        helpers = L.lifecycle_helpers()
        runtime = L.ROOT / 'tasks/qualification/run-controlled/runtime'
        for prefix in ('owasp-ai-goat-role-mail-', 'owasp-ai-goat-standalone-commerce-'):
            value = SimpleNamespace(profile=str(runtime / 'tmp' / (prefix + 'controlled')))
            ownership = SimpleNamespace(capture_live_v36=Mock(return_value=value),
                                        retire_live_v36=Mock())
            helpers.install_profile_cleanup(ownership, Mock())
            with self.assertRaisesRegex(RuntimeError, 'Exact captured'):
                ownership.capture_live_v36({}, (1, 2), runtime, api=Mock())

    def test_real_fifo_contains_only_mail_grant_and_closes_original_fd(self):
        helpers = L.lifecycle_helpers()
        child = SimpleNamespace(pid=111, wait=Mock(return_value=0))
        api = Mock()
        api.identity.return_value = SimpleNamespace(pid=111, ppid=os.getpid(),
            uid=os.getuid(), ruid=os.getuid(), pgid=111)
        captured = {}
        def spawn(command, **options):
            captured.update(options)
            captured['duplicate'] = os.dup(options['pass_fds'][0])
            return child
        try:
            with patch.object(helpers.os, 'getsid', return_value=111):
                result = helpers.GrantSpawner(spawn, parsed(), {'build': {}}, api=api)(
                    [parsed().node, '--test-reporter=tap', L.TEST],
                    env=environment(), start_new_session=True)
            self.assertIs(result, child)
            data = json.loads(os.read(captured['duplicate'], 8192))
            self.assertEqual(data['cohort'], L.COHORT)
            self.assertEqual(data['evidencePath'], environment()[L.EVIDENCE_ENV])
            self.assertIn(L.FD_ENV, captured['env'])
            self.assertNotIn('SECURESHOP_COMMERCE_ADMISSION_FD', captured['env'])
            self.assertEqual(os.read(captured['duplicate'], 1), b'')
            self.assertEqual(len(captured['pass_fds']), 1)
            with self.assertRaises(OSError):
                os.fstat(captured['pass_fds'][0])
        finally:
            if 'duplicate' in captured:
                os.close(captured['duplicate'])

    def test_foreign_child_receives_no_capability_but_stays_registered_for_cleanup(self):
        helpers = L.lifecycle_helpers()
        child = SimpleNamespace(pid=111, wait=Mock(return_value=0))
        api = Mock(identity=Mock(return_value=SimpleNamespace(ppid=-1)))
        captured = {}
        def spawn(command, **options):
            captured['fd'] = os.dup(options['pass_fds'][0])
            return child
        try:
            result = helpers.GrantSpawner(spawn, parsed(), {'build': {}}, api=api)(
                [parsed().node, '--test-reporter=tap', L.TEST],
                env=environment(), start_new_session=True)
            self.assertIs(result, child)
            self.assertEqual(os.read(captured['fd'], 8192), b'')
            with self.assertRaises(RuntimeError):
                result.wait()
            self.assertEqual(result.wait(), 0)
        finally:
            if 'fd' in captured:
                os.close(captured['fd'])



