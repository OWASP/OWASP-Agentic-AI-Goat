"""Controlled mail-actions admission; never starts a model, browser or database."""
import argparse
import contextlib
import importlib.util
import io
import json
import os
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


L = module('run-secureshop-merchant-mail-actions-browser.py', 'mail_actions_controlled')
C = module('run_merchant_mail_actions_with_inspector.py', 'mail_actions_outer_controlled')


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
                           policy_renderer_admission=None, plan=False)


def environment():
    run = L.ROOT / 'tasks/qualification/run-mail-controlled'
    return {
        L.NATIVE_ENV: '1', L.EVIDENCE_ENV: str(run / L.RECEIPT),
        'LIVE_OLLAMA_TEST': '1', 'PG_TEST_DISPOSABLE': 'yes', 'NODE_ENV': 'test',
        'LAB_MODE': 'vuln', 'TMPDIR': str(run / 'runtime/tmp'),
        'OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE': str(L.ROOT),
        'OLLAMA_BASE_URL': 'http://127.0.0.1:11434', 'OLLAMA_MODEL': 'llama3.1:8b',
        'PUPPETEER_EXECUTABLE_PATH': parsed().browser,
        'SECURESHOP_MERCHANT_MAIL_ACTIONS_BROWSER_BUILD': str(L.ROOT / 'client/build'),
        'PG_SECURESHOP_MERCHANT_MAIL_ACTIONS_BROWSER_IDENTITY_RUNTIME_URL': 'preserved',
    }


class ClosedAdmission(unittest.TestCase):
    def test_mode_exclusion_precedes_any_reservation_or_browser_owner(self):
        helpers = SimpleNamespace(browser_owner=Mock())
        shared = SimpleNamespace(subprocess=SimpleNamespace(Popen=Mock()), main=Mock())
        for change in ({L.Q05_ENV:'1', L.PASSIVE_ENV:'1'},
                       {L.Q05_ENV:'0'}, {L.PASSIVE_ENV:'0'}):
            with self.subTest(change=change), patch.dict(os.environ, change), \
                    patch.object(L, 'reserve_passive_diagnostic') as passive, \
                    patch.object(L, 'reserve_q05_diagnostic') as q05, \
                    self.assertRaisesRegex(RuntimeError, 'exclusive exact opt-in'):
                L.run(shared, [], parsed(), Mock(), {'build':{}}, helpers)
            passive.assert_not_called()
            q05.assert_not_called()
            helpers.browser_owner.assert_not_called()
            shared.main.assert_not_called()

    def test_q05_mail_mode_is_exclusive_and_one_shot_before_dispatch(self):
        parent = L.ROOT / 'tasks/tmp'
        with tempfile.TemporaryDirectory(prefix='mail-q05-contract-', dir=parent) as temporary:
            fake_root = Path(temporary)
            (fake_root / 'tasks/qualification').mkdir(parents=True, mode=0o700)
            before = {'build': {'index.html': 'a' * 64}}
            run = fake_root / 'tasks/qualification/run-controlled'
            clean = {**environment(), L.EVIDENCE_ENV: str(run / L.RECEIPT),
                'TMPDIR': str(run / 'runtime/tmp'),
                'OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE': str(fake_root),
                'SECURESHOP_MERCHANT_MAIL_ACTIONS_BROWSER_BUILD': str(fake_root / 'client/build')}
            with patch.object(L, 'ROOT', fake_root), patch.dict(os.environ, {L.Q05_ENV:'1'}):
                with self.assertRaises((FileNotFoundError, RuntimeError)):
                    L.owned_environment(clean, parsed(), before)
                marker = L.reserve_q05_diagnostic(before)
                self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
                child, _ = L.owned_environment(clean, parsed(), before)
                self.assertEqual(child[L.Q05_ENV], '1')
                with self.assertRaisesRegex(RuntimeError, 'already admitted'):
                    L.reserve_q05_diagnostic(before)
                with self.assertRaisesRegex(RuntimeError, 'exclusive'):
                    L.reserve_q05_diagnostic(before, environment={L.Q05_ENV:'1', L.PASSIVE_ENV:'1'})
            with patch.object(L, 'ROOT', fake_root), patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(RuntimeError, 'exclusive'):
                    L.owned_environment({**clean, L.Q05_ENV:'1'}, parsed(), before)

    def test_q05_report_uses_actual_actor_count_and_distinct_receipt(self):
        owner = SimpleNamespace(evidence=L.ROOT / 'tasks/qualification/run-controlled',
                                captured=SimpleNamespace(record={}), error=None, retired=None)
        before = {'build': {}}
        helpers = SimpleNamespace(browser_owner=Mock(return_value=owner),
                                  inventory=Mock(return_value=before))
        original = Mock()
        shared = SimpleNamespace(subprocess=SimpleNamespace(Popen=original),
            main=lambda _values: (print(json.dumps({'passed': True})), 0)[1],
            mail_keep_unresolved_q05_receipt=Mock(return_value={
                'actorCalls': 7, 'judgeCalls': 0, 'roleTurns': 0}))
        ownership = SimpleNamespace(_browser_modules=Mock(return_value=(None,None,None,None,
            Mock(return_value=[{'absent': True}]))))
        with patch.dict(os.environ, {L.Q05_ENV:'1'}), \
                patch.object(L, 'reserve_q05_diagnostic', return_value=Path('/reserved-q05')), \
                patch.object(L, 'digest', return_value='a' * 64), \
                patch.object(L.safety, 'private_json') as save, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(L.run(shared, [], parsed(), ownership, before, helpers), 0)
        report = save.call_args.args[1]
        self.assertEqual(report['actualModelCalls'], 7)
        self.assertEqual(report['judgeCalls'], 0)
        self.assertEqual(report['q05ReceiptSha256'], 'a' * 64)
        self.assertTrue(report['q05Facet'])
        self.assertFalse(report['canonicalCredit'])
        shared.mail_keep_unresolved_q05_receipt.assert_called_once_with(owner.evidence / L.RECEIPT)
        self.assertIs(shared.subprocess.Popen, original)

    def test_real_qualified_receipt_is_rejected_after_current_source_drift(self):
        report = L.ROOT / 'tasks/qualification/frontend-build-8vhqkht1/report.json'
        self.assertEqual(L.safety.sha(report),
            'fac3a9a57cb798dff3dbe25f42589b81b41eb2e550ca98f89b19793f7e5d0e01')
        args = SimpleNamespace(build_report=str(report),
            build_report_sha256='fac3a9a57cb798dff3dbe25f42589b81b41eb2e550ca98f89b19793f7e5d0e01',
            build_input_sha256='03c16630ec877e4ed1aa3347a5459667d6fd805ee0ae9ca4175abc6bbeaab5dd',
            build_output_sha256='ad51fd4270f18d404615fe66cfcb54af0e8c6543c11e3b6b332348375b7db1fc',
            build_recorder_sha256='2e899f4334bd03fa985240567b9bbd01ef1ae9c8f70ea98ea5e375f53e032be2')
        with self.assertRaisesRegex(RuntimeError, 'Frontend build inputs do not match'):
            L.safety.validate_modern_build_receipt(L.ROOT, args)

    def test_historical_recorder_pin_is_rejected_before_input_drift(self):
        report = L.ROOT / 'tasks/qualification/frontend-build-8vhqkht1/report.json'
        args = SimpleNamespace(build_report=str(report),
            build_report_sha256='fac3a9a57cb798dff3dbe25f42589b81b41eb2e550ca98f89b19793f7e5d0e01',
            build_input_sha256='03c16630ec877e4ed1aa3347a5459667d6fd805ee0ae9ca4175abc6bbeaab5dd',
            build_output_sha256='ad51fd4270f18d404615fe66cfcb54af0e8c6543c11e3b6b332348375b7db1fc',
            build_recorder_sha256='46bb5f40daec1067ab04c0747e59e94c03b9a38646cfbcda9d78e0f80dfe892d')
        with self.assertRaisesRegex(RuntimeError, 'Frontend build recorder pin mismatch'):
            L.safety.validate_modern_build_receipt(L.ROOT, args)

    def test_original_parser_carries_all_qualified_build_fields_and_rejects_missing(self):
        shared = L.load(L.MAIN, 'mail_actions_parse_contract')
        parsed = shared.parse(L.arguments(arguments()))
        self.assertEqual(parsed.build_report_sha256, '1' * 64)
        self.assertEqual(parsed.build_input_sha256, '2' * 64)
        self.assertEqual(parsed.build_output_sha256, '3' * 64)
        self.assertEqual(parsed.build_recorder_sha256, '4' * 64)
        for field in ('build_report', 'build_report_sha256', 'build_input_sha256',
                      'build_output_sha256', 'build_recorder_sha256'):
            missing = argparse.Namespace(**vars(parsed))
            setattr(missing, field, None)
            with self.subTest(missing=field), self.assertRaisesRegex(RuntimeError,
                    'Exact qualified browser build provenance required'):
                shared.validate_static(missing)
        unrelated = argparse.Namespace(**vars(parsed))
        unrelated.cohort = 'transport'
        with self.assertRaisesRegex(RuntimeError, 'cohort exclusive'):
            shared.validate_static(unrelated)

    def test_passive_mail_diagnostic_consumes_one_private_snapshot_admission(self):
        parent = L.ROOT / 'tasks/tmp'
        with tempfile.TemporaryDirectory(prefix='mail-passive-contract-', dir=parent) as temporary:
            fake_root = Path(temporary)
            private = fake_root / 'tasks/qualification'
            private.mkdir(parents=True, mode=0o700)
            before = {'build': {'index.html': 'a' * 64}}
            with patch.object(L, 'ROOT', fake_root):
                self.assertIsNone(L.reserve_passive_diagnostic(before, environment={}))
                with self.assertRaisesRegex(RuntimeError, 'one-shot opt-in'):
                    L.reserve_passive_diagnostic(before, environment={L.PASSIVE_ENV: '0'})
                marker = L.reserve_passive_diagnostic(before, environment={L.PASSIVE_ENV: '1'})
                self.assertEqual(marker.parent, private)
                self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
                self.assertTrue(json.loads(marker.read_text())['admissionConsumed'])
                with self.assertRaisesRegex(RuntimeError, 'already admitted'):
                    L.reserve_passive_diagnostic(before, environment={L.PASSIVE_ENV: '1'})

    def test_passive_marker_fsyncs_file_then_parent_and_closes_both_descriptors(self):
        parent = L.ROOT / 'tasks/tmp'
        with tempfile.TemporaryDirectory(prefix='mail-passive-fsync-', dir=parent) as temporary:
            fake_root = Path(temporary)
            private = fake_root / 'tasks/qualification'
            private.mkdir(parents=True, mode=0o700)
            observed = []
            original_fsync = os.fsync

            def verified_fsync(fd):
                observed.append((fd, stat.S_ISDIR(os.fstat(fd).st_mode)))
                original_fsync(fd)

            with patch.object(L, 'ROOT', fake_root), patch.object(L.os, 'fsync', side_effect=verified_fsync):
                marker = L.reserve_passive_diagnostic({'build': {'index.html': 'a' * 64}},
                                                      environment={L.PASSIVE_ENV: '1'})
            self.assertEqual([is_directory for _, is_directory in observed], [False, True])
            self.assertTrue(marker.is_file())
            for descriptor, _ in observed:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_passive_marker_fsync_failure_retains_marker_and_prevents_native_dispatch(self):
        parent = L.ROOT / 'tasks/tmp'
        before = {'build': {'index.html': 'a' * 64}}
        for failed_call in (1, 2):
            with self.subTest(failed_call=failed_call), \
                    tempfile.TemporaryDirectory(prefix='mail-passive-fail-', dir=parent) as temporary:
                fake_root = Path(temporary)
                private = fake_root / 'tasks/qualification'
                private.mkdir(parents=True, mode=0o700)
                descriptors = []

                def fail_fsync(fd):
                    descriptors.append(fd)
                    if len(descriptors) == failed_call:
                        raise OSError('controlled fsync failure')

                owner = SimpleNamespace(error=None, captured=None, retired=False, evidence=None)
                helpers = SimpleNamespace(browser_owner=Mock(return_value=owner),
                                          inventory=Mock(return_value=before))
                original_popen = Mock()
                shared = SimpleNamespace(subprocess=SimpleNamespace(Popen=original_popen), main=Mock())
                with patch.object(L, 'ROOT', fake_root), \
                        patch.dict(os.environ, {L.PASSIVE_ENV: '1'}), \
                        patch.object(L.os, 'fsync', side_effect=fail_fsync):
                    with self.assertRaisesRegex(OSError, 'controlled fsync failure'):
                        L.run(shared, [], parsed(), object(), before, helpers)
                    marker = private / ('mail-actions-passive-diagnostic-' + L.safety.encoded(before) + '.json')
                    self.assertTrue(marker.is_file())
                    with self.assertRaisesRegex(RuntimeError, 'already admitted'):
                        L.reserve_passive_diagnostic(before, environment={L.PASSIVE_ENV: '1'})
                shared.main.assert_not_called()
                original_popen.assert_not_called()
                self.assertIs(shared.subprocess.Popen, original_popen)
                for descriptor in descriptors:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)

    def test_unreviewed_pins_deny_even_plan(self):
        with patch.object(L, 'PINS', None), patch.object(L, 'RENDERED_PINS', None):
            with self.assertRaisesRegex(RuntimeError, 'not independently reviewed'):
                L.main(arguments())
        with patch.object(L, 'PINS', {L.MAIN: 'a' * 64}), \
                patch.object(L, 'RENDERED_PINS', {L.TEST: 'b' * 64}):
            with self.assertRaises(RuntimeError):
                L.validate_pins()
        with patch.object(L, 'RENDERED_PINS', {key: value for key, value in L.RENDERED_PINS.items()
                                             if key != L.CANCEL_CONTRACT}):
            with self.assertRaises(RuntimeError):
                L.validate_pins()

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
                       {L.PASSIVE_ENV: '0'},
                       {L.EVIDENCE_ENV: str(run / 'standalone-commerce-browser.json')},
                       {'SECURESHOP_STANDALONE_COMMERCE_NATIVE': '1'},
                       {'SECURESHOP_MERCHANT_MAIL_BROWSER_NATIVE': '1'},
                       {'LAB_MODE': 'fixed'}, {'PUPPETEER_EXECUTABLE_PATH': '/substitute'}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                L.owned_environment({**original, **change}, parsed(), before)

    def test_clean_child_receives_only_reserved_outer_passive_selector(self):
        parent = L.ROOT / 'tasks/tmp'
        with tempfile.TemporaryDirectory(prefix='mail-passive-child-', dir=parent) as temporary:
            fake_root = Path(temporary)
            (fake_root / 'tasks/qualification').mkdir(parents=True, mode=0o700)
            run = fake_root / 'tasks/qualification/run-controlled'
            clean = {**environment(), L.EVIDENCE_ENV: str(run / L.RECEIPT),
                     'TMPDIR': str(run / 'runtime/tmp'),
                     'OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE': str(fake_root),
                     'SECURESHOP_MERCHANT_MAIL_ACTIONS_BROWSER_BUILD': str(fake_root / 'client/build')}
            before = {'build': {'index.html': 'a' * 64}}
            with patch.object(L, 'ROOT', fake_root), patch.dict(os.environ,
                    {L.PASSIVE_ENV: '1', 'UNRELATED_OUTER_SECRET': 'not-forwarded'}):
                with self.assertRaises((FileNotFoundError, RuntimeError)):
                    L.owned_environment(clean, parsed(), before)
                L.reserve_passive_diagnostic(before)
                child, _ = L.owned_environment(clean, parsed(), before)
                self.assertEqual(child[L.PASSIVE_ENV], '1')
                self.assertNotIn('UNRELATED_OUTER_SECRET', child)
                with self.assertRaisesRegex(RuntimeError, 'one-shot opt-in'):
                    L.owned_environment({**clean, L.PASSIVE_ENV: '0'}, parsed(), before)
            with patch.object(L, 'ROOT', fake_root), patch.dict(os.environ,
                    {L.PASSIVE_ENV: '0'}):
                with self.assertRaisesRegex(RuntimeError, 'one-shot opt-in'):
                    L.owned_environment(clean, parsed(), before)
            with patch.object(L, 'ROOT', fake_root), patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(RuntimeError, 'one-shot opt-in'):
                    L.owned_environment({**clean, L.PASSIVE_ENV: '1'}, parsed(), before)

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


class ExplicitReuse(unittest.TestCase):
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
                                                  browser_root=Path(options.browser_root),
                                                  policy_renderer=False)
        self.assertEqual(before, after)
        self.assertNotIn('plan', before['executionArguments'])
        self.assertEqual(before['originalSource'], {'server': 'original'})
        self.assertIn(C.ADAPTER, before['files'])
        self.assertIn(L.CANCEL_CONTRACT, before['files'])

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


class PlanAndReporting(unittest.TestCase):
    def test_q05_plan_is_nonallocating_and_distinct(self):
        options = parsed()
        options.plan = True
        shared = SimpleNamespace(MERCHANT_MAIL_ACTIONS_TEST=L.TEST,
            MERCHANT_MAIL_ACTIONS_ASSERTION=L.TITLE,
            MERCHANT_MAIL_ACTIONS_FLAGS=('cancelProposalNoEffect',),
            MAIL_KEEP_Q05_ENV=L.Q05_ENV, MAIL_KEEP_Q05_SCOPE=L.Q05_SCOPE,
            MAIL_KEEP_Q05_ASSERTION=L.Q05_TITLE,
            parse=Mock(return_value=options), validate_static=Mock())
        helpers = SimpleNamespace(inventory=Mock(return_value={'build':{}}),
                                  assert_reviewed_snapshot=Mock(), syntax_check=Mock())
        with patch.dict(os.environ, {L.Q05_ENV:'1'}), patch.object(L, 'validate_pins'), \
                patch.object(L, 'load', return_value=shared), \
                patch.object(L, 'lifecycle_helpers', return_value=helpers), \
                patch.object(L, 'reserve_q05_diagnostic') as reserve, \
                patch.object(L, 'consume_environment') as inspector, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(L.main(arguments()), 0)
        plan = json.loads(output.getvalue())
        self.assertTrue(plan['q05Facet'])
        self.assertFalse(plan['canonicalCredit'])
        self.assertFalse(plan['qualificationAccepted'])
        self.assertIsNone(plan['actualModelCalls'])
        self.assertEqual(plan['limits']['maximumPhysicalActorCalls'], 30)
        self.assertEqual(plan['limits']['judgeCalls'], 0)
        reserve.assert_not_called()
        inspector.assert_not_called()

    def test_plan_is_nonallocating_and_does_not_claim_zero_actual_model_execution(self):
        options = parsed()
        options.plan = True
        shared = SimpleNamespace(MERCHANT_MAIL_ACTIONS_TEST=L.TEST,
            MERCHANT_MAIL_ACTIONS_ASSERTION=L.TITLE,
            MERCHANT_MAIL_ACTIONS_FLAGS=('cancelProposalNoEffect',),
            MAIL_KEEP_Q05_ENV=L.Q05_ENV, MAIL_KEEP_Q05_SCOPE=L.Q05_SCOPE,
            MAIL_KEEP_Q05_ASSERTION=L.Q05_TITLE,
            parse=Mock(return_value=options), validate_static=Mock())
        helpers = SimpleNamespace(inventory=Mock(return_value={'build': {}}),
                                  assert_reviewed_snapshot=Mock(), syntax_check=Mock())
        with patch.object(L, 'validate_pins'), patch.object(L, 'load', return_value=shared), \
                patch.object(L, 'lifecycle_helpers', return_value=helpers), \
                patch.object(L, 'consume_environment') as inspector, \
                patch.object(L, 'run') as run, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(L.main(arguments()), 0)
        result = json.loads(output.getvalue())
        self.assertFalse(result['nativeStarted'])
        self.assertTrue(result['requiresActualModel'])
        self.assertIsNone(result['actualModelCalls'])
        self.assertEqual(result['limits'], L.LIMITS)
        self.assertEqual(result['limits']['maximumPhysicalActorCalls'], 30)
        self.assertEqual(result['limits']['providerSeconds'], 60)
        self.assertEqual(result['limits']['fixtureSeconds'], 600)
        self.assertEqual(result['limits']['launcherSeconds'], 600)
        self.assertEqual(result['limits']['roleTurns'], 5)
        self.assertEqual(result['limits']['judgeCalls'], 0)
        self.assertEqual((result['limits']['databaseCount'], result['limits']['roleCount']), (4, 8))
        inspector.assert_not_called()
        run.assert_not_called()

    def test_reviewed_snapshot_mismatch_precedes_any_execution(self):
        helpers = L.lifecycle_helpers()
        supplied = C.validate_arguments(arguments('--run'))
        with self.assertRaisesRegex(RuntimeError, 'reviewed plan'):
            helpers.assert_reviewed_snapshot(supplied, {'build': {}})

    def test_successful_report_uses_validated_actual_counts_not_commerce_zero(self):
        owner = SimpleNamespace(evidence=L.ROOT / 'tasks/qualification/run-controlled',
                                captured=SimpleNamespace(record={}), error=None, retired=None)
        before = {'build': {}}
        helpers = SimpleNamespace(browser_owner=Mock(return_value=owner),
                                  inventory=Mock(return_value=before))
        result = {'passed': True}
        def main(_values):
            print(json.dumps(result))
            return 0
        original = Mock()
        shared = SimpleNamespace(subprocess=SimpleNamespace(Popen=original), main=main,
            merchant_mail_actions_receipt=Mock(return_value={
                'cancelProposalNoEffect': True, 'actorCalls': 12, 'judgeCalls': 0, 'roleTurns': 5}))
        ownership = SimpleNamespace(_browser_modules=Mock(return_value=(None, None, None, None,
            Mock(return_value=[{'absent': True}]))))
        with patch.object(L.safety, 'private_json') as save, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(L.run(shared, [], parsed(), ownership, before, helpers), 0)
        report = save.call_args.args[1]
        self.assertEqual(report['actualModelCalls'], 12)
        self.assertEqual(report['judgeCalls'], 0)
        self.assertTrue(report['adapterPassed'])
        self.assertEqual(save.call_args.args[0].name, 'mail-actions-adapter-report.json')
        self.assertFalse(report['canonicalCredit'])
        self.assertIs(shared.subprocess.Popen, original)

    def test_opted_in_success_without_passive_artifact_cannot_pass(self):
        owner = SimpleNamespace(evidence=L.ROOT / 'tasks/qualification/run-controlled',
                                captured=SimpleNamespace(record={}), error=None, retired=None)
        before = {'build': {}}
        helpers = SimpleNamespace(browser_owner=Mock(return_value=owner),
                                  inventory=Mock(return_value=before))
        original = Mock()
        shared = SimpleNamespace(subprocess=SimpleNamespace(Popen=original),
            main=lambda _values: (print(json.dumps({'passed': True})), 0)[1],
            merchant_mail_actions_receipt=Mock(return_value={
                'cancelProposalNoEffect': True, 'actorCalls': 13, 'judgeCalls': 0, 'roleTurns': 5}))
        with patch.object(L, 'reserve_passive_diagnostic', return_value=Path('/reserved-marker')), \
                patch.object(L.safety, 'read_private', side_effect=FileNotFoundError('missing passive artifact')), \
                patch.object(L.safety, 'private_json') as save, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(FileNotFoundError, 'missing passive artifact'):
                L.run(shared, [], parsed(), Mock(), before, helpers)
        self.assertFalse(save.call_args.args[1]['adapterPassed'])
        self.assertIs(shared.subprocess.Popen, original)

    def test_passive_artifact_requires_exact_bounded_recipient_projection(self):
        observed = dict(version=1, originalSenderId=7,
                        providerInputSystemSha256='a' * 64, trustedContextSha256='b' * 64,
                        selectedRecipientId=7, persistedRecipientId=7)
        with patch.object(L.safety, 'read_private', return_value=observed) as read:
            self.assertEqual(L.require_passive_diagnostic(Path('/controlled/evidence')), observed)
        self.assertEqual(read.call_args.args[0],
                         Path('/controlled/evidence/merchant-mail-actions-passive-diagnostic.json'))
        self.assertEqual(read.call_args.kwargs, {'maximum': 1024})
        for changed in ({**observed, 'rawMessage': 'forbidden'},
                        {**observed, 'persistedRecipientId': 8},
                        {**observed, 'providerInputSystemSha256': 'not-a-sha'},
                        {**observed, 'originalSenderId': True}):
            with self.subTest(changed=changed), patch.object(L.safety, 'read_private', return_value=changed):
                with self.assertRaisesRegex(RuntimeError, 'Exact private mail passive diagnostic'):
                    L.require_passive_diagnostic(Path('/controlled/evidence'))

    def test_primary_failure_preserved_and_unknown_actual_calls_not_reported_zero(self):
        primary = RuntimeError('original mail qualification failed')
        owner = SimpleNamespace(evidence=L.ROOT / 'tasks/qualification/run-controlled',
                                captured=None, error=None, retired=None)
        helpers = SimpleNamespace(browser_owner=Mock(return_value=owner),
                                  inventory=Mock(side_effect=OSError('postflight unavailable')))
        original = Mock()
        shared = SimpleNamespace(subprocess=SimpleNamespace(Popen=original),
                                 main=Mock(side_effect=primary))
        reports = []
        def save(_path, report):
            reports.append(report)
            raise OSError('report unavailable')
        with patch.object(L.safety, 'private_json', side_effect=save), \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(RuntimeError) as error:
                L.run(shared, [], parsed(), Mock(), {}, helpers)
        self.assertIs(error.exception, primary)
        self.assertIsNone(reports[0]['actualModelCalls'])
        self.assertFalse(reports[0]['adapterPassed'])
        self.assertIs(shared.subprocess.Popen, original)


if __name__ == '__main__':
    unittest.main()
