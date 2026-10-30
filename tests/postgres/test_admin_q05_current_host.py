"""Controlled safety contracts; no browser, database, model or network starts."""
import contextlib
import copy
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch, Mock

import admin_q05_current_host as profile
import run_admin_q05_with_inspector as coordinator


def args(mode='--plan', cohort=profile.COHORT):
    pairs = {
        'cohort': cohort, 'node': '/repo/node', 'node-sha256': 'a' * 64,
        'docker': '/repo/docker', 'docker-sha256': 'b' * 64,
        'docker-host': 'unix:///repo/.qualification/goat-q/docker.sock',
        'daemon-id': '945f6fce-3aaf-4d8f-a483-170464fb2416',
        'image-id': 'sha256:' + 'c' * 64, 'current-host-profile': 'goat-q',
        'chromium': '/browser/chrome', 'chromium-sha256': 'd' * 64,
        'browser-root': '/browser', 'python-sha256': 'e' * 64,
        'build-sha256': 'f' * 64,
        'build-report': '/repo/tasks/qualification/frontend-build-abcdef/report.json',
        'build-report-sha256': '1' * 64,
        'build-input-sha256': '2' * 64,
        'build-output-sha256': '3' * 64,
        'build-recorder-sha256': '4' * 64,
    }
    result = [mode] + [item for key, value in pairs.items() for item in ('--' + key, value)]
    if mode == '--run':
        result += ['--snapshot-sha256', '1' * 64]
    return result


def row(pid, ppid, start=10):
    return types.SimpleNamespace(pid=pid, ppid=ppid, pgid=pid, uid=os.getuid(),
                                 ruid=os.getuid(), start_sec=start, start_usec=20)


def fixture_receipt():
    actions = {}
    for name, fields in profile.ACTION_FACTS.items():
        actions[name] = {key: (21 if name.startswith('student') or name.startswith('account') else 22)
                         if key == 'targetId' else 2 if key == 'storageEventsObserved' else True
                         for key in fields}
    return dict(resources={'browser': {'pid': 222}}, testBody='passed', tempRootAbsent=False,
        status='browser_cleanup_delegated_to_current_host_launcher',
        cleanup=[{'name': 'server-close', 'ok': True}],
        q05=dict(status='bounded-rendered-manual-actions-observed', modelCalls=0, judgeCalls=0,
            siblingsPreserved=True, lateAck='one-response-discarded-after-mounted-effect',
            excluded=['student-reset', 'student-deletion', 'model-grading', 'full-Q05-denominator'],
            actions=actions, ackLoss={'method': 'PUT', 'path': '/api/admin/administrators/22',
                                     'phase': 'after-mounted-handler-before-response'},
            accountUnlockAckLoss={'method': 'POST', 'path': '/api/admin/users/21/unlock',
                                  'phase': 'after-mounted-handler-before-response'},
            administratorDeactivationAckLoss={'method': 'DELETE',
                'path': '/api/admin/administrators/22',
                'phase': 'after-real-http-200-before-browser-consumption',
                'status': 200, 'serverAcknowledgedInactive': True},
            administratorDeactivationResponseStage={'browserRequests': 1,
                'browserFailed': 1, 'browserFinished': 0, 'serverReceived': 1},
            studentPasswordResponseStage={'browserRequests': 1,
                'browserFailed': 1, 'browserFinished': 0},
            accountAccessServerReceived={'lock': 1, 'unlock': 1},
            administratorDeactivationServerReceived={'delete': 1},
            requestCounts={'POST /api/admin/users/21/lock': 1,
                           'POST /api/admin/users/21/unlock': 1,
                           'POST /api/admin/students/21/change-password': 1,
                           'DELETE /api/admin/administrators/22': 1}))


def reset_receipt():
    result = fixture_receipt()
    del result['q05']
    result['studentResetQ05'] = dict(version=1,
        status='bounded-rendered-student-reset-observed',
        workshopKey='sensitive_info_disclosure', targetId=21, siblingId=22,
        modelCalls=0, judgeCalls=0, canonicalCredit=False,
        seedProvenance='controlled-preexisting-completion-not-model-credit',
        facts=dict.fromkeys(profile.RESET_FACTS, True),
        requestOperationIds=['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'] * 2 +
                            ['bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'],
        realResetPostCount=3, deniedResetPostCount=1, originalGeneration=3, finalGeneration=5,
        ackLoss=dict(method='POST',
            path='/api/admin/students/21/workshops/sensitive_info_disclosure/reset',
            phase='after-real-http-200-before-browser-consumption'),
        excluded=list(profile.RESET_EXCLUSIONS),
        snapshots={name: dict(before='a' * 64, after='a' * 64)
                   for name in ('cancel', 'stagedAuthority', 'replay', 'sibling')})
    return result


class ResetAdmission(unittest.TestCase):
    def test_reset_selector_uses_same_fixed_coordinator_and_exact_grant(self):
        supplied = args('--run', profile.RESET_COHORT)
        parsed = coordinator.validate_arguments(supplied)
        self.assertEqual(parsed.cohort, profile.RESET_COHORT)
        grant = profile.admission_grant(Path('/repo'), parsed, 123, Path('/profile'))
        self.assertEqual(grant['cohort'], profile.RESET_COHORT)
        manual = profile.admission_grant(Path('/repo'), profile.arguments(args('--run')),
                                         123, Path('/profile'))
        self.assertEqual(manual['cohort'], profile.COHORT)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            profile.arguments(args('--plan', 'admin-arbitrary-reset'))

    def test_reset_admission_is_closed_until_reviewed_pins_exist(self):
        with patch.object(profile, 'RESET_RENDERED_PINS', None):
            with self.assertRaisesRegex(RuntimeError, 'not yet reviewed/pinned'):
                profile.selected_pins(profile.RESET_COHORT)
        self.assertIs(profile.selected_pins(profile.COHORT), profile.RENDERED_PINS)

    def test_frozen_reset_and_manual_pins_match_exact_current_source(self):
        repo = Path(profile.__file__).resolve().parents[2]
        for cohort in profile.COHORTS:
            pins = profile.selected_pins(cohort)
            for name, expected in pins.items():
                with self.subTest(cohort=cohort, path=name):
                    self.assertEqual(profile.sha(repo / name), expected)
        self.assertEqual(len(profile.RESET_RENDERED_PINS), 6)
        for name, expected in profile.RENDERED_PINS.items():
            self.assertEqual(profile.RESET_RENDERED_PINS[name], expected)

    def test_two_stores_four_roles_share_only_owned_nonce_and_loopback_port(self):
        from urllib.parse import urlparse
        parsed = profile.arguments(args('--run', profile.RESET_COHORT))
        env = profile.environment(Path('/repo'), Path('/repo/tasks/qualification/run-x/runtime'),
            55432, 'owasp_ai_goat_test_admin_browser_abcdef123456', parsed)
        urls = [urlparse(env[name]) for name in (
            'PG_ADMIN_BROWSER_TEST_RUNTIME_URL', 'PG_ADMIN_BROWSER_TEST_MIGRATION_URL',
            'FINFLOW_WORKSHOP_DATABASE_URL', 'FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL')]
        self.assertEqual(len({url.username for url in urls}), 4)
        self.assertEqual({url.path for url in urls}, {
            '/owasp_ai_goat_test_admin_browser_abcdef123456',
            '/owasp_ai_goat_test_student_reset_finflow_abcdef123456'})
        for url in urls:
            self.assertEqual((url.hostname, url.port, url.password, url.query, url.fragment),
                             ('127.0.0.1', 55432, None, '', ''))
        for name in ('PG_ADMIN_BROWSER_TEST_RUNTIME_URL', 'PG_ADMIN_BROWSER_TEST_MIGRATION_URL',
                     'FINFLOW_WORKSHOP_DATABASE_URL', 'FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL'):
            original = env[name]
            for replacement in (
                    original.replace('127.0.0.1', 'localhost'),
                    original.replace(':55432/', ':55433/'),
                    original.replace('abcdef123456', 'bbbbbb123456'),
                    original + '?options=unsafe',
                    original.replace('@', ':password@'),
                    env['PG_ADMIN_BROWSER_TEST_RUNTIME_URL'] if name.startswith('FINFLOW')
                    else env['FINFLOW_WORKSHOP_DATABASE_URL']):
                changed = {**env, name: replacement}
                with self.subTest(variable=name, replacement=replacement), self.assertRaises(RuntimeError):
                    profile.validate_database_environment(changed, profile.RESET_COHORT,
                                                          'abcdef123456', 55432)
        self.assertEqual(env['ADMIN_Q05_COHORT'], profile.RESET_COHORT)
        self.assertEqual(env['ADMIN_STUDENT_RESET_ONLY'], '1')
        self.assertEqual(env['PLATFORM_DATABASE_ENGINE'], 'postgres')
        self.assertEqual(env['WORKSHOP_DATABASE_ENGINE'], 'postgres')
        self.assertEqual(env['SENSITIVE_INFO_AGGREGATE_RESET_ENABLED'], 'true')
        manual = profile.environment(Path('/repo'), Path('/repo/runtime'), 55432,
            'owasp_ai_goat_test_admin_browser_abcdef123456', profile.arguments(args('--run')))
        for name in ('FINFLOW_WORKSHOP_DATABASE_URL', 'ADMIN_STUDENT_RESET_ONLY', 'ADMIN_Q05_COHORT'):
            self.assertNotIn(name, manual)
        for database, port in (
                ('application_database', 55432), ('owasp_ai_goat_test_admin_browser_abcdef123456;SQL', 55432),
                ('owasp_ai_goat_test_admin_browser_abcdef123456', True),
                ('owasp_ai_goat_test_admin_browser_abcdef123456', 65536)):
            with self.assertRaisesRegex(RuntimeError, 'owned database/port'):
                profile.environment(Path('/repo'), Path('/repo/runtime'), port, database, parsed)

    def test_database_commands_are_closed_separate_and_preserve_manual_commands(self):
        manual = list(profile.database_statements(profile.COHORT, 'abcdef123456'))
        reset = list(profile.database_statements(profile.RESET_COHORT, 'abcdef123456'))
        self.assertEqual(reset[:3], manual)
        self.assertEqual(len(reset), 6)
        self.assertEqual(sum('CREATE DATABASE' in sql for sql in reset), 2)
        self.assertEqual(sum(sql.count('CREATE ROLE ') for sql in reset), 4)
        self.assertIn('REVOKE ALL ON DATABASE owasp_ai_goat_test_student_reset_finflow_abcdef123456 FROM PUBLIC',
                      reset[-1])
        self.assertNotIn('identity', ''.join(reset[3:]))
        for nonce in ('', 'ABCDEF123456', 'abcdef123456;'):
            with self.assertRaises(RuntimeError):
                list(profile.database_statements(profile.RESET_COHORT, nonce))

    def test_reset_receipt_is_separate_and_requires_all_cases(self):
        profile.verify_fixture(reset_receipt(), profile.RESET_COHORT)
        with self.assertRaises(RuntimeError):
            profile.verify_fixture(reset_receipt())
        with self.assertRaises(RuntimeError):
            profile.verify_fixture(fixture_receipt(), profile.RESET_COHORT)
        for key in profile.RESET_FACTS:
            changed = reset_receipt()
            changed['studentResetQ05']['facts'][key] = False
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, 'acceptance'):
                profile.verify_fixture(changed, profile.RESET_COHORT)

    def test_reset_receipt_rejects_scope_identity_effect_and_exclusion_overclaims(self):
        mutations = (
            lambda f: f.update(modelCalls=1),
            lambda f: f.update(judgeCalls=True),
            lambda f: f.update(canonicalCredit=True),
            lambda f: f.update(seedProvenance='actual-model-credit'),
            lambda f: f.update(siblingId=f['targetId']),
            lambda f: f.update(finalGeneration=4),
            lambda f: f.update(originalGeneration=True),
            lambda f: f.update(realResetPostCount=4),
            lambda f: f.update(deniedResetPostCount=0),
            lambda f: f['requestOperationIds'].__setitem__(1, f['requestOperationIds'][2]),
            lambda f: f['requestOperationIds'].__setitem__(2, f['requestOperationIds'][0]),
            lambda f: f['ackLoss'].update(phase='after-mounted-handler-before-response'),
            lambda f: f['ackLoss'].update(path='/api/admin/students/22/workshops/sensitive_info_disclosure/reset'),
            lambda f: f['excluded'].remove('inflight-model-cancellation'),
            lambda f: f['snapshots']['cancel'].update(after='b' * 64),
            lambda f: f['snapshots'].pop('stagedAuthority'),
            lambda f: f['snapshots']['sibling'].update(before='', after=''),
            lambda f: f.update(backupTraversalTested=True),
        )
        for mutate in mutations:
            changed = reset_receipt()
            mutate(changed['studentResetQ05'])
            with self.subTest(mutation=mutate), self.assertRaises(RuntimeError):
                profile.verify_fixture(changed, profile.RESET_COHORT)


class API:
    def __init__(self):
        self.rows = {111: row(111, os.getpid()), 222: row(222, 111)}
        self.argv = ('/browser/chrome', '--user-data-dir=/profile', '--no-sandbox')

    def identity(self, pid):
        return self.rows.get(pid)

    short_identity = identity

    def all_pids(self):
        return list(self.rows)

    def arguments(self, _pid):
        return self.argv


class Admission(unittest.TestCase):
    def test_partial_failed_journal_is_retained_without_promoting_run(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            (runtime / 'tmp').mkdir()
            partial = {'testBody': 'failed', 'q05': {'status': 'running', 'actions': {
                'studentCreate': {'oneConfirmedRequest': True}}}}
            profile.private_json(runtime / 'tmp/admin-browser-resources.json', partial)
            state = {'status': 'failed'}
            profile.retain_fixture_journal(state, runtime)
            self.assertEqual(state['fixture'], partial)
            self.assertEqual(state['fixtureCapture']['status'], 'saved')
            self.assertEqual(state['status'], 'failed')

    def test_missing_or_invalid_original_journal_retains_capture_error(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            state = {'status': 'passed'}
            profile.retain_fixture_journal(state, runtime)
            self.assertEqual(state['status'], 'failed')
            self.assertEqual(state['fixtureCapture']['error']['type'], 'FileNotFoundError')
            (runtime / 'tmp').mkdir()
            path = runtime / 'tmp/admin-browser-resources.json'
            path.write_text('invalid-json')
            os.chmod(path, 0o600)
            profile.retain_fixture_journal(state, runtime)
            self.assertEqual(state['fixtureCapture']['status'], 'unavailable')
            self.assertEqual(state['fixtureCapture']['error']['type'], 'JSONDecodeError')

    def test_command_failure_retains_bounded_original_stderr_without_retry(self):
        original = b'psql: connection refused\n'
        result = profile.failure_details(subprocess.CalledProcessError(
            2, ['docker', 'exec', 'owned', 'psql'], stderr=original))
        self.assertEqual(result['exitCode'], 2)
        self.assertEqual(result['stderr'], original.decode())
        self.assertFalse(result['stderrTruncated'])
        large = profile.failure_details(subprocess.TimeoutExpired(
            ['docker', 'exec', 'owned', 'psql'], 15, stderr=b'x' * 10000))
        self.assertEqual(len(large['stderr']), 8192)
        self.assertEqual(large['stderrBytes'], 10000)
        self.assertTrue(large['stderrTruncated'])

    def test_physical_python_accepts_only_exact_same_framework_app_or_direct_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            version = Path(directory) / 'Python.framework/Versions/3.14'
            launcher = version / 'bin/python3.14'
            actual = version / 'Resources/Python.app/Contents/MacOS/Python'
            launcher.parent.mkdir(parents=True)
            actual.parent.mkdir(parents=True)
            launcher.write_text('pinned bootstrap')
            actual.write_text('pinned actual interpreter')
            self.assertEqual(profile.physical_python_path(launcher, str(actual)), actual)
            self.assertEqual(profile.physical_python_path(launcher, str(launcher)), launcher)
            unrelated = Path(directory) / 'Python'
            unrelated.write_text('same name is not authority')
            with self.assertRaisesRegex(RuntimeError, 'physical interpreter'):
                profile.physical_python_path(launcher, str(unrelated))
            foreign_version = Path(str(actual).replace('/3.14/', '/3.13/'))
            foreign_version.parent.mkdir(parents=True)
            foreign_version.write_text('other runtime')
            with self.assertRaisesRegex(RuntimeError, 'physical interpreter'):
                profile.physical_python_path(launcher, str(foreign_version))
            actual.unlink()
            actual.symlink_to(unrelated)
            with self.assertRaisesRegex(RuntimeError, 'physical interpreter'):
                profile.physical_python_path(launcher, str(actual))

    def test_missing_action_false_claim_and_unbound_ack_fail_receipt(self):
        original = fixture_receipt()
        profile.verify_fixture(original)
        for change in (
            lambda value: value['q05']['actions'].pop('studentEdit'),
            lambda value: value['q05']['actions']['selfPassword'].update(freshLogin=False),
            lambda value: value['q05']['actions']['studentEdit'].update(targetId=999),
            lambda value: value['q05']['actions']['studentPassword'].update(crossTabAbaNoRequest=False),
            lambda value: value['q05']['actions']['studentPassword'].update(storageEventsObserved=1),
            lambda value: value['q05']['actions']['studentPassword'].update(storageEventsObserved=3),
            lambda value: value['q05']['actions']['studentPassword'].update(storageEventsObserved=True),
            lambda value: value['q05']['actions']['studentPassword'].update(secretsRetired=False),
            lambda value: value['q05']['actions']['studentPassword'].update(lostAckEffectPersisted=False),
            lambda value: value['q05']['actions']['studentPassword'].update(unknownUiNoRetry=False),
            lambda value: value['q05']['actions']['studentPassword'].update(responseStageBrowserFailure=False),
            lambda value: value['q05']['actions']['studentPassword'].pop('secretsRetired'),
            lambda value: value['q05']['actions']['accountLock'].update(storageEventsObserved=0),
            lambda value: value['q05']['actions']['accountUnlock'].update(targetId=999),
            lambda value: value['q05']['actions']['administratorDeactivation'].update(inactive=False),
            lambda value: value['q05']['actions']['administratorDeactivation'].update(sessionsRevoked=False),
            lambda value: value['q05']['actions']['administratorDeactivation'].update(responseStageBrowserFailure=False),
            lambda value: value['q05']['actions']['administratorDeactivation'].update(actorPreserved=False),
            lambda value: value['q05']['actions']['administratorDeactivation'].update(siblingsPreserved=False),
            lambda value: value['q05']['actions']['administratorDeactivation'].update(targetId=999),
            lambda value: value['q05']['actions']['administratorDeactivation'].update(storageEventsObserved=3),
            lambda value: value['q05']['ackLoss'].update(path='/api/admin/administrators/99'),
            lambda value: value['q05']['administratorDeactivationAckLoss'].update(status=202),
            lambda value: value['q05']['administratorDeactivationAckLoss'].update(phase='after-mounted-handler-before-response'),
            lambda value: value['q05']['administratorDeactivationAckLoss'].update(status=200.0),
            lambda value: value['q05']['administratorDeactivationAckLoss'].update(path='/api/admin/administrators/99'),
            lambda value: value['q05']['administratorDeactivationAckLoss'].update(serverAcknowledgedInactive=False),
            lambda value: value['q05']['administratorDeactivationAckLoss'].update(serverAcknowledgedInactive=1),
            lambda value: value['q05']['accountUnlockAckLoss'].update(path='/api/admin/users/99/unlock'),
            lambda value: value['q05']['requestCounts'].update({'POST /api/admin/users/21/lock': 2}),
            lambda value: value['q05']['requestCounts'].update({'POST /api/admin/students/21/change-password': 2}),
            lambda value: value['q05']['requestCounts'].pop('POST /api/admin/students/21/change-password'),
            lambda value: value['q05']['requestCounts'].update({'POST /api/admin/students/99/change-password': 1}),
            lambda value: value['q05']['requestCounts'].update({'POST /api/admin/students/21/change-password': True}),
            lambda value: value['q05']['requestCounts'].update({'DELETE /api/admin/administrators/22': 2}),
            lambda value: value['q05']['requestCounts'].update({'DELETE /api/admin/administrators/22': True}),
            lambda value: value['q05']['requestCounts'].update({'DELETE /api/admin/administrators/99': 1}),
            lambda value: value['q05']['accountAccessServerReceived'].update(unlock=2),
            lambda value: value['q05']['administratorDeactivationServerReceived'].update(delete=2),
            lambda value: value['q05']['administratorDeactivationServerReceived'].update(delete=True),
            lambda value: value['q05']['administratorDeactivationResponseStage'].update(browserFailed=0),
            lambda value: value['q05']['administratorDeactivationResponseStage'].update(browserFailed=True),
            lambda value: value['q05']['administratorDeactivationResponseStage'].update(browserFinished=1),
            lambda value: value['q05']['administratorDeactivationResponseStage'].update(browserRequests=2),
            lambda value: value['q05']['administratorDeactivationResponseStage'].update(serverReceived=2),
            lambda value: value['q05']['administratorDeactivationResponseStage'].update(extra=0),
            lambda value: value['q05'].pop('studentPasswordResponseStage'),
            lambda value: value['q05']['studentPasswordResponseStage'].update(browserRequests=2),
            lambda value: value['q05']['studentPasswordResponseStage'].update(browserFailed=0),
            lambda value: value['q05']['studentPasswordResponseStage'].update(browserFailed=True),
            lambda value: value['q05']['studentPasswordResponseStage'].update(browserFinished=1),
            lambda value: value['q05']['studentPasswordResponseStage'].update(extra=0),
            lambda value: value['q05'].update(modelCalls=True),
            lambda value: value.update(cleanup=[]),
        ):
            changed = copy.deepcopy(original)
            change(changed)
            with self.assertRaises(RuntimeError):
                profile.verify_fixture(changed)

    def test_closed_parser_requires_explicit_execution_pin_and_rejects_duplicates(self):
        self.assertTrue(profile.arguments(args()).plan)
        self.assertTrue(profile.arguments(args('--run')).run)
        with self.assertRaisesRegex(RuntimeError, 'snapshot'):
            profile.arguments(args('--run')[:-2])
        with self.assertRaisesRegex(RuntimeError, 'Duplicate'):
            profile.arguments(args() + ['--cohort', profile.COHORT])
        with self.assertRaisesRegex(RuntimeError, 'execution only'):
            coordinator.validate_arguments(args())

    def test_plan_does_not_allocate_or_start_resources(self):
        with patch.object(profile, 'snapshot', return_value={'controlled': True}), \
                patch.object(profile, 'validate_current_host') as validate, \
                patch.object(profile, 'consume_environment') as consume, \
                patch.object(profile.subprocess, 'Popen') as spawn, \
                patch.object(Path, 'mkdir') as mkdir, contextlib.redirect_stdout(io.StringIO()) as text:
            self.assertEqual(profile.main(args()), 0)
        self.assertFalse(json.loads(text.getvalue())['actualExecution'])
        for mock in (validate, consume, spawn, mkdir):
            mock.assert_not_called()

    def test_run_refuses_missing_inspector_before_allocating(self):
        value = {'controlled': True}
        supplied = args('--run')
        supplied[-1] = profile.encoded(value)
        with patch.object(profile, 'snapshot', return_value=value), \
                patch.object(profile.sys, 'platform', 'darwin'), \
                patch.object(profile, 'consume_environment', return_value=None), \
                patch.object(Path, 'mkdir') as mkdir:
            with self.assertRaisesRegex(RuntimeError, 'inspector required'):
                profile.main(supplied)
        mkdir.assert_not_called()

    def test_environment_is_repo_only_and_does_not_forward_inspector(self):
        parsed = profile.arguments(args('--run'))
        env = profile.environment(Path('/repo'), Path('/repo/tasks/qualification/run-x/runtime'),
                                  55432, 'owasp_ai_goat_test_admin_browser_abcdef123456', parsed)
        for key in ('HOME', 'TMPDIR', 'TMP', 'TEMP', 'MAC_CHROMIUM_TMPDIR',
                    'XDG_CACHE_HOME', 'LOGS_DIR', 'OWASP_AI_GOAT_APP_DATA_ROOT',
                    'ADMIN_Q05_BROWSER_ACK'):
            self.assertTrue(env[key].startswith('/repo/tasks/qualification/run-x/runtime/'))
        self.assertNotIn('OWASP_AI_GOAT_PROCESS_INSPECTOR_FD', env)
        self.assertEqual(env['ADMIN_Q05_SNAPSHOT_SHA256'], '1' * 64)
        self.assertEqual(env['OWASP_AI_GOAT_CHROMIUM_ACTUAL_EXECUTABLE'], env['PUPPETEER_EXECUTABLE_PATH'])
        self.assertNotEqual(env['PG_ADMIN_BROWSER_TEST_RUNTIME_URL'],
                            env['PG_ADMIN_BROWSER_TEST_MIGRATION_URL'])

    def test_grant_is_exact_child_bound_and_nonce_fresh(self):
        parsed = profile.arguments(args('--run'))
        one = profile.admission_grant(Path('/repo'), parsed, 123, Path('/profile'))
        two = profile.admission_grant(Path('/repo'), parsed, 123, Path('/profile'))
        self.assertEqual(one['launcherPid'], os.getpid())
        self.assertEqual(one['workerPid'], 123)
        self.assertEqual(one['outerSandbox'], 'repository-only')
        self.assertRegex(one['nonce'], '^[a-f0-9]{64}$')
        self.assertNotEqual(one['nonce'], two['nonce'])
        self.assertLess(len(json.dumps(one).encode()), 8192)

    def test_current_files_and_build_digest_are_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'index.html').write_text('owned build')
            (root / 'asset.js').write_text('asset')
            observed = profile.files(root)
            self.assertEqual(list(observed), ['asset.js', 'index.html'])
            first = profile.encoded(observed)
            (root / 'asset.js').write_text('changed')
            self.assertNotEqual(first, profile.encoded(profile.files(root)))
            (root / 'link').symlink_to(root / 'asset.js')
            with self.assertRaisesRegex(RuntimeError, 'links'):
                profile.files(root)

    def test_private_journal_rejects_public_or_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            profile.private_json(path, {'ok': True})
            self.assertEqual(profile.read_private(path), {'ok': True})
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                profile.read_private(path)
            link = Path(directory) / 'link'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                profile.read_private(link)

    def test_tap_requires_exact_title_count_and_zero_skips(self):
        text = f'ok 1 - {profile.TITLE}\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n'
        profile.verify_tap(text)
        for bad in (text.replace('skipped 0', 'skipped 1'), text.replace('tests 1', 'tests 2'),
                    text.replace(profile.TITLE, 'other case'), text.replace('pass 1', 'pass 0')):
            with self.assertRaises(RuntimeError):
                profile.verify_tap(bad)

    def test_fixed_parent_and_readonly_sandbox_policy_are_required(self):
        argv = args('--run')
        parent = os.getppid()
        api = Mock()
        api.identity.return_value = row(parent, 1)
        api.arguments.return_value = (str(Path(profile.sys.executable).resolve()), '-B',
            '/repo/tests/postgres/run_admin_q05_with_inspector.py', *argv)
        client = types.SimpleNamespace(parent=parent)
        with patch.object(profile.os, 'getppid', return_value=parent):
            profile.verify_outer_boundary(Path('/repo'), argv, client, api=api,
                                          denied=lambda path: str(path) == '/private/tmp')
            with self.assertRaisesRegex(RuntimeError, 'write sandbox'):
                profile.verify_outer_boundary(Path('/repo'), argv, client, api=api,
                                              denied=lambda _path: False)
            api.arguments.return_value = ('/usr/bin/python3', '-c', 'forged parent')
            with self.assertRaisesRegex(RuntimeError, 'fixed outside'):
                profile.verify_outer_boundary(Path('/repo'), argv, client, api=api,
                                              denied=lambda _path: True)

    def test_build_provenance_binds_reviewed_verifier_and_explicit_report_pins(self):
        parsed = profile.arguments(args())
        repo = Path(__file__).resolve().parents[2]
        calls = []
        qualified = {'exitCode': 0, 'inputMode': 'legacy',
                     'repositoryOnly': True, 'qualified': True}

        def check(*values, **options):
            calls.append((values, options))
            return qualified

        imported = types.SimpleNamespace(validate_frontend_build_report=check)
        loader = types.SimpleNamespace(exec_module=lambda _module: None)
        with patch.object(profile.importlib.util, 'spec_from_file_location',
                          return_value=types.SimpleNamespace(loader=loader)), \
             patch.object(profile.importlib.util, 'module_from_spec', return_value=imported):
            result = profile.validate_modern_build_receipt(repo, parsed)
            self.assertEqual(result['reportSha256'], '1' * 64)
            self.assertEqual(calls[0][0], (repo, Path(parsed.build_report),
                '1' * 64, '2' * 64, '3' * 64, '4' * 64))
            self.assertEqual(calls[0][1], {'private_external': False,
                'require_installed_match': True})
            parsed.build_report_sha256 = 'bad'
            with self.assertRaisesRegex(RuntimeError, 'pins'):
                profile.validate_modern_build_receipt(repo, parsed)
            parsed.build_report_sha256 = '1' * 64
            qualified['exitCode'] = False
            with self.assertRaisesRegex(RuntimeError, 'successful repository-only'):
                profile.validate_modern_build_receipt(repo, parsed)

    def test_build_verifier_symlink_or_hash_mismatch_never_invokes_loader(self):
        parsed = profile.arguments(args())
        repo = Path(__file__).resolve().parents[2]
        with patch.object(profile.importlib.util, 'spec_from_file_location') as loader, \
             patch.object(profile, 'BUILD_VERIFIER_SHA256', '0' * 64):
            with self.assertRaisesRegex(RuntimeError, 'source pin'):
                profile.validate_modern_build_receipt(repo, parsed)
            loader.assert_not_called()

        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory)
            (fake / 'tests/postgres').mkdir(parents=True)
            verifier = fake / 'tests/postgres/run-ctf-stages-route-isolated.py'
            verifier.symlink_to(repo / 'tests/postgres/run-ctf-stages-route-isolated.py')
            with patch.object(profile.importlib.util, 'spec_from_file_location') as loader:
                with self.assertRaisesRegex(RuntimeError, 'source pin'):
                    profile.validate_modern_build_receipt(fake, parsed)
                loader.assert_not_called()

    def test_actual_current_build_verifier_checks_artifacts_and_provenance(self):
        """Execute both actual verifier imports; only inventory leaves are controlled.

        No build or dependency-tree scan is performed. The real recorder hashes
        tiny owned trees, while the real verifier validates the receipt, runtime
        pins, evidence paths, artifact hashes and inventory joins. This is not a
        qualified application build receipt and is removed with the test area.
        """
        repo = Path(__file__).resolve().parents[2]
        parsed = profile.arguments(args())
        recorder_path = repo / 'tests/release-inputs/record-current-frontend-build.py'
        node = repo / 'tasks/runtime/node/node_modules/node/bin/node'
        npm = Path('/opt/homebrew/lib/node_modules/npm/bin/npm-cli.js')
        original_exec = importlib.machinery.SourceFileLoader.exec_module
        loaded = []
        with tempfile.TemporaryDirectory(prefix='frontend-build-controlled-',
                dir=repo / 'tasks/qualification') as directory:
            area = Path(directory)
            area.chmod(0o700)
            input_tree, output_tree = area / 'controlled-input', area / 'controlled-output'
            input_tree.mkdir(); output_tree.mkdir()
            (input_tree / 'source.txt').write_text('controlled input\n')
            (output_tree / 'index.html').write_text('controlled output\n')

            spec = importlib.util.spec_from_file_location('q05_controlled_recorder', recorder_path)
            recorder = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(recorder)
            inputs = recorder.inventory(input_tree)
            outputs = recorder.inventory(output_tree)
            parsed.build_input_sha256 = recorder.fingerprint(inputs)
            parsed.build_output_sha256 = recorder.fingerprint(outputs)
            parsed.build_recorder_sha256 = profile.sha(recorder_path)
            parsed.build_report = str(area / 'report.json')

            def execute(loader, module):
                original_exec(loader, module)
                loaded.append(module.__name__)
                if module.__name__ == 'owasp_ai_goat_frontend_build_receipt':
                    actual_inventory = module.inventory

                    def current_inputs(root):
                        self.assertEqual(root, repo)
                        return actual_inventory(input_tree)

                    def current_output(root):
                        self.assertEqual(root, repo / 'client/build')
                        return actual_inventory(output_tree)

                    module.inputs = current_inputs
                    module.inventory = current_output

            def prepare(change=None, artifact_change=None):
                values = {'inputs-before.json': inputs, 'inputs-after.json': inputs,
                          'output.json': outputs}
                if artifact_change:
                    values[artifact_change] = {'coherently-rehashed-wrong-inventory': {}}
                artifacts = {}
                for name, value in values.items():
                    path = area / name
                    path.write_text(json.dumps(value))
                    artifacts[name] = profile.sha(path)
                report = dict(exitCode=0, inputMode='legacy', repositoryOnly=True,
                    qualified=True, beforeAfterInputsEqual=True, workspace=str(repo),
                    outputRoot=str(repo / 'client/build'),
                    command=[str(node), str(npm), '--prefix', 'client', 'run', 'build'],
                    runtimePins={key: {'path': str(path), 'sha256': profile.sha(path)}
                                 for key, path in (('node', node), ('npm', npm))},
                    buildInputInventorySha256=parsed.build_input_sha256,
                    clientBuildInventorySha256=parsed.build_output_sha256,
                    artifacts=artifacts)
                if change:
                    report.update(change)
                Path(parsed.build_report).write_text(json.dumps(report))
                parsed.build_report_sha256 = profile.sha(Path(parsed.build_report))

            with patch.object(importlib.machinery.SourceFileLoader, 'exec_module', execute):
                prepare()
                result = profile.validate_modern_build_receipt(repo, parsed)
                self.assertEqual(result['reportSha256'], parsed.build_report_sha256)
                self.assertIn('q05_reviewed_frontend_build_verifier', loaded)
                self.assertIn('owasp_ai_goat_frontend_build_receipt', loaded)
                for change in ({'qualified': False}, {'beforeAfterInputsEqual': False},
                        {'buildInputInventorySha256': '0' * 64},
                        {'clientBuildInventorySha256': '0' * 64},
                        {'command': [str(node), 'unreviewed-build']},
                        {'runtimePins': {}}, {'repositoryOnly': False},
                        {'exitCode': False}, {'inputMode': 'private-external-v1'}):
                    with self.subTest(change=change):
                        prepare(change)
                        with self.assertRaises(RuntimeError):
                            profile.validate_modern_build_receipt(repo, parsed)
                for name in ('inputs-before.json', 'inputs-after.json', 'output.json'):
                    with self.subTest(artifact=name):
                        prepare(artifact_change=name)
                        with self.assertRaises(RuntimeError):
                            profile.validate_modern_build_receipt(repo, parsed)
                prepare()
                (area / 'output.json').write_text('{}')
                with self.assertRaisesRegex(RuntimeError, 'artifact mismatch'):
                    profile.validate_modern_build_receipt(repo, parsed)
                prepare()
                parsed.build_report_sha256 = '0' * 64
                with self.assertRaisesRegex(RuntimeError, 'report pin mismatch'):
                    profile.validate_modern_build_receipt(repo, parsed)
                prepare()
                parsed.build_recorder_sha256 = '0' * 64
                with self.assertRaisesRegex(RuntimeError, 'recorder pin mismatch'):
                    profile.validate_modern_build_receipt(repo, parsed)
class Ownership(unittest.TestCase):
    def setUp(self):
        self.api = API()
        self.signals = []
        self.owned = profile.Owned(self.api, getsid=lambda pid: pid,
                                   kill=lambda pid, number: self.signals.append((pid, number)))
        self.owned.register_child(111)

    def test_browser_ack_requires_live_birth_ancestry_executable_profile_and_flag(self):
        ack = self.owned.register_browser(222, 111, Path('/profile'), Path('/browser/chrome'))
        self.assertEqual(ack['startSec'], 10)
        self.assertEqual(ack['pid'], 222)
        self.assertEqual(ack['profile'], '/profile')
        self.api.argv = ('/browser/chrome', '--user-data-dir=/other', '--no-sandbox')
        with self.assertRaisesRegex(RuntimeError, 'arguments'):
            self.owned.register_browser(222, 111, Path('/profile'), Path('/browser/chrome'))
        self.api.rows[222].ppid = 999
        with self.assertRaisesRegex(RuntimeError, 'direct child'):
            self.owned.register_browser(222, 111, Path('/profile'), Path('/browser/chrome'))

    def test_forged_journal_pid_cannot_authorize_signal(self):
        with self.assertRaisesRegex(RuntimeError, 'ownership'):
            self.owned.signal(222, signal.SIGTERM)
        self.assertEqual(self.signals, [])

    def test_pid_reuse_uid_transition_and_session_change_deny_signal(self):
        self.api.rows[111].start_sec += 1
        with self.assertRaisesRegex(RuntimeError, 'birth'):
            self.owned.signal(111, signal.SIGTERM)
        self.api.rows[111].start_sec -= 1
        self.api.rows[111].uid += 1
        with self.assertRaisesRegex(RuntimeError, 'same-user'):
            self.owned.signal(111, signal.SIGTERM)
        self.api.rows[111].uid -= 1
        self.owned.getsid = lambda _pid: 999
        with self.assertRaisesRegex(RuntimeError, 'birth'):
            self.owned.signal(111, signal.SIGTERM)
        self.assertEqual(self.signals, [])

    def test_live_signal_and_absent_process_do_not_signal_other_pid(self):
        self.owned.signal(111, signal.SIGTERM)
        self.assertEqual(self.signals, [(111, signal.SIGTERM)])
        del self.api.rows[111]
        self.owned.signal(111, signal.SIGKILL)
        self.assertEqual(len(self.signals), 1)

    def test_observed_descendants_not_foreign_roots_gain_signal_authority(self):
        self.api.rows[333] = row(333, 444)
        self.owned.observe()
        self.assertIn(222, self.owned.records)
        self.assertNotIn(333, self.owned.records)
        self.owned.signal(222, signal.SIGTERM)
        self.assertEqual(self.signals, [(222, signal.SIGTERM)])

    def test_parent_birth_change_denies_browser_ack(self):
        self.api.rows[111].start_sec += 1
        with self.assertRaisesRegex(RuntimeError, 'parent changed'):
            self.owned.register_browser(222, 111, Path('/profile'), Path('/browser/chrome'))


class Structure(unittest.TestCase):
    def test_fixed_coordinator_and_single_process_fixture(self):
        source = Path(profile.__file__).read_text()
        outer = Path(coordinator.__file__).read_text()
        self.assertIn("'--test-isolation=none'", source)
        self.assertIn('pass_fds=(admission_read,)', source)
        self.assertIn("fixture_env['ADMIN_Q05_ADMISSION_FD']", source)
        self.assertIn("consume_environment()", source)
        self.assertIn("'--pull', 'never'", source)
        self.assertNotIn('killpg(', source)
        self.assertIn("pass_fds=(worker.fileno(),)", outer)
        self.assertIn("'tasks/run-in-repository.sh'", outer)
        self.assertIn("'temporary-profiles'", source)
        self.assertIn("'size=536870912'", source.replace('/var/lib/postgresql:rw,', ''))
        for name in ('tasks/run-in-repository.sh', 'tasks/repository-only.sb'):
            self.assertIn(name, profile.CONTROL_FILES)

    def test_dispatch_preserves_failure_exit_and_historical_path(self):
        path = Path(profile.__file__).with_name('run-admin-auth-browser-cohort-isolated.py')
        spec = importlib.util.spec_from_file_location('admin_q05_legacy_dispatch', path)
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)
        with patch.object(profile, 'main', return_value=1):
            with self.assertRaisesRegex(RuntimeError, 'qualification failed'):
                launcher.main(['--cohort', profile.COHORT])
            with self.assertRaisesRegex(RuntimeError, 'qualification failed'):
                launcher.main(['--cohort', profile.RESET_COHORT])
        with patch.object(profile, 'main', return_value=0) as new, \
                patch.object(launcher, 'current_profile_arguments', return_value=[]) as old:
            launcher.main(['--cohort', 'platform-auth-ctf0123'])
        new.assert_not_called()
        old.assert_called_once()


class ControlledLifecycle(unittest.TestCase):
    def execute(self, *, profile_absent=True, postflight_error=False, setup_error=False,
                fixture_failed=False, cohort=profile.COHORT):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        repo = Path(temporary.name)
        parent = repo / 'tasks/qualification'
        parent.mkdir(parents=True, mode=0o700)
        supplied = args('--run', cohort)
        before = {'controlled': True}
        supplied[-1] = profile.encoded(before)
        parsed = profile.arguments(supplied)
        docker_state = {'present': False, 'id': 'a' * 64, 'name': None, 'owner': None}
        commands = []
        spawned = []

        def run(argv, **_options):
            commands.append(argv)
            command = argv[3:]
            result = types.SimpleNamespace(returncode=0, stdout='', stderr='')
            if command[:1] == ['info']:
                result.stdout = parsed.daemon_id
            elif command[:2] == ['image', 'inspect']:
                result.stdout = json.dumps([{'Id': parsed.image_id}])
            elif command[:1] == ['run']:
                docker_state.update(present=True, name=command[command.index('--name') + 1],
                    owner=command[command.index('--label') + 1].split('=', 1)[1])
            elif command[:2] == ['container', 'inspect']:
                if docker_state['present']:
                    result.stdout = json.dumps([{
                        'Id': docker_state['id'], 'Config': {'Labels': {
                            'owasp-ai-goat.test.owner': docker_state['owner']}},
                        'NetworkSettings': {'Ports': {'5432/tcp': [
                            {'HostIp': '127.0.0.1', 'HostPort': '55432'}]}}}])
                else:
                    result.returncode = 1
                    result.stderr = 'Error: No such object: ' + command[2]
            elif command[:2] == ['rm', '-f']:
                docker_state['present'] = False
            elif setup_error and 'psql' in command and any('CREATE DATABASE' in item for item in command):
                raise subprocess.CalledProcessError(2, argv,
                    stderr='psql: controlled bootstrap connection failure\n')
            return result

        class Child:
            pid = 111
            returncode = None
            count = 0

            def poll(self):
                self.count += 1
                if self.count > 1:
                    self.returncode = 1 if fixture_failed else 0
                return self.returncode

        def spawn(argv, **options):
            spawned.append((argv, options))
            # A real child inherits its own read descriptor; preserve that
            # ownership in this mock so the parent's pipe write is meaningful.
            inherited = os.dup(options['pass_fds'][0])
            self.addCleanup(os.close, inherited)
            options['stdout'].write((f'ok 1 - {profile.TITLE}\n# tests 1\n# pass 1\n'
                                     '# fail 0\n# skipped 0\n').encode())
            options['stdout'].flush()
            journal = Path(options['env']['PG_ADMIN_BROWSER_RESOURCE_JOURNAL'])
            receipt = reset_receipt() if cohort == profile.RESET_COHORT else fixture_receipt()
            if fixture_failed:
                receipt.update(testBody='failed', q05={'status': 'running', 'actions': {}})
            profile.private_json(journal, receipt)
            return Child()

        owner = Mock()
        owner.records = {111: {'controlledBirth': 123}}
        owner.register_browser.return_value = {'pid': 222, 'controlled': True}
        owner.stop.return_value = True
        inspector = Mock()
        inspector.absent.return_value = profile_absent
        signal_before = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
        snapshots = [before, RuntimeError('controlled postflight failure') if postflight_error else before]
        with patch.object(profile, '__file__', str(repo / 'tests/postgres/admin_q05_current_host.py')), \
                patch.object(profile, 'snapshot', side_effect=snapshots), \
                patch.object(profile.sys, 'platform', 'darwin'), \
                patch.object(profile, 'consume_environment', return_value=inspector), \
                patch.object(profile, 'verify_outer_boundary'), \
                patch.object(profile, 'validate_current_host', return_value={'controlled': True}), \
                patch.object(profile, 'evidence_parent', return_value=parent), \
                patch.object(profile, 'Owned', return_value=owner), \
                patch.object(profile.subprocess, 'run', side_effect=run), \
                patch.object(profile.subprocess, 'Popen', side_effect=spawn), \
                patch.object(profile.time, 'sleep'), contextlib.redirect_stdout(io.StringIO()):
            code = profile.main(supplied)
        receipt = json.loads(next(parent.glob('run-*/result.json')).read_text())
        self.assertEqual(signal_before, {number: signal.getsignal(number) for number in signal_before})
        self.assertEqual(len(spawned), 0 if setup_error else 1)
        if not setup_error:
            self.assertNotIn('OWASP_AI_GOAT_PROCESS_INSPECTOR_FD', spawned[0][1]['env'])
            self.assertEqual(len(spawned[0][1]['pass_fds']), 1)
            self.assertIn('--test-isolation=none', spawned[0][0])
            owner.register_child.assert_called_once_with(111)
            owner.register_browser.assert_called_once()
        return code, receipt, commands, parent

    def test_complete_mocked_lifecycle_persists_only_after_verified_absence(self):
        code, receipt, commands, parent = self.execute()
        self.assertEqual(code, 0)
        self.assertEqual(receipt['status'], 'passed')
        self.assertTrue(receipt['sourceUnchanged'])
        self.assertTrue(all(receipt['cleanup'].values()))
        self.assertFalse(list(parent.glob('run-*/runtime')))
        self.assertEqual(sum(command[3:5] == ['rm', '-f'] for command in commands), 1)
        self.assertFalse(receipt['fullQ05Qualification'])
        self.assertEqual(receipt['fixtureCapture']['status'], 'saved')
        postgres = [command for command in commands if 'pg_isready' in command or 'psql' in command]
        self.assertEqual(len(postgres), 4)
        for command in postgres:
            self.assertEqual(command[command.index('-h') + 1], '127.0.0.1')
            self.assertEqual(command[command.index('-p') + 1], '5432')
        # No retries of any setup write, even though readiness itself is polled.
        self.assertEqual(sum('CREATE DATABASE' in ' '.join(command) for command in postgres), 1)

    def test_reset_mocked_lifecycle_owns_one_container_two_databases_and_no_extra_runtime(self):
        code, receipt, commands, parent = self.execute(cohort=profile.RESET_COHORT)
        self.assertEqual(code, 0)
        self.assertEqual(receipt['cohort'], profile.RESET_COHORT)
        self.assertEqual(set(receipt['stores']), {'identity', 'finflow'})
        self.assertEqual(receipt['fixture']['studentResetQ05']['realResetPostCount'], 3)
        self.assertEqual(sum(command[3:4] == ['run'] for command in commands), 1)
        self.assertEqual(sum('CREATE DATABASE' in ' '.join(command) for command in commands), 2)
        self.assertEqual(sum(' '.join(command).count('CREATE ROLE ') for command in commands), 4)
        container = next(command for command in commands if command[3:4] == ['run'])
        for flag, value in (('--memory', '1g'), ('--pids-limit', '128'),
                            ('--tmpfs', '/var/lib/postgresql:rw,size=536870912'),
                            ('--pull', 'never')):
            self.assertEqual(container[container.index(flag) + 1], value)
        self.assertTrue(all(receipt['cleanup'].values()))
        self.assertTrue(receipt['sourceUnchanged'])
        self.assertFalse(receipt['canonicalCredit'])
        self.assertFalse(receipt['fullQ05Qualification'])
        self.assertFalse(list(parent.glob('run-*/runtime')))

    def test_profile_uncertainty_retains_owned_runtime_and_cluster_and_fails(self):
        code, receipt, commands, parent = self.execute(profile_absent=False)
        self.assertEqual(code, 1)
        self.assertEqual(receipt['status'], 'failed')
        self.assertFalse(receipt['cleanup']['profileAbsence'])
        self.assertTrue(list(parent.glob('run-*/runtime')))
        self.assertFalse(any(command[3:5] == ['rm', '-f'] for command in commands))

    def test_failed_postflight_cannot_skip_failure_receipt_or_cleanups(self):
        code, receipt, _commands, _parent = self.execute(postflight_error=True)
        self.assertEqual(code, 1)
        self.assertFalse(receipt['sourceUnchanged'])
        self.assertIn('controlled postflight failure', receipt['integrityError'])
        self.assertTrue(receipt['cleanup']['containerIdAbsent'])

    def test_setup_failure_is_retained_with_stderr_and_never_retries_mutation(self):
        code, receipt, commands, _parent = self.execute(setup_error=True)
        self.assertEqual(code, 1)
        self.assertEqual(receipt['error']['exitCode'], 2)
        self.assertEqual(receipt['error']['stderr'], 'psql: controlled bootstrap connection failure\n')
        self.assertTrue(receipt['cleanup']['containerIdAbsent'])
        self.assertEqual(sum('CREATE DATABASE' in ' '.join(command) for command in commands), 1)

    def test_failed_native_worker_preserves_partial_journal_before_runtime_removal(self):
        code, receipt, _commands, parent = self.execute(fixture_failed=True)
        self.assertEqual(code, 1)
        self.assertEqual(receipt['fixture']['testBody'], 'failed')
        self.assertEqual(receipt['fixture']['q05'], {'status': 'running', 'actions': {}})
        self.assertEqual(receipt['fixtureCapture']['status'], 'saved')
        self.assertFalse(list(parent.glob('run-*/runtime')))
        self.assertTrue(receipt['cleanup']['containerIdAbsent'])


if __name__ == '__main__':
    unittest.main()
