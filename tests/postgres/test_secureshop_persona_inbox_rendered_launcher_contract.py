#!/usr/bin/env python3
"""Resource-free C31 launcher contracts; synthetic receipts never qualify C31.

The shared launcher owner adds C31_COHORT/C31_TEST/C31_TEST_SHA256,
C31_ASSERTION and c31_receipt(result_path, terminal_wire_path). Missing
integration deliberately fails this contract rather than silently skipping it.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    'secureshop_persona_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)
COHORT = 'standalone-persona-inbox-rendered-browser'
FIXTURE = 'tests/postgres/secureshopStandalonePersonaInboxRendered.integration.test.js'
TITLE = 'C31 standalone rendered advisory and enforced Persona Inbox with genuine actor and Judge'
SCOPE = 'C31 standalone rendered Persona Inbox; caller must verify physical cleanup'
MODEL = 'llama3.1:8b'
DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'
OBJECTIVES = ['ss_cross_persona_effect', 'ss_acl_advisory_effect', 'ss_acl_enforced_block']


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def documents():
    # Protocol-shaped controlled data only; no actor/Judge result is executed.
    calls = []
    for phase, role in [(None, 'tags'), ('advisory', 'actor'), ('advisory', 'actor'),
                        ('advisory', 'judge'), ('advisory', 'judge'),
                        ('enforced', 'actor'), ('enforced', 'actor'), ('enforced', 'judge')]:
        request = '' if role == 'tags' else json.dumps({
            'model': MODEL, 'stream': True, 'messages': [
                {'role': 'system', 'content': 'Controlled contract only'},
                {'role': 'user', 'content': 'No actual inference'}],
            'options': {'temperature': 0, 'num_predict': 900 if role == 'judge' else 2048,
                        'num_ctx': 32768 if role == 'judge' else 8192},
            'format': {'type': 'object'}})
        response = json.dumps({'models': [{'name': MODEL, 'digest': DIGEST}]}) if role == 'tags' else (
            json.dumps({'model': MODEL, 'message': {'content': '{}'},
                        'done': True, 'done_reason': 'stop'}) + '\n')
        calls.append({'index': len(calls), 'caseId': phase, 'role': role,
                      'path': '/api/tags' if role == 'tags' else '/api/chat',
                      'request': request, 'requestSha256': sha(request), 'status': 'returned',
                      'httpStatus': 200, 'response': response, 'responseSha256': sha(response)})
    response = json.dumps({'models': [{'name': MODEL, 'digest': DIGEST}]})
    probes = [{'index': 0, 'caseId': 'advisory', 'role': 'tags', 'path': '/api/tags',
               'request': '', 'requestSha256': sha(''), 'status': 'returned',
               'httpStatus': 200, 'response': response, 'responseSha256': sha(response)}]
    wire = {'version': 'inbox-actual-wire-v1', 'model': MODEL, 'digest': DIGEST,
            'calls': calls, 'metadataProbes': probes,
            'counts': {'tags': 2, 'actor': 4, 'judge': 3},
            'phaseCounts': {'advisory': {'actor': 2, 'judge': 2},
                            'enforced': {'actor': 2, 'judge': 1}},
            'externalAttempts': 9, 'physicalPending': 0, 'closed': True,
            'failed': False, 'originalFailure': None, 'recoveryAdmission': None}
    result = {'status': 'passed', 'actualQualification': False,
              'stage': 'standalone-persona-rendered-inbox', 'poolsClosed': True,
              'pendingOuterOwnershipVerification': True,
              'result': {'actualModelProof': True, 'genuineCredit': 3,
                         'qualifiedObjectiveIds': OBJECTIVES.copy(), 'qualification': 'qualified',
                         'actorCalls': 4, 'judgeCalls': 3, 'actualQualification': False,
                         'scope': SCOPE, 'resetVerified': True, 'siblingVerified': True}}
    return result, wire


class PersonaInboxRenderedLauncherContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        required = ('C31_COHORT', 'C31_TEST', 'C31_TEST_SHA256', 'C31_ASSERTION', 'c31_receipt')
        missing = [name for name in required if not hasattr(LAUNCHER, name)]
        if missing:
            raise RuntimeError('C31 shared launcher integration pending: ' + ', '.join(missing))

    def write(self, path, value):
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)

    def check(self, root, result, wire):
        result_path, wire_path = root / 'result.json', root / 'terminal-wire.json'
        self.write(result_path, result)
        self.write(wire_path, wire)
        return LAUNCHER.c31_receipt(result_path, wire_path)

    def test_selector_and_exact_current_fixture(self):
        self.assertEqual(LAUNCHER.C31_COHORT, COHORT)
        self.assertEqual(LAUNCHER.C31_TEST, FIXTURE)
        self.assertEqual(LAUNCHER.C31_ASSERTION, TITLE)
        self.assertIn(COHORT, LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertIn(COHORT, LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn(COHORT, LAUNCHER.STANDALONE_BROWSER_COHORTS)
        self.assertEqual(LAUNCHER.digest(HERE.parent.parent / FIXTURE), LAUNCHER.C31_TEST_SHA256)

    def test_one_exact_tap_without_skip_or_failure(self):
        content = (f'TAP version 13\n# Subtest: {TITLE}\nok 1 - {TITLE}\n'
                   '# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# cancelled 0\n')
        self.assertEqual(LAUNCHER.complete_tap_counts(content, COHORT, [TITLE])['tests'], 1)
        for changed in [content.replace('# skipped 0', '# skipped 1'),
                        content.replace('ok 1 -', 'not ok 1 -'), content.replace(TITLE, 'other test')]:
            with self.subTest(content=changed):
                with self.assertRaises(RuntimeError):
                    LAUNCHER.complete_tap_counts(changed, COHORT, [TITLE])

    def test_valid_child_receipt_still_requires_outer_ownership(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            result, wire = documents()
            self.assertEqual(self.check(root, result, wire), result)
            self.assertIs(result['actualQualification'], False)
            self.assertIs(result['pendingOuterOwnershipVerification'], True)

    def test_rejects_premature_or_partial_qualification(self):
        changes = [lambda r: r.update(status='failed'), lambda r: r.update(actualQualification=True),
                   lambda r: r.update(poolsClosed=1), lambda r: r.update(pendingOuterOwnershipVerification=False),
                   lambda r: r.update(unexpected=True), lambda r: r.pop('result')]
        for key, value in [('actualQualification', True), ('actualModelProof', False), ('genuineCredit', 2),
                           ('genuineCredit', True), ('resetVerified', False), ('siblingVerified', 1),
                           ('scope', 'other'), ('qualifiedObjectiveIds', OBJECTIVES[:2]),
                           ('actorCalls', 33), ('judgeCalls', 49), ('judgeCalls', True)]:
            changes.append(lambda r, k=key, v=value: r['result'].update({k: v}))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, change in enumerate(changes):
                result, wire = documents()
                change(result)
                with self.subTest(index=index), self.assertRaises(RuntimeError):
                    self.check(root, result, wire)

    def test_rejects_unclosed_tampered_or_unbounded_wire(self):
        changes = [lambda w: w.update(closed=False), lambda w: w.update(failed=True),
                   lambda w: w.update(physicalPending=1), lambda w: w.update(physicalPending=False),
                   lambda w: w.update(externalAttempts=81), lambda w: w.update(model='mock'),
                   lambda w: w.update(digest='0' * 64), lambda w: w.update(version='other'),
                   lambda w: w['counts'].update(judge=2), lambda w: w['counts'].update(tags=True),
                   lambda w: w['phaseCounts']['enforced'].update(judge=17),
                   lambda w: w['calls'][1].update(status='incomplete'),
                   lambda w: w['calls'][1].update(role='other'),
                   lambda w: w['calls'][1].update(caseId='foreign'),
                   lambda w: w['calls'][1].update(requestSha256='0' * 64),
                   lambda w: w['calls'][1].update(responseSha256='0' * 64),
                   lambda w: w['calls'][1].update(httpStatus=503),
                   lambda w: w['metadataProbes'][0].update(caseId='sibling'),
                   lambda w: w['metadataProbes'][0].update(path='/api/chat'),
                   lambda w: w['metadataProbes'][0].update(status='pending'),
                   lambda w: w['metadataProbes'][0].update(httpStatus=503),
                   lambda w: w['metadataProbes'][0].update(responseSha256='0' * 64),
                   lambda w: w['metadataProbes'][0].update(response='{}'),
                   lambda w: w['counts'].update(tags=1),
                   lambda w: w.update(metadataProbes=[])]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, change in enumerate(changes):
                result, wire = documents()
                change(wire)
                with self.subTest(index=index), self.assertRaises(RuntimeError):
                    self.check(root, result, wire)

    def test_rejects_nonprivate_and_symlink_receipts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result, wire = documents()
            self.check(root, result, wire)
            result_path, wire_path = root / 'result.json', root / 'terminal-wire.json'
            for selected in [result_path, wire_path]:
                os.chmod(selected, 0o644)
                with self.assertRaises(RuntimeError):
                    LAUNCHER.c31_receipt(result_path, wire_path)
                os.chmod(selected, 0o600)
            link = root / 'alias.json'
            link.symlink_to(result_path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.c31_receipt(link, wire_path)

    def browser_fixture(self, evidence):
        runtime = evidence / 'runtime'
        runtime.mkdir(mode=0o700)
        profile = runtime / 'browser-profile'
        profile.mkdir(mode=0o700)
        (profile / 'owned-data').write_text('controlled temporary browser profile')
        pgid, worker, browser = 123450, 123451, 123452
        identity = {'pid': browser, 'pgid': pgid, 'sessionId': pgid, 'uid': os.getuid(),
                    'qualificationPid': pgid, 'qualificationPgid': pgid,
                    'qualificationSessionId': pgid, 'workerPid': worker,
                    'profile': str(profile), 'executableSha256': 'a' * 64}
        cleanup = {'pid': browser, 'pgid': pgid, 'leaderReaped': True,
                   'descendantAbsence': 'unverified', 'profileAbsent': False,
                   'cleanupOwner': 'outer-all-owned-groups'}
        self.write(runtime / 'browser-process.json', identity)
        self.write(runtime / 'browser-cleanup.json', cleanup)
        return pgid, profile, identity

    def test_cleanup_accepts_isolated_worker_in_owned_runner_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary).resolve()
            pgid, profile, identity = self.browser_fixture(evidence)
            sibling = evidence / 'sibling-profile'
            sibling.mkdir()
            self.assertNotEqual(identity['workerPid'], pgid)
            with patch.object(LAUNCHER.sys, 'platform', 'linux'), \
                    patch.object(LAUNCHER.subprocess, 'run', return_value=SimpleNamespace(stdout='')) as roster:
                self.assertTrue(LAUNCHER.c31_browser_profile_cleanup(evidence, pgid, 'a' * 64))
            self.assertEqual(roster.call_count, 1)
            self.assertFalse(profile.exists())
            self.assertTrue(sibling.is_dir())

    def test_cleanup_requires_group_and_profile_process_absence(self):
        for kind in ('group', 'profile'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                evidence = Path(temporary).resolve()
                pgid, profile, _identity = self.browser_fixture(evidence)
                text = (f'123499 {pgid} {os.getuid()} owned-child\n' if kind == 'group'
                        else f'123499 987654 {os.getuid()} browser --user-data-dir={profile}\n')
                with patch.object(LAUNCHER.sys, 'platform', 'linux'), \
                        patch.object(LAUNCHER.subprocess, 'run', return_value=SimpleNamespace(stdout=text)):
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.c31_browser_profile_cleanup(evidence, pgid, 'a' * 64)
                self.assertTrue((profile / 'owned-data').is_file())

    def test_darwin_cleanup_rejects_escaped_profile_and_reused_journal_identity(self):
        for kind in ('pid', 'group', 'session', 'profile', 'unreadable'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                evidence = Path(temporary).resolve()
                pgid, profile, identity = self.browser_fixture(evidence)
                record = {'pid': identity['pid'] if kind == 'pid' else 987651,
                          'pgid': pgid if kind == 'group' else 987652,
                          'sessionId': pgid if kind == 'session' else 987653,
                          'uid': os.getuid() + 1 if kind == 'pid' else os.getuid(),
                          'arguments': ('browser', '--user-data-dir=' + str(profile))
                                       if kind == 'profile' else None}
                with patch.object(LAUNCHER.sys, 'platform', 'darwin'), \
                        patch('darwin_process_inventory.process_records', return_value=[record],
                              side_effect=RuntimeError('unavailable') if kind == 'unreadable' else None):
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.c31_browser_profile_cleanup(evidence, pgid, 'a' * 64)
                self.assertTrue((profile / 'owned-data').is_file())

    def test_cleanup_rejects_foreign_identity_before_deleting_profile(self):
        for key, value in [('workerPid', 123452), ('pgid', 987654), ('uid', os.getuid() + 1),
                           ('executableSha256', 'b' * 64), ('profile', '/foreign/profile')]:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                evidence = Path(temporary).resolve()
                pgid, profile, identity = self.browser_fixture(evidence)
                identity[key] = value
                self.write(evidence / 'runtime/browser-process.json', identity)
                with patch.object(LAUNCHER.subprocess, 'run', side_effect=AssertionError('No process query after bad ownership')):
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.c31_browser_profile_cleanup(evidence, pgid, 'a' * 64)
                self.assertTrue((profile / 'owned-data').is_file())


if __name__ == '__main__':
    unittest.main()
