"""Pure bounded receipt mutations; no database, browser, or model calls."""

from pathlib import Path
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from admin_student_deletion_receipt import (
    NETWORK_ZERO, STORE_NAMES, WORKSHOP, validate_artifact_journal,
    validate_provisional_receipt, verify_deletion_tap, verify_final_evidence,
    TAP_TITLE,
)
from full_backend_auth_contract import STORES


REPO = Path(__file__).resolve().parents[2]
NONCE = 'a' * 12
RUN = REPO / 'tasks/qualification' / ('run-admin-student-deletion-' + NONCE)
CHROME = '/owned/chrome'
JOB = '12345678-1234-4123-8123-123456789abc'
UPLOAD_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'


def sample():
    effects = {
        'identity': dict(identityTerminal=True, allStepsCompleted=True,
            sessionsRemoved=True, siblingSnapshotUnchanged=True,
            fullQ05Qualification=False, canonicalCredit=False),
        'workshop': dict(workshopRowsDeleted=True, siblingRowsUnchanged=True,
            fullStoreCoverage=False, canonicalCredit=False,
            unsupportedStores=[name for name, _ in STORES if name not in WORKSHOP]),
        'nonCtf': dict(serviceRowsDeleted=True, fullStoreCoverage=False,
            nativeVerified=False, siblingRowsUnchanged=True, canonicalCredit=False,
            supportedStores=['excessive_agency', 'session_disclosure']),
        'ctf': dict(canonicalCredit=False, modelCalls=0, nativeVerified=False,
            fullStoreCoverage=False, registeredThroughAuthority=True,
            targetDeleted=True, immutableRegistrationRetained=True,
            deletionReceiptValidated=True, siblingBusinessAndEvidenceUnchanged=True,
            siblingLeaderboardRecomputed=True, sharedPayloadContentPreserved=True),
        'shop': dict(scopedLifecycleRowsDeleted=True, immutableRevisionsRetained=True,
            siblingUnchanged=True, fullStoreCoverage=False,
            allExternalResourcesAbsent=False, canonicalCredit=False,
            nativeVerified=False),
        'artifacts': dict(targetArtifactsCleaned=True, immutableEvidenceRetained=True,
            siblingArtifactsPreserved=True, modelCreditClaimed=False,
            fullDeletionClaimed=False),
    }
    witness = dict(version=1, active=True, intact=True, postgresAttempts=2,
        literalLoopbackLookups=1, workerAttempts=2, passwordWorkersStarted=2,
        passwordWorkersExited=2, passwordWorkersLive=0,
        passwordWorkerPolicy='source-pinned-bcrypt-only-max-four-total',
        chromeSpawnAttempts=1, chromeSpawnsAllowed=1,
        policy='node-owned-postgres-and-one-chrome-pipe-only',
        browserNetworkPolicySeparate=True, osSandboxClaimed=False,
        **{key: 0 for key in NETWORK_ZERO})
    upload = lambda owner, present: dict(ownerId=owner,
        filePath=str(REPO / 'server/uploads/managed' / str(owner) / UPLOAD_ID /
                     'deletion-owned.txt'), observedBeforeFixtureCleanup=present,
        exactFixtureArtifactsRemoved=True)
    receipt = dict(version=1, cohort='admin-student-deletion-current-host',
        status='bounded-rendered-student-deletion-observed',
        seedProvenance='controlled-preexisting-lifecycle-data-not-model-or-judge-credit',
        targetId=100, siblingId=101, actorId=102, mountedActorSessionId=200,
        jobId=JOB, cancelNoRequest=True, storageAbaEventsObserved=2,
        storageAbaNoRequest=True, realHttp200BeforeBrowserLoss=True,
        unknownUiNoAutomaticRetry=True, browserResponseFailed=True,
        heldRunFenced=True, heldRunGenerations=dict(before='2', after='3'),
        pageRetiredBeforeFinalCounts=True, actorUnchanged=True,
        artifactJournal=dict(path=str(RUN / 'student-deletion-artifact-stages.jsonl'),
                             entryCount=3),
        requestCounts=dict(browserDelete=1, serverDelete=1,
        unexpectedDelete=0), coveredStores=list(STORE_NAMES), effects=effects,
        controlledEmbeddingCalls=1, managedUploads=dict(target=upload(100, False),
        sibling=upload(101, True)), canonicalCredit=False,
        excluded=['model-grading', 'judge-credit', 'non-synthetic-users'],
        networkWitness=witness, modelProviderAttemptsObserved=0,
        judgeProviderAttemptsObserved=0)
    journal = dict(version=1, cohort='admin-student-deletion-current-host',
        status='browser_cleanup_delegated_to_current_host_launcher',
        resources=dict(browser=dict(pid=345, profile=str(RUN / 'runtime/tmp' /
            ('dvaia-student-deletion-browser-' + NONCE)), executable=CHROME),
            server=dict(address='127.0.0.1', port=4444)))
    captured = dict(version=1, pid=345, pgid=344, sessionId=344,
        uid=os.getuid(), startSec=123, startUsec=456,
        profile=journal['resources']['browser']['profile'], executable=CHROME)
    return receipt, journal, captured


class RenderedDeletionReceiptControls(unittest.TestCase):
    def verify(self, receipt, journal, captured):
        return validate_provisional_receipt(receipt, journal, captured, repo=REPO,
            run_root=RUN, nonce=NONCE, chromium=CHROME)

    def test_exact_current_source_projection_passes_without_credit(self):
        receipt, journal, captured = sample()
        self.assertEqual(self.verify(receipt, journal, captured), dict(passed=True,
            storeCount=16, browserDeleteCount=1, serverDeleteCount=1,
            canonicalCredit=False, modelCalls=0, judgeCalls=0))

    def test_final_binding_requires_retained_artifact_bytes_and_absent_owned_files(self):
        receipt, journal, captured = sample()
        fake_proof = {'entryCount': 3, 'syntheticOwners': 2,
                      'preEffectFamilies': 5, 'contentSha256': 'a'*64,
                      'managedUploads': {str(owner): {'filePath': receipt['managedUploads'][label]['filePath']}
                          for label, owner in (('target', 100), ('sibling', 101))}}
        with patch('admin_student_deletion_receipt.validate_artifact_journal',
                   return_value=fake_proof) as replay, \
             patch('admin_student_deletion_receipt.os.path.lexists', return_value=False):
            result = verify_final_evidence(receipt, journal, captured,
                repo=REPO, run_root=RUN, nonce=NONCE, chromium=CHROME)
        self.assertIs(result['passed'], True)
        self.assertEqual(result['artifactJournal'], fake_proof)
        self.assertIs(result['managedUploadsAbsent'], True)
        self.assertEqual(replay.call_args.kwargs['entry_count'], 3)
        receipt['managedUploads']['target']['filePath'] = str(
            REPO / 'server/uploads/managed/100/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/deletion-owned.txt')
        with patch('admin_student_deletion_receipt.validate_artifact_journal',
                   return_value=fake_proof), \
             patch('admin_student_deletion_receipt.os.path.lexists', return_value=False):
            with self.assertRaisesRegex(RuntimeError, 'differs from admitted'):
                verify_final_evidence(receipt, journal, captured,
                    repo=REPO, run_root=RUN, nonce=NONCE, chromium=CHROME)
        receipt['managedUploads']['target']['filePath'] = fake_proof['managedUploads']['100']['filePath']
        with patch('admin_student_deletion_receipt.validate_artifact_journal',
                   return_value=fake_proof), \
             patch('admin_student_deletion_receipt.os.path.lexists', return_value=True):
            with self.assertRaisesRegex(RuntimeError, 'upload cleanup'):
                verify_final_evidence(receipt, journal, captured,
                    repo=REPO, run_root=RUN, nonce=NONCE, chromium=CHROME)

    def test_exact_one_case_tap_and_negative_status_controls(self):
        content = (f'TAP version 13\nok 1 - {TAP_TITLE}\n1..1\n'
                   '# tests 1\n# pass 1\n# fail 0\n# skipped 0\n')
        self.assertIs(verify_deletion_tap(content), True)
        for invalid in (content.replace('# skipped 0', '# skipped 1'),
                        content.replace(TAP_TITLE, 'old admin Q05 title'),
                        content + 'ok 2 - invented\n',
                        content + 'not ok 2 - failure\n'):
            with self.assertRaises(RuntimeError): verify_deletion_tap(invalid)

    def test_wrong_actor_effect_network_and_ack_are_rejected(self):
        changes = (
            lambda r, j: r.update(cancelNoRequest=1),
            lambda r, j: r['requestCounts'].update(serverDelete=2),
            lambda r, j: r['effects']['ctf'].update(siblingLeaderboardRecomputed=False),
            lambda r, j: r['effects']['artifacts'].update(fullDeletionClaimed=True),
            lambda r, j: r['networkWitness'].update(nonPostgresAttempts=1),
            lambda r, j: r['networkWitness'].update(literalLoopbackLookups=0),
            lambda r, j: r['networkWitness'].update(workerAttempts=3),
            lambda r, j: r['networkWitness'].update(passwordWorkersStarted=5),
            lambda r, j: r['networkWitness'].update(passwordWorkersExited=1),
            lambda r, j: r['networkWitness'].update(passwordWorkersLive=1),
            lambda r, j: r['networkWitness'].update(passwordWorkerPolicy='unbounded'),
            lambda r, j: r['networkWitness'].update(chromeSpawnsAllowed=2),
            lambda r, j: r.update(modelProviderAttemptsObserved=1),
            lambda r, j: r['managedUploads']['sibling'].update(
                observedBeforeFixtureCleanup=False),
            lambda r, j: r['heldRunGenerations'].update(after='2'),
            lambda r, j: r['artifactJournal'].update(path='/foreign/journal'),
            lambda r, j: r.update(pageRetiredBeforeFinalCounts=0),
            lambda r, j: j['resources']['browser'].update(profile='/foreign'),
            lambda r, j: j.update(status='running'),
            lambda r, j: r['coveredStores'].pop(),
            lambda r, j: r.update(unexpected='invented'),
        )
        for change in changes:
            with self.subTest(change=changes.index(change)):
                receipt, journal, captured = sample()
                change(receipt, journal)
                with self.assertRaises(RuntimeError):
                    self.verify(receipt, journal, captured)
        receipt, journal, captured = sample()
        captured['pid'] += 1
        with self.assertRaises(RuntimeError):
            self.verify(receipt, journal, captured)

    def test_fsynced_artifact_journal_replay_binds_both_owners_and_pre_effects(self):
        with tempfile.TemporaryDirectory(dir=REPO / 'tasks/tmp') as directory:
            run = Path(directory)
            file = run / 'student-deletion-artifact-stages.jsonl'
            entries = [
                dict(version=1, kind='finflowRoots', phase=phase,
                     backupRoot=str(run / 'runtime/finflow-backups'),
                     traversalRoot=str(run / 'runtime/finflow-traversal-targets'))
                for phase in ('before', 'ready')
            ]
            for owner in (100, 101):
                for kind in ('rag', 'ipiEmail', 'finflow', 'runGeneration'):
                    for phase in ('before', 'after'):
                        variants = (('RAG', 'current'), ('CSRF', 'clean'),
                                    ('CSRF', 'poison')) if kind == 'rag' else ((None, None),)
                        for family, slot in variants:
                            stage = dict(version=1, kind=kind, phase=phase, ownerId=owner)
                            if kind == 'rag':
                                stage.update(family=family, slot=slot)
                            entries.append(stage)
                for phase in ('reserved', 'before', 'admitted', 'bound', 'published'):
                    stage = dict(version=1, kind='legacyUpload', phase=phase,
                                 ownerId=owner)
                    if phase in ('admitted', 'bound', 'published'):
                        stage['intentId'] = UPLOAD_ID
                    if phase == 'admitted':
                        stage.update(ownerDirectory=str(REPO / 'server/uploads/managed' / str(owner)),
                            filePath=str(REPO / 'server/uploads/managed' / str(owner) /
                                UPLOAD_ID / 'deletion-owned.txt'), contentSha256='a'*64)
                    entries.append(stage)
            def write(rows):
                file.write_bytes(b''.join((json.dumps(row, separators=(',', ':'))+'\n').encode()
                                          for row in rows))
                file.chmod(0o600)
            write(entries)
            proof = validate_artifact_journal(file, run_root=run, repo=REPO,
                entry_count=len(entries), target_id=100, sibling_id=101)
            self.assertEqual(proof['entryCount'], 36)
            self.assertEqual(proof['syntheticOwners'], 2)
            self.assertEqual(proof['managedUploads']['100']['intentId'], UPLOAD_ID)
            for mutation in (
                lambda rows: rows.pop(),
                lambda rows: rows[2].update(ownerId=999),
                lambda rows: rows[2].update(targetToken='raw-secret'),
                lambda rows: rows[2].update(phase='unreviewed'),
                lambda rows: next(row for row in rows if row.get('kind') == 'legacyUpload'
                    and row.get('ownerId') == 100 and row['phase'] == 'admitted').update(
                    filePath=str(REPO / 'server/uploads/managed/100' / UPLOAD_ID / '..' /
                        'deletion-owned.txt')),
                lambda rows: next(row for row in rows if row.get('kind') == 'legacyUpload'
                    and row.get('ownerId') == 100 and row['phase'] == 'bound').update(
                    intentId='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'),
            ):
                rows = [dict(item) for item in entries]
                mutation(rows)
                write(rows)
                with self.assertRaises(RuntimeError):
                    validate_artifact_journal(file, run_root=run, repo=REPO,
                        entry_count=len(entries), target_id=100, sibling_id=101)


if __name__ == '__main__': unittest.main()
