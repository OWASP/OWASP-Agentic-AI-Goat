"""Exact current rendered-deletion receipt projection; no qualification side effects.

This validator is intentionally source-shape specific. The Node producer is still
under independent review, and the run selector remains closed until final schema,
artifact-journal, TAP, and ownership replay are bound together.
"""

from pathlib import Path
import hashlib
import json
import os
import re
import stat

from admin_student_deletion_current_host import COHORT
from full_backend_auth_contract import STORES


UUID_V4 = re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\Z')
STORE_NAMES = sorted(schema for schema, _ in STORES)
WORKSHOP = ('aria', 'nova', 'mcp', 'csrf', 'supply_chain', 'finflow',
            'sensitive_lookup', 'xss', 'legacy_challenge')
NETWORK_ZERO = ('nonPostgresAttempts', 'blockedAttempts', 'fetchAttempts',
                'tlsAttempts', 'httpAttempts', 'dnsAttempts', 'udpAttempts',
                'subprocessAttempts')
TAP_TITLE = 'student deletion rendered current-host cohort performs one real scoped deletion'
JOURNAL_KINDS = frozenset(('rag', 'ipiEmail', 'finflow', 'legacyUpload',
                           'runGeneration', 'finflowRoots'))
JOURNAL_FIELDS = frozenset(('version', 'phase', 'kind', 'ownerId', 'family',
    'slot', 'documentId', 'operationId', 'artifactId', 'runId', 'generation',
    'backupName', 'backupId', 'targetTokenSha256', 'intentId',
    'ownerDirectory', 'filePath', 'contentSha256', 'backupRoot',
    'traversalRoot', 'ownerKey'))


def exact(value, keys, label):
    if type(value) is not dict or set(value) != set(keys):
        raise RuntimeError(f'Exact {label} evidence fields required')
    return value


def boolean(value, expected, label):
    if type(value) is not bool or value is not expected:
        raise RuntimeError(f'Exact {label} evidence required')


def integer(value, label, *, minimum=0):
    if type(value) is not int or value < minimum:
        raise RuntimeError(f'Exact {label} count required')


def flags(value, expected, label):
    exact(value, expected, label)
    for key, wanted in expected.items():
        boolean(value[key], wanted, f'{label}.{key}')


def _effects(value):
    exact(value, ('identity', 'workshop', 'nonCtf', 'ctf', 'shop', 'artifacts'), 'store effects')
    flags(value['identity'], dict(identityTerminal=True, allStepsCompleted=True,
        sessionsRemoved=True, siblingSnapshotUnchanged=True,
        fullQ05Qualification=False, canonicalCredit=False), 'identity')
    workshop = value['workshop']
    exact(workshop, ('workshopRowsDeleted', 'siblingRowsUnchanged', 'fullStoreCoverage',
        'canonicalCredit', 'unsupportedStores'), 'workshop')
    for key, wanted in (('workshopRowsDeleted', True), ('siblingRowsUnchanged', True),
                        ('fullStoreCoverage', False), ('canonicalCredit', False)):
        boolean(workshop[key], wanted, f'workshop.{key}')
    if workshop['unsupportedStores'] != [name for name, _ in STORES if name not in WORKSHOP]:
        raise RuntimeError('Exact partial workshop-store boundary required')
    non_ctf = value['nonCtf']
    exact(non_ctf, ('serviceRowsDeleted', 'fullStoreCoverage', 'nativeVerified',
        'siblingRowsUnchanged', 'canonicalCredit', 'supportedStores'), 'non-CTF')
    for key, wanted in (('serviceRowsDeleted', True), ('fullStoreCoverage', False),
                        ('nativeVerified', False), ('siblingRowsUnchanged', True),
                        ('canonicalCredit', False)):
        boolean(non_ctf[key], wanted, f'nonCtf.{key}')
    if non_ctf['supportedStores'] != ['excessive_agency', 'session_disclosure']:
        raise RuntimeError('Exact non-CTF service-store boundary required')
    ctf = value['ctf']
    ctf_expected = dict(canonicalCredit=False, nativeVerified=False,
        fullStoreCoverage=False, registeredThroughAuthority=True, targetDeleted=True,
        immutableRegistrationRetained=True, deletionReceiptValidated=True,
        siblingBusinessAndEvidenceUnchanged=True, siblingLeaderboardRecomputed=True,
        sharedPayloadContentPreserved=True)
    exact(ctf, (*ctf_expected, 'modelCalls'), 'CTF')
    for key, wanted in ctf_expected.items():
        boolean(ctf[key], wanted, f'CTF.{key}')
    integer(ctf['modelCalls'], 'CTF.modelCalls')
    if ctf['modelCalls'] != 0:
        raise RuntimeError('CTF model call count must be zero')
    flags(value['shop'], dict(scopedLifecycleRowsDeleted=True,
        immutableRevisionsRetained=True, siblingUnchanged=True,
        fullStoreCoverage=False, allExternalResourcesAbsent=False,
        canonicalCredit=False, nativeVerified=False), 'SecureShop')
    flags(value['artifacts'], dict(targetArtifactsCleaned=True,
        immutableEvidenceRetained=True, siblingArtifactsPreserved=True,
        modelCreditClaimed=False, fullDeletionClaimed=False), 'artifacts')


def _network(value):
    exact(value, ('version', 'active', 'intact', 'postgresAttempts',
        'literalLoopbackLookups',
        'workerAttempts', 'passwordWorkersStarted', 'passwordWorkersExited',
        'passwordWorkersLive', 'passwordWorkerPolicy',
        'chromeSpawnAttempts', 'chromeSpawnsAllowed', *NETWORK_ZERO, 'policy',
        'browserNetworkPolicySeparate', 'osSandboxClaimed'), 'network witness')
    integer(value['version'], 'network version', minimum=1)
    if value['version'] != 1:
        raise RuntimeError('Network witness version changed')
    boolean(value['active'], True, 'network active')
    boolean(value['intact'], True, 'network guard intact')
    integer(value['postgresAttempts'], 'PostgreSQL attempts', minimum=1)
    integer(value['literalLoopbackLookups'], 'literal loopback lookups', minimum=1)
    integer(value['passwordWorkersStarted'], 'password workers started', minimum=1)
    if value['passwordWorkersStarted'] > 4 or \
            value['passwordWorkerPolicy'] != 'source-pinned-bcrypt-only-max-four-total':
        raise RuntimeError('Exact bounded bcrypt worker policy required')
    for key, wanted in (('workerAttempts', value['passwordWorkersStarted']),
                        ('passwordWorkersExited', value['passwordWorkersStarted']),
                        ('passwordWorkersLive', 0)):
        integer(value[key], key)
        if value[key] != wanted:
            raise RuntimeError('All and only owned password workers must exit')
    for key in ('chromeSpawnAttempts', 'chromeSpawnsAllowed'):
        integer(value[key], key, minimum=1)
        if value[key] != 1:
            raise RuntimeError('One owned browser spawn required')
    for key in NETWORK_ZERO:
        integer(value[key], key)
        if value[key] != 0:
            raise RuntimeError('Forbidden network/process attempt recorded')
    if value['policy'] != 'node-owned-postgres-and-one-chrome-pipe-only':
        raise RuntimeError('Network witness policy changed')
    boolean(value['browserNetworkPolicySeparate'], True, 'browser network policy scope')
    boolean(value['osSandboxClaimed'], False, 'OS sandbox claim')


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError('Duplicate artifact journal field')
        result[key] = value
    return result


def validate_artifact_journal(path, *, run_root, repo, entry_count,
                              target_id, sibling_id):
    """Replay the fsynced pre-effect owner journal, without exposing its fields."""
    expected = Path(run_root) / 'student-deletion-artifact-stages.jsonl'
    path = Path(path)
    if path != expected or path.is_symlink():
        raise RuntimeError('Exact retained artifact journal required')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or \
            info.st_uid != os.getuid() or info.st_mode & 0o177 or \
            info.st_mode & 0o600 != 0o600 or info.st_size <= 0 or \
            info.st_size > 256 * 4096:
        raise RuntimeError('Private bounded artifact journal required')
    data = path.read_bytes()
    after = path.lstat()
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != \
            (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
        raise RuntimeError('Artifact journal changed during read')
    lines = data.splitlines(keepends=True)
    if type(entry_count) is not int or not 1 <= entry_count <= 256 or \
            len(lines) != entry_count:
        raise RuntimeError('Artifact journal count mismatch')
    seen = {target_id: set(), sibling_id: set()}
    upload_intents = {target_id: {}, sibling_id: {}}
    roots = set()
    for line in lines:
        if len(line) > 4096 or not line.endswith(b'\n'):
            raise RuntimeError('Bounded complete artifact journal line required')
        try:
            item = json.loads(line, object_pairs_hook=_unique_object)
        except (UnicodeError, ValueError) as error:
            raise RuntimeError('Artifact journal JSON invalid') from error
        if type(item) is not dict or not {'version', 'phase', 'kind'} <= set(item) or \
                not set(item) <= JOURNAL_FIELDS or \
                type(item['version']) is not int or item['version'] != 1 or \
                type(item['phase']) is not str or \
                item['phase'] not in ('before', 'after', 'reserved', 'admitted',
                                      'bound', 'published', 'ready') or \
                item['kind'] not in JOURNAL_KINDS:
            raise RuntimeError('Artifact journal entry outside reviewed taxonomy')
        if 'targetToken' in item:
            raise RuntimeError('Raw target token forbidden in retained journal')
        for key in ('contentSha256', 'targetTokenSha256'):
            if key in item and (type(item[key]) is not str or
                                re.fullmatch(r'[a-f0-9]{64}', item[key]) is None):
                raise RuntimeError('Artifact journal digest malformed')
        if item['kind'] == 'finflowRoots':
            if 'ownerId' in item:
                raise RuntimeError('Global FinFlow roots cannot claim an owner')
            roots.add(item['phase'])
            for key, directory in (('backupRoot', 'finflow-backups'),
                                   ('traversalRoot', 'finflow-traversal-targets')):
                if item.get(key) != str(Path(run_root) / 'runtime' / directory):
                    raise RuntimeError('Owned FinFlow roots changed')
        else:
            owner = item.get('ownerId')
            if type(owner) is not int or owner not in seen:
                raise RuntimeError('Artifact journal owner outside synthetic pair')
            stage = (item['kind'], item['phase'])
            if item['kind'] == 'legacyUpload' and stage in seen[owner]:
                raise RuntimeError('Duplicate managed upload stage')
            seen[owner].add(stage)
            if 'ownerDirectory' in item and item['ownerDirectory'] != str(
                    Path(repo) / 'server/uploads/managed' / str(owner)):
                raise RuntimeError('Artifact owner directory changed')
            if 'filePath' in item:
                file_path = item['filePath']
                if type(file_path) is not str or not file_path.startswith(str(
                        Path(repo) / 'server/uploads/managed' / str(owner)) + os.sep):
                    raise RuntimeError('Artifact file path outside owned owner directory')
            if item['kind'] == 'legacyUpload' and item['phase'] in ('admitted', 'bound', 'published'):
                intent = item.get('intentId')
                if type(intent) is not str or UUID_V4.fullmatch(intent) is None:
                    raise RuntimeError('Canonical managed upload intent required')
                upload_intents[owner][item['phase']] = intent
                if item['phase'] == 'admitted':
                    expected_file = Path(repo) / 'server/uploads/managed' / str(owner) / intent / 'deletion-owned.txt'
                    if item.get('filePath') != str(expected_file) or \
                            type(item.get('contentSha256')) is not str or \
                            re.fullmatch(r'[a-f0-9]{64}', item['contentSha256']) is None or \
                            item.get('ownerDirectory') != str(expected_file.parent.parent):
                        raise RuntimeError('Exact admitted managed upload path and digest required')
                    upload_intents[owner]['filePath'] = str(expected_file)
                    upload_intents[owner]['contentSha256'] = item['contentSha256']
    if roots != {'before', 'ready'}:
        raise RuntimeError('FinFlow root preparation incomplete')
    for owner, phases in seen.items():
        for kind in ('rag', 'ipiEmail', 'finflow', 'runGeneration'):
            if (kind, 'before') not in phases or (kind, 'after') not in phases:
                raise RuntimeError('Pre-effect artifact lineage incomplete')
        for phase in ('reserved', 'before', 'admitted', 'bound', 'published'):
            if ('legacyUpload', phase) not in phases:
                raise RuntimeError('Managed upload lineage incomplete')
        intents = upload_intents[owner]
        if intents['admitted'] != intents['bound'] or intents['admitted'] != intents['published']:
            raise RuntimeError('Managed upload intent lineage changed')
    return {'entryCount': entry_count, 'syntheticOwners': 2,
            'preEffectFamilies': 5, 'contentSha256': hashlib.sha256(data).hexdigest(),
            'managedUploads': {str(owner): {'filePath': upload_intents[owner]['filePath'],
                'intentId': upload_intents[owner]['admitted'],
                'contentSha256': upload_intents[owner]['contentSha256']}
                for owner in (target_id, sibling_id)}}


def verify_deletion_tap(text):
    if type(text) is not str or len(text.encode('utf-8')) > 16 * 1024 * 1024 or \
            len(re.findall(r'(?m)^ok [0-9]+ - ', text)) != 1 or \
            re.search(r'(?m)^not ok ', text):
        raise RuntimeError('Exact one-case deletion TAP proof required')
    for pattern in (r'(?m)^ok 1 - ' + re.escape(TAP_TITLE) + r'\s*$',
                    r'(?m)^# tests 1\s*$', r'(?m)^# pass 1\s*$',
                    r'(?m)^# fail 0\s*$', r'(?m)^# skipped 0\s*$'):
        if not re.search(pattern, text):
            raise RuntimeError('Exact one-case zero-skip deletion TAP proof required')
    return True


def validate_provisional_receipt(receipt, journal, captured_browser, *,
                                 repo, run_root, nonce, chromium):
    """Replay the current source projection; not sufficient alone to enable --run."""
    exact(receipt, ('version', 'cohort', 'status', 'seedProvenance', 'targetId',
        'siblingId', 'actorId', 'mountedActorSessionId', 'jobId', 'cancelNoRequest',
        'storageAbaEventsObserved', 'storageAbaNoRequest',
        'realHttp200BeforeBrowserLoss', 'unknownUiNoAutomaticRetry',
        'browserResponseFailed', 'heldRunFenced', 'heldRunGenerations',
        'pageRetiredBeforeFinalCounts', 'actorUnchanged', 'artifactJournal',
        'requestCounts', 'coveredStores',
        'effects', 'controlledEmbeddingCalls', 'managedUploads', 'canonicalCredit',
        'excluded', 'networkWitness', 'modelProviderAttemptsObserved',
        'judgeProviderAttemptsObserved'), 'rendered deletion receipt')
    if type(receipt['version']) is not int or receipt['version'] != 1 or \
            receipt['cohort'] != COHORT or \
            receipt['status'] != 'bounded-rendered-student-deletion-observed' or \
            receipt['seedProvenance'] != 'controlled-preexisting-lifecycle-data-not-model-or-judge-credit':
        raise RuntimeError('Current rendered deletion receipt identity required')
    for key in ('targetId', 'siblingId', 'actorId', 'mountedActorSessionId'):
        integer(receipt[key], key, minimum=1)
    if len({receipt[key] for key in ('targetId', 'siblingId', 'actorId')}) != 3 or \
            re.fullmatch(r'[a-f0-9]{12}', nonce or '') is None or \
            UUID_V4.fullmatch(receipt['jobId'] or '') is None:
        raise RuntimeError('Distinct synthetic principals and canonical job required')
    for key in ('cancelNoRequest', 'storageAbaNoRequest',
                'realHttp200BeforeBrowserLoss', 'unknownUiNoAutomaticRetry',
                'browserResponseFailed', 'heldRunFenced',
                'pageRetiredBeforeFinalCounts', 'actorUnchanged'):
        boolean(receipt[key], True, key)
    generations = exact(receipt['heldRunGenerations'], ('before', 'after'),
                        'held-run generations')
    for key in ('before', 'after'):
        if type(generations[key]) is not str or re.fullmatch(r'(0|[1-9][0-9]*)',
                                                          generations[key]) is None:
            raise RuntimeError('Canonical held-run generation required')
    if int(generations['after']) <= int(generations['before']):
        raise RuntimeError('Held-run generation did not advance')
    artifact = exact(receipt['artifactJournal'], ('path', 'entryCount'),
                     'artifact journal reference')
    if artifact['path'] != str(Path(run_root) / 'student-deletion-artifact-stages.jsonl'):
        raise RuntimeError('Exact retained private artifact journal path required')
    integer(artifact['entryCount'], 'artifact journal entries', minimum=1)
    integer(receipt['storageAbaEventsObserved'], 'storage ABA events', minimum=2)
    if receipt['storageAbaEventsObserved'] != 2:
        raise RuntimeError('Exact A-to-B-to-A authority event count required')
    exact(receipt['requestCounts'], ('browserDelete', 'serverDelete', 'unexpectedDelete'),
          'DELETE counts')
    for key, wanted in (('browserDelete', 1), ('serverDelete', 1), ('unexpectedDelete', 0)):
        integer(receipt['requestCounts'][key], key)
        if receipt['requestCounts'][key] != wanted:
            raise RuntimeError('One physical and server DELETE without extras required')
    if receipt['coveredStores'] != STORE_NAMES:
        raise RuntimeError('Canonical sixteen-store coverage required')
    _effects(receipt['effects'])
    integer(receipt['controlledEmbeddingCalls'], 'controlled embedding calls', minimum=1)
    boolean(receipt['canonicalCredit'], False, 'canonical credit')
    if receipt['excluded'] != ['model-grading', 'judge-credit', 'non-synthetic-users']:
        raise RuntimeError('Exact bounded qualification exclusions required')
    for key in ('modelProviderAttemptsObserved', 'judgeProviderAttemptsObserved'):
        integer(receipt[key], key)
        if receipt[key] != 0:
            raise RuntimeError('No model/Judge provider attempts required')
    _network(receipt['networkWitness'])
    uploads = exact(receipt['managedUploads'], ('target', 'sibling'), 'managed upload cleanup')
    for label, owner, present in (('target', receipt['targetId'], False),
                                  ('sibling', receipt['siblingId'], True)):
        item = exact(uploads[label], ('ownerId', 'filePath',
            'observedBeforeFixtureCleanup', 'exactFixtureArtifactsRemoved'), label + ' upload')
        integer(item['ownerId'], label + ' upload owner', minimum=1)
        if item['ownerId'] != owner:
            raise RuntimeError('Managed upload owner mismatch')
        boolean(item['observedBeforeFixtureCleanup'], present, label + ' upload presence')
        boolean(item['exactFixtureArtifactsRemoved'], True, label + ' upload cleanup')
        expected_parent = Path(repo) / 'server/uploads/managed' / str(owner)
        upload = Path(item['filePath']) if type(item['filePath']) is str else Path('.')
        if upload.name != 'deletion-owned.txt' or upload.parent.parent != expected_parent or \
                UUID_V4.fullmatch(upload.parent.name) is None:
            raise RuntimeError('Exact owned managed upload path required')
    run = Path(run_root)
    exact(journal, ('version', 'cohort', 'status', 'resources'), 'resource journal')
    if type(journal['version']) is not int or journal['version'] != 1 or \
            journal['cohort'] != COHORT or \
            journal['status'] != 'browser_cleanup_delegated_to_current_host_launcher':
        raise RuntimeError('Terminal delegated resource journal required')
    resources = exact(journal['resources'], ('browser', 'server'), 'resource identities')
    browser = exact(resources['browser'], ('pid', 'profile', 'executable'), 'browser identity')
    integer(browser['pid'], 'browser PID', minimum=1)
    exact(captured_browser, ('version', 'pid', 'pgid', 'sessionId', 'uid',
        'startSec', 'startUsec', 'profile', 'executable'), 'live captured browser birth')
    for key in ('version', 'pid', 'pgid', 'sessionId', 'uid', 'startSec', 'startUsec'):
        integer(captured_browser[key], 'live browser ' + key)
    if captured_browser['version'] != 1 or captured_browser['uid'] != os.getuid() or \
            any(browser[key] != captured_browser[key]
                for key in ('pid', 'profile', 'executable')):
        raise RuntimeError('Terminal browser journal does not match live birth')
    if browser['profile'] != str(run / 'runtime/tmp' /
                                ('dvaia-student-deletion-browser-' + nonce)) or \
            browser['executable'] != str(chromium):
        raise RuntimeError('Exact admitted browser profile and executable required')
    server = exact(resources['server'], ('address', 'port'), 'server identity')
    if server['address'] != '127.0.0.1':
        raise RuntimeError('Loopback server identity required')
    integer(server['port'], 'server port', minimum=1)
    if server['port'] > 65535:
        raise RuntimeError('Valid loopback server port required')
    return {'passed': True, 'storeCount': 16, 'browserDeleteCount': 1,
            'serverDeleteCount': 1, 'canonicalCredit': False,
            'modelCalls': 0, 'judgeCalls': 0}


def verify_final_evidence(receipt, journal, captured_browser, *,
                          repo, run_root, nonce, chromium):
    """Join rendered facts, live browser birth, and retained pre-effect bytes."""
    proof = validate_provisional_receipt(receipt, journal, captured_browser,
        repo=repo, run_root=run_root, nonce=nonce, chromium=chromium)
    artifact = validate_artifact_journal(receipt['artifactJournal']['path'],
        run_root=run_root, repo=repo,
        entry_count=receipt['artifactJournal']['entryCount'],
        target_id=receipt['targetId'], sibling_id=receipt['siblingId'])
    for label in ('target', 'sibling'):
        file_path = Path(receipt['managedUploads'][label]['filePath'])
        owner = receipt[label + 'Id']
        if artifact['managedUploads'][str(owner)]['filePath'] != str(file_path):
            raise RuntimeError('Managed upload receipt differs from admitted artifact')
        if os.path.lexists(file_path) or os.path.lexists(file_path.parent) or \
                os.path.lexists(file_path.parent.parent):
            raise RuntimeError('Fixture-owned managed upload cleanup unproved')
    return {**proof, 'artifactJournal': artifact, 'managedUploadsAbsent': True}
