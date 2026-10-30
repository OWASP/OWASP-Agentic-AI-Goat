#!/usr/bin/env python3
"""Strict root-owned launcher for the Legacy Sensitive manual actual-8B cohort.

This launcher owns one disposable PostgreSQL identity database through migration 0061.  It accepts only a copied,
read-only source/dependency closure, a pinned Node binary, a pinned loopback
Ollama model, and an exact one-use root grant.  The child receives a new private
HOME/TMPDIR and a small explicit environment; the canonical workspace, .env
files, application data, and cloud credentials are not copied or passed to it.
This is an owned test harness, not an operating-system filesystem sandbox.
"""

import argparse
import contextlib
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


STAGE = 'actual8b-v1'
SCOPE = 'legacy_sensitive_manual_actual8b'
COHORT = 'legacy-sensitive-manual-actual8b-v1'
MODEL = 'llama3.1:8b'
MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'
OLLAMA_BASE_URL = 'http://127.0.0.1:11434'
POSTGRES_IMAGE = 'postgres:18'
POSTGRES_IMAGE_ID = 'sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
DOCKER_HOST = 'unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock'
DOCKER_DAEMON_ID = '2c9da9a7-1f8c-490b-af98-87bbf6bf83db'
NODE_VERSION = 'v26.8.2'
MIGRATION_ROLE = 'dvaia_identity_migration'
RUNTIME_ROLE = 'dvaia_identity_runtime'

NODE_SHA256 = '3fbe98203f8f4a86ce5b0b573a1a30aa4253064c4c2a0299c436d259b68e54b0'
REGISTERED_IDENTITY_HEAD = '0061_mcp_supply_chain_curriculum_defaults.sql'
TEST_PATH = 'tests/postgres/legacySensitiveManualActual8b.integration.test.js'
LAUNCHER_PATH = 'tests/postgres/run-legacy-sensitive-manual-actual8b-isolated.py'
CONTRACT_PATH = 'tests/postgres/test_legacy_sensitive_manual_actual8b_launcher_contract.py'
PRODUCTION_PATH = 'server/services/legacySensitiveTools.js'
SHA256_PATTERN = re.compile(r'^[0-9a-f]{64}$')
FORBIDDEN_RESULT_KEYS = frozenset((
    'prompt', 'response', 'canary', 'artifact', 'artifactId', 'explanation',
    'evidence', 'raw', 'request', 'messages', 'content', 'judgeMetadata',
))


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def json_digest(value):
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(encoded).hexdigest()


def save_json(path, value):
    path = Path(path)
    pending = Path(str(path) + f'.{os.getpid()}.pending')
    with pending.open('w') as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    os.chmod(pending, 0o600)
    os.replace(pending, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def run(command, **kwargs):
    return subprocess.run(command, check=False, text=True, **kwargs)


def resolve_without_symlinks(value, label, *, must_exist=True):
    path = Path(value)
    if not path.is_absolute():
        raise RuntimeError(f'absolute {label} path required')
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor /= part
        if os.path.lexists(cursor) and cursor.is_symlink():
            raise RuntimeError(f'{label} symlink ancestry forbidden')
    return path.resolve(strict=must_exist)


def _dependency_path(relative):
    return relative == 'source/node_modules' or relative.startswith('source/node_modules/') \
        or relative == 'source/client/node_modules' or relative.startswith('source/client/node_modules/')


def package_inventory(package):
    package = Path(package)
    source = package / 'source'
    source_files, dependency_files, dependency_links = {}, {}, {}
    source_directories, dependency_directories = [], []
    if source.is_symlink() or not source.is_dir() or source.stat().st_mode & 0o222:
        raise RuntimeError('copied read-only package source required')
    for path in source.rglob('*'):
        relative = path.relative_to(package).as_posix()
        dependency = _dependency_path(relative)
        if path.is_symlink():
            if not dependency:
                raise RuntimeError(f'source symlink forbidden: {relative}')
            target = os.readlink(path)
            if Path(target).is_absolute():
                raise RuntimeError(f'absolute dependency symlink forbidden: {relative}')
            resolved = path.resolve(strict=True)
            roots = (source / 'node_modules', source / 'client/node_modules')
            if not any(root.is_dir() and resolved.is_relative_to(root.resolve()) for root in roots):
                raise RuntimeError(f'external dependency symlink forbidden: {relative}')
            dependency_links[relative] = target
        elif path.is_file():
            if path.stat().st_mode & 0o222:
                raise RuntimeError(f'writable frozen file forbidden: {relative}')
            (dependency_files if dependency else source_files)[relative] = sha256(path)
        elif path.is_dir():
            if path.stat().st_mode & 0o222:
                raise RuntimeError(f'writable frozen directory forbidden: {relative}')
            (dependency_directories if dependency else source_directories).append(relative)
        else:
            raise RuntimeError(f'special package leaf forbidden: {relative}')
    return {
        'sourceFiles': source_files,
        'dependencyFiles': dependency_files,
        'dependencySymlinks': dependency_links,
        'sourceDirectories': sorted(source_directories),
        'dependencyDirectories': sorted(dependency_directories),
    }


def verify_manifest(package, manifest_path):
    package, manifest_path = Path(package), Path(manifest_path)
    if package.is_symlink() or not package.is_dir() or manifest_path != package / 'manifest.json' \
            or manifest_path.is_symlink() or not manifest_path.is_file() \
            or manifest_path.stat().st_mode & 0o222:
        raise RuntimeError('exact read-only package manifest required')
    if {entry.name for entry in package.iterdir()} != {'source', 'manifest.json'}:
        raise RuntimeError('package inventory must contain only source and manifest.json')
    manifest = json.loads(manifest_path.read_text())
    expected_suite = {
        'name': 'legacySensitiveManualActual8b',
        'test': TEST_PATH,
        'timeoutSeconds': 1800,
        'database': True,
        'docker': True,
    }
    if manifest.get('stage') != STAGE or manifest.get('scope') != SCOPE \
            or manifest.get('qualification') != 'actual-model-candidate' \
            or manifest.get('activation') != 'isolated-identity-only-no-activation' \
            or manifest.get('registeredIdentityHead') != REGISTERED_IDENTITY_HEAD \
            or manifest.get('suite') != expected_suite \
            or manifest.get('semanticEffectsQualified') != [] \
            or manifest.get('mutableSourcePaths') != []:
        raise RuntimeError('manifest actual-model boundary invalid')
    observed = package_inventory(package)
    for field, value in observed.items():
        if manifest.get(field) != value or manifest.get(field + 'Sha256') != json_digest(value):
            raise RuntimeError(f'manifest inventory mismatch: {field}')
    required = {f'source/{name}' for name in (
        TEST_PATH, LAUNCHER_PATH, CONTRACT_PATH, PRODUCTION_PATH,
        'tests/fixtures/legacySensitiveManualOwnedCases.js',
        'tests/fixtures/legacySensitiveManualReportContract.js',
        'server/agent-runtime/legacySensitiveEvidence.js',
        'server/agent-runtime/runCoordinator.js',
        'server/agent-runtime/postgresRunLedger.js',
        'server/agent-runtime/runTraceStore.js',
        'server/config/legacySensitiveFlags.js',
        'server/database/postgres/index.js',
        'server/database/postgres/poolBudget.js',
        'server/database/postgres/identityRepository.js',
        'server/database/postgres/identityValidation.js',
        'db/postgres/migrate.js',
        'server/services/legacySensitiveTools.js',
        'server/services/legacySensitiveObjectiveGrader.js',
        'db/postgres/identity-migrations/0001_identity.sql',
        f'db/postgres/identity-migrations/{REGISTERED_IDENTITY_HEAD}',
        'server/agent-runtime/objectiveJudge.js',
        'server/agent-runtime/judgeErrors.js',
        'server/agent-runtime/providers/langchainProvider.js',
        'server/agent-runtime/providers/modelScheduler.js',
        'server/agent-runtime/providers/finalResponseContract.js',
        'server/agent-runtime/ownerWorkflowRoutes.js',
        'server/agent-runtime/ownerWorkflowHttpError.js',
        'server/agent-runtime/sourceComparisonVerifier.js',
        'server/agent-runtime/sourceComparisonLegacyVerifier.js',
        'server/utils/requestContext.js',
        'package.json', 'package-lock.json',
    )}
    if not required.issubset(observed['sourceFiles']):
        raise RuntimeError('actual-model source closure is incomplete')
    if 'source/node_modules/pg/package.json' not in observed['dependencyFiles'] \
            or 'source/node_modules/@langchain/ollama/package.json' not in observed['dependencyFiles'] \
            or 'source/node_modules/@langchain/langgraph/package.json' not in observed['dependencyFiles']:
        raise RuntimeError('frozen LangChain dependency closure missing')
    if any((package / 'source').rglob('.env*')):
        raise RuntimeError('environment files forbidden in package')
    for suffix in ('.db', '.db-wal', '.db-shm', '.db-journal', '.sqlite', '.sqlite3', '.log'):
        if any((package / 'source').rglob(f'*{suffix}')):
            raise RuntimeError('runtime data or logs forbidden in package')
    migrations = [p for p in observed['sourceFiles'] if p.startswith('source/db/postgres/identity-migrations/')]
    if any(not re.fullmatch(r'source/db/postgres/identity-migrations/\d{4}_[^/]+\.sql', p)
           or p.rsplit('/', 1)[1] > REGISTERED_IDENTITY_HEAD for p in migrations):
        raise RuntimeError('identity migration outside approved prefix')
    if any('/drafts/' in p for p in observed['sourceFiles']):
        raise RuntimeError('draft activation assets forbidden')
    return manifest


def verify_postflight_identity(package, manifest_path, expected_manifest, expected_manifest_sha,
                               node, expected_node_sha):
    observed_manifest = verify_manifest(package, manifest_path)
    if observed_manifest != expected_manifest or sha256(manifest_path) != expected_manifest_sha \
            or sha256(node) != expected_node_sha:
        raise RuntimeError('postflight source/runtime identity changed')


def process_group_absent(pgid):
    if not isinstance(pgid, int) or pgid <= 0:
        return True
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def process_absent(pid):
    if not isinstance(pid, int) or pid <= 0:
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def terminate_group(pgid, process=None, grace=10):
    if not isinstance(pgid, int) or pgid <= 0:
        return True
    with contextlib.suppress(ProcessLookupError):
        os.killpg(pgid, signal.SIGTERM)
    if process is not None and process.poll() is None:
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=grace)
    deadline = time.monotonic() + min(grace, 3)
    while time.monotonic() < deadline:
        if process_group_absent(pgid):
            return True
        time.sleep(.1)
    with contextlib.suppress(ProcessLookupError):
        os.killpg(pgid, signal.SIGKILL)
    if process is not None and process.poll() is None:
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=5)
    return process_group_absent(pgid)


def terminate_pid(pid, process=None, grace=5):
    if not isinstance(pid, int) or pid <= 0:
        return True
    if not process_absent(pid):
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGTERM)
        if process is not None and process.poll() is None:
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=grace)
    deadline = time.monotonic() + min(grace, 2)
    while time.monotonic() < deadline:
        if process_absent(pid):
            return True
        time.sleep(.1)
    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, signal.SIGKILL)
    if process is not None and process.poll() is None:
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=2)
    return process_absent(pid)


def register_owned_process(process, state, persist, getpgid=os.getpgid, name="test"):
    """Journal the only safe fallback identity before querying live PGID state."""
    pid = process.pid
    record = {
        'pid': pid,
        'expectedPgid': pid,
        'status': 'spawned',
        'startedAt': utc_now(),
    }
    state['processes'][name] = record
    persist()
    actual_pgid = getpgid(pid)
    if actual_pgid != pid:
        raise RuntimeError('detached child process-group identity mismatch')
    record.update(pgid=actual_pgid, status='running')
    persist()
    return actual_pgid


def cleanup_owned_process(record, process, *, group_cleanup=terminate_group,
                          pid_cleanup=terminate_pid):
    expected_pgid = record.get('pgid', record.get('expectedPgid'))
    group_absent = group_cleanup(expected_pgid, process, grace=8)
    pid_absent = pid_cleanup(record.get('pid'), process, grace=5)
    record.update(groupAbsent=group_absent, pidAbsent=pid_absent,
        exitCode=process.poll() if process else None)
    return group_absent and pid_absent


def docker_missing_exact_target(message, target):
    return re.search(rf'No such (?:object|container): {re.escape(target)}\r?$',
                     message or '', flags=re.MULTILINE) is not None


def docker_object_absent(docker, target):
    result = run(docker + ['inspect', target], capture_output=True, timeout=20)
    if result.returncode == 0:
        return False
    message = (result.stdout or '') + (result.stderr or '')
    if result.returncode == 1 and docker_missing_exact_target(message, target):
        return True
    raise RuntimeError('Docker object absence could not be verified')


def remove_owned_container(docker, container_name, container_id, labels):
    target = container_id or container_name
    inspected = run(docker + ['inspect', target], capture_output=True, timeout=20)
    if inspected.returncode:
        message = (inspected.stdout or '') + (inspected.stderr or '')
        if inspected.returncode == 1 and docker_missing_exact_target(message, target):
            return None
        raise RuntimeError('owned container inspection failed during cleanup')
    try:
        values = json.loads(inspected.stdout)
        info = values[0] if len(values) == 1 else None
    except (ValueError, TypeError):
        info = None
    actual_labels = ((info or {}).get('Config') or {}).get('Labels') or {}
    actual_id = (info or {}).get('Id')
    if not isinstance(actual_id, str) or not re.fullmatch(r'[0-9a-f]{64}', actual_id) \
            or (container_id is not None and actual_id != container_id) \
            or (info or {}).get('Name') != '/' + container_name \
            or any(actual_labels.get(key) != value for key, value in labels.items()):
        raise RuntimeError('unowned container cleanup refused')
    removed = run(docker + ['rm', '--force', actual_id], capture_output=True, timeout=60)
    if removed.returncode:
        raise RuntimeError('owned container removal failed')
    return actual_id


def consume_one_use_grant(grant_path, expected, evidence_path):
    lock = Path(str(grant_path) + '.consume-lock')
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError:
        raise RuntimeError('grant already consumed')
    try:
        grant = json.loads(Path(grant_path).read_text())
        if grant.get('status') != 'granted' \
                or any(grant.get(key) != value for key, value in expected.items()):
            raise RuntimeError('grant changed before consumption')
        grant.update(status='consumed', runStatus='waiting_owner_handle', consumedAt=utc_now(),
            consumerPid=os.getpid(), launcherPid=os.getpid(), evidence=str(evidence_path))
        save_json(grant_path, grant)
    finally:
        lock.rmdir()


def record_terminal_grant(grant_path, grant_id, owner_handle, state, clean):
    terminal_grant = json.loads(Path(grant_path).read_text())
    if terminal_grant.get('grantId') != grant_id \
            or terminal_grant.get('status') != 'consumed' \
            or terminal_grant.get('consumerPid') != os.getpid() \
            or terminal_grant.get('ownerHandle') not in (None, owner_handle):
        raise RuntimeError('consumed grant ownership changed before terminal update')
    terminal_grant.update(
        runStatus='terminal_pass' if state['runStatus'] == 'terminal_pass_cleaned'
            else 'terminal_fail',
        terminalAt=state['completedAt'], evidence=state['evidence'],
        cleanup={'clean': clean, 'errors': state['cleanupErrors'],
            'allProcessGroupsAbsent': state.get('allProcessGroupsAbsent'),
            'allProcessIdsAbsent': state.get('allProcessIdsAbsent')},
        resultSha256=state['suite'].get('qualificationSha256'),
        logSha256=state['suite'].get('logSha256'),
    )
    save_json(grant_path, terminal_grant)


def read_json_file(path, label, maximum=1024 * 1024):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum \
            or path.stat().st_mode & 0o077:
        raise RuntimeError(f'private bounded {label} required')
    try:
        return json.loads(path.read_text())
    except (OSError, UnicodeError, ValueError) as error:
        raise RuntimeError(f'valid {label} JSON required') from error


def query_model_tags():
    request = urllib.request.Request(OLLAMA_BASE_URL + '/api/tags', method='GET')
    try:
        # Ignore launcher-host proxy configuration; the only permitted endpoint
        # is the exact loopback origin above.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=10) as response:
            if response.status != 200:
                raise RuntimeError('Ollama tags endpoint returned non-200')
            body = response.read(1024 * 1024 + 1)
    except (urllib.error.URLError, TimeoutError) as error:
        raise RuntimeError('pinned loopback Ollama endpoint unavailable') from error
    if len(body) > 1024 * 1024:
        raise RuntimeError('Ollama tags response exceeds bound')
    try:
        payload = json.loads(body)
    except (UnicodeError, ValueError) as error:
        raise RuntimeError('Ollama tags response is not valid JSON') from error
    models = payload.get('models') if isinstance(payload, dict) else None
    if not isinstance(models, list):
        raise RuntimeError('Ollama tags model inventory missing')
    matches = [row for row in models if isinstance(row, dict)
        and (row.get('name') == MODEL or row.get('model') == MODEL)]
    if len(matches) != 1 or matches[0].get('digest') != MODEL_DIGEST:
        raise RuntimeError('exact pinned Ollama model digest unavailable')
    return {'model': MODEL, 'digest': MODEL_DIGEST, 'endpoint': OLLAMA_BASE_URL}


def validate_safe_result_value(value, path='result'):
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            validate_safe_result_value(child, f'{path}[{index}]')
        return
    if not isinstance(value, dict) or type(value) is not dict:
        raise RuntimeError(f'non-JSON result value forbidden at {path}')
    for key, child in value.items():
        if not isinstance(key, str) or key in FORBIDDEN_RESULT_KEYS:
            raise RuntimeError(f'private result key forbidden at {path}')
        if key.endswith('Sha256') and (not isinstance(child, str) or not SHA256_PATTERN.fullmatch(child)):
            raise RuntimeError(f'invalid result digest at {path}.{key}')
        if (key.endswith('Bytes') or key.endswith('CallCount')) \
                and (not isinstance(child, int) or isinstance(child, bool) or child < 0):
            raise RuntimeError(f'invalid result counter at {path}.{key}')
        validate_safe_result_value(child, f'{path}.{key}')


MANUAL_CASES = {
    'traversal_protected': ('path_traversal', 'readTeachingFile', True),
    'traversal_public': ('path_traversal', 'readTeachingFile', False),
    'ssi_known_echo': ('ssi_injection', 'renderSsiTemplate', True),
    'ssi_simulated_exec': ('ssi_injection', 'renderSsiTemplate', False),
    'combined_known_echo': ('combined_traversal_ssi', 'processTeachingDocument', True),
    'combined_unknown_echo': ('combined_traversal_ssi', 'processTeachingDocument', False),
    'ssi_failed_include': ('ssi_injection', 'renderSsiTemplate', False),
    'ssi_unknown_echo': ('ssi_injection', 'renderSsiTemplate', False),
    'combined_without_processing': ('combined_traversal_ssi', 'processTeachingDocument', False),
    'combined_simulated_exec': ('combined_traversal_ssi', 'processTeachingDocument', False),
    'traversal_outside_root': ('path_traversal', 'readTeachingFile', False),
}


def require_contract(condition, message):
    if not condition:
        raise RuntimeError(message)


def exact_fields(value, fields):
    require_contract(type(value) is dict and set(value) == set(fields.split()), 'exact report schema required')


def validate_model_calls(calls, label):
    require_contract(type(calls) is list and len(calls) <= 2, 'bounded Judge calls required')
    for call in calls:
        exact_fields(call, 'phase requestSha256 requestBytes outputSha256 outputBytes configuredContextTokens completed')
        require_contract(call['phase'] == 'judge' and type(call['configuredContextTokens']) is int
                         and call['configuredContextTokens'] == 32768 and type(call['completed']) is bool,
                         'Judge-only exact context required')
        for field in ('requestBytes', 'outputBytes'):
            require_contract(type(call[field]) is int and 0 <= call[field] <= 9007199254740991, 'bounded model bytes required')
        for field in ('requestSha256', 'outputSha256'):
            require_contract(type(call[field]) is str and SHA256_PATTERN.fullmatch(call[field]), 'model digest required')
        validate_safe_result_value(call)
    return calls


def validate_qualification(path, *, require_qualified=True):
    result = read_json_file(path, 'qualification')
    exact_fields(result, 'version cohort model digest qualification modelVerifiedBefore modelVerifiedAfter casesPreservedSibling cases cancellation failures')
    # observationSha256 is explicitly nullable before an effect returns.
    for key, value in result.items():
        if key != 'cases':
            validate_safe_result_value(value)
    require_contract(type(result['version']) is int and result['version'] == 1 and result['cohort'] == COHORT
                     and result['model'] == MODEL and result['digest'] == MODEL_DIGEST, 'qualification identity mismatch')
    require_contract(result['qualification'] in ('qualified', 'incomplete'), 'qualification state invalid')
    for field in ('modelVerifiedBefore', 'modelVerifiedAfter', 'casesPreservedSibling'):
        require_contract(type(result[field]) is bool, 'qualification boolean required')
    cases = result['cases']
    require_contract(type(cases) is list and len(cases) <= 11, 'bounded manual cases required')
    seen = set()
    for row in cases:
        exact_fields(row, 'name objectiveId operation passed failedPositive toolCalls receiptCount receiptCompleted observationSha256 scenarioChecks failureStage failureCode receiptReadFailed verdict completed durable calls')
        name = row['name']
        require_contract(type(name) is str and name in MANUAL_CASES and name not in seen, 'case identity invalid')
        seen.add(name)
        objective, operation, positive = MANUAL_CASES[name]
        require_contract(row['objectiveId'] == objective and row['operation'] == operation, 'manual operation mismatch')
        for field in ('passed', 'failedPositive', 'receiptCompleted', 'receiptReadFailed', 'completed', 'durable'):
            require_contract(type(row[field]) is bool, 'case boolean required')
        require_contract(row['durable'] is False and row['failedPositive'] == (positive and not row['passed']), 'credit boundary invalid')
        if row['receiptReadFailed']:
            require_contract(row['toolCalls'] is None and row['receiptCount'] is None, 'unknown effect counters must remain null')
        else:
            require_contract(all(type(row[k]) is int and 0 <= row[k] <= 1 for k in ('toolCalls', 'receiptCount'))
                             and row['receiptCount'] <= row['toolCalls'], 'manual effect counters invalid')
        digest = row['observationSha256']
        require_contract(digest is None or type(digest) is str and SHA256_PATTERN.fullmatch(digest), 'observation digest invalid')
        require_contract(row['verdict'] in ('pass', 'fail', 'inconclusive', 'unavailable'), 'verdict invalid')
        checks = row['scenarioChecks']
        exact_fields(checks, 'independentEffects canonicalFacts')
        require_contract(all(v is None or type(v) is bool for v in checks.values()), 'scenario booleans required')
        calls = validate_model_calls(row['calls'], name)
        if row['passed']:
            require_contract(row['failureStage'] is None and row['failureCode'] is None and not row['receiptReadFailed'], 'passing failure diagnostics invalid')
            require_contract(row['receiptCompleted'] and row['toolCalls'] == 1 and row['receiptCount'] == 1 and digest is not None, 'completed receipt required')
            require_contract(row['verdict'] == ('pass' if positive else 'fail') and row['completed'] == positive, 'case verdict contradicts expected effect')
            require_contract(bool(calls) and all(c['completed'] and c['requestBytes'] > 0 and c['outputBytes'] > 0 for c in calls), 'actual Judge calls required')
        else:
            require_contract(row['failureStage'] in ('admission', 'tool', 'receipt_validation', 'scenario_validation', 'judge', 'judge_validation', 'run_completion')
                             and row['failureCode'] in ('23514', 'ERR_ASSERTION', 'EFFECT_RECEIPT_INVALID', 'GRAPH_EFFECT_REPLAY_BLOCKED', 'ABORTED', 'UNCLASSIFIED'), 'safe failure diagnostics required')
        if row['failureStage'] in ('admission', 'tool', 'receipt_validation', 'scenario_validation'):
            require_contract(not calls, 'model calls before Judge forbidden')
        if not row['passed'] and row['failureStage'] in ('admission', 'tool', 'receipt_validation'):
            require_contract(all(v is None for v in checks.values()), 'unreached checks must remain null')
        else:
            require_contract(all(type(v) is bool for v in checks.values()), 'reached checks require booleans')
        if row['passed'] or row['failureStage'] in ('judge', 'judge_validation', 'run_completion'):
            require_contract(all(v is True for v in checks.values()), 'Judge reached without independently verified effects')
    cancellation = result['cancellation']
    exact_fields(cancellation, 'passed actorCalls judgeCalls calls')
    require_contract(type(cancellation['passed']) is bool and type(cancellation['actorCalls']) is int and cancellation['actorCalls'] == 0, 'manual cancellation actor boundary invalid')
    calls = validate_model_calls(cancellation['calls'], 'cancellation')
    require_contract(type(cancellation['judgeCalls']) is int and cancellation['judgeCalls'] == len(calls), 'cancellation Judge count invalid')
    if cancellation['passed']:
        require_contract(not calls, 'cancelled manual run must not invoke Judge')
    failures = result['failures']
    allowed = set(MANUAL_CASES) | {'reset_cancellation', 'qualification_infrastructure', 'model_provenance', 'pool_cleanup', 'sibling_case_isolation'}
    require_contract(type(failures) is list and all(type(f) is str and f in allowed for f in failures), 'safe failure labels required')
    require_contract(len(set(failures)) == len(failures), 'duplicate failure labels')
    for row in cases:
        require_contract((row['name'] in failures) == (not row['passed']), 'failure labels contradict cases')
    if result['qualification'] == 'qualified':
        require_contract(seen == set(MANUAL_CASES) and all(row['passed'] for row in cases) and cancellation['passed']
                         and result['modelVerifiedBefore'] and result['modelVerifiedAfter'] and result['casesPreservedSibling'] and not failures,
                         'qualified state contradicts evidence')
    else:
        require_contract(bool(failures), 'incomplete report requires failure reason')
    if require_qualified:
        require_contract(result['qualification'] == 'qualified', 'actual-model qualification incomplete')
    return result


def retain_artifact(path):
    """Retain identical audit treatment for passing and failing child evidence."""
    digest = sha256(path)
    os.chmod(path, 0o400)
    return digest


def verify_tap(log_path):
    content = Path(log_path).read_text()
    if not re.search(r'(?m)^1\.\.1\s*$', content) \
            or not re.search(r'(?m)^# tests 1\s*$', content) \
            or not re.search(r'(?m)^# pass 1\s*$', content) \
            or not re.search(r'(?m)^# fail 0\s*$', content) \
            or not re.search(r'(?m)^# skipped 0\s*$', content) \
            or re.search(r'(?m)^not ok\b', content):
        raise RuntimeError('actual-model TAP did not prove exactly one pass and zero fail/skip')
    return sha256(log_path)


def expected_grant(args, manifest, owner_handle, node_sha, manifest_sha):
    package = Path(args.package_root).resolve()
    handle = Path(args.owner_handle_file).resolve()
    return {
        'grantId': args.grant_id,
        'owner': '/root',
        'allowedLaunches': 1,
        'runNonce': args.run_nonce,
        'canonicalWorkspaceRoot': str(Path(args.canonical_workspace).resolve()),
        'candidateSourceRoot': str(package / 'source'),
        'candidateManifestSha256': manifest_sha,
        'sourceFilesSha256': manifest['sourceFilesSha256'],
        'dependencyFilesSha256': manifest['dependencyFilesSha256'],
        'dependencySymlinksSha256': manifest['dependencySymlinksSha256'],
        'managedNodePath': str(Path(args.managed_node).resolve()),
        'managedNodeSha256': node_sha,
        'dockerHost': DOCKER_HOST,
        'dockerDaemonId': DOCKER_DAEMON_ID,
        'postgresImageId': POSTGRES_IMAGE_ID,
        'registeredIdentityHead': REGISTERED_IDENTITY_HEAD,
        'ollamaBaseUrl': OLLAMA_BASE_URL,
        'ollamaModel': MODEL,
        'ollamaModelDigest': MODEL_DIGEST,
        'stage': STAGE,
        'scope': SCOPE,
        'evidenceRoot': str(Path(args.evidence_root).resolve()),
        'expectedOwnerHandle': owner_handle,
        'ownerHandlePath': str(handle),
        'ownerHandleFileSha256': sha256(handle),
        'expectedLauncherPid': os.getpid(),
        'ownerHandle': None,
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    for name in ('package-root', 'manifest', 'managed-node', 'run-nonce', 'evidence-root',
                 'grant-file', 'grant-id', 'owner', 'owner-handle-file',
                 'canonical-workspace', 'model-digest', 'scope'):
        parser.add_argument('--' + name, required=True)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.owner != '/root' or args.scope != SCOPE or args.model_digest != MODEL_DIGEST \
            or not re.fullmatch(r'[0-9a-f]{12}', args.run_nonce):
        raise RuntimeError('launch binding invalid')
    package = resolve_without_symlinks(args.package_root, 'package')
    source = package / 'source'
    manifest_path = resolve_without_symlinks(args.manifest, 'manifest')
    node = resolve_without_symlinks(args.managed_node, 'managed Node')
    grant_path = resolve_without_symlinks(args.grant_file, 'grant')
    handle_path = resolve_without_symlinks(args.owner_handle_file, 'owner handle')
    evidence_path = resolve_without_symlinks(args.evidence_root, 'evidence', must_exist=False)
    canonical = resolve_without_symlinks(args.canonical_workspace, 'canonical workspace')
    if not canonical.is_dir() or canonical.is_symlink() \
            or evidence_path.is_relative_to(package) or evidence_path.is_relative_to(canonical):
        raise RuntimeError('canonical/evidence path binding invalid')
    manifest = verify_manifest(package, manifest_path)
    if node.is_symlink() or not node.is_file():
        raise RuntimeError('managed Node regular file required')
    node_version = run([str(node), '--version'], capture_output=True, timeout=10)
    if node_version.returncode or node_version.stdout.strip() != NODE_VERSION:
        raise RuntimeError('managed Node version mismatch')
    node_sha, manifest_sha = sha256(node), sha256(manifest_path)
    if node_sha != NODE_SHA256:
        raise RuntimeError('managed Node digest mismatch')
    if handle_path.is_symlink() or not handle_path.is_file() or handle_path.stat().st_mode & 0o077:
        raise RuntimeError('private owner handle file required')
    handle_text = handle_path.read_text().strip()
    if not handle_text.isdecimal() or int(handle_text) <= 0:
        raise RuntimeError('positive opaque owner handle required')
    owner_handle = int(handle_text)
    if os.path.lexists(evidence_path):
        raise RuntimeError('fresh evidence root required')
    parent = evidence_path.parent
    parent_stat = parent.lstat()
    if parent.is_symlink() or not parent.is_dir() or parent_stat.st_uid != os.getuid() \
            or parent_stat.st_mode & 0o077:
        raise RuntimeError('private evidence parent required')
    expected = expected_grant(args, manifest, owner_handle, node_sha, manifest_sha)
    if grant_path.is_symlink() or not grant_path.is_file() or grant_path.stat().st_mode & 0o077:
        raise RuntimeError('private grant file required')
    grant = json.loads(grant_path.read_text())
    if grant.get('status') != 'granted' or any(grant.get(key) != value for key, value in expected.items()):
        raise RuntimeError('exact one-use grant binding mismatch')
    # Prepare the recovery journal and signal guard before the one-way grant
    # transition. Every operation after consumption is inside the try/finally.
    evidence_path.mkdir(mode=0o700)
    ownership_path = evidence_path / 'ownership.json'
    qualification_path = evidence_path / 'qualification.json'
    log_path = evidence_path / 'legacySensitiveManualActual8b.tap'
    state = {
        'version': 1,
        'stage': STAGE,
        'scope': SCOPE,
        'owner': '/root',
        'ownerHandle': owner_handle,
        'grantId': args.grant_id,
        'launcherPid': os.getpid(),
        'createdAt': utc_now(),
        'runStatus': 'owner_handle_pending',
        'manifestSha256': manifest_sha,
        'sourceFilesSha256': manifest['sourceFilesSha256'],
        'dependencyFilesSha256': manifest['dependencyFilesSha256'],
        'managedNodePath': str(node),
        'managedNodeSha256': node_sha,
        'model': MODEL,
        'modelDigest': MODEL_DIGEST,
        'dockerHost': DOCKER_HOST,
        'dockerDaemonId': DOCKER_DAEMON_ID,
        'postgresImageId': POSTGRES_IMAGE_ID,
        'registeredIdentityHead': REGISTERED_IDENTITY_HEAD,
        'ollamaBaseUrl': OLLAMA_BASE_URL,
        'evidence': str(evidence_path),
        'processes': {},
        'suite': {'name': 'legacySensitiveManualActual8b', 'test': TEST_PATH},
    }

    def persist():
        save_json(ownership_path, state)

    persist()
    docker = ['docker', '--host', DOCKER_HOST]
    container_name = 'owasp-ai-goat-legacy-sensitive-manual-' + args.run_nonce
    container_id = None
    container_attempted = False
    database = 'owasp_ai_goat_test_legacy_sensitive_manual'
    labels = {'owasp-ai-goat.owner': '/root', 'owasp-ai-goat.grant': args.grant_id,
              'owasp-ai-goat.nonce': args.run_nonce, 'owasp-ai-goat.stage': STAGE}

    def psql(sql):
        result = run(docker + ['exec', container_id, 'psql', '-U', 'owasp_ai_goat_bootstrap',
            '-d', 'postgres', '-v', 'ON_ERROR_STOP=1', '-c', sql],
            capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError('owned PostgreSQL provisioning failed')

    active_name = 'bootstrap'
    active_process = None
    active_pgid = None
    passed = False
    cleanup_errors = []

    def handle_signal(signum, _frame):
        raise InterruptedError(f'received signal {signum}')

    previous_handlers = {signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)}
    for signum in previous_handlers:
        signal.signal(signum, handle_signal)

    try:
        consume_one_use_grant(grant_path, expected, evidence_path)
        state['runStatus'] = 'grant_consumed'
        persist()
        print('WAITING_OWNER_HANDLE', flush=True)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            current = json.loads(grant_path.read_text())
            registered = current.get('ownerHandle')
            if registered is not None:
                if registered != owner_handle:
                    raise RuntimeError('registered owner handle mismatch')
                break
            time.sleep(.1)
        else:
            raise RuntimeError('owner handle registration timeout')
        state['runStatus'] = 'owner_registered'
        state['modelInventory'] = query_model_tags()
        persist()

        daemon = run(docker + ['info', '--format', '{{json .}}'], capture_output=True, timeout=30)
        try:
            daemon_info = json.loads(daemon.stdout) if daemon.returncode == 0 else None
        except (TypeError, ValueError):
            daemon_info = None
        if not daemon_info or daemon_info.get('ID') != DOCKER_DAEMON_ID \
                or daemon_info.get('Name') != 'colima-owasp-ai-goat-pg-verify' \
                or daemon_info.get('Architecture') != 'aarch64':
            raise RuntimeError('exact Colima verification daemon required')
        state['dockerDaemon'] = {'id': daemon_info['ID'], 'name': daemon_info['Name'],
            'architecture': daemon_info['Architecture']}
        persist()
        image = run(docker + ['image', 'inspect', '--format', '{{.Id}}', POSTGRES_IMAGE],
            capture_output=True, timeout=20)
        if image.returncode or image.stdout.strip() != POSTGRES_IMAGE_ID:
            raise RuntimeError('PostgreSQL image identity mismatch')
        if not docker_object_absent(docker, container_name):
            raise RuntimeError('owned container name already exists')
        container_attempted = True
        state['containerCreateAttempt'] = {'status': 'started', 'startedAt': utc_now(),
            'name': container_name, 'expectedLabels': labels}
        persist()
        created = run(docker + ['run', '--detach', '--pull', 'never', '--name', container_name,
            *sum((['--label', f'{key}={value}'] for key, value in labels.items()), []),
            '--tmpfs', '/var/lib/postgresql:rw,size=536870912',
            '-e', 'POSTGRES_USER=owasp_ai_goat_bootstrap', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
            '-p', '127.0.0.1::5432', POSTGRES_IMAGE,
            '-c', 'shared_buffers=24MB', '-c', 'max_connections=32'],
            capture_output=True, timeout=60)
        state['containerCreateAttempt'].update(status='returned', returnCode=created.returncode,
            stdoutSha256=hashlib.sha256((created.stdout or '').encode()).hexdigest(),
            stderrSha256=hashlib.sha256((created.stderr or '').encode()).hexdigest())
        persist()
        if created.returncode:
            raise RuntimeError('owned PostgreSQL container creation failed')
        created_id = created.stdout.strip()
        if not re.fullmatch(r'[0-9a-f]{64}', created_id):
            raise RuntimeError('invalid owned container id')
        container_id = created_id
        state.update(containerId=container_id, runStatus='container_started')
        persist()
        for _ in range(120):
            ready = run(docker + ['exec', container_id, 'pg_isready', '-h', '127.0.0.1',
                '-U', 'owasp_ai_goat_bootstrap'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            if ready.returncode == 0:
                break
            time.sleep(.25)
        else:
            raise RuntimeError('owned PostgreSQL readiness timeout')
        binding = run(docker + ['port', container_id, '5432/tcp'], capture_output=True, timeout=20)
        if binding.returncode or not re.fullmatch(r'127\.0\.0\.1:\d+\s*', binding.stdout):
            raise RuntimeError('loopback PostgreSQL binding required')
        postgres_port = int(binding.stdout.strip().rsplit(':', 1)[1])
        state['postgresLoopbackPort'] = postgres_port
        state['databaseProvisioningAttempt'] = {'status': 'started', 'startedAt': utc_now(),
            'databaseName': database, 'roles': [MIGRATION_ROLE, RUNTIME_ROLE]}
        persist()
        psql(f'CREATE ROLE {MIGRATION_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
        psql(f'CREATE ROLE {RUNTIME_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
        psql(f'CREATE DATABASE {database} OWNER {MIGRATION_ROLE}')
        psql(f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; '
             f'GRANT CONNECT ON DATABASE {database} TO {MIGRATION_ROLE},{RUNTIME_ROLE}')
        state['databaseProvisioningAttempt']['status'] = 'complete'
        persist()

        home = evidence_path / 'home'
        temporary = evidence_path / 'tmp'
        fixtures = evidence_path / 'fixtures'
        for directory in (home, temporary, fixtures):
            directory.mkdir(mode=0o700)
        child_env = {
            'PG_TEST_DISPOSABLE': 'yes',
            'PG_LEGACY_SENSITIVE_MANUAL_RUNTIME_URL': f'postgresql://{RUNTIME_ROLE}@127.0.0.1:{postgres_port}/{database}',
            'LEGACY_SENSITIVE_MANUAL_FIXTURE_ROOT': str(fixtures),
            'PATH': str(node.parent) + ':/usr/bin:/bin:/usr/sbin:/sbin',
            'HOME': str(home),
            'TMPDIR': str(temporary),
            'TMP': str(temporary),
            'TEMP': str(temporary),
            'NODE_ENV': 'test',
            'AWS_EC2_METADATA_DISABLED': 'true',
            'LANGCHAIN_TRACING_V2': 'false',
            'LANGSMITH_TRACING': 'false',
            'NO_PROXY': '127.0.0.1,localhost',
            'OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE': str(source),
            'LEGACY_SENSITIVE_MANUAL_ACTUAL8B_ISOLATED': '1',
            'LEGACY_SENSITIVE_MANUAL_ACTUAL8B_STAGE': STAGE,
            'AI_PROVIDER': 'ollama',
            'OLLAMA_BASE_URL': OLLAMA_BASE_URL,
            'OLLAMA_MODEL': MODEL,
            'JUDGE_PROVIDER': 'ollama',
            'JUDGE_MODEL': MODEL,
            'LEGACY_SENSITIVE_MANUAL_MODEL_DIGEST': MODEL_DIGEST,
            'LEGACY_SENSITIVE_MANUAL_EVIDENCE_PATH': str(qualification_path),
        }
        bootstrap_env = {key: value for key, value in child_env.items() if key in
            ('PATH','HOME','TMPDIR','TMP','TEMP','NODE_ENV','AWS_EC2_METADATA_DISABLED','PG_TEST_DISPOSABLE')}
        bootstrap_env['IDENTITY_RUNTIME_URL'] = child_env['PG_LEGACY_SENSITIVE_MANUAL_RUNTIME_URL']
        bootstrap_env['IDENTITY_MIGRATION_URL'] = f'postgresql://{MIGRATION_ROLE}@127.0.0.1:{postgres_port}/{database}'
        bootstrap_script = r"""
const assert = require('node:assert/strict');
const path = require('node:path');
const { createPool } = require('./server/database/postgres');
const { readMigrations } = require('./db/postgres/migrate');
const { initializeIdentityRepository } = require('./server/database/postgres/identityRepository');
(async()=> {
  const runtime=createPool(process.env,'IDENTITY_RUNTIME_URL');
  const migration=createPool(process.env,'IDENTITY_MIGRATION_URL');
  try {
    assert.equal((await migration.query("SELECT to_regnamespace('identity') AS schema")).rows[0].schema,null);
    const rows=await readMigrations(path.resolve('db/postgres/identity-migrations'));
    assert.equal(rows.at(-1).name,'0061_mcp_supply_chain_curriculum_defaults.sql');
    assert.deepEqual(await initializeIdentityRepository(runtime,migration), rows.map(r=>r.name));
    assert.deepEqual(await initializeIdentityRepository(runtime,migration), []);
    console.log('IDENTITY_PREFIX_0061_READY');
  } finally { await runtime.end(); await migration.end(); }
})().catch(()=>{console.error('IDENTITY_BOOTSTRAP_FAILED');process.exitCode=1;});
"""
        bootstrap_log=evidence_path/'bootstrap.log'
        with bootstrap_log.open('w') as output:
            os.chmod(bootstrap_log,0o600)
            active_process=subprocess.Popen([str(node),'-e',bootstrap_script],cwd=source,
                env=bootstrap_env,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
            active_pgid=register_owned_process(active_process,state,persist,name='bootstrap')
            code=active_process.wait(timeout=180)
        if not cleanup_owned_process(state['processes']['bootstrap'],active_process) or code != 0 \
                or bootstrap_log.read_text().strip() != 'IDENTITY_PREFIX_0061_READY':
            raise RuntimeError('identity bootstrap failed')
        state['bootstrapLogSha256']=sha256(bootstrap_log)
        active_process=None
        active_name='test'
        state['suite'].update(status='starting', log=str(log_path), startedAt=utc_now())
        persist()
        with log_path.open('w') as output:
            os.chmod(log_path, 0o600)
            active_process = subprocess.Popen([
                str(node), '--test', '--test-concurrency=1', '--test-reporter=tap', TEST_PATH,
            ], cwd=source, env=child_env, stdout=output, stderr=subprocess.STDOUT,
                start_new_session=True)
            active_pgid = register_owned_process(active_process, state, persist)
            state['suite']['status'] = 'running'
            persist()
            try:
                exit_code = active_process.wait(timeout=1800)
            except subprocess.TimeoutExpired:
                terminate_group(active_pgid, active_process, grace=8)
                raise RuntimeError('actual-model test timed out')
        state['suite']['logSha256'] = retain_artifact(log_path)
        persist()
        group_absent = terminate_group(active_pgid, active_process, grace=3)
        state['processes']['test'].update(status='exited', exitCode=exit_code,
            groupAbsent=group_absent, completedAt=utc_now())
        # A deliberately failed positive remains useful redacted evidence. Read
        # and hash its structurally valid incomplete report before failing the
        # launcher on the test exit code.
        qualification = validate_qualification(qualification_path, require_qualified=False)
        qualification_sha = retain_artifact(qualification_path)
        state['suite'].update(qualificationSha256=qualification_sha,
            caseCount=len(qualification['cases']), qualification=qualification['qualification'])
        persist()
        if exit_code or not group_absent:
            raise RuntimeError('actual-model test failed or left its process group')
        validate_qualification(qualification_path, require_qualified=True)
        log_sha = verify_tap(log_path)
        os.chmod(qualification_path, 0o400)
        os.chmod(log_path, 0o400)
        state['suite'].update(status='passed', logSha256=log_sha,
            completedAt=utc_now())
        state['runStatus'] = 'suite_passed'
        persist()
        passed = True
    except BaseException as error:
        state.update(runStatus='suite_failed', failure=f'{type(error).__name__}: {error}'[:1000])
        persist()
        raise
    finally:
        # A second controller signal must not interrupt owned cleanup or the
        # terminal grant write. Restore the caller's handlers only afterward.
        for signum, handler in previous_handlers.items():
            signal.signal(signum, signal.SIG_IGN)
        if active_process:
            try:
                cleanup_owned_process(state['processes'].setdefault(active_name, {
                    'pid': active_process.pid, 'expectedPgid': active_process.pid,
                }), active_process)
            except Exception as error:
                cleanup_errors.append(f'active process cleanup: {error}'[:500])
        if container_attempted:
            try:
                removed = remove_owned_container(docker, container_name, container_id, labels)
                container_id = container_id or removed
                state['containerNameAbsent'] = docker_object_absent(docker, container_name)
                state['containerIdAbsent'] = docker_object_absent(docker, container_id) if container_id else None
            except Exception as error:
                cleanup_errors.append(f'container cleanup: {type(error).__name__}')
                state['containerNameAbsent'] = False
        else:
            state['containerNameAbsent'] = True
            state['containerIdAbsent'] = None
        state['databaseAbsent'] = state['containerNameAbsent'] and state.get('containerIdAbsent') in (True, None)
        for process in state['processes'].values():
            if isinstance(process.get('pgid'), int):
                process['groupAbsent'] = process_group_absent(process['pgid'])
            if isinstance(process.get('pid'), int):
                process['pidAbsent'] = process_absent(process['pid'])
        state['allProcessGroupsAbsent'] = all(row.get('groupAbsent') is True
            for row in state['processes'].values())
        state['allProcessIdsAbsent'] = all(row.get('pidAbsent') is True
            for row in state['processes'].values())
        try:
            verify_postflight_identity(package, manifest_path, manifest, manifest_sha, node, node_sha)
            state['postflightManifestVerified'] = True
        except Exception as error:
            state['postflightManifestVerified'] = False
            cleanup_errors.append(f'postflight manifest: {error}'[:500])
        try:
            state['postflightModelInventory'] = query_model_tags()
        except Exception as error:
            cleanup_errors.append('postflight model provenance unavailable')
        state['cleanupErrors'] = cleanup_errors
        state['completedAt'] = utc_now()
        clean = not cleanup_errors and state.get('databaseAbsent') is True \
            and state.get('allProcessGroupsAbsent') is True \
            and state.get('allProcessIdsAbsent') is True \
            and state.get('postflightManifestVerified') is True
        state['runStatus'] = 'terminal_pass_cleaned' if passed and clean \
            else 'terminal_fail_cleaned' if clean else 'terminal_fail_cleanup_uncertain'
        persist()
        try:
            record_terminal_grant(grant_path, args.grant_id, owner_handle, state, clean)
            state['terminalGrantRecorded'] = True
            persist()
        except Exception as error:
            state['terminalGrantRecorded'] = False
            state['cleanupErrors'].append(f'terminal grant update: {error}'[:500])
            state['runStatus'] = 'terminal_fail_cleanup_uncertain'
            persist()
            clean = False
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        if not passed or not clean:
            raise RuntimeError('actual-model qualification did not pass with verified cleanup')
    print(json.dumps({'status': state['runStatus'], 'evidence': str(evidence_path),
        'qualificationSha256': state['suite'].get('qualificationSha256'),
        'logSha256': state['suite'].get('logSha256')}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'launcher failure: {error}', file=sys.stderr)
        raise SystemExit(1)
