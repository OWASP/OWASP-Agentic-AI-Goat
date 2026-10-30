#!/usr/bin/env python3
"""Strict root-owned launcher for the PostgreSQL admin/auth/browser/analytics cohort.

This source file is inert when imported. Historical cohorts require an immutable
exact source/dependency package. The closed admin-browser-current-main cohort
instead admits the exact canonical checkout through a pinned current manifest.
Every cohort requires an exact one-use native grant and never reads application
database URLs or secrets from the canonical workspace.
"""

import argparse
import contextlib
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


STAGE = 'admin-auth-browser-cohort-source-r2'
SCOPE = 'admin_auth_browser_pg18'
POSTGRES_IMAGE = 'postgres:18'
POSTGRES_IMAGE_ID = 'sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
DOCKER_HOST = 'unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock'
NODE_VERSION = 'v26.9.0'
MIGRATION_ROLE = 'dvaia_identity_migration'
RUNTIME_ROLE = 'dvaia_identity_runtime'
BROWSER_RESOURCE_ENV = 'PG_ADMIN_BROWSER_RESOURCE_JOURNAL'
BROWSER_TEMP_ENV = 'PG_ADMIN_BROWSER_TEMP_ROOT'
CHROMIUM_ACTUAL_ENV = 'OWASP_AI_GOAT_CHROMIUM_ACTUAL_EXECUTABLE'
CHROMIUM_WRAPPER_JOURNAL_ENV = 'OWASP_AI_GOAT_CHROMIUM_WRAPPER_JOURNAL'

CHROMIUM_WRAPPER_SOURCE = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path

actual = Path(os.environ['OWASP_AI_GOAT_CHROMIUM_ACTUAL_EXECUTABLE']).resolve()
journal = Path(os.environ['OWASP_AI_GOAT_CHROMIUM_WRAPPER_JOURNAL']).resolve()
pending = Path(str(journal) + f'.{os.getpid()}.pending')
with pending.open('w') as output:
    json.dump({'version': 1, 'pid': os.getpid(), 'pgid': os.getpgrp(),
               'actualExecutable': str(actual)}, output, sort_keys=True)
    output.write('\\n'); output.flush(); os.fsync(output.fileno())
os.chmod(pending, 0o600); os.replace(pending, journal)
directory = os.open(journal.parent, os.O_RDONLY)
try: os.fsync(directory)
finally: os.close(directory)
os.execv(actual, [str(actual), *sys.argv[1:]])
'''

SUITES = (
    {
        'name': 'authHttp',
        'test': 'tests/postgres/authHttp.integration.test.js',
        'databaseStem': 'auth_http',
        'migrationVariable': 'PG_HTTP_TEST_MIGRATION_URL',
        'runtimeVariable': 'PG_HTTP_TEST_RUNTIME_URL',
        'gate': None,
        'timeoutSeconds': 300,
    },
    {
        'name': 'adminHttp',
        'test': 'tests/postgres/adminHttp.integration.test.js',
        'databaseStem': 'admin_http',
        'migrationVariable': 'PG_ADMIN_TEST_MIGRATION_URL',
        'runtimeVariable': 'PG_ADMIN_TEST_RUNTIME_URL',
        'gate': None,
        'timeoutSeconds': 300,
    },
    {
        'name': 'adminProgressAnalytics',
        'test': 'tests/postgres/adminProgressAnalytics.integration.test.js',
        'databaseStem': 'admin_analytics',
        'migrationVariable': 'PG_ADMIN_ANALYTICS_TEST_MIGRATION_URL',
        'runtimeVariable': 'PG_ADMIN_ANALYTICS_TEST_RUNTIME_URL',
        'gate': None,
        'timeoutSeconds': 300,
    },
    {
        'name': 'adminProductionAuthBrowser',
        'test': 'tests/postgres/adminProductionAuthBrowser.integration.test.js',
        'databaseStem': 'admin_browser',
        'migrationVariable': 'PG_ADMIN_BROWSER_TEST_MIGRATION_URL',
        'runtimeVariable': 'PG_ADMIN_BROWSER_TEST_RUNTIME_URL',
        'gate': ('RUN_ADMIN_PRODUCTION_BROWSER', '1'),
        'timeoutSeconds': 480,
    },
)



FULL_SUITES = SUITES
FULL_SCOPE = SCOPE
FULL_NODE_VERSION = NODE_VERSION
ANALYTICS_NODE_SHA256 = '56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'

DPI_CONTAINMENT_SUITE = {
    'name': 'dpiSemanticContainment',
    'test': 'tests/postgres/dpiSemanticCreditContainment.integration.test.js',
    'databaseStem': 'dpi_containment_fresh',
    'migrationVariable': 'PG_DPI_CONTAINMENT_FRESH_MIGRATION_URL',
    'runtimeVariable': 'PG_DPI_CONTAINMENT_FRESH_RUNTIME_URL',
    'gate': ('DPI_CONTAINMENT_ISOLATED', '1'),
    'timeoutSeconds': 300,
    'extraDatabases': [{
        'name': 'dpiSemanticContainmentPopulated',
        'databaseStem': 'dpi_containment_populated',
        'migrationVariable': 'PG_DPI_CONTAINMENT_POPULATED_MIGRATION_URL',
        'runtimeVariable': 'PG_DPI_CONTAINMENT_POPULATED_RUNTIME_URL',
    }],
}


STUDENT_RESET_SUITE = {
    **FULL_SUITES[3],
    'extraDatabases': [{
        'name': 'studentResetFinflow', 'databaseStem': 'student_reset_finflow',
        'migrationVariable': 'FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL',
        'runtimeVariable': 'FINFLOW_WORKSHOP_DATABASE_URL',
        'migrationRole': 'dvaia_finflow_migration', 'runtimeRole': 'dvaia_finflow_runtime',
    }],
}

def database_roles():
    return {store['name']: {'migrationRole': store.get('migrationRole', MIGRATION_ROLE),
                           'runtimeRole': store.get('runtimeRole', RUNTIME_ROLE)}
            for suite in SUITES for store in (suite, *suite.get('extraDatabases', []))}


def configure_cohort(name):
    """Closed CLI selection; full cohort keeps its historical contract."""
    global SUITES, SCOPE, NODE_VERSION
    if name not in ('full', 'analytics-only', 'dpi-containment', 'student-reset-only',
                    'admin-browser-current-main'):
        raise ValueError('unknown admin cohort')
    SUITES = FULL_SUITES if name == 'full' else tuple(s for s in FULL_SUITES if s['name'] == 'adminProgressAnalytics')
    if name == 'dpi-containment':
        SUITES = (DPI_CONTAINMENT_SUITE,)
    if name == 'student-reset-only':
        SUITES = (STUDENT_RESET_SUITE,)
    if name == 'admin-browser-current-main':
        SUITES = (FULL_SUITES[3],)
    SCOPE = {'full': FULL_SCOPE, 'analytics-only': 'admin_progress_analytics_pg18',
             'dpi-containment': 'dpi_semantic_containment_pg18',
             'student-reset-only': 'admin_student_reset_pg18',
             'admin-browser-current-main': 'admin_production_browser_current_main_pg18'}[name]
    NODE_VERSION = FULL_NODE_VERSION if name == 'full' else 'v26.10.0'


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
    """Atomically persist and fsync the private ownership/resource journal."""
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
    return relative == 'source/node_modules' \
        or relative.startswith('source/node_modules/') \
        or relative == 'source/client/node_modules' \
        or relative.startswith('source/client/node_modules/')


def package_inventory(package):
    source = Path(package) / 'source'
    source_files, dependency_files, dependency_links = {}, {}, {}
    source_directories, dependency_directories = [], []
    if source.is_symlink() or not source.is_dir():
        raise RuntimeError('copied package source directory required')
    if source.stat().st_mode & 0o222:
        raise RuntimeError('frozen source root must be read-only')
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
            roots = [source / 'node_modules', source / 'client/node_modules']
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
    package = Path(package)
    manifest_path = Path(manifest_path)
    if package.is_symlink() or not package.is_dir() \
            or manifest_path != package / 'manifest.json' \
            or manifest_path.is_symlink() or not manifest_path.is_file():
        raise RuntimeError('exact package manifest path required')
    if manifest_path.stat().st_mode & 0o222:
        raise RuntimeError('frozen manifest must be read-only')
    entries = {entry.name for entry in package.iterdir()}
    if entries != {'source', 'manifest.json'}:
        raise RuntimeError('package inventory must contain only source and manifest.json')
    manifest = json.loads(manifest_path.read_text())
    expected_suites = [{
        **{key: suite[key] for key in (
            'name', 'test', 'databaseStem', 'migrationVariable', 'runtimeVariable',
            'timeoutSeconds')},
        'gate': list(suite['gate']) if suite['gate'] else None,
        **({'extraDatabases': suite['extraDatabases']} if suite.get('extraDatabases') else {}),
    } for suite in SUITES]
    if manifest.get('stage') != STAGE or manifest.get('scope') != SCOPE \
            or manifest.get('qualification') != 'native-source-candidate' \
            or manifest.get('semanticEffectsQualified') != [] \
            or manifest.get('mutableSourcePaths') != [] \
            or manifest.get('suites') != expected_suites:
        raise RuntimeError('manifest cohort boundary invalid')
    observed = package_inventory(package)
    for field, value in observed.items():
        if manifest.get(field) != value:
            raise RuntimeError(f'manifest inventory mismatch: {field}')
        if manifest.get(field + 'Sha256') != json_digest(value):
            raise RuntimeError(f'manifest snapshot mismatch: {field}')
    required = {f'source/{suite["test"]}' for suite in SUITES}
    required.add('source/tests/postgres/run-admin-auth-browser-cohort-isolated.py')
    if SCOPE == 'admin_student_reset_pg18':
        required.update('source/' + p for p in (
            'tests/postgres/adminStudentResetRecoverySupport.js',
            'tests/postgres/adminStudentResetRecoveryBrowser.js',
            'client/src/utils/adminStudentReset.js'))
    if not required.issubset(observed['sourceFiles']):
        raise RuntimeError('cohort source closure is incomplete')
    for required_dependency in ('source/node_modules/pg/package.json',
                                'source/node_modules/puppeteer/package.json',
                                'source/client/node_modules/vite/package.json'):
        if required_dependency not in observed['dependencyFiles']:
            raise RuntimeError(f'required frozen dependency missing: {required_dependency}')
    if any(path.name != '.env.example' for path in (package / 'source').rglob('.env*')):
        raise RuntimeError('live environment files forbidden in package')
    return manifest


def verify_postflight_identity(package, manifest_path, expected_manifest, expected_manifest_sha,
                               node, expected_node_sha, chromium, expected_chromium_sha):
    observed_manifest = verify_manifest(package, manifest_path)
    if observed_manifest != expected_manifest or sha256(manifest_path) != expected_manifest_sha \
            or sha256(node) != expected_node_sha or sha256(chromium) != expected_chromium_sha:
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


def docker_missing_exact_target(message, target):
    pattern = rf'No such (?:object|container): {re.escape(target)}\r?$'
    return re.search(pattern, message or '', flags=re.MULTILINE) is not None


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


def database_plan(nonce):
    if not re.fullmatch(r'[0-9a-f]{12}', nonce):
        raise ValueError('12-character lowercase hexadecimal nonce required')
    return {store['name']: f'owasp_ai_goat_test_{store["databaseStem"]}_{nonce}'
            for suite in SUITES for store in (suite, *suite.get('extraDatabases', []))}


def suite_environment(base_env, suite, databases, postgres_port):
    env = dict(base_env)
    for store in (suite, *suite.get('extraDatabases', [])):
        database = databases[store['name']]
        env[store['migrationVariable']] = f'postgresql://{store.get("migrationRole", MIGRATION_ROLE)}@127.0.0.1:{postgres_port}/{database}'
        env[store['runtimeVariable']] = f'postgresql://{store.get("runtimeRole", RUNTIME_ROLE)}@127.0.0.1:{postgres_port}/{database}'
    if SCOPE == 'admin_student_reset_pg18':
        env.update(ADMIN_STUDENT_RESET_ONLY='1', PLATFORM_DATABASE_ENGINE='postgres', WORKSHOP_DATABASE_ENGINE='postgres',
                   SENSITIVE_INFO_AGGREGATE_RESET_ENABLED='true')
    if suite['gate']:
        env[suite['gate'][0]] = suite['gate'][1]
    return env


def cohort_resource_args(name):
    return ['--memory', '1g', '--cpus', '1', '--pids-limit', '128'] if name in (
        'dpi-containment', 'student-reset-only', 'admin-browser-current-main') else []


def verify_tap(log_path):
    content = Path(log_path).read_text()
    for pattern in (r'(?m)^# pass 1\s*$', r'(?m)^# fail 0\s*$', r'(?m)^# skipped 0\s*$'):
        if not re.search(pattern, content):
            raise RuntimeError('cohort TAP did not prove exactly one pass, zero fail, zero skipped')
    return sha256(log_path)


def load_browser_resource_journal(path, expected_root, require_terminal=False):
    path, expected_root = Path(path), Path(expected_root)
    if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o077:
        if require_terminal:
            raise RuntimeError('private browser resource journal required')
        return None
    journal = json.loads(path.read_text())
    expected_paths = {
        'tempRoot': str(expected_root),
        'buildDirectory': str(expected_root / 'build'),
        'profileDirectory': str(expected_root / 'chromium-profile'),
    }
    resources = journal.get('resources', {})
    if journal.get('version') != 1 or any(resources.get(key) != value for key, value in expected_paths.items()):
        raise RuntimeError('browser resource journal binding invalid')
    if require_terminal:
        server = resources.get('server', {})
        if journal.get('status') != 'cleanup_complete' or journal.get('testBody') != 'passed' \
                or journal.get('externalCleanupAuthority') != 'launcher-owned-test-process-group-and-database' \
                or server.get('address') != '127.0.0.1' \
                or journal.get('tempRootAbsent') is not True:
            raise RuntimeError('browser resource cleanup was not proven')
        if not isinstance(server.get('port'), int) or not 1 <= server['port'] <= 65535:
            raise RuntimeError('browser loopback server port missing')
        if not journal.get('cleanup') or any(row.get('ok') is not True for row in journal['cleanup']):
            raise RuntimeError('browser cleanup step failed')
        build = resources.get('build', {})
        if not process_absent(build.get('pid')) or not process_group_absent(build.get('pgid')):
            raise RuntimeError('build cleanup was not proven')
        if not process_absent(resources.get('browser', {}).get('pid')):
            raise RuntimeError('browser root cleanup was not proven')
    return journal


def terminate_browser_journal_resources(path, expected_root):
    journal = load_browser_resource_journal(path, expected_root, require_terminal=False)
    results = {}
    if journal:
        for name in ('build', 'browser'):
            process = journal.get('resources', {}).get(name, {})
            pgid = process.get('pgid')
            if isinstance(pgid, int) and pgid > 0 and pgid not in (os.getpgrp(), os.getpid()):
                results[name] = {
                    'groupAbsent': terminate_group(pgid, grace=5),
                    'pidAbsent': process_absent(process.get('pid')),
                }
    expected_root = Path(expected_root)
    if os.path.lexists(expected_root):
        if expected_root.is_symlink() or not expected_root.is_dir():
            raise RuntimeError('refusing unexpected browser temp root cleanup')
        shutil.rmtree(expected_root)
    return {'processes': results, 'tempRootAbsent': not os.path.lexists(expected_root)}


def load_chromium_wrapper_journal(path, actual_executable):
    path = Path(path)
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise RuntimeError('private Chromium wrapper journal required')
    value = json.loads(path.read_text())
    if value.get('version') != 1 or value.get('actualExecutable') != str(Path(actual_executable).resolve()) \
            or not isinstance(value.get('pid'), int) or not isinstance(value.get('pgid'), int):
        raise RuntimeError('Chromium wrapper journal binding invalid')
    return value


def expected_grant(args, manifest, owner_handle, node_sha, chromium_sha, manifest_sha):
    package = Path(args.package_root).resolve()
    source = package if args.cohort == 'admin-browser-current-main' else package / 'source'
    handle = Path(args.owner_handle_file).resolve()
    plan = database_plan(args.container_nonce)
    return {
        'grantId': args.grant_id,
        'owner': '/root',
        'allowedLaunches': 1,
        'dockerHost': DOCKER_HOST,
        'containerNonce': args.container_nonce,
        'containerName': f'owasp-ai-goat-admin-auth-browser-{args.container_nonce}',
        'databasePlan': plan,
        **({'databaseRoles': database_roles()} if args.cohort == 'student-reset-only' else {}),
        'canonicalWorkspaceRoot': str(Path(args.canonical_workspace).resolve()),
        'candidateSourceRoot': str(source),
        'candidateManifestSha256': manifest_sha,
        'sourceFilesSha256': manifest['sourceFilesSha256'],
        'dependencyFilesSha256': manifest['dependencyFilesSha256'],
        'dependencySymlinksSha256': manifest['dependencySymlinksSha256'],
        'managedNodePath': str(Path(args.managed_node).resolve()),
        'managedNodeSha256': node_sha,
        **({'runningPythonPath': str(Path(sys.executable).resolve()),
            'runningPythonSha256': args.python_sha256}
           if args.cohort == 'admin-browser-current-main' else {}),
        'chromiumPath': str(Path(args.chromium).resolve()),
        'chromiumSha256': chromium_sha,
        'postgresImageRef': POSTGRES_IMAGE,
        'postgresImageId': POSTGRES_IMAGE_ID,
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
    for name in ('package-root', 'manifest', 'managed-node', 'chromium', 'docker-host',
                 'postgres-image-id', 'container-nonce', 'evidence-root', 'grant-file',
                 'grant-id', 'owner', 'owner-handle-file', 'canonical-workspace', 'scope'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--cohort', choices=('full', 'analytics-only', 'dpi-containment',
        'student-reset-only', 'admin-browser-current-main'), default='full')
    parser.add_argument('--main-workspace', action='store_true')
    parser.add_argument('--manifest-sha256')
    parser.add_argument('--browser-root')
    parser.add_argument('--python-sha256')
    parser.add_argument('--await-grant', action='store_true')
    parser.add_argument('--launcher-pid-file')
    return parser.parse_args(argv)


def current_profile_arguments(argv):
    values = list(sys.argv[1:] if argv is None else argv)
    selectors = [values[i + 1] for i, value in enumerate(values[:-1]) if value == '--cohort']
    selectors += [value.split('=', 1)[1] for value in values if value.startswith('--cohort=')]
    if len(selectors) > 1:
        raise RuntimeError('Duplicate cohort selector')
    if selectors == ['platform-auth-ctf0123']:
        # Validate every Python dependency byte before importing the current profile.
        if '--help' in values or '-h' in values:
            print('platform-auth-ctf0123: explicit manifest/runtime/Docker pins and empty evidence root required')
            return []
        def one(flag):
            matches = [values[i+1] for i,v in enumerate(values[:-1]) if v == flag]
            if len(matches) != 1: raise RuntimeError('Exactly one ' + flag + ' required')
            return matches[0]
        manifest = Path(one('--manifest'))
        if manifest.is_symlink() or manifest.resolve() != manifest or sha256(manifest) != one('--manifest-sha256'):
            raise RuntimeError('Current profile manifest pin mismatch')
        document = json.loads(manifest.read_text());source = Path(__file__).resolve().parents[2]
        if manifest != source.parent/'manifest.json':raise RuntimeError('Current profile package binding mismatch')
        for name, expected in document['files'].items():
            if name.endswith('.py'):
                path = source/name
                if not path.is_relative_to(source) or '..' in Path(name).parts or path.is_symlink() or path.resolve() != path or sha256(path) != expected:raise RuntimeError('Python closure pin mismatch')
        if 'tests/postgres/platform_auth_ctf_profile.py' not in document['files']:raise RuntimeError('Profile helper missing')
        return values
    return None

def main(argv=None):
    # New direct-source profile has independent closed admission. Historical
    # package/current-main cohorts retain their exact existing code paths.
    selected = list(sys.argv[1:] if argv is None else argv)
    if '--cohort' in selected and selected[selected.index('--cohort') + 1:
            selected.index('--cohort') + 2] in (
                ['admin-q05-current-host'], ['admin-student-reset-current-host']):
        from admin_q05_current_host import main as run_q05
        if run_q05(selected):
            raise RuntimeError('Current-host admin Q05 qualification failed')
        return
    current = current_profile_arguments(argv)
    if current is not None:
        if not current:return
        from platform_auth_ctf_profile import main as run_current
        if run_current(current):raise RuntimeError('Current auth/CTF qualification failed')
        return
    args = parse_args(argv)
    configure_cohort(args.cohort)
    package = resolve_without_symlinks(args.package_root, 'package')
    manifest_path = resolve_without_symlinks(args.manifest, 'manifest')
    node = resolve_without_symlinks(args.managed_node, 'managed Node')
    chromium = resolve_without_symlinks(args.chromium, 'Chromium')
    evidence_path = resolve_without_symlinks(args.evidence_root, 'evidence', must_exist=False)
    canonical = resolve_without_symlinks(args.canonical_workspace, 'canonical workspace')
    current_main = args.cohort == 'admin-browser-current-main'
    if current_main != bool(args.main_workspace):
        raise RuntimeError('current-main selector requires exact --main-workspace binding')
    if current_main:
        if package != canonical or canonical != Path(__file__).resolve().parents[2]:
            raise RuntimeError('admin browser current-main must use this canonical checkout')
        if not args.manifest_sha256 or not args.browser_root or not args.python_sha256 \
                or not args.await_grant or not args.launcher_pid_file:
            raise RuntimeError('current-main manifest, runtime and live grant handshake required')
        browser_root = resolve_without_symlinks(args.browser_root, 'browser root')
        source = canonical
    else:
        if args.manifest_sha256 or args.browser_root or args.python_sha256 \
                or args.await_grant or args.launcher_pid_file:
            raise RuntimeError('current-main arguments forbidden for immutable package cohorts')
        browser_root = None
        source = package / 'source'
    if args.owner != '/root' or args.scope != SCOPE or args.docker_host != DOCKER_HOST \
            or args.postgres_image_id != POSTGRES_IMAGE_ID \
            or not re.fullmatch(r'[0-9a-f]{12}', args.container_nonce):
        raise RuntimeError('root launcher binding invalid')
    if not canonical.is_dir() or canonical.is_symlink():
        raise RuntimeError('canonical workspace binding invalid')
    if current_main:
        from admin_browser_current_main_admission import (
            current_main_control_path,
            publish_launcher_pid,
            require_fresh_launch_authorization,
            validate as validate_current_main,
            validate_evidence_path as validate_current_main_evidence,
            wait_for_launch_authorization,
        )
        validate_current_main_evidence(source, evidence_path, args.container_nonce)
        current_main_control_path(source, manifest_path, 'manifest', 'json', args.container_nonce)
        manifest = validate_current_main(source, manifest_path, args.manifest_sha256,
            args.python_sha256, node, chromium, browser_root)
        require_fresh_launch_authorization(
            source, Path(args.grant_file), Path(args.owner_handle_file), args.container_nonce)
        pid_path = resolve_without_symlinks(
            args.launcher_pid_file, 'launcher PID receipt', must_exist=False)
        publish_launcher_pid(source, pid_path, args.container_nonce)
        print('WAITING_CURRENT_MAIN_GRANT', flush=True)
        wait_for_launch_authorization(
            source, Path(args.grant_file), Path(args.owner_handle_file), args.container_nonce)
    else:
        if evidence_path.is_relative_to(package):
            raise RuntimeError('immutable cohort evidence must remain outside package')
        manifest = verify_manifest(package, manifest_path)
    grant_path = resolve_without_symlinks(args.grant_file, 'grant')
    handle_path = resolve_without_symlinks(args.owner_handle_file, 'owner handle')
    if node.is_symlink() or not node.is_file() or chromium.is_symlink() or not chromium.is_file():
        raise RuntimeError('managed Node and Chromium regular files required')
    node_version = run([str(node), '--version'], capture_output=True, timeout=10)
    if node_version.returncode or node_version.stdout.strip() != NODE_VERSION:
        raise RuntimeError('managed Node version mismatch')
    node_sha, chromium_sha, manifest_sha = sha256(node), sha256(chromium), sha256(manifest_path)
    if args.cohort in ('analytics-only', 'dpi-containment', 'student-reset-only',
                       'admin-browser-current-main') and node_sha != ANALYTICS_NODE_SHA256:
        raise RuntimeError('selected cohort Node executable hash mismatch')
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
    expected = expected_grant(args, manifest, owner_handle, node_sha, chromium_sha, manifest_sha)
    if grant_path.is_symlink() or not grant_path.is_file() or grant_path.stat().st_mode & 0o077:
        raise RuntimeError('private grant file required')
    grant = json.loads(grant_path.read_text())
    if grant.get('status') != 'granted' or any(grant.get(key) != value for key, value in expected.items()):
        raise RuntimeError('exact one-use grant binding mismatch')
    lock = Path(str(grant_path) + '.consume-lock')
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError:
        raise RuntimeError('grant already consumed')
    try:
        grant = json.loads(grant_path.read_text())
        if grant.get('status') != 'granted' or any(grant.get(key) != value for key, value in expected.items()):
            raise RuntimeError('grant changed before consumption')
        grant.update(status='consumed', consumerPid=os.getpid(), launcherPid=os.getpid())
        save_json(grant_path, grant)
    finally:
        lock.rmdir()

    evidence_path.mkdir(mode=0o700)
    ownership_path = evidence_path / 'ownership.json'
    browser_journal = evidence_path / 'admin-browser-resources.json'
    browser_temp = evidence_path / 'admin-browser-runtime'
    chromium_wrapper = evidence_path / 'chromium-owned-wrapper.py'
    chromium_wrapper_journal = evidence_path / 'chromium-wrapper.json'
    container_name = expected['containerName']
    databases = expected['databasePlan']
    labels = {
        'owasp-ai-goat.owner': '/root',
        'owasp-ai-goat.grant': args.grant_id,
        'owasp-ai-goat.scope': SCOPE,
        'owasp-ai-goat.nonce': args.container_nonce,
        'owasp-ai-goat.manifest': manifest_sha,
        'owasp-ai-goat.image': POSTGRES_IMAGE_ID,
    }
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
        **({'runningPythonPath': str(Path(sys.executable).resolve()),
            'runningPythonSha256': args.python_sha256} if current_main else {}),
        'managedNodePath': str(node),
        'managedNodeSha256': node_sha,
        'chromiumPath': str(chromium),
        'chromiumSha256': chromium_sha,
        'postgresImageRef': POSTGRES_IMAGE,
        'postgresImageId': POSTGRES_IMAGE_ID,
        'dockerHost': DOCKER_HOST,
        'resourcePlan': {
            'containerName': container_name,
            'containerLabels': labels,
            'databaseNames': databases,
            'migrationRole': MIGRATION_ROLE,
            'runtimeRole': RUNTIME_ROLE,
            'browserResourceJournal': str(browser_journal),
            'browserTempRoot': str(browser_temp),
            'chromiumWrapper': str(chromium_wrapper),
            'chromiumWrapperJournal': str(chromium_wrapper_journal),
            'applicationLogs': str(evidence_path / 'application-logs'),
            'applicationData': str(evidence_path / 'application-data'),
        },
        'processes': {},
        'suites': {},
    }

    def persist():
        save_json(ownership_path, state)

    persist()
    docker = ['docker', '--host', DOCKER_HOST]
    container_id = None
    active_process = None
    active_pgid = None
    passed = False
    cleanup_errors = []
    interrupted = {'value': False}

    def handle_signal(signum, _frame):
        interrupted['value'] = True
        raise InterruptedError(f'received signal {signum}')

    previous_handlers = {signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)}
    for signum in previous_handlers:
        signal.signal(signum, handle_signal)

    def psql(sql, database='postgres', timeout=60):
        result = run(docker + ['exec', container_id, 'psql', '-U', 'owasp_ai_goat_bootstrap',
            '-d', database, '-v', 'ON_ERROR_STOP=1', '-c', sql], capture_output=True,
            timeout=timeout)
        if result.returncode:
            raise RuntimeError('owned PostgreSQL command failed: ' + (result.stderr or '')[-1000:])
        return result.stdout

    try:
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
        persist()

        image = run(docker + ['image', 'inspect', '--format', '{{.Id}}', POSTGRES_IMAGE],
            capture_output=True, timeout=20)
        if image.returncode or image.stdout.strip() != POSTGRES_IMAGE_ID:
            raise RuntimeError('PostgreSQL image identity mismatch')
        if not docker_object_absent(docker, container_name):
            raise RuntimeError('owned container name already exists')
        state['containerCreateAttempt'] = {'status': 'started', 'startedAt': utc_now(),
            'name': container_name, 'expectedLabels': labels}
        persist()
        created = run(docker + ['run', '--detach', '--pull', 'never', '--name', container_name,
            *sum((['--label', f'{key}={value}'] for key, value in labels.items()), []),
            *cohort_resource_args(args.cohort),
            '--tmpfs', '/var/lib/postgresql:rw,size=536870912',
            '-e', 'POSTGRES_USER=owasp_ai_goat_bootstrap', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
            '-p', '127.0.0.1::5432', POSTGRES_IMAGE,
            '-c', 'shared_buffers=24MB', '-c', 'max_connections=64'],
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
            ready = run(docker + ['exec', container_id, 'pg_isready', '-U', 'owasp_ai_goat_bootstrap'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            if ready.returncode == 0:
                break
            time.sleep(.25)
        else:
            raise RuntimeError('owned PostgreSQL readiness timeout')
        binding = run(docker + ['port', container_id, '5432/tcp'], capture_output=True,
            timeout=20)
        if binding.returncode or not re.fullmatch(r'127\.0\.0\.1:\d+\s*', binding.stdout):
            raise RuntimeError('loopback PostgreSQL binding required')
        postgres_port = int(binding.stdout.strip().rsplit(':', 1)[1])
        state['postgresLoopbackPort'] = postgres_port
        state['databaseProvisioningAttempt'] = {'status': 'started', 'startedAt': utc_now(),
            'databaseNames': databases, 'roles': [MIGRATION_ROLE, RUNTIME_ROLE]}
        persist()
        roles_by_store = database_roles()
        roles = sorted({role for pair in roles_by_store.values() for role in pair.values()})
        state['databaseProvisioningAttempt']['roles'] = roles
        state['databaseProvisioningAttempt']['databaseRoles'] = roles_by_store
        persist()
        for role in roles:
            psql(f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
        for store_name, database in databases.items():
            migration_role = roles_by_store[store_name]['migrationRole']
            runtime_role = roles_by_store[store_name]['runtimeRole']
            psql(f'CREATE DATABASE {database} OWNER {migration_role}')
            psql(f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; '
                 f'GRANT CONNECT ON DATABASE {database} TO {migration_role},{runtime_role}')
        state['databaseProvisioningAttempt']['status'] = 'complete'
        persist()

        home = evidence_path / 'home'
        temporary = evidence_path / 'tmp'
        application_logs = evidence_path / 'application-logs'
        application_data = evidence_path / 'application-data'
        for directory in (home, temporary, application_logs, application_data):
            directory.mkdir(mode=0o700)
        base_env = {key: os.environ[key] for key in ('PATH',) if key in os.environ}
        base_env.update(HOME=str(home), TMPDIR=str(temporary), TMP=str(temporary), TEMP=str(temporary),
            NODE_ENV='test', PG_TEST_DISPOSABLE='yes', AWS_EC2_METADATA_DISABLED='true',
            OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(source), LOGS_DIR=str(application_logs),
            OWASP_AI_GOAT_APP_DATA_ROOT=str(application_data))

        for suite in SUITES:
            database = databases[suite['name']]
            env = suite_environment(base_env, suite, databases, postgres_port)
            if suite['name'] == 'adminProductionAuthBrowser':
                env[BROWSER_RESOURCE_ENV] = str(browser_journal)
                env[BROWSER_TEMP_ENV] = str(browser_temp)
                env['PUPPETEER_EXECUTABLE_PATH'] = str(chromium_wrapper)
                env[CHROMIUM_ACTUAL_ENV] = str(chromium)
                env[CHROMIUM_WRAPPER_JOURNAL_ENV] = str(chromium_wrapper_journal)
                if any(os.path.lexists(path) for path in (
                        browser_journal, browser_temp, chromium_wrapper, chromium_wrapper_journal)):
                    raise RuntimeError('fresh browser resource paths required')
                state['browserWrapperCreateAttempt'] = {'status': 'started',
                    'path': str(chromium_wrapper), 'journal': str(chromium_wrapper_journal)}
                persist()
                with chromium_wrapper.open('x') as output:
                    output.write(CHROMIUM_WRAPPER_SOURCE)
                    output.flush()
                    os.fsync(output.fileno())
                os.chmod(chromium_wrapper, 0o500)
                state['browserWrapperCreateAttempt'].update(status='complete',
                    sha256=sha256(chromium_wrapper))
                persist()
            log_path = evidence_path / f'{suite["name"]}.tap'
            state['suites'][suite['name']] = {'status': 'starting', 'test': suite['test'],
                'database': database, 'log': str(log_path), 'startedAt': utc_now()}
            persist()
            with log_path.open('w') as output:
                os.chmod(log_path, 0o600)
                active_process = subprocess.Popen([str(node), '--test', '--test-concurrency=1',
                    '--test-reporter=tap', suite['test']], cwd=source, env=env,
                    stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
                active_pgid = os.getpgid(active_process.pid)
                state['processes'][suite['name']] = {'pid': active_process.pid,
                    'pgid': active_pgid, 'status': 'running', 'startedAt': utc_now()}
                state['suites'][suite['name']]['status'] = 'running'
                persist()
                try:
                    exit_code = active_process.wait(timeout=suite['timeoutSeconds'])
                except subprocess.TimeoutExpired:
                    terminate_group(active_pgid, active_process, grace=8)
                    raise RuntimeError(f'{suite["name"]} timed out')
            group_absent = terminate_group(active_pgid, active_process, grace=3)
            state['processes'][suite['name']].update(status='exited', exitCode=exit_code,
                groupAbsent=group_absent, completedAt=utc_now())
            active_process = None
            active_pgid = None
            if exit_code or not group_absent:
                persist()
                raise RuntimeError(f'{suite["name"]} failed or left its process group')
            log_sha = verify_tap(log_path)
            if suite['name'] == 'adminProductionAuthBrowser':
                browser_resources = load_browser_resource_journal(
                    browser_journal, browser_temp, require_terminal=True)
                wrapper_resources = load_chromium_wrapper_journal(chromium_wrapper_journal, chromium)
                if not wrapper_resources:
                    raise RuntimeError('Chromium wrapper did not record a launch')
                recorded_browser = browser_resources['resources'].get('browser', {})
                if recorded_browser.get('pid') != wrapper_resources['pid'] \
                        or wrapper_resources['pgid'] != wrapper_resources['pid'] \
                        or not process_absent(wrapper_resources['pid']) \
                        or not process_group_absent(wrapper_resources['pgid']):
                    raise RuntimeError('browser launch/cleanup journals disagree')
                if os.path.lexists(browser_temp):
                    raise RuntimeError('browser temp/profile root remains after successful test')
            os.chmod(log_path, 0o400)
            state['suites'][suite['name']].update(status='passed', logSha256=log_sha,
                completedAt=utc_now())
            persist()
        state['runStatus'] = 'cohort_passed'
        persist()
        passed = True
    except BaseException as error:
        state.update(runStatus='cohort_failed', failure=f'{type(error).__name__}: {error}'[:1000])
        persist()
        raise
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        if active_pgid:
            try:
                absent = terminate_group(active_pgid, active_process, grace=8)
                state['processes'].setdefault('active', {}).update(groupAbsent=absent,
                    exitCode=active_process.poll() if active_process else None)
            except Exception as error:
                cleanup_errors.append(f'active process cleanup: {error}'[:500])
        try:
            wrapper_resource = load_chromium_wrapper_journal(chromium_wrapper_journal, chromium)
            if wrapper_resource:
                wrapper_group_absent = terminate_group(wrapper_resource['pgid'], grace=8)
                state['chromiumWrapperCleanup'] = {
                    'pid': wrapper_resource['pid'], 'pgid': wrapper_resource['pgid'],
                    'pidAbsent': process_absent(wrapper_resource['pid']),
                    'groupAbsent': wrapper_group_absent,
                }
                if not state['chromiumWrapperCleanup']['pidAbsent'] or not wrapper_group_absent:
                    raise RuntimeError('wrapper-recorded Chromium process remains')
            else:
                state['chromiumWrapperCleanup'] = {'notLaunched': True}
        except Exception as error:
            cleanup_errors.append(f'Chromium wrapper cleanup: {error}'[:500])
        try:
            state['browserCleanup'] = terminate_browser_journal_resources(browser_journal, browser_temp)
        except Exception as error:
            cleanup_errors.append(f'browser resource cleanup: {error}'[:500])
        if container_id or state.get('containerCreateAttempt'):
            try:
                state['databaseCleanupAttempt'] = {'status': 'started', 'startedAt': utc_now(),
                    'databaseNames': databases}
                persist()
                if container_id:
                    results = {}
                    for database in databases.values():
                        command = run(docker + ['exec', container_id, 'psql', '-U', 'owasp_ai_goat_bootstrap',
                            '-d', 'postgres', '-v', 'ON_ERROR_STOP=1', '-c',
                            f'DROP DATABASE IF EXISTS {database} WITH (FORCE)'], capture_output=True,
                            timeout=60)
                        results[database] = command.returncode
                    remaining = run(docker + ['exec', container_id, 'psql', '-U', 'owasp_ai_goat_bootstrap',
                        '-d', 'postgres', '-At', '-c',
                        "SELECT datname FROM pg_database WHERE datname LIKE 'owasp_ai_goat_test_%' ORDER BY datname"],
                        capture_output=True, timeout=30)
                    state['databaseCleanupAttempt'].update(status='complete', returnCodes=results,
                        absenceQueryReturnCode=remaining.returncode,
                        databasesAbsent=remaining.returncode == 0 and not remaining.stdout.strip())
                    if any(results.values()) or remaining.returncode or remaining.stdout.strip():
                        raise RuntimeError('owned database cleanup was not proven')
            except Exception as error:
                cleanup_errors.append(f'database cleanup: {error}'[:500])
        try:
            removed_id = remove_owned_container(docker, container_name, container_id, labels)
            state['containerCleanupId'] = removed_id
            if container_id is None and removed_id is not None:
                container_id = removed_id
        except Exception as error:
            cleanup_errors.append(f'container cleanup: {error}'[:500])
        try:
            state['containerNameAbsent'] = docker_object_absent(docker, container_name)
        except Exception as error:
            state['containerNameAbsent'] = False
            cleanup_errors.append(f'container name absence: {error}'[:500])
        if container_id:
            try:
                state['containerIdAbsent'] = docker_object_absent(docker, container_id)
            except Exception as error:
                state['containerIdAbsent'] = False
                cleanup_errors.append(f'container id absence: {error}'[:500])
        else:
            state['containerIdAbsent'] = None
        state['databasesAbsent'] = state.get('containerNameAbsent') is True \
            and state.get('containerIdAbsent') in (True, None)
        try:
            if current_main:
                from admin_browser_current_main_admission import verify_postflight
                verify_postflight(source, manifest_path, args.manifest_sha256,
                    args.python_sha256, manifest, node, chromium, browser_root)
            else:
                verify_postflight_identity(package, manifest_path, manifest, manifest_sha,
                    node, node_sha, chromium, chromium_sha)
            state['postflightManifestVerified'] = True
        except Exception as error:
            state['postflightManifestVerified'] = False
            cleanup_errors.append(f'postflight manifest: {error}'[:500])
        for process in state['processes'].values():
            if isinstance(process.get('pgid'), int):
                process['groupAbsent'] = process_group_absent(process['pgid'])
            if isinstance(process.get('pid'), int):
                process['pidAbsent'] = process_absent(process['pid'])
        state['allProcessGroupsAbsent'] = all(row.get('groupAbsent') is True
            for row in state['processes'].values())
        state['allProcessIdsAbsent'] = all(row.get('pidAbsent') is True
            for row in state['processes'].values())
        state['cleanupErrors'] = cleanup_errors
        state['applicationLogFiles'] = {
            path.relative_to(evidence_path / 'application-logs').as_posix(): sha256(path)
            for path in (evidence_path / 'application-logs').rglob('*')
            if path.is_file() and not path.is_symlink()
        } if (evidence_path / 'application-logs').is_dir() else {}
        state['completedAt'] = utc_now()
        clean = not cleanup_errors and state.get('containerNameAbsent') is True \
            and state.get('containerIdAbsent') in (True, None) \
            and state.get('databasesAbsent') is True \
            and state.get('allProcessGroupsAbsent') is True \
            and state.get('allProcessIdsAbsent') is True \
            and state.get('postflightManifestVerified') is True \
            and state.get('browserCleanup', {}).get('tempRootAbsent') is True
        state['runStatus'] = 'terminal_pass_cleaned' if passed and clean \
            else 'terminal_fail_cleaned' if clean else 'terminal_fail_cleanup_uncertain'
        persist()
        if not passed or not clean:
            raise RuntimeError('admin/auth/browser cohort did not pass with verified cleanup')
    print(json.dumps({'status': state['runStatus'], 'evidence': str(evidence_path),
        'suiteLogs': {name: row.get('logSha256') for name, row in state['suites'].items()}},
        sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'launcher failure: {error}', file=sys.stderr)
        raise SystemExit(1)
