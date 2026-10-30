"""Closed, model-free, direct-source administrator browser qualification.

No resources are allocated on import or --plan. The outside coordinator grants
only read-only profile absence inspection; live libproc ancestry/birth records,
never a fixture journal, authorize individual process signals.
"""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid

from admin_browser_current_main_admission import inventory
from darwin_process_inventory import LibProc
from secureshop_current_host_admission import validate_current_host, evidence_parent
from trusted_process_inspector import consume_environment

COHORT = 'admin-q05-current-host'
RESET_COHORT = 'admin-student-reset-current-host'
COHORTS = (COHORT, RESET_COHORT)
TITLE = 'production admin UI uses durable PostgreSQL auth and responds to delegated permission changes'
FIXTURE = 'tests/postgres/adminProductionAuthBrowser.integration.test.js'
BUILD_VERIFIER_SHA256 = 'e81f56febe99afd6424c30f1b121d4da0e11df547c9949d33f57d99222355832'
RENDERED_PINS = {
    FIXTURE: '4fabf1b7f3509cfeb2f352f44f6a474dde8ef0dfee63de4091e1f65670df3263',
    'tests/postgres/adminQ05RenderedScenario.js': '215b987ff1410d6987861c762a9f8dfa359f1c9260e969967648e3bddd4cf629',
    'tests/postgres/adminQ05RenderedScenario.test.js': '1447345ab526424ce0bb61ccad6e03f6c89af7a40eccd29b2d59585bd1ea1ff2',
}
# Separate reviewed scenario; the old accept-only scenario is not proof of
# Cancel/staged-authority behavior. Shared transport pins apply to both cohorts.
RESET_RENDERED_PINS = {
    **RENDERED_PINS,
    'tests/postgres/adminStudentResetRecoverySupport.js': '6f960e792812f619c907eba5bbc38295bf4f65b00fd1458f63382a333089770b',
    'tests/postgres/adminStudentResetRecoveryBrowser.js': '98fcd5ce4c951503e171ac80c8bc4203d3eb82047fedb96e46df7ef5915b2f4a',
    'tests/adminStudentResetRecoveryBrowserContract.test.js': '350fcd5a45c2757330809b8c7313a5900719db25513ddaac642d258da087207e',
}
LIMITS = dict(seconds=480, cleanupSeconds=90, logBytes=16 * 1024 * 1024,
              memoryBytes=1024 ** 3, postgresTmpfsBytes=512 * 1024 ** 2, pids=128,
              actualModelCalls=0)
CONTROL_FILES = (
    'tasks/run-in-repository.sh', 'tasks/repository-only.sb',
    'tests/release-inputs/record-current-frontend-build.py',
    'tests/postgres/run-ctf-stages-route-isolated.py',
    'tests/postgres/run-admin-auth-browser-cohort-isolated.py',
    'tests/postgres/run_admin_q05_with_inspector.py',
    'tests/postgres/admin_q05_current_host.py',
    'tests/postgres/trusted_process_inspector.py',
    'tests/postgres/darwin_process_inventory.py',
    'tests/postgres/secureshop_current_host_admission.py',
    'tests/postgres/admin_browser_current_main_admission.py',
)
ACTION_FACTS = {
    'studentCreate': ('cancelNoRequest', 'oneConfirmedRequest', 'persisted', 'targetId'),
    'studentEdit': ('cancelNoRequest', 'staleAuthorityNoRequest', 'oneConfirmedRequest', 'persisted', 'targetId'),
    'studentPassword': ('cancelNoRequest', 'crossTabAbaNoRequest', 'storageEventsObserved',
                        'secretsRetired', 'oneConfirmedRequest', 'credentialRotated',
                        'sessionsRevoked', 'lostAckEffectPersisted', 'unknownUiNoRetry',
                        'responseStageBrowserFailure', 'targetId'),
    'administratorCreate': ('cancelNoRequest', 'oneConfirmedRequest', 'persisted', 'permissionPersisted', 'targetId'),
    'administratorEdit': ('cancelNoRequest', 'oneConfirmedRequest', 'persisted',
                          'lostAckEffectPersisted', 'unknownUiNoRetry', 'targetId'),
    'administratorDeactivation': ('cancelNoRequest', 'crossTabAbaNoRequest',
                                 'storageEventsObserved', 'oneConfirmedRequest',
                                 'inactive', 'sessionsRevoked', 'actorPreserved',
                                 'siblingsPreserved', 'lostAckEffectPersisted',
                                 'unknownUiNoRetry', 'responseStageBrowserFailure',
                                 'targetId'),
    'accountLock': ('cancelNoRequest', 'crossTabAbaNoRequest', 'storageEventsObserved',
                    'oneConfirmedRequest', 'sessionsRevoked', 'loginDenied', 'targetId'),
    'accountUnlock': ('cancelNoRequest', 'lostAckEffectPersisted', 'unknownUiNoRetry',
                      'failedAttemptsCleared', 'revokedSessionStayedRevoked', 'freshLogin', 'targetId'),
    'globalVisibilityDisable': ('cancelNoRequest', 'oneConfirmedRequest', 'activeRowsHidden', 'otherGatesPreserved'),
    'globalVisibilityEnable': ('cancelNoRequest', 'oneConfirmedRequest', 'legitimateReadiness409', 'noEffect'),
    'selfPassword': ('cancelNoRequest', 'oneConfirmedRequest', 'credentialRotated', 'priorSessionRevoked', 'freshLogin'),
}
RESET_FACTS = (
    'cancelNoRequest', 'cancelStateUnchanged', 'stagedAuthorityDenied',
    'stagedAuthorityNoEffect', 'completionSeeded', 'completionCleared',
    'timeCleared', 'toolActivityCleared', 'durableStepsCompleted',
    'cleanupReceiptsCompleted', 'lostAckEffectPersisted',
    'unknownUiNoAutomaticRetry', 'remountNoRequest',
    'sameIdReplayPreservedResumedState', 'originalReceiptsUnchanged',
    'newExplicitOperation', 'siblingPreserved',
)
RESET_EXCLUSIONS = [
    'bulk-reset', 'other-workshop-reset', 'student-deletion',
    'nonempty-backup-traversal-cleanup', 'inflight-model-cancellation',
    'model-grading', 'full-Q05-denominator',
]


def selected_pins(cohort):
    if cohort == COHORT:
        return RENDERED_PINS
    if cohort == RESET_COHORT:
        if not RESET_RENDERED_PINS:
            raise RuntimeError('Reset rendered scenario is not yet reviewed/pinned')
        return RESET_RENDERED_PINS
    raise RuntimeError('Unknown current-host administrator cohort')


def database_plan(cohort, nonce):
    """Closed database/role identities; no caller-controlled SQL identifiers."""
    if cohort not in COHORTS or not re.fullmatch('[a-f0-9]{12}', nonce):
        raise RuntimeError('Exact cohort and database nonce required')
    result = dict(identity=dict(database='owasp_ai_goat_test_admin_browser_' + nonce,
        runtime='dvaia_identity_runtime', migration='dvaia_identity_migration'))
    if cohort == RESET_COHORT:
        result['finflow'] = dict(database='owasp_ai_goat_test_student_reset_finflow_' + nonce,
            runtime='dvaia_finflow_runtime', migration='dvaia_finflow_migration')
    return result


def database_statements(cohort, nonce):
    for row in database_plan(cohort, nonce).values():
        yield ''.join(f'CREATE ROLE {row[role]} LOGIN NOSUPERUSER NOCREATEDB '
                      'NOCREATEROLE NOREPLICATION NOBYPASSRLS;'
                      for role in ('migration', 'runtime'))
        yield f"CREATE DATABASE {row['database']} OWNER {row['migration']};"
        yield (f"REVOKE ALL ON DATABASE {row['database']} FROM PUBLIC; "
               f"GRANT CONNECT ON DATABASE {row['database']} TO "
               f"{row['migration']},{row['runtime']};")


def validate_database_environment(env, cohort, nonce, port):
    if type(port) is not int or not 1 <= port <= 65535:
        raise RuntimeError('Exact owned database/port required')
    stores = database_plan(cohort, nonce)
    variables = {'identity': {'runtime': 'PG_ADMIN_BROWSER_TEST_RUNTIME_URL',
                             'migration': 'PG_ADMIN_BROWSER_TEST_MIGRATION_URL'},
                 'finflow': {'runtime': 'FINFLOW_WORKSHOP_DATABASE_URL',
                             'migration': 'FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL'}}
    for store, names in variables.items():
        for role, variable in names.items():
            if store not in stores:
                if variable in env:
                    raise RuntimeError('Unexpected store outside selected cohort')
                continue
            row = stores[store]
            expected = f"postgresql://{row[role]}@127.0.0.1:{port}/{row['database']}"
            if env.get(variable) != expected:
                raise RuntimeError('Exact owned store URL required: ' + variable)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def encoded(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False).encode()).hexdigest()


def ordered_digest(value):
    return hashlib.sha256(json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def files(root):
    root = Path(root)
    if not root.is_dir() or root.is_symlink() or root.resolve() != root:
        raise RuntimeError('Canonical source/build directory required')
    result = {}
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in sorted(dirs + names):
            path = Path(directory) / name
            if path.is_symlink():
                raise RuntimeError('Source/build links forbidden')
            if path.is_dir():
                continue
            if not path.is_file():
                raise RuntimeError('Source/build special files forbidden')
            if path.suffix not in ('.pyc', '.pyo') and name != '.DS_Store':
                result[path.relative_to(root).as_posix()] = sha(path)
    return dict(sorted(result.items()))


def source_files(repo):
    result = {}
    for name in ('server', 'db', 'tests', 'scripts', 'client/src', 'client/public'):
        root = repo / name
        if not root.exists():
            continue
        # Logs are runtime, never source. Avoid traversing them at all.
        for directory, dirs, names in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in ('node_modules', '__pycache__')
                             and Path(directory, d) != repo / 'server/logs')
            if any(Path(directory, d).is_symlink() for d in dirs):
                raise RuntimeError('Source directory link forbidden')
            for item in sorted(names):
                path = Path(directory) / item
                if path.suffix in ('.pyc', '.pyo') or item == '.DS_Store':
                    continue
                if path.is_symlink() or not path.is_file():
                    raise RuntimeError('Source file must be regular')
                result[path.relative_to(repo).as_posix()] = sha(path)
    for name in (*CONTROL_FILES, 'package.json', 'package-lock.json',
                 'client/package.json', 'client/package-lock.json',
                 'client/index.html', 'client/vite.config.mjs'):
        path = repo / name
        if path.is_symlink() or not path.is_file():
            raise RuntimeError('Required control/source file unavailable')
        result[name] = sha(path)
    return dict(sorted(result.items()))


def build_inputs(repo):
    """Revalidate the input inventory recorded by root's real in-place build."""
    root = repo / 'client'
    result = {}
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if name not in ('build', 'node_modules')]
        if any(Path(directory, name).is_symlink() for name in dirs):
            raise RuntimeError('Client build input directory link forbidden')
        for name in names:
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                raise RuntimeError('Client build input must be regular')
            result[path.relative_to(root).as_posix()] = sha(path)
    result = dict(sorted(result.items()))
    for name in ('package.json', 'package-lock.json', '.env', '.env.local',
                 '.env.production', '.env.production.local'):
        path = repo / name
        if path.exists():
            if path.is_symlink() or not path.is_file():
                raise RuntimeError('Root build input must be regular')
            result['../' + name] = sha(path)
    return result


def validate_modern_build_receipt(repo, args):
    repo = Path(repo)
    verifier = repo / 'tests/postgres/run-ctf-stages-route-isolated.py'
    for directory in (repo, repo / 'tests', repo / 'tests/postgres'):
        if directory.is_symlink() or directory.resolve() != directory \
                or not directory.is_dir():
            raise RuntimeError('Q05 reviewed build verifier ancestors must be canonical directories')
    if verifier.is_symlink() or verifier.resolve() != verifier \
            or not verifier.is_file() or not stat.S_ISREG(verifier.stat().st_mode) \
            or sha(verifier) != BUILD_VERIFIER_SHA256:
        raise RuntimeError('Q05 reviewed build verifier source pin mismatch')
    report_path = Path(args.build_report)
    for name in ('build_report_sha256', 'build_input_sha256',
                 'build_output_sha256', 'build_recorder_sha256'):
        if not re.fullmatch('[a-f0-9]{64}', getattr(args, name, '')):
            raise RuntimeError('Exact qualified frontend build provenance pins required')
    spec = importlib.util.spec_from_file_location('q05_reviewed_frontend_build_verifier', verifier)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    report = module.validate_frontend_build_report(repo, report_path,
        args.build_report_sha256, args.build_input_sha256,
        args.build_output_sha256, args.build_recorder_sha256,
        private_external=False, require_installed_match=True)
    if type(report.get('exitCode')) is not int or report['exitCode'] != 0 \
            or report.get('inputMode') != 'legacy' \
            or report.get('repositoryOnly') is not True \
            or report.get('qualified') is not True:
        raise RuntimeError('Q05 requires a successful repository-only frontend build')
    return {'reportPath': str(report_path), 'reportSha256': args.build_report_sha256,
            'inputSha256': args.build_input_sha256,
            'outputSha256': args.build_output_sha256,
            'recorderSha256': args.build_recorder_sha256}


def physical_python_path(executable, argv0):
    """Homebrew's macOS framework launcher re-execs this exact sibling app."""
    executable = Path(executable).resolve()
    physical = Path(argv0)
    permitted = {executable}
    version = executable.parent.parent
    if executable.parent.name == 'bin' and version.parent.name == 'Versions' \
            and version.parent.parent.name == 'Python.framework':
        permitted.add(version / 'Resources/Python.app/Contents/MacOS/Python')
    if physical not in permitted or physical.is_symlink() or physical.resolve() != physical \
            or not physical.is_file():
        raise RuntimeError('Exact pinned Python physical interpreter required')
    return physical


def physical_python(api=None):
    api = api or LibProc()
    arguments_seen = api.arguments(os.getpid())
    if not arguments_seen:
        raise RuntimeError('Physical Python invocation unavailable')
    return physical_python_path(sys.executable, arguments_seen[0])


def snapshot(repo, args):
    browser = Path(args.chromium)
    browser_root = Path(args.browser_root)
    python = Path(sys.executable).resolve()
    physical = physical_python()
    if any(sha(repo / name) != expected for name, expected in selected_pins(args.cohort).items()):
        raise RuntimeError('Reviewed rendered fixture/contract pin mismatch')
    if browser.is_symlink() or browser.resolve() != browser or not browser.is_file() \
            or not browser.is_relative_to(browser_root) \
            or sha(browser) != args.chromium_sha256 or sha(python) != args.python_sha256:
        raise RuntimeError('Exact Chromium/Python pins required')
    build = files(repo / 'client/build')
    if 'index.html' not in build or encoded(build) != args.build_sha256:
        raise RuntimeError('Existing production build pin mismatch')
    build_provenance = validate_modern_build_receipt(repo, args)
    executables = {}
    for name in ('node', 'docker'):
        path = Path(getattr(args, name))
        expected = getattr(args, name + '_sha256')
        if path.is_symlink() or path.resolve() != path or not path.is_file() \
                or not path.is_relative_to(repo) or sha(path) != expected:
            raise RuntimeError('Exact repository-contained runtime pins required')
        executables[name] = {'path': str(path), 'sha256': expected}
    return dict(source=source_files(repo), build=build, buildProvenance=build_provenance,
                dependencies={'root': inventory(repo / 'node_modules'),
                              'client': inventory(repo / 'client/node_modules')},
                browser=inventory(browser_root),
                python={'path': str(python), 'sha256': sha(python),
                        'physicalPath': str(physical), 'physicalSha256': sha(physical)},
                runtimes=executables,
                executionPins=dict(profile=args.current_host_profile, dockerHost=args.docker_host,
                                   daemonId=args.daemon_id, imageId=args.image_id,
                                   chromium=str(browser), chromiumSha256=args.chromium_sha256),
                limits=LIMITS, cohort=args.cohort)


def arguments(argv):
    flags = [item.split('=', 1)[0] for item in argv if item.startswith('--')]
    if len(flags) != len(set(flags)):
        raise RuntimeError('Duplicate options forbidden')
    parser = argparse.ArgumentParser()
    parser.add_argument('--cohort', choices=COHORTS, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--plan', action='store_true')
    mode.add_argument('--run', action='store_true')
    for name in ('node', 'node-sha256', 'docker', 'docker-sha256', 'docker-host',
                 'daemon-id', 'image-id', 'current-host-profile', 'chromium',
                 'chromium-sha256', 'browser-root', 'python-sha256', 'build-sha256',
                 'build-report', 'build-report-sha256', 'build-input-sha256',
                 'build-output-sha256', 'build-recorder-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--snapshot-sha256')
    args = parser.parse_args(argv)
    if args.run and not re.fullmatch('[a-f0-9]{64}', args.snapshot_sha256 or ''):
        raise RuntimeError('Explicit plan snapshot digest required')
    return args


def private_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.tmp')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def read_private(path, maximum=1024 * 1024):
    path = Path(path)
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() \
            or info.st_nlink != 1 or info.st_mode & 0o077 or not 0 < info.st_size <= maximum:
        raise RuntimeError('Bounded private journal required')
    return json.loads(path.read_text())


def retain_fixture_journal(state, runtime):
    """Preserve original partial facts before cleanup, without validating a pass."""
    path = runtime / 'tmp/admin-browser-resources.json'
    try:
        value = read_private(path)
        if not isinstance(value, dict):
            raise RuntimeError('Fixture journal object required')
        state['fixture'] = value
        state['fixtureCapture'] = dict(status='saved', sha256=sha(path),
                                       bytes=path.stat().st_size)
    except BaseException as error:
        state['fixtureCapture'] = dict(status='unavailable',
            error={'type': type(error).__name__, 'message': str(error)})
        # A successful run must never lose its required original journal.
        if state.get('status') == 'passed':
            state['status'] = 'failed'


def identity(row, getsid=os.getsid):
    if row is None or row.uid != os.getuid() or row.ruid != os.getuid():
        raise RuntimeError('Live same-user process identity required')
    return dict(pid=row.pid, pgid=row.pgid, sessionId=getsid(row.pid), uid=row.uid,
                startSec=row.start_sec, startUsec=row.start_usec)


class Owned:
    """Signal only identities observed as our direct child/descendants."""
    def __init__(self, api=None, getsid=os.getsid, kill=os.kill):
        self.api = api or LibProc()
        self.getsid, self.kill = getsid, kill
        self.records = {}
        self.roots = set()

    def current(self, pid):
        row = self.api.identity(pid)
        return None if row is None else identity(row, self.getsid)

    def register_child(self, pid):
        row = self.api.identity(pid)
        if row is None or row.ppid != os.getpid():
            raise RuntimeError('Direct child ownership missing')
        value = identity(row, self.getsid)
        if value['pgid'] != pid or value['sessionId'] != pid:
            raise RuntimeError('Owned child session required')
        self.records[pid] = value
        self.roots.add(pid)
        return value

    def register_browser(self, pid, child_pid, profile, executable):
        if child_pid not in self.roots or self.current(child_pid) != self.records[child_pid]:
            raise RuntimeError('Browser parent changed')
        row = self.api.identity(pid)
        if row is None or row.ppid != child_pid:
            raise RuntimeError('Browser must be a live direct child of owned fixture')
        value = identity(row, self.getsid)
        argv = self.api.arguments(pid)
        if not argv or argv[0] != str(executable) \
                or '--user-data-dir=' + str(profile) not in argv \
                or '--no-sandbox' not in argv:
            raise RuntimeError('Browser executable/profile arguments mismatch')
        if value != self.current(pid):
            raise RuntimeError('Browser identity changed during observation')
        self.records[pid] = value
        self.roots.add(pid)
        return dict(version=1, **value, profile=str(profile), executable=str(executable))

    def observe(self):
        # Iterate to capture descendants while their parent remains proved.
        for _ in range(8):
            added = False
            for pid in self.api.all_pids():
                if pid in self.records:
                    continue
                short = self.api.short_identity(pid)
                if short is None or short.ppid not in self.records:
                    continue
                if self.current(short.ppid) != self.records[short.ppid]:
                    raise RuntimeError('Owned ancestor reused')
                row = self.api.identity(pid)
                if row is None:
                    continue
                if row.ppid != short.ppid:
                    continue
                value = identity(row, self.getsid)
                if value != self.current(pid):
                    raise RuntimeError('Descendant identity changed')
                self.records[pid] = value
                added = True
            if not added:
                return
        raise RuntimeError('Process ancestry exceeds bound')

    def signal(self, pid, number):
        current = self.current(pid)
        if current is None:
            return
        if pid not in self.records or current != self.records[pid]:
            raise RuntimeError('Signal denied: process birth/ownership changed')
        self.kill(pid, number)

    def stop(self, deadline, child=None, exclude=()):
        self.observe()
        targets = [pid for pid in self.records if pid not in exclude]
        for number, grace in ((signal.SIGTERM, 5), (signal.SIGKILL, 3)):
            # Descendants before parents; never signal a PGID from a journal.
            for pid in reversed(targets):
                self.signal(pid, number)
            until = min(deadline, time.monotonic() + grace)
            while time.monotonic() < until:
                if child is not None:
                    child.poll()  # Reap our child before absence checks.
                if all(self.api.identity(pid) is None for pid in targets):
                    return True
                time.sleep(.05)
        if any(self.api.identity(pid) is not None for pid in targets):
            raise RuntimeError('Owned process absence unverified')
        return True


def environment(repo, runtime, port, database, args):
    # The supplied identity name is itself an exact nonce source, never an
    # arbitrary connection string or SQL identifier. Both stores share this
    # nonce and the single owned container's loopback port.
    match = re.fullmatch('owasp_ai_goat_test_admin_browser_([a-f0-9]{12})', database)
    if not match or type(port) is not int or not 1 <= port <= 65535:
        raise RuntimeError('Exact owned database/port required')
    stores = database_plan(args.cohort, match[1])
    tmp = runtime / 'tmp'
    env = dict(PATH=str(Path(args.node).parent) + ':/usr/bin:/bin',
               HOME=str(runtime / 'home'), TMPDIR=str(tmp), TMP=str(tmp), TEMP=str(tmp),
               XDG_CACHE_HOME=str(runtime / 'cache'), MAC_CHROMIUM_TMPDIR=str(tmp),
               NODE_ENV='test', PG_TEST_DISPOSABLE='yes', RUN_ADMIN_PRODUCTION_BROWSER='1',
               ADMIN_Q05_CURRENT_HOST='1', ADMIN_Q05_BUILD_DIRECTORY=str(repo / 'client/build'),
               ADMIN_Q05_BUILD_SHA256=args.build_sha256,
               ADMIN_Q05_SNAPSHOT_SHA256=args.snapshot_sha256,
               ADMIN_Q05_BROWSER_ACK=str(runtime / 'browser-ack.json'),
               PG_ADMIN_BROWSER_RESOURCE_JOURNAL=str(tmp / 'admin-browser-resources.json'),
               PG_ADMIN_BROWSER_TEMP_ROOT=str(tmp / 'admin-browser-runtime'),
               PUPPETEER_EXECUTABLE_PATH=args.chromium,
               OWASP_AI_GOAT_CHROMIUM_ACTUAL_EXECUTABLE=args.chromium,
               AWS_EC2_METADATA_DISABLED='true', LOGS_DIR=str(runtime / 'logs'),
               OWASP_AI_GOAT_APP_DATA_ROOT=str(runtime / 'data'),
               OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(repo),
               PGCONNECT_TIMEOUT='5',
               PGOPTIONS='-c statement_timeout=15000 -c idle_in_transaction_session_timeout=30000')
    for role in ('runtime', 'migration'):
        env['PG_ADMIN_BROWSER_TEST_' + role.upper() + '_URL'] = \
            f'postgresql://dvaia_identity_{role}@127.0.0.1:{port}/{database}'
    if args.cohort == RESET_COHORT:
        env.update(ADMIN_Q05_COHORT=RESET_COHORT, ADMIN_STUDENT_RESET_ONLY='1',
                   PLATFORM_DATABASE_ENGINE='postgres', WORKSHOP_DATABASE_ENGINE='postgres',
                   SENSITIVE_INFO_AGGREGATE_RESET_ENABLED='true')
        for role, variable in (('runtime', 'FINFLOW_WORKSHOP_DATABASE_URL'),
                               ('migration', 'FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL')):
            row = stores['finflow']
            env[variable] = f"postgresql://{row[role]}@127.0.0.1:{port}/{row['database']}"
    validate_database_environment(env, args.cohort, match[1], port)
    return env


def verify_tap(text):
    if not all(re.search(pattern, text) for pattern in (
            r'(?m)^ok 1 - ' + re.escape(TITLE) + r'\s*$',
            r'(?m)^# tests 1\s*$', r'(?m)^# pass 1\s*$',
            r'(?m)^# fail 0\s*$', r'(?m)^# skipped 0\s*$')):
        raise RuntimeError('Exact one-case zero-skip browser proof missing')


def failure_details(error):
    """Fixed setup/inspection commands contain no user/password payloads."""
    result = {'type': type(error).__name__, 'message': str(error)}
    if isinstance(error, (subprocess.CalledProcessError, subprocess.TimeoutExpired)):
        raw = error.stderr or ''
        raw = raw if isinstance(raw, bytes) else raw.encode('utf-8', errors='replace')
        result.update(stderr=raw[:8192].decode('utf-8', errors='replace'),
                      stderrBytes=len(raw), stderrTruncated=len(raw) > 8192)
        if isinstance(error, subprocess.CalledProcessError):
            result['exitCode'] = error.returncode
    return result


def verify_fixture(receipt, cohort=COHORT):
    if receipt.get('testBody') != 'passed' or receipt.get('status') != \
            'browser_cleanup_delegated_to_current_host_launcher' or receipt.get('tempRootAbsent') is not False:
        raise RuntimeError('Fixture application cleanup incomplete')
    cleanup = receipt.get('cleanup')
    if not isinstance(cleanup, list) or not cleanup or any(row.get('ok') is not True for row in cleanup):
        raise RuntimeError('Fixture application resource cleanup unproved')
    if cohort == RESET_COHORT:
        verify_reset_fixture(receipt)
        return
    if cohort != COHORT:
        raise RuntimeError('Unknown fixture cohort')
    facts = receipt.get('q05', {})
    for key, expected in {
        'status': 'bounded-rendered-manual-actions-observed', 'modelCalls': 0, 'judgeCalls': 0,
        'siblingsPreserved': True, 'lateAck': 'one-response-discarded-after-mounted-effect',
        'excluded': ['student-reset', 'student-deletion', 'model-grading', 'full-Q05-denominator'],
    }.items():
        if type(facts.get(key)) is not type(expected) or facts.get(key) != expected:
            raise RuntimeError('Q05 rendered scope fact missing: ' + key)
    actions = facts.get('actions')
    if not isinstance(actions, dict) or set(actions) != set(ACTION_FACTS):
        raise RuntimeError('Exact rendered action set required')
    for name, fields in ACTION_FACTS.items():
        row = actions[name]
        if not isinstance(row, dict) or set(row) != set(fields):
            raise RuntimeError('Rendered action receipt fields incomplete: ' + name)
        for key in fields:
            value = row[key]
            if key == 'targetId':
                if type(value) is not int or value <= 0:
                    raise RuntimeError('Persisted action target identity invalid')
            elif key == 'storageEventsObserved':
                if type(value) is not int or (value != 2 if name in (
                        'administratorDeactivation', 'studentPassword') else value < 2):
                    raise RuntimeError('Physical cross-tab authority events missing')
            elif value is not True:
                raise RuntimeError('Rendered action proof false: ' + name + '.' + key)
    for first, second in (('studentCreate', 'studentEdit'), ('studentCreate', 'studentPassword'),
                          ('studentCreate', 'accountLock'), ('studentCreate', 'accountUnlock'),
                          ('administratorCreate', 'administratorEdit'),
                          ('administratorCreate', 'administratorDeactivation')):
        if actions[first]['targetId'] != actions[second]['targetId']:
            raise RuntimeError('Rendered created/edit target mismatch')
    if actions['studentCreate']['targetId'] == actions['administratorCreate']['targetId']:
        raise RuntimeError('Independent created targets required')
    expected_ack = dict(method='PUT',
        path='/api/admin/administrators/' + str(actions['administratorEdit']['targetId']),
        phase='after-mounted-handler-before-response')
    if facts.get('ackLoss') != expected_ack:
        raise RuntimeError('Exact single post-effect acknowledgement loss proof required')
    expected_deactivation_ack = dict(method='DELETE',
        path='/api/admin/administrators/' + str(actions['administratorDeactivation']['targetId']),
        phase='after-real-http-200-before-browser-consumption', status=200,
        serverAcknowledgedInactive=True)
    deactivation_ack = facts.get('administratorDeactivationAckLoss')
    if type(deactivation_ack) is not dict or set(deactivation_ack) != set(expected_deactivation_ack) \
            or type(deactivation_ack['status']) is not int \
            or deactivation_ack['status'] != 200 \
            or deactivation_ack['serverAcknowledgedInactive'] is not True \
            or deactivation_ack['method'] != expected_deactivation_ack['method'] \
            or deactivation_ack['path'] != expected_deactivation_ack['path'] \
            or deactivation_ack['phase'] != expected_deactivation_ack['phase']:
        raise RuntimeError('Exact Deactivate post-effect acknowledgement loss proof required')
    expected_unlock_ack = dict(method='POST',
        path='/api/admin/users/' + str(actions['accountUnlock']['targetId']) + '/unlock',
        phase='after-mounted-handler-before-response')
    if facts.get('accountUnlockAckLoss') != expected_unlock_ack:
        raise RuntimeError('Exact Unlock post-effect acknowledgement loss proof required')
    if facts.get('accountAccessServerReceived') != {'lock': 1, 'unlock': 1}:
        raise RuntimeError('Exact mounted-server Lock and Unlock POST counts required')
    received_deactivation = facts.get('administratorDeactivationServerReceived')
    if type(received_deactivation) is not dict or set(received_deactivation) != {'delete'} \
            or type(received_deactivation['delete']) is not int \
            or received_deactivation['delete'] != 1:
        raise RuntimeError('Exact mounted-server Deactivate DELETE count required')
    response_stage = facts.get('administratorDeactivationResponseStage')
    expected_response_stage = dict(browserRequests=1, browserFailed=1,
                                   browserFinished=0, serverReceived=1)
    if type(response_stage) is not dict or set(response_stage) != set(expected_response_stage) \
            or any(type(response_stage[key]) is not int or response_stage[key] != value
                   for key, value in expected_response_stage.items()):
        raise RuntimeError('Exact browser response-stage failure and server DELETE join required')
    student_response_stage = facts.get('studentPasswordResponseStage')
    expected_student_response_stage = dict(browserRequests=1, browserFailed=1, browserFinished=0)
    if type(student_response_stage) is not dict \
            or set(student_response_stage) != set(expected_student_response_stage) \
            or any(type(student_response_stage[key]) is not int
                   or student_response_stage[key] != value
                   for key, value in expected_student_response_stage.items()):
        raise RuntimeError('Exact student-password browser response-stage failure required')
    counts = facts.get('requestCounts')
    if not isinstance(counts, dict) or counts.get(
            'POST /api/admin/users/' + str(actions['accountLock']['targetId']) + '/lock') != 1 \
            or counts.get('POST /api/admin/users/' + str(actions['accountUnlock']['targetId']) + '/unlock') != 1:
        raise RuntimeError('Exact one-request physical Lock and Unlock counts required')
    expected_password_request = ('POST /api/admin/students/' +
                                 str(actions['studentPassword']['targetId']) + '/change-password')
    password_counts = {key: value for key, value in counts.items()
                       if key.startswith('POST /api/admin/students/')
                       and '/change-password' in key}
    if set(password_counts) != {expected_password_request} \
            or type(password_counts[expected_password_request]) is not int \
            or password_counts[expected_password_request] != 1:
        raise RuntimeError('Exact one-request physical student Password count required')
    expected_deactivation_request = ('DELETE /api/admin/administrators/' +
                                     str(actions['administratorDeactivation']['targetId']))
    delete_counts = {key: value for key, value in counts.items() if key.startswith('DELETE ')}
    if set(delete_counts) != {expected_deactivation_request} \
            or type(delete_counts[expected_deactivation_request]) is not int \
            or delete_counts[expected_deactivation_request] != 1:
        raise RuntimeError('Exact one-request physical Deactivate count required')


def verify_reset_fixture(receipt):
    facts = receipt.get('studentResetQ05')
    fields = {
        'version', 'status', 'workshopKey', 'targetId', 'siblingId', 'modelCalls',
        'judgeCalls', 'canonicalCredit', 'seedProvenance', 'facts',
        'requestOperationIds', 'realResetPostCount', 'deniedResetPostCount',
        'originalGeneration', 'finalGeneration', 'ackLoss', 'excluded', 'snapshots',
    }
    if not isinstance(facts, dict) or set(facts) != fields or receipt.get('q05') is not None:
        raise RuntimeError('Exact separate reset scope receipt required')
    expected = dict(version=1, status='bounded-rendered-student-reset-observed',
        workshopKey='sensitive_info_disclosure', modelCalls=0, judgeCalls=0,
        canonicalCredit=False, seedProvenance='controlled-preexisting-completion-not-model-credit',
        realResetPostCount=3, deniedResetPostCount=1, excluded=RESET_EXCLUSIONS)
    for key, value in expected.items():
        if type(facts.get(key)) is not type(value) or facts[key] != value:
            raise RuntimeError('Reset scope fact invalid: ' + key)
    for key in ('targetId', 'siblingId'):
        if type(facts[key]) is not int or facts[key] <= 0:
            raise RuntimeError('Exact reset learner identities required')
    if facts['targetId'] == facts['siblingId']:
        raise RuntimeError('Distinct reset sibling required')
    proofs = facts['facts']
    if not isinstance(proofs, dict) or set(proofs) != set(RESET_FACTS) \
            or any(value is not True for value in proofs.values()):
        raise RuntimeError('All bounded reset acceptance cases required')
    operations = facts['requestOperationIds']
    uuid_pattern = '[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}'
    if not isinstance(operations, list) or len(operations) != 3 \
            or any(not isinstance(value, str) or not re.fullmatch(uuid_pattern, value)
                   for value in operations) \
            or operations[0] != operations[1] or operations[0] == operations[2]:
        raise RuntimeError('Exact original/replay/new reset operation identities required')
    if type(facts['originalGeneration']) is not int or facts['originalGeneration'] < 0 \
            or type(facts['finalGeneration']) is not int \
            or facts['finalGeneration'] != facts['originalGeneration'] + 2:
        raise RuntimeError('Exactly two distinct reset generations required')
    expected_ack = dict(method='POST',
        path=f"/api/admin/students/{facts['targetId']}/workshops/sensitive_info_disclosure/reset",
        phase='after-real-http-200-before-browser-consumption')
    if facts['ackLoss'] != expected_ack:
        raise RuntimeError('Exact successful reset response loss required')
    snapshots = facts['snapshots']
    if not isinstance(snapshots, dict) or set(snapshots) != {
            'cancel', 'stagedAuthority', 'replay', 'sibling'}:
        raise RuntimeError('Complete reset no-effect snapshot pairs required')
    for name, pair in snapshots.items():
        if not isinstance(pair, dict) or set(pair) != {'before', 'after'} \
                or any(not isinstance(value, str) or not re.fullmatch('[a-f0-9]{64}', value)
                       for value in pair.values()) or pair['before'] != pair['after']:
            raise RuntimeError('Reset state preservation unproved: ' + name)


def admission_grant(repo, args, child_pid, profile):
    return dict(version=1, cohort=args.cohort, launcherPid=os.getpid(), workerPid=child_pid,
                nonce=secrets.token_hex(32), workspace=str(repo),
                buildSha256=args.build_sha256, snapshotSha256=args.snapshot_sha256,
                outerSandbox='repository-only', chromium=args.chromium, profile=str(profile))


def sandbox_write_denied(path):
    """Consult Seatbelt policy only: never attempt a probe file write."""
    library = ctypes.CDLL('/usr/lib/libsandbox.dylib', use_errno=True)
    check = library.sandbox_check
    # Required on arm64 for the fixed-prefix / variadic argument ABI.
    check.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    check.restype = ctypes.c_int
    # Variadic sandbox_check(pid, operation, SANDBOX_FILTER_PATH, path).
    result = check(ctypes.c_int(os.getpid()), ctypes.c_char_p(b'file-write-create'),
                   ctypes.c_int(1), ctypes.c_char_p(os.fsencode(path)))
    if result not in (0, 1):
        raise RuntimeError('Repository sandbox policy inspection unavailable')
    return result == 1


def verify_outer_boundary(repo, argv, inspector, *, api=None, denied=sandbox_write_denied):
    api = api or LibProc()
    parent = os.getppid()
    if inspector.parent != parent:
        raise RuntimeError('Inspector is not current direct parent')
    row = api.identity(parent)
    if row is None or row.uid != os.getuid() or row.ruid != os.getuid():
        raise RuntimeError('Same-user coordinator identity required')
    birth = (row.start_sec, row.start_usec)
    arguments_seen = api.arguments(parent)
    fixed = str(repo / 'tests/postgres/run_admin_q05_with_inspector.py')
    if len(arguments_seen) != len(argv) + 3 or arguments_seen[0] != str(physical_python(api)) \
            or list(arguments_seen[1:]) != ['-B', fixed, *argv]:
        raise RuntimeError('Exact fixed outside coordinator invocation required')
    after = api.identity(parent)
    if after is None or (after.start_sec, after.start_usec) != birth \
            or after.uid != os.getuid() or after.ruid != os.getuid():
        raise RuntimeError('Coordinator birth changed')
    # Existing directories: sandbox_check cannot resolve nonexistent paths
    # reliably, so an absent probe filename would produce a false denial.
    if not denied('/private/tmp') or denied(repo / 'tasks/qualification'):
        raise RuntimeError('Repository-only write sandbox required')


def main(argv):
    args = arguments(argv)
    repo = Path(__file__).resolve().parents[2]
    before = snapshot(repo, args)
    if args.plan:
        print(json.dumps(dict(cohort=args.cohort, snapshotSha256=encoded(before),
                              buildSha256=args.build_sha256, limits=LIMITS,
                              sourceCopy=False, existingBuild=True, actualExecution=False,
                              databaseCount=2 if args.cohort == RESET_COHORT else 1)))
        return 0
    if sys.platform != 'darwin' or encoded(before) != args.snapshot_sha256:
        raise RuntimeError('Darwin current-source plan pin mismatch')
    inspector = consume_environment()
    if inspector is None:
        raise RuntimeError('Fixed outside inspector required')
    verify_outer_boundary(repo, argv, inspector)
    pins = validate_current_host(workspace=str(repo), profile=args.current_host_profile,
        docker_host=args.docker_host, node=args.node, node_sha256=args.node_sha256,
        docker=args.docker, docker_sha256=args.docker_sha256, daemon_id=args.daemon_id,
        image_id=args.image_id)
    parent = evidence_parent(repo)
    nonce = uuid.uuid4().hex[:12]
    root = parent / (('run-admin-student-reset-' if args.cohort == RESET_COHORT
                     else 'run-admin-q05-') + nonce)
    root.mkdir(mode=0o700)
    runtime = root / 'runtime'
    runtime.mkdir(mode=0o700)
    for name in ('home', 'tmp', 'cache', 'logs', 'data'):
        (runtime / name).mkdir(mode=0o700)
    state = dict(schemaVersion=1, cohort=args.cohort, status='preparing', sourceCopy=False,
                 actualModelCalls=0, canonicalCredit=False, fullQ05Qualification=False,
                 pins=pins, limits=LIMITS, cleanup={}, processIdentities={})
    private_json(root / 'source-before.json', before)
    private_json(root / 'result.json', state)
    deadline = time.monotonic() + LIMITS['seconds']
    docker = [args.docker, '--host', args.docker_host]
    env = dict(PATH='/usr/bin:/bin', HOME=str(runtime / 'home'), TMPDIR=str(runtime / 'tmp'))
    container = None
    name = ('owasp-ai-goat-admin-student-reset-' if args.cohort == RESET_COHORT else 'owasp-ai-goat-admin-q05-') + nonce
    owner = uuid.uuid4().hex
    database = 'owasp_ai_goat_test_admin_browser_' + nonce
    state['stores'] = database_plan(args.cohort, nonce)
    child = None
    owned = Owned()
    previous = {}
    browser_ack = None
    log = root / 'browser.tap'
    output = None
    admission_read = admission_write = None

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError('Admin qualification deadline')
        return value

    def command(argv, check=True):
        return subprocess.run(argv, env=env, capture_output=True, text=True,
                              timeout=min(15, remaining()), check=check)

    def inspect():
        result = command(docker + ['container', 'inspect', name], check=False)
        if result.returncode:
            if result.returncode == 1 and result.stderr.strip() in (
                f'Error: No such object: {name}', f'Error: No such container: {name}',
                f'Error response from daemon: No such container: {name}'):
                return None
            raise RuntimeError('Container absence inspection failed')
        row = json.loads(result.stdout)[0]
        if row['Config']['Labels'].get('owasp-ai-goat.test.owner') != owner \
                or (container is not None and row['Id'] != container):
            raise RuntimeError('Container identity mismatch')
        return row

    def interrupted(number, _frame):
        raise RuntimeError('Qualification interrupted: ' + str(number))

    try:
        for number in (signal.SIGINT, signal.SIGTERM):
            previous[number] = signal.signal(number, interrupted)
        if command(docker + ['info', '--format', '{{.ID}}']).stdout.strip() != args.daemon_id:
            raise RuntimeError('Daemon identity mismatch')
        image = json.loads(command(docker + ['image', 'inspect', args.image_id]).stdout)[0]
        if image['Id'] != args.image_id:
            raise RuntimeError('Existing image identity mismatch')
        if inspect() is not None:
            raise RuntimeError('Fresh owned container required')
        command(docker + ['run', '-d', '--pull', 'never', '--name', name,
            '--label', 'owasp-ai-goat.test.owner=' + owner, '--memory', '1g', '--cpus', '1',
            '--pids-limit', '128', '--tmpfs', '/var/lib/postgresql:rw,size=536870912',
            '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-p', '127.0.0.1::5432',
            args.image_id, '-c', 'max_connections=100'])
        row = inspect()
        container = row['Id']
        state.update(containerId=container, containerName=name, owner=owner)
        private_json(root / 'result.json', state)
        ports = row['NetworkSettings']['Ports']['5432/tcp']
        if len(ports) != 1 or ports[0]['HostIp'] != '127.0.0.1':
            raise RuntimeError('Loopback-only PostgreSQL required')
        port = int(ports[0]['HostPort'])
        ready = time.monotonic() + 30
        # The image initializer temporarily serves a Unix-only cluster. Probe
        # TCP so readiness cannot admit that server before its shutdown/restart.
        while command(docker + ['exec', container, 'pg_isready', '-h', '127.0.0.1',
                               '-p', '5432', '-U', 'postgres'], check=False).returncode:
            if time.monotonic() >= ready:
                raise TimeoutError('PostgreSQL readiness')
            time.sleep(.1)
        for statement in database_statements(args.cohort, nonce):
            command(docker + ['exec', container, 'psql', '-h', '127.0.0.1',
                              '-p', '5432', '-U', 'postgres', '-d', 'postgres', '-v',
                              'ON_ERROR_STOP=1', '-c', statement])
        fixture_env = environment(repo, runtime, port, database, args)
        profile = Path(fixture_env['PG_ADMIN_BROWSER_TEMP_ROOT']) / 'chromium-profile'
        admission_read, admission_write = os.pipe()
        fixture_env['ADMIN_Q05_ADMISSION_FD'] = str(admission_read)
        output = log.open('xb')
        os.chmod(log, 0o600)
        child = subprocess.Popen([args.node, '--test', '--test-isolation=none', '--test-concurrency=1',
            '--test-reporter=tap', str(repo / FIXTURE)], cwd=repo, env=fixture_env,
            stdout=output, stderr=output, start_new_session=True, close_fds=True,
            pass_fds=(admission_read,))
        os.close(admission_read)
        admission_read = None
        owned.register_child(child.pid)
        grant = admission_grant(repo, args, child.pid, profile)
        data = json.dumps(grant, separators=(',', ':')).encode()
        if len(data) > 8192 or os.write(admission_write, data) != len(data):
            raise RuntimeError('Complete bounded admission pipe required')
        os.close(admission_write)
        admission_write = None
        journal = Path(fixture_env['PG_ADMIN_BROWSER_RESOURCE_JOURNAL'])
        browser_stopped = False
        while child.poll() is None:
            remaining()
            if log.stat().st_size > LIMITS['logBytes']:
                raise RuntimeError('Browser log bound exceeded')
            owned.observe()
            if browser_ack is None and journal.exists():
                receipt = read_private(journal)
                pid = receipt.get('resources', {}).get('browser', {}).get('pid')
                if pid is not None:
                    browser_ack = owned.register_browser(pid, child.pid, profile, Path(args.chromium))
                    private_json(runtime / 'browser-ack.json', browser_ack)
                    state['browserIdentity'] = browser_ack
                    private_json(root / 'result.json', state)
            if browser_ack is not None and not browser_stopped and journal.exists():
                terminal = read_private(journal)
                if terminal.get('status') == 'browser_cleanup_delegated_to_current_host_launcher':
                    owned.stop(min(deadline, time.monotonic() + 10), child, exclude=(child.pid,))
                    browser_stopped = True
            time.sleep(.05)
        output.close()
        output = None
        if child.returncode != 0 or browser_ack is None:
            raise RuntimeError('Rendered fixture failed or browser ownership unproved')
        verify_tap(log.read_text())
        receipt = read_private(journal)
        state['fixture'] = receipt
        verify_fixture(receipt, args.cohort)
        state['status'] = 'passed'
    except BaseException as error:
        state.update(status='failed', error=failure_details(error))
    finally:
        for number in previous:
            signal.signal(number, signal.SIG_IGN)
        deadline = time.monotonic() + LIMITS['cleanupSeconds']
        for descriptor in (admission_read, admission_write):
            if descriptor is not None:
                os.close(descriptor)
        if output is not None:
            output.close()
        for key, action in (
            ('processes', lambda: owned.stop(deadline, child)),
            ('profileAbsence', lambda: inspector.absent(runtime, 'temporary-profiles')),
        ):
            try:
                state['cleanup'][key] = action() is True
            except BaseException as error:
                state['cleanup'][key] = False
                state['cleanup'][key + 'Error'] = str(error)
        # Read after process shutdown (settled writer) and before deleting the
        # owned runtime, including failed TAP/timeout paths with partial facts.
        retain_fixture_journal(state, runtime)
        private_json(root / 'result.json', state)
        try:
            if not all(state['cleanup'].get(key) for key in ('processes', 'profileAbsence')):
                raise RuntimeError('Retain cluster/runtime while process absence is unproved')
            row = inspect()
            if row is not None:
                command(docker + ['rm', '-f', row['Id']])
            state['cleanup']['containerAbsent'] = inspect() is None
            if not state['cleanup']['containerAbsent']:
                raise RuntimeError('Container remains')
            if container is not None:
                absent_id = command(docker + ['container', 'inspect', container], check=False)
                if absent_id.returncode != 1 or absent_id.stderr.strip() not in (
                        f'Error: No such object: {container}', f'Error: No such container: {container}',
                        f'Error response from daemon: No such container: {container}'):
                    raise RuntimeError('Exact container ID absence unproved')
            state['cleanup']['containerIdAbsent'] = True
            shutil.rmtree(runtime)
            state['cleanup']['runtimeAbsent'] = not os.path.lexists(runtime)
        except BaseException as error:
            state['cleanup']['resourceError'] = str(error)
        try:
            after = snapshot(repo, args)
            private_json(root / 'source-after.json', after)
            state['sourceUnchanged'] = after == before
        except BaseException as error:
            state['sourceUnchanged'] = False
            state['integrityError'] = str(error)
        state['processIdentities'] = owned.records
        if log.exists():
            state['logSha256'] = sha(log)
        if not state.get('sourceUnchanged') or not all(state['cleanup'].get(key) is True
                for key in ('processes', 'profileAbsence', 'containerAbsent',
                            'containerIdAbsent', 'runtimeAbsent')):
            state['status'] = 'failed'
        private_json(root / 'result.json', state)
        for number, handler in previous.items():
            signal.signal(number, handler)
    print(json.dumps({'status': state['status'], 'evidence': str(root / 'result.json')}))
    return 0 if state['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
