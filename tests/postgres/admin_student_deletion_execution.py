"""Closed execution primitives for the rendered sixteen-store deletion cohort.

Only the reviewed current-host launcher may call these. Importing this module
allocates nothing, and no method infers authority from an inherited env var.
"""

import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time

from admin_student_deletion_current_host import COHORT, LIMITS, database_plan, store_plan_sha256


def provision_statements(nonce):
    """Fresh-cluster DDL; identifiers come solely from the canonical manifest."""
    rows = database_plan(nonce)
    roles = []
    for row in rows:
        schema = row['schema']
        roles.extend((f'dvaia_{schema}_runtime', f'dvaia_{schema}_migration'))
    roles.append('dvaia_ctf_delivery')
    if len(roles) != 33 or len(set(roles)) != 33 or any(
            re.fullmatch(r'[a-z][a-z0-9_]{0,62}', name) is None for name in roles):
        raise RuntimeError('Canonical thirty-three login roles required')
    statements = [f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'
                  for role in roles]
    for row in rows:
        schema, database = row['schema'], row['database']
        migration, runtime = f'dvaia_{schema}_migration', f'dvaia_{schema}_runtime'
        statements.extend((f'CREATE DATABASE {database} OWNER {migration}',
                           f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC',
                           f'GRANT CONNECT ON DATABASE {database} TO {migration},{runtime}' +
                           (',dvaia_ctf_delivery' if schema == 'ctf' else '')))
    return tuple(statements)


def store_urls(nonce, port):
    if type(port) is not int or not 1 <= port <= 65535:
        raise RuntimeError('Owned loopback PostgreSQL port required')
    result = {}
    for row in database_plan(nonce):
        schema, database = row['schema'], row['database']
        for role, key in (('runtime', 'runtimeVariable'), ('migration', 'migrationVariable')):
            result[row[key]] = f'postgresql://dvaia_{schema}_{role}@127.0.0.1:{port}/{database}'
        if schema == 'ctf':
            result['CTF_DELIVERY_DATABASE_URL'] = \
                f'postgresql://dvaia_ctf_delivery@127.0.0.1:{port}/{database}'
    if len(result) != 33:
        raise RuntimeError('Exact sixteen-store and delivery URL manifest required')
    return result


def container_command(docker, docker_host, name, image, owner):
    if not all(type(item) is str and item for item in (docker, docker_host, name, image, owner)) \
            or not re.fullmatch(r'sha256:[a-f0-9]{64}', image) \
            or not re.fullmatch(r'owasp-ai-goat-student-deletion-[a-f0-9]{12}', name) \
            or not re.fullmatch(r'[a-f0-9]{32}', owner):
        raise RuntimeError('Exact owned container identity required')
    return (docker, '--host', docker_host, 'run', '-d', '--pull', 'never',
            '--name', name, '--label', 'owasp-ai-goat.test.owner=' + owner,
            '--memory', str(LIMITS['memoryBytes']), '--cpus', str(LIMITS['cpus']),
            '--memory-swap', str(LIMITS['memorySwapBytes']),
            '--pids-limit', str(LIMITS['pids']),
            '--tmpfs', '/var/lib/postgresql:rw,size=' + str(LIMITS['postgresTmpfsBytes']),
            '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-p', '127.0.0.1::5432',
            image, '-c', 'max_connections=' + str(LIMITS['maxConnections']))


def resource_envelope_matches(host):
    return type(host) is dict and \
        type(host.get('Memory')) is int and host['Memory'] == LIMITS['memoryBytes'] and \
        type(host.get('MemorySwap')) is int and host['MemorySwap'] == LIMITS['memorySwapBytes'] and \
        type(host.get('NanoCpus')) is int and host['NanoCpus'] == LIMITS['cpus'] * 10**9 and \
        type(host.get('PidsLimit')) is int and host['PidsLimit'] == LIMITS['pids'] and \
        type(host.get('Tmpfs')) is dict and host['Tmpfs'].get('/var/lib/postgresql') == \
            'rw,size=' + str(LIMITS['postgresTmpfsBytes'])


def worker_environment(repo, runtime, nonce, port, args, snapshot_sha256, jwt_secret):
    """Minimal child env; exact paths are private and entirely inside checkout."""
    repo, runtime = Path(repo), Path(runtime)
    expected_run = repo / 'tasks/qualification' / ('run-admin-student-deletion-' + nonce)
    if runtime != expected_run / 'runtime' or runtime.is_symlink() or \
            not runtime.is_dir() or runtime.stat().st_uid != os.getuid() or \
            runtime.stat().st_mode & 0o077:
        raise RuntimeError('Exact owned deletion runtime required')
    if not isinstance(jwt_secret, str) or len(jwt_secret) < 32 or \
            not re.fullmatch(r'[a-zA-Z0-9_-]+', jwt_secret):
        raise RuntimeError('Private synthetic signing secret required')
    node = Path(args.node)
    tmp = runtime / 'tmp'
    result = dict(PATH=str(node.parent) + ':/usr/bin:/bin', HOME=str(runtime / 'home'),
                  TMPDIR=str(tmp), TMP=str(tmp), TEMP=str(tmp),
                  XDG_CACHE_HOME=str(runtime / 'cache'), MAC_CHROMIUM_TMPDIR=str(tmp),
                  NODE_ENV='test', PG_TEST_DISPOSABLE='yes', PG_POOL_BUDGET='78',
                  PGCONNECT_TIMEOUT='5',
                  PGOPTIONS='-c statement_timeout=15000 -c idle_in_transaction_session_timeout=30000',
                  PLATFORM_DATABASE_ENGINE='postgres', WORKSHOP_DATABASE_ENGINE='postgres',
                  AWS_EC2_METADATA_DISABLED='true', JWT_SECRET=jwt_secret,
                  OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(repo),
                  OWASP_AI_GOAT_APP_DATA_ROOT=str(runtime), LOGS_DIR=str(runtime / 'logs'),
                  ADMIN_STUDENT_DELETION_CURRENT_HOST='1',
                  ADMIN_STUDENT_DELETION_BUILD_DIRECTORY=str(repo / 'client/build'),
                  ADMIN_STUDENT_DELETION_BUILD_SHA256=args.build_sha256,
                  ADMIN_STUDENT_DELETION_SNAPSHOT_SHA256=snapshot_sha256,
                  ADMIN_STUDENT_DELETION_STORE_PLAN_SHA256=store_plan_sha256(nonce),
                  ADMIN_STUDENT_DELETION_BROWSER_ACK=str(runtime / 'browser-ack.json'),
                  STUDENT_DELETION_RESOURCE_JOURNAL=str(tmp / 'student-deletion-resources.json'),
                  STUDENT_DELETION_EVIDENCE_PATH=str(expected_run / 'student-deletion-evidence.json'),
                  PUPPETEER_EXECUTABLE_PATH=args.chromium,
                  OWASP_AI_GOAT_CHROMIUM_ACTUAL_EXECUTABLE=args.chromium)
    result.update(store_urls(nonce, port))
    return result


def initializer_command(node, repo):
    return (str(node), str(Path(repo) / 'tests/postgres/adminStudentDeletionInitialize.js'))


def worker_command(node, repo):
    return (str(node), '--test', '--test-isolation=none', '--test-concurrency=1',
            '--test-reporter=tap',
            str(Path(repo) / 'tests/postgres/adminStudentDeletionRendered.integration.test.js'))


def postgres_failure_diagnostic(row, logs):
    """Retain only fixed Docker state and server-event classes, never raw logs."""
    state = row.get('State') if type(row) is dict else None
    if type(state) is not dict or type(state.get('Running')) is not bool or \
            type(state.get('OOMKilled')) is not bool or \
            type(state.get('ExitCode')) is not int or \
            type(logs) is not str or len(logs.encode('utf-8')) > 65536:
        raise RuntimeError('Bounded PostgreSQL failure observation unavailable')
    return {'containerRunning': state['Running'], 'containerOOMKilled': state['OOMKilled'],
            'containerExitCode': state['ExitCode'],
            'backendSignalNine': bool(re.search(r'(?i)(?:server process|backend process)[^\n]{0,160}(?:signal 9|killed)', logs)),
            'outOfMemoryReported': bool(re.search(r'(?i)out of memory|cannot allocate memory|could not fork new process', logs)),
            'connectionTerminatedReported': bool(re.search(r'(?i)connection (?:terminated|reset)|terminating connection', logs))}


def run_initializer(node, repo, environment, log, owned, *, deadline, on_spawn):
    """One direct child performs canonical sequential migrations, then fully exits."""
    child = subprocess.Popen(initializer_command(node, repo), cwd=repo, env=environment,
                             stdout=log, stderr=log, start_new_session=True)
    on_spawn(child)
    owned.register_child(child.pid)
    while child.poll() is None:
        if time.monotonic() >= deadline:
            raise TimeoutError('Sequential deletion migrations exceeded deadline')
        if os.fstat(log.fileno()).st_size > 16 * 1024 * 1024:
            raise RuntimeError('Sequential migration log bound exceeded')
        time.sleep(.05)
    if os.fstat(log.fileno()).st_size > 16 * 1024 * 1024:
        raise RuntimeError('Sequential migration log bound exceeded')
    if child.returncode != 0:
        raise RuntimeError('Canonical sequential store initialization failed')
    if owned.api.identity(child.pid) is not None:
        raise RuntimeError('Migration child absence unproved')
    return {'exitCode': 0, 'stores': 16, 'migrationPoolsDrainedByChildExit': True}


def parse_resource_browser_pid(journal, read_private):
    receipt = read_private(journal)
    value = receipt.get('resources', {}).get('browser', {})
    if not value:
        return None
    if set(value) != {'pid', 'profile', 'executable'} or \
            type(value['profile']) is not str or not value['profile'] or \
            type(value['executable']) is not str or not value['executable']:
        raise RuntimeError('Unexpected browser resource identity')
    pid = value.get('pid')
    if pid is None:
        return None
    if type(pid) is not int or pid <= 0:
        raise RuntimeError('Unexpected browser resource identity')
    return pid


def await_worker(child, owned, journal, ack_path, profile, chromium, log_path,
                 *, deadline, read_private, private_json, tap_verifier,
                 log_limit=16 * 1024 * 1024):
    """Witness original browser birth before issuing one launcher-owned ACK."""
    if not callable(tap_verifier):
        raise RuntimeError('Strict deletion TAP verifier required')
    browser = None
    stopped = False
    while child.poll() is None:
        if time.monotonic() >= deadline:
            raise TimeoutError('Rendered deletion child exceeded deadline')
        if log_path.stat().st_size > log_limit:
            raise RuntimeError('Rendered deletion log bound exceeded')
        owned.observe()
        if browser is None and journal.exists():
            receipt = read_private(journal)
            entry = receipt.get('resources', {}).get('browser', {})
            pid = parse_resource_browser_pid(journal, lambda _: receipt)
            if entry and (entry['profile'] != str(profile) or
                          entry['executable'] != str(chromium)):
                raise RuntimeError('Browser resource path identity changed')
            if pid is not None:
                browser = owned.register_browser(pid, child.pid, profile, chromium)
                private_json(ack_path, browser)
        if browser is not None and not stopped and journal.exists():
            status = read_private(journal).get('status')
            if status == 'browser_cleanup_delegated_to_current_host_launcher':
                owned.stop(min(deadline, time.monotonic() + 10), child, exclude=(child.pid,))
                stopped = True
        time.sleep(.05)
    if browser is None or child.returncode != 0:
        raise RuntimeError('Rendered deletion failed or browser birth unproved')
    if log_path.stat().st_size > log_limit:
        raise RuntimeError('Rendered deletion log bound exceeded')
    tap_verifier(log_path.read_text())
    return {'browser': browser, 'terminalJournal': read_private(journal)}


def execute(args, *, repo, inspector, before, verify_fixture, verify_tap,
            snapshot_after):
    """Run once against existing local resources; no call path skips cleanup.

    The caller first authenticates the reviewed source/runtime/build snapshot and
    supplies a strict final-evidence verifier. Until that verifier exists this
    function has no admitted CLI caller and cannot award qualification.
    """
    from admin_q05_current_host import Owned, private_json, read_private
    from admin_student_deletion_current_host import admission_grant
    from secureshop_current_host_admission import evidence_parent, validate_current_host

    if not callable(verify_fixture) or not callable(verify_tap) or \
            not callable(snapshot_after) or inspector is None \
            or not isinstance(before, dict):
        raise RuntimeError('Complete reviewed execution admission required')
    repo = Path(repo)
    nonce = args.nonce
    database_plan(nonce)
    pins = validate_current_host(workspace=str(repo), profile=args.current_host_profile,
        docker_host=args.docker_host, node=args.node, node_sha256=args.node_sha256,
        docker=args.docker, docker_sha256=args.docker_sha256,
        daemon_id=args.daemon_id, image_id=args.image_id)
    parent = evidence_parent(repo)
    root = parent / ('run-admin-student-deletion-' + nonce)
    root.mkdir(mode=0o700, exist_ok=False)
    runtime = root / 'runtime'
    runtime.mkdir(mode=0o700)
    for name in ('home', 'tmp', 'cache', 'logs'):
        (runtime / name).mkdir(mode=0o700)
    state = dict(schemaVersion=1, cohort=COHORT, status='preparing', eligible=False,
                 actualModelCalls=0, actualJudgeCalls=0, canonicalCredit=False,
                 sourceCopy=False, limits=LIMITS, pins=pins, cleanup={},
                 storePlanSha256=store_plan_sha256(nonce))
    private_json(root / 'source-before.json', before)
    private_json(root / 'result.json', state)

    docker = (args.docker, '--host', args.docker_host)
    docker_env = dict(PATH='/usr/bin:/bin', HOME=str(runtime / 'home'),
                      TMPDIR=str(runtime / 'tmp'))
    owner_token = os.urandom(16).hex()
    name = 'owasp-ai-goat-student-deletion-' + nonce
    container_id = None
    owned = Owned()
    child = None
    initializer_child = None
    output = None
    read_fd = write_fd = None
    previous = {}
    deadline = time.monotonic() + 600
    port = None
    phase = 'preallocation'

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError('Student-deletion qualification deadline')
        return value

    def command(parts, *, check=True):
        return subprocess.run(parts, env=docker_env, capture_output=True, text=True,
                              timeout=min(15, remaining()), check=check)

    def inspect():
        result = command((*docker, 'container', 'inspect', name), check=False)
        if result.returncode:
            if result.returncode == 1 and result.stderr.strip() in (
                f'Error: No such object: {name}', f'Error: No such container: {name}',
                f'Error response from daemon: No such container: {name}'):
                return None
            raise RuntimeError('Owned container inspection unavailable')
        data = json.loads(result.stdout)
        if type(data) is not list or len(data) != 1:
            raise RuntimeError('Exact owned container inspection required')
        row = data[0]
        if row['Config']['Labels'].get('owasp-ai-goat.test.owner') != owner_token or \
                (container_id is not None and row['Id'] != container_id):
            raise RuntimeError('Owned container identity changed')
        return row

    def interrupted(number, _frame):
        raise RuntimeError('Student-deletion qualification interrupted: ' + str(number))

    def retain_initializer(process):
        nonlocal initializer_child
        initializer_child = process

    try:
        for number in (signal.SIGINT, signal.SIGTERM):
            previous[number] = signal.signal(number, interrupted)
        if command((*docker, 'info', '--format', '{{.ID}}')).stdout.strip() != args.daemon_id:
            raise RuntimeError('Dedicated daemon identity changed')
        image = json.loads(command((*docker, 'image', 'inspect', args.image_id)).stdout)
        if type(image) is not list or len(image) != 1 or image[0].get('Id') != args.image_id:
            raise RuntimeError('Exact existing PostgreSQL image unavailable')
        if inspect() is not None:
            raise RuntimeError('Fresh owned container required')
        phase = 'container-allocation'
        command(container_command(args.docker, args.docker_host, name,
                                  args.image_id, owner_token))
        row = inspect()
        container_id = row['Id']
        host = row['HostConfig']
        if not resource_envelope_matches(host):
            raise RuntimeError('PostgreSQL resource envelope changed')
        exposed = row['NetworkSettings']['Ports']['5432/tcp']
        if type(exposed) is not list or len(exposed) != 1 or \
                exposed[0].get('HostIp') != '127.0.0.1':
            raise RuntimeError('Loopback-only PostgreSQL required')
        port = int(exposed[0]['HostPort'])
        store_urls(nonce, port)
        state.update(containerId=container_id, containerName=name, postgresPort=port)
        private_json(root / 'result.json', state)
        ready_until = time.monotonic() + 30
        phase = 'postgres-readiness'
        while command((*docker, 'exec', container_id, 'pg_isready', '-h', '127.0.0.1',
                       '-p', '5432', '-U', 'postgres'), check=False).returncode:
            if time.monotonic() >= ready_until:
                raise TimeoutError('Owned PostgreSQL TCP readiness')
            time.sleep(.1)
        for statement in provision_statements(nonce):
            phase = 'store-provisioning'
            command((*docker, 'exec', container_id, 'psql', '-h', '127.0.0.1',
                     '-p', '5432', '-U', 'postgres', '-d', 'postgres', '-v',
                     'ON_ERROR_STOP=1', '-c', statement))
        environment = worker_environment(repo, runtime, nonce, port, args,
            args.snapshot_sha256, os.urandom(32).hex())
        init_log = root / 'initialize.tap'
        phase = 'sequential-migration'
        with init_log.open('xb') as stream:
            state['initializer'] = run_initializer(args.node, repo, environment,
                stream, owned, deadline=min(deadline, time.monotonic() + 180),
                on_spawn=retain_initializer)
        private_json(root / 'result.json', state)
        profile = runtime / 'tmp' / ('owasp-ai-goat-student-deletion-browser-' + nonce)
        read_fd, write_fd = os.pipe()
        environment['ADMIN_STUDENT_DELETION_ADMISSION_FD'] = str(read_fd)
        log_path = root / 'browser.tap'
        output = log_path.open('xb')
        child = subprocess.Popen(worker_command(args.node, repo), cwd=repo, env=environment,
                                 stdout=output, stderr=output, start_new_session=True,
                                 close_fds=True, pass_fds=(read_fd,))
        os.close(read_fd)
        read_fd = None
        phase = 'rendered-worker-admission'
        owned.register_child(child.pid)
        grant = admission_grant(repo, root, nonce, args, child.pid, profile)
        packet = json.dumps(grant, separators=(',', ':')).encode()
        if len(packet) > 8192 or os.write(write_fd, packet) != len(packet):
            raise RuntimeError('Complete one-worker admission grant required')
        os.close(write_fd)
        write_fd = None
        observed = await_worker(child, owned,
            runtime / 'tmp/student-deletion-resources.json', runtime / 'browser-ack.json',
            profile, Path(args.chromium), log_path, deadline=deadline,
            read_private=read_private, private_json=private_json,
            tap_verifier=verify_tap)
        phase = 'strict-evidence-replay'
        evidence = read_private(root / 'student-deletion-evidence.json', maximum=2 * 1024 * 1024)
        verified = verify_fixture(evidence, observed['terminalJournal'],
                                  observed['browser'])
        if type(verified) is not dict or verified.get('passed') is not True:
            raise RuntimeError('Complete deletion evidence replay missing')
        state.update(status='passed', fixture=verified,
                     browserIdentity=observed['browser'])
    except BaseException as error:
        code = getattr(error, 'code', None)
        state.update(status='failed', error={'type': type(error).__name__,
            'phase': phase, 'code': code if type(code) is str and
            re.fullmatch(r'[A-Z][A-Z0-9_]{0,79}', code) else 'OTHER'})
    finally:
        for number in previous:
            try:
                signal.signal(number, signal.SIG_IGN)
            except BaseException as error:
                state['cleanup']['signalIgnoreErrorType'] = type(error).__name__
        deadline = time.monotonic() + 120  # Cleanup has its own bound after work expiry.
        cleanup_deadline = deadline
        for descriptor in (read_fd, write_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except BaseException as error:
                    state['cleanup']['descriptorCloseErrorType'] = type(error).__name__
        if output is not None:
            try:
                output.close()
            except BaseException as error:
                state['cleanup']['outputCloseErrorType'] = type(error).__name__
        def stop_processes():
            if initializer_child is not None:
                initializer_child.poll()  # Reap even when migration work timed out.
            if child is not None:
                child.poll()
            return owned.stop(cleanup_deadline, child or initializer_child)
        for key, action in (
            ('processes', stop_processes),
            ('profileAbsence', lambda: inspector.absent(runtime, 'temporary-profiles')),
        ):
            try:
                state['cleanup'][key] = action() is True
            except BaseException as error:
                state['cleanup'][key] = False
                state['cleanup'][key + 'ErrorType'] = type(error).__name__
        try:
            private_json(root / 'result.json', state)
        except BaseException as error:
            state['cleanup']['intermediateJournalErrorType'] = type(error).__name__
        try:
            if not state['cleanup'].get('processes') or not state['cleanup'].get('profileAbsence'):
                raise RuntimeError('Retain owned resources while absence is uncertain')
            row = inspect()
            if row is not None and state['status'] != 'passed':
                try:
                    logs = command((*docker, 'logs', '--tail', '80', row['Id']), check=False)
                    if logs.returncode != 0:
                        raise RuntimeError('PostgreSQL server logs unavailable')
                    state['postgresFailureDiagnostic'] = postgres_failure_diagnostic(
                        row, logs.stdout + logs.stderr)
                except BaseException as error:
                    state['postgresFailureDiagnosticErrorType'] = type(error).__name__
            if row is not None:
                command((*docker, 'rm', '-f', row['Id']))
            state['cleanup']['containerAbsent'] = inspect() is None
            if not state['cleanup']['containerAbsent']:
                raise RuntimeError('Owned container remains')
            if container_id is not None:
                absent = command((*docker, 'container', 'inspect', container_id), check=False)
                if absent.returncode != 1 or absent.stderr.strip() not in (
                    f'Error: No such object: {container_id}',
                    f'Error: No such container: {container_id}',
                    f'Error response from daemon: No such container: {container_id}'):
                    raise RuntimeError('Exact container ID absence unproved')
            state['cleanup']['containerIdAbsent'] = True
            shutil.rmtree(runtime)
            state['cleanup']['runtimeAbsent'] = not os.path.lexists(runtime)
        except BaseException as error:
            state['cleanup']['resourceErrorType'] = type(error).__name__
        try:
            after = snapshot_after()
            private_json(root / 'source-after.json', after)
            state['sourceUnchanged'] = after == before
        except BaseException as error:
            state['sourceUnchanged'] = False
            state['integrityErrorType'] = type(error).__name__
        if not state.get('sourceUnchanged') or not all(state['cleanup'].get(key) is True
                for key in ('processes', 'profileAbsence', 'containerAbsent',
                            'containerIdAbsent', 'runtimeAbsent')):
            state['status'] = 'failed'
        if any(key.endswith('ErrorType') for key in state['cleanup']):
            state['status'] = 'failed'
        state['eligible'] = state['status'] == 'passed' and state.get('sourceUnchanged') is True \
            and all(state['cleanup'].get(key) is True for key in
                    ('processes', 'profileAbsence', 'containerAbsent',
                     'containerIdAbsent', 'runtimeAbsent')) \
            and not any(key.endswith('ErrorType') for key in state['cleanup'])
        state['processIdentities'] = owned.records
        try:
            private_json(root / 'result.json', state)
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)
    return {'status': state['status'], 'evidence': str(root / 'result.json')}
