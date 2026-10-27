#!/usr/bin/env python3
"""Disposable PostgreSQL owner for the inert V30 boundary probe.

This is not original-host or model qualification. Import and --plan allocate
nothing. The admitted run must execute outside the repository Seatbelt wrapper;
its child receives the exact combined repository-write/network policy.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time
import uuid

import v30_agent_host_controller as host
import run_v30_controller_boundary_probe as boundary_probe
from admin_browser_current_main_admission import inventory
from secureshop_current_host_admission import validate_current_host, evidence_parent
from darwin_process_inventory import LibProc, owned_group_members
from sql_nosql_docker_ownership import (verify_daemon, verify_image, inspect_owned,
                                        validate_container_layout, cleanup_owned)


LIVE_ENABLED = True
ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / 'tests/postgres/run_v30_controller_boundary_probe.py'
PROFILE = 'goat-q'
DOCKER_HOST = 'unix://' + str(ROOT / '.qualification/goat-q/docker.sock')
NODE = ROOT / host.NODE_RELATIVE
DOCKER = ROOT / 'tasks/runtime/container/bin/docker'
CONTAINER_PREFIX = 'dvaia-v30-original-disclosure-'
WORK_SECONDS = 170
PROBE_SECONDS = 55  # Probe work 30s + its 20s retirement + outer allowance.
CLEANUP_SECONDS = 30
TOTAL_SECONDS = 270  # Acceptance budget, not a hard wall cap on synchronous postflight inventory.
MAX_OUTPUT = 16384
SOURCE_LIMIT = 32 * 1024 * 1024
SOURCE_FILES = (
    'tests/postgres/run_v30_boundary_probe_current_host.py',
    'tests/postgres/test_run_v30_boundary_probe_current_host.py',
    'tests/postgres/run_v30_controller_boundary_probe.py',
    'tests/postgres/v30_agent_host_controller.py',
    'tests/postgres/test_v30_agent_host_controller.py',
    'tests/postgres/secureshop_current_host_admission.py',
    'tests/postgres/admin_browser_current_main_admission.py',
    'tests/postgres/secureshop_current_host_admission.py',
    'tests/postgres/sql_nosql_docker_ownership.py',
    'tests/postgres/darwin_process_inventory.py',
    'tests/postgres/trusted_process_inspector.py',
    'agent-host/index.js',
    host.FIXTURE,
    'server/services/secureshop/agentHostSupervisor.js',
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def private_json(path, value, *, limit=MAX_OUTPUT):
    raw = host.encoded(value) + b'\n'
    if len(raw) > limit:
        raise RuntimeError('V30_PROBE_EVIDENCE_BOUND')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        identity = os.fstat(fd)
        if identity.st_mode & 0o777 != 0o600:
            raise RuntimeError('V30_PROBE_EVIDENCE_PRIVATE')
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            if written <= 0: raise RuntimeError('V30_PROBE_EVIDENCE_WRITE')
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)
    return (identity.st_dev, identity.st_ino)


def publish_final(path, value):
    """Commit success only after the candidate is closed and directory-synced."""
    placeholder = host.private(path)
    candidate = path.with_name(path.name + '.candidate')
    created = private_json(candidate, value)
    actual_placeholder = host.private(path)
    actual_candidate = host.private(candidate)
    if (actual_placeholder.st_dev, actual_placeholder.st_ino) != (placeholder.st_dev, placeholder.st_ino) \
            or (actual_candidate.st_dev, actual_candidate.st_ino) != created:
        raise RuntimeError('V30_PROBE_PUBLICATION_IDENTITY')
    os.replace(candidate, path)  # Last fallible step before the caller returns.


def source_snapshot(repo=ROOT):
    repo = Path(repo)
    pins = {relative: host.sha(host.canonical_file(repo, relative)) for relative in SOURCE_FILES}
    return {'cohort': host.COHORT, 'sourcePins': pins,
            'dependencyInventory': inventory(repo / 'node_modules')}


def current_host(repo=ROOT):
    repo = Path(repo)
    return validate_current_host(workspace=str(repo), profile=PROFILE,
        docker_host='unix://' + str(repo / '.qualification/goat-q/docker.sock'),
        node=str(repo / host.NODE_RELATIVE), node_sha256=host.NODE_SHA256,
        docker=str(repo / 'tasks/runtime/container/bin/docker'), docker_sha256=host.DOCKER_SHA256,
        daemon_id=host.DAEMON, image_id=host.IMAGE)


def validate_owner_write_paths(repo, parent, run, runtime):
    repo, parent, run, runtime = map(Path, (repo, parent, run, runtime))
    if parent != repo / 'tasks/qualification' or run.parent != parent \
            or runtime != run / 'runtime':
        raise RuntimeError('V30_PROBE_WRITE_SCOPE')
    for path in (parent, run, runtime, runtime / 'tmp'):
        host.private(path, directory=True)


def provision_statements(nonce, store):
    """Closed two-store equivalent of the reviewed agent-host disposable plan."""
    if not re.fullmatch(r'[a-f0-9]{12}', nonce) or store not in ('secureshop', 'secureshop_agents'):
        raise RuntimeError('V30_PROBE_STORE')
    migration = f'dvaia_{store}_migration'
    runtime = f'dvaia_{store}_runtime'
    database = f'dvaia_test_agent_host_{nonce}_{store}'
    return (
        f'CREATE ROLE {migration} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
        f'CREATE ROLE {runtime} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
        f'CREATE DATABASE {database} OWNER {migration}',
        f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC',
        f'GRANT CONNECT ON DATABASE {database} TO {migration},{runtime}',
    )


def may_retire_container(*, probe_attempted, probe_terminal, probe_report,
                         probe_group_absent, sandbox_group_absent):
    if not probe_attempted:
        return True
    return (probe_terminal is True and probe_report is True and
            probe_group_absent is True and sandbox_group_absent is True)


def retire_container_if_safe(command, *, creation_attempted, probe_attempted,
        probe_terminal, probe_report, probe_group_absent, sandbox_group_absent,
        name, labels, captured_id):
    if not creation_attempted:
        return None
    if not may_retire_container(probe_attempted=probe_attempted,
            probe_terminal=probe_terminal, probe_report=probe_report,
            probe_group_absent=probe_group_absent, sandbox_group_absent=sandbox_group_absent):
        raise RuntimeError('V30_PROBE_CONTAINER_RETAINED_UNCERTAIN')
    return cleanup_owned(command, daemon_id=host.DAEMON, name=name,
        labels=labels, image=host.IMAGE, captured_id=captured_id)


class Docker:
    def __init__(self, admitted, runtime, deadline):
        self.args = [admitted['docker'], '--host', admitted['dockerHost']]
        self.env = {'PATH': '/usr/bin:/bin', 'HOME': str(runtime),
            'TMPDIR': str(runtime / 'tmp'), 'XDG_CACHE_HOME': str(runtime / 'tmp'),
            'DOCKER_CONFIG': str(runtime)}
        self.deadline = deadline

    def __call__(self, parts, *, cap=8):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0: raise TimeoutError('V30_PROBE_TOTAL_TIMEOUT')
        deadline = time.monotonic() + min(cap, remaining)
        child = subprocess.Popen([*self.args, *parts], env=self.env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, start_new_session=True)
        streams = [bytearray(), bytearray()]; selector = None
        try:
            selector = selectors.DefaultSelector()
            for number, pipe in enumerate((child.stdout, child.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, number)
            while selector.get_map():
                if time.monotonic() >= deadline: raise TimeoutError('V30_PROBE_DOCKER_TIMEOUT')
                for key, _ in selector.select(min(.1, max(.001, deadline-time.monotonic()))):
                    data = os.read(key.fileobj.fileno(), min(8192, MAX_OUTPUT + 1))
                    if not data: selector.unregister(key.fileobj); continue
                    streams[key.data].extend(data)
                    if len(streams[0]) + len(streams[1]) > MAX_OUTPUT:
                        raise RuntimeError('V30_PROBE_DOCKER_OUTPUT_BOUND')
            code = child.wait(timeout=max(.001, deadline-time.monotonic()))
            return subprocess.CompletedProcess(parts, code,
                streams[0].decode('utf8', 'replace'), streams[1].decode('utf8', 'replace'))
        finally:
            failures = []
            if child.poll() is None:
                try: child.kill()
                except Exception as error: failures.append(error)
            try: child.wait(timeout=2)
            except Exception as error: failures.append(error)
            for resource in (selector, child.stdout, child.stderr):
                try:
                    if resource is not None: resource.close()
                except Exception as error: failures.append(error)
            if failures: raise RuntimeError('V30_PROBE_DOCKER_UNREAPED') from failures[0]


def required(command, parts, *, cap=8):
    result = command(parts, cap=cap)
    if result.returncode != 0:
        raise RuntimeError('V30_PROBE_DOCKER_COMMAND')
    return result.stdout.strip()


def prepare_stores(command, container_id, port, nonce):
    urls = {}
    for store in ('secureshop', 'secureshop_agents'):
        for statement in provision_statements(nonce, store):
            required(command, ['exec', container_id, 'psql', '-h', '127.0.0.1',
                '-p', '5432', '-U', 'postgres', '-d', 'postgres', '-v', 'ON_ERROR_STOP=1',
                '-c', statement])
        urls[store] = (f'postgresql://dvaia_{store}_runtime@127.0.0.1:{port}/'
                       f'dvaia_test_agent_host_{nonce}_{store}')
    return urls


def postgres_run_args(name, labels):
    if not re.fullmatch(r'dvaia-v30-original-disclosure-[a-f0-9]{12}', name) \
            or set(labels) != {'dvaia.owner', 'dvaia.cohort'} \
            or not uuid.UUID(labels['dvaia.owner']) or labels['dvaia.cohort'] != host.COHORT:
        raise RuntimeError('V30_PROBE_CONTAINER_IDENTITY')
    label_args = [value for key, item in labels.items() for value in ('--label', key + '=' + item)]
    return ['run', '--detach', '--pull', 'never', '--name', name, *label_args,
        '--memory', '512m', '--cpus', '2', '--pids-limit', '256',
        '--tmpfs', '/var/lib/postgresql:rw,size=268435456',
        '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-p', '127.0.0.1::5432',
        host.IMAGE, '-c', 'max_connections=64']


def choose_host_port():
    address = __import__('socket').socket()
    try:
        address.bind(('127.0.0.1', 0))
        return address.getsockname()[1]
    finally:
        address.close()


def inspect_probe_retirement(run, process, birth, api=None):
    """No PG retirement from a child exit code or self-claimed report alone."""
    if process is None or birth is None or process.poll() is None:
        return False, False, False, False
    api = api or LibProc()
    try:
        probe_group_absent = not owned_group_members(process.pid, api=api,
            births={process.pid: birth})
    except (OSError, RuntimeError):
        return False, False, False, False
    report_path = run / 'v30-boundary-probe.json'
    journal_path = run / 'v30-boundary-probe.jsonl'
    try:
        report_info = host.private(report_path)
        journal_info = host.private(journal_path)
        if not 0 < report_info.st_size <= MAX_OUTPUT or not 0 < journal_info.st_size <= MAX_OUTPUT:
            return False, probe_group_absent, False, False
        report = host.unique_json(report_path.read_bytes())
        rows = [host.unique_json(line) for line in journal_path.read_bytes().splitlines()]
        if not rows or any(type(row) is not dict or row.get('version') != 1 for row in rows):
            return False, probe_group_absent, False, False
        spawned = [row for row in rows if row.get('event') == 'spawned']
        born = [row for row in rows if row.get('event') == 'birth']
        retired = [row for row in rows if row.get('event') == 'retired']
        if len(spawned) > 1 or len(born) > 1 or len(born) > len(spawned) \
                or len(retired) != 1 or retired[0].get('processQuiescent') is not True:
            return False, probe_group_absent, False, False
        expected_inner_pid = spawned[0].get('pid') if spawned else None
        grant_path = run / 'v30-boundary-probe-grant.json'
        source_path = run / 'source-before.json'
        report_ok = (report.get('kind') == 'v30-combined-boundary-probe-v1'
            and report.get('cleanupVerified') is True
            and report.get('sourceUnchanged') is True
            and report.get('originalV30Qualified') is False
            and type(report.get('modelCalls')) is int and report['modelCalls'] == 0
            and report.get('databaseMutation') is False
            and type(report.get('terminal')) is dict
            and set(report['terminal']) == {'exitCode', 'signalCode'}
            and ((type(report['terminal']['exitCode']) is int and report['terminal']['exitCode'] >= 0
                and report['terminal']['signalCode'] is None)
                or (report['terminal']['exitCode'] is None
                    and type(report['terminal']['signalCode']) is str
                    and report['terminal']['signalCode'].startswith('SIG')))
            and report.get('grantSha256') == host.sha(grant_path)
            and report.get('sourceManifestSha256') == host.sha(source_path)
            and report.get('pid') == expected_inner_pid
            and bool(born) and report.get('birth') == born[0].get('birth'))
        if not spawned:
            sandbox_group_absent = True
        else:
            pid = spawned[0].get('pid')
            if type(pid) is not int or pid <= 1 or pid == process.pid:
                return False, probe_group_absent, False, False
            if born and (born[0].get('pid') != pid or type(born[0].get('birth')) is not list
                    or len(born[0]['birth']) != 2):
                return False, probe_group_absent, False, False
            births = {pid: tuple(born[0]['birth'])} if born else {}
            sandbox_group_absent = not owned_group_members(pid, api=api, births=births)
        return report_ok, probe_group_absent, sandbox_group_absent, report.get('passed') is True
    except (OSError, ValueError, RuntimeError):
        return False, probe_group_absent, False, False


def retire_probe_process(process, birth, *, api=None, seconds=20):
    """Signal only the captured same-birth child group, then prove it absent."""
    if process is None or birth is None:
        return False
    api = api or LibProc()
    deadline = time.monotonic() + seconds
    for name in ('SIGTERM', 'SIGKILL'):
        if process.poll() is not None: break
        identity = api.identity(process.pid)
        if identity is None or identity.uid != os.getuid() or identity.ruid != os.getuid() \
                or identity.ppid != os.getpid() or identity.pgid != process.pid \
                or (identity.start_sec, identity.start_usec) != birth:
            return False
        if owned_group_members(process.pid, api=api, births={process.pid:birth}):
            os.killpg(process.pid, getattr(signal, name))
        try: process.wait(timeout=min(8, max(.001, deadline-time.monotonic())))
        except subprocess.TimeoutExpired: continue
    if process.poll() is None: return False
    return not owned_group_members(process.pid, api=api, births={process.pid:birth})


def execute(repo=ROOT):
    if not LIVE_ENABLED: raise RuntimeError('V30_PROBE_PROVISION_UNQUALIFIED')
    if sys.platform != 'darwin': raise RuntimeError('V30_PROBE_DARWIN_REQUIRED')
    repo = Path(repo)
    admitted = current_host(repo)
    parent = evidence_parent(str(repo))
    nonce, owner = os.urandom(6).hex(), str(uuid.uuid4())
    run = parent / ('run-v30-boundary-' + nonce)
    os.mkdir(run, 0o700)
    runtime = run / 'runtime'; os.mkdir(runtime, 0o700)
    os.mkdir(runtime / 'tmp', 0o700)
    validate_owner_write_paths(repo, parent, run, runtime)
    beginning = time.monotonic()
    docker = Docker(admitted, runtime, beginning + WORK_SECONDS)
    name = CONTAINER_PREFIX + nonce
    labels = {'dvaia.owner': owner, 'dvaia.cohort': host.COHORT}
    captured_id = None; creation_attempted = False
    probe = None; probe_birth = None; probe_attempted = False
    probe_terminal = False; probe_report = False; probe_group_absent = False; sandbox_group_absent = False
    probe_passed = False
    cleanup = None; failure = None; grant_sha = None
    before = source_snapshot(repo)
    private_json(run / 'source-before.json', before, limit=SOURCE_LIMIT)
    result_path = run / 'v30-boundary-probe-owner-result.json'
    private_json(result_path, {'version': 1, 'kind': 'v30-disposable-boundary-probe-owner-v1',
        'passed': False, 'originalV30Qualified': False, 'modelCalls': 0,
        'status': 'incomplete'})
    try:
        verify_daemon(docker, host.DAEMON)
        verify_image(docker, host.IMAGE)
        if inspect_owned(docker, name=name, labels=labels, image=host.IMAGE) is not None:
            raise RuntimeError('V30_PROBE_NAME_OCCUPIED')
        run_args = postgres_run_args(name, labels)
        private_json(run / 'pg-create-intent.json', {'version': 1, 'name': name,
            'owner': owner, 'daemonId': host.DAEMON, 'imageId': host.IMAGE,
            'commandSha256': digest(host.encoded(run_args)),
            'sourceManifestSha256': host.sha(run / 'source-before.json')})
        creation_attempted = True
        created = required(docker, run_args, cap=45)
        if not re.fullmatch(r'[a-f0-9]{64}', created):
            raise RuntimeError('V30_PROBE_CONTAINER_ACK')
        captured_id = created
        row = inspect_owned(docker, name=name, labels=labels, image=host.IMAGE,
            captured_id=captured_id)
        if row is None: raise RuntimeError('V30_PROBE_CONTAINER_ABSENT')
        port = validate_container_layout(row)
        for _ in range(120):
            if time.monotonic() >= docker.deadline: raise TimeoutError('V30_PROBE_TOTAL_TIMEOUT')
            if docker(['exec', captured_id, 'pg_isready', '-h', '127.0.0.1',
                       '-p', '5432', '-U', 'postgres'], cap=2).returncode == 0: break
            time.sleep(.1)
        else: raise TimeoutError('V30_PROBE_POSTGRES_READINESS')
        count = required(docker, ['exec', captured_id, 'psql', '-h', '127.0.0.1',
            '-p', '5432', '-U', 'postgres', '-d', 'postgres', '-At', '-c',
            "SELECT count(*) FROM pg_database WHERE datname NOT IN ('postgres','template0','template1')"])
        if count != '0': raise RuntimeError('V30_PROBE_CLUSTER_NOT_FRESH')
        urls = prepare_stores(docker, captured_id, port, nonce)
        port_for_host = choose_host_port()
        grant = {'run': str(run), 'nodePath': admitted['node'],
            'nodeSha256': host.NODE_SHA256, 'sourceManifestSha256': host.sha(run / 'source-before.json'),
            'pgNonce': nonce, 'pgPort': port, 'hostPort': port_for_host,
            'commerceUrl': urls['secureshop'], 'agentsUrl': urls['secureshop_agents'],
            'containerId': captured_id, 'owner': owner}
        grant_file = run / 'v30-boundary-probe-grant.json'
        private_json(grant_file, grant)
        grant_sha = host.sha(grant_file)
        host.validate_grant(repo, grant)
        argv = [sys.executable, '-B', str(repo / 'tests/postgres/run_v30_controller_boundary_probe.py'), '--run', '--grant',
                str(grant_file), '--expected-grant-sha256', grant_sha]
        probe_attempted = True
        probe = subprocess.Popen(argv, cwd=repo,
            env={'PATH': '/usr/bin:/bin', 'HOME': str(runtime),
                 'XDG_CACHE_HOME': str(runtime / 'tmp'), 'PYTHONDONTWRITEBYTECODE': '1',
                 'TMPDIR': str(runtime / 'tmp')}, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True, start_new_session=True)
        api = LibProc(); identity = api.identity(probe.pid)
        if identity is None or identity.uid != os.getuid() or identity.ruid != os.getuid() \
                or identity.ppid != os.getpid() or identity.pgid != probe.pid \
                or os.getsid(probe.pid) != probe.pid or list(api.arguments(probe.pid)) != argv:
            raise RuntimeError('V30_PROBE_CHILD_BIRTH')
        probe_birth = (identity.start_sec, identity.start_usec)
        private_json(run / 'outer-probe-birth.json', {'version': 1, 'pid': probe.pid,
            'birth': list(probe_birth), 'argv': argv})
        if probe.wait(timeout=min(PROBE_SECONDS, max(.001, beginning + TOTAL_SECONDS - time.monotonic()))) != 0:
            raise RuntimeError('V30_PROBE_CHILD_FAILED')
        probe_terminal = True
        probe_report, probe_group_absent, sandbox_group_absent, probe_passed = inspect_probe_retirement(
            run, probe, probe_birth, api)
        if not may_retire_container(probe_attempted=probe_attempted,
                probe_terminal=probe_terminal, probe_report=probe_report,
                probe_group_absent=probe_group_absent, sandbox_group_absent=sandbox_group_absent):
            raise RuntimeError('V30_PROBE_CHILD_CLEANUP_UNCERTAIN')
        if not probe_passed: raise RuntimeError('V30_PROBE_CASE_FAILED')
    except BaseException as error:
        failure = type(error).__name__
    finally:
        if probe is not None and probe.poll() is None:
            try:
                if not retire_probe_process(probe, probe_birth):
                    failure = failure or 'V30_PROBE_CHILD_UNREAPED'
            except BaseException as error:
                failure = failure or ('probe-retirement:' + type(error).__name__)
        if probe is not None and probe.poll() is not None and probe_birth is not None:
            try:
                probe_terminal = True
                probe_report, probe_group_absent, sandbox_group_absent, probe_passed = inspect_probe_retirement(
                    run, probe, probe_birth)
            except BaseException as error:
                failure = failure or ('probe-inspection:' + type(error).__name__)
        if creation_attempted:
            docker.deadline = min(beginning + TOTAL_SECONDS, time.monotonic() + CLEANUP_SECONDS)
            try:
                cleanup = retire_container_if_safe(docker,
                    creation_attempted=creation_attempted, probe_attempted=probe_attempted,
                    probe_terminal=probe_terminal, probe_report=probe_report,
                    probe_group_absent=probe_group_absent, sandbox_group_absent=sandbox_group_absent,
                    name=name, labels=labels, captured_id=captured_id)
            except BaseException as error:
                failure = failure or ('cleanup:' + type(error).__name__)
        try: source_unchanged = source_snapshot(repo) == before
        except BaseException as error:
            source_unchanged = False
            failure = failure or ('source-postflight:' + type(error).__name__)
        removed = cleanup is not None and cleanup.get('status') == 'removed_absence_verified'
        result = {'version': 1, 'kind': 'v30-disposable-boundary-probe-owner-v1',
            'passed': failure is None and probe_passed and removed and source_unchanged
                and time.monotonic() <= beginning + TOTAL_SECONDS,
            'originalV30Qualified': False, 'modelCalls': 0, 'databaseProvisioned': creation_attempted,
            'containerId': captured_id, 'containerCleanup': cleanup,
            'probeAttempted': probe_attempted, 'probeTerminal': probe_terminal,
            'probeCleanupVerified': probe_report and probe_group_absent and sandbox_group_absent,
            'sourceUnchanged': source_unchanged, 'grantSha256': grant_sha, 'error': failure}
        publish_final(result_path, result)
    if not result['passed']: raise RuntimeError('V30_PROBE_OWNER_FAILED')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--plan', action='store_true')
    mode.add_argument('--run', action='store_true')
    args = parser.parse_args(argv)
    if args.plan:
        admitted = current_host()
        print(json.dumps({'liveEnabled': LIVE_ENABLED, 'probeLiveEnabled': boundary_probe.PROBE_LIVE_ENABLED,
            'originalV30Qualified': False, 'modelCalls': 0, 'databaseStores': 2,
            'postgresImageId': admitted['postgresImageId'], 'workSeconds': WORK_SECONDS,
            'probeSeconds': PROBE_SECONDS, 'cleanupSeconds': CLEANUP_SECONDS,
            'acceptanceBudgetSeconds': TOTAL_SECONDS}, sort_keys=True))
        return 0
    execute()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
