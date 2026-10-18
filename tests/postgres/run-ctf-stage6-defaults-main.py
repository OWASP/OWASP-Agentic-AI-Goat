#!/usr/bin/env python3
"""Owned, no-copy current-main Stage 6 CTF default/migration qualification."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
REQUIRED = {
    'tests/postgres/run-ctf-stage6-defaults-main.py',
    'tests/postgres/ctfStageDefaultProvenance.integration.test.js',
    'tests/postgres/currentMigrationTails.integration.test.js',
    'tests/postgres/ctfStage6ReviewerProfile.integration.test.js',
    'tests/postgres/sql_nosql_process_ownership.py',
    'tests/postgres/sql_nosql_docker_ownership.py',
    'tests/helpers/loadCtfDbForProvenance.js',
    'tests/fixtures/ctfDefaults.previous.js',
    'tests/fixtures/ctfStage6PriorDefaults.js',
    'server/data/ctfDefaults.js',
    'server/database/postgres/ctfDb.js',
    'server/database/postgres/ctfStageDefaultProvenance.js',
    'server/database/postgres/workshopSupport.js',
    'server/database/postgres/index.js',
    'server/data/ctfSolutions.js',
    'server/services/ctfDefenseLayers.js',
    'server/services/promptInjectionCTF.js',
    'server/agent-runtime/ctfStageJudge.js',
    'db/postgres/migrate.js',
    'package.json', 'package-lock.json', 'node_modules/pg/package.json',
}


def digest(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def parse_args():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    for name in ('manifest', 'manifest-sha256', 'docker-host', 'docker-cli',
                 'docker-cli-sha256', 'docker-daemon', 'node', 'node-sha256',
                 'python-sha256', 'image-id'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--plan', action='store_true')
    return parser.parse_args()


def validate(args):
    if ROOT.resolve() != ROOT or Path(__file__).resolve() != ROOT / 'tests/postgres/run-ctf-stage6-defaults-main.py':
        raise RuntimeError('Exact current main required')
    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute() or manifest_path.is_symlink() or digest(manifest_path) != args.manifest_sha256:
        raise RuntimeError('Exact external manifest required')
    manifest = json.loads(manifest_path.read_text())
    if manifest.get('cohort') != 'ctf-stage6-defaults-main' or manifest.get('repoRoot') != str(ROOT):
        raise RuntimeError('Wrong source manifest')
    pins = manifest.get('sourcePins')
    required = REQUIRED | {path.relative_to(ROOT).as_posix()
                           for path in (ROOT / 'db/postgres/workshop-migrations/ctf').glob('*.sql')}
    required |= {path.relative_to(ROOT).as_posix() for directory in
                 ('db/postgres/identity-migrations',)
                 for path in (ROOT / directory).glob('*.sql')}
    if not isinstance(pins, dict) or set(pins) != required:
        raise RuntimeError('Incomplete or expanded source pins')
    for relative, expected in pins.items():
        source = ROOT / relative
        if source.is_symlink() or not source.is_file() or not source.resolve().is_relative_to(ROOT) or digest(source) != expected:
            raise RuntimeError('Current-main source drift')
    for path, expected in ((args.node, args.node_sha256), (args.docker_cli, args.docker_cli_sha256)):
        binary = Path(path)
        if not binary.is_absolute() or binary.is_symlink() or binary.resolve() != binary or digest(binary) != expected:
            raise RuntimeError('Runtime pin mismatch')
    python = Path(sys.executable).resolve(strict=True)
    if digest(python) != args.python_sha256:
        raise RuntimeError('Running Python pin mismatch')
    if not args.docker_host.startswith('unix:///') or len(args.image_id) != 71 or not args.image_id.startswith('sha256:'):
        raise RuntimeError('Owned local Docker socket and image ID required')
    socket = Path(args.docker_host.removeprefix('unix://'))
    if socket.is_symlink() or not stat.S_ISSOCK(socket.stat().st_mode):
        raise RuntimeError('Owned local Docker socket required')
    return pins


def publish(path, value):
    fd, temporary = tempfile.mkstemp(prefix='.receipt-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(value, handle, sort_keys=True)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_helper(name, pins):
    relative = 'tests/postgres/' + name + '.py'
    path = ROOT / relative
    if digest(path) != pins[relative]:
        raise RuntimeError('Helper pin drift')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    args = parse_args()
    pins = validate(args)
    if args.plan:
        print(json.dumps({'cohort': 'ctf-stage6-defaults-main', 'allocation': False,
                          'sourceCopied': False, 'stores': ['ctf-fresh', 'ctf-populated', 'ctf-tail', 'identity-profile'],
                          'tests': ['ctfStageDefaultProvenance', 'currentMigrationTails CTF',
                                    'ctfStage6ReviewerProfile']}))
        return 0
    if shutil.disk_usage(ROOT).free < 3 * 1024 ** 3:
        raise RuntimeError('Owned runtime space plus reserve required')
    process_helper = load_helper('sql_nosql_process_ownership', pins)
    docker_helper = load_helper('sql_nosql_docker_ownership', pins)
    parent = ROOT / 'backups/private-recovery/ctf-stage6-defaults-main'
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if parent.is_symlink() or parent.resolve() != parent or parent.stat().st_mode & 0o777 != 0o700:
        raise RuntimeError('Private owned evidence directory required')
    evidence = Path(tempfile.mkdtemp(prefix='run-', dir=parent))
    for folder in ('home', 'tmp', 'logs'):
        (evidence / folder).mkdir(mode=0o700)
    owner = uuid.uuid4().hex
    name = 'dvaia-ctf-stage6-defaults-' + owner[:12]
    labels = {'dvaia.owner': owner, 'dvaia.cohort': 'ctf-stage6-defaults-main'}
    clean = {'PATH': str(Path(args.node).parent) + ':' + str(Path(args.docker_cli).parent) + ':/usr/bin:/bin',
             'HOME': str(evidence / 'home'), 'TMPDIR': str(evidence / 'tmp'),
             'LANG': 'C', 'DOCKER_HOST': args.docker_host}
    state = {'cohort': 'ctf-stage6-defaults-main', 'owner': owner,
             'containerName': name, 'labels': labels, 'imageId': args.image_id,
             'manifestSha256': args.manifest_sha256, 'sourceRoot': str(ROOT),
             'sourceCopied': False, 'children': [], 'nativeStarted': False}
    def record(): publish(evidence / 'ownership.json', state)
    deadline = time.monotonic() + 420
    def remaining(cap):
        value = min(cap, deadline - time.monotonic())
        if value <= 0:
            raise TimeoutError('Qualification deadline')
        return value
    def docker(argv, input_text=None):
        return subprocess.run([args.docker_cli, '--host', args.docker_host, *argv],
                              input=input_text, env=clean, text=True, capture_output=True,
                              timeout=remaining(30))
    def checked(argv, input_text=None):
        result = docker(argv, input_text)
        if result.returncode:
            raise RuntimeError('Owned Docker/PostgreSQL command failed')
        return result.stdout
    def members(pgid, sid):
        result = subprocess.run(['/bin/ps', '-axo', 'pid=,pgid=,uid='],
                                capture_output=True, text=True, check=True, timeout=remaining(2))
        found = []
        for line in result.stdout.splitlines():
            pid, group, uid = map(int, line.split())
            if group != pgid:
                continue
            try:
                if uid != os.getuid() or os.getsid(pid) != sid:
                    raise RuntimeError('Unknown process group identity')
            except ProcessLookupError:
                continue
            found.append(pid)
        return found
    def stop_group(child, pgid, sid):
        if members(pgid, sid):
            os.killpg(pgid, signal.SIGTERM)
        until = time.monotonic() + remaining(10)
        while members(pgid, sid) and time.monotonic() < until:
            time.sleep(.05)
        if members(pgid, sid):
            os.killpg(pgid, signal.SIGKILL)
        child.wait(timeout=remaining(10))
        if members(pgid, sid):
            raise RuntimeError('Owned child remains')
    owned = process_helper.OwnedProcesses(stop_group, lambda row: (state['children'].append(row), record()))
    owned.install()
    captured = None
    attempted = False
    failures = []
    code = 1
    try:
        state['phase'] = 'daemon-image'; record()
        docker_helper.verify_daemon(lambda argv: docker(argv), args.docker_daemon)
        docker_helper.verify_image(lambda argv: docker(argv), args.image_id)
        if docker_helper.inspect_owned(lambda argv: docker(argv), name=name, labels=labels, image=args.image_id):
            raise RuntimeError('Container name collision')
        attempted = True
        state['phase'] = 'container-create'; record()
        checked(['run', '--detach', '--pull', 'never', '--name', name,
                 *sum((['--label', key + '=' + value] for key, value in labels.items()), []),
                 '--memory', '1g', '--cpus', '2', '--pids-limit', '256',
                 '--tmpfs', '/var/lib/postgresql:rw,size=805306368',
                 '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-p', '127.0.0.1::5432',
                 args.image_id, '-c', 'max_connections=64', '-c', 'shared_buffers=32MB'])
        row = docker_helper.inspect_owned(lambda argv: docker(argv), name=name,
                                          labels=labels, image=args.image_id)
        captured = row['Id']
        host, ports = row['HostConfig'], row['NetworkSettings']['Ports']
        if (row['Mounts'] or host['Memory'] != 1073741824 or host['NanoCpus'] != 2000000000
                or host['PidsLimit'] != 256 or host['Tmpfs'] != {'/var/lib/postgresql': 'rw,size=805306368'}
                or set(ports) != {'5432/tcp'} or len(ports['5432/tcp']) != 1
                or ports['5432/tcp'][0]['HostIp'] != '127.0.0.1'):
            raise RuntimeError('Owned container layout mismatch')
        port = int(ports['5432/tcp'][0]['HostPort'])
        state.update(containerId=captured, port=port, phase='postgres-ready'); record()
        psql = ['exec', '-i', captured, 'psql', '-h', '127.0.0.1', '-p', '5432',
                '-U', 'postgres', '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
        for _ in range(100):
            if docker(['exec', captured, 'pg_isready', '-h', '127.0.0.1', '-p', '5432', '-U', 'postgres']).returncode == 0:
                break
            time.sleep(.1)
        else:
            raise RuntimeError('Owned PostgreSQL readiness deadline')
        if checked(psql + ['-Atc', "SELECT count(*) FROM pg_database WHERE datname NOT IN ('postgres','template0','template1')"]).strip() != '0':
            raise RuntimeError('Owned cluster not empty')
        checked(psql, 'CREATE ROLE dvaia_ctf_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE dvaia_ctf_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE dvaia_identity_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE dvaia_identity_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;')
        nonce = owner[:12]
        names = {
            'fresh': 'dvaia_ctf_provenance_fresh_' + nonce,
            'populated': 'dvaia_ctf_provenance_populated_' + nonce,
            'tail': 'dvaia_test_ctf_stage6_tail_' + nonce,
            'identity': 'dvaia_test_ctf_stage6_profile_' + nonce,
        }
        for label, database in names.items():
            family = 'identity' if label == 'identity' else 'ctf'
            checked(psql, 'CREATE DATABASE ' + database + ' OWNER dvaia_' + family + '_migration;')
            checked(psql, 'REVOKE CONNECT ON DATABASE ' + database + ' FROM PUBLIC; '
                    'GRANT CONNECT ON DATABASE ' + database + ' TO dvaia_' + family + '_migration,dvaia_' + family + '_runtime;')
        env = {**clean, 'PG_TEST_DISPOSABLE': 'yes', 'CTF_PROVENANCE_NATIVE': '1',
               'CTF_STAGE6_PROFILE_ISOLATED': '1', 'WORKSHOP_DATABASE_ENGINE': 'postgres',
               'PLATFORM_DATABASE_ENGINE': 'postgres', 'NODE_ENV': 'test',
               'DVAIA_ISOLATED_TEST_WORKSPACE': str(evidence / 'tmp')}
        for label in ('fresh', 'populated'):
            env['CTF_PROVENANCE_' + label.upper() + '_MIGRATION_URL'] = (
                f'postgresql://dvaia_ctf_migration@127.0.0.1:{port}/{names[label]}')
            env['CTF_PROVENANCE_' + label.upper() + '_RUNTIME_URL'] = (
                f'postgresql://dvaia_ctf_runtime@127.0.0.1:{port}/{names[label]}')
        env['PG_CURRENT_MIGRATION_TAILS_POPULATED_CTF_MIGRATION_URL'] = (
            f'postgresql://dvaia_ctf_migration@127.0.0.1:{port}/{names["tail"]}')
        env['PG_CURRENT_MIGRATION_TAILS_POPULATED_CTF_RUNTIME_URL'] = (
            f'postgresql://dvaia_ctf_runtime@127.0.0.1:{port}/{names["tail"]}')
        env['PG_CTF_STAGE6_PROFILE_IDENTITY_MIGRATION_URL'] = (
            f'postgresql://dvaia_identity_migration@127.0.0.1:{port}/{names["identity"]}')
        env['PG_CTF_STAGE6_PROFILE_IDENTITY_RUNTIME_URL'] = (
            f'postgresql://dvaia_identity_runtime@127.0.0.1:{port}/{names["identity"]}')
        for label, filename in [('provenance', 'ctfStageDefaultProvenance.integration.test.js'),
                                ('tail', 'currentMigrationTails.integration.test.js'),
                                ('identity-profile', 'ctfStage6ReviewerProfile.integration.test.js')]:
            state['phase'] = 'test-' + label; record()
            log_path = evidence / (label + '.tap')
            with log_path.open('x') as log:
                os.fchmod(log.fileno(), 0o600)
                command = [args.node, '--test', '--test-concurrency=1', str(ROOT / 'tests/postgres' / filename)]
                child = owned.launch(command,
                                     name=label, cwd=ROOT, env=env,
                                     stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                state['nativeStarted'] = True; record()
                until = time.monotonic() + remaining(180)
                while child.poll() is None:
                    if log_path.stat().st_size > 8 * 1024 ** 2 or time.monotonic() >= until:
                        raise TimeoutError('Native child/log budget')
                    time.sleep(.1)
                result = child.returncode
                owned.finish(child)
                if result:
                    raise RuntimeError('Native CTF migration test failed')
        code = 0
    except BaseException as error:
        state['failure'] = {'type': type(error).__name__, 'phase': state.get('phase')}
    finally:
        deadline = time.monotonic() + 120
        owned.mask_cleanup_signals()
        try:
            owned.cleanup()
        except BaseException as error:
            failures.append({'phase': 'process-cleanup', 'type': type(error).__name__})
        try:
            if attempted:
                state['containerCleanup'] = docker_helper.cleanup_owned(
                    lambda argv: docker(argv), daemon_id=args.docker_daemon, name=name,
                    labels=labels, image=args.image_id, captured_id=captured)
        except BaseException as error:
            failures.append({'phase': 'container-cleanup', 'type': type(error).__name__})
        try:
            validate(args)
            state['sourceUnchanged'] = True
        except BaseException as error:
            failures.append({'phase': 'source-integrity', 'type': type(error).__name__})
        state['cleanupFailures'] = failures
        state['status'] = 'passed' if code == 0 and not failures else 'failed'
        record()
        owned.restore()
    print(json.dumps({'evidenceRoot': str(evidence), 'status': state['status']}))
    return 0 if state['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
