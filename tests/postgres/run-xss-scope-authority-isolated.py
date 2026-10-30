#!/usr/bin/env python3
"""Closed XSS authority/store suites against one owned disposable PostgreSQL DB."""
import argparse
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import uuid

spec = importlib.util.spec_from_file_location(
    'owned_qualification', Path(__file__).with_name('run-csrf-email-composed-isolated.py'))
owned = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owned)
owned.OWNER_LABEL = 'org.owasp-ai-goat.xss-scope-owner'
owned.NONCE_LABEL = 'org.owasp-ai-goat.xss-scope-nonce'

SUITES = {
    'application-upgrade': ('identity', 'owasp_ai_goat_test_xss_upgrade_identity', 'PG_XSS_UPGRADE_IDENTITY', 'xssApplicationUpgrade.integration.test.js'),
    'deletion-finalizers': ('identity', 'owasp_ai_goat_test_deletion_identity', 'PG_STUDENT_DELETION_FINALIZER_IDENTITY', 'studentDeletionFinalizers.integration.test.js'),
    'parent-admission-race': ('identity', 'owasp_ai_goat_test_xss_parent_admission_identity', 'PG_XSS_PARENT_ADMISSION', 'xssParentAdmissionRace.integration.test.js'),
    'parent-recovery-composed': ('identity', 'owasp_ai_goat_test_xss_recovery_identity', 'PG_XSS_RECOVERY_IDENTITY', 'xssParentRecoveryComposed.integration.test.js'),
    'xss-judgment-child': ('identity', 'owasp_ai_goat_test_xss_judgment_test_native', 'PG_XSS_JUDGMENT_TEST', 'xssJudgmentChildBinding.integration.test.js'),
    'scope-authority': ('identity', 'owasp_ai_goat_test_xss_scope_authority_identity', 'PG_XSS_SCOPE', 'xssScopeAuthority.integration.test.js'),
    'profile-origin': ('xss', 'owasp_ai_goat_test_xss_profile_origin', 'PG_XSS_PROFILE_ORIGIN', 'xssProfileOrigin.integration.test.js'),
    'profile-reset': ('xss', 'owasp_ai_goat_test_xss_scoped_profile_reset', 'PG_XSS_SCOPED_PROFILE', 'xssScopedProfileReset.integration.test.js'),
    'profile-journal': ('identity', 'owasp_ai_goat_test_xss_profile_reset_journal', 'PG_XSS_PROFILE_JOURNAL', 'xssProfileResetJournal.integration.test.js'),
}


def main():
    parser = argparse.ArgumentParser()
    for key in ('docker-host', 'docker-cli', 'docker-cli-sha256', 'docker-server-id',
                'node', 'node-sha256', 'source-manifest-sha256', 'dependency-manifest-sha256'):
        parser.add_argument('--' + key, required=True)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--suite', choices=tuple(SUITES), default='scope-authority')
    args = parser.parse_args()
    if not args.run:
        print('plan: no resources launched')
        return
    node = owned.validate_executable(args.node, args.node_sha256, 'Managed Node')
    cli = owned.validate_executable(args.docker_cli, args.docker_cli_sha256, 'Docker CLI')
    env = {key: os.environ[key] for key in ('PATH', 'HOME', 'TMPDIR') if key in os.environ}
    env['PATH'] = str(node.parent) + ':' + env.get('PATH', '')
    docker = [str(cli), '--host', args.docker_host]
    owned.validate_docker_authority(docker, env, args.docker_server_id)
    owned.validate_image(docker, env, owned.POSTGRES_IMAGE)
    evidence = Path(tempfile.mkdtemp(prefix='owasp-ai-goat-xss-scope-'))
    evidence.chmod(0o700)
    workspace = evidence / 'source'
    workspace.mkdir(mode=0o700)
    snapshot = owned.copy_frozen_source(Path(__file__).resolve().parents[2], workspace,
                                       args.source_manifest_sha256, args.dependency_manifest_sha256)
    owned.write_private_json(evidence / 'admission.json', {
        **snapshot, 'nodeSha256': args.node_sha256, 'dockerServerId': args.docker_server_id,
        'suite': args.suite, 'testFile': SUITES[args.suite][3]})
    nonce = uuid.uuid4().hex
    intent = {'name': 'owasp-ai-goat-xss-scope-' + nonce[:12], 'nonce': nonce,
              'image': owned.POSTGRES_IMAGE, 'kind': 'postgres'}
    owned.write_private_json(evidence / 'container-intent.json', intent)
    child = None
    primary = None
    finalizing = False
    previous = {}

    def interrupted(signum, _frame):
        if not finalizing:
            raise owned.OwnedSignalExit(128 + signum)

    def run(command, **kwargs):
        return subprocess.run(command, env=env, timeout=60, check=True, **kwargs)

    for sig in (signal.SIGINT, signal.SIGTERM):
        previous[sig] = signal.signal(sig, interrupted)
    try:
        intent['containerId'] = run(owned.container_command(docker, name=intent['name'],
            nonce=nonce, image=intent['image'], kind='postgres'), capture_output=True, text=True).stdout.strip()
        owned.inspect_owned(intent, docker, env)
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            ready = subprocess.run(docker + ['exec', intent['containerId'], 'pg_isready',
                '-h', '127.0.0.1', '-U', 'csrf_email_admin'], env=env, timeout=2,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if ready.returncode == 0:
                break
            time.sleep(.25)
        else:
            raise RuntimeError('Owned PostgreSQL readiness timeout')
        port = int(run(docker + ['port', intent['containerId'], '5432/tcp'],
                       capture_output=True, text=True).stdout.strip().rsplit(':', 1)[1])
        psql = docker + ['exec', intent['containerId'], 'psql', '-U', 'csrf_email_admin',
                         '-d', 'postgres', '-v', 'ON_ERROR_STOP=1', '-c']
        store, database, prefix, test_file = SUITES[args.suite]
        stores = [(store, database, prefix)]
        if args.suite == 'application-upgrade':
            stores.append(('xss', 'owasp_ai_goat_test_xss_upgrade_store', 'PG_XSS_UPGRADE_STORE'))
        if args.suite == 'parent-recovery-composed':
            stores.append(('xss', 'owasp_ai_goat_test_xss_recovery_store', 'PG_XSS_RECOVERY_STORE'))
        if args.suite == 'deletion-finalizers':
            stores.extend([('xss', 'owasp_ai_goat_test_deletion_xss', 'PG_STUDENT_DELETION_FINALIZER_XSS'),
                           ('finflow', 'owasp_ai_goat_test_deletion_finflow', 'PG_STUDENT_DELETION_FINALIZER_FINFLOW')])
        child_env = dict(env, NODE_ENV='test', PG_TEST_DISPOSABLE='yes', AWS_EC2_METADATA_DISABLED='true')
        for store, database, prefix in stores:
            migration_role, runtime_role = f'dvaia_{store}_migration', f'dvaia_{store}_runtime'
            for role in (migration_role, runtime_role):
                run(psql + [f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'], stdout=subprocess.DEVNULL)
            run(psql + [f'CREATE DATABASE {database} OWNER {migration_role}'], stdout=subprocess.DEVNULL)
            run(psql + [f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration_role},{runtime_role}'], stdout=subprocess.DEVNULL)
            child_env[prefix + '_MIGRATION_URL'] = f'postgresql://{migration_role}@127.0.0.1:{port}/{database}'
            child_env[prefix + '_RUNTIME_URL'] = f'postgresql://{runtime_role}@127.0.0.1:{port}/{database}'
        child = owned.launch_child([str(node), '--test', '--test-reporter=tap',
            'tests/postgres/' + test_file], name='xss-scope-qualification',
            workspace=workspace, env=child_env, intent_path=evidence / 'child-intent.json')
        code, size = owned.stream_child(child, evidence / 'result.tap', 180)
        if code != 0:
            raise RuntimeError(f'XSS scope qualification failed ({code})')
        tap = owned.validate_tap_result(evidence / 'result.tap')
        owned.write_private_json(evidence / 'result.json', {'returncode': code,
            'tap': tap, 'tapBytes': size, 'tapSha256': owned.sha256(evidence / 'result.tap')})
    except BaseException as error:
        primary = error
    finally:
        finalizing = True
        errors = owned.capture_container_logs([intent], docker, env, evidence) if primary else []
        processes = []
        if child is not None:
            try:
                code = owned.stop_group(child, env=env)
                processes.append({'pid': child.pid, 'pgid': child._owned_pgid, 'absent': True, 'returncode': code})
            except Exception as error:
                errors.append(error)
                processes.append({'pid': child.pid, 'pgid': child._owned_pgid, 'absent': False})
        containers, failures = owned.cleanup_containers([intent], docker, env)
        errors.extend(failures)
        owned.write_private_json(evidence / 'cleanup.json', {'processes': processes,
            'containers': containers, 'terminalCleanup': not errors})
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        print(f'Owned evidence retained at {evidence}', flush=True)
        owned.add_cleanup_errors(primary, errors)
    if primary is not None:
        raise primary


if __name__ == '__main__':
    main()
