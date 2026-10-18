#!/usr/bin/env python3
"""Qualify identity0065 in an immutable package and an owned disposable cluster."""
import sys
sys.dont_write_bytecode = True
import argparse, fcntl, importlib.util, json, os, subprocess, uuid
from pathlib import Path
from full_backend_auth_contract import validate_package, prepare_evidence_root, digest, validate_fullboot_layout
from sql_nosql_docker_ownership import verify_daemon, verify_image, inspect_owned, cleanup_owned, CONTAINER
from sql_nosql_process_ownership import OwnedProcesses
from mcp_connected_baseline_contract import validate_docker_cli

SCOPE = 'ipi_email_canonical_migration'
TEST = 'tests/postgres/ipiEmailCanonicalMigration.integration.test.js'
CANDIDATE = 'docs/modernization/drafts/0065_ipi_email_artifacts_v2.sql'
DATABASES = ('fresh', 'populated', 'rollback')
BASE_ENV = {'PATH': '/usr/bin:/bin'}

def parser():
    result = argparse.ArgumentParser()
    for name in ['docker-host','docker-daemon-id','postgres-image-id','docker-cli','docker-cli-sha256',
                 'package','manifest','manifest-sha256','node','node-sha256','evidence-root',
                 'control','owner-handle','slot']:
        result.add_argument('--'+name, required=True)
    return result

def private_json(path):
    path = Path(path)
    stat = path.lstat()
    if not path.is_file() or path.is_symlink() or stat.st_uid != os.getuid() or stat.st_mode & 0o077:
        raise RuntimeError('Private owned control file required')
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise RuntimeError('Control object required')
    return value

def write_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.' + str(os.getpid()) + '.pending')
    with temporary.open('x') as output:
        os.chmod(temporary, 0o600)
        json.dump(value, output, sort_keys=True); output.write('\n'); output.flush(); os.fsync(output.fileno())
    os.replace(temporary, path)

def validate_grant(grant, values):
    if grant.get('scope') != SCOPE or grant.get('owner') != '/root' or grant.get('status') != 'granted' or grant.get('allowedLaunches') != 1:
        raise RuntimeError('Fresh exact-scope grant required')
    if any(grant.get(key) != value for key, value in values.items()):
        raise RuntimeError('Grant argument binding mismatch')
    if set(grant) != set(values) | {'scope','owner','status','allowedLaunches','priorSlot'}:
        raise RuntimeError('Unexpected grant field')
    if not str(values['owner_handle']).isdecimal() or int(values['owner_handle']) <= 0:
        raise RuntimeError('Actual returned owner handle required')

def consume(args):
    slot = Path(args.slot)
    with slot.with_name('native-verification.lock').open('a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        grant = private_json(args.control)
        validate_grant(grant, vars(args))
        prior = json.loads(slot.read_text())
        if prior != grant['priorSlot'] or prior.get('status') not in ['terminal_pass_cleaned','terminal_fail_cleaned'] or prior.get('cleanupVerified') is not True:
            raise RuntimeError('Exact cleaned predecessor required')
        write_json(Path(args.control).with_name('prior-slot.json'), prior)
        grant.update(status='consumed', launcherPid=os.getpid())
        write_json(args.control, grant)
        write_json(slot, {'status':'consumed','scope':SCOPE,'owner':'/root','ownerHandle':int(args.owner_handle),
            'launcherPid':os.getpid(),'candidateSourceRoot':args.package,'candidateManifestSha256':args.manifest_sha256,
            'controlRoot':str(Path(args.control).parent),'evidenceRoot':args.evidence_root,'allowedLaunches':1})

def main():
    args = parser().parse_args()
    source = Path(args.package)
    def validate():
        manifest = validate_package(source,args.manifest,args.manifest_sha256,args.node,args.node_sha256)
        if any(name not in manifest['files'] for name in [TEST,CANDIDATE,'docs/modernization/drafts/0065_ipi_email_artifacts.sql']):
            raise RuntimeError('Migration qualification closure missing')
        return manifest
    validate()
    helpers = ['run-ipi-email-canonical-migration-isolated.py','run-full-backend-auth-isolated.py',
        'full_backend_auth_contract.py','sql_nosql_package_contract.py','sql_nosql_docker_ownership.py',
        'sql_nosql_process_ownership.py','mcp_connected_baseline_contract.py']
    for name in helpers:
        if digest(Path(__file__).parent/name) != digest(source/'tests/postgres'/name):
            raise RuntimeError('Executing helper differs from frozen package')
    docker_cli = validate_docker_cli(args.docker_cli,args.docker_cli_sha256)
    root = prepare_evidence_root(args.evidence_root,[source,Path(__file__).resolve().parents[2]])
    consume(args)
    spec = importlib.util.spec_from_file_location('qualified_full_launcher',source/'tests/postgres/run-full-backend-auth-isolated.py')
    shared = importlib.util.module_from_spec(spec); spec.loader.exec_module(shared)
    docker = [docker_cli,'--host',args.docker_host]
    def command(arguments):
        return subprocess.run(docker+arguments,env=BASE_ENV,capture_output=True,text=True,timeout=30)
    def run(arguments):
        result = command(arguments)
        if result.returncode: raise RuntimeError('Owned Docker operation failed')
        return result
    def record(name,value): write_json(root/name,value)
    nonce = str(uuid.uuid4()); name = 'dvaia-ipi-email-0065-'+nonce
    labels = {'dvaia.qualification':SCOPE,'dvaia.owner-uid':str(os.getuid()),'dvaia.run-nonce':nonce}
    processes = OwnedProcesses(shared.stop_group,lambda value:record('process-'+value['name']+'.json',value))
    intended = False; captured = None; passed = False; failures = []; children = []
    processes.install()
    try:
        verify_daemon(command,args.docker_daemon_id); verify_image(command,args.postgres_image_id)
        record('ownership.json',{'ownerHandle':int(args.owner_handle),'launcherPid':os.getpid(),'manifestSha256':args.manifest_sha256})
        record('container-intent.json',{'name':name,'labels':labels,'imageId':args.postgres_image_id,'daemonId':args.docker_daemon_id})
        intended = True
        labelargs = [value for key,value in labels.items() for value in ['--label',key+'='+value]]
        result = run(['run','--detach','--name',name]+labelargs+['--tmpfs','/var/lib/postgresql:rw,size=1073741824',
            '-e','POSTGRES_USER=ownership_test_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1',
            '-p','127.0.0.1::5432',args.postgres_image_id,'-c','shared_buffers=16MB','-c','max_connections=40',
            '-c','max_wal_size=16MB','-c','min_wal_size=4MB'])
        if not CONTAINER.fullmatch(result.stdout.strip()): raise RuntimeError('Captured container identity missing')
        captured = result.stdout.strip()
        row = inspect_owned(command,name=name,labels=labels,image=args.postgres_image_id,captured_id=captured)
        port = validate_fullboot_layout(row)
        record('container-created.json',{'containerId':captured,'port':port,'labels':labels})
        import time
        deadline = time.monotonic()+30
        while command(['exec',captured,'pg_isready','-h','127.0.0.1','-U','ownership_test_admin']).returncode:
            if time.monotonic()>deadline: raise RuntimeError('Owned PostgreSQL readiness timeout')
            time.sleep(.25)
        def sql(statement):
            return run(['exec',captured,'psql','-h','127.0.0.1','-U','ownership_test_admin','-d','postgres','-v','ON_ERROR_STOP=1','-c',statement])
        for role in ['dvaia_identity_migration','dvaia_identity_runtime']:
            sql(f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
        runtime = root/'runtime'; runtime.mkdir(mode=0o700)
        env = dict(BASE_ENV,NODE_ENV='test',PG_TEST_DISPOSABLE='yes',IPI_EMAIL_0065_ISOLATED='1',
            PLATFORM_DATABASE_ENGINE='postgres',IPI_EMAIL_0065_RUNTIME_ROOT=str(runtime),
            DVAIA_ISOLATED_TEST_WORKSPACE=str(source),HOME=str(runtime),AWS_EC2_METADATA_DISABLED='true')
        for variant in DATABASES:
            database = 'dvaia_test_ipi_email_0065_'+variant
            sql(f'CREATE DATABASE {database} OWNER dvaia_identity_migration')
            sql(f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO dvaia_identity_migration,dvaia_identity_runtime')
            for role in ['migration','runtime']:
                env[f'PG_IPI_EMAIL_0065_{variant.upper()}_{role.upper()}_URL'] = f'postgresql://dvaia_identity_{role}@127.0.0.1:{port}/{database}'
        with (root/'result.tap').open('x') as output:
            os.chmod(root/'result.tap',0o600)
            child = processes.launch([args.node,'--test','--test-reporter=tap',TEST],name='qualification',cwd=source,
                env=env,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
            children.append(child)
            try: code = child.wait(timeout=240)
            finally: processes.finish(child)
        if code: raise RuntimeError('Migration qualification failed')
        report = (root/'result.tap').read_text()
        if '# pass 2' not in report or '# fail 0' not in report or '# skipped 0' not in report:
            raise RuntimeError('Native migration assertions did not all execute')
        passed = True
    finally:
        processes.mask_cleanup_signals()
        try:
            try: processes.cleanup(); shared.assert_owned_children_absent(children)
            except BaseException: failures.append('process_cleanup')
            if intended:
                try: record('container-cleanup.json',cleanup_owned(command,daemon_id=args.docker_daemon_id,name=name,labels=labels,image=args.postgres_image_id,captured_id=captured))
                except BaseException: failures.append('container_cleanup')
            try: validate()
            except BaseException: failures.append('immutable_postflight')
            record('terminal.json',{'status':'passed_cleaned' if passed and not failures else 'failed','failures':failures,
                'ownerHandle':int(args.owner_handle),'manifestSha256':args.manifest_sha256,
                'resultSha256':digest(root/'result.tap') if (root/'result.tap').exists() else None})
        finally: processes.restore()
        if failures: raise RuntimeError('Qualification cleanup requires recovery')

if __name__ == '__main__': main()
