#!/usr/bin/env python3
"""Run the draft SecureShop persona-inbox DB contract in one owned PostgreSQL 18 container."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
from urllib.parse import quote

parser = argparse.ArgumentParser()
parser.add_argument('--docker-host', required=True)
parser.add_argument('--grant-id', required=True)
parser.add_argument('--grant-file', default='tasks/native-verification-slot.json')
args = parser.parse_args()
source = Path(__file__).resolve().parents[2]
grant_path = (source / args.grant_file).resolve() if not Path(args.grant_file).is_absolute() else Path(args.grant_file)
grant_lock = grant_path.with_suffix(grant_path.suffix + '.consume-lock')
root = Path(tempfile.mkdtemp(prefix='owasp-ai-goat-secureshop-persona-inbox-'))
workspace = root / 'source'
workspace.mkdir()
os.chmod(root, 0o700)
base_env = {key: os.environ[key] for key in ['PATH','HOME','TMPDIR'] if key in os.environ}
managed_node = Path(base_env.get('HOME','/nonexistent')) / '.owasp-ai-goat/runtimes/node-v26.8.2-darwin-arm64/bin'
base_env['PATH'] = str(managed_node) + os.pathsep + base_env.get('PATH','')
docker = ['docker','--host',args.docker_host]
container = 'owasp-ai-goat-secureshop-persona-inbox-' + uuid.uuid4().hex[:12]
ownership_path = root / 'ownership.json'
tracked = [
    'docs/modernization/drafts/secureshop-persona-inbox-identity.sql',
    'docs/modernization/drafts/secureshop-persona-inbox-agents.sql',
    'server/database/postgres/secureshopPersonaInboxRepository.js',
    'server/services/secureshopPersonaInboxPriorAdvisoryReader.js',
    'tests/postgres/secureshopPersonaInbox.integration.test.js',
    'tests/postgres/run-secureshop-persona-inbox-isolated.py',
]
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
ownership = {'version':1,'owner':'/root/agent_loop_review','launcherPid':os.getpid(),
    'workspace':str(root),'container':container,'grantId':args.grant_id,
    'grantFile':str(grant_path),'status':'prepared','startedAt':datetime.now(timezone.utc).isoformat(),
    'sourceSha256':{name:digest(source / name) for name in tracked},'cleanup':None}
started = False
child = None

def persist_ownership():
    pending = ownership_path.with_suffix('.json.pending')
    pending.write_text(json.dumps(ownership,sort_keys=True) + '\n')
    os.replace(pending,ownership_path)

persist_ownership()

def consume_grant():
    try:
        grant_lock.mkdir(mode=0o700)
    except FileExistsError as cause:
        raise RuntimeError('Native verification grant is already being consumed') from cause
    try:
        grant = json.loads(grant_path.read_text())
        if grant.get('grantId') != args.grant_id or grant.get('status') != 'granted' \
                or grant.get('owner') != '/root/agent_loop_review' or grant.get('allowedLaunches') != 1:
            raise RuntimeError('Exact unconsumed native verification grant is required')
        grant['status'] = 'consumed'
        grant['consumedAt'] = datetime.now(timezone.utc).isoformat()
        grant['consumerPid'] = os.getpid()
        grant['evidence'] = str(root)
        grant['container'] = container
        pending = grant_path.with_suffix(grant_path.suffix + '.pending')
        pending.write_text(json.dumps(grant,indent=2,sort_keys=True) + '\n')
        os.replace(pending,grant_path)
        ownership['grantConsumedAt'] = grant['consumedAt']
        ownership['status'] = 'grant_consumed'
        persist_ownership()
    finally:
        grant_lock.rmdir()

def run(command,**kwargs):
    kwargs.setdefault('timeout',60)
    return subprocess.run(command,check=True,env=base_env,**kwargs)

def ignore(_directory,names):
    denied={'.git','node_modules','build','logs','uploads','sensitive_files','workshop_data',
            'vector-indexes','coverage','.cache','__pycache__'}
    return [name for name in names if name in denied or name.startswith('.env') or
            any(name.endswith(suffix) for suffix in
                ['.db','.db-wal','.db-shm','.db-journal','.sqlite','.sqlite3','.log'])]

def stop_child():
    global child
    if child is not None and child.poll() is None:
        os.killpg(os.getpgid(child.pid),signal.SIGTERM)
        try: child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(child.pid),signal.SIGKILL)
            child.wait(timeout=5)

def interrupted(signum,_frame):
    stop_child()
    raise SystemExit(128+signum)

signal.signal(signal.SIGTERM,interrupted)
consume_grant()
for directory in ['server','db','tests','docs']:
    shutil.copytree(source / directory,workspace / directory,ignore=ignore)
(workspace / 'node_modules').symlink_to(source / 'node_modules',target_is_directory=True)

try:
    run(docker + ['run','--detach','--name',container,
        '--tmpfs','/var/lib/postgresql:rw,size=268435456',
        '-e','POSTGRES_USER=persona_inbox_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust',
        '-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432','postgres:18',
        '-c','shared_buffers=16MB','-c','max_connections=48','-c','max_wal_size=16MB','-c','min_wal_size=4MB'],
        stdout=subprocess.DEVNULL)
    started=True; ownership['status']='container_started'; persist_ownership()
    deadline=time.monotonic()+25; stable=0
    while time.monotonic()<deadline:
        ready=subprocess.run(docker+['exec',container,'pg_isready','-h','127.0.0.1','-U','persona_inbox_admin'],env=base_env,
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
        if ready.returncode==0:
            running=run(docker+['inspect','--format','{{.State.Running}}',container],capture_output=True,text=True).stdout.strip()=='true'
            stable=stable+1 if running else 0
            if stable>=3: break
        else: stable=0
        time.sleep(.25)
    else: raise RuntimeError('Owned PostgreSQL container did not become ready')
    port=int(run(docker+['port',container,'5432'],capture_output=True,text=True).stdout.strip().rsplit(':',1)[1])
    psql=['psql','-h','127.0.0.1','-p',str(port),'-U','persona_inbox_admin','-d','postgres','-v','ON_ERROR_STOP=1']
    stores=[('identity','dvaia_identity_migration','dvaia_identity_runtime'),
            ('agents','dvaia_secureshop_agents_migration','dvaia_secureshop_agents_runtime')]
    urls={}
    for label,migration_role,runtime_role in stores:
        for role in [migration_role,runtime_role]:
            run(psql+['-c',f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],stdout=subprocess.DEVNULL)
        database=f'owasp_ai_goat_test_secureshop_persona_inbox_{label}'
        run(psql+['-c',f'CREATE DATABASE {database} OWNER {migration_role}'],stdout=subprocess.DEVNULL)
        run(psql+['-c',f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration_role}, {runtime_role}'],stdout=subprocess.DEVNULL)
        urls[label]={'migration':f'postgresql://{quote(migration_role)}@127.0.0.1:{port}/{database}',
                     'runtime':f'postgresql://{quote(runtime_role)}@127.0.0.1:{port}/{database}'}
    env=dict(base_env,NODE_ENV='test',PLATFORM_DATABASE_ENGINE='postgres',PG_TEST_DISPOSABLE='yes',
        OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(workspace),
        PG_SECURESHOP_PERSONA_INBOX_IDENTITY_MIGRATION_URL=urls['identity']['migration'],
        PG_SECURESHOP_PERSONA_INBOX_IDENTITY_RUNTIME_URL=urls['identity']['runtime'],
        PG_SECURESHOP_PERSONA_INBOX_AGENTS_MIGRATION_URL=urls['agents']['migration'],
        PG_SECURESHOP_PERSONA_INBOX_AGENTS_RUNTIME_URL=urls['agents']['runtime'])
    log_path=root/'result.log'
    with log_path.open('w') as log:
        ownership['status']='test_running'; ownership['testPid']=None; persist_ownership()
        child=subprocess.Popen(['node','--test','--test-reporter=tap',
            'tests/postgres/secureshopPersonaInbox.integration.test.js'],cwd=workspace,env=env,
            stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        ownership['testPid']=child.pid; persist_ownership()
        try: code=child.wait(timeout=90)
        except subprocess.TimeoutExpired:
            stop_child(); raise RuntimeError('SecureShop persona inbox integration timed out')
    print(log_path.read_text(),flush=True)
    if code: raise RuntimeError(f'SecureShop persona inbox integration failed ({code})')
    ownership['resultSha256']=digest(log_path)
    ownership['status']='test_passed'; persist_ownership()
finally:
    stop_child()
    if started:
        removed=subprocess.run(docker+['rm','--force',container],env=base_env,stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,timeout=30)
        remaining=run(docker+['ps','-a','--filter',f'name=^{container}$','--format','{{.Names}}'],capture_output=True,text=True).stdout.strip()
        ownership['cleanup']={'removeReturnCode':removed.returncode,'exactNameAbsent':remaining==''}
        ownership['status']='cleaned' if removed.returncode==0 and not remaining else 'cleanup_failed'
        ownership['finishedAt']=datetime.now(timezone.utc).isoformat(); persist_ownership()
        if remaining: raise RuntimeError('Owned PostgreSQL container cleanup did not complete')
    else:
        ownership['cleanup']={'removeReturnCode':None,'exactNameAbsent':True,'containerNeverStarted':True}
        ownership['status']='cleaned_without_container'; ownership['finishedAt']=datetime.now(timezone.utc).isoformat(); persist_ownership()
    print(f'Owned container {container} cleanup recorded at {ownership_path}; evidence retained: {root}',flush=True)
