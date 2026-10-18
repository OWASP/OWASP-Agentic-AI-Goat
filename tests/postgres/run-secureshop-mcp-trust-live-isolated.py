#!/usr/bin/env python3
"""Run the launch-owned SecureShop MCP trust actual actor and Judge workflow in one owned PostgreSQL 18 container."""

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
from sensitive_info_recovery_safety import SignalGate

parser = argparse.ArgumentParser()
parser.add_argument('--docker-host', required=True)
parser.add_argument('--grant-id', required=True)
parser.add_argument('--grant-file', default='tasks/native-verification-slot.json')
args = parser.parse_args()
EXPECTED_DOCKER_HOST = 'unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
if args.docker_host != EXPECTED_DOCKER_HOST:
    raise RuntimeError('Exact owned Colima verification Docker host is required')
source = Path(__file__).resolve().parents[2]
grant_path = (source / args.grant_file).resolve() if not Path(args.grant_file).is_absolute() else Path(args.grant_file)
grant_lock = grant_path.with_suffix(grant_path.suffix + '.consume-lock')
root = Path(tempfile.mkdtemp(prefix='dvaia-secureshop-mcp-trust-live-'))
workspace = root / 'source'
workspace.mkdir()
os.chmod(root, 0o700)
base_env = {key: os.environ[key] for key in ['PATH','HOME','TMPDIR'] if key in os.environ}
managed_node = Path(base_env.get('HOME','/nonexistent')) / '.dvaia/runtimes/node-v26.8.2-darwin-arm64/bin'
base_env['PATH'] = str(managed_node) + os.pathsep + base_env.get('PATH','')
docker = ['docker','--host',args.docker_host]
container = 'dvaia-secureshop-mcp-trust-live-' + uuid.uuid4().hex[:12]
ownership_path = root / 'ownership.json'
tracked = [
    'scripts/register-native-owner-handle.py',
    'tests/postgres/sensitive_info_recovery_safety.py',
    'db/postgres/migrate.js',
    'db/postgres/identity-migrations/0045_secureshop_persona_inbox_identity.sql',
    'db/postgres/identity-migrations/0046_graph_judge_validation_code.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0010_secureshop_persona_inbox.sql',
    'docs/modernization/drafts/secureshop-mcp-trust-identity.sql',
    'docs/modernization/drafts/secureshop-mcp-trust-agents.sql',
    'server/database/postgres/identityRepository.js',
    'server/database/postgres/secureshopAgentsDb.js',
    'server/database/postgres/secureshopLaunchRepository.js',
    'server/database/postgres/secureshopResetCleanupAuthorityRepository.js',
    'server/database/postgres/secureshopTargetReconciliationRepository.js',
    'server/database/postgres/secureshopBoundMcpRepository.js',
    'server/database/postgres/secureshopBoundConversationsRepository.js',
    'server/database/postgres/secureshopTurnRequestsRepository.js',
    'server/database/postgres/secureshopConversationLifecycleRepository.js',
    'server/database/postgres/secureshopConversationCleanupCheckpointRepository.js',
    'server/database/postgres/secureshopProgressCleanupCheckpointRepository.js',
    'server/database/postgres/objectiveJudgmentRepository.js',
    'server/database/postgres/workshopProgressRepository.js',
    'server/agent-runtime/runCoordinator.js',
    'server/agent-runtime/postgresRunLedger.js',
    'server/agent-runtime/secureshopSupervisorGraph.js',
    'server/agent-runtime/objectiveJudge.js',
    'server/agent-runtime/judgeErrors.js',
    'server/agent-runtime/providers/langchainProvider.js',
    'server/agent-runtime/providers/finalResponseContract.js',
    'server/services/secureshop/providerRouter.js',
    'server/services/secureshop/providers/ollamaProvider.js',
    'server/services/secureshopTurnAdmission.js',
    'server/services/secureshopBoundTurns.js',
    'server/services/secureshopBoundAgentRunner.js',
    'server/services/secureshopBoundConversation.js',
    'server/services/secureshopConversationBinding.js',
    'server/services/secureshopConversationLifecycle.js',
    'server/services/secureshopModelQualification.js',
    'server/services/objectiveCompletionService.js',
    'server/services/secureshopLaunchResetCoordinator.js',
    'server/services/secureshopMcpOwnedFixture.js',
    'server/services/secureshopMcpControlledServer.js',
    'server/services/secureshopMcpSdkTransport.js',
    'server/services/secureshopMcpControlledTargetPool.js',
    'server/services/secureshopMcpTrustApplication.js',
    'server/services/secureshopMcpTrustTools.js',
    'server/services/secureshopMcpTrustExternalAdapter.js',
    'server/services/secureshopMcpTrustExecutionConfig.js',
    'server/services/secureshopMcpTrustEvidence.js',
    'server/services/secureshopMcpTrustAssessment.js',
    'server/services/secureshopMcpTrustComposition.js',
    'server/services/secureshopMcpTrustBoundRunner.js',
    'server/services/secureshopMcpTrustResetAdapter.js',
    'server/services/secureshopReviewResetCoordinator.js',
    'tests/postgres/secureshopMcpTrustQualifierSchema.js',
    'tests/postgres/mcpJudgeInputCapture.js',
    'tests/postgres/secureshopMcpTrustLive.integration.test.js',
    'tests/postgres/run-secureshop-mcp-trust-live-isolated.py',
]
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
ownership = {'version':1,'owner':'/root/agent_loop_review','launcherPid':os.getpid(),
    'workspace':str(root),'container':container,'grantId':args.grant_id,
    'grantFile':str(grant_path),'status':'prepared','runStatus':'preparing','cleanupStatus':'pending',
    'startedAt':datetime.now(timezone.utc).isoformat(),
    'sourceSha256':{name:digest(source / name) for name in tracked},'cleanup':None}
started = False
creation_attempted = False
child = None
frozen_hashes = None

def persist_ownership():
    pending = ownership_path.with_suffix('.json.pending')
    descriptor=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(descriptor,'w') as output: output.write(json.dumps(ownership,sort_keys=True) + '\n')
    os.replace(pending,ownership_path)

persist_ownership()
node_version=subprocess.run([str(managed_node/'node'),'--version'],check=True,env=base_env,
    capture_output=True,text=True,timeout=10).stdout.strip()
if node_version!='v26.8.2': raise RuntimeError('Managed Node 26.8.2 is required')
ownership['nodeVersion']=node_version; persist_ownership()

def consume_grant():
    global frozen_hashes
    try:
        grant_lock.mkdir(mode=0o700)
    except FileExistsError as cause:
        raise RuntimeError('Native verification grant is already being consumed') from cause
    try:
        grant = json.loads(grant_path.read_text())
        if grant.get('grantId') != args.grant_id or grant.get('status') != 'granted' \
                or grant.get('owner') != '/root/agent_loop_review' or grant.get('allowedLaunches') != 1 \
                or grant.get('dockerHost') != args.docker_host:
            raise RuntimeError('Exact unconsumed native verification grant is required')
        frozen_hashes=grant.get('sourceHashes')
        if not isinstance(frozen_hashes,dict) or set(frozen_hashes)!=set(tracked) \
                or any(ownership['sourceSha256'][name]!=frozen_hashes[name] for name in tracked):
            raise RuntimeError('Frozen native verification source hashes differ')
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

def await_owner_handle():
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        grant = json.loads(grant_path.read_text())
        handle = grant.get('ownerHandle')
        if grant.get('grantId') == args.grant_id and grant.get('status') == 'consumed' \
                and grant.get('consumerPid') == os.getpid() \
                and isinstance(handle, int) and handle > 0:
            ownership['ownerHandle'] = handle
            ownership['status'] = 'owner_handle_registered'
            persist_ownership()
            return
        time.sleep(.1)
    raise RuntimeError('Actual exec owner handle was not registered before Docker use')

def persist_terminal_grant():
    try:
        grant_lock.mkdir(mode=0o700)
    except FileExistsError as cause:
        raise RuntimeError('Native verification grant ledger is busy during terminal update') from cause
    try:
        grant=json.loads(grant_path.read_text())
        if grant.get('grantId')!=args.grant_id or grant.get('status')!='consumed' \
                or grant.get('owner')!='/root/agent_loop_review' or grant.get('consumerPid')!=os.getpid() \
                or grant.get('ownerHandle')!=ownership.get('ownerHandle'):
            raise RuntimeError('Consumed native verification grant changed before terminal update')
        grant.update({'runStatus':ownership['runStatus'],'completedAt':ownership['finishedAt'],
            'cleanup':ownership['cleanup'],'resultSha256':ownership.get('resultSha256'),
            'ownershipSha256':digest(ownership_path)})
        pending=grant_path.with_suffix(grant_path.suffix+'.pending')
        descriptor=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(descriptor,'w') as output:
            json.dump(grant,output,indent=2,sort_keys=True);output.write('\n');output.flush();os.fsync(output.fileno())
        os.replace(pending,grant_path)
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

signal_gate = SignalGate()
signal.signal(signal.SIGTERM,signal_gate.handler)
signal.signal(signal.SIGINT,signal_gate.handler)
run_error = None
try:
    consume_grant()
    await_owner_handle()
    for directory in ['server','db','tests','docs']:
        shutil.copytree(source / directory,workspace / directory,ignore=ignore)
    copied={name:digest(workspace/name) for name in tracked if not name.startswith('scripts/')}
    copied_mismatches=[name for name,value in copied.items() if value!=frozen_hashes[name]]
    if copied_mismatches: raise RuntimeError('Copied native verification source hashes differ')
    ownership['snapshotAudit']={'verifiedBeforeDocker':True,'copiedTrackedCount':len(copied),
        'originalHelperSha256':ownership['sourceSha256']['scripts/register-native-owner-handle.py'],
        'mismatches':copied_mismatches};persist_ownership()
    (workspace / 'node_modules').symlink_to(source / 'node_modules',target_is_directory=True)
    creation_attempted=True; ownership['containerCreationAttempted']=True; persist_ownership()
    run(docker + ['run','--detach','--name',container,
        '--tmpfs','/var/lib/postgresql:rw,size=268435456',
        '-e','POSTGRES_USER=mcp_trust_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust',
        '-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432','postgres:18',
        '-c','shared_buffers=16MB','-c','max_connections=48','-c','max_wal_size=16MB','-c','min_wal_size=4MB'],
        stdout=subprocess.DEVNULL)
    started=True; ownership['status']='container_started'; persist_ownership()
    deadline=time.monotonic()+25; stable=0
    while time.monotonic()<deadline:
        ready=subprocess.run(docker+['exec',container,'pg_isready','-h','127.0.0.1','-U','mcp_trust_admin'],env=base_env,
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
        if ready.returncode==0:
            running=run(docker+['inspect','--format','{{.State.Running}}',container],capture_output=True,text=True).stdout.strip()=='true'
            stable=stable+1 if running else 0
            if stable>=3: break
        else: stable=0
        time.sleep(.25)
    else: raise RuntimeError('Owned PostgreSQL container did not become ready')
    port=int(run(docker+['port',container,'5432'],capture_output=True,text=True).stdout.strip().rsplit(':',1)[1])
    psql=['psql','-h','127.0.0.1','-p',str(port),'-U','mcp_trust_admin','-d','postgres','-v','ON_ERROR_STOP=1']
    stores=[('identity','dvaia_identity_migration','dvaia_identity_runtime'),
            ('agents','dvaia_secureshop_agents_migration','dvaia_secureshop_agents_runtime')]
    urls={}
    for label,migration_role,runtime_role in stores:
        for role in [migration_role,runtime_role]:
            run(psql+['-c',f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],stdout=subprocess.DEVNULL)
        database=f'dvaia_test_secureshop_mcp_trust_{label}'
        run(psql+['-c',f'CREATE DATABASE {database} OWNER {migration_role}'],stdout=subprocess.DEVNULL)
        run(psql+['-c',f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration_role}, {runtime_role}'],stdout=subprocess.DEVNULL)
        urls[label]={'migration':f'postgresql://{quote(migration_role)}@127.0.0.1:{port}/{database}',
                     'runtime':f'postgresql://{quote(runtime_role)}@127.0.0.1:{port}/{database}'}
    env=dict(base_env,NODE_ENV='test',PLATFORM_DATABASE_ENGINE='postgres',PG_TEST_DISPOSABLE='yes',LIVE_OLLAMA_TEST='1',
        OLLAMA_BASE_URL=os.environ.get('OLLAMA_BASE_URL','http://127.0.0.1:11434'),OLLAMA_MODEL='llama3.1:8b',
        JUDGE_PROVIDER='ollama',JUDGE_MODEL='llama3.1:8b',
        DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace), AWS_EC2_METADATA_DISABLED='true',
        PG_SECURESHOP_MCP_TRUST_LIVE_IDENTITY_MIGRATION_URL=urls['identity']['migration'],
        PG_SECURESHOP_MCP_TRUST_LIVE_IDENTITY_RUNTIME_URL=urls['identity']['runtime'],
        PG_SECURESHOP_MCP_TRUST_LIVE_AGENTS_MIGRATION_URL=urls['agents']['migration'],
        PG_SECURESHOP_MCP_TRUST_LIVE_AGENTS_RUNTIME_URL=urls['agents']['runtime'])
    log_path=root/'result.log'
    log_descriptor=os.open(log_path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(log_descriptor,'w') as log:
        ownership['status']='test_running'; ownership['runStatus']='running'; ownership['testPid']=None; persist_ownership()
        child=subprocess.Popen(['node','--test','--test-reporter=tap',
            'tests/postgres/secureshopMcpTrustLive.integration.test.js'],cwd=workspace,env=env,
            stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        ownership['testPid']=child.pid; persist_ownership()
        try: code=child.wait(timeout=420)
        except subprocess.TimeoutExpired:
            stop_child(); raise RuntimeError('SecureShop MCP trust actual actor and Judge workflow timed out')
    if code: raise RuntimeError(f'SecureShop MCP trust actual actor and Judge workflow failed ({code})')
    ownership['resultSha256']=digest(log_path)
    ownership['status']='terminal_pass'; ownership['runStatus']='terminal_pass'; persist_ownership()
except BaseException as error:
    run_error=error
    ownership['status']='terminal_fail'; ownership['runStatus']='terminal_fail'; ownership['errorType']=type(error).__name__
    log_path=root/'result.log'
    if log_path.exists(): ownership['resultSha256']=digest(log_path)
    persist_ownership()
    raise
finally:
    signal_gate.protect_cleanup(); cleanup_errors=[]; removed=None; exact_absent=None; absence_return_code=None
    try: stop_child()
    except Exception as error: cleanup_errors.append(f'child:{type(error).__name__}')
    if creation_attempted:
        try: removed=subprocess.run(docker+['rm','--force',container],env=base_env,stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,timeout=30,check=False)
        except Exception as error: cleanup_errors.append(f'remove:{type(error).__name__}')
    try:
        absence=subprocess.run(docker+['ps','-a','--filter',f'name=^{container}$','--format','{{.Names}}'],env=base_env,
            capture_output=True,text=True,timeout=30,check=False)
        absence_return_code=absence.returncode; exact_absent=absence.returncode==0 and absence.stdout.strip()==''
        if absence.returncode!=0: cleanup_errors.append('absence:NonZeroExit')
    except Exception as error: cleanup_errors.append(f'absence:{type(error).__name__}')
    ownership['cleanup']={'removeReturnCode':None if removed is None else removed.returncode,
        'absenceQueryReturnCode':absence_return_code,'exactNameAbsent':exact_absent,
        'containerCreationAttempted':creation_attempted,'containerStarted':started,
        'signals':signal_gate.received,'errors':cleanup_errors}
    cleanup_failed=bool(cleanup_errors or exact_absent is not True or (started and (removed is None or removed.returncode!=0)))
    ownership['cleanupStatus']='failed' if cleanup_failed else 'complete'
    ownership['finishedAt']=datetime.now(timezone.utc).isoformat(); persist_ownership()
    terminal_ledger_error=None
    if ownership.get('grantConsumedAt'):
        try:
            ownership['terminalLedgerStatus']='complete';persist_ownership();persist_terminal_grant()
        except Exception as error:
            terminal_ledger_error=error;ownership['terminalLedgerStatus']='failed';ownership['terminalLedgerError']=type(error).__name__;persist_ownership()
    print(f'Run {ownership["runStatus"]}; cleanup {ownership["cleanupStatus"]}; evidence retained: {root}',flush=True)
    if run_error is None and (cleanup_failed or terminal_ledger_error is not None):
        raise RuntimeError('Owned qualifier cleanup or terminal ledger update did not complete')
