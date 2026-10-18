#!/usr/bin/env python3
"""Single-use PG18 gate for persona-inbox drafts on identity0044/agents0009."""
import argparse, fcntl, hashlib, json, os, shutil, signal, subprocess, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from sensitive_info_recovery_safety import SignalGate

EXPECTED_DOCKER = 'unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
OWNER = '/root/secureshop_architecture'
SOURCE = Path(__file__).resolve().parents[2]
NODE_BIN = Path('/Users/averma5/.dvaia/runtimes/node-v26.8.2-darwin-arm64/bin')

parser=argparse.ArgumentParser()
parser.add_argument('--docker-host',required=True);parser.add_argument('--grant-file',required=True)
parser.add_argument('--grant-id',required=True);args=parser.parse_args()
if args.docker_host != EXPECTED_DOCKER: raise SystemExit('the reviewed isolated PostgreSQL Docker daemon is required')
grant_path=Path(args.grant_file).resolve()
if grant_path != (SOURCE/'tasks/native-verification-slot.json').resolve():
    raise SystemExit('the durable repository grant file is required')

evidence=Path(tempfile.mkdtemp(prefix='dvaia-secureshop-persona-current-'));os.chmod(evidence,0o700)
workspace=evidence/'source';workspace.mkdir()
container=f'dvaia-secureshop-persona-current-{uuid.uuid4().hex[:12]}'
ownership_path=evidence/'ownership.json';result_path=evidence/'result.log'
base_env={key:os.environ[key] for key in ('PATH','HOME','TMPDIR') if key in os.environ}
base_env['PATH']=f'{NODE_BIN}:{base_env.get("PATH","")}'
docker=['docker','--host',args.docker_host]
state={'owner':OWNER,'grantId':args.grant_id,'dockerHost':args.docker_host,'container':container,
       'evidence':str(evidence),'launcherPid':os.getpid(),'ownerHandle':None,
       'createdAt':datetime.now(timezone.utc).isoformat(),'runStatus':'preparing','cleanup':None}
def write_state(): ownership_path.write_text(json.dumps(state,indent=2)+'\n');os.chmod(ownership_path,0o600)
def run(command,**kwargs):
    kwargs.setdefault('timeout',90)
    return subprocess.run(command,check=True,env=kwargs.pop('env',base_env),**kwargs)
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def exact_container_absence():
    listed=subprocess.run(docker+['ps','-a','--filter',f'name=^/{container}$','--format','{{.Names}}'],
      env=base_env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=30)
    if listed.returncode!=0: raise RuntimeError('exact-name container query failed')
    return not listed.stdout.strip()
write_state()

node_version=run([str(NODE_BIN/'node'),'--version'],stdout=subprocess.PIPE,text=True).stdout.strip()
if node_version!='v26.8.2': raise RuntimeError('managed Node 26.8.2 is required')
preflight_hashes={
  'docs/modernization/drafts/secureshop-persona-inbox-identity.sql':'a7736a4dfa7277b713f19c2842418eefba376f221b94702b8bab661ed70c824c',
  'docs/modernization/drafts/secureshop-persona-inbox-agents.sql':'3855742f3a716f8498611a7fce8b442c8759706974dc0a45a14a810dc968ec45',
}
for name,expected in preflight_hashes.items():
    if digest(SOURCE/name)!=expected: raise RuntimeError('qualified persona draft bytes changed')
for target in (SOURCE/'db/postgres/identity-migrations/0045_secureshop_persona_inbox_identity.sql',
               SOURCE/'db/postgres/workshop-migrations/secureshop_agents/0010_secureshop_persona_inbox.sql'):
    if target.exists(): raise RuntimeError('persona candidate migration is already registered')
state['nodeVersion']=node_version;write_state()
if not exact_container_absence(): raise RuntimeError('owned container name unexpectedly already exists')

with grant_path.open('r+') as grant_file:
    fcntl.flock(grant_file.fileno(),fcntl.LOCK_EX);grant=json.load(grant_file)
    if (grant.get('grantId')!=args.grant_id or grant.get('owner')!=OWNER or grant.get('status')!='granted'
            or grant.get('allowedLaunches')!=1 or grant.get('dockerHost')!=EXPECTED_DOCKER):
        raise RuntimeError('single-use persona current-head grant is absent, mismatched, or consumed')
    grant.update({'status':'consumed','consumedAt':datetime.now(timezone.utc).isoformat(),
      'launcherPid':os.getpid(),'ownerHandle':None,'container':container,'evidence':str(evidence),'runStatus':'preparing'})
    grant_file.seek(0);json.dump(grant,grant_file,indent=2);grant_file.write('\n');grant_file.truncate();grant_file.flush();os.fsync(grant_file.fileno())

# Docker cannot start until the orchestrator records the returned exec session.
for _ in range(600):
    with grant_path.open() as grant_file:
        fcntl.flock(grant_file.fileno(),fcntl.LOCK_SH);registered=json.load(grant_file)
    handle=registered.get('ownerHandle')
    if (registered.get('grantId')==args.grant_id and registered.get('launcherPid')==os.getpid()
            and isinstance(handle,int) and handle>0 and handle!=os.getpid()):
        state['ownerHandle']=handle;state['runStatus']='owner_registered';write_state();break
    time.sleep(.1)
else:
    state['runStatus']='owner_registration_failed';state['cleanup']={'containerAbsent':True,'containerNeverStarted':True};write_state()
    raise RuntimeError('actual exec session owner handle was not registered before Docker')

def ignore(_directory,names):
    denied={'.git','node_modules','build','logs','uploads','sensitive_files','workshop_data','vector-indexes','coverage','.cache','__pycache__'}
    return [name for name in names if name in denied or name.startswith('.env') or
      any(name.endswith(suffix) for suffix in ('.db','.db-wal','.db-shm','.db-journal','.sqlite','.sqlite3','.log'))]
for directory in ('server','db','tests','docs'):
    shutil.copytree(SOURCE/directory,workspace/directory,ignore=ignore)
(workspace/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
tracked=['docs/modernization/drafts/secureshop-persona-inbox-identity.sql',
 'docs/modernization/drafts/secureshop-persona-inbox-agents.sql',
 'db/postgres/identity-migrations/0044_sensitive_info_aggregate_reset.sql',
 'db/postgres/workshop-migrations/secureshop_agents/0009_secureshop_bound_persona_renewal.sql',
 'server/database/postgres/secureshopPersonaInboxRepository.js',
 'server/services/secureshopPersonaInboxAvailability.js','server/services/secureshopBoundReviewComposition.js',
 'tests/postgres/secureshopPersonaInboxCurrentHead.integration.test.js',
 'tests/postgres/run-secureshop-persona-current-head-isolated.py']
state['sourceSha256']={name:digest(workspace/name) for name in tracked}
write_state()

child=None;started=False;creation_attempted=False;cleanup_failed=False
def stop_child():
    global child
    if child is not None and child.poll() is None:
        os.killpg(os.getpgid(child.pid),signal.SIGTERM)
        try: child.wait(timeout=5)
        except subprocess.TimeoutExpired: os.killpg(os.getpgid(child.pid),signal.SIGKILL);child.wait(timeout=5)
signal_gate=SignalGate()
signal.signal(signal.SIGTERM,signal_gate.handler);signal.signal(signal.SIGINT,signal_gate.handler)

try:
    creation_attempted=True;state['containerCreationAttempted']=True;write_state()
    run(docker+['run','--detach','--name',container,'--tmpfs','/var/lib/postgresql:rw,size=402653184',
      '-e','POSTGRES_USER=persona_current_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust',
      '-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432','postgres:18',
      '-c','shared_buffers=16MB','-c','max_connections=48','-c','max_wal_size=24MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL)
    started=True;state['runStatus']='container_started';write_state()
    details=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]
    if details.get('Mounts'): raise RuntimeError('owned PostgreSQL unexpectedly has host mounts')
    port=int(run(docker+['port',container,'5432'],stdout=subprocess.PIPE,text=True).stdout.strip().rsplit(':',1)[1])
    for _ in range(120):
        ready=subprocess.run(['psql','-h','127.0.0.1','-p',str(port),'-U','persona_current_admin','-d','postgres','-Atqc','SELECT 1'],
          env=base_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
        if ready.returncode==0: break
        time.sleep(.25)
    else: raise RuntimeError('owned PostgreSQL did not become TCP SQL-ready')
    admin=['psql','-h','127.0.0.1','-p',str(port),'-U','persona_current_admin','-d','postgres','-v','ON_ERROR_STOP=1']
    roles=('dvaia_identity_migration','dvaia_identity_runtime','dvaia_secureshop_agents_migration','dvaia_secureshop_agents_runtime')
    for role in roles:
        run(admin+['-c',f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],stdout=subprocess.DEVNULL)
    urls={}
    for variant in ('fresh','populated'):
        urls[variant]={}
        for store,migration_role,runtime_role in (('identity',roles[0],roles[1]),('agents',roles[2],roles[3])):
            database=f'dvaia_test_secureshop_persona_current_{variant}_{store}'
            run(admin+['-c',f'CREATE DATABASE {database} OWNER {migration_role}'],stdout=subprocess.DEVNULL)
            run(admin+['-c',f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration_role},{runtime_role}'],stdout=subprocess.DEVNULL)
            urls[variant][store]={'migration':f'postgresql://{quote(migration_role)}@127.0.0.1:{port}/{database}',
                                  'runtime':f'postgresql://{quote(runtime_role)}@127.0.0.1:{port}/{database}'}
    env=dict(base_env,NODE_ENV='test',PLATFORM_DATABASE_ENGINE='postgres',PG_TEST_DISPOSABLE='yes',
      DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace))
    for variant in ('fresh','populated'):
        prefix=f'PG_SECURESHOP_PERSONA_CURRENT_{variant.upper()}_'
        env.update({prefix+'IDENTITY_MIGRATION_URL':urls[variant]['identity']['migration'],
          prefix+'IDENTITY_RUNTIME_URL':urls[variant]['identity']['runtime'],
          prefix+'AGENTS_MIGRATION_URL':urls[variant]['agents']['migration'],
          prefix+'AGENTS_RUNTIME_URL':urls[variant]['agents']['runtime']})
    with result_path.open('w') as log:
        os.chmod(result_path,0o600)
        child=subprocess.Popen(['node','--test','--test-reporter=tap',
          'tests/postgres/secureshopPersonaInboxCurrentHead.integration.test.js'],cwd=workspace,env=env,
          stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        state['testPid']=child.pid;state['runStatus']='test_running';write_state()
        try: code=child.wait(timeout=120)
        except subprocess.TimeoutExpired: stop_child();raise RuntimeError('persona current-head integration timed out')
    if code: raise RuntimeError(f'persona current-head integration failed ({code})')
    state['resultSha256']=digest(result_path);state['runStatus']='passed';write_state()
except BaseException as error:
    state['runStatus']='failed';state['errorType']=type(error).__name__
    if creation_attempted:
        try:
            details=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]
            state['containerFailure']={'oomKilled':details['State'].get('OOMKilled'),'exitCode':details['State'].get('ExitCode')}
            logs=subprocess.run(docker+['logs','--tail','80',container],env=base_env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20)
            (evidence/'container.log').write_text(logs.stdout);os.chmod(evidence/'container.log',0o600)
        except Exception as diagnostic: state['diagnosticError']=type(diagnostic).__name__
    write_state();raise
finally:
    signal_gate.protect_cleanup();errors=[];remove_code=None;absent=None
    try: stop_child()
    except Exception as error: errors.append(f'child:{type(error).__name__}')
    if creation_attempted:
        try:
            removed=subprocess.run(docker+['rm','-f','-v',container],env=base_env,
              stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30,check=False)
            remove_code=removed.returncode
        except Exception as error: errors.append(f'remove:{type(error).__name__}')
    try: absent=exact_container_absence()
    except Exception as error: errors.append(f'absence:{type(error).__name__}')
    state['cleanup']={'removeExitCode':remove_code,'containerAbsent':absent,
      'containerCleanupDebt':absent is not True,'errors':errors,'signals':signal_gate.received,
      'completedAt':datetime.now(timezone.utc).isoformat()}
    cleanup_failed=bool(errors or absent is not True or (creation_attempted and remove_code!=0))
    if state['runStatus']=='passed' and cleanup_failed: state['runStatus']='failed';state['errorType']='CleanupFailed'
    write_state()
    try:
        with grant_path.open('r+') as grant_file:
            fcntl.flock(grant_file.fileno(),fcntl.LOCK_EX);grant=json.load(grant_file)
            if grant.get('grantId')==args.grant_id:
                grant.update({'runStatus':state['runStatus'],'terminalAt':datetime.now(timezone.utc).isoformat(),
                              'cleanup':state['cleanup'],'evidence':str(evidence)})
                grant_file.seek(0);json.dump(grant,grant_file,indent=2);grant_file.write('\n');grant_file.truncate();grant_file.flush();os.fsync(grant_file.fileno())
    except Exception: pass
print(evidence,flush=True)
if cleanup_failed: raise RuntimeError('owned qualifier cleanup is incomplete')
