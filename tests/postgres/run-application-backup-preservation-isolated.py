#!/usr/bin/env python3
"""Owned PG18 qualification for backup preservation SQL helpers; never reads configured stores."""
import argparse, hashlib, json, os, signal, subprocess, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from sensitive_info_recovery_safety import SignalGate

EXPECTED_DOCKER='unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
NODE=Path('/Users/averma5/.dvaia/runtimes/node-v26.9.0-darwin-arm64/bin/node')
DOCKER=Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')
IMAGE='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
SOURCE=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True);args=parser.parse_args()
if args.docker_host!=EXPECTED_DOCKER:raise SystemExit('reviewed isolated Docker host required')
evidence=Path(tempfile.mkdtemp(prefix='dvaia-backup-preservation-'));os.chmod(evidence,0o700)
workspace=evidence/'source';container='dvaia-backup-preservation-'+uuid.uuid4().hex[:12];owner=uuid.uuid4().hex
docker=[str(DOCKER),'--host',args.docker_host]
env={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':os.environ['HOME'],'TMPDIR':str(evidence)}
state={'scope':'application-backup-preservation-sql-v1','container':container,'owner':owner,'image':IMAGE,
 'evidence':str(evidence),'launcherPid':os.getpid(),'nodeVersion':None,'containerCreationAttempted':False,
 'child':None,'runStatus':'preparing','cleanup':None,'createdAt':datetime.now(timezone.utc).isoformat()}
ownership=evidence/'ownership.json';log_path=evidence/'tests.log';log_path.touch(mode=0o600)
def persist():ownership.write_text(json.dumps(state,indent=2)+'\n');os.chmod(ownership,0o600)
def run(command,**kwargs):kwargs.setdefault('timeout',120);return subprocess.run(command,check=True,env=kwargs.pop('env',env),**kwargs)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def exact_absence():
 result=subprocess.run(docker+['ps','-a','--filter',f'name=^/{container}$','--format','{{.Names}}'],env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=30)
 if result.returncode:raise RuntimeError('exact-name container query failed')
 return not result.stdout.strip()
child=None;creation_attempted=False;gate=SignalGate();signal.signal(signal.SIGTERM,gate.handler);signal.signal(signal.SIGINT,gate.handler);persist()
def owned_group_members(pgid):
 output=subprocess.run(['ps','-axo','pid=,pgid=,uid='],env=env,stdout=subprocess.PIPE,text=True,check=True,timeout=5).stdout
 members=[]
 for line in output.splitlines():
  fields=line.split()
  if len(fields)==3 and int(fields[1])==pgid:
   if int(fields[2])!=os.getuid():raise RuntimeError('foreign process in owned process group')
   members.append(int(fields[0]))
 return members
def stop_child():
 if child is None:return
 pgid=state.get('child',{}).get('pgid')
 if not pgid:return
 if owned_group_members(pgid):os.killpg(pgid,signal.SIGTERM)
 deadline=time.monotonic()+5
 while owned_group_members(pgid) and time.monotonic()<deadline:time.sleep(.05)
 if owned_group_members(pgid):os.killpg(pgid,signal.SIGKILL)
 try:child.wait(timeout=5)
 except subprocess.TimeoutExpired:pass
 if owned_group_members(pgid):raise RuntimeError('owned test process group remains')
try:
 version=run([str(NODE),'--version'],stdout=subprocess.PIPE,text=True).stdout.strip()
 if version!='v26.9.0':raise RuntimeError('managed Node v26.9.0 required')
 state['nodeVersion']=version
 daemon=run(docker+['info','--format','{{.Name}}'],stdout=subprocess.PIPE,text=True).stdout.strip()
 if daemon!='colima-dvaia-pg-verify':raise RuntimeError('reviewed isolated Docker daemon required')
 image=run(docker+['image','inspect','--format','{{.Id}}',IMAGE],stdout=subprocess.PIPE,text=True).stdout.strip()
 if image!=IMAGE:raise RuntimeError('immutable PostgreSQL image mismatch')
 state.update({'dockerDaemon':daemon,'imageId':image});persist()
 if not exact_absence():raise RuntimeError('owned container name unexpectedly exists')
 run([str(NODE),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(SOURCE),str(workspace)],cwd=SOURCE)
 (workspace/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
 inventory=['scripts/qualify-application-backups.js','scripts/lib/isolated-source-copy.js',
  'tests/postgres/applicationBackupPreservation.integration.test.js',
  'tests/postgres/run-application-backup-preservation-isolated.py','tests/postgres/sensitive_info_recovery_safety.py',
  'db/postgres/initialize-application.js','package.json','package-lock.json']
 state['sourceSha256']={name:digest(workspace/name) for name in inventory};persist()
 run([str(NODE),'--check','scripts/qualify-application-backups.js'],cwd=workspace)
 run([str(NODE),'--check','tests/postgres/applicationBackupPreservation.integration.test.js'],cwd=workspace)
 creation_attempted=True;state['containerCreationAttempted']=True;persist()
 run(docker+['run','--detach','--pull','never','--name',container,'--label','dvaia.test.owner='+owner,
  '--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size=268435456',
  '-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',IMAGE,
  '-c','shared_buffers=16MB','-c','max_connections=24','-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL)
 details=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]
 if details.get('Mounts') or details['Image']!=IMAGE or details['Config']['Labels'].get('dvaia.test.owner')!=owner:raise RuntimeError('owned PostgreSQL isolation check failed')
 for _ in range(120):
  ready=subprocess.run(docker+['exec',container,'pg_isready','-h','127.0.0.1','-U','postgres'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
  if ready.returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('owned PostgreSQL unavailable')
 port=int(run(docker+['port',container,'5432/tcp'],stdout=subprocess.PIPE,text=True).stdout.strip().rsplit(':',1)[1])
 psql=docker+['exec',container,'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-c']
 role='dvaia_identity_migration';database='dvaia_backup_preservation_'+owner[:12];role_password=uuid.uuid4().hex+uuid.uuid4().hex
 run(psql+[f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],stdout=subprocess.DEVNULL)
 run(docker+['exec','-i',container,'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1'],
  input=f"ALTER ROLE {role} PASSWORD '{role_password}';\n",text=True,stdout=subprocess.DEVNULL)
 run(psql+[f'CREATE DATABASE {database} OWNER {role}'],stdout=subprocess.DEVNULL)
 env.update(NODE_ENV='test',PG_TEST_DISPOSABLE='yes',DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace),
  BACKUP_PRESERVATION_TEST_URL=f'postgresql://{role}:{role_password}@127.0.0.1:{port}/{database}',AWS_EC2_METADATA_DISABLED='true')
 with log_path.open('w') as log:
  child=subprocess.Popen([str(NODE),'--test','--test-reporter=tap','tests/postgres/applicationBackupPreservation.integration.test.js'],cwd=workspace,env=env,stdout=log,stderr=log,start_new_session=True)
  state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid)};state['runStatus']='test_running';persist()
  try:code=child.wait(timeout=180)
  except subprocess.TimeoutExpired:stop_child();raise RuntimeError('backup preservation SQL qualification timed out')
 if code:raise RuntimeError(f'backup preservation SQL qualification failed ({code})')
 state.update({'runStatus':'passed','resultSha256':digest(log_path)});persist()
except BaseException as error:
 if creation_attempted:
  try:
   logs=subprocess.run(docker+['logs','--tail','100',container],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20)
   (evidence/'container.log').write_text(logs.stdout);os.chmod(evidence/'container.log',0o600)
  except Exception as diagnostic:state['diagnosticError']=type(diagnostic).__name__
 state.update({'runStatus':'failed','errorType':type(error).__name__,'resultSha256':digest(log_path)});persist();raise
finally:
 gate.protect_cleanup();errors=[];remove_code=None
 try:stop_child()
 except Exception as error:errors.append('child:'+type(error).__name__)
 if creation_attempted:
  try:remove_code=subprocess.run(docker+['rm','--force','--volumes',container],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30).returncode
  except Exception as error:errors.append('remove:'+type(error).__name__)
 try:absent=exact_absence()
 except Exception as error:absent=None;errors.append('absence:'+type(error).__name__)
 state['cleanup']={'removeExitCode':remove_code,'containerAbsent':absent,'processGroupAbsent':not owned_group_members(state.get('child',{}).get('pgid',-1)),'errors':errors,'signals':gate.received,'completedAt':datetime.now(timezone.utc).isoformat()}
 if state['runStatus']=='passed' and (errors or absent is not True or state['cleanup']['processGroupAbsent'] is not True):state.update({'runStatus':'failed','errorType':'CleanupFailed'})
 persist()
 print(evidence,flush=True)
if state['runStatus']!='passed':raise RuntimeError('backup preservation qualification did not pass cleanly')
