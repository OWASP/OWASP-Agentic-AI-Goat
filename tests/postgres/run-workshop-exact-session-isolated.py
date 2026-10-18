#!/usr/bin/env python3
"""Combined workshop exact-session qualification; five owned stores, sequential controlled families."""
import argparse, hashlib, http.client, json, os, shutil, signal, subprocess, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from sensitive_info_recovery_safety import SignalGate

EXPECTED_DOCKER='unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
NODE=Path('/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node')
DOCKER=Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')
IMAGE='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
SOURCE=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True);parser.add_argument('--preflight-only',action='store_true');args=parser.parse_args()
class PreflightComplete(Exception):pass
mode='workshop-controlled-session'
test_file='tests/postgres/workshopSessionSqlNoSql.native.js'
if args.docker_host!=EXPECTED_DOCKER:raise SystemExit('reviewed isolated Docker host required')
root=Path(tempfile.mkdtemp(prefix='dvaia-workshop-session-'));os.chmod(root,0o700);workspace=root/'source'
container='dvaia-workshop-session-'+uuid.uuid4().hex[:12];owner=uuid.uuid4().hex
docker=[str(DOCKER),'--host',args.docker_host]
env={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':os.environ['HOME'],'TMPDIR':str(root)}
state={'container':container,'owner':owner,'image':IMAGE,'evidence':str(root),'launcherPid':os.getpid(),
 'nodeVersion':None,'containerCreationAttempted':False,'child':None,'runStatus':'preparing','cleanup':None,
 'mode':mode,'createdAt':datetime.now(timezone.utc).isoformat()}
ownership=root/'ownership.json';log_path=root/'tests.log';log_path.touch(mode=0o600)
def persist():ownership.write_text(json.dumps(state,indent=2)+'\n');os.chmod(ownership,0o600)
def run(command,**kwargs):kwargs.setdefault('timeout',120);return subprocess.run(command,check=True,env=kwargs.pop('env',env),**kwargs)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def exact_absence(name=container):
 query=subprocess.run(docker+['ps','-a','--filter',f'name=^/{name}$','--format','{{.Names}}'],env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=30)
 if query.returncode:raise RuntimeError('exact-name container query failed')
 return not query.stdout.strip()
executor=None;child=None;creation_attempted=False;gate=SignalGate();signal.signal(signal.SIGTERM,gate.handler);signal.signal(signal.SIGINT,gate.handler);signal.signal(signal.SIGALRM,gate.handler);signal.alarm(900);persist()
def owned_group_members(pgid):
 listing=subprocess.run(['ps','-axo','pid=,pgid=,uid='],env=env,stdout=subprocess.PIPE,text=True,check=True,timeout=5).stdout
 members=[]
 for line in listing.splitlines():
  fields=line.split()
  if len(fields)==3 and int(fields[1])==pgid:
   if int(fields[2])!=os.getuid():raise RuntimeError(f'refusing foreign process in owned group {pgid}')
   members.append(int(fields[0]))
 return members
def stop_child():
 if child is None:return
 pgid=state.get('child',{}).get('pgid')
 if not pgid:return
 if owned_group_members(pgid):os.killpg(pgid,signal.SIGTERM)
 deadline=time.monotonic()+5
 while owned_group_members(pgid) and time.monotonic()<deadline:
  child.poll();time.sleep(.05)
 if owned_group_members(pgid):os.killpg(pgid,signal.SIGKILL)
 try:child.wait(timeout=5)
 except subprocess.TimeoutExpired:pass
 if owned_group_members(pgid):raise RuntimeError('owned Node/browser process group cleanup incomplete')
try:
 version=run([str(NODE),'--version'],stdout=subprocess.PIPE,text=True).stdout.strip()
 if version!='v26.10.0':raise RuntimeError('managed Node v26.10.0 required')
 state['nodeVersion']=version;persist()
 daemon_name=run(docker+['info','--format','{{.Name}}'],stdout=subprocess.PIPE,text=True).stdout.strip()
 if daemon_name!='colima-dvaia-pg-verify':raise RuntimeError('reviewed isolated Docker daemon required')
 image_id=run(docker+['image','inspect','--format','{{.Id}}',IMAGE],stdout=subprocess.PIPE,text=True).stdout.strip()
 if image_id!=IMAGE:raise RuntimeError('immutable PostgreSQL image identity mismatch')
 state['dockerDaemon']=daemon_name;state['imageId']=image_id;persist()
 if not exact_absence():raise RuntimeError('owned container name unexpectedly exists')
 run([str(NODE),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(SOURCE),str(workspace)],cwd=SOURCE)
 (workspace/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
 state['bounds']={'parentSeconds':900,'childSeconds':150,'totalChildSeconds':720,'maxActorCalls':0,'maxActualHttpCalls':0,'perHttpSeconds':60};persist()
 inventory=['tests/workshopSessionNativeContract.test.js','tests/workshopExactSession.test.js','tests/excessiveAgencySessionFence.test.js','tests/ownerWorkflowRoutes.test.js','tests/xssOwnerWorkflowRoute.test.js','tests/admittedPlatformSession.test.js',test_file,'tests/postgres/workshopSessionEaXss.native.js','tests/postgres/workshopSessionNativeSupport.js','tests/postgres/run-workshop-exact-session-isolated.py','tests/postgres/sensitive_info_recovery_safety.py','package-lock.json','package.json']
 for folder in ['server/database/postgres','server/config','server/data','server/services','server/agent-runtime','db/postgres','scripts/lib','shared','server/routes','server/middleware','server/utils','tests/fixtures']:
  inventory.extend(str(item.relative_to(workspace)) for item in sorted((workspace/folder).rglob('*')) if item.is_file())
 state['sourceSha256']={name:digest(workspace/name) for name in sorted(set(inventory))};state['nodeSha256']=digest(NODE);persist()
 for fixture in [test_file,'tests/postgres/workshopSessionEaXss.native.js','tests/postgres/workshopSessionNativeSupport.js']:
  run([str(NODE),'--check',fixture],cwd=workspace)
 if args.preflight_only:
  with log_path.open('a') as log:run([str(NODE),'--test','tests/workshopSessionNativeContract.test.js','tests/workshopExactSession.test.js','tests/excessiveAgencySessionFence.test.js','tests/ownerWorkflowRoutes.test.js','tests/xssOwnerWorkflowRoute.test.js','tests/admittedPlatformSession.test.js'],cwd=workspace,stdout=log,stderr=log,timeout=30)
  state['logSha256']=digest(log_path);raise PreflightComplete()
 creation_attempted=True;state['containerCreationAttempted']=True;persist()
 run(docker+['run','--detach','--pull','never','--name',container,'--label','dvaia.test.owner='+owner,
  '--memory','1g','--cpus','2','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size=536870912','-e','POSTGRES_HOST_AUTH_METHOD=trust',
  '-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',IMAGE,'-c','shared_buffers=16MB','-c','max_connections=40',
  '-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL)
 details=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]
 if details.get('Mounts') or details['Config']['Labels'].get('dvaia.test.owner')!=owner:raise RuntimeError('owned PostgreSQL isolation/ownership check failed')
 for _ in range(100):
  ready=subprocess.run(docker+['exec',container,'pg_isready','-h','127.0.0.1','-U','postgres'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
  if ready.returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('owned PostgreSQL unavailable')
 port=int(run(docker+['port',container,'5432/tcp'],stdout=subprocess.PIPE,text=True).stdout.strip().rsplit(':',1)[1])
 server_version=run(docker+['exec',container,'psql','-U','postgres','-d','postgres','-Atc','SHOW server_version'],stdout=subprocess.PIPE,text=True).stdout.strip()
 state['postgresServerVersion']=server_version;state['postgresImageMetadata']=json.loads(run(docker+['image','inspect',IMAGE],stdout=subprocess.PIPE,text=True).stdout)[0].get('Config',{}).get('Labels',{});persist()
 psql=docker+['exec',container,'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-c']
 nonce=owner[:12];state['databases']=[]
 for label,schema in [('IDENTITY','identity'),('SQL_WORKSHOP','aria'),('NOSQL_WORKSHOP','nova'),('EXCESSIVE_AGENCY','excessive_agency'),('XSS_WORKSHOP','xss')]:
  migration='dvaia_'+schema+'_migration';runtime='dvaia_'+schema+'_runtime'
  run(psql+[f'CREATE ROLE {migration} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE {runtime} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],stdout=subprocess.DEVNULL)
  database=f'dvaia_test_workshop_session_{nonce}_{schema}'
  run(psql+[f'CREATE DATABASE {database} OWNER {migration}'],stdout=subprocess.DEVNULL)
  run(psql+[f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime}'],stdout=subprocess.DEVNULL)
  state['databases'].append(database)
  env[f'{label}_MIGRATION_DATABASE_URL']=f'postgresql://{migration}@127.0.0.1:{port}/{database}'
  env[f'{label}_DATABASE_URL']=f'postgresql://{runtime}@127.0.0.1:{port}/{database}'
 persist()
 env['WORKSHOP_SESSION_EVIDENCE_ROOT']=str(root)
 app_data=root/'app-data';app_data.mkdir(mode=0o700);env['DVAIA_APP_DATA_ROOT']=str(app_data)
 env.update(NODE_ENV='test',PG_TEST_DISPOSABLE='yes',DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace),
  PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',
  AI_PROVIDER='mock',TRANSFORMERS_OFFLINE='1',JWT_SECRET=uuid.uuid4().hex+uuid.uuid4().hex,SESSION_SECRET=uuid.uuid4().hex+uuid.uuid4().hex,
  AWS_EC2_METADATA_DISABLED='true',MCP_WORKSHOP_AUTOSTART='false',MCP_SIDECARS_AUTOSTART='false',SS_ENABLE='false',HF_HUB_OFFLINE='1',
  OLLAMA_BASE_URL='http://127.0.0.1:1',SANDBOX_RUNNER_URL='http://127.0.0.1:1',SSRF_TARGET_URL='http://127.0.0.1:1',
 ROGUE_MCP_URL='http://127.0.0.1:1',MAILPIT_API_URL='http://127.0.0.1:1',MAILPIT_SMTP_HOST='127.0.0.1',MAILPIT_SMTP_PORT='1')
 state['families']=[];persist();child_deadline=time.monotonic()+720
 with log_path.open('w') as log:
  for family in ['aria','nova','excessive_agency','xss']:
   fixture='tests/postgres/workshopSessionSqlNoSql.native.js' if family in ['aria','nova'] else 'tests/postgres/workshopSessionEaXss.native.js'
   child=subprocess.Popen([str(NODE),fixture,family],cwd=workspace,env=env,stdout=log,stderr=log,start_new_session=True)
   state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid),'family':family};state['runStatus']='test_running';persist()
   try:code=child.wait(timeout=min(150,max(1,child_deadline-time.monotonic())))
   except subprocess.TimeoutExpired:stop_child();raise RuntimeError('Owned workshop family timed out')
   stop_child()
   item={'family':family,'pid':child.pid,'pgid':state['child']['pgid'],'exitCode':code,'pgidAbsent':not owned_group_members(state['child']['pgid'])}
   result_path=root/(family+'-result.json')
   if result_path.exists():item.update(resultSha256=digest(result_path),result=json.loads(result_path.read_text()))
   state['families'].append(item);persist()
   if code or item.get('result',{}).get('status')!='passed-controlled-session-only':raise RuntimeError('Owned workshop family failed; retained individual evidence')
 if any(digest(workspace/name)!=expected for name,expected in state['sourceSha256'].items()):raise RuntimeError('Frozen source changed during qualification')
 state['runStatus']='passed-controlled-session-only';state['logSha256']=digest(log_path);persist()

except PreflightComplete:
 state['runStatus']='prepared';persist()
except BaseException as error:
 if creation_attempted:
  try:
   diagnostic=subprocess.run(docker+['logs','--tail','120',container],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20)
   (root/'container.log').write_text(diagnostic.stdout);os.chmod(root/'container.log',0o600)
  except Exception as diagnostic_error:state['containerDiagnosticError']=type(diagnostic_error).__name__
 state.update({'runStatus':'failed','errorType':type(error).__name__,'resultSha256':digest(log_path)});persist();raise
finally:
 signal.alarm(0);gate.protect_cleanup();errors=[];remove_code=None;absent=None
 try:stop_child()
 except Exception as error:errors.append('child:'+type(error).__name__)
 if creation_attempted:
  try:
   if not exact_absence():
    info=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]
    if info['Config']['Labels'].get('dvaia.test.owner')!=owner:raise RuntimeError('refusing foreign container cleanup')
    remove_code=subprocess.run(docker+['rm','-f','-v',container],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30).returncode
   else:remove_code=0
  except Exception as error:errors.append('remove:'+type(error).__name__)
 try:absent=exact_absence()
 except Exception as error:errors.append('absence:'+type(error).__name__)
 try:pgid_absent=not state.get('child') or not owned_group_members(state['child']['pgid'])
 except Exception as error:errors.append('pgid:'+type(error).__name__);pgid_absent=False
 app_data=root/'app-data'
 if app_data.exists():
  if app_data.is_symlink() or app_data.parent!=root:raise RuntimeError('invalid owned app data cleanup')
  shutil.rmtree(app_data)
 state['cleanup']={'ownedAppDataAbsent':not app_data.exists(),'removeExitCode':remove_code,'containerAbsent':absent,'nodeBrowserPgidAbsent':pgid_absent,
 'errors':errors,'completedAt':datetime.now(timezone.utc).isoformat()}
 if state['runStatus'] in ('passed','passed-pending-raw-review','passed-controlled-session-only','observed_negative') and (errors or absent is not True or pgid_absent is not True or (creation_attempted and remove_code!=0)):state['runStatus']='failed';state['errorType']='CleanupFailed'
 persist()
print(json.dumps({'evidence':str(root),'status':state['runStatus'],'cleanup':state['cleanup']}),flush=True)
if state['runStatus'] not in ('passed','passed-pending-raw-review','passed-controlled-session-only','prepared'):raise SystemExit(1)
