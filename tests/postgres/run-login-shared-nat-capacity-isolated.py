#!/usr/bin/env python3
"""Run real route-level shared-NAT login capacity in an owned PostgreSQL18 store."""
import argparse,hashlib,json,os,signal,subprocess,tempfile,time,uuid
from datetime import datetime,timezone
from pathlib import Path
EXPECTED_DOCKER='unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock';NODE=Path('/Users/averma5/.owasp-ai-goat/runtimes/node-v26.9.0-darwin-arm64/bin/node');DOCKER=Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker');IMAGE='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280';SOURCE=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True);parser.add_argument('--diagnostic',action='store_true');args=parser.parse_args()
if args.docker_host!=EXPECTED_DOCKER:raise SystemExit('reviewed isolated Docker host required')
root=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-login-shared-nat-'));os.chmod(root,0o700);workspace=root/'source';container='owasp-ai-goat-login-shared-nat-'+uuid.uuid4().hex[:12];owner=uuid.uuid4().hex;docker=[str(DOCKER),'--host',args.docker_host];env={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':os.environ['HOME'],'TMPDIR':str(root)}
state={'container':container,'owner':owner,'image':IMAGE,'evidence':str(root),'launcherPid':os.getpid(),'nodeVersion':None,'containerCreationAttempted':False,'child':None,'runStatus':'preparing','cleanup':None,'createdAt':datetime.now(timezone.utc).isoformat()};ownership=root/'ownership.json';log_path=root/'tests.log';log_path.touch(mode=0o600)
def persist():ownership.write_text(json.dumps(state,indent=2)+'\n');os.chmod(ownership,0o600)
def run(command,**kwargs):kwargs.setdefault('timeout',120);return subprocess.run(command,check=True,env=kwargs.pop('env',env),**kwargs)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def exact_absence():
 q=subprocess.run(docker+['ps','-a','--filter',f'name=^/{container}$','--format','{{.Names}}'],env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=30)
 if q.returncode:raise RuntimeError('exact-name container query failed')
 return not q.stdout.strip()
def group_members(pgid):
 rows=subprocess.run(['ps','-axo','pid=,pgid=,uid='],env=env,stdout=subprocess.PIPE,text=True,check=True,timeout=5).stdout;members=[]
 for row in rows.splitlines():
  f=row.split()
  if len(f)==3 and int(f[1])==pgid:
   if int(f[2])!=os.getuid():raise RuntimeError('foreign process in owned group')
   members.append(int(f[0]))
 return members
child=None;creation=False;interrupted=False
def handle(_sig,_frame):
 global interrupted;interrupted=True
signal.signal(signal.SIGTERM,handle);signal.signal(signal.SIGINT,handle);persist()
def stop_child():
 if child is None:return
 pgid=state.get('child',{}).get('pgid')
 if not pgid:return
 if group_members(pgid):os.killpg(pgid,signal.SIGTERM)
 deadline=time.monotonic()+5
 while group_members(pgid) and time.monotonic()<deadline:time.sleep(.05)
 if group_members(pgid):os.killpg(pgid,signal.SIGKILL)
 try:child.wait(timeout=5)
 except subprocess.TimeoutExpired:pass
 if group_members(pgid):raise RuntimeError('owned process group cleanup incomplete')
try:
 version=run([str(NODE),'--version'],stdout=subprocess.PIPE,text=True).stdout.strip()
 if version!='v26.9.0':raise RuntimeError('managed Node v26.9.0 required')
 state['nodeVersion']=version;persist()
 if not exact_absence():raise RuntimeError('owned container already exists')
 run([str(NODE),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(SOURCE),str(workspace)],cwd=SOURCE)
 (workspace/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
 inventory=['tests/postgres/loginSharedNatCapacity.integration.test.js','tests/fixtures/loginSharedNatServer.cjs','tests/postgres/run-login-shared-nat-capacity-isolated.py','server/routes/postgresAuth.js','server/middleware/rateLimiter.js','server/services/teachingSessionRuntime.js','server/services/postgresTeachingSessionStore.js','server/middleware/postgresSessionManager.js','server/services/postgresIdentityAdapter.js','server/database/postgres/identityRepository.js','server/services/loginAdmission.js','server/services/passwordComparisonWorkerPool.js','server/services/loginAuthenticationProduction.js','server/agent-runtime/workers/passwordComparisonWorker.js']
 state['sourceSha256']={name:digest(workspace/name) for name in inventory};persist();creation=True;state['containerCreationAttempted']=True;persist()
 run(docker+['run','--detach','--pull','never','--name',container,'--label','owasp-ai-goat.test.owner='+owner,'--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size=268435456','-p','127.0.0.1::5432','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1',IMAGE,'-c','shared_buffers=16MB','-c','max_connections=32','-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL)
 details=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]
 if details.get('Mounts') or details['Config']['Labels'].get('owasp-ai-goat.test.owner')!=owner:raise RuntimeError('container ownership failed')
 for _ in range(100):
  if subprocess.run(docker+['exec',container,'pg_isready','-h','127.0.0.1','-U','postgres'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2).returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('PostgreSQL unavailable')
 port=int(run(docker+['port',container,'5432/tcp'],stdout=subprocess.PIPE,text=True).stdout.strip().rsplit(':',1)[1]);psql=docker+['exec',container,'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-c']
 run(psql+["CREATE ROLE dvaia_identity_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE dvaia_identity_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"],stdout=subprocess.DEVNULL)
 run(psql+["CREATE DATABASE owasp_ai_goat_login_nat OWNER dvaia_identity_migration"],stdout=subprocess.DEVNULL)
 run(psql+["REVOKE CONNECT ON DATABASE owasp_ai_goat_login_nat FROM PUBLIC; GRANT CONNECT ON DATABASE owasp_ai_goat_login_nat TO dvaia_identity_migration,dvaia_identity_runtime"],stdout=subprocess.DEVNULL)
 env.update(NODE_ENV='test',PG_TEST_DISPOSABLE='yes',PG_LOGIN_SHARED_NAT='1',OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(workspace),LOGIN_SHARED_NAT_EVIDENCE_PATH=str(root/'service-evidence.json'),LOGIN_SHARED_NAT_METRICS_KEY=uuid.uuid4().hex,PLATFORM_DATABASE_ENGINE='postgres',IDENTITY_DATABASE_URL=f'postgresql://dvaia_identity_runtime@127.0.0.1:{port}/owasp_ai_goat_login_nat',IDENTITY_MIGRATION_DATABASE_URL=f'postgresql://dvaia_identity_migration@127.0.0.1:{port}/owasp_ai_goat_login_nat',PG_POOL_BUDGET='12',PG_POOL_MAX_CONTROL='8',PG_POOL_MAX_TEACHING='2',PG_POOL_MAX_MIGRATION='1',JWT_SECRET=uuid.uuid4().hex+uuid.uuid4().hex,AWS_EC2_METADATA_DISABLED='true')
 if args.diagnostic:env['LOGIN_SHARED_NAT_DIAGNOSTIC']='1'
 with log_path.open('w') as log:
  child=subprocess.Popen([str(NODE),'--test','--test-reporter=tap','tests/postgres/loginSharedNatCapacity.integration.test.js'],cwd=workspace,env=env,stdout=log,stderr=log,start_new_session=True);state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid)};state['runStatus']='test_running';persist()
  deadline=time.monotonic()+300
  while child.poll() is None and time.monotonic()<deadline and not interrupted:time.sleep(.2)
  if child.poll() is None:stop_child();raise RuntimeError('test interrupted or exceeded five-minute suite deadline')
  if child.returncode:raise RuntimeError(f'qualification failed ({child.returncode}); inspect retained tests.log')
 state['runStatus']='passed';state['resultSha256']=digest(log_path);state['serviceEvidenceSha256']=digest(root/'service-evidence.json');persist()
except BaseException as error:
 state['runStatus']='failed';state['failureType']=type(error).__name__;state['failureMessage']=str(error)[:500]
 if creation:
  captured=subprocess.run(docker+['logs','--tail','200',container],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
  (root/'container.log').write_bytes(captured.stdout[-65536:]);os.chmod(root/'container.log',0o600);state['containerLogSha256']=digest(root/'container.log')
 persist();raise
finally:
 cleanup={'childPidAbsent':True,'childPgidAbsent':True,'containerRemoved':False,'containerAbsent':False}
 try:
  stop_child()
  if state.get('child',{}).get('pid'):
   try:os.kill(state['child']['pid'],0);cleanup['childPidAbsent']=False
   except ProcessLookupError:cleanup['childPidAbsent']=True
  if state.get('child',{}).get('pgid'):cleanup['childPgidAbsent']=not bool(group_members(state['child']['pgid']))
 finally:
  if creation:
   removed=subprocess.run(docker+['rm','-f',container],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30);cleanup['containerRemoveCode']=removed.returncode;cleanup['containerRemoved']=removed.returncode==0
  cleanup['containerAbsent']=exact_absence();state['cleanup']=cleanup;persist()
 if not (cleanup['childPidAbsent'] and cleanup['childPgidAbsent'] and cleanup['containerRemoved'] and cleanup['containerAbsent']):raise RuntimeError('owned cleanup incomplete')
print(str(root))
