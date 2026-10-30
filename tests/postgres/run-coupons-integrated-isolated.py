#!/usr/bin/env python3
"""Qualify bound coupons with two disposable PostgreSQL clusters; no model or browser."""
import argparse, hashlib, http.client, json, os, signal, subprocess, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from sensitive_info_recovery_safety import SignalGate

EXPECTED_DOCKER='unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock'
NODE=Path('/Users/averma5/.owasp-ai-goat/runtimes/node-v26.9.0-darwin-arm64/bin/node')
DOCKER=Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')
IMAGE='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
SOURCE=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True);args=parser.parse_args()
mode='coupons-integrated'
test_file='tests/postgres/secureshopCouponsIntegrated.native.js'
if args.docker_host!=EXPECTED_DOCKER:raise SystemExit('reviewed isolated Docker host required')
root=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-coupons-integrated-'));os.chmod(root,0o700);workspace=root/'source'
container='owasp-ai-goat-coupons-integrated-'+uuid.uuid4().hex[:12];owner=uuid.uuid4().hex
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
executor=None;child=None;creation_attempted=False;gate=SignalGate();signal.signal(signal.SIGTERM,gate.handler);signal.signal(signal.SIGINT,gate.handler);signal.signal(signal.SIGALRM,gate.handler);signal.alarm(600);persist()
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
 if version!='v26.9.0':raise RuntimeError('managed Node v26.9.0 required')
 state['nodeVersion']=version;persist()
 daemon_name=run(docker+['info','--format','{{.Name}}'],stdout=subprocess.PIPE,text=True).stdout.strip()
 if daemon_name!='colima-owasp-ai-goat-pg-verify':raise RuntimeError('reviewed isolated Docker daemon required')
 image_id=run(docker+['image','inspect','--format','{{.Id}}',IMAGE],stdout=subprocess.PIPE,text=True).stdout.strip()
 if image_id!=IMAGE:raise RuntimeError('immutable PostgreSQL image identity mismatch')
 state['dockerDaemon']=daemon_name;state['imageId']=image_id;persist()
 if not exact_absence():raise RuntimeError('owned container name unexpectedly exists')
 run([str(NODE),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(SOURCE),str(workspace)],cwd=SOURCE)
 (workspace/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
 import shutil
 candidate_dir=root/'candidate-migrations';candidate_dir.mkdir();baseline_dir=root/'baseline-migrations';baseline_dir.mkdir()
 for migration in (workspace/'db/postgres/workshop-migrations/secureshop_review').glob('*.sql'):
  shutil.copy2(migration,candidate_dir/migration.name)
  if int(migration.name.split('_',1)[0])<25:shutil.copy2(migration,baseline_dir/migration.name)
 coupon_candidate=workspace/'docs/modernization/drafts/secureshop-bound-coupons/0025_bound_coupon_commerce.sql'
 assert (candidate_dir/coupon_candidate.name).read_bytes()==coupon_candidate.read_bytes()
 env['COUPON_CANDIDATE_MIGRATIONS']=str(candidate_dir);env['COUPON_BASELINE_MIGRATIONS']=str(baseline_dir)
 inventory=[test_file,'tests/postgres/run-coupons-integrated-isolated.py','tests/postgres/sensitive_info_recovery_safety.py','package-lock.json','package.json']
 for folder in ['sidecars/analytics-sql-target','server/database/postgres','server/services','server/agent-runtime','db/postgres','scripts/lib','shared','agent-host','server/routes','server/middleware','tests/fixtures','docs/modernization/drafts/secureshop-bound-coupons']:
  inventory.extend(str(item.relative_to(workspace)) for item in sorted((workspace/folder).rglob('*')) if item.is_file())
 state['sourceSha256']={name:digest(workspace/name) for name in sorted(set(inventory))};state['nodeSha256']=digest(NODE);persist()
 run([str(NODE),'--check',test_file],cwd=workspace)
 creation_attempted=True;state['containerCreationAttempted']=True;persist()
 run(docker+['run','--detach','--pull','never','--name',container,'--label','owasp-ai-goat.test.owner='+owner,
  '--memory','1g','--cpus','2','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size=268435456','-e','POSTGRES_HOST_AUTH_METHOD=trust',
  '-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',IMAGE,'-c','shared_buffers=16MB','-c','max_connections=40',
  '-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL)
 details=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]
 if details.get('Mounts') or details['Config']['Labels'].get('owasp-ai-goat.test.owner')!=owner:raise RuntimeError('owned PostgreSQL isolation/ownership check failed')
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
 for label,schema in [('IDENTITY','identity'),('COMMERCE','secureshop'),('AGENTS','secureshop_agents'),('REVIEW','secureshop_review')]:
  migration='dvaia_'+schema+'_migration';runtime='dvaia_'+schema+'_runtime'
  run(psql+[f'CREATE ROLE {migration} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE {runtime} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],stdout=subprocess.DEVNULL)
  database=f'owasp_ai_goat_test_listings_{nonce}_{schema}'
  run(psql+[f'CREATE DATABASE {database} OWNER {migration}'],stdout=subprocess.DEVNULL)
  run(psql+[f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime}'],stdout=subprocess.DEVNULL)
  state['databases'].append(database)
  env[f'LISTINGS_{label}_MIGRATION_URL']=f'postgresql://{migration}@127.0.0.1:{port}/{database}'
  env[f'LISTINGS_{label}_RUNTIME_URL']=f'postgresql://{runtime}@127.0.0.1:{port}/{database}'
 persist()
 env['COUPON_NATIVE']='1';env['COUPON_EVIDENCE_ROOT']=str(root);env['COUPON_RESULT']=str(root/'candidate-result.json')
 env.update(NODE_ENV='test',PG_TEST_DISPOSABLE='yes',OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(workspace),
  PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',
  AI_PROVIDER='mock',TRANSFORMERS_OFFLINE='1',JWT_SECRET=uuid.uuid4().hex+uuid.uuid4().hex,SESSION_SECRET=uuid.uuid4().hex+uuid.uuid4().hex,
  AWS_EC2_METADATA_DISABLED='true',MCP_WORKSHOP_AUTOSTART='false',MCP_SIDECARS_AUTOSTART='false',SS_ENABLE='false',HF_HUB_OFFLINE='1',
  OLLAMA_BASE_URL='http://127.0.0.1:1',SANDBOX_RUNNER_URL='http://127.0.0.1:1',SSRF_TARGET_URL='http://127.0.0.1:1',
 ROGUE_MCP_URL='http://127.0.0.1:1',MAILPIT_API_URL='http://127.0.0.1:1',MAILPIT_SMTP_HOST='127.0.0.1',MAILPIT_SMTP_PORT='1')
 analytics_name=container+'-sql';state['analyticsContainer']=analytics_name;persist()
 if not exact_absence(analytics_name):raise RuntimeError('Analytics container already exists')
 state['analyticsCreationAttempted']=True;persist()
 run(docker+['run','--detach','--pull','never','--name',analytics_name,'--label','owasp-ai-goat.test.owner='+owner,'--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size=268435456','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',IMAGE,'-c','shared_buffers=16MB','-c','max_connections=40','-c','max_wal_size=16MB','-c','min_wal_size=4MB','-c','cluster_name=owasp-ai-goat-owned-analytics-'+nonce],stdout=subprocess.DEVNULL)
 details=json.loads(run(docker+['inspect',analytics_name],stdout=subprocess.PIPE,text=True).stdout)[0]
 if details.get('Mounts') or details['Config']['Labels'].get('owasp-ai-goat.test.owner')!=owner:raise RuntimeError('Analytics ownership mismatch')
 for _ in range(100):
  ready=subprocess.run(docker+['exec',analytics_name,'pg_isready','-h','127.0.0.1','-U','postgres'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
  if ready.returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('Analytics unavailable')
 sqlport=int(run(docker+['port',analytics_name,'5432/tcp'],stdout=subprocess.PIPE,text=True).stdout.strip().rsplit(':',1)[1])
 database='owasp_ai_goat_analytics_control_'+nonce
 run(docker+['exec',analytics_name,'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-c','CREATE DATABASE '+database],stdout=subprocess.DEVNULL)
 env['COUPON_SQL_PORT']=str(sqlport);env['COUPON_OWNER']=nonce;env['COUPON_SQL_DATABASE']=database
 with log_path.open('w') as log:
  child=subprocess.Popen([str(NODE),'--test','--test-reporter=tap',test_file],cwd=workspace,env=env,stdout=log,stderr=log,start_new_session=True)
  state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid)};state['runStatus']='test_running';persist()
  try:code=child.wait(timeout=360)
  except subprocess.TimeoutExpired:stop_child();raise RuntimeError('Owned coupon qualification timed out')
 if code:raise RuntimeError(f'Owned coupon qualification failed ({code}); inspect retained tests.log')
 if any(digest(workspace/name)!=expected for name,expected in state['sourceSha256'].items()):raise RuntimeError('Frozen source changed during qualification')
 state['runStatus']='passed';state['logSha256']=digest(log_path);state['runtimeResultSha256']=digest(root/'candidate-result.json');persist()
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
 if state.get('analyticsCreationAttempted'):
  try:
   name=state['analyticsContainer']
   if not exact_absence(name):
    info=json.loads(run(docker+['inspect',name],stdout=subprocess.PIPE,text=True).stdout)[0]
    if info['Config']['Labels'].get('owasp-ai-goat.test.owner')!=owner:raise RuntimeError('Foreign Analytics container')
    run(docker+['rm','-f','-v',name],stdout=subprocess.DEVNULL)
   state['analyticsAbsent']=exact_absence(name)
   if not state['analyticsAbsent']:raise RuntimeError('Analytics remains')
  except Exception as error:errors.append('analytics:'+type(error).__name__)
 if creation_attempted:
  try:
   if not exact_absence():
    info=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]
    if info['Config']['Labels'].get('owasp-ai-goat.test.owner')!=owner:raise RuntimeError('refusing foreign container cleanup')
    remove_code=subprocess.run(docker+['rm','-f','-v',container],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30).returncode
   else:remove_code=0
  except Exception as error:errors.append('remove:'+type(error).__name__)
 try:absent=exact_absence()
 except Exception as error:errors.append('absence:'+type(error).__name__)
 try:pgid_absent=not state.get('child') or not owned_group_members(state['child']['pgid'])
 except Exception as error:errors.append('pgid:'+type(error).__name__);pgid_absent=False
 state['cleanup']={'removeExitCode':remove_code,'containerAbsent':absent,'nodeBrowserPgidAbsent':pgid_absent,
 'errors':errors,'completedAt':datetime.now(timezone.utc).isoformat()}
 if state['runStatus']=='passed' and (errors or absent is not True or pgid_absent is not True or (creation_attempted and remove_code!=0)):state['runStatus']='failed';state['errorType']='CleanupFailed'
 persist()
print(json.dumps({'evidence':str(root),'status':state['runStatus'],'cleanup':state['cleanup']}),flush=True)
if state['runStatus']!='passed':raise SystemExit(1)
