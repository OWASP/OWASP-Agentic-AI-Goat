#!/usr/bin/env python3
"""Qualify owned Analytics in a launcher-owned synthetic cluster; no model."""
import argparse, hashlib, http.client, json, os, re, signal, subprocess, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from sensitive_info_recovery_safety import SignalGate

EXPECTED_DOCKER='unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock'
NODE=Path('/Users/averma5/.owasp-ai-goat/runtimes/node-v26.10.0-darwin-arm64/bin/node')
NODE_SHA256='56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
DOCKER=Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')
IMAGE='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
DOCKER_SHA256='95fab203ab36bd2b4f3cd8a1d0dc6d084252f2ec224dc76bfbaebe1540cdd15e'
DOCKER_DAEMON_ID='2c9da9a7-1f8c-490b-af98-87bbf6bf83db'
SOURCE=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser(allow_abbrev=False);parser.add_argument('--docker-host',required=True);parser.add_argument('--main-source',action='store_true');args=parser.parse_args()
if not args.main_source: raise SystemExit('Owned Analytics qualification requires explicit --main-source; source copying is disabled')
mode='owned-analytics'
test_file='tests/postgres/secureshopOwnedAnalytics.integration.test.js'
if args.docker_host!=EXPECTED_DOCKER:raise SystemExit('reviewed isolated Docker host required')
root=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-owned-analytics-'));os.chmod(root,0o700);workspace=SOURCE
owner=uuid.uuid4().hex;nonce=owner[:12];container='owasp-ai-goat-owned-analytics-'+nonce
docker=[str(DOCKER),'--host',args.docker_host]
env={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':os.environ['HOME'],'TMPDIR':str(root)}
state={'container':container,'owner':owner,'image':IMAGE,'evidence':str(root),'launcherPid':os.getpid(),
 'nodeVersion':None,'nodeSha256':None,'dockerSha256':None,'dockerDaemonId':None,'imageId':None,'containerCreationAttempted':False,'child':None,'runStatus':'preparing','cleanup':None,
 'mode':mode,'createdAt':datetime.now(timezone.utc).isoformat()}
ownership=root/'ownership.json';log_path=root/'tests.log';log_path.touch(mode=0o600)
def persist():ownership.write_text(json.dumps(state,indent=2)+'\n');os.chmod(ownership,0o600)
def run(command,**kwargs):kwargs.setdefault('timeout',120);return subprocess.run(command,check=True,env=kwargs.pop('env',env),**kwargs)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def validate_tap(text):
 lines=[line.strip() for line in text.splitlines() if line.strip()]
 plan=[line for line in lines if re.fullmatch(r'1\.\.1',line)]
 named=[line for line in lines if re.match(r'ok\s+\d+\b',line)]
 if len(plan)!=1 or len(named)!=1 or any(re.match(r'not ok\b',line) for line in lines): raise RuntimeError('exact one named TAP assertion required')
 if named!=['ok 1 - owned Analytics native candidate']: raise RuntimeError('unexpected TAP assertion')
 if any(re.search(r'#\s*(SKIP|TODO)\b',line,re.I) for line in lines if re.match(r'(?:not )?ok\s+\d+\b|\d+\.\.\d+',line)): raise RuntimeError('TAP skips and todos are not permitted')
 for key,value in [('tests',1),('pass',1),('fail',0),('cancelled',0),('skipped',0),('todo',0)]:
  if [line for line in lines if re.match(r'# '+key+r'\b',line)]!=[f'# {key} {value}']: raise RuntimeError('TAP summary mismatch')
 return {'plan':'1..1','namedAssertions':named,'skips':0,'todos':0}
def exact_absence(name=container):
 query=subprocess.run(docker+['ps','-a','--filter',f'name=^/{name}$','--format','{{.Names}}'],env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=30)
 if query.returncode:raise RuntimeError('exact-name container query failed')
 return not query.stdout.strip()
child=None;creation_attempted=False;inventory=[];gate=SignalGate();signal.signal(signal.SIGTERM,gate.handler);signal.signal(signal.SIGINT,gate.handler);persist()
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
 if digest(NODE)!=NODE_SHA256:raise RuntimeError('reviewed Node26.10 checksum mismatch')
 if digest(DOCKER)!=DOCKER_SHA256:raise RuntimeError('reviewed Docker executable checksum mismatch')
 state['nodeVersion']=version;state['nodeSha256']=NODE_SHA256;state['dockerSha256']=DOCKER_SHA256;persist()
 daemon_name=run(docker+['info','--format','{{.Name}}'],stdout=subprocess.PIPE,text=True).stdout.strip()
 if daemon_name!='colima-owasp-ai-goat-pg-verify':raise RuntimeError('reviewed isolated Docker daemon required')
 daemon_id=run(docker+['info','--format','{{.ID}}'],stdout=subprocess.PIPE,text=True).stdout.strip()
 if daemon_id!=DOCKER_DAEMON_ID:raise RuntimeError('reviewed Docker daemon ID mismatch')
 image_id=run(docker+['image','inspect','--format','{{.Id}}',IMAGE],stdout=subprocess.PIPE,text=True).stdout.strip()
 if image_id!=IMAGE:raise RuntimeError('immutable PostgreSQL image identity mismatch')
 state['dockerDaemon']=daemon_name;state['dockerDaemonId']=daemon_id;state['imageId']=image_id;persist()
 if not exact_absence():raise RuntimeError('owned container name unexpectedly exists')
 inventory=[test_file,'tests/postgres/run-owned-analytics-isolated.py','tests/postgres/sensitive_info_recovery_safety.py','package-lock.json','package.json']
 for folder in ['server/database/postgres','server/services','server/agent-runtime','server/data','db/postgres','scripts/lib','shared','agent-host','server/routes','server/middleware','tests/fixtures','sidecars/analytics-sql-target','docs/modernization/drafts/secureshop-bound-analytics']:
  inventory.extend(str(item.relative_to(workspace)) for item in sorted((workspace/folder).rglob('*')) if item.is_file())
 state['sourceSha256']={name:digest(workspace/name) for name in sorted(set(inventory))};state['nodeSha256']=digest(NODE);persist()
 run([str(NODE),'--check',test_file],cwd=workspace)
 creation_attempted=True;state['containerCreationAttempted']=True;persist()
 run(docker+['run','--detach','--pull','never','--name',container,'--label','owasp-ai-goat.test.owner='+owner,
  '--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size=268435456','-e','POSTGRES_HOST_AUTH_METHOD=trust',
  '-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',IMAGE,'-c','shared_buffers=16MB','-c','max_connections=40',
  '-c','max_wal_size=16MB','-c','min_wal_size=4MB','-c','cluster_name=owasp-ai-goat-owned-analytics-'+nonce],stdout=subprocess.DEVNULL)
 details=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]
 if details.get('Mounts') or details['Config']['Labels'].get('owasp-ai-goat.test.owner')!=owner:raise RuntimeError('owned PostgreSQL isolation/ownership check failed')
 for _ in range(100):
  ready=subprocess.run(docker+['exec',container,'pg_isready','-h','127.0.0.1','-U','postgres'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
  if ready.returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('owned PostgreSQL unavailable')
 port=int(run(docker+['port',container,'5432/tcp'],stdout=subprocess.PIPE,text=True).stdout.strip().rsplit(':',1)[1])
 psql=docker+['exec',container,'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-c']
 database='owasp_ai_goat_analytics_control_'+nonce
 run(psql+[f'CREATE DATABASE {database}'],stdout=subprocess.DEVNULL)
 for name in ['postgres','template0','template1',database]:
  run(psql+[f'REVOKE CONNECT ON DATABASE {name} FROM PUBLIC'],stdout=subprocess.DEVNULL)
 state['databases']=[database];persist()
 env['OWNED_ANALYTICS_NATIVE']='1'
 env['OWNED_ANALYTICS_OWNER']=nonce
 env['OWNED_ANALYTICS_PORT']=str(port)
 env['OWNED_ANALYTICS_CONTROL']=database
 env.update(NODE_ENV='test',PG_TEST_DISPOSABLE='yes',OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(workspace),
  PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',
  AI_PROVIDER='mock',TRANSFORMERS_OFFLINE='1',JWT_SECRET=uuid.uuid4().hex+uuid.uuid4().hex,SESSION_SECRET=uuid.uuid4().hex+uuid.uuid4().hex,
  AWS_EC2_METADATA_DISABLED='true',MCP_WORKSHOP_AUTOSTART='false',MCP_SIDECARS_AUTOSTART='false',SS_ENABLE='false',HF_HUB_OFFLINE='1',
  OLLAMA_BASE_URL='http://127.0.0.1:1',SANDBOX_RUNNER_URL='http://127.0.0.1:1',SSRF_TARGET_URL='http://127.0.0.1:1',
 ROGUE_MCP_URL='http://127.0.0.1:1',MAILPIT_API_URL='http://127.0.0.1:1',MAILPIT_SMTP_HOST='127.0.0.1',MAILPIT_SMTP_PORT='1')
 with log_path.open('w') as log:
  child=subprocess.Popen([str(NODE),'--test','--test-reporter=tap',test_file],cwd=workspace,env=env,stdout=log,stderr=log,start_new_session=True)
  state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid)};state['runStatus']='test_running';persist()
  try:code=child.wait(timeout=180)
  except subprocess.TimeoutExpired:stop_child();raise RuntimeError('Owned Analytics qualification timed out')
 if code:raise RuntimeError(f'Owned Analytics qualification failed ({code}); inspect retained tests.log')
 tap=validate_tap(log_path.read_text())
 after={name:digest(workspace/name) for name in sorted(set(inventory))}
 state['sourceAfterSha256']=after;state['sourceUnchanged']=after==state['sourceSha256'];state['tap']=tap
 if not state['sourceUnchanged']:raise RuntimeError('main source inventory changed during qualification')
 state['runStatus']='passed';state['resultSha256']=digest(log_path);persist()
except BaseException as error:
 if creation_attempted:
  try:
   diagnostic=subprocess.run(docker+['logs','--tail','120',container],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20)
   (root/'container.log').write_text(diagnostic.stdout);os.chmod(root/'container.log',0o600)
  except Exception as diagnostic_error:state['containerDiagnosticError']=type(diagnostic_error).__name__
 try:
  if inventory:
   after={name:digest(workspace/name) for name in sorted(set(inventory))};state['sourceAfterSha256']=after;state['sourceUnchanged']=after==state.get('sourceSha256')
 except Exception as inventory_error: state['sourceAfterError']=type(inventory_error).__name__
 state.update({'runStatus':'failed','errorType':type(error).__name__,'resultSha256':digest(log_path)});persist();raise
finally:
 gate.protect_cleanup();errors=[];remove_code=None;absent=None
 try:stop_child()
 except Exception as error:errors.append('child:'+type(error).__name__)
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
