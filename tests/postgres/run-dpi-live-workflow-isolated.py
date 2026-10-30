#!/usr/bin/env python3
"""Run the mounted eight-objective DPI actor/Judge proof in one owned PG18 cluster."""
import argparse, fcntl, hashlib, importlib.util, json, os, secrets, signal, stat, subprocess, sys, time, urllib.request
from datetime import datetime, timezone
from pathlib import Path

MAIN=Path(__file__).resolve().parents[2]
REQUIRED={'tests/postgres/run-dpi-live-workflow-isolated.py',
          'tests/postgres/dpiLiveWorkflow.integration.test.js',
          'tests/fixtures/dpiMountedQualification.js',
          'tests/postgres/sql_nosql_process_ownership.py',
          'tests/postgres/sql_nosql_docker_ownership.py',
          'tests/postgres/run-application-maintenance-fence-isolated.py',
          'server/routes/promptInjectionWorkshop.js',
          'server/services/promptInjectionWorkshop.js',
          'server/agent-runtime/objectiveJudge.js',
          'server/database/postgres/objectiveJudgmentRepository.js',
          'package.json','package-lock.json'}
SOURCE_ROOTS=('server/services','server/agent-runtime','server/database','server/routes',
              'server/data','server/config','server/middleware','server/utils','db/postgres',
              'scripts/lib','tests/postgres','tests/fixtures')
SOURCE_EXCLUDE=('__pycache__','.DS_Store')

def child_wait_timeout(db_route_preflight):
 return 120 if db_route_preflight else 2400

def enumerate_source():
 paths=set(REQUIRED)
 for name in SOURCE_ROOTS:
  root=MAIN/name
  if root.is_symlink() or not root.is_dir():raise RuntimeError('DPI source root changed')
  for path in root.rglob('*'):
   if any(part in SOURCE_EXCLUDE for part in path.parts) or path.suffix=='.pyc' or '.db' in path.suffixes or path.name.endswith(('.db-wal','.db-shm')):continue
   if path.is_symlink():raise RuntimeError('DPI source symlink refused')
   if path.is_file():paths.add(path.relative_to(MAIN).as_posix())
   elif not path.is_dir():raise RuntimeError('DPI source entry unsupported')
 return paths

def digest(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as stream:
  for chunk in iter(lambda:stream.read(1024*1024),b''):h.update(chunk)
 return h.hexdigest()

def validate_inputs(args):
 source=Path(args.main_workspace)
 if source!=MAIN or source.resolve()!=source or source.is_symlink():raise RuntimeError('Exact current main workspace required')
 manifest_path=Path(args.manifest)
 if not manifest_path.is_absolute() or manifest_path.is_symlink() or digest(manifest_path)!=args.manifest_sha256:raise RuntimeError('Main manifest pin mismatch')
 manifest=json.loads(manifest_path.read_text())
 if manifest.get('cohort')!='dpi-live-workflow-main' or manifest.get('scope')!=args.scope or manifest.get('workspace')!=str(MAIN) or manifest.get('mode')!='actual-model':raise RuntimeError('Wrong main DPI manifest')
 pins=manifest.get('sourcePins')
 if manifest.get('sourceRoots')!=list(SOURCE_ROOTS) or not isinstance(pins,dict) or not enumerate_source().issubset(pins):raise RuntimeError('Incomplete DPI source closure')
 for rel,expected in pins.items():
  path=MAIN/rel
  if Path(rel).is_absolute() or '..' in Path(rel).parts or path.is_symlink() or not path.resolve().is_relative_to(MAIN) or digest(path)!=expected:raise RuntimeError('Main source pin mismatch')
 python_path=str(Path(sys.executable).resolve(strict=True))
 for path,expected in ((args.node,args.node_sha256),(args.docker,args.docker_sha256),(python_path,args.python_sha256)):
  binary=Path(path)
  if not binary.is_absolute() or binary.is_symlink() or binary.resolve()!=binary or digest(binary)!=expected:raise RuntimeError('Runtime pin mismatch')
 if manifest.get('runtimePins')!={'node':{'path':args.node,'sha256':args.node_sha256},'docker':{'path':args.docker,'sha256':args.docker_sha256},'python':{'path':python_path,'sha256':args.python_sha256}}:raise RuntimeError('Runtime manifest mismatch')
 if manifest.get('imageId')!=args.image_id or manifest.get('dockerDaemon')!=args.docker_daemon:raise RuntimeError('Docker authority mismatch')
 if manifest.get('model')!='llama3.1:8b' or manifest.get('modelDigest')!=args.model_digest:raise RuntimeError('Model manifest mismatch')
 helper=MAIN/'tests/postgres/run-application-maintenance-fence-isolated.py'
 spec=importlib.util.spec_from_file_location('dpi_dependency_inventory',helper)
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 if module.inventory(MAIN/'node_modules')!=manifest.get('dependencyInventory'):raise RuntimeError('Main dependency inventory mismatch')
 return manifest

parser=argparse.ArgumentParser()
parser.add_argument('--docker-host',required=True)
parser.add_argument('--evidence-dir',required=True)
parser.add_argument('--container',required=True)
parser.add_argument('--grant-file',required=True)
parser.add_argument('--grant-id',required=True)
parser.add_argument('--scope',choices=['all','system_prompt'],default='all')
parser.add_argument('--main-workspace',required=True)
for name in ('manifest','manifest-sha256','node','node-sha256','docker','docker-sha256','docker-daemon','image-id','python-sha256','model-digest'):
 parser.add_argument('--'+name,required=True)
parser.add_argument('--plan',action='store_true')
parser.add_argument('--db-route-preflight',action='store_true',help='Exercise owned authentication, PostgreSQL route and teardown without generation')
args=parser.parse_args()
manifest=validate_inputs(args)
from sql_nosql_process_ownership import OwnedProcesses
from sql_nosql_docker_ownership import verify_daemon, verify_image, inspect_owned, validate_container_layout, cleanup_owned
source=MAIN
if not args.docker_host.startswith('unix:///') or not args.container.startswith('owasp-ai-goat-dpi-live-'):
 raise RuntimeError('Owned local Docker authority required')
if args.plan:
 print(json.dumps({'mode':'main-checkout-no-copy','scope':args.scope,'allocation':False,'sourcePins':len(manifest['sourcePins']),'dependencyEntries':len(manifest['dependencyInventory']),'childWaitSeconds':child_wait_timeout(args.db_route_preflight)}))
 raise SystemExit(0)
evidence=Path(args.evidence_dir)
if not evidence.is_absolute() or evidence.resolve()!=evidence or evidence.name!='evidence' or evidence.parent.parent!=Path('/private/tmp') or evidence.parent.is_symlink():raise RuntimeError('Private /private/tmp/<owned>/evidence required')
parent_stat=evidence.parent.lstat()
if not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid!=os.getuid() or stat.S_IMODE(parent_stat.st_mode)!=0o700:raise RuntimeError('Owned evidence parent required')
evidence.mkdir(mode=0o700,exist_ok=False)
for name in ('home','tmp','logs','cache'):(evidence/name).mkdir(mode=0o700)
container=args.container
base_env={'PATH':str(Path(args.node).parent)+':/usr/bin:/bin','HOME':str(evidence/'home'),'TMPDIR':str(evidence/'tmp'),'XDG_CACHE_HOME':str(evidence/'cache'),'LANG':'C'}
docker=[args.docker,'--host',args.docker_host];child=None;started=False;terminal='terminal_fail'
ownership_path=evidence/'ownership.json';result_path=evidence/'result.log';diagnostics_path=evidence/'diagnostics.json';docker_log=evidence/'docker.log'
state={'container':container,'dockerHost':args.docker_host,'evidence':str(evidence),'grantId':args.grant_id,'scope':args.scope,'launcherPid':os.getpid(),'ownerHandle':None,'createdAt':datetime.now(timezone.utc).isoformat(),'started':False,'mounts':[],'cleanup':None,'nodeVersion':None,'children':[],'manifestSha256':args.manifest_sha256,'mainSource':str(source)}
def save_ownership():
 if ownership_path.exists() and state.get('ownerHandle') is None:
  try:state['ownerHandle']=json.loads(ownership_path.read_text()).get('ownerHandle')
  except (OSError,json.JSONDecodeError):pass
 tmp=ownership_path.with_suffix('.tmp');tmp.write_text(json.dumps(state,indent=2,sort_keys=True)+'\n');os.chmod(tmp,0o600);tmp.replace(ownership_path)
save_ownership()
def run(command,**kwargs):kwargs.setdefault('timeout',60);return subprocess.run(command,check=True,env=base_env,**kwargs)
def update_grant(mutator):
 grant=Path(args.grant_file)
 if not grant.is_absolute() or grant.is_symlink() or grant.resolve()!=grant or grant.is_relative_to(MAIN):raise RuntimeError('Private exact grant path required')
 metadata=grant.lstat()
 if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=os.getuid() or metadata.st_nlink!=1 or stat.S_IMODE(metadata.st_mode)!=0o600:raise RuntimeError('Private owned grant required')
 fd=os.open(grant,os.O_RDWR|os.O_NOFOLLOW)
 with os.fdopen(fd,'r+') as handle:
  fcntl.flock(handle.fileno(),fcntl.LOCK_EX);data=json.load(handle);mutator(data);handle.seek(0);json.dump(data,handle,indent=2,sort_keys=True);handle.write('\n');handle.truncate();handle.flush();os.fsync(handle.fileno());fcntl.flock(handle.fileno(),fcntl.LOCK_UN)
def consume(data):
 if data.get('grantId')!=args.grant_id or data.get('owner')!='/root' or data.get('status')!='granted' or data.get('allowedLaunches')!=1:raise RuntimeError('single-use DPI native grant is absent, mismatched, or already consumed')
 data.update(status='consumed',consumedAt=datetime.now(timezone.utc).isoformat(),ownerHandle=os.getpid(),launcherPid=os.getpid(),container=container,evidence=str(evidence),runStatus='starting')
def group_members(pgid,session):
 result=subprocess.run(['/bin/ps','-axo','pid=,pgid=,uid='],env=base_env,capture_output=True,text=True,check=True,timeout=3)
 members=[]
 for line in result.stdout.splitlines():
  pid,group,uid=map(int,line.split())
  if group!=pgid:continue
  try:
   if uid!=os.getuid() or os.getsid(pid)!=session:raise RuntimeError('Foreign process-group member')
  except ProcessLookupError:continue
  members.append(pid)
 return members
def stop_group(process,pgid,session):
 if group_members(pgid,session):os.killpg(pgid,signal.SIGTERM)
 deadline=time.monotonic()+10
 while group_members(pgid,session) and time.monotonic()<deadline:process.poll();time.sleep(.05)
 if group_members(pgid,session):os.killpg(pgid,signal.SIGKILL)
 process.wait(timeout=10)
 deadline=time.monotonic()+5
 while group_members(pgid,session) and time.monotonic()<deadline:time.sleep(.05)
 if group_members(pgid,session):raise RuntimeError('Owned process group remains')
processes=OwnedProcesses(stop_group,lambda row:(state['children'].append(row),save_ownership()))
processes.install()
workspace=source
state['sourceSha256']=digest(workspace/'tests/postgres/dpiLiveWorkflow.integration.test.js');save_ownership()
labels={'owasp-ai-goat.test.cohort':'dpi-live-workflow-main','owasp-ai-goat.test.grant':args.grant_id}
captured_id=None
def docker_command(argv):
 return subprocess.run(docker+argv,env=base_env,capture_output=True,text=True,timeout=30)
def verify_model():
 request=urllib.request.Request('http://127.0.0.1:11434/api/tags',method='GET')
 with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=5) as response:
  if response.status!=200:raise RuntimeError('Ollama model inventory unavailable')
  payload=json.load(response)
 matches=[row for row in payload.get('models',[]) if row.get('name')==manifest['model'] and row.get('digest')==manifest['modelDigest']]
 if len(matches)!=1:raise RuntimeError('Actual Ollama model digest mismatch')
try:
 version=run([args.node,'--version'],capture_output=True,text=True).stdout.strip();state['nodeVersion']=version;save_ownership()
 if not version.startswith('v26.'):raise RuntimeError('supported Node 26 runtime required')
 verify_daemon(docker_command,args.docker_daemon);verify_image(docker_command,args.image_id)
 verify_model()
 if inspect_owned(docker_command,name=container,labels=labels,image=args.image_id) is not None:raise RuntimeError('Owned container name occupied')
 update_grant(consume)
 response=docker_command(['run','--detach','--pull','never','--name',container,'--label','owasp-ai-goat.test.cohort=dpi-live-workflow-main','--label','owasp-ai-goat.test.grant='+args.grant_id,'--memory','512m','--cpus','2','--pids-limit','256','--tmpfs','/var/lib/postgresql:rw,size=268435456','-e','POSTGRES_USER=dpi_live_owner','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',args.image_id,'-c','shared_buffers=16MB','-c','max_connections=32','-c','max_wal_size=16MB','-c','min_wal_size=4MB'])
 if response.returncode:raise RuntimeError('Owned PostgreSQL container creation failed')
 started=True
 inspected=inspect_owned(docker_command,name=container,labels=labels,image=args.image_id)
 captured_id=inspected['Id'];port=validate_container_layout(inspected)
 state.update(started=True,containerId=captured_id,mounts=inspected.get('Mounts',[]));save_ownership()
 deadline=time.monotonic()+30
 while time.monotonic()<deadline:
  probe=docker_command(['exec',captured_id,'pg_isready','-h','127.0.0.1','-U','dpi_live_owner'])
  if probe.returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('owned PostgreSQL container did not become TCP ready')
 for role in ['dvaia_identity_migration','dvaia_identity_runtime']:
  created=docker_command(['exec',captured_id,'psql','-h','127.0.0.1','-U','dpi_live_owner','-d','postgres','-v','ON_ERROR_STOP=1','-c',f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'])
  if created.returncode:raise RuntimeError('Owned PostgreSQL role creation failed')
 url=f'postgresql://dpi_live_owner@127.0.0.1:{port}/postgres'
 env=dict(base_env,NODE_ENV='test',RUN_LIVE_DPI_WORKFLOW='1',PG_TEST_DISPOSABLE='yes',DPI_LIVE_ISOLATED='1',DPI_LIVE_SCOPE=args.scope,PG_LIVE_ADMIN_URL=url,DPI_LIVE_DIAGNOSTICS_PATH=str(diagnostics_path),PLATFORM_DATABASE_ENGINE='postgres',JWT_SECRET=secrets.token_hex(32),AI_PROVIDER='ollama',OLLAMA_BASE_URL='http://127.0.0.1:11434',OLLAMA_MODEL='llama3.1:8b',JUDGE_PROVIDER='ollama',JUDGE_MODEL='llama3.1:8b',AWS_EC2_METADATA_DISABLED='true',OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(workspace),LOGS_DIR=str(evidence/'logs'),OWASP_AI_GOAT_APP_DATA_ROOT=str(evidence/'appdata'),LEGACY_SENSITIVE_FILES_ROOT=str(evidence/'assets'))
 if args.db_route_preflight:env['DPI_LIVE_BOOT_ONLY']='1'
 for name in ('appdata','assets'):(evidence/name).mkdir(mode=0o700)
 with result_path.open('x') as log:
  os.chmod(result_path,0o600)
  child=processes.launch([args.node,'--test','--test-reporter=tap','tests/postgres/dpiLiveWorkflow.integration.test.js'],name='dpi-live',cwd=workspace,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);state['testPid']=child.pid;state['runStatus']='running';save_ownership();code=child.wait(timeout=child_wait_timeout(args.db_route_preflight));processes.finish(child)
 if result_path.stat().st_size>64*1024*1024:raise RuntimeError('DPI result log exceeds private cap')
 print(json.dumps({'resultLog':str(result_path),'resultSha256':digest(result_path),'childExitCode':code}),flush=True)
 if code:raise RuntimeError(f'DPI live workflow failed ({code})')
 terminal='terminal_pass';state['runStatus']=terminal
finally:
 processes.mask_cleanup_signals()
 failures=[]
 try:processes.cleanup()
 except BaseException as error:failures.append('process:'+type(error).__name__)
 if state.get('runStatus')!='terminal_pass':state['runStatus']=terminal
 if started:
  try:
   logs=docker_command(['logs',captured_id or container]);docker_log.write_text(logs.stdout+logs.stderr);os.chmod(docker_log,0o600)
  except BaseException as error:failures.append('container-log:'+type(error).__name__)
  try:
   state['cleanup']=cleanup_owned(docker_command,daemon_id=args.docker_daemon,name=container,labels=labels,image=args.image_id,captured_id=captured_id)
  except BaseException as error:failures.append('container:'+type(error).__name__)
 else:state['cleanup']={'status':'not-started'}
 try:validate_inputs(args)
 except BaseException as error:failures.append('source-drift:'+type(error).__name__)
 if failures:state['runStatus']='cleanup_failed';state['cleanupFailures']=failures
 state['completedAt']=datetime.now(timezone.utc).isoformat();save_ownership()
 def complete(data):
  if data.get('grantId')==args.grant_id and data.get('launcherPid')==os.getpid():data.update(runStatus=state['runStatus'],completedAt=state['completedAt'],cleanup=state['cleanup'],ownershipSha256=hashlib.sha256(ownership_path.read_bytes()).hexdigest(),resultSha256=hashlib.sha256(result_path.read_bytes()).hexdigest() if result_path.exists() else None)
 try:update_grant(complete)
 except BaseException as error:failures.append('grant:'+type(error).__name__)
 processes.restore()
 print(f'Owned container cleanup complete; evidence retained: {evidence}',flush=True)
 if failures:raise RuntimeError('Owned cleanup, source integrity or grant finalization failed')
