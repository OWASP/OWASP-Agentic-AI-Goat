#!/usr/bin/env python3
"""Qualify the configured full index and rendered multi-target System restart recovery and canonical cleanup; no model."""
import argparse, hashlib, json, os, secrets, signal, subprocess, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from sensitive_info_recovery_safety import SignalGate

EXPECTED_DOCKER='unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
NODE=Path('/Users/averma5/.dvaia/runtimes/node-v26.9.0-darwin-arm64/bin/node')
DOCKER=Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')
IMAGE='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
LISTENER_BASE='sha256:3a771f83944bb763050c23c0225c260638c4b7899e7a72485ef75e5e570499e5'
SOURCE=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True);args=parser.parse_args()
mode='system-restart-enabled-index-registered'
test_file='tests/postgres/secureshopSystemRestartEnabledIndex.integration.test.js'
if args.docker_host!=EXPECTED_DOCKER:raise SystemExit('reviewed isolated Docker host required')
root=Path(tempfile.mkdtemp(prefix='dvaia-system-restart-enabled-index-')).resolve();os.chmod(root,0o700);workspace=root/'source'
container='dvaia-system-restart-enabled-index-'+uuid.uuid4().hex[:12];owner=uuid.uuid4().hex
listener=container+'-listener';volume=container+'-state';tag=container+':owned';listener_image_id=None
docker=[str(DOCKER),'--host',args.docker_host]
env={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':os.environ['HOME'],'TMPDIR':str(root)}
state={'container':container,'listenerContainer':listener,'volume':volume,'listenerTag':tag,'owner':owner,'image':IMAGE,'listenerBase':LISTENER_BASE,'evidence':str(root),'launcherPid':os.getpid(),
 'nodeVersion':None,'containerCreationAttempted':False,'child':None,'runStatus':'preparing','cleanup':None,
 'mode':mode,'actualModel':None,'createdAt':datetime.now(timezone.utc).isoformat()}
ownership=root/'ownership.json';log_path=root/'tests.log';log_path.touch(mode=0o600)
def persist():ownership.write_text(json.dumps(state,indent=2)+'\n');os.chmod(ownership,0o600)
def run(command,**kwargs):kwargs.setdefault('timeout',120);return subprocess.run(command,check=True,env=kwargs.pop('env',env),**kwargs)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def exact_absence(name=container):
 query=subprocess.run(docker+['ps','-a','--filter',f'name=^/{name}$','--format','{{.Names}}'],env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=30)
 if query.returncode:raise RuntimeError('exact-name container query failed')
 return not query.stdout.strip()
def inspect_absence(kind,name):
 return subprocess.run(docker+[kind,'inspect',name],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30).returncode!=0
child=None;creation_attempted=False;gate=SignalGate();signal.signal(signal.SIGTERM,gate.handler);signal.signal(signal.SIGINT,gate.handler);persist()
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
 child.poll()
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
 if daemon_name!='colima-dvaia-pg-verify':raise RuntimeError('reviewed isolated Docker daemon required')
 image_id=run(docker+['image','inspect','--format','{{.Id}}',IMAGE],stdout=subprocess.PIPE,text=True).stdout.strip()
 if image_id!=IMAGE:raise RuntimeError('immutable PostgreSQL image identity mismatch')
 listener_base_id=run(docker+['image','inspect','--format','{{.Id}}',LISTENER_BASE],stdout=subprocess.PIPE,text=True).stdout.strip()
 if listener_base_id!=LISTENER_BASE:raise RuntimeError('immutable listener base image identity mismatch')
 state['dockerDaemon']=daemon_name;state['imageId']=image_id;persist()
 if not exact_absence() or not exact_absence(listener):raise RuntimeError('owned container name unexpectedly exists')
 run([str(NODE),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(SOURCE),str(workspace)],cwd=SOURCE)
 (workspace/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
 (workspace/'client/node_modules').symlink_to(SOURCE/'client/node_modules',target_is_directory=True)
 inventory=[test_file,'tests/fixtures/secureshopEnabledSystemRestartBrowser.js','tests/fixtures/secureshopSystemRestartBrowser.js','tests/secureshopSystemRestartLifecycle.test.js','db/postgres/workshop-migrations/secureshop_review/0020_bound_owned_system_restart.sql','db/postgres/workshop-migrations/secureshop_review/0021_bound_owned_system_restart_manager.sql','tests/postgres/run-system-restart-enabled-index-isolated.py','tests/postgres/sensitive_info_recovery_safety.py','package-lock.json','package.json']
 for folder in ['server','db/postgres','scripts','shared','agent-host','client','tests/fixtures','sidecars/sandbox-runner/owned-system']:
  inventory.extend(str(item.relative_to(workspace)) for item in sorted((workspace/folder).rglob('*')) if item.is_file())
 state['sourceSha256']={name:digest(workspace/name) for name in sorted(set(inventory))};state['nodeSha256']=digest(NODE);persist()
 run([str(NODE),'--check',test_file],cwd=workspace)
 run([str(NODE),'--test','tests/secureshopSystemRestartLifecycle.test.js','tests/secureshopSystemRestartConcurrency.review.test.js','tests/secureshopRestartManagerConcurrency.review.test.js'],cwd=workspace,stdout=subprocess.DEVNULL)
 creation_attempted=True;state['containerCreationAttempted']=True;persist()
 run(docker+['run','--detach','--pull','never','--name',container,'--label','dvaia.test.owner='+owner,
  '--memory','1g','--cpus','2','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size=1073741824','-e','POSTGRES_HOST_AUTH_METHOD=trust',
  '-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',IMAGE,'-c','shared_buffers=16MB','-c','max_connections=100',
  '-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL)
 details=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]
 if details.get('Mounts') or details['Config']['Labels'].get('dvaia.test.owner')!=owner:raise RuntimeError('owned PostgreSQL isolation/ownership check failed')
 for _ in range(100):
  ready=subprocess.run(docker+['exec',container,'pg_isready','-h','127.0.0.1','-U','postgres'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
  if ready.returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('owned PostgreSQL unavailable')
 port=int(run(docker+['port',container,'5432/tcp'],stdout=subprocess.PIPE,text=True).stdout.strip().rsplit(':',1)[1])
 psql=docker+['exec',container,'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-c']
 manifest=json.loads(run([str(NODE),'-e',"console.log(JSON.stringify(require('./db/postgres/initialize-application').requiredStoreManifest))"],cwd=workspace,stdout=subprocess.PIPE,text=True).stdout)
 if len(manifest)!=16:raise RuntimeError('full16 manifest required')
 for row in manifest:
  family=row['schema'];migration='dvaia_'+family+'_migration';runtime=row['runtimeRole'];database='dvaia_test_full_backend_'+family
  run(psql+[f'CREATE ROLE {migration} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE {runtime} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],stdout=subprocess.DEVNULL)
  run(psql+[f'CREATE DATABASE {database} OWNER {migration}'],stdout=subprocess.DEVNULL)
  run(psql+[f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime}'],stdout=subprocess.DEVNULL)
  env[row['migrationVariable']]=f'postgresql://{migration}@127.0.0.1:{port}/{database}'
  env[row['runtimeVariable']]=f'postgresql://{runtime}@127.0.0.1:{port}/{database}'
 runtime_root=root/'runtime';runtime_root.mkdir(mode=0o700)
 env.update(NODE_ENV='test',PG_TEST_DISPOSABLE='yes',PG_SECURESHOP_RESTART_ENABLED_INDEX='1',DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace),DVAIA_FULL_BACKEND_RUNTIME_ROOT=str(runtime_root))
 # Build children are owned process groups just like the test process.
 state['buildChildren']=[]
 for name,command in [('client',[str(NODE),str(workspace/'client/node_modules/vite/bin/vite.js'),'build']),('review-renderer',[str(NODE),str(workspace/'client/node_modules/vite/bin/vite.js'),'build','--config','vite.review-renderer.config.mjs'])]:
  with (root/(name+'-build.log')).open('w') as log:
   child=subprocess.Popen(command,cwd=workspace/'client',env=env,stdout=log,stderr=log,start_new_session=True)
   state['child']={'pid':child.pid,'pgid':child.pid};state['buildChildren'].append(child.pid);persist()
   try:build_code=child.wait(timeout=240)
   except subprocess.TimeoutExpired:stop_child();raise RuntimeError('Owned client build timed out')
   stop_child()
   if build_code:raise RuntimeError('Owned client build failed')
 for item in (workspace/'client/build').rglob('*'):
  if item.is_file():state['sourceSha256'][str(item.relative_to(workspace))]=digest(item)
 persist()
 import shutil
 cache=Path('/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/dvaia-csrf-clean-rag-lrvupnva/source/model-cache')
 if not cache.is_dir():raise RuntimeError('reviewed cached CPU embedding runtime unavailable')
 shutil.copytree(cache,workspace/'model-cache')
 cache_files={str(item.relative_to(workspace/'model-cache')):digest(item) for item in sorted((workspace/'model-cache').rglob('*')) if item.is_file()}
 cache_manifest=json.dumps(cache_files,sort_keys=True,separators=(',',':')).encode()
 expected_manifest='dfc9cfe80991bb642c319ab95514b3bb1cebd9c3132def77b9afd0274d9f7d6e'
 if len(cache_files)!=4 or hashlib.sha256(cache_manifest).hexdigest()!=expected_manifest:raise RuntimeError('embedding cache manifest mismatch')
 state['embeddingCache']={'source':str(cache),'copiedPath':str(workspace/'model-cache'),'fileCount':len(cache_files),'manifestSha256':expected_manifest};persist()
 env['XENOVA_CACHE']=str(workspace/'model-cache');env['TRANSFORMERS_CACHE']=str(workspace/'model-cache')
 for directory,dirs,files in os.walk(workspace,followlinks=False):
  for name in files:
   item=Path(directory)/name
   if not item.is_symlink():item.chmod(item.stat().st_mode & ~0o222)
  Path(directory).chmod(Path(directory).stat().st_mode & ~0o222)

 with (root/'listener-build.log').open('w') as log:
  child=subprocess.Popen(docker+['build','--pull=false','--network=default','--label','dvaia.test.owner='+owner,'-f','Dockerfile.local','-t',tag,'.'],cwd=workspace/'sidecars/sandbox-runner/owned-system',env=env,stdout=log,stderr=log,start_new_session=True)
  state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid),'purpose':'listener_build'};persist()
  try:listener_build=child.wait(timeout=300)
  except subprocess.TimeoutExpired:stop_child();raise RuntimeError('Owned restart listener build timed out')
  stop_child()
  if listener_build:raise RuntimeError('Owned restart listener build failed')
 listener_image_id=run(docker+['image','inspect','--format','{{.Id}}',tag],stdout=subprocess.PIPE,text=True).stdout.strip();state['listenerImageId']=listener_image_id
 run(docker+['volume','create','--label','dvaia.test.owner='+owner,volume],stdout=subprocess.DEVNULL)
 token=secrets.token_urlsafe(32);envfile=root/'restart.env';envfile.write_text('SECURESHOP_SYSTEM_RESTART_HTTP_ENABLED=true\nSECURESHOP_SYSTEM_RESTART_TOKEN='+token+'\nSECURESHOP_SYSTEM_RESTART_HOST=0.0.0.0\nSECURESHOP_SYSTEM_RESTART_PORT=8090\n');os.chmod(envfile,0o600)
 run(docker+['run','-d','--pull','never','--name',listener,'--label','dvaia.test.owner='+owner,'--read-only','--user','10001:10001','--memory','512m','--cpus','1','--pids-limit','512','--tmpfs','/tmp:rw,nosuid,nodev,size=128m','--tmpfs','/owned-restart:rw,nosuid,nodev,size=8m,mode=0700,uid=10001,gid=10001','--mount','type=volume,source='+volume+',target=/var/lib/dvaia-owned-restart','--security-opt','seccomp=unconfined','--security-opt','apparmor=dvaia-mcp-sandbox','-p','127.0.0.1::8090','--env-file',str(envfile),listener_image_id,'restart'],stdout=subprocess.DEVNULL);envfile.unlink()
 listener_port=int(run(docker+['port',listener,'8090/tcp'],stdout=subprocess.PIPE,text=True).stdout.strip().rsplit(':',1)[1]);deadline=time.monotonic()+60
 while time.monotonic()<deadline:
  ready=subprocess.run([str(NODE),'-e',"fetch(process.argv[1],{headers:{authorization:'Bearer '+process.argv[2]}}).then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))",f'http://127.0.0.1:{listener_port}/secureshop/system/restart-health',token],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3)
  if ready.returncode==0:break
  time.sleep(.15)
 else:raise RuntimeError('Owned restart listener unavailable')
 env['PG_SECURESHOP_RESTART_ORIGIN']=f'http://127.0.0.1:{listener_port}';env['PG_SECURESHOP_RESTART_TOKEN']=token;state['listenerPort']=listener_port;persist()

 with log_path.open('w') as log:
  child=subprocess.Popen([str(NODE),'--test','--test-reporter=tap',test_file],cwd=workspace,env=env,stdout=log,stderr=log,start_new_session=True)
  state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid)};state['runStatus']='test_running';persist()
  try:code=child.wait(timeout=420)
  except subprocess.TimeoutExpired:stop_child();raise RuntimeError('System restart enabled-index qualification timed out')
 if code:raise RuntimeError(f'System restart enabled-index qualification failed ({code}); inspect retained tests.log')
 runtime_result=runtime/'system-restart-enabled-index-result.json'
 if not runtime_result.is_file():raise RuntimeError('System restart runtime result missing')
 state['runStatus']='passed';state['logSha256']=digest(log_path);state['runtimeResultSha256']=digest(runtime_result);persist()
except BaseException as error:
 if creation_attempted:
  try:
   diagnostic=subprocess.run(docker+['logs','--tail','120',container],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20)
   (root/'container.log').write_text(diagnostic.stdout);os.chmod(root/'container.log',0o600)
  except Exception as diagnostic_error:state['containerDiagnosticError']=type(diagnostic_error).__name__
  try:
   if not exact_absence(listener):
    diagnostic=subprocess.run(docker+['logs','--tail','160',listener],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20)
    (root/'listener.log').write_text(diagnostic.stdout);os.chmod(root/'listener.log',0o600)
  except Exception as diagnostic_error:state['listenerDiagnosticError']=type(diagnostic_error).__name__
 state.update({'runStatus':'failed','errorType':type(error).__name__,'logSha256':digest(log_path)});persist();raise
finally:
 gate.protect_cleanup();errors=[];remove_code=None;absent=None
 try:stop_child()
 except Exception as error:errors.append('child:'+type(error).__name__)
 for name in [listener,container]:
  try:
   if not exact_absence(name):
    info=json.loads(run(docker+['inspect',name],stdout=subprocess.PIPE,text=True).stdout)[0]
    if info['Config']['Labels'].get('dvaia.test.owner')!=owner:raise RuntimeError('refusing foreign container cleanup')
    code=subprocess.run(docker+['rm','-f','-v',name],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30).returncode
    if name==container:remove_code=code
  except Exception as error:errors.append('remove_'+name+':'+type(error).__name__)
 try:
  if not inspect_absence('volume',volume):subprocess.run(docker+['volume','rm',volume],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
 except Exception as error:errors.append('volume:'+type(error).__name__)
 try:
  if not inspect_absence('image',tag):subprocess.run(docker+['image','rm',tag],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=40)
 except Exception as error:errors.append('image:'+type(error).__name__)
 try:absent=exact_absence();listener_absent=exact_absence(listener);volume_absent=inspect_absence('volume',volume);tag_absent=inspect_absence('image',tag);image_id_absent=not listener_image_id or inspect_absence('image',listener_image_id)
 except Exception as error:errors.append('absence:'+type(error).__name__);listener_absent=volume_absent=tag_absent=image_id_absent=False
 try:pgid_absent=not state.get('child') or not owned_group_members(state['child']['pgid'])
 except Exception as error:errors.append('pgid:'+type(error).__name__);pgid_absent=False
 state['cleanup']={'removeExitCode':remove_code,'containerAbsent':absent,'listenerAbsent':listener_absent,'volumeAbsent':volume_absent,'listenerTagAbsent':tag_absent,'listenerImageIdAbsent':image_id_absent,'nodeBrowserPgidAbsent':pgid_absent,
  'errors':errors,'completedAt':datetime.now(timezone.utc).isoformat()}
 if state['runStatus']=='passed' and (errors or not all([absent,listener_absent,volume_absent,tag_absent,image_id_absent,pgid_absent]) or (creation_attempted and remove_code not in (None,0))):state['runStatus']='failed';state['errorType']='CleanupFailed'
 persist()
print(json.dumps({'evidence':str(root),'status':state['runStatus'],'cleanup':state['cleanup']}),flush=True)
if state['runStatus']!='passed':raise SystemExit(1)
