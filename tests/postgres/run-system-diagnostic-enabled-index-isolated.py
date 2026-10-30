#!/usr/bin/env python3
"""Qualify registered diagnostic full index plus config and diagnostic executors; no model."""
import argparse, hashlib, json, os, signal, subprocess, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from sensitive_info_recovery_safety import SignalGate

EXPECTED_DOCKER='unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock'
NODE=Path('/Users/averma5/.owasp-ai-goat/runtimes/node-v26.9.0-darwin-arm64/bin/node')
DOCKER=Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')
IMAGE='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
SOURCE=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True);args=parser.parse_args()
mode='system-diagnostic-enabled-index-registered'
test_file='tests/postgres/secureshopSystemDiagnosticEnabledIndex.integration.test.js'
if args.docker_host!=EXPECTED_DOCKER:raise SystemExit('reviewed isolated Docker host required')
root=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-system-diagnostic-enabled-index-')).resolve();os.chmod(root,0o700);workspace=root/'source'
container='owasp-ai-goat-system-diagnostic-enabled-index-'+uuid.uuid4().hex[:12];owner=uuid.uuid4().hex
docker=[str(DOCKER),'--host',args.docker_host]
env={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':os.environ['HOME'],'TMPDIR':str(root)}
state={'container':container,'owner':owner,'image':IMAGE,'evidence':str(root),'launcherPid':os.getpid(),
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
executor=None;config_executor=None;child=None;creation_attempted=False;gate=SignalGate();signal.signal(signal.SIGTERM,gate.handler);signal.signal(signal.SIGINT,gate.handler);persist()
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
 if daemon_name!='colima-owasp-ai-goat-pg-verify':raise RuntimeError('reviewed isolated Docker daemon required')
 image_id=run(docker+['image','inspect','--format','{{.Id}}',IMAGE],stdout=subprocess.PIPE,text=True).stdout.strip()
 if image_id!=IMAGE:raise RuntimeError('immutable PostgreSQL image identity mismatch')
 state['dockerDaemon']=daemon_name;state['imageId']=image_id;persist()
 if not exact_absence():raise RuntimeError('owned container name unexpectedly exists')
 run([str(NODE),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(SOURCE),str(workspace)],cwd=SOURCE)
 (workspace/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
 (workspace/'client/node_modules').symlink_to(SOURCE/'client/node_modules',target_is_directory=True)
 inventory=[test_file,'tests/postgres/system_diagnostic_owned_executor.py','tests/postgres/system_config_owned_executor.py','tests/fixtures/secureshopEnabledSystemDiagnosticBrowser.js','db/postgres/workshop-migrations/secureshop_agents/0030_bound_system_diagnostics.sql','tests/postgres/run-system-diagnostic-enabled-index-isolated.py','tests/postgres/sensitive_info_recovery_safety.py','package-lock.json','package.json']
 for folder in ['server','db/postgres','scripts','shared','agent-host','client','tests/fixtures','sidecars/sandbox-runner/owned-system']:
  inventory.extend(str(item.relative_to(workspace)) for item in sorted((workspace/folder).rglob('*')) if item.is_file())
 state['sourceSha256']={name:digest(workspace/name) for name in sorted(set(inventory))};state['nodeSha256']=digest(NODE);persist()
 run([str(NODE),'--check',test_file],cwd=workspace)
 creation_attempted=True;state['containerCreationAttempted']=True;persist()
 run(docker+['run','--detach','--pull','never','--name',container,'--label','owasp-ai-goat.test.owner='+owner,
  '--memory','1g','--cpus','2','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size=1073741824','-e','POSTGRES_HOST_AUTH_METHOD=trust',
  '-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',IMAGE,'-c','shared_buffers=16MB','-c','max_connections=100',
  '-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL)
 details=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]
 if details.get('Mounts') or details['Config']['Labels'].get('owasp-ai-goat.test.owner')!=owner:raise RuntimeError('owned PostgreSQL isolation/ownership check failed')
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
  family=row['schema'];migration='dvaia_'+family+'_migration';runtime=row['runtimeRole'];database='owasp_ai_goat_test_full_backend_'+family
  run(psql+[f'CREATE ROLE {migration} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE {runtime} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],stdout=subprocess.DEVNULL)
  run(psql+[f'CREATE DATABASE {database} OWNER {migration}'],stdout=subprocess.DEVNULL)
  run(psql+[f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime}'],stdout=subprocess.DEVNULL)
  env[row['migrationVariable']]=f'postgresql://{migration}@127.0.0.1:{port}/{database}'
  env[row['runtimeVariable']]=f'postgresql://{runtime}@127.0.0.1:{port}/{database}'
 runtime_root=root/'runtime';runtime_root.mkdir(mode=0o700)
 env.update(NODE_ENV='test',PG_TEST_DISPOSABLE='yes',PG_SECURESHOP_DIAGNOSTIC_ENABLED_INDEX='1',OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(workspace),OWASP_AI_GOAT_FULL_BACKEND_RUNTIME_ROOT=str(runtime_root))
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
 import importlib.util
 spec=importlib.util.spec_from_file_location('frozen_diagnostic_owned_executor',workspace/'tests/postgres/system_diagnostic_owned_executor.py')
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 executor=module.OwnedDiagnosticExecutor(root,workspace,docker,env,owner,persist)
 state['executor']=executor.state;persist()
 executor_url,executor_token=executor.start()
 env.update(PG_SECURESHOP_DIAGNOSTIC_EXECUTOR_ORIGIN=executor_url,PG_SECURESHOP_DIAGNOSTIC_EXECUTOR_TOKEN=executor_token)
 config_root=root/'config-listener';config_root.mkdir(mode=0o700)
 config_spec=importlib.util.spec_from_file_location('frozen_config_owned_executor',workspace/'tests/postgres/system_config_owned_executor.py')
 config_module=importlib.util.module_from_spec(config_spec);config_spec.loader.exec_module(config_module)
 config_executor=config_module.OwnedSystemExecutor(config_root,workspace,docker,env,owner,persist)
 state['configExecutor']=config_executor.state;persist()
 config_url,config_token=config_executor.start()
 env.update(PG_SECURESHOP_SYSTEM_EXECUTOR_ORIGIN=config_url,PG_SECURESHOP_SYSTEM_EXECUTOR_TOKEN=config_token)
 for directory,dirs,files in os.walk(workspace,followlinks=False):
  for name in files:
   item=Path(directory)/name
   if not item.is_symlink():item.chmod(item.stat().st_mode & ~0o222)
  Path(directory).chmod(Path(directory).stat().st_mode & ~0o222)

 with log_path.open('w') as log:
  child=subprocess.Popen([str(NODE),'--test','--test-reporter=tap',test_file],cwd=workspace,env=env,stdout=log,stderr=log,start_new_session=True)
  state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid)};state['runStatus']='test_running';persist()
  try:code=child.wait(timeout=420)
  except subprocess.TimeoutExpired:stop_child();raise RuntimeError('Persona judgment qualification timed out')
 if code:raise RuntimeError(f'Persona judgment foundation failed ({code}); inspect retained tests.log')
 state['runStatus']='passed';state['resultSha256']=digest(log_path);persist()
except BaseException as error:
 if creation_attempted:
  try:
   diagnostic=subprocess.run(docker+['logs','--tail','120',container],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20)
   (root/'container.log').write_text(diagnostic.stdout);os.chmod(root/'container.log',0o600)
  except Exception as diagnostic_error:state['containerDiagnosticError']=type(diagnostic_error).__name__
 state.update({'runStatus':'failed','errorType':type(error).__name__,'resultSha256':digest(log_path)});persist();raise
finally:
 gate.protect_cleanup();errors=[];remove_code=None;absent=None
 try:stop_child()
 except Exception as error:errors.append('child:'+type(error).__name__)
 if config_executor is not None:
  try:
   if not config_executor.close():errors.append('config-executor-cleanup')
  except BaseException as error:errors.append('config-executor:'+type(error).__name__)
 if executor is not None:
  try:
   if not executor.close():errors.append('executor-cleanup')
  except BaseException as error:errors.append('executor:'+type(error).__name__)
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
