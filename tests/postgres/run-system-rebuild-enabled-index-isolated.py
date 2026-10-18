#!/usr/bin/env python3
"""Qualify the configured full index and rendered System rebuild recovery with real cached embeddings; no model."""
import argparse, hashlib, json, os, signal, subprocess, tempfile, time, uuid, importlib.util, re, sys
from datetime import datetime, timezone
from pathlib import Path
from sensitive_info_recovery_safety import SignalGate

EXPECTED_DOCKER='unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
NODE=Path('/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node')
DOCKER=Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')
IMAGE='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
SOURCE=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True);parser.add_argument('--node-sha256',required=True);parser.add_argument('--data-root',required=True);parser.add_argument('--cache',required=True);parser.add_argument('--cache-sha256',required=True);parser.add_argument('--build-sha256',required=True);parser.add_argument('--chrome',required=True);parser.add_argument('--chrome-sha256',required=True);args=parser.parse_args()
mode='system-rebuild-enabled-index-registered'
test_file='tests/postgres/secureshopSystemRebuildEnabledIndex.integration.test.js'
if args.docker_host!=EXPECTED_DOCKER:raise SystemExit('reviewed isolated Docker host required')
data_root=Path(args.data_root)
if not data_root.is_absolute() or data_root.resolve()!=data_root or data_root.stat().st_uid!=os.getuid() or data_root.stat().st_mode&0o777!=0o700 or data_root==SOURCE or SOURCE in data_root.parents or data_root in SOURCE.parents:raise SystemExit('Canonical private external data root required')
cache=Path(args.cache);chrome=Path(args.chrome)
if not cache.is_absolute() or cache.resolve()!=cache or cache==SOURCE or SOURCE in cache.parents:raise SystemExit('Cache must be canonical external data')
if not chrome.is_absolute() or chrome.resolve()!=chrome or not chrome.is_file():raise SystemExit('Canonical Chrome required')
for value in (args.cache_sha256,args.build_sha256,args.chrome_sha256,args.node_sha256):
 if not re.fullmatch('[0-9a-f]{64}',value):raise SystemExit('Artifact SHA256 required')
root=Path(tempfile.mkdtemp(prefix='dvaia-system-rebuild-enabled-index-',dir=data_root)).resolve();os.chmod(root,0o700);workspace=SOURCE
spec=importlib.util.spec_from_file_location('system_owned_browser_lifecycle',SOURCE/'tests/postgres/run-secureshop-audit-central-isolated.py');lifecycle=importlib.util.module_from_spec(spec);spec.loader.exec_module(lifecycle)
browser=None;browser_state={'executable':str(chrome),'profile':str(root/'runtime/system-rebuild-browser'),'members':{}}

container='dvaia-system-rebuild-enabled-index-'+uuid.uuid4().hex[:12];owner=uuid.uuid4().hex
docker=[str(DOCKER),'--host',args.docker_host]
(root/'parent-home').mkdir(mode=0o700)
env={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':str(root/'parent-home'),'TMPDIR':str(root),'PYTHONDONTWRITEBYTECODE':'1'}
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
child=None;creation_attempted=False;gate=SignalGate();signal.signal(signal.SIGTERM,gate.handler);signal.signal(signal.SIGINT,gate.handler);persist()
def owned_group_members(pgid):
 listing=subprocess.run(['ps','-axo','pid=,pgid=,uid='],env=env,stdout=subprocess.PIPE,text=True,check=True,timeout=5).stdout
 members=[]
 for line in listing.splitlines():
  fields=line.split()
  if len(fields)!=3:raise RuntimeError('Malformed process inventory')
  if int(fields[1])==pgid:
   if int(fields[2])!=os.getuid():raise RuntimeError(f'refusing foreign process in owned group {pgid}')
   pid=int(fields[0])
   try:sid=os.getsid(pid)
   except ProcessLookupError:continue
   if sid!=state['child']['sid']:raise RuntimeError('Foreign process session')
   if pid==state['child']['pid']:
    start=run(['/bin/ps','-p',str(pid),'-o','lstart='],stdout=subprocess.PIPE,text=True).stdout.strip()
    if not state['child'].get('start') or start!=state['child']['start']:raise RuntimeError('Changed child start identity')
   members.append(pid)
 return members
def browser_cleanup_runner(*command_args,**command_kwargs):
 # Reap our direct Chrome child before the shared helper checks process absence.
 if browser is not None:browser.poll()
 return subprocess.run(*command_args,**command_kwargs)
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
 if args.node_sha256!='56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861' or digest(NODE)!=args.node_sha256:raise RuntimeError('Node digest mismatch')
 version=run([str(NODE),'--version'],stdout=subprocess.PIPE,text=True).stdout.strip()
 if version!='v26.10.0':raise RuntimeError('managed Node v26.10.0 required')
 state['nodeVersion']=version;persist()
 daemon_name=run(docker+['info','--format','{{.Name}}'],stdout=subprocess.PIPE,text=True).stdout.strip()
 if daemon_name!='colima-dvaia-pg-verify':raise RuntimeError('reviewed isolated Docker daemon required')
 image_id=run(docker+['image','inspect','--format','{{.Id}}',IMAGE],stdout=subprocess.PIPE,text=True).stdout.strip()
 if image_id!=IMAGE:raise RuntimeError('immutable PostgreSQL image identity mismatch')
 state['dockerDaemonId']=run(docker+['info','--format','{{.ID}}'],stdout=subprocess.PIPE,text=True).stdout.strip()
 if state['dockerDaemonId']!='2c9da9a7-1f8c-490b-af98-87bbf6bf83db':raise RuntimeError('Docker daemon identity missing')
 state['dockerDaemon']=daemon_name;state['imageId']=image_id;persist()
 if not exact_absence():raise RuntimeError('owned container name unexpectedly exists')
 private_masks=json.loads(run([str(NODE),'-e',"console.log(JSON.stringify(require('./scripts/lib/isolated-test-boundary').discoverSecrets(process.argv[1],process.argv[2])))",str(SOURCE),os.environ['HOME']],cwd=SOURCE,stdout=subprocess.PIPE,text=True).stdout)
 inventory=['tests/postgres/run-secureshop-audit-central-isolated.py','tests/secureshop/fixtures/e2eServer.js',test_file,'tests/fixtures/secureshopEnabledSystemRebuildBrowser.js','tests/secureshopSystemRebuildScopedRecovery.test.js','db/postgres/workshop-migrations/secureshop_review/0017_bound_system_rebuild_operations.sql','tests/postgres/run-system-rebuild-enabled-index-isolated.py','tests/postgres/sensitive_info_recovery_safety.py','package-lock.json','package.json']
 for folder in ['server','db/postgres','scripts','shared','agent-host','client','tests/fixtures','sidecars/sandbox-runner/owned-system']:
  for directory,dirs,files in os.walk(workspace/folder,followlinks=False):
   dirs[:]=[d for d in dirs if d not in ('node_modules','.git') and not (Path(directory)/d).is_symlink()]
   inventory.extend(str((Path(directory)/name).relative_to(workspace)) for name in files if not (Path(directory)/name).is_symlink())
 state['sourceSha256']={name:digest(workspace/name) for name in sorted(set(inventory)) if not any(workspace/name==Path(mask) or Path(mask) in (workspace/name).parents for mask in private_masks)};state['nodeSha256']=digest(NODE);persist()
 run([str(NODE),'--check',test_file],cwd=workspace)

 # Run the scoped recovery contract before any PostgreSQL resource is created.
 # Keep this pure preflight behind the same source/private-data boundary used by
 # the later qualification; it must never become a provisioning prerequisite
 # that can read host state or create native resources.
 env.update(NODE_ENV='test',PG_TEST_DISPOSABLE='yes')
 preflight_directory=root/'scoped-recovery-boundary';preflight_directory.mkdir(mode=0o700)
 preflight_home=preflight_directory/'home';preflight_tmp=preflight_directory/'tmp';preflight_home.mkdir(mode=0o700);preflight_tmp.mkdir(mode=0o700)
 preflight_env=env.copy();preflight_env.update(HOME=str(preflight_home),TMPDIR=str(preflight_tmp))
 preflight_log=root/'scoped-recovery-preflight.log';preflight_js="const {buildBoundary,discoverSecrets}=require('./scripts/lib/isolated-test-boundary');console.log(JSON.stringify(buildBoundary({source:process.argv[1],directory:process.argv[2],secrets:discoverSecrets(process.argv[1],process.argv[3]),executable:process.execPath,args:['--test','--test-reporter=tap',process.argv[4]]})));"
 preflight=json.loads(run([str(NODE),'-e',preflight_js,str(workspace),str(preflight_directory),os.environ['HOME'],'tests/secureshopSystemRebuildScopedRecovery.test.js'],cwd=workspace,stdout=subprocess.PIPE,text=True).stdout)
 preflight_command=[preflight['command']]+preflight['args']
 with preflight_log.open('w') as preflight_output:
  child=subprocess.Popen(preflight_command,cwd=workspace,env=preflight_env,stdout=preflight_output,stderr=subprocess.STDOUT,start_new_session=True)
  state['child']={'pid':child.pid,'pgid':child.pid,'sid':child.pid,'uid':os.getuid(),'start':None,'purpose':'scoped-recovery-preflight'};persist()
  identity_probe=subprocess.run(['/bin/ps','-p',str(child.pid),'-o','lstart='],env=env,stdout=subprocess.PIPE,text=True,timeout=5)
  if identity_probe.returncode==0 and identity_probe.stdout.strip():state['child']['start']=identity_probe.stdout.strip();persist()
  elif child.poll() is None:raise RuntimeError('Preflight child identity unavailable')
  deadline=time.monotonic()+120
  while child.poll() is None:
   if time.monotonic()>=deadline:
    stop_child();raise RuntimeError('Scoped recovery preflight timed out')
   time.sleep(.05)
  code=child.returncode
  if code:
   stop_child();raise RuntimeError(f'Scoped recovery preflight failed ({code})')
  stop_child()
  child=None
  state['child']=None;persist()
 state['scopedRecoveryPreflight']={'test':'tests/secureshopSystemRebuildScopedRecovery.test.js','boundary':preflight['command'],'resultSha256':digest(preflight_log)};persist()

 creation_attempted=True;state['containerCreationAttempted']=True;persist()
 run(docker+['run','--detach','--pull','never','--name',container,'--label','dvaia.test.owner='+owner,
  '--memory','1g','--cpus','2','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size=1073741824','-e','POSTGRES_HOST_AUTH_METHOD=trust',
  '-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',IMAGE,'-c','shared_buffers=16MB','-c','max_connections=100',
  '-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL)
 details=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]
 if details.get('Mounts') or details['Config']['Labels'].get('dvaia.test.owner')!=owner:raise RuntimeError('owned PostgreSQL isolation/ownership check failed')
 state['containerId']=details['Id'];state['containerImage']=details['Image'];persist()
 if details['Image']!=IMAGE:raise RuntimeError('Unexpected container image')
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
 run(psql+['CREATE ROLE dvaia_ctf_delivery LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; GRANT CONNECT ON DATABASE dvaia_test_full_backend_ctf TO dvaia_ctf_delivery'],stdout=subprocess.DEVNULL)
 env['CTF_DELIVERY_DATABASE_URL']=f'postgresql://dvaia_ctf_delivery@127.0.0.1:{port}/dvaia_test_full_backend_ctf'
 runtime_root=root/'runtime';runtime_root.mkdir(mode=0o700)
 env.update(NODE_ENV='test',PG_TEST_DISPOSABLE='yes',PG_SECURESHOP_REBUILD_ENABLED_INDEX='1',DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace),DVAIA_FULL_BACKEND_RUNTIME_ROOT=str(runtime_root))
 # Existing artifacts only: no build, download, source copying or chmod.
 inventory_js="const {buildInventorySha256}=require('./tests/secureshop/fixtures/e2eServer');console.log(buildInventorySha256(process.argv[1]));"
 for location,expected in ((cache,args.cache_sha256),(workspace/'client/build',args.build_sha256)):
  observed=run([str(NODE),'-e',inventory_js,str(location)],cwd=workspace,stdout=subprocess.PIPE,text=True).stdout.strip()
  if observed!=expected:raise RuntimeError('Admitted artifact digest mismatch')
 # The canonical generated build is separately digest-admitted above. Refuse
 # private/config artifacts before removing only its blanket generated-tree mask.
 for artifact in (workspace/'client/build').rglob('*'):
  if re.search(r'^(?:\.env(?:\..*)?|platform_secrets(?:\.json)?|administrator\.json|teaching\.env|(?:private|credentials|secrets)(?:[._-].*)?)$',artifact.name,re.I) or re.search(r'\.(?:db|sqlite|sqlite3)(?:-(?:wal|shm|journal))?$',artifact.name,re.I):raise RuntimeError('Private artifact in admitted build')
 if digest(chrome)!=args.chrome_sha256:raise RuntimeError('Chrome digest mismatch')
 state['artifacts']={'cache':str(cache),'cacheSha256':args.cache_sha256,'build':str(workspace/'client/build'),'buildSha256':args.build_sha256,'chromeSha256':args.chrome_sha256};persist()
 profile=Path(browser_state['profile']);profile.mkdir(mode=0o700)
 browser_args=json.loads(run([str(NODE),'-e',"(async()=>console.log(JSON.stringify(await require('puppeteer').defaultArgs({headless:true,userDataDir:process.argv[1],args:['--remote-debugging-port=0','--disable-background-networking','--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1']}))))().catch(()=>{process.exitCode=1})",str(profile)],cwd=workspace,stdout=subprocess.PIPE,text=True).stdout)
 if not isinstance(browser_args,list) or not all(isinstance(arg,str) for arg in browser_args):raise RuntimeError('Invalid browser arguments')
 browser_log=root/'browser.stderr.log'
 with browser_log.open('w') as err:
  browser=subprocess.Popen([str(chrome)]+browser_args,cwd=root,env=env,stdout=subprocess.DEVNULL,stderr=err,start_new_session=True)
 state['browserPid']=browser.pid;persist();endpoint=None;deadline=time.monotonic()+30
 while time.monotonic()<deadline:
  lifecycle.observe_browsers(browser_state,os.getpid())
  if browser.poll() is not None:raise RuntimeError('Owned Chrome exited before admission')
  if browser_log.stat().st_size>1048576:raise RuntimeError('Chrome diagnostic bound exceeded')
  match=re.search(r'DevTools listening on (ws://127\.0\.0\.1:\d+/devtools/browser/[^\s]+)',browser_log.read_text())
  if match:endpoint=match.group(1);break
  time.sleep(.05)
 if not endpoint or browser.pid not in browser_state['members']:raise RuntimeError('Owned browser endpoint unavailable')
 identity=browser_state['members'][browser.pid]
 admission={'version':1,'sourceRoot':str(workspace),'runtimeRoot':str(runtime_root),'endpoint':endpoint,'executable':str(chrome),'executableSha256':args.chrome_sha256,'profile':str(profile),'processIdentity':{k:identity[k] for k in ('pid','pgid','uid','start')}}
 admission_file=root/'browser-admission.json';admission_file.write_text(json.dumps(admission));admission_file.chmod(0o600)
 env.update(SS_SYSTEM_BROWSER_ADMISSION=str(admission_file),SS_SYSTEM_BROWSER_ADMISSION_SHA256=digest(admission_file),SS_SYSTEM_BUILD_ROOT=str(workspace/'client/build'),SS_SYSTEM_BUILD_ROOT_SHA256=args.build_sha256,SS_SYSTEM_EMBEDDING_CACHE=str(cache),SS_SYSTEM_EMBEDDING_CACHE_SHA256=args.cache_sha256)
 boundary_js="const {buildBoundary,discoverSecrets}=require('./scripts/lib/isolated-test-boundary');console.log(JSON.stringify(buildBoundary({source:process.argv[1],directory:process.argv[2],secrets:discoverSecrets(process.argv[1],process.argv[3]).filter(mask=>mask!==require('node:path').join(process.argv[1],'client/build')),executable:process.execPath,args:['--test','--test-reporter=tap',process.argv[4]]})));"
 boundary=json.loads(run([str(NODE),'-e',boundary_js,str(workspace),str(root),os.environ['HOME'],test_file],cwd=workspace,stdout=subprocess.PIPE,text=True).stdout)
 if sys.platform!='darwin':raise RuntimeError('System main browser boundary currently Darwin only')
 command=[boundary['command']]+boundary['args']
 # The fenced consumer hashes one parent-pinned executable; it never executes it.
 policy_index=command.index('-p')+1
 command[policy_index]+='\n(allow file-read* (literal '+json.dumps(str(chrome))+'))'
 command[policy_index]+='\n(allow file-read* (subpath '+json.dumps(str(cache))+'))'
 for ancestor in set(chrome.parents)|set(cache.parents):command[policy_index]+='\n(allow file-read-metadata (literal '+json.dumps(str(ancestor))+'))'
 state['boundaryCommand']=command[0];persist()
 with log_path.open('w') as log:
  child=subprocess.Popen(command,cwd=workspace,env=env,stdout=log,stderr=log,start_new_session=True)
  state['child']={'pid':child.pid,'pgid':child.pid,'sid':child.pid,'uid':os.getuid(),'start':None};persist()
  identity_probe=subprocess.run(['/bin/ps','-p',str(child.pid),'-o','lstart='],env=env,stdout=subprocess.PIPE,text=True,timeout=5)
  if identity_probe.returncode==0 and identity_probe.stdout.strip():state['child']['start']=identity_probe.stdout.strip()
  elif child.poll() is None:raise RuntimeError('Child identity unavailable')
  state['runStatus']='test_running';persist()
  try:
   deadline=time.monotonic()+420
   while child.poll() is None:
    lifecycle.observe_browsers(browser_state,os.getpid())
    if time.monotonic()>=deadline:raise subprocess.TimeoutExpired(command,420)
    time.sleep(.1)
   code=child.returncode
  except subprocess.TimeoutExpired:stop_child();raise RuntimeError('System rebuild enabled-index qualification timed out')
 if code:raise RuntimeError(f'System rebuild enabled-index qualification failed ({code}); inspect retained tests.log')
 if any(digest(workspace/name)!=sha for name,sha in state['sourceSha256'].items()):raise RuntimeError('Source changed during qualification')
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
 if browser is not None:
  try:lifecycle.observe_browsers(browser_state,os.getpid())
  except Exception as error:errors.append('browserobserve:'+type(error).__name__)
  errors.extend('browser:'+e for e in lifecycle.retire_browsers(browser_state,runner=browser_cleanup_runner))
  try:browser.wait(timeout=5)
  except Exception as error:errors.append('browserwait:'+type(error).__name__)
 if creation_attempted:
  try:
   if run(docker+['info','--format','{{.ID}}'],stdout=subprocess.PIPE,text=True).stdout.strip()!=state.get('dockerDaemonId'):raise RuntimeError('Docker daemon changed before cleanup')
   if not exact_absence():
    info=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]
    if info.get('Name')!='/'+container or info['Config']['Labels'].get('dvaia.test.owner')!=owner or info['Image']!=IMAGE:raise RuntimeError('refusing foreign container cleanup')
    if not state.get('containerId'):
     host=info['HostConfig'];bindings=host.get('PortBindings',{}).get('5432/tcp',[])
     if info.get('Mounts') or host.get('Memory')!=1073741824 or host.get('NanoCpus')!=2000000000 or host.get('PidsLimit')!=128 or host.get('Tmpfs')!={'/var/lib/postgresql':'rw,size=1073741824'} or len(bindings)!=1 or bindings[0].get('HostIp')!='127.0.0.1' or not re.fullmatch('[0-9a-f]{64}',info.get('Id','')):raise RuntimeError('Unknown-outcome container layout mismatch')
     state['containerId']=info['Id'];state['containerImage']=info['Image'];state['containerIdentityRecoveredAfterUnknownOutcome']=True;persist()
    if info['Id']!=state['containerId']:raise RuntimeError('refusing replaced container cleanup')
    remove_code=subprocess.run(docker+['rm','-f','-v',state['containerId']],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30).returncode
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
