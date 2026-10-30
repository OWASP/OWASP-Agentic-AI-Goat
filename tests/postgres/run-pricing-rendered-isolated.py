#!/usr/bin/env python3
"""Qualify current full application Pricing browser against owned native stores."""
import argparse,hashlib,json,os,signal,subprocess,tempfile,time,uuid,sys,shutil,socket,shlex
from pricing_runtime_pins import validate as validate_runtime_pins, validate_copied_cache
from full_backend_auth_contract import validate_package
from owned_dependency_overlay import prepare_owned_runtime_directories
from mail_disclosure_cleanup_budget import CleanupBudget
from mcp_connected_baseline_contract import validate_ssh
from pathlib import Path
from sensitive_info_recovery_safety import SignalGate
SOURCE=Path(__file__).resolve().parents[2]

DOCKER='/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker'
HOST='unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock'
IMAGE='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
legacy=False
parser=argparse.ArgumentParser()
for option in ['node-binary','node-sha256','node-version','dependency-root','dependency-hashes','dependency-byte-sha256','embedding-cache','embedding-manifest-sha256','manifest','manifest-sha256','docker-binary','docker-sha256','docker-daemon-id','ssh-binary','ssh-sha256','ssh-config','ssh-config-sha256','ssh-host','browser','browser-sha256']:parser.add_argument('--'+option,required=True)
args=parser.parse_args()
NODE,DEPENDENCIES,EMBEDDING_CACHE=validate_runtime_pins(args,SOURCE,rendered=True)
if EMBEDDING_CACHE!=SOURCE/'tests/fixtures/fullBackendModelCache':raise ValueError('Canonical package embedding cache required')
if DEPENDENCIES!=SOURCE:raise ValueError('Pricing requires dependency tree inside reviewed frozen source')
validate_package(SOURCE,args.manifest,args.manifest_sha256,NODE,args.node_sha256)
DOCKER=Path(args.docker_binary)
if not DOCKER.is_absolute() or DOCKER.is_symlink() or not DOCKER.is_file() or hashlib.sha256(DOCKER.read_bytes()).hexdigest()!=args.docker_sha256:raise ValueError('Docker executable pin mismatch')
SSH=validate_ssh(args.ssh_binary,args.ssh_sha256,args.ssh_config,args.ssh_config_sha256,args.ssh_host)
cleanup_budget=None
def remaining(seconds):return min(seconds,cleanup_budget.remaining()) if cleanup_budget else seconds
browser_path=Path(args.browser)
if not browser_path.is_absolute() or browser_path.is_symlink() or browser_path.resolve()!=browser_path or not browser_path.is_file() or not os.access(browser_path,os.X_OK) or hashlib.sha256(browser_path.read_bytes()).hexdigest()!=args.browser_sha256:raise ValueError('Explicit browser pin mismatch')
root=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-pricing-rendered-')).resolve();os.chmod(root,0o700)
workspace=root/'source';home=root/'home';home.mkdir(mode=0o700)
workspace_id=hashlib.sha256(str(workspace).encode()).hexdigest()[:12]
name='owasp-ai-goat-pricing-'+workspace_id;network=name+'-network';tag='owasp-ai-goat-owned-pricing-'+workspace_id+':local';profile='owasp-ai-goat-owned-pricing-http-'+workspace_id
state_name=name+'-setup-state';state_owner=uuid.uuid4().hex
env={'PATH':str(NODE.parent)+':'+str(Path(DOCKER).parent)+':/usr/bin:/bin','HOME':str(home),'DOCKER_HOST':HOST,'TMPDIR':str(root),'PG_TEST_DISPOSABLE':'yes','OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE':str(workspace),'PRICING_INSTALL_TEST_HOME':str(home),'PRICING_INSTALL_TEST_RESULT':str(root/'result.json')}
ssh=SSH
def remote(args):return subprocess.run(ssh+[shlex.join(args)],env=env,check=True,capture_output=True,text=True,timeout=remaining(25))
def deadline(*_):raise TimeoutError('Pricing full-index parent deadline')
signal.signal(signal.SIGALRM,deadline);signal.alarm(900)
docker=[str(DOCKER),'--host',HOST];child=None;state={'workspaceId':workspace_id,'container':name,'network':network,'imageTag':tag,'profile':profile,'setupStateContainer':state_name,'setupStateOwner':state_owner,'status':'preparing','cleanup':None};log=root/'tests.log'
gate=SignalGate();signal.signal(signal.SIGTERM,gate.handler);signal.signal(signal.SIGINT,gate.handler)
def run(command,**kwargs):
 kwargs.setdefault('timeout',remaining(30));return subprocess.run(command,check=True,env=env,**kwargs)
def persist():
 (root/'ownership.json').write_text(json.dumps(state,indent=2)+'\n');os.chmod(root/'ownership.json',0o600)
def digest(file):return hashlib.sha256(file.read_bytes()).hexdigest()
def inspect(kind,identifier):
 p=subprocess.run(docker+[kind,'inspect',identifier],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=remaining(15))
 if p.returncode==0:return json.loads(p.stdout)[0]
 if kind=='container':
  missing=p.stderr.strip() in [f'Error: No such object: {identifier}',f'Error response from daemon: No such container: {identifier}']
  if p.returncode!=0 and missing:return None
 else:
  from listings_integrated_executor_owner import inspected_absent
  if inspected_absent(p,kind,identifier):return None
 raise RuntimeError('Docker inspection unavailable')
def members():
 if not child:return []
 rows=run(['ps','-axo','pid=,pgid=,uid='],stdout=subprocess.PIPE,text=True).stdout.splitlines();found=[]
 for row in rows:
  fields=row.split()
  if len(fields)==3 and int(fields[1])==child.pid:
   if int(fields[2])!=os.getuid():raise RuntimeError('Foreign process in group')
   found.append(int(fields[0]))
 return found
def stop():
 if not child:return
 if members():os.killpg(child.pid,signal.SIGTERM)
 until=time.monotonic()+5
 while members() and time.monotonic()<until:child.poll();time.sleep(.05)
 if members():os.killpg(child.pid,signal.SIGKILL)
 child.wait(timeout=remaining(5))
 until=time.monotonic()+min(5,remaining(5))
 while members() and time.monotonic()<until:time.sleep(.05)
 if members():raise RuntimeError('Owned child remains')
persist()
try:
 assert run([str(NODE),'--version'],stdout=subprocess.PIPE,text=True).stdout.strip()==args.node_version
 assert run(docker+['info','--format','{{.Name}}'],stdout=subprocess.PIPE,text=True).stdout.strip()=='colima-owasp-ai-goat-pg-verify'
 env['ANALYTICS_BROWSER_EXECUTABLE']=str(browser_path);env['ANALYTICS_BROWSER_SHA256']=digest(browser_path);state['browserExecutableSha256']=env['ANALYTICS_BROWSER_SHA256'];persist()
 if run(docker+['info','--format','{{.ID}}'],stdout=subprocess.PIPE,text=True).stdout.strip()!=args.docker_daemon_id:raise RuntimeError('Docker daemon identity mismatch')
 assert inspect('image','postgres:18')['Id']==IMAGE
 assert inspect('container',name) is None and inspect('network',network) is None and inspect('image',tag) is None and inspect('container',state_name) is None
 assert subprocess.run(ssh+[shlex.join(['sudo','test','-e','/etc/apparmor.d/'+profile])],env=env,capture_output=True,timeout=remaining(15)).returncode==1
 run([str(NODE),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(SOURCE),str(workspace)],cwd=SOURCE)
 prepare_owned_runtime_directories(SOURCE,workspace,root)
 validate_copied_cache(EMBEDDING_CACHE,workspace/'tests/fixtures/fullBackendModelCache')
 env['XENOVA_CACHE']=str(workspace/'tests/fixtures/fullBackendModelCache');env['TRANSFORMERS_CACHE']=str(workspace/'tests/fixtures/fullBackendModelCache');env['HF_HUB_OFFLINE']='1';env['TRANSFORMERS_OFFLINE']='1'
 (workspace/'node_modules').symlink_to(DEPENDENCIES/'node_modules',target_is_directory=True)
 (workspace/'client/node_modules').mkdir(mode=0o700)
 for dependency in (DEPENDENCIES/'client/node_modules').iterdir():
  if dependency.name in ['.vite','.vite-temp','.cache']:continue
  (workspace/'client/node_modules'/dependency.name).symlink_to(dependency,target_is_directory=dependency.is_dir())
 directory=home/'.owasp-ai-goat'/workspace_id;directory.mkdir(parents=True,mode=0o700);directory_identity=(directory.stat().st_dev,directory.stat().st_ino)
 authority={'version':1,'workspaceId':workspace_id,'host':HOST,'daemonId':json.loads(run(docker+['info','--format','{{json .ID}}'],stdout=subprocess.PIPE,text=True).stdout),'source':'environment-host'}
 auth=directory/'local-docker.json';auth.write_text(json.dumps(authority));auth.chmod(0o600)
 with socket.socket() as reservation:reservation.bind(('127.0.0.1',0));env['PRICING_LISTENER_PORT']=str(reservation.getsockname()[1])
 inventory=[]
 for folder in ['server','client','agent-host','shared','db/postgres','sidecars/sandbox-runner','scripts','tests/fixtures','tests/helpers','docs/modernization/drafts/secureshop-bound-pricing']:
  inventory.extend(file for file in (workspace/folder).rglob('*') if file.is_file() and 'node_modules' not in file.parts and 'build' not in file.parts)
 inventory.extend(workspace/file for file in ['tests/postgres/pricing_runtime_pins.py','scripts/local-docker-authority.js','scripts/lib/isolated-source-copy.js','tests/postgres/secureshopPricingRendered.native.js','tests/postgres/run-pricing-rendered-isolated.py','package.json','package-lock.json'])
 state['sourceSha256']={str(file.relative_to(workspace)):digest(file) for file in sorted(set(inventory))};state['status']='running';persist()
 state['setupStateCreationAttempted']=True;persist()
 run(docker+['run','--detach','--pull','never','--name',state_name,'--label','owasp-ai-goat.test.owner='+state_owner,'--memory','1g','--cpus','2','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size=1073741824','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',IMAGE,'-c','shared_buffers=16MB','-c','max_connections=100','-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL)
 state_container=inspect('container',state_name);state['setupStateContainerId']=state_container['Id'];persist()
 for attempt in range(80):
  ready=subprocess.run(docker+['exec',state_name,'pg_isready','-h','127.0.0.1','-U','postgres'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=remaining(2))
  if ready.returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('Setup fixture PostgreSQL unavailable')
 port=int(state_container['NetworkSettings']['Ports']['5432/tcp'][0]['HostPort'])
 manifest=json.loads(run([str(NODE),'-e',"console.log(JSON.stringify(require('./db/postgres/initialize-application').requiredStoreManifest))"],cwd=workspace,stdout=subprocess.PIPE,text=True).stdout)
 assert len(manifest)==16
 for row in manifest:
  family=row['schema'];migration='dvaia_'+family+'_migration';runtime=row['runtimeRole'];database='owasp_ai_goat_test_full_backend_'+family
  psql=docker+['exec',state_name,'psql','-U','postgres','-v','ON_ERROR_STOP=1','-c']
  run(psql+[f'CREATE ROLE {migration} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE {runtime} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],stdout=subprocess.DEVNULL)
  run(psql+[f'CREATE DATABASE {database} OWNER {migration}'],stdout=subprocess.DEVNULL)
  run(psql+[f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime}'],stdout=subprocess.DEVNULL)
  env[row['migrationVariable']]=f'postgresql://{migration}@127.0.0.1:{port}/{database}'
  env[row['runtimeVariable']]=f'postgresql://{runtime}@127.0.0.1:{port}/{database}'
 env['PRICING_RENDERED_ROOT']=str(root)
 state['buildChildren']=[];build_deadline=time.monotonic()+240
 for label,command in [('client',[str(NODE),str(workspace/'client/node_modules/vite/bin/vite.js'),'build']),('renderer',[str(NODE),str(workspace/'client/node_modules/vite/bin/vite.js'),'build','--config','vite.review-renderer.config.mjs'])]:
  with (root/(label+'-build.log')).open('w') as output:
   child=subprocess.Popen(command,cwd=workspace/'client',env=env,stdout=output,stderr=output,start_new_session=True);state['childPgid']=child.pid;state['buildChildren'].append(child.pid);persist()
   try:code=child.wait(timeout=max(1,build_deadline-time.monotonic()))
   except subprocess.TimeoutExpired:stop();raise RuntimeError('Owned frontend build deadline')
   assert code==0,'Owned frontend build failed'
 state['buildSha256']={str(file.relative_to(workspace)):digest(file) for file in (workspace/'client/build').rglob('*') if file.is_file()};persist()
 for item in workspace.rglob('*'):
  if item.is_symlink() or 'node_modules' in item.parts:continue
  if item.is_file():item.chmod(0o444)
 for item in sorted([x for x in workspace.rglob('*') if x.is_dir() and not x.is_symlink() and 'node_modules' not in x.parts],key=lambda x:len(x.parts),reverse=True):item.chmod(0o555)
 workspace.chmod(0o555)
 with log.open('w') as output:
  child=subprocess.Popen([str(NODE),'tests/postgres/secureshopPricingRendered.native.js'],cwd=workspace,env=env,stdout=output,stderr=output,start_new_session=True);state['childPgid']=child.pid;persist()
  try:code=child.wait(timeout=remaining(420))
  except subprocess.TimeoutExpired:stop();raise RuntimeError('Rendered fixture deadline exceeded')
 assert code==0,'Native full-index rendered fixture failed'
 result=json.loads((root/'result.json').read_text());assert result['passed'] is True
 state['resultSha256']=digest(root/'result.json');state['status']='passed'
except BaseException as error:
 state['status']='failed';state['errorType']=type(error).__name__;raise
finally:
 signal.alarm(0);gate.protect_cleanup();cleanup_budget=CleanupBudget(120);errors=[]
 try:stop()
 except Exception as error:errors.append('child:'+type(error).__name__)
 try:
  item=inspect('container',state_name)
  if item:
   assert state.get('setupStateCreationAttempted') and item['Config']['Labels'].get('owasp-ai-goat.test.owner')==state_owner and item['Image']==IMAGE
   if state.get('setupStateContainerId'):assert item['Id']==state['setupStateContainerId']
   run(docker+['rm','-f',item['Id']],stdout=subprocess.DEVNULL)
  assert inspect('container',state_name) is None
 except Exception as error:errors.append('setup-state:'+type(error).__name__)
 try:
  directory=home/'.owasp-ai-goat'/workspace_id;stage_file=directory/'pricing-provisioning.json';staged=json.loads(stage_file.read_text()) if stage_file.exists() else None
  for kind,identifier in [('container',name),('network',network)]:
   item=inspect(kind,identifier)
   if item:
    labels=item['Config']['Labels'] if kind=='container' else item['Labels'];assert staged and labels.get('owasp-ai-goat.pricing.owner')==staged['ownerId'] and labels.get('owasp-ai-goat.pricing.workspace')==workspace_id and labels.get('owasp-ai-goat.pricing.package')==staged['packageSha256']
    run(docker+(['rm','-f',item['Id']] if kind=='container' else ['network','rm',item['Id']]),stdout=subprocess.DEVNULL)
   assert inspect(kind,identifier) is None
  image=inspect('image',tag)
  if image:
   package=json.loads((workspace/'sidecars/sandbox-runner/owned-pricing-http/local-package-manifest.json').read_text());assert image['Config']['Labels']['owasp-ai-goat.pricing.package']==package['sha256'] and image['RepoTags']==[tag];run(docker+['image','rm',tag],stdout=subprocess.DEVNULL);assert inspect('image',image['Id']) is None
  if subprocess.run(ssh+[shlex.join(['sudo','test','-e','/etc/apparmor.d/'+profile])],env=env,capture_output=True,timeout=remaining(15)).returncode==0:
   expected=(workspace/'sidecars/sandbox-runner/owned-pricing-http/http-profile.apparmor.in').read_text().replace('@@SUPERVISOR_PROFILE@@',profile);assert remote(['sudo','cat','/etc/apparmor.d/'+profile]).stdout==expected;remote(['sudo','apparmor_parser','-R','/etc/apparmor.d/'+profile]);remote(['sudo','rm','--','/etc/apparmor.d/'+profile])
  assert not any(line.startswith(profile+' ') or line.startswith(profile+'//') for line in remote(['sudo','cat','/sys/kernel/security/apparmor/profiles']).stdout.splitlines())
  if directory.exists():
   assert not directory.is_symlink() and (directory.stat().st_dev,directory.stat().st_ino)==directory_identity
   for file in directory.iterdir():assert file.name in ['local-docker.json','pricing-provisioning.json','pricing-managed.json'] and file.is_file() and not file.is_symlink();file.unlink()
   directory.rmdir()
 except Exception as error:errors.append('pricing:'+type(error).__name__)
 for label in ['pricing']:
  profile=root/(label+'-profile')
  if profile.exists():
   if members():errors.append(label+':owned-processes-remain')
   else:shutil.rmtree(profile)
 try:cleanup_budget.run(lambda:validate_package(SOURCE,args.manifest,args.manifest_sha256,NODE,args.node_sha256))
 except Exception as error:errors.append('frozen-integrity:'+type(error).__name__)
 state['cleanup']={'browserProfilesAbsent':all(not(root/(label+'-profile')).exists() for label in ['pricing']),'errors':errors}
 for key,probe in [('childPgidAbsent',lambda:not members()),('containerAbsent',lambda:inspect('container',name) is None),('networkAbsent',lambda:inspect('network',network) is None),('imageAbsent',lambda:inspect('image',tag) is None),('setupStateAbsent',lambda:inspect('container',state_name) is None)]:
  try:state['cleanup'][key]=probe()
  except Exception as error:state['cleanup'][key]=None;errors.append(key+':'+type(error).__name__)
 if errors or not all(state['cleanup'][key] for key in ['childPgidAbsent','containerAbsent','networkAbsent','imageAbsent','setupStateAbsent','browserProfilesAbsent']):state['status']='failed'
 if log.exists():state['logSha256']=digest(log)
 persist()
print(json.dumps({'evidence':str(root),'status':state['status'],'cleanup':state['cleanup']}),flush=True)
if state['status']!='passed':raise SystemExit(1)
