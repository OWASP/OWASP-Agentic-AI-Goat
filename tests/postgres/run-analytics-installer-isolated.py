#!/usr/bin/env python3
"""Qualify real installer only in a frozen workspace/private home, exact owned cleanup."""
import hashlib,json,os,signal,subprocess,tempfile,time,uuid,sys
from pathlib import Path
from sensitive_info_recovery_safety import SignalGate
SOURCE=Path(__file__).resolve().parents[2]
NODE=Path('/Users/averma5/.owasp-ai-goat/runtimes/node-v26.9.0-darwin-arm64/bin/node')
DOCKER='/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker'
HOST='unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock'
IMAGE='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
legacy='--legacy-upgrade' in sys.argv[1:]
assert all(arg=='--legacy-upgrade' for arg in sys.argv[1:])
root=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-analytics-installer-')).resolve();os.chmod(root,0o700)
workspace=root/'source';home=root/'home';home.mkdir(mode=0o700)
workspace_id=hashlib.sha256(str(workspace).encode()).hexdigest()[:12]
name='owasp-ai-goat-analytics-'+workspace_id;volume=name+'-data'
state_name=name+'-setup-state';state_owner=uuid.uuid4().hex
env={'PATH':str(NODE.parent)+':'+str(Path(DOCKER).parent)+':/usr/bin:/bin','HOME':str(home),'DOCKER_HOST':HOST,'TMPDIR':str(root),'PG_TEST_DISPOSABLE':'yes','OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE':str(workspace),'ANALYTICS_INSTALL_TEST_HOME':str(home),'ANALYTICS_INSTALL_TEST_RESULT':str(root/'result.json')}
env['ANALYTICS_LEGACY_UPGRADE']='yes' if legacy else 'no'
docker=[DOCKER,'--host',HOST];child=None;state={'workspaceId':workspace_id,'container':name,'volume':volume,'setupStateContainer':state_name,'setupStateOwner':state_owner,'status':'preparing','cleanup':None};log=root/'tests.log'
gate=SignalGate();signal.signal(signal.SIGTERM,gate.handler);signal.signal(signal.SIGINT,gate.handler)
def run(command,**kwargs):
 kwargs.setdefault('timeout',30);return subprocess.run(command,check=True,env=env,**kwargs)
def persist():
 (root/'ownership.json').write_text(json.dumps(state,indent=2)+'\n');os.chmod(root/'ownership.json',0o600)
def digest(file):return hashlib.sha256(file.read_bytes()).hexdigest()
def inspect(kind,identifier):
 p=subprocess.run(docker+[kind,'inspect',identifier],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=15)
 if p.returncode==0:return json.loads(p.stdout)[0]
 if p.returncode==1 and 'no such' in p.stderr.lower():return None
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
 child.wait(timeout=5)
 if members():raise RuntimeError('Owned child remains')
persist()
try:
 assert run([str(NODE),'--version'],stdout=subprocess.PIPE,text=True).stdout.strip()=='v26.9.0'
 assert run(docker+['info','--format','{{.Name}}'],stdout=subprocess.PIPE,text=True).stdout.strip()=='colima-owasp-ai-goat-pg-verify'
 assert inspect('image','postgres:18')['Id']==IMAGE
 assert inspect('container',name) is None and inspect('volume',volume) is None and inspect('container',state_name) is None
 run([str(NODE),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(SOURCE),str(workspace)],cwd=SOURCE)
 if legacy:
  current=(workspace/'scripts/install/analytics-target.js').read_text();assert current.count('requiredVersion:2')==2
  historical=current.replace('requiredVersion:2','requiredVersion:1');(workspace/'scripts/install/analytics-target-legacy-fixture.js').write_text(historical)
  state['historicalInstaller']={'currentSha256':hashlib.sha256(current.encode()).hexdigest(),'historicalSha256':hashlib.sha256(historical.encode()).hexdigest(),'onlyChange':'two requiredVersion:2 literals to requiredVersion:1'}
 (workspace/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
 inventory=[]
 for folder in ['server/services','server/database/postgres','db/postgres','sidecars/analytics-sql-target','scripts/install','docs/modernization/drafts/secureshop-bound-analytics']:
  inventory.extend(file for file in (workspace/folder).rglob('*') if file.is_file())
 inventory.extend(workspace/file for file in ['scripts/local-docker-authority.js','scripts/lib/isolated-source-copy.js','tests/postgres/secureshopAnalyticsInstaller.native.js','tests/postgres/run-analytics-installer-isolated.py','package.json','package-lock.json'])
 state['sourceSha256']={str(file.relative_to(workspace)):digest(file) for file in sorted(set(inventory))};state['status']='running';persist()
 state['setupStateCreationAttempted']=True;persist()
 run(docker+['run','--detach','--pull','never','--name',state_name,'--label','owasp-ai-goat.test.owner='+state_owner,'--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size=268435456','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',IMAGE,'-c','shared_buffers=16MB','-c','max_connections=30','-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL)
 state_container=inspect('container',state_name);state['setupStateContainerId']=state_container['Id'];persist()
 for attempt in range(80):
  ready=subprocess.run(docker+['exec',state_name,'pg_isready','-U','postgres'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
  if ready.returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('Setup fixture PostgreSQL unavailable')
 port=int(state_container['NetworkSettings']['Ports']['5432/tcp'][0]['HostPort'])
 for role in ['dvaia_secureshop_agents_runtime','dvaia_secureshop_agents_migration']:
  run(docker+['exec',state_name,'psql','-U','postgres','-v','ON_ERROR_STOP=1','-c',f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],stdout=subprocess.DEVNULL)
 database='owasp_ai_goat_test_setup_'+workspace_id
 run(docker+['exec',state_name,'psql','-U','postgres','-v','ON_ERROR_STOP=1','-c',f'CREATE DATABASE {database} OWNER dvaia_secureshop_agents_migration'],stdout=subprocess.DEVNULL)
 for kind in ['runtime','migration']:env['ANALYTICS_SETUP_'+kind.upper()+'_URL']=f'postgresql://dvaia_secureshop_agents_{kind}@127.0.0.1:{port}/{database}'
 with log.open('w') as output:
  child=subprocess.Popen([str(NODE),'tests/postgres/secureshopAnalyticsInstaller.native.js'],cwd=workspace,env=env,stdout=output,stderr=output,start_new_session=True);state['childPgid']=child.pid;persist()
  try:code=child.wait(timeout=240)
  except subprocess.TimeoutExpired:stop();raise RuntimeError('Installer deadline exceeded')
 assert code==0,'Native installer fixture failed'
 result=json.loads((root/'result.json').read_text());assert result['passed'] is True
 state['resultSha256']=digest(root/'result.json');state['status']='passed'
except BaseException as error:
 state['status']='failed';state['errorType']=type(error).__name__;raise
finally:
 gate.protect_cleanup();errors=[]
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
 intent_file=home/'.owasp-ai-goat'/workspace_id/'analytics-install-intent.json'
 owner=json.loads(intent_file.read_text()).get('ownerId') if intent_file.exists() else None
 for kind,identifier in [('container',name),('volume',volume)]:
  try:
   item=inspect(kind,identifier)
   if item:
    labels=item['Config']['Labels'] if kind=='container' else item['Labels']
    assert owner and labels.get('owasp-ai-goat.owner')==owner and labels.get('owasp-ai-goat.workspace')==workspace_id and labels.get('owasp-ai-goat.purpose')=='owned-analytics'
    run(docker+(['rm','-f',item['Id']] if kind=='container' else ['volume','rm',identifier]),stdout=subprocess.DEVNULL)
   assert inspect(kind,identifier) is None
  except Exception as error:errors.append(kind+':'+type(error).__name__)
 state['cleanup']={'errors':errors,'childPgidAbsent':not members(),'containerAbsent':inspect('container',name) is None,'volumeAbsent':inspect('volume',volume) is None,'setupStateAbsent':inspect('container',state_name) is None}
 if errors or not all(state['cleanup'][key] for key in ['childPgidAbsent','containerAbsent','volumeAbsent']):state['status']='failed'
 if log.exists():state['logSha256']=digest(log)
 persist()
print(json.dumps({'evidence':str(root),'status':state['status'],'cleanup':state['cleanup']}),flush=True)
if state['status']!='passed':raise SystemExit(1)
