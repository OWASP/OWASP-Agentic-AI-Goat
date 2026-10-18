#!/usr/bin/env python3
"""Owned connected Analytics parity; import and admission never launch resources."""
import stat,argparse,hashlib,json,os,signal,subprocess,tempfile,time,uuid,sys,shutil
from pathlib import Path
from sensitive_info_recovery_safety import SignalGate
from pricing_runtime_pins import validate as validate_runtime
from full_backend_auth_contract import validate_package,inventory
from owned_dependency_overlay import prepare_owned_runtime_directories,vite_config_arguments
from mail_disclosure_cleanup_budget import CleanupBudget
from owned_diagnostic_process_cleanup import stop_directive_child
from mcp_connected_baseline_contract import validate_docker_cli

def arguments(argv=None):
 p=argparse.ArgumentParser(description=__doc__)
 for key in ('node-binary','node-sha256','node-version','dependency-root','dependency-hashes','dependency-byte-sha256','embedding-cache','embedding-manifest-sha256','manifest','manifest-sha256','browser-executable','browser-sha256','docker-binary','docker-sha256','docker-host','daemon-id','postgres-image'):
  p.add_argument('--'+key,required=True)
 return p.parse_args(argv)

def digest(file):return hashlib.sha256(Path(file).read_bytes()).hexdigest()
def validate(args,source):
 node,donor,cache=validate_runtime(args,source,rendered=True)
 validate_package(source,Path(args.manifest),args.manifest_sha256,node,args.node_sha256)
 browser=Path(args.browser_executable)
 if not browser.is_absolute() or browser.is_symlink() or browser.resolve()!=browser or not browser.is_file() or not os.access(browser,os.X_OK) or digest(browser)!=args.browser_sha256:raise ValueError('Browser pin mismatch')
 validate_docker_cli(args.docker_binary,args.docker_sha256)
 if not args.docker_host.startswith('unix:///') or not args.daemon_id or not __import__('re').fullmatch(r'sha256:[a-f0-9]{64}',args.postgres_image):raise ValueError('Owned Docker pins required')
 return node,donor,cache,browser

def absent_response(kind,identifier,response):
 if response.returncode==0:return False
 expected={f'Error: No such {kind}: {identifier}',f'Error response from daemon: No such {kind}: {identifier}',f'Error: No such object: {identifier}'}
 if response.returncode==1 and response.stderr.strip() in expected:return True
 raise RuntimeError('Docker inspection unavailable')

class OwnedGroups:
 def __init__(self,read):self.children=[];self.read=read;self.completed=set()
 def add(self,child):self.children.append(child);return child
 def members(self,child):
  found=[]
  for line in self.read().splitlines():
   fields=line.split()
   if len(fields)!=3 or not all(x.isdigit() for x in fields):raise RuntimeError('Unknown process roster')
   pid,pgid,uid=map(int,fields)
   if pgid==child.pid:
    if uid!=os.getuid():raise RuntimeError('Foreign group member')
    found.append(pid)
  return found
 def all_members(self):return [pid for child in self.children if child.pid not in self.completed for pid in self.members(child)]
 def stop(self,child,budget):
  if child.pid in self.completed:return True
  absent=stop_directive_child(child,lambda _:self.members(child),budget)
  if absent:self.completed.add(child.pid)
  return absent
 def cleanup(self,budget):
  errors=[]
  for child in self.children:
   try:budget.run(lambda:self.stop(child,budget))
   except Exception as error:errors.append(type(error).__name__)
  if errors:raise RuntimeError('Owned groups cleanup incomplete: '+','.join(errors))

def modes(root):
 return {str(p.relative_to(root)):stat.S_IMODE(p.lstat().st_mode) for p in Path(root).rglob('*')}

def build_commands(node,workspace):
 vite=str(workspace/'client/node_modules/vite/bin/vite.js')
 return [('client',[str(node),vite,'build',*vite_config_arguments(True)]),('renderer',[str(node),vite,'build','--config','vite.review-renderer.config.mjs',*vite_config_arguments(True)])]

def main(argv=None):
 args=arguments(argv);SOURCE=Path(__file__).resolve().parents[2]
 work=CleanupBudget(900)
 NODE,DONOR,CACHE,BROWSER=work.run(lambda:validate(args,SOURCE))
 initial=work.run(lambda:inventory(SOURCE));donor_initial=work.run(lambda:inventory(DONOR));initial_modes=work.run(lambda:modes(SOURCE));donor_modes=work.run(lambda:modes(DONOR))
 DOCKER=args.docker_binary;HOST=args.docker_host;IMAGE=args.postgres_image;legacy=False
 root=Path(tempfile.mkdtemp(prefix='dvaia-analytics-rendered-')).resolve();os.chmod(root,0o700)
 workspace=root/'source';home=root/'home';home.mkdir(mode=0o700)
 workspace_id=hashlib.sha256(str(workspace).encode()).hexdigest()[:12]
 name='dvaia-analytics-'+workspace_id;volume=name+'-data'
 state_name=name+'-setup-state';state_owner=uuid.uuid4().hex
 env={'PATH':str(NODE.parent)+':'+str(Path(DOCKER).parent)+':/usr/bin:/bin','HOME':str(home),'DOCKER_HOST':HOST,'TMPDIR':str(root),'PG_TEST_DISPOSABLE':'yes','DVAIA_ISOLATED_TEST_WORKSPACE':str(workspace),'ANALYTICS_INSTALL_TEST_HOME':str(home),'ANALYTICS_INSTALL_TEST_RESULT':str(root/'result.json')}
 env.update({'ANALYTICS_DOCKER_BINARY':DOCKER,'ANALYTICS_DOCKER_SHA256':args.docker_sha256,'ANALYTICS_DOCKER_DAEMON':args.daemon_id,'ANALYTICS_POSTGRES_IMAGE':IMAGE})
 env['ANALYTICS_LEGACY_UPGRADE']='yes' if legacy else 'no'
 docker=[DOCKER,'--host',HOST];child=None;state={'workspaceId':workspace_id,'container':name,'volume':volume,'setupStateContainer':state_name,'setupStateOwner':state_owner,'status':'preparing','cleanup':None};log=root/'tests.log'
 budget=work
 gate=SignalGate();signal.signal(signal.SIGTERM,gate.handler);signal.signal(signal.SIGINT,gate.handler)
 def run(command,**kwargs):
  kwargs['timeout']=min(kwargs.get('timeout',30),budget.remaining());return subprocess.run(command,check=True,env=env,**kwargs)
 def persist():
  (root/'ownership.json').write_text(json.dumps(state,indent=2)+'\n');os.chmod(root/'ownership.json',0o600)
 def digest(file):return hashlib.sha256(file.read_bytes()).hexdigest()
 def inspect(kind,identifier):
  p=subprocess.run(docker+[kind,'inspect',identifier],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=min(15,budget.remaining()))
  if p.returncode==0:return json.loads(p.stdout)[0]
  if absent_response(kind,identifier,p):return None
  raise RuntimeError('Docker inspection unavailable')
 groups=OwnedGroups(lambda:run(['ps','-axo','pid=,pgid=,uid='],stdout=subprocess.PIPE,text=True).stdout)
 def members():return groups.all_members()
 def stop():groups.cleanup(budget)
 persist()
 previous_alarm=signal.getsignal(signal.SIGALRM)
 def work_expired(signum,frame):raise TimeoutError('Analytics aggregate work deadline')
 signal.signal(signal.SIGALRM,work_expired);signal.setitimer(signal.ITIMER_REAL,work.remaining())
 try:
  assert run(docker+['info','--format','{{.ID}}'],stdout=subprocess.PIPE,text=True).stdout.strip()==args.daemon_id
  env['ANALYTICS_BROWSER_EXECUTABLE']=str(BROWSER);env['ANALYTICS_BROWSER_SHA256']=args.browser_sha256;state['browserExecutableSha256']=args.browser_sha256;persist()
  assert inspect('image','postgres:18')['Id']==IMAGE
  assert inspect('container',name) is None and inspect('volume',volume) is None and inspect('container',state_name) is None
  run([str(NODE),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(SOURCE),str(workspace)],cwd=SOURCE)
  work.run(lambda:prepare_owned_runtime_directories(SOURCE,workspace,root))
  if legacy:
   current=(workspace/'scripts/install/analytics-target.js').read_text();assert current.count('requiredVersion:2')==2
   historical=current.replace('requiredVersion:2','requiredVersion:1');(workspace/'scripts/install/analytics-target-legacy-fixture.js').write_text(historical)
   state['historicalInstaller']={'currentSha256':hashlib.sha256(current.encode()).hexdigest(),'historicalSha256':hashlib.sha256(historical.encode()).hexdigest(),'onlyChange':'two requiredVersion:2 literals to requiredVersion:1'}
  (workspace/'node_modules').symlink_to(DONOR/'node_modules',target_is_directory=True)
  (workspace/'client/node_modules').mkdir(mode=0o700)
  for dependency in (DONOR/'client/node_modules').iterdir():
   if dependency.name in ['.vite','.vite-temp','.cache']:continue
   (workspace/'client/node_modules'/dependency.name).symlink_to(dependency,target_is_directory=dependency.is_dir())
  candidate_file=workspace/'server/config/secureshopCurriculum.js';candidate_before=digest(candidate_file)
  run([str(NODE),'-e',"require('./tests/helpers/secureshopAnalyticsCurriculumCandidate').stage(process.cwd())"],cwd=workspace)
  state['candidateDelta']={'file':'server/config/secureshopCurriculum.js','before':candidate_before,'after':digest(candidate_file),'scope':'private copied candidate only'};persist()
  source_files=[]
  for folder in ['server','client','agent-host','shared','db/postgres','sidecars/analytics-sql-target','scripts','tests/fixtures','tests/helpers','docs/modernization/drafts/secureshop-bound-analytics']:
   source_files.extend(file for file in (workspace/folder).rglob('*') if file.is_file() and 'node_modules' not in file.parts and 'build' not in file.parts)
  source_files.extend(workspace/file for file in ['scripts/local-docker-authority.js','scripts/lib/isolated-source-copy.js','tests/postgres/secureshopAnalyticsRendered.native.js','tests/postgres/run-analytics-rendered-isolated.py','package.json','package-lock.json'])
  state['sourceSha256']={str(file.relative_to(workspace)):digest(file) for file in sorted(set(source_files))};state['status']='running';persist()
  state['setupStateCreationAttempted']=True;persist()
  run(docker+['run','--detach','--pull','never','--name',state_name,'--label','dvaia.test.owner='+state_owner,'--memory','1g','--cpus','2','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size=1073741824','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',IMAGE,'-c','shared_buffers=16MB','-c','max_connections=100','-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL)
  state_container=inspect('container',state_name);state['setupStateContainerId']=state_container['Id'];persist()
  for attempt in range(80):
   ready=subprocess.run(docker+['exec',state_name,'pg_isready','-h','127.0.0.1','-U','postgres'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=min(2,work.remaining()))
   if ready.returncode==0:break
   time.sleep(.25)
  else:raise RuntimeError('Setup fixture PostgreSQL unavailable')
  port=int(state_container['NetworkSettings']['Ports']['5432/tcp'][0]['HostPort'])
  env['ANALYTICS_RENDERED_ROOT']=str(root)
  env['ANALYTICS_SETUP_PORT']=str(port)
  env['PG_ADMIN_DATABASE_URL']=f'postgresql://postgres@127.0.0.1:{port}/postgres'
  with (root/'canonical-setup.log').open('w') as output:
   child=groups.add(subprocess.Popen([str(NODE),'tests/fixtures/secureshopAnalyticsCanonicalSetup.js'],cwd=workspace,env=env,stdout=output,stderr=output,start_new_session=True));state['childPgid']=child.pid;persist()
   assert child.wait(timeout=min(180,work.remaining()))==0,'Canonical setup failed'
   work.run(lambda:groups.stop(child,work))
  setup_result=json.loads((root/'canonical-setup-result.json').read_text());assert setup_result=={'completed':True,'canonicalStores':16,'ctfJournalComplete':True,'privatePublication':True,'actualModel':False}
  state['canonicalSetup']=setup_result;persist()
  state['buildChildren']=[];build_deadline=time.monotonic()+240
  for label,command in build_commands(NODE,workspace):
   with (root/(label+'-build.log')).open('w') as output:
    child=groups.add(subprocess.Popen(command,cwd=workspace/'client',env=env,stdout=output,stderr=output,start_new_session=True));state['childPgid']=child.pid;state['buildChildren'].append(child.pid);persist()
    try:code=child.wait(timeout=min(work.remaining(),max(.001,build_deadline-time.monotonic())))
    except subprocess.TimeoutExpired:stop();raise RuntimeError('Owned frontend build deadline')
    assert code==0,'Owned frontend build failed'
    work.run(lambda:groups.stop(child,work))
  state['buildSha256']={str(file.relative_to(workspace)):digest(file) for file in (workspace/'client/build').rglob('*') if file.is_file()};persist()
  for item in workspace.rglob('*'):
   if item.is_symlink() or 'node_modules' in item.parts:continue
   if item.is_file() and item.name not in ['.env','.env.setup-publication']:item.chmod(0o444)
  for item in sorted([x for x in workspace.rglob('*') if x.is_dir() and not x.is_symlink() and 'node_modules' not in x.parts],key=lambda x:len(x.parts),reverse=True):item.chmod(0o555)
  workspace.chmod(0o555)
  with log.open('w') as output:
   child=groups.add(subprocess.Popen([str(NODE),'tests/postgres/secureshopAnalyticsRendered.native.js'],cwd=workspace,env=env,stdout=output,stderr=output,start_new_session=True));state['childPgid']=child.pid;persist()
   try:code=child.wait(timeout=min(420,work.remaining()))
   except subprocess.TimeoutExpired:stop();raise RuntimeError('Rendered fixture deadline exceeded')
  assert code==0,'Native full-index rendered fixture failed'
  result=json.loads((root/'result.json').read_text());assert result['passed'] is True
  state['resultSha256']=digest(root/'result.json');state['status']='passed'
 except BaseException as error:
  state['status']='failed';state['errorType']=type(error).__name__;raise
 finally:
  signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous_alarm)
  gate.protect_cleanup();errors=[];budget=CleanupBudget(120)
  try:budget.run(stop)
  except Exception as error:errors.append('child:'+type(error).__name__)
  def daemon():assert run(docker+['info','--format','{{.ID}}'],stdout=subprocess.PIPE,text=True).stdout.strip()==args.daemon_id
  def clean_setup():
   daemon();item=inspect('container',state_name)
   if item:
    assert state.get('setupStateCreationAttempted') and item['Config']['Labels'].get('dvaia.test.owner')==state_owner and item['Image']==IMAGE and item['Name']=='/'+state_name
    if state.get('setupStateContainerId'):assert item['Id']==state['setupStateContainerId']
    run(docker+['rm','-f',item['Id']],stdout=subprocess.DEVNULL)
   assert inspect('container',state_name) is None
  try:budget.run(clean_setup)
  except Exception as error:errors.append('setup-state:'+type(error).__name__)
  def clean_analytics(kind,identifier):
   daemon();intent_file=home/'.dvaia'/workspace_id/'analytics-install-intent.json'
   intent=json.loads(intent_file.read_text()) if intent_file.exists() else None
   item=inspect(kind,identifier)
   if item:
    labels=item['Config']['Labels'] if kind=='container' else item['Labels']
    assert intent and intent['workspaceId']==workspace_id and intent['imageId']==IMAGE
    assert labels.get('dvaia.owner')==intent['ownerId'] and labels.get('dvaia.workspace')==workspace_id and labels.get('dvaia.purpose')=='owned-analytics'
    if kind=='container':assert item['Image']==IMAGE and item['Name']=='/'+identifier
    else:assert item['Name']==identifier
    run(docker+(['rm','-f',item['Id']] if kind=='container' else ['volume','rm',identifier]),stdout=subprocess.DEVNULL)
   assert inspect(kind,identifier) is None
  for kind,identifier in [('container',name),('volume',volume)]:
   try:budget.run(lambda:clean_analytics(kind,identifier))
   except Exception as error:errors.append(kind+':'+type(error).__name__)
  def clean_profiles():
   assert not members(),'Owned group remains; preserve profiles'
   for label in ['analytics','dashboard','transport']:
    profile=root/(label+'-profile')
    if profile.exists():shutil.rmtree(profile)
  try:budget.run(clean_profiles)
  except Exception as error:errors.append('profiles:'+type(error).__name__)
  observed={}
  for key,kind,identifier in [('containerAbsent','container',name),('volumeAbsent','volume',volume),('setupStateAbsent','container',state_name)]:
   try:observed[key]=budget.run(lambda:inspect(kind,identifier) is None)
   except Exception as error:observed[key]=None;errors.append(key+':'+type(error).__name__)
  try:observed['childPgidAbsent']=budget.run(lambda:not members())
  except Exception as error:observed['childPgidAbsent']=None;errors.append('group-observation:'+type(error).__name__)
  state['cleanup']={'browserProfilesAbsent':all(not(root/(label+'-profile')).exists() for label in ['analytics','dashboard','transport']),'errors':errors,**observed}
  if errors or not all(state['cleanup'][key] for key in ['childPgidAbsent','containerAbsent','volumeAbsent','setupStateAbsent','browserProfilesAbsent']):state['status']='failed'
  integrity=CleanupBudget(120)
  try:
   assert integrity.run(lambda:inventory(SOURCE))==initial
   assert integrity.run(lambda:inventory(DONOR))==donor_initial
   assert integrity.run(lambda:modes(SOURCE))==initial_modes and integrity.run(lambda:modes(DONOR))==donor_modes
   state['immutableInputsUnchanged']=True
  except Exception as error:state['immutableInputsUnchanged']=False;state['integrityError']=type(error).__name__;state['status']='failed'
  if log.exists():state['logSha256']=digest(log)
  persist()
 print(json.dumps({'evidence':str(root),'status':state['status'],'cleanup':state['cleanup']}),flush=True)
 if state['status']!='passed':raise SystemExit(1)

if __name__=='__main__':main()
