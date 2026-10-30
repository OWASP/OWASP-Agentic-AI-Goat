#!/usr/bin/env python3
"""Qualify bounded genuine Pricing actor/Judge and uploaded manual with owned stores/listener."""
import argparse, hashlib, json, os, signal, stat, subprocess, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path
import types
# Execute the exact captured helper bytes; verify the frozen copy before creating resources.
SAFETY_PATH = Path(__file__).resolve().with_name("sensitive_info_recovery_safety.py")
SAFETY_BYTES = SAFETY_PATH.read_bytes()
safety = types.ModuleType("pricing_captured_safety")
exec(compile(SAFETY_BYTES, str(SAFETY_PATH), "exec"), safety.__dict__)
SignalGate = safety.SignalGate

EXPECTED_DOCKER='unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock'
from pricing_runtime_pins import validate as validate_runtime_pins, validate_copied_cache
from full_backend_auth_contract import validate_package
from owned_dependency_overlay import prepare_owned_runtime_directories
from mail_disclosure_cleanup_budget import CleanupBudget
from mcp_connected_baseline_contract import validate_ssh
DOCKER=Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')
IMAGE='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
SOURCE=Path(__file__).resolve().parents[2]
MAIN_SOURCE_FOLDERS=('server/database/postgres','server/services','server/agent-runtime','server/data','server/config','db/postgres','scripts/lib','agent-host','server/routes','server/middleware','sidecars/sandbox-runner/owned-pricing-http')
MAIN_SOURCE_FILES=('tests/postgres/pricing_runtime_pins.py','tests/postgres/secureshopPricingJournal.integration.test.js','tests/postgres/run-pricing-actual-isolated.py','tests/postgres/pricing_owned_listener.py','tests/postgres/listings_integrated_executor_owner.py','tests/postgres/full_backend_auth_contract.py','tests/postgres/owned_dependency_overlay.py','tests/postgres/mail_disclosure_cleanup_budget.py','tests/postgres/mcp_connected_baseline_contract.py','tests/fixtures/secureshopPricingActual.js','tests/fixtures/pricingOwnedOutput.js','tests/fixtures/pricingNearMarketCohort.json','tests/fixtures/secureshopPricingAssembled.js','tests/fixtures/secureshopPricingJudgmentPersistence.js','scripts/application-data-root.js','scripts/local-docker-authority.js','sidecars/sandbox-runner/mcpSeccompFilter.c','sidecars/sandbox-runner/secureshopFiles.js','docs/modernization/drafts/secureshop-bound-pricing/0033_bound_pricing.candidate.sql','tests/postgres/sensitive_info_recovery_safety.py','package-lock.json','package.json')
def main_source_inventory(source=None):
 source=Path(source) if source is not None else SOURCE
 paths=set(MAIN_SOURCE_FILES)
 for folder in MAIN_SOURCE_FOLDERS:
  base=source/folder
  if not base.is_dir() or base.is_symlink():raise RuntimeError('Pricing source folder changed')
  for item in base.rglob('*'):
   if item.is_symlink():raise RuntimeError('Pricing source link refused')
   if item.is_file():paths.add(item.relative_to(source).as_posix())
   elif not item.is_dir():raise RuntimeError('Pricing source entry unsupported')
 result={}
 for name in sorted(paths):
  p=source/name;fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
  try:
   before=os.fstat(fd)
   if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1:raise RuntimeError('Pricing source file identity invalid')
   with os.fdopen(os.dup(fd),'rb') as f:content=f.read()
   after=os.fstat(fd);named=p.lstat()
   if len(content)!=before.st_size or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) or stat.S_ISLNK(named.st_mode) or (named.st_dev,named.st_ino)!=(before.st_dev,before.st_ino):raise RuntimeError('Pricing source changed during read')
   result[name]=hashlib.sha256(content).hexdigest()
  finally:os.close(fd)
 return result
def main_dependency_inventory(source=None):
 source=Path(source) if source is not None else SOURCE
 base=source/'node_modules';result={}
 if base.is_symlink() or not base.is_dir():raise RuntimeError('Pricing main dependency root changed')
 for directory,dirs,files in os.walk(base,followlinks=False):
  for name in dirs+files:
   item=Path(directory)/name;relative=item.relative_to(base).as_posix();entry=item.lstat()
   if stat.S_ISLNK(entry.st_mode):
    target=os.readlink(item)
    if os.path.isabs(target) or not (item.parent/target).resolve().is_relative_to(base):raise RuntimeError('Pricing main dependency link escapes root')
    result[relative]={'symlink':target}
   elif stat.S_ISDIR(entry.st_mode):result[relative]={'directory':True,'mode':entry.st_mode&0o777}
   elif stat.S_ISREG(entry.st_mode):
    fd=os.open(item,os.O_RDONLY|os.O_NOFOLLOW)
    try:
     before=os.fstat(fd)
     if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or (before.st_dev,before.st_ino)!=(entry.st_dev,entry.st_ino):raise RuntimeError('Pricing main dependency identity changed')
     digest=hashlib.sha256()
     with os.fdopen(os.dup(fd),'rb') as stream:
      for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
     after=os.fstat(fd);named=item.lstat()
     if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) or (named.st_dev,named.st_ino)!=(before.st_dev,before.st_ino):raise RuntimeError('Pricing main dependency changed during read')
     result[relative]={'sha256':digest.hexdigest(),'mode':entry.st_mode&0o777}
    finally:os.close(fd)
   else:raise RuntimeError('Pricing main dependency entry unsupported')
 return result
def validate_main_source(manifest_path,expected_sha,cohort):
 path=Path(manifest_path)
 if not path.is_absolute() or path.resolve()!=path or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=expected_sha:raise RuntimeError('Pricing main manifest identity mismatch')
 value=json.loads(path.read_text())
 if set(value)!={'version','workspace','cohort','mode','sourcePins','dependencyInventory'} or value['version']!=1 or value['workspace']!=str(SOURCE) or value['cohort']!=cohort or value['mode']!='remaining' or value['sourcePins']!=main_source_inventory() or value['dependencyInventory']!=main_dependency_inventory():raise RuntimeError('Pricing main source/dependency closure mismatch')
 return value
def copy_main_embedding_cache(cache,private_cache):
 private_cache.mkdir(mode=0o700)
 for item in sorted(cache.rglob('*')):
  entry=item.lstat();destination=private_cache/item.relative_to(cache)
  if stat.S_ISLNK(entry.st_mode):raise RuntimeError('Pricing cache link refused')
  if stat.S_ISDIR(entry.st_mode):destination.mkdir(mode=0o700)
  elif stat.S_ISREG(entry.st_mode):
   fd=os.open(item,os.O_RDONLY|os.O_NOFOLLOW)
   try:
    before=os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or (before.st_dev,before.st_ino)!=(entry.st_dev,entry.st_ino):raise RuntimeError('Pricing cache file identity changed')
    with os.fdopen(os.dup(fd),'rb') as source_file,destination.open('xb') as target_file:
     for chunk in iter(lambda:source_file.read(1024*1024),b''):target_file.write(chunk)
    after=os.fstat(fd);named=item.lstat()
    if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) or (named.st_dev,named.st_ino)!=(before.st_dev,before.st_ino):raise RuntimeError('Pricing cache file changed during copy')
    os.chmod(destination,0o600)
   finally:os.close(fd)
  else:raise RuntimeError('Pricing cache entry invalid')
def historical_pricing_config(cohort, remaining=False):
 # These closed selectors match retained fixture budgets; they authorize no execution.
 configurations={
  'baseline':('manual',20,12,True),
  'near-market-v1':('manual',20,12,True),
  'historical-strong-10-v1':('full',10,3,False),
  'historical-strong-20-v1':('full',20,3,False),
  'historical-strong-remaining-3-v1':('remaining',20,3,False),
  'historical-strong-remaining-4-v1':('remaining',20,4,False),
  'historical-strong-manual-3-v1':('manual',20,3,True),
  'pricing-grounding-two-observation-v1':('remaining',16,8,False),
  'pricing-final-positive-v1':('remaining',20,4,False),
 }
 if cohort not in configurations:raise ValueError('Unknown Pricing cohort')
 mode,actor,judge,manual_acceptance=configurations[cohort]
 if remaining != (mode=='remaining'):raise ValueError('Pricing cohort requires its exact remaining-mode selector')
 return {'mode':mode,'actor':actor,'judge':judge,'manualAcceptance':manual_acceptance}

def pricing_cohort_environment(cohort, configuration):
 return {'PERSONA_PRICING_ACTUAL':'1','PERSONA_PRICING_COHORT':cohort,
         'PERSONA_PRICING_MANUAL_ONLY':'1' if configuration['mode']=='manual' else '0',
         'PERSONA_PRICING_ACTUAL_REMAINING':'1' if configuration['mode']=='remaining' else '0'}

def validate_pricing_result(result, configuration):
 if result.get('status')!='passed':raise RuntimeError('pricing result scope mismatch')
 for field,limit in [('actualModelCalls',configuration['actor']),('actualJudgeCalls',configuration['judge'])]:
  value=result.get(field)
  if type(value) is not int or not 0<=value<=limit:raise RuntimeError('pricing result scope mismatch')

parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True);parser.add_argument('--canonical',action='store_true');parser.add_argument('--remaining',action='store_true');parser.add_argument('--main-workspace',action='store_true');parser.add_argument('--plan',action='store_true');parser.add_argument('--python-sha256')
for option in ['node-binary','node-sha256','node-version','dependency-root','dependency-hashes','dependency-byte-sha256','embedding-cache','embedding-manifest-sha256','manifest','manifest-sha256','docker-binary','docker-sha256','docker-daemon-id','ssh-binary','ssh-sha256','ssh-config','ssh-config-sha256','ssh-host']:parser.add_argument('--'+option,required=True)
parser.add_argument('--cohort',choices=['baseline','near-market-v1','historical-strong-10-v1','historical-strong-20-v1','historical-strong-remaining-3-v1','historical-strong-remaining-4-v1','historical-strong-manual-3-v1','pricing-grounding-two-observation-v1','pricing-final-positive-v1'],default='baseline')
args=parser.parse_args();args.canonical=True
cohort_config=historical_pricing_config(args.cohort,args.remaining)
if args.main_workspace and (args.cohort not in ('historical-strong-remaining-3-v1','historical-strong-remaining-4-v1','pricing-grounding-two-observation-v1','pricing-final-positive-v1') or not args.remaining):raise ValueError('Main Pricing path is exact remaining cohort only')
if args.plan and not args.main_workspace:raise ValueError('Pricing plan requires current main path')
if args.main_workspace and (not args.python_sha256 or hashlib.sha256(Path(os.path.realpath(__import__('sys').executable)).read_bytes()).hexdigest()!=args.python_sha256):raise ValueError('Pricing Python executable pin mismatch')
NODE,DEPENDENCIES,EMBEDDING_CACHE=validate_runtime_pins(args,SOURCE)
if EMBEDDING_CACHE!=SOURCE/'tests/fixtures/fullBackendModelCache':raise ValueError('Canonical package embedding cache required')
if DEPENDENCIES!=SOURCE:raise ValueError('Pricing requires dependency tree inside reviewed frozen source')
if args.main_workspace:validate_main_source(args.manifest,args.manifest_sha256,args.cohort)
else:validate_package(SOURCE,args.manifest,args.manifest_sha256,NODE,args.node_sha256)
DOCKER=Path(args.docker_binary)
if not DOCKER.is_absolute() or DOCKER.is_symlink() or not DOCKER.is_file() or hashlib.sha256(DOCKER.read_bytes()).hexdigest()!=args.docker_sha256:raise ValueError('Docker executable pin mismatch')
SSH=validate_ssh(args.ssh_binary,args.ssh_sha256,args.ssh_config,args.ssh_config_sha256,args.ssh_host)
if args.plan:
 print(json.dumps({'workspace':str(SOURCE),'cohort':args.cohort,'mode':'remaining','sourcePins':len(main_source_inventory()),'actorLimit':cohort_config['actor'],'judgeLimit':cohort_config['judge'],'ownedRuntime':False,'executed':False}));raise SystemExit(0)
cleanup_budget=None
def remaining(seconds):return min(seconds,cleanup_budget.remaining()) if cleanup_budget else seconds
mode='pricing-actual-remaining' if args.remaining else 'pricing-actual-upload-model'
test_file='tests/postgres/secureshopPricingJournal.integration.test.js'
if args.docker_host!=EXPECTED_DOCKER:raise SystemExit('reviewed isolated Docker host required')
root=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-pricing-journal-')).resolve();os.chmod(root,0o700);workspace=SOURCE if args.main_workspace else root/'source'
output_root=root/'outputs';output_root.mkdir(mode=0o700)
private_home=root/'home';private_home.mkdir(mode=0o700)
container='owasp-ai-goat-pricing-journal-'+uuid.uuid4().hex[:12];owner=uuid.uuid4().hex
docker=[str(DOCKER),'--host',args.docker_host]
env={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':str(private_home) if args.main_workspace else os.environ['HOME'],'TMPDIR':str(root)}
state={'container':container,'owner':owner,'image':IMAGE,'evidence':str(root),'launcherPid':os.getpid(),
 'nodeVersion':None,'containerCreationAttempted':False,'child':None,'runStatus':'preparing','cleanup':None,
 'mode':mode,'mainWorkspace':args.main_workspace,'actualModel':None,'createdAt':datetime.now(timezone.utc).isoformat()}
ownership=root/'ownership.json';log_path=root/'tests.log';log_path.touch(mode=0o600)
def persist():ownership.write_text(json.dumps(state,indent=2)+'\n');os.chmod(ownership,0o600)
def run(command,**kwargs):kwargs.setdefault('timeout',remaining(120));return subprocess.run(command,check=True,env=kwargs.pop('env',env),**kwargs)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def exact_absence(name=container):
 query=subprocess.run(docker+['ps','-a','--filter',f'name=^/{name}$','--format','{{.Names}}'],env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=remaining(30))
 if query.returncode:raise RuntimeError('exact-name container query failed')
 return not query.stdout.strip()
executor=None;child=None;creation_attempted=False;gate=SignalGate();signal.signal(signal.SIGTERM,gate.handler);signal.signal(signal.SIGINT,gate.handler);persist()
def deadline(_signum,_frame):raise TimeoutError('pricing native parent deadline')
signal.signal(signal.SIGALRM,deadline);signal.alarm(900)
def owned_group_members(pgid):
 listing=subprocess.run(['ps','-axo','pid=,pgid=,uid='],env=env,stdout=subprocess.PIPE,text=True,check=True,timeout=remaining(5)).stdout
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
 while owned_group_members(pgid) and time.monotonic()<deadline:time.sleep(.05)
 if owned_group_members(pgid):os.killpg(pgid,signal.SIGKILL)
 try:child.wait(timeout=remaining(5))
 except subprocess.TimeoutExpired:pass
 until=time.monotonic()+min(5,remaining(5))
 while owned_group_members(pgid) and time.monotonic()<until:time.sleep(.05)
 if owned_group_members(pgid):raise RuntimeError('owned Node/browser process group cleanup incomplete')
try:
 version=run([str(NODE),'--version'],stdout=subprocess.PIPE,text=True).stdout.strip()
 if version!=args.node_version:raise RuntimeError('pinned Node version required')
 state['nodeVersion']=version;persist()
 daemon_name=run(docker+['info','--format','{{.Name}}'],stdout=subprocess.PIPE,text=True).stdout.strip()
 if daemon_name!='colima-owasp-ai-goat-pg-verify':raise RuntimeError('reviewed isolated Docker daemon required')
 image_id=run(docker+['image','inspect','--format','{{.Id}}',IMAGE],stdout=subprocess.PIPE,text=True).stdout.strip()
 if image_id!=IMAGE:raise RuntimeError('immutable PostgreSQL image identity mismatch')
 state['dockerDaemon']=daemon_name;state['imageId']=image_id;persist()
 if run(docker+['info','--format','{{.ID}}'],stdout=subprocess.PIPE,text=True).stdout.strip()!=args.docker_daemon_id:raise RuntimeError('Docker daemon identity mismatch')
 if not exact_absence():raise RuntimeError('owned container name unexpectedly exists')
 if not args.main_workspace:
  run([str(NODE),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(SOURCE),str(workspace)],cwd=SOURCE)
  prepare_owned_runtime_directories(SOURCE,workspace,root)
  (workspace/'node_modules').symlink_to(DEPENDENCIES/'node_modules',target_is_directory=True)
 inventory=['tests/postgres/pricing_runtime_pins.py',test_file,'docs/modernization/drafts/secureshop-bound-pricing/0033_bound_pricing.candidate.sql','tests/postgres/run-pricing-actual-isolated.py','tests/fixtures/secureshopPricingActual.js','tests/fixtures/pricingNearMarketCohort.json','tests/postgres/pricing_owned_listener.py','tests/fixtures/secureshopPricingAssembled.js','scripts/application-data-root.js','scripts/local-docker-authority.js','sidecars/sandbox-runner/mcpSeccompFilter.c','tests/postgres/sensitive_info_recovery_safety.py','package-lock.json','package.json']
 for folder in ['server/database/postgres','server/services','server/agent-runtime','server/data','server/config','db/postgres','scripts/lib','shared','agent-host','server/routes','server/middleware','sidecars/sandbox-runner/owned-pricing-http']:
  inventory.extend(str(item.relative_to(workspace)) for item in sorted((workspace/folder).rglob('*')) if item.is_file())
 if (workspace/'tests/postgres/sensitive_info_recovery_safety.py').read_bytes()!=SAFETY_BYTES:raise RuntimeError('cleanup helper changed during freeze')
 state['sourceSha256']={name:digest(workspace/name) for name in sorted(set(inventory))};state['nodeSha256']=digest(NODE);persist()
 cache=EMBEDDING_CACHE
 private_cache=root/'model-cache'
 if args.main_workspace:
  copy_main_embedding_cache(cache,private_cache)
 else:private_cache=workspace/'tests/fixtures/fullBackendModelCache'
 validate_copied_cache(cache,private_cache)
 cache_files={str(item.relative_to(private_cache)):digest(item) for item in sorted(private_cache.rglob('*')) if item.is_file()}
 expected_manifest=args.embedding_manifest_sha256
 if len(cache_files)!=4 or hashlib.sha256(json.dumps(cache_files,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=expected_manifest:raise RuntimeError('embedding cache manifest mismatch')
 state['embeddingCache']={'source':str(cache),'copiedPath':str(private_cache),'files':cache_files,'manifestSha256':expected_manifest};persist()
 env['XENOVA_CACHE']=str(private_cache);env['TRANSFORMERS_CACHE']=str(private_cache);env.update(pricing_cohort_environment(args.cohort,cohort_config))
 if args.main_workspace:env['OWASP_AI_GOAT_PRICING_OWNED_OUTPUT_ROOT']=str(output_root)
 run([str(NODE),'--check',test_file],cwd=workspace)
 creation_attempted=True;state['containerCreationAttempted']=True;persist()
 run(docker+['run','--detach','--pull','never','--name',container,'--label','owasp-ai-goat.test.owner='+owner,
  '--memory','1g','--cpus','2','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size=536870912','-e','POSTGRES_HOST_AUTH_METHOD=trust',
  '-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',IMAGE,'-c','shared_buffers=16MB','-c','max_connections=40',
  '-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL)
 details=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]
 if details.get('Mounts') or details['Config']['Labels'].get('owasp-ai-goat.test.owner')!=owner or details['Image']!=IMAGE:raise RuntimeError('owned PostgreSQL isolation/ownership check failed')
 limits=details['HostConfig']
 if limits['Memory']!=1073741824 or limits['NanoCpus']!=2000000000 or limits['PidsLimit']!=128 or list(limits['PortBindings'])!=['5432/tcp'] or len(limits['PortBindings']['5432/tcp'])!=1 or limits['PortBindings']['5432/tcp'][0]['HostIp']!='127.0.0.1':raise RuntimeError('owned PostgreSQL resource/publication mismatch')
 state['containerId']=details['Id'];state['inspectedResources']={'memory':limits['Memory'],'nanoCpus':limits['NanoCpus'],'pidsLimit':limits['PidsLimit'],'portBindings':limits['PortBindings'],'mounts':details.get('Mounts')};persist()
 for _ in range(100):
  ready=subprocess.run(docker+['exec',container,'pg_isready','-h','127.0.0.1','-U','postgres'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=remaining(2))
  if ready.returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('owned PostgreSQL unavailable')
 port=int(run(docker+['port',container,'5432/tcp'],stdout=subprocess.PIPE,text=True).stdout.strip().rsplit(':',1)[1])
 published=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]['NetworkSettings']['Ports']
 if published!={'5432/tcp':[{'HostIp':'127.0.0.1','HostPort':str(port)}]}:raise RuntimeError('owned PostgreSQL effective publication mismatch')
 state['inspectedResources']['effectivePorts']=published;persist()
 psql=docker+['exec',container,'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-c']
 roles=[f'dvaia_{family}_{role}' for family in ['identity','secureshop','secureshop_agents','secureshop_review'] for role in ['migration','runtime']]
 run(psql+[';'.join(f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS' for role in roles)+';'],stdout=subprocess.DEVNULL)
 nonce=owner[:12]
 for store,family in [('identity','identity'),('commerce','secureshop'),('fresh','secureshop_agents'),('aclfresh','secureshop_agents'),('review','secureshop_review')]:
  database=f'owasp_ai_goat_test_persona_{nonce}_{store}';migration=f'dvaia_{family}_migration';runtime=f'dvaia_{family}_runtime'
  run(psql+[f'CREATE DATABASE {database} OWNER {migration}'],stdout=subprocess.DEVNULL)
  run(psql+[f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime}'],stdout=subprocess.DEVNULL)
  env[f'PERSONA_{store.upper()}_MIGRATION_URL']=f'postgresql://{migration}@127.0.0.1:{port}/{database}'
  env[f'PERSONA_{store.upper()}_RUNTIME_URL']=f'postgresql://{runtime}@127.0.0.1:{port}/{database}'
 import importlib.util
 spec=importlib.util.spec_from_file_location('pricing_frozen_listener',workspace/'tests/postgres/pricing_owned_listener.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 executor=module.PricingOwnedListener(workspace=workspace,evidence=root,docker=docker,node=NODE,environment=env,ssh=SSH)
 env.update(executor.start())
 env['PERSONA_PRICING_NATIVE']='1'
 if args.canonical:env['PERSONA_PRICING_CANONICAL']='1'
 env.update(NODE_ENV='test',PG_TEST_DISPOSABLE='yes',PERSONA_REVIEW_CANONICAL_NATIVE='1',OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(workspace),
  PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',
  AI_PROVIDER='mock',TRANSFORMERS_OFFLINE='1',JWT_SECRET=uuid.uuid4().hex+uuid.uuid4().hex,SESSION_SECRET=uuid.uuid4().hex+uuid.uuid4().hex,
  AWS_EC2_METADATA_DISABLED='true',MCP_WORKSHOP_AUTOSTART='false',MCP_SIDECARS_AUTOSTART='false',SS_ENABLE='false',HF_HUB_OFFLINE='1',
  OLLAMA_BASE_URL='http://127.0.0.1:1',SANDBOX_RUNNER_URL='http://127.0.0.1:1',SSRF_TARGET_URL='http://127.0.0.1:1',
 ROGUE_MCP_URL='http://127.0.0.1:1',MAILPIT_API_URL='http://127.0.0.1:1',MAILPIT_SMTP_HOST='127.0.0.1',MAILPIT_SMTP_PORT='1')
 command=[str(NODE),'--test','--test-reporter=tap',test_file]
 if args.main_workspace:
  boundary_source="const b=require('./scripts/lib/isolated-test-boundary');const [source,root,node,home,...args]=process.argv.slice(1);const data=b.artifactEnvironment(root);const boundary=b.buildBoundary({source,directory:root,secrets:b.discoverSecrets(source,home),executable:node,args});process.stdout.write(JSON.stringify({data,command:boundary.command,args:boundary.args,cwd:boundary.cwd}));"
  bounded=json.loads(run([str(NODE),'-e',boundary_source,str(SOURCE),str(root),str(NODE),os.environ['HOME'],'--test','--test-reporter=tap',test_file],cwd=SOURCE,stdout=subprocess.PIPE,text=True,timeout=remaining(120)).stdout)
  for value in bounded['data'].values():
   p=Path(value)
   if not p.is_absolute() or not p.is_relative_to(root):raise RuntimeError('Pricing private data path escaped')
   p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
  for name in ['home','tmp','config','cache','share','databases','uploads','logs','vectors','legacy-sensitive']:(root/'data'/name).mkdir(parents=True,exist_ok=True,mode=0o700)
  env.update(bounded['data']);command=[bounded['command'],*bounded['args']]
  state['filesystemBoundary']='isolated-test-boundary';persist()
 with log_path.open('w') as log:
  child=subprocess.Popen(command,cwd=workspace,env=env,stdout=log,stderr=log,start_new_session=True)
  state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid)};state['runStatus']='test_running';persist()
  try:code=child.wait(timeout=remaining(840))
  except subprocess.TimeoutExpired:stop_child();raise RuntimeError('Pricing journal qualification timed out')
 if code:raise RuntimeError(f'Pricing journal qualification failed ({code}); inspect retained tests.log')
 artifact=output_root/'pricing-journal-result.json' if args.main_workspace else workspace/'pricing-journal-result.json'
 result=json.loads(artifact.read_text())
 validate_pricing_result(result,cohort_config)
 actual=output_root/'pricing-actual-result.json' if args.main_workspace else workspace/'pricing-actual-result.json'
 if not actual.is_file():raise RuntimeError('actual observation artifact missing')
 (root/'pricing-actual-result.json').write_bytes(actual.read_bytes());os.chmod(root/'pricing-actual-result.json',0o600)
 state['actualArtifactSha256']=digest(root/'pricing-actual-result.json')
 from pricing_runtime_pins import require_manual_acceptance
 observation=json.loads(actual.read_text());state['qualificationStatus']='unqualified';persist()
 if observation.get('cohort')!=args.cohort:raise RuntimeError('Pricing cohort mismatch')
 if args.cohort=='pricing-final-positive-v1':
  from pricing_runtime_pins import require_final_positive_acceptance
  require_final_positive_acceptance(observation)
  state['qualificationStatus']='passed_final_two_positive'
 elif args.cohort=='pricing-grounding-two-observation-v1':
  from pricing_runtime_pins import require_two_observation_acceptance
  require_two_observation_acceptance(observation)
  state['qualificationStatus']='passed_two_observation_positive_and_negative'
 if args.main_workspace:
  if observation.get('model')!={'name':'llama3.1:8b','digest':'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'}:raise RuntimeError('Pricing actual model identity missing')
  expected_actor={'grounding_attack':8,'grounding_clean':8} if args.cohort=='pricing-grounding-two-observation-v1' else {'false_grounding':8,'manual_upload':4,'manual_override':8}
  if observation.get('budget',{}).get('actorPerPhase')!=expected_actor:raise RuntimeError('Pricing remaining actor budget mismatch')
  if any(call.get('status')!='returned' or call.get('httpStatus')!=200 or call.get('request',{}).get('model')!='llama3.1:8b' for call in observation.get('calls',[])):raise RuntimeError('Pricing actual wire incomplete')
 if cohort_config['manualAcceptance']:
  require_manual_acceptance(observation)
  state['qualificationStatus']='passed_manual_positive_and_matched_negative'
 elif args.cohort not in ('pricing-grounding-two-observation-v1','pricing-final-positive-v1'):
  state['qualificationStatus']='historical_observation_only'
 retained=root/'pricing-journal-result.json';retained.write_bytes(artifact.read_bytes());os.chmod(retained,0o600)
 state['artifactPath']=str(retained);state['artifactSha256']=digest(retained)
 state['runStatus']='passed';state['resultSha256']=digest(log_path);persist()
except BaseException as error:
 if creation_attempted:
  try:
   diagnostic=subprocess.run(docker+['logs','--tail','120',container],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=remaining(20))
   (root/'container.log').write_text(diagnostic.stdout);os.chmod(root/'container.log',0o600)
  except Exception as diagnostic_error:state['containerDiagnosticError']=type(diagnostic_error).__name__
 state.update({'runStatus':'failed','errorType':type(error).__name__,'resultSha256':digest(log_path)});persist();raise
finally:
 actual=output_root/'pricing-actual-result.json' if args.main_workspace else workspace/'pricing-actual-result.json'
 if actual.is_file():
  (root/'pricing-actual-result.json').write_bytes(actual.read_bytes());os.chmod(root/'pricing-actual-result.json',0o600)
  state['actualArtifactSha256']=digest(root/'pricing-actual-result.json');persist()
 signal.alarm(0);gate.protect_cleanup();cleanup_budget=CleanupBudget(120);errors=[];remove_code=None;absent=None
 try:stop_child()
 except Exception as error:errors.append('child:'+type(error).__name__)
 if executor is not None:
  try:
   if not executor.close(budget=cleanup_budget):errors.append('executor-cleanup')
  except BaseException as error:errors.append('executor:'+type(error).__name__)
 if creation_attempted:
  try:
   if not exact_absence():
    info=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]
    if info['Config']['Labels'].get('owasp-ai-goat.test.owner')!=owner or info['Image']!=IMAGE or (state.get('containerId') and info['Id']!=state['containerId']):raise RuntimeError('refusing foreign container cleanup')
    remove_code=subprocess.run(docker+['rm','-f','-v',container],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=remaining(30)).returncode
   else:remove_code=0
  except Exception as error:errors.append('remove:'+type(error).__name__)
 try:absent=exact_absence()
 except Exception as error:errors.append('absence:'+type(error).__name__)
 try:pgid_absent=not state.get('child') or not owned_group_members(state['child']['pgid'])
 except Exception as error:errors.append('pgid:'+type(error).__name__);pgid_absent=False
 try:cleanup_budget.run(lambda:validate_main_source(args.manifest,args.manifest_sha256,args.cohort) if args.main_workspace else validate_package(SOURCE,args.manifest,args.manifest_sha256,NODE,args.node_sha256))
 except Exception as error:errors.append('frozen-integrity:'+type(error).__name__)
 state['cleanup']={'removeExitCode':remove_code,'containerAbsent':absent,'nodeBrowserPgidAbsent':pgid_absent,
  'errors':errors,'completedAt':datetime.now(timezone.utc).isoformat()}
 if state['runStatus']=='passed' and (errors or absent is not True or pgid_absent is not True or (creation_attempted and remove_code!=0)):state['runStatus']='failed';state['errorType']='CleanupFailed'
 persist()
print(json.dumps({'evidence':str(root),'status':state['runStatus'],'cleanup':state['cleanup']}),flush=True)
if state['runStatus']!='passed':raise SystemExit(1)
