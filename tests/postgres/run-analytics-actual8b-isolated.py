#!/usr/bin/env python3
"""Two owned clusters; bounded fixed-input canonical Analytics actor/Judge qualification."""
import argparse,hashlib,json,os,signal,subprocess,tempfile,time,uuid
from pathlib import Path
from datetime import datetime,timezone
from sensitive_info_recovery_safety import SignalGate
NODE=Path('/Users/averma5/.dvaia/runtimes/node-v26.9.0-darwin-arm64/bin/node')
DOCKER='/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker'
HOST='unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
IMAGE='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
SOURCE=Path(__file__).resolve().parents[2]
STANDALONE_DISCLOSURE_NATIVE='tests/postgres/secureshopAnalyticsActual8b.integration.test.js'
STANDALONE_DISCLOSURE_NATIVE_SHA256='c311d13377ed420b822982f451e088f00bc5c845c4ca44e3ff53ad85ee9dbf35'
STANDALONE_DISCLOSURE_BROWSER='tests/fixtures/secureshopAnalyticsRenderedBrowser.js'
STANDALONE_DISCLOSURE_BROWSER_SHA256='4a68c3d294f114fcb94655d19f566f87a728d23b537f049a7501a2b521b7f362'
STANDALONE_DISCLOSURE_CONTRACT='tests/fixtures/secureshopAnalyticsRenderedBrowser.test.js'
STANDALONE_DISCLOSURE_CONTRACT_SHA256='a87a2414bcb5159ab6e4fee2c9da34c3e2ae0a83ff1e87a8e75a1354fbc4a1d7'
p=argparse.ArgumentParser(allow_abbrev=False);p.add_argument('--docker-host',required=True);g=p.add_mutually_exclusive_group();g.add_argument('--effect-only',action='store_true');g.add_argument('--admission-only',action='store_true');g.add_argument('--mounted-only',action='store_true');g.add_argument('--fixed-mode',action='store_true');g.add_argument('--catalog-only',action='store_true');g.add_argument('--merchant-history-browser',action='store_true');g.add_argument('--standalone-disclosure-browser',action='store_true')
p.add_argument('--main-source',action='store_true');p.add_argument('--plan',action='store_true')
for key in ['node','node-sha256','browser','browser-sha256','browser-root','build','build-sha256','ollama-model-sha256']:p.add_argument('--'+key)
args=p.parse_args()
if args.docker_host!=HOST:raise SystemExit('Reviewed isolated daemon required')
browser_cohort=args.merchant_history_browser or args.standalone_disclosure_browser
def tree_inventory(root,allow_links=False):
 root=Path(root);rows={}
 if root.resolve()!=root or root.is_symlink() or not root.is_dir():raise ValueError('Canonical directory required')
 for item in sorted(root.rglob('*')):
  if item.is_symlink():
   target=item.resolve()
   if not (allow_links or root.name=='node_modules') or not target.is_relative_to(root) or not (target.is_file() or target.is_dir()):raise ValueError('Directory symlink denied')
   rows[item.relative_to(root).as_posix()]={'target':str(target.relative_to(root)),**({'sha256':hashlib.sha256(target.read_bytes()).hexdigest()} if target.is_file() else {'directory':True})};continue
  if item.is_file():rows[item.relative_to(root).as_posix()]=hashlib.sha256(item.read_bytes()).hexdigest()
 return rows
def tree_digest(root,allow_links=False):return hashlib.sha256(json.dumps(tree_inventory(root,allow_links),sort_keys=True,separators=(',',':')).encode()).hexdigest()
def verify_standalone_disclosure_sources(root):
 for relative,expected in ((STANDALONE_DISCLOSURE_NATIVE,STANDALONE_DISCLOSURE_NATIVE_SHA256),(STANDALONE_DISCLOSURE_BROWSER,STANDALONE_DISCLOSURE_BROWSER_SHA256),(STANDALONE_DISCLOSURE_CONTRACT,STANDALONE_DISCLOSURE_CONTRACT_SHA256)):
  if digest(Path(root)/relative)!=expected:raise SystemExit('Frozen standalone disclosure source pin required')
 return True
def validate_standalone_disclosure_receipt(value):
 counters=value.get('counters') if isinstance(value,dict) else None
 if (not isinstance(counters,dict) or not 7<=counters.get('actor',-1)<=14 or not 1<=counters.get('judge',-1)<=6 or counters.get('queries')!=4 or counters.get('successfulQueries')!=4 or counters.get('posts')!=5 or counters['actor']+counters['judge']>=20):raise RuntimeError('Standalone disclosure counters outside frozen V20 bounds')
 browser=value.get('browser');disclosure=browser.get('disclosure') if isinstance(browser,dict) else None;fixed=browser.get('fixedDisclosure') if isinstance(browser,dict) else None
 proof=fixed.get('callbackProof') if isinstance(fixed,dict) else None
 judgment=proof.get('fixedJudgment') if isinstance(proof,dict) else None
 judgment_keys={'evaluationId','runId','evidenceDigest','mode','verdict','disposition','errorCode','provider','model'}
 if (not isinstance(disclosure,dict) or disclosure.get('physicalSubmit') is not True or disclosure.get('rendered') is not True or disclosure.get('savedGetCount')!=2 or disclosure.get('replayed') is not True or not isinstance(fixed,dict) or fixed.get('physicalModeSwitch') is not True or fixed.get('physicalSubmit') is not True or fixed.get('rendered') is not True or fixed.get('status')!='denied' or fixed.get('noProtectedDisclosure') is not True or fixed.get('noCredit') is not True or not isinstance(proof,dict) or proof.get('denial')!={'code':'42501','source':'postgresql','backendAbsent':True} or proof.get('priorJudgmentsUnchanged') is not True or proof.get('completionUnchanged') is not True or proof.get('activeCreditUnchanged') is not True or not isinstance(judgment,dict) or set(judgment)!=judgment_keys or judgment.get('mode')!='fixed' or judgment.get('verdict')!='fail' or judgment.get('disposition')!='not_pass' or judgment.get('errorCode')!='REQUIRED_FACTS_NOT_SATISFIED' or judgment.get('provider') is not None or judgment.get('model') is not None or not all(isinstance(judgment.get(key),str) and judgment.get(key) for key in ('evaluationId','runId')) or not isinstance(judgment.get('evidenceDigest'),str) or len(judgment['evidenceDigest'])!=64 or any(char not in '0123456789abcdef' for char in judgment['evidenceDigest'])):raise RuntimeError('Standalone disclosure fixed-contrast receipt incomplete')
 return value
if browser_cohort:
 if not args.main_source:raise SystemExit('Standalone Analytics browser qualification requires current main source')
 for value,pin in [(args.node,args.node_sha256),(args.browser,args.browser_sha256)]:
  path=Path(value or '/')
  if not path.is_absolute() or path.resolve()!=path or path.is_symlink() or not path.is_file() or not os.access(path,os.X_OK) or not __import__('re').fullmatch('[a-f0-9]{64}',pin or '') or hashlib.sha256(path.read_bytes()).hexdigest()!=pin:raise SystemExit('Pinned executable required')
 NODE=Path(args.node);BUILD=Path(args.build or '/')
 BROWSER_ROOT=Path(args.browser_root or '/')
 if not Path(args.browser).is_relative_to(BROWSER_ROOT) or BROWSER_ROOT==Path('/'):raise SystemExit('Canonical browser package root required')
 browser_package_pin=tree_digest(BROWSER_ROOT,True)
 if subprocess.run([str(NODE),'--version'],check=True,stdout=subprocess.PIPE,text=True,timeout=5,env={'PATH':str(NODE.parent)+':/usr/bin:/bin'}).stdout.strip()!='v26.10.0':raise SystemExit('Pinned Node26.10 required')
 if BUILD!=SOURCE/'client/build' or tree_digest(BUILD)!=args.build_sha256:raise SystemExit('Qualified current build pin required')
 if args.ollama_model_sha256!='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e':raise SystemExit('Qualified llama3.1:8b digest required')
 if args.plan:
  print(json.dumps({'cohort':'standalone-analytics-disclosure-browser' if args.standalone_disclosure_browser else 'merchant-analytics-history-browser','workspace':str(SOURCE),'sourceCopy':False,'stores':['identity','secureshop_agents','secureshop','secureshop_review'],'ownedSqlTarget':True,'browser':True,'actorBudget':[7,14] if args.standalone_disclosure_browser else [4,12],'judgeBudget':[1,6] if args.standalone_disclosure_browser else [0,6],'queryPosts':5 if args.standalone_disclosure_browser else 2,'sqlAttempts':4 if args.standalone_disclosure_browser else 2,'modelCallsMax':19 if args.standalone_disclosure_browser else 17,'sourcePins':({'native':STANDALONE_DISCLOSURE_NATIVE_SHA256,'browser':STANDALONE_DISCLOSURE_BROWSER_SHA256,'contract':STANDALONE_DISCLOSURE_CONTRACT_SHA256} if args.standalone_disclosure_browser else None),'allocationStarted':False}));raise SystemExit(0)
elif args.plan:raise SystemExit('Plan requires standalone Analytics browser opt-in')
elif any([args.node,args.node_sha256,args.browser,args.browser_sha256,args.browser_root,args.build,args.build_sha256,args.ollama_model_sha256]):raise SystemExit('Browser pins require standalone Analytics browser opt-in')
owner=uuid.uuid4().hex;nonce=owner[:12];root=Path(tempfile.mkdtemp(prefix='dvaia-analytics-model-'));os.chmod(root,0o700);workspace=SOURCE if args.main_source else root/'source'
containers={kind:f'dvaia-analytics-model-{nonce}-{kind}' for kind in ['target','state']};attempted=[]
docker=[DOCKER,'--host',HOST];env={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':os.environ['HOME'],'TMPDIR':str(root)}
state={'owner':owner,'containers':containers,'image':IMAGE,'evidence':str(root),'runStatus':'preparing','child':None,'cleanup':None,'launcherPid':os.getpid(),'createdAt':datetime.now(timezone.utc).isoformat()}
log=root/'tests.log';log.touch(mode=0o600);child=None;gate=SignalGate();signal.signal(signal.SIGTERM,gate.handler);signal.signal(signal.SIGINT,gate.handler)
def persist():
 path=root/'ownership.json';path.write_text(json.dumps(state,indent=2)+'\n');os.chmod(path,0o600)
def run(command,**kwargs):kwargs.setdefault('timeout',60);return subprocess.run(command,check=True,env=env,**kwargs)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def absent(name):return not run(docker+['ps','-a','--filter',f'name=^/{name}$','--format','{{.Names}}'],stdout=subprocess.PIPE,text=True).stdout.strip()
def members(pgid):
 result=[]
 for line in run(['ps','-axo','pid=,pgid=,uid='],stdout=subprocess.PIPE,text=True).stdout.splitlines():
  fields=line.split()
  if len(fields)==3 and int(fields[1])==pgid:
   if int(fields[2])!=os.getuid():raise RuntimeError('Foreign process in owned group')
   result.append(int(fields[0]))
 return result
def stop_child():
 if child is None:return
 pgid=state['child']['pgid']
 if members(pgid):os.killpg(pgid,signal.SIGTERM)
 deadline=time.monotonic()+5
 while members(pgid) and time.monotonic()<deadline:child.poll();time.sleep(.05)
 if members(pgid):os.killpg(pgid,signal.SIGKILL)
 child.wait(timeout=5)
 if members(pgid):raise RuntimeError('Child group cleanup incomplete')
persist()
try:
 assert run([str(NODE),'--version'],stdout=subprocess.PIPE,text=True).stdout.strip()==('v26.10.0' if browser_cohort else 'v26.9.0')
 assert run(docker+['info','--format','{{.Name}}'],stdout=subprocess.PIPE,text=True).stdout.strip()=='colima-dvaia-pg-verify'
 assert run(docker+['image','inspect','--format','{{.Id}}',IMAGE],stdout=subprocess.PIPE,text=True).stdout.strip()==IMAGE
 for name in containers.values():assert absent(name)
 if not args.main_source:
  run([str(NODE),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(SOURCE),str(workspace)],cwd=SOURCE)
  (workspace/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
 if args.catalog_only:
  before=digest(workspace/'server/config/secureshopCurriculum.js')
  run([str(NODE),'-e',"require('./tests/helpers/secureshopAnalyticsCurriculumCandidate').stage(process.cwd())"],cwd=workspace)
  state['stagedCurriculum']={'originalSha256':before,'candidateSha256':digest(workspace/'server/config/secureshopCurriculum.js'),'scope':'Analytics qualification/content only; production remains pending'}
 test='tests/postgres/secureshopAnalyticsCatalog.integration.test.js' if args.catalog_only else 'tests/postgres/secureshopAnalyticsAdmission.integration.test.js' if (args.admission_only or args.mounted_only) else 'tests/postgres/secureshopAnalyticsPersonaEffect.integration.test.js' if args.effect_only else 'tests/postgres/secureshopAnalyticsActual8b.integration.test.js'
 inventory=['tests/helpers/secureshopAnalyticsCurriculumCandidate.js','client/src/pages/secureshop/pages/merchant/useBoundAnalytics.js','client/src/pages/secureshop/pages/merchant/useBoundAnalytics.test.jsx','client/src/pages/secureshop/pages/merchant/Analytics.jsx',test,'tests/postgres/secureshopAnalyticsMounted.cohort.js','tests/postgres/secureshopAnalyticsHttpHarness.js','tests/postgres/secureshopAnalyticsProtectedColumns.cohort.js','tests/postgres/secureshopAnalyticsFixedMode.cohort.js','tests/postgres/run-analytics-actual8b-isolated.py','tests/postgres/sensitive_info_recovery_safety.py','package.json','package-lock.json']
 if browser_cohort:
  if args.standalone_disclosure_browser:verify_standalone_disclosure_sources(SOURCE)
  inventory+=['tests/fixtures/secureshopAnalyticsRenderedBrowser.js','tests/fixtures/secureshopAnalyticsBrowserOwner.js',
   'tests/fixtures/browserProcessOwnership.js','tests/fixtures/secureshopAnalyticsRenderedBrowser.test.js','tests/postgres/test_analytics_rendered_launcher.py']
  inventory.extend(str(file.relative_to(workspace)) for folder in ['client/build','client/src','shared'] for file in (workspace/folder).rglob('*') if file.is_file())
  inventory.extend(str(file.relative_to(workspace)) for file in (workspace/'server/routes').rglob('*') if file.is_file())
  state['dependencySha256']=tree_digest(SOURCE/'node_modules');state['browserSha256']=args.browser_sha256;state['browserPackageSha256']=browser_package_pin;state['buildSha256']=args.build_sha256
 for folder in ['server/database/postgres','server/services','server/agent-runtime','server/config','server/data','server/middleware','server/routes/secureshop','db/postgres','scripts/lib','sidecars/analytics-sql-target','docs/modernization/drafts/secureshop-bound-analytics']:
  inventory.extend(str(file.relative_to(workspace)) for file in (workspace/folder).rglob('*') if file.is_file())
 state['sourceSha256']={name:digest(workspace/name) for name in sorted(set(inventory))};state['nodeSha256']=digest(NODE);persist()
 run([str(NODE),'--check',test],cwd=workspace)
 ports={};container_ids={}
 for kind,name in containers.items():
  attempted.append(name);state['creationAttempted']=attempted;persist()
  run(docker+['run','--detach','--pull','never','--name',name,'--label','dvaia.test.owner='+owner,'--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size=268435456','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',IMAGE,'-c','shared_buffers=16MB','-c','max_connections=50','-c','max_wal_size=16MB','-c','min_wal_size=4MB','-c','cluster_name='+('dvaia-owned-analytics-'+nonce if kind=='target' else 'dvaia-analytics-state-'+nonce)],stdout=subprocess.DEVNULL)
  info=json.loads(run(docker+['inspect',name],stdout=subprocess.PIPE,text=True).stdout)[0]
  container_ids[name]=info['Id']
  assert not info.get('Mounts') and info['Config']['Labels'].get('dvaia.test.owner')==owner
  for _ in range(100):
   ready=subprocess.run(docker+['exec',name,'pg_isready','-h','127.0.0.1','-U','postgres'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
   if ready.returncode==0:break
   time.sleep(.25)
  else:raise RuntimeError('Owned PostgreSQL unavailable')
  ports[kind]=int(run(docker+['port',name,'5432/tcp'],stdout=subprocess.PIPE,text=True).stdout.strip().rsplit(':',1)[1])
 def sql(kind,text):run(docker+['exec',containers[kind],'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-c',text],stdout=subprocess.DEVNULL)
 control='dvaia_analytics_control_'+nonce;sql('target',f'CREATE DATABASE {control}')
 for name in ['postgres','template0','template1',control]:sql('target',f'REVOKE CONNECT ON DATABASE {name} FROM PUBLIC')
 for label,prefix in [('identity','identity'),('agents','secureshop_agents'),('commerce','secureshop')]+([('review','secureshop_review')] if args.mounted_only or browser_cohort else []):
  migration='dvaia_'+prefix+'_migration';runtime='dvaia_'+prefix+'_runtime'
  for role in [migration,runtime]:sql('state',f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
  database=f'dvaia_test_analytics_model_{nonce}_{label}';sql('state',f'CREATE DATABASE {database} OWNER {migration}');sql('state',f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime}')
  for key,role in [('MIGRATION',migration),('RUNTIME',runtime)]:env[f'ANALYTICS_ACTUAL_{label.upper()}_{key}_URL']=f'postgresql://{role}@127.0.0.1:{ports["state"]}/{database}'
 if args.admission_only or args.mounted_only:
  database=f'dvaia_test_analytics_model_{nonce}_fresh';sql('state',f'CREATE DATABASE {database} OWNER dvaia_secureshop_agents_migration');sql('state',f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO dvaia_secureshop_agents_migration,dvaia_secureshop_agents_runtime')
  for key,role in [('MIGRATION','dvaia_secureshop_agents_migration'),('RUNTIME','dvaia_secureshop_agents_runtime')]:env[f'ANALYTICS_ACTUAL_FRESH_{key}_URL']=f'postgresql://{role}@127.0.0.1:{ports["state"]}/{database}'
  env['ANALYTICS_ADMISSION_ONLY']='1'
 env.update(ANALYTICS_FIXED_MODE='1' if args.fixed_mode else '0',ANALYTICS_ACTUAL8B='1',ANALYTICS_ACTUAL_OWNER=nonce,ANALYTICS_ACTUAL_TARGET_PORT=str(ports['target']),ANALYTICS_ACTUAL_EVIDENCE=str(root/'actual-evidence.json'),NODE_ENV='test',PG_TEST_DISPOSABLE='yes',DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace),PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',AI_PROVIDER='ollama',OLLAMA_MODEL='llama3.1:8b',OLLAMA_BASE_URL='http://127.0.0.1:11434',AWS_EC2_METADATA_DISABLED='true',MCP_WORKSHOP_AUTOSTART='false',MCP_SIDECARS_AUTOSTART='false',SS_ENABLE='false',HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',JWT_SECRET=uuid.uuid4().hex+uuid.uuid4().hex,SESSION_SECRET=uuid.uuid4().hex+uuid.uuid4().hex)
 if args.catalog_only:env['ANALYTICS_CATALOG_ONLY']='1'
 if args.mounted_only:env['ANALYTICS_MOUNTED_ONLY']='1'
 if args.effect_only:env['ANALYTICS_EFFECT_ONLY']='1'
 if browser_cohort:env.update(**({'ANALYTICS_STANDALONE_DISCLOSURE_BROWSER':'1'} if args.standalone_disclosure_browser else {'ANALYTICS_MERCHANT_HISTORY_BROWSER':'1'}),ANALYTICS_BROWSER_EXECUTABLE=args.browser,ANALYTICS_BROWSER_SHA256=args.browser_sha256,ANALYTICS_BROWSER_BUILD=str(BUILD),ANALYTICS_BROWSER_EVIDENCE_ROOT=str(root))
 state['cohort']='standalone-analytics-disclosure-browser' if args.standalone_disclosure_browser else 'merchant-analytics-history-browser' if args.merchant_history_browser else 'zero-model-catalog-candidate' if args.catalog_only else 'zero-model-mounted' if args.mounted_only else 'zero-model-admission' if (args.admission_only or args.mounted_only) else 'zero-model-persona-effect' if args.effect_only else 'actual8b-fixed' if args.fixed_mode else 'actual8b';persist()
 with log.open('w') as output:
  selected=['--test-name-pattern=^standalone Analytics disclosure has a real Judge, exact saved GET and idempotent replay$'] if args.standalone_disclosure_browser else ['--test-name-pattern=^standalone merchant selects an older genuine Analytics result without another query$'] if args.merchant_history_browser else []
  child=subprocess.Popen([str(NODE),'--test','--test-reporter=tap',*selected,test],cwd=workspace,env=env,stdout=output,stderr=output,start_new_session=True);state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid)};state['runStatus']='running';persist()
  try:code=child.wait(timeout=180 if args.catalog_only else 300 if args.mounted_only else 240 if args.admission_only else 180 if args.effect_only else 900)
  except subprocess.TimeoutExpired:stop_child();raise RuntimeError('Actual Analytics parent deadline')
 if code:raise RuntimeError('Actual Analytics fixture failed; inspect retained evidence')
 observed=json.loads((root/'actual-evidence.json').read_text())
 if args.standalone_disclosure_browser:validate_standalone_disclosure_receipt(observed)
 state['runStatus']='observed';state['semanticComplete']=observed.get('semanticComplete') is True;state['qualification']='passed' if state['semanticComplete'] else 'incomplete';state['actualCalls']=len(observed.get('calls',[]));state['resultSha256']=digest(log);state['actualEvidenceSha256']=digest(root/'actual-evidence.json');persist()
 if browser_cohort:
  if any(digest(SOURCE/name)!=pin for name,pin in state['sourceSha256'].items()) or digest(NODE)!=args.node_sha256 or digest(Path(args.browser))!=args.browser_sha256 or tree_digest(BROWSER_ROOT,True)!=state['browserPackageSha256'] or tree_digest(BUILD)!=args.build_sha256 or tree_digest(SOURCE/'node_modules')!=state['dependencySha256']:raise RuntimeError('Qualification source/runtime changed')
  if state['semanticComplete'] is not True:raise RuntimeError('Standalone Analytics browser proof incomplete')
except BaseException as error:
 state['runStatus']='failed';state['errorType']=type(error).__name__;state['resultSha256']=digest(log);persist();raise
finally:
 gate.protect_cleanup();errors=[];absence={}
 try:stop_child()
 except Exception as error:errors.append('child:'+type(error).__name__)
 for name in attempted:
  try:
   if not absent(name):
    info=json.loads(run(docker+['inspect',name],stdout=subprocess.PIPE,text=True).stdout)[0]
    if info['Config']['Labels'].get('dvaia.test.owner')!=owner:raise RuntimeError('Refusing foreign container cleanup')
    if browser_cohort and (info['Id']!=container_ids.get(name) or info['Image']!=IMAGE):raise RuntimeError('Owned container identity changed')
    run(docker+['rm','-f','-v',name],stdout=subprocess.DEVNULL)
   absence[name]=absent(name)
  except Exception as error:errors.append(name+':'+type(error).__name__)
 try:pgidAbsent=not state['child'] or not members(state['child']['pgid'])
 except Exception as error:pgidAbsent=False;errors.append('pgid:'+type(error).__name__)
 state['cleanup']={'containersAbsent':absence,'childPgidAbsent':pgidAbsent,'errors':errors,'completedAt':datetime.now(timezone.utc).isoformat()}
 if errors or not pgidAbsent or not all(absence.values()):state['runStatus']='failed'
 persist()
print(json.dumps({'evidence':str(root),'status':state['runStatus'],'qualification':state.get('qualification'),'actualCalls':state.get('actualCalls'),'cleanup':state['cleanup']}),flush=True)
if state['runStatus']!='observed':raise SystemExit(1)
