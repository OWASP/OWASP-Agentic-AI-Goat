#!/usr/bin/env python3
"""Run model-free Excessive Agency full-App parity in owned disposable stores."""
import argparse, hashlib, importlib.util, json, os, signal, subprocess, tempfile, time, uuid, sys, stat
from datetime import datetime, timezone
from pathlib import Path
from sensitive_info_recovery_safety import SignalGate

EXPECTED_DAEMON='2c9da9a7-1f8c-490b-af98-87bbf6bf83db'
EXPECTED_DOCKER='unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
NODE=Path('/Users/averma5/.dvaia/runtimes/node-v26.9.0-darwin-arm64/bin/node')
DOCKER=Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')
IMAGE='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
SOURCE=Path(__file__).resolve().parents[2]
COHORT='ea-nine-content-main'
def profile_contract(profile):
 if profile=='nine-content':return {'cohort':COHORT,'workSeconds':780,'databasePrefix':'dvaia_test_ea_parity','child':'tests/postgres/excessiveAgencyFullAppParity.integration.test.js'}
 if profile=='route-session-controlled':return {'cohort':'ea-route-session-controlled-main','workSeconds':180,'databasePrefix':'dvaia_test_ea_route','child':'tests/postgres/excessiveAgencyRoute.integration.test.js'}
 if profile=='route-actual-remaining-four':return {'cohort':'ea-route-actual-remaining-four-main','workSeconds':960,'databasePrefix':'dvaia_test_ea_route','child':'tests/postgres/excessiveAgencyRoute.integration.test.js'}
 if profile=='route-actual-objective-four':return {'cohort':'ea-route-actual-objective-four-main','workSeconds':960,'databasePrefix':'dvaia_test_ea_route','child':'tests/postgres/excessiveAgencyRoute.integration.test.js'}
 if profile=='route-actual-objective-seven-8b':return {'cohort':'ea-route-actual-objective-seven-8b-main','workSeconds':960,'databasePrefix':'dvaia_test_ea_route','child':'tests/postgres/excessiveAgencyRoute.integration.test.js'}
 if profile=='route-actual-objective-seven-70b':return {'cohort':'ea-route-actual-objective-seven-70b-main','workSeconds':960,'databasePrefix':'dvaia_test_ea_route','child':'tests/postgres/excessiveAgencyRoute.integration.test.js'}
 if profile=='route-actual-eight':return {'cohort':'ea-route-actual-eight-main','workSeconds':960,'databasePrefix':'dvaia_test_ea_route','child':'tests/postgres/excessiveAgencyRoute.integration.test.js'}
 raise RuntimeError('Closed EA profile required')
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def browser_admission():
 path=SOURCE/'tests/postgres/run-finflow-backup-browser-main.py'
 spec=importlib.util.spec_from_file_location('ea_existing_browser_admission',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def missing_first_party_modules(source,pins,inventory_for):
 missing=[]
 for relative in ('server','db/postgres','scripts/lib'):
  for name,metadata in inventory_for(source/relative).items():
   suffix=Path(name).suffix
   if metadata.get('directory') or suffix not in ('.js','.cjs','.mjs','.json'):continue
   # Lesson data and private synthetic secrets under server/ are not import closure.
   if relative=='server' and suffix=='.json' and not name.startswith(('agent-runtime/','config/','database/postgres/','routes/','services/')):continue
   path=f'{relative}/{name}'
   if path not in pins:missing.append(path)
 return sorted(missing)

def validate_main(args):
 if Path(args.main_workspace)!=SOURCE or SOURCE.resolve()!=SOURCE:raise RuntimeError('Exact main workspace required')
 path=Path(args.manifest);st=path.lstat()
 if not path.is_absolute() or path.resolve()!=path or not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_nlink!=1 or st.st_mode&0o077:raise RuntimeError('Private canonical manifest required')
 if digest(path)!=args.manifest_sha256:raise RuntimeError('Manifest digest mismatch')
 m=json.loads(path.read_text())
 if args.docker_daemon!=EXPECTED_DAEMON or m.get('dockerAuthority')!={'host':EXPECTED_DOCKER,'daemonId':EXPECTED_DAEMON} or m.get('imageId')!=IMAGE:raise RuntimeError('Docker authority mismatch')
 if digest(SOURCE/'.env')!=m.get('mainEnvSha256'):raise RuntimeError('Private configuration changed')
 contract=profile_contract(getattr(args,'profile','nine-content'))
 if m.get('cohort')!=contract['cohort'] or m.get('workspace')!=str(SOURCE) or m.get('mode')!=('actual' if getattr(args,'profile','nine-content') in ('route-actual-eight','route-actual-remaining-four','route-actual-objective-four','route-actual-objective-seven-8b','route-actual-objective-seven-70b') else 'controlled'):raise RuntimeError('Closed main cohort required')
 required={'tests/postgres/run-ea-full-app-parity-isolated.py','tests/postgres/ea_full_app_parity_launcher_test.py','tests/postgres/excessiveAgencyFullAppParity.integration.test.js','tests/fixtures/excessiveAgencyFullAppParity.js','tests/fixtures/legacyFileSsiFullAppParity.js','tests/fixtures/secureshopAnalyticsBrowserOwner.js','tests/fixtures/browserProcessOwnership.js','tests/postgres/run-finflow-backup-browser-main.py','tests/postgres/sql_nosql_docker_ownership.py','tests/release-inputs/record-current-frontend-build.py','package.json','package-lock.json','client/package.json','client/package-lock.json','client/vite.config.mjs','client/index.html'}
 for directory in ('db/postgres/identity-migrations','db/postgres/workshop-migrations/excessive_agency'):required.update(p.relative_to(SOURCE).as_posix() for p in (SOURCE/directory).glob('*.sql'))
 required.add(contract['child'])
 if getattr(args,'profile','nine-content') in ('route-actual-eight','route-actual-remaining-four','route-actual-objective-four','route-actual-objective-seven-8b','route-actual-objective-seven-70b'):
  validate_actual_manifest(m,args.profile)
  required.update({'tests/postgres/finflowBackupBrowserActualTransport.js','tests/fixtures/excessiveAgencyActualWirePolicy.js'})
 pins=m.get('sourcePins',{})
 if not required.issubset(pins):raise RuntimeError('Required main source pins missing')
 missing=missing_first_party_modules(SOURCE,pins,browser_admission().inventory)
 if missing:raise RuntimeError('Unpinned first-party module: '+missing[0])
 for rel,pin in pins.items():
  p=SOURCE/rel
  if Path(rel).is_absolute() or '..' in Path(rel).parts or p.is_symlink() or not p.resolve().is_relative_to(SOURCE) or digest(p)!=pin:raise RuntimeError('Main source mismatch')
 for value,pin in ((args.node,args.node_sha256),(args.docker,args.docker_sha256),(args.browser,args.browser_sha256)):
  p=Path(value)
  if not p.is_absolute() or p.resolve()!=p or digest(p)!=pin:raise RuntimeError('Canonical runtime mismatch')
 helper=browser_admission();helper.validate_running_python(args.python_sha256)
 for rel,key in (('node_modules','dependencyInventory'),('client/build','clientBuildInventory')):
  if not m.get(key) or helper.inventory(SOURCE/rel)!=m[key]:raise RuntimeError('Frozen inventory mismatch')
 browser=Path(args.browser);browser_root=Path(args.browser_root)
 if not browser_root.is_absolute() or browser_root.resolve()!=browser_root or not browser.is_relative_to(browser_root) or m.get('browserRoot')!=str(browser_root) or m.get('browserExecutable')!=str(browser):raise RuntimeError('Browser binding mismatch')
 if not m.get('browserInventory') or helper.inventory(browser_root)!=m['browserInventory']:raise RuntimeError('Browser inventory mismatch')
 helper.validate_build_provenance(SOURCE,m)
 return m

def validate_receipt(value):
 if not isinstance(value,dict) or value.get('profile')!='ea-nine-content':raise RuntimeError('EA main receipt required')
 for key in ('actualModelProof',):
  if value.get(key)is not False:raise RuntimeError('Controlled provenance required')
 for key,want in (('modelCalls',0),('genuineCredit',0),('controlledProjectionCount',9),('completed',9),('total',9)):
  if type(value.get(key))is not int or value[key]!=want:raise RuntimeError('Controlled counts mismatch')
 if value.get('completionScope')!='Controlled completion projections only; no earned credit':raise RuntimeError('Controlled scope mismatch')
 for key in ('canonicalAuth','threeStudentViews','dbDerivedTotalsAndTime','objectiveHideRestore','independentHintSolutionControls','deniedStudentAdmin','siblingIsolation','adminStudentProjection','configurationRestored','projectionRestored','immutableEvidencePreserved','browserRetired'):
  if value.get(key)is not True:raise RuntimeError('Required parity check missing')
 cases=value.get('cases')
 if not isinstance(cases,list) or len(cases)!=9:raise RuntimeError('Nine exact cases required')
 for index,case in enumerate(cases,1):
  if not isinstance(case,dict) or case.get('id')!='objective_'+str(index) or any(case.get(key)is not True for key in ('label','hint','solution','adminPreview','completedProjection')):raise RuntimeError('Case projection mismatch')
 requests=value.get('requests',{})
 for key,low,high in (('browser',1,1000),('api',0,40)):
  if type(requests.get(key))is not int or not low<=requests[key]<=high:raise RuntimeError('Request bound mismatch')
 cleanup=value.get('cleanup')
 if not isinstance(cleanup,list) or [x.get('name') for x in cleanup]!=['restore','server','parity','auth','shared-pools','pools'] or any(x.get('status')!='fulfilled' for x in cleanup):raise RuntimeError('Owned cleanup incomplete')
 return True

def validate_route_receipt(value):
 if not isinstance(value,dict) or value.get('profile')!='ea-route-session-controlled-main' or value.get('status')!='passed' or value.get('actualModelProof')is not False:raise RuntimeError('Controlled route receipt required')
 for key,want in (('modelCalls',0),('genuineCredit',0),('controlledProjectionCount',9),('controlledSessionOwners',2)):
  if type(value.get(key))is not int or value[key]!=want:raise RuntimeError('Controlled route count mismatch')
 if value.get('controlledObjectiveIds')!=['objective_'+str(i) for i in range(1,10)]:raise RuntimeError('Exact controlled objectives required')
 for key in ('originalNineQualified','ownerReset','siblingPreserved','preEffectSessionDenied','postGradePublicationDenied','priorCommitsPreserved','postGradeControlledCommit'):
  if value.get(key)is not True:raise RuntimeError('Route lifecycle proof missing')
 cleanup=value.get('cleanup')
 if not isinstance(cleanup,list) or [x.get('name') for x in cleanup]!=['server','pools','shared-pools'] or any(x.get('status')!='fulfilled' for x in cleanup):raise RuntimeError('Route cleanup incomplete')
 return True

ACTUAL_MODEL='llama3.1:8b'
ACTUAL_DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'
ACTUAL_70B_MODEL='llama3.3:70b'
ACTUAL_70B_DIGEST='a6eb4748fd2990ad2952b2335a95a7f952d1a06119a0aa6a2df6cd052a93a3fa'
ACTUAL_BUDGET={'actor':32,'judge':16,'chat':48,'generate':0,'tags':97,'version':0,'metadata':97,'external':145}
ACTUAL_INPUT_SHA256='b35aefdd5538c428d7da027b28753c96bd62b7bcd78a3b9736c80c2306a57704'
ACTUAL_IDS=['objective_'+str(i) for i in range(1,9)]
def actual_contract(profile='route-actual-eight'):
 if profile=='route-actual-objective-seven-8b':return ['objective_7'],{'actor':4,'judge':2,'chat':6,'generate':0,'tags':13,'version':0,'metadata':13,'external':19},'b28bcb5ecde45db68f1a78160e984034ce631e87a37b25daa3f2c0c84a132d69','ea-route-actual-objective-seven-8b'
 if profile=='route-actual-objective-seven-70b':return ['objective_7'],{'actor':4,'judge':2,'chat':6,'generate':0,'tags':13,'version':0,'metadata':13,'external':19},'4c685f719baeb5c03d771acede69b60fcef94d15ded528a77ec12c2b6d95210a','ea-route-actual-objective-seven-70b'
 if profile=='route-actual-objective-four':return ['objective_4'],{'actor':4,'judge':2,'chat':6,'generate':0,'tags':13,'version':0,'metadata':13,'external':19},'7534edf0645d66e1631aba2dcacb39e02adf05c05616b93a6a029d17935f9173','ea-route-actual-objective-four'
 if profile=='route-actual-eight':return ACTUAL_IDS,ACTUAL_BUDGET,ACTUAL_INPUT_SHA256,'ea-route-actual-eight'
 if profile=='route-actual-remaining-four':return ['objective_'+str(i) for i in range(5,9)],{'actor':16,'judge':8,'chat':24,'generate':0,'tags':49,'version':0,'metadata':49,'external':73},'515c19f38d5dafe8561c2963af8d68233eee5e272c2b9c443dcd06dfdcea0cc6','ea-route-actual-remaining-four'
 raise RuntimeError('Closed actual subset required')
def validate_actual_manifest(value,profile='route-actual-eight'):
 ids,budget,input_sha,_=actual_contract(profile)
 expected={'model':ACTUAL_70B_MODEL if profile=='route-actual-objective-seven-70b' else ACTUAL_MODEL,'modelDigest':ACTUAL_70B_DIGEST if profile=='route-actual-objective-seven-70b' else ACTUAL_DIGEST,'inputSha256':input_sha,'caseIds':ids,'wireBudget':budget}
 if any(value.get(k)!=v for k,v in expected.items()) or any(type(x)is not int for x in value.get('wireBudget',{}).values()):raise RuntimeError('Frozen actual identity/input/budget required')
 return True

def validate_actual_wire(value,receipt,profile='route-actual-eight'):
 ids,budget,_,wire_profile=actual_contract(profile)
 model,digest=(ACTUAL_70B_MODEL,ACTUAL_70B_DIGEST) if profile=='route-actual-objective-seven-70b' else (ACTUAL_MODEL,ACTUAL_DIGEST)
 if value.get('version')!=wire_profile+'-wire-v1' or value.get('model')!=model or value.get('digest')!=digest or value.get('closed')is not True or type(value.get('physicalPending'))is not int or value['physicalPending']!=0 or value.get('failures')!=[]:raise RuntimeError('Actual wire retirement incomplete')
 counts=value.get('counts',{})
 if any(type(counts.get(k))is not int or not 0<=counts[k]<=cap for k,cap in budget.items() if k not in ('actor','judge')):raise RuntimeError('Actual wire budget mismatch')
 calls=value.get('calls',[])
 if not isinstance(calls,list) or len(calls)!=counts['external'] or counts['metadata']!=counts['tags'] or counts['external']!=counts['chat']+counts['tags']:raise RuntimeError('Actual wire accounting mismatch')
 role_counts={role:sum(c.get('kind')=='chat' and c.get('role')==role for c in calls) for role in ('actor','judge')}
 if sum(role_counts.values())!=counts['chat'] or any(role_counts[role]>budget[role] for role in role_counts):raise RuntimeError('Actual role counts mismatch')
 if not calls or calls[0].get('kind')!='tags' or calls[0].get('caseId')is not None:raise RuntimeError('Startup identity observation missing')
 if any(sum(c.get('kind')==kind for c in calls)!=counts[kind] for kind in ('chat','tags','generate','version')):raise RuntimeError('Actual wire kind mismatch')
 phases=[]
 for index,call in enumerate(calls):
  if type(call.get('index'))is not int or call['index']!=index or call.get('terminal')!='returned':raise RuntimeError('Actual wire terminal mismatch')
  case=call.get('caseId')
  if index==0:continue
  if case not in ids:raise RuntimeError('Unknown actual wire case')
  if not phases or phases[-1]!=case:phases.append(case)
  if call.get('kind')=='chat' and call.get('role')not in ('actor','judge'):raise RuntimeError('Actual role missing')
 if phases!=ids:raise RuntimeError('Actual wire case order mismatch')
 for row in receipt['cases']:
  for role,key in (('actor','actorCalls'),('judge','judgeCalls')):
   if sum(c.get('kind')=='chat' and c.get('caseId')==row['id'] and c.get('role')==role for c in calls)!=row[key]:raise RuntimeError('Actual role/receipt mismatch')
 return True

def validate_actual_receipt(value,profile='route-actual-eight'):
 ids,_,_,wire_profile=actual_contract(profile)
 if not isinstance(value,dict) or value.get('profile')!=wire_profile+'-main' or value.get('status')!='passed' or value.get('actualModelProof')is not True:raise RuntimeError('Actual eight technical receipt required')
 cases=value.get('cases')
 if not isinstance(cases,list) or [r.get('id') for r in cases]!=ids:raise RuntimeError('Exact eight actual cases required')
 for row in cases:
  i=int(row['id'].split('_')[1])
  if row.get('mode')!=('fixed' if i<=4 else 'vuln') or row.get('outcome')not in ('awarded','not_awarded','inconclusive','wrong_task'):raise RuntimeError('Actual case scope mismatch')
  for key,low,high in (('httpStatus',100,599),('actorCalls',1,4),('judgeCalls',0,2)):
   if type(row.get(key))is not int or not low<=row[key]<=high:raise RuntimeError('Actual case count mismatch')
  if row.get('packetStatus')not in ('present','absent_verified') or (row['judgeCalls']>0 and row['packetStatus']!='present'):raise RuntimeError('Actual packet presence mismatch')
  if row.get('wireBound')is not True or row.get('packetBound')is not True:raise RuntimeError('Actual case binding missing')
  unexpected=row.get('unexpectedObjectiveAwards')
  if not isinstance(unexpected,list) or len(set(unexpected))!=len(unexpected) or any(x not in ['objective_'+str(n) for n in range(1,10)] or x==row['id'] for x in unexpected):raise RuntimeError('Unexpected awards scope invalid')
  if (unexpected and row['outcome']!='wrong_task') or (row['outcome']=='wrong_task' and not unexpected):raise RuntimeError('Wrong task disposition mismatch')
  if row['outcome']=='awarded' and (row['judgeCalls']<1 or row['httpStatus']!=200):raise RuntimeError('Award without Judge/HTTP success')
 if type(value.get('genuineCredit'))is not int or value['genuineCredit']!=sum(r['outcome']=='awarded' for r in cases):raise RuntimeError('Actual credit count mismatch')
 count=value['genuineCredit']
 if type(value.get('qualifiedCount'))is not int or value['qualifiedCount']!=count or value.get('qualification')!=('qualified' if count==len(ids) else 'partial' if count else 'unqualified'):raise RuntimeError('Semantic qualification summary mismatch')
 if any(value.get(k)is not True for k in ('ownerReset','siblingPreserved')):raise RuntimeError('Actual lifecycle incomplete')
 if profile=='route-actual-objective-seven-8b':
  row=cases[0]
  if row.get('outcome')!='awarded' or row.get('firstEffectExact')is not True or row.get('effectCount')!=1 or row.get('repeatedEffectCount')!=0:raise RuntimeError('Objective seven current-8B exact first effect required')
  if value.get('genuineCredit')!=1 or value.get('qualifiedCount')!=1 or value.get('qualification')!='qualified' or value.get('immutableEvidencePreserved')is not True:raise RuntimeError('Objective seven current-8B qualification/lifecycle incomplete')
 cleanup=value.get('cleanup')
 if not isinstance(cleanup,list) or [r.get('name') for r in cleanup]!=['server','transport','pools','shared-pools'] or any(r.get('status')!='fulfilled' for r in cleanup):raise RuntimeError('Actual cleanup incomplete')
 return True

def remaining_timeout(deadline,seconds):
 if deadline is None:return seconds
 left=deadline-time.monotonic()
 if left<=0:raise RuntimeError('Owned physical cleanup deadline exhausted')
 return min(seconds,left)

def main(argv=None):
 parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True)
 for key in ('main-workspace','manifest','manifest-sha256','node','node-sha256','docker','docker-sha256','python-sha256','browser','browser-root','browser-sha256','docker-daemon'):parser.add_argument('--'+key)
 parser.add_argument('--profile',choices=['nine-content','route-session-controlled','route-actual-eight','route-actual-remaining-four','route-actual-objective-four','route-actual-objective-seven-8b','route-actual-objective-seven-70b'],default='nine-content')
 parser.add_argument('--plan',action='store_true');args=parser.parse_args(argv)
 contract=profile_contract(args.profile)
 if args.profile!='nine-content' and not args.main_workspace:raise RuntimeError('Route profile requires admitted main workspace')
 if args.docker_host!=EXPECTED_DOCKER:raise RuntimeError('Reviewed Docker host required')
 manifest=validate_main(args) if args.main_workspace else None
 if not manifest and any(getattr(args,k.replace('-','_')) for k in ('manifest','manifest-sha256','node','node-sha256','docker','docker-sha256','python-sha256','browser','browser-root','browser-sha256')):raise RuntimeError('Main admission arguments require main workspace')
 node=Path(args.node) if manifest else NODE;docker_binary=Path(args.docker) if manifest else DOCKER
 if args.plan:
  if not manifest:raise RuntimeError('Plan requires main admission')
  print(json.dumps({'status':'planned','cohort':contract['cohort'],'stores':['identity','excessive_agency'],'allocation':False,'workSeconds':contract['workSeconds'],'cleanupSeconds':120}));return 0
 evidence_parent=SOURCE/'backups/private-recovery/ea-full-app-parity'
 if manifest:
  evidence_parent.mkdir(parents=True,exist_ok=True,mode=0o700)
  if evidence_parent.resolve()!=evidence_parent:raise RuntimeError('Canonical evidence parent required')
 root=Path(tempfile.mkdtemp(prefix='run-' if manifest else 'dvaia-ea-parity-',dir=evidence_parent if manifest else None));os.chmod(root,0o700);workspace=SOURCE if manifest else root/'source'
 container='dvaia-ea-parity-'+uuid.uuid4().hex[:12];owner=uuid.uuid4().hex
 docker=[str(docker_binary),'--host',args.docker_host]
 env={'PATH':str(node.parent)+':/usr/bin:/bin','HOME':os.environ['HOME'],'TMPDIR':str(root)}
 state={'container':container,'owner':owner,'image':IMAGE,'evidence':str(root),'launcherPid':os.getpid(),
  'nodeVersion':None,'containerCreationAttempted':False,'child':None,'runStatus':'preparing','cleanup':None,
  'createdAt':datetime.now(timezone.utc).isoformat()}
 work_deadline=time.monotonic()+contract['workSeconds'] if manifest else None
 ownership=root/'ownership.json';log_path=root/'tests.log';log_path.touch(mode=0o600)
 def persist():ownership.write_text(json.dumps(state,indent=2)+'\n');os.chmod(ownership,0o600)
 def remaining():
  left=work_deadline-time.monotonic()
  if left<=0:raise RuntimeError('EA main work deadline exhausted')
  return left
 def run(command,**kwargs):
  kwargs.setdefault('timeout',120)
  if manifest:kwargs['timeout']=min(kwargs['timeout'],remaining())
  return subprocess.run(command,check=True,env=kwargs.pop('env',env),**kwargs)
 def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
 cleanup_deadline=None
 def bounded_timeout(seconds):
  return remaining_timeout(cleanup_deadline,seconds)
 def exact_absence():
  query=subprocess.run(docker+['ps','-a','--filter',f'name=^/{container}$','--format','{{.Names}}'],env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=bounded_timeout(30))
  if query.returncode:raise RuntimeError('exact-name container query failed')
  return not query.stdout.strip()
 child=None;creation_attempted=False;gate=SignalGate();signal.signal(signal.SIGTERM,gate.handler);signal.signal(signal.SIGINT,gate.handler);persist()
 def owned_group_members(pgid):
  listing=subprocess.run(['ps','-axo','pid=,pgid=,uid='],env=env,stdout=subprocess.PIPE,text=True,check=True,timeout=bounded_timeout(5)).stdout
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
  try:child.wait(timeout=bounded_timeout(5))
  except subprocess.TimeoutExpired:pass
  if owned_group_members(pgid):raise RuntimeError('owned Node/browser process group cleanup incomplete')
 try:
  version=run([str(node),'--version'],stdout=subprocess.PIPE,text=True).stdout.strip()
  if version!=('v26.10.0' if manifest else 'v26.9.0'):raise RuntimeError('Managed Node version mismatch')
  state['nodeVersion']=version;persist()
  if manifest:
   import sql_nosql_docker_ownership as owned_docker
   def docker_command(arguments):return subprocess.run(docker+arguments,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=bounded_timeout(30))
   owned_docker.verify_daemon(docker_command,args.docker_daemon);owned_docker.verify_image(docker_command,IMAGE)
  if not exact_absence():raise RuntimeError('owned container name unexpectedly exists')
  if not manifest:
   run([str(node),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(SOURCE),str(workspace)],cwd=SOURCE)
   (workspace/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
   (workspace/'client/node_modules').symlink_to(SOURCE/'client/node_modules',target_is_directory=True)
  inventory=['tests/fixtures/excessiveAgencyFullAppParity.js','tests/postgres/excessiveAgencyFullAppParity.integration.test.js',
   'tests/postgres/run-ea-full-app-parity-isolated.py','tests/fixtures/legacyFileSsiFullAppParity.js',
   'client/src/pages/challenges/ExcessiveAgencyBolaLab.js','client/src/pages/WorkshopChallenges.js',
   'client/src/pages/ComprehensiveAdminDashboard.js','server/routes/excessiveAgencyLab.js',
   'server/routes/postgresWorkshop.js','server/routes/adminExercises.js','server/routes/solutions.js','server/routes/hints.js']
  state['sourceSha256']=manifest['sourcePins'] if manifest else {name:digest(workspace/name) for name in inventory};persist()
  creation_attempted=True;state['containerCreationAttempted']=True;persist()
  run(docker+['run','--detach','--pull','never','--name',container,'--label','dvaia.test.owner='+owner,
   '--tmpfs','/var/lib/postgresql:rw,size=268435456','-e','POSTGRES_HOST_AUTH_METHOD=trust',
   '-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',IMAGE,'-c','shared_buffers=16MB','-c','max_connections=40',
   '-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL)
  details=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]
  if manifest:details=owned_docker.inspect_owned(docker_command,name=container,labels={'dvaia.test.owner':owner},image=IMAGE)
  state['containerId']=details['Id'];persist()
  if details.get('Mounts') or details['Config']['Labels'].get('dvaia.test.owner')!=owner:raise RuntimeError('owned PostgreSQL isolation/ownership check failed')
  if details.get('HostConfig',{}).get('Tmpfs')!={'/var/lib/postgresql':'rw,size=268435456'}:raise RuntimeError('Owned PostgreSQL tmpfs isolation check failed')
  for _ in range(100):
   ready=subprocess.run(docker+['exec',container,'pg_isready','-h','127.0.0.1','-U','postgres'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
   if ready.returncode==0:break
   time.sleep(.25)
  else:raise RuntimeError('owned PostgreSQL unavailable')
  port=int(run(docker+['port',container,'5432/tcp'],stdout=subprocess.PIPE,text=True).stdout.strip().rsplit(':',1)[1])
  psql=docker+['exec',container,'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-c']
  roles=['dvaia_identity_migration','dvaia_identity_runtime','dvaia_excessive_agency_migration','dvaia_excessive_agency_runtime']
  run(psql+[';'.join(f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS' for role in roles)+';'],stdout=subprocess.DEVNULL)
  for family,database in [('identity',contract['databasePrefix']+'_identity'),('excessive_agency',contract['databasePrefix']+'_lab')]:
   migration=f'dvaia_{family}_migration';runtime=f'dvaia_{family}_runtime'
   run(psql+[f'CREATE DATABASE {database} OWNER {migration}'],stdout=subprocess.DEVNULL)
   run(psql+[f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime}'],stdout=subprocess.DEVNULL)
   prefix='IDENTITY' if family=='identity' else 'EXCESSIVE_AGENCY'
   env[f'{prefix}_MIGRATION_DATABASE_URL']=f'postgresql://{migration}@127.0.0.1:{port}/{database}'
   env[f'{prefix}_DATABASE_URL']=f'postgresql://{runtime}@127.0.0.1:{port}/{database}'
  env.update(NODE_ENV='test',PG_TEST_DISPOSABLE='yes',EA_FULL_APP_PARITY='1',EA_ROUTE_LIVE='0',DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace),
   EA_PARITY_EVIDENCE_PATH=str(root/'service-evidence.json'),PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',
   AI_PROVIDER='mock',JUDGE_PROVIDER='mock',JWT_SECRET=uuid.uuid4().hex+uuid.uuid4().hex,SESSION_SECRET=uuid.uuid4().hex+uuid.uuid4().hex,
   AWS_EC2_METADATA_DISABLED='true',MCP_WORKSHOP_AUTOSTART='false',MCP_SIDECARS_AUTOSTART='false',SS_ENABLE='false',HF_HUB_OFFLINE='1',
   OLLAMA_BASE_URL='http://127.0.0.1:1',SANDBOX_RUNNER_URL='http://127.0.0.1:1',SSRF_TARGET_URL='http://127.0.0.1:1',
   ROGUE_MCP_URL='http://127.0.0.1:1',MAILPIT_API_URL='http://127.0.0.1:1',MAILPIT_SMTP_HOST='127.0.0.1',MAILPIT_SMTP_PORT='1')
  if manifest:
   env.update(EA_PARITY_MAIN='1',EA_PARITY_RUNTIME_ROOT=str(root),EA_PARITY_MANIFEST=str(Path(args.manifest).resolve()),EA_PARITY_MANIFEST_SHA256=args.manifest_sha256,ANALYTICS_BROWSER_EXECUTABLE=args.browser,ANALYTICS_BROWSER_SHA256=args.browser_sha256)
  if args.profile in ('route-session-controlled','route-actual-eight','route-actual-remaining-four','route-actual-objective-four','route-actual-objective-seven-8b','route-actual-objective-seven-70b'):
   env.update(EA_FULL_APP_PARITY='0',EA_ROUTE_ISOLATED='1',EA_ROUTE_LIVE='0',EA_ROUTE_UI='0',EA_ROUTE_OBJECTIVE='',EA_ROUTE_EVIDENCE_PATH=str(root/'service-evidence.json'))
  if args.profile in ('route-actual-eight','route-actual-remaining-four','route-actual-objective-four','route-actual-objective-seven-8b','route-actual-objective-seven-70b'):
   env.update(EA_ROUTE_ACTUAL_OBJECTIVE_FOUR='1' if args.profile=='route-actual-objective-four' else '0',EA_ROUTE_ACTUAL_OBJECTIVE_SEVEN_8B='1' if args.profile=='route-actual-objective-seven-8b' else '0',EA_ROUTE_ACTUAL_OBJECTIVE_SEVEN_70B='1' if args.profile=='route-actual-objective-seven-70b' else '0',EA_ROUTE_ACTUAL_EIGHT='1' if args.profile=='route-actual-eight' else '0',EA_ROUTE_ACTUAL_REMAINING_FOUR='1' if args.profile=='route-actual-remaining-four' else '0',EA_ROUTE_LIVE='1',AI_PROVIDER='ollama',JUDGE_PROVIDER='ollama')
  with log_path.open('w') as log:
   child=subprocess.Popen([str(node),'--test','--test-reporter=tap',contract['child']],cwd=workspace,env=env,stdout=log,stderr=log,start_new_session=True)
   state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid)};state['runStatus']='test_running';persist()
   try:code=child.wait(timeout=remaining() if manifest else 300)
   except subprocess.TimeoutExpired:stop_child();raise RuntimeError('EA parity timed out')
  if code:raise RuntimeError(f'EA parity failed ({code}); inspect retained tests.log')
  if manifest:
   (lambda value: validate_actual_receipt(value,args.profile) if args.profile in ('route-actual-eight','route-actual-remaining-four','route-actual-objective-four','route-actual-objective-seven-8b','route-actual-objective-seven-70b') else validate_route_receipt(value) if args.profile=='route-session-controlled' else validate_receipt(value))(json.loads((root/'service-evidence.json').read_text()));state['sourceUnchanged']=True
  if args.profile in ('route-actual-eight','route-actual-remaining-four','route-actual-objective-four','route-actual-objective-seven-8b','route-actual-objective-seven-70b'):
   validate_actual_wire(json.loads((root/'actual-model-wire.json').read_text()),json.loads((root/'service-evidence.json').read_text()),args.profile);state['actualModelWireSha256']=digest(root/'actual-model-wire.json')
  state['runStatus']='passed';state['resultSha256']=digest(log_path);state['serviceEvidenceSha256']=digest(root/'service-evidence.json');persist()
 except BaseException as error:
  if creation_attempted:
   try:
    diagnostic=subprocess.run(docker+['logs','--tail','120',container],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20)
    (root/'container.log').write_text(diagnostic.stdout);os.chmod(root/'container.log',0o600)
   except Exception as diagnostic_error:state['containerDiagnosticError']=type(diagnostic_error).__name__
  state.update({'runStatus':'failed','errorType':type(error).__name__,'resultSha256':digest(log_path)});persist();raise
 finally:
  gate.protect_cleanup();cleanup_deadline=time.monotonic()+120 if manifest else None;errors=[];remove_code=None;absent=None
  try:stop_child()
  except Exception as error:errors.append('child:'+type(error).__name__)
  if creation_attempted:
   try:
    if manifest:
     state['containerCleanup']=owned_docker.cleanup_owned(docker_command,daemon_id=args.docker_daemon,name=container,labels={'dvaia.test.owner':owner},image=IMAGE,captured_id=state.get('containerId'));remove_code=0
     identifier=state.get('containerId')
     if identifier:
      check=docker_command(['inspect','--type','container',identifier])
      if check.returncode==0 or not any(check.stderr.strip()==x for x in (f'Error: No such object: {identifier}',f'Error: No such container: {identifier}',f'Error response from daemon: No such container: {identifier}')):raise RuntimeError('Exact container ID absence unavailable')
    else:remove_code=subprocess.run(docker+['rm','-f','-v',container],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30).returncode
   except Exception as error:errors.append('remove:'+type(error).__name__)
  try:absent=exact_absence()
  except Exception as error:errors.append('absence:'+type(error).__name__)
  try:pgid_absent=not state.get('child') or not owned_group_members(state['child']['pgid'])
  except Exception as error:errors.append('pgid:'+type(error).__name__);pgid_absent=False
  physical_cleanup_completed=time.monotonic();state['physicalCleanupWithinBudget']=cleanup_deadline is None or physical_cleanup_completed<=cleanup_deadline
  if manifest:
   try:validate_main(args);state['sourceUnchanged']=True
   except Exception as error:state['sourceUnchanged']=False;errors.append('integrity:'+type(error).__name__)
  state['postCleanupIntegritySeconds']=round(time.monotonic()-physical_cleanup_completed,3)
  state['cleanup']={'removeExitCode':remove_code,'containerAbsent':absent,'nodeBrowserPgidAbsent':pgid_absent,
   'errors':errors,'completedAt':datetime.now(timezone.utc).isoformat()}
  if state['runStatus']=='passed' and (errors or state['physicalCleanupWithinBudget']is not True or absent is not True or pgid_absent is not True or (creation_attempted and remove_code!=0)):state['runStatus']='failed';state['errorType']='CleanupFailed'
  persist()
 print(json.dumps({'evidence':str(root),'status':state['runStatus'],'cleanup':state['cleanup']}),flush=True)
 return 0 if state['runStatus']=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
