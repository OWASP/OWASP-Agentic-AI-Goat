#!/usr/bin/env python3
"""Bounded current-main Pricing Judge calibration; no actor, database, or credit."""
import argparse,hashlib,json,os,signal,stat,subprocess,tempfile,time
from pathlib import Path
from pricing_runtime_pins import validate as validate_runtime_pins
from mail_disclosure_cleanup_budget import CleanupBudget
from owned_diagnostic_process_cleanup import stop_directive_child

SOURCE=Path(__file__).resolve().parents[2]
PROFILES={
 'grounding':{'fixture':'tests/fixtures/pricingGroundingActualJudge.js','cases':'tests/fixtures/pricingGroundingSemanticCases.json','observed':'tests/fixtures/pricingGroundingObservedSource.json','cohort':'historical-strong-remaining-3-v1','mode':'remaining','environment':'PRICING_GROUNDING_ACTUAL_JUDGE','resultEnvironment':'PRICING_GROUNDING_RESULT','scope':'five fixed Judge-only cases','runScope':'Judge-only five fixed responses against a saved generated observation; no actor/database/credit','maxInference':10,'childSeconds':510,'overallSeconds':720,'verifier':'server/agent-runtime/pricingGroundingComparisonVerifier.js','verifierSha256':None},
 'manual':{'fixture':'tests/fixtures/pricingManualActualJudgeCalibration.js','cases':'tests/fixtures/pricingManualSemanticCalibrationCases.json','observed':None,'cohort':'historical-strong-manual-calibration-4-v1','mode':'manual-calibration','environment':'PRICING_MANUAL_CALIBRATION_ACTUAL_JUDGE','resultEnvironment':'PRICING_MANUAL_CALIBRATION_RESULT','scope':'four fixed manual Judge-only cases','runScope':'Judge-only four fixed manual semantic inputs; no actor/database/credit','maxInference':24,'childSeconds':720,'overallSeconds':930,'verifier':'server/agent-runtime/pricingSemanticDecompositionVerifier.js','verifierSha256':'d050e68e2758dd9a4ce82720f36a9d2a45bc5e1d72b657177c7a80a114e343cd'}
}
PROFILES['manual70b']={**PROFILES['manual'],'fixture':'tests/fixtures/pricingManualActualJudgeCalibration70b.js','cohort':'manual-calibration-70b-4-v1','mode':'manual-calibration-70b','model':'llama3.3:70b','verifierSha256':None}
PROFILES['manual70bv5']={**PROFILES['manual70b'],'fixture':'tests/fixtures/pricingManualActualJudgeCalibration70bV5.js','cohort':'manual-calibration-70b-v5-4-v1','mode':'manual-calibration-70b-v5','verifier':'server/agent-runtime/pricingSemanticDecompositionV5Verifier.js'}
PROFILES['manual70bv6']={**PROFILES['manual70b'],'fixture':'tests/fixtures/pricingManualActualJudgeCalibration70bV6.js','cohort':'manual-calibration-70b-v6-4-v1','mode':'manual-calibration-70b-v6','verifier':'server/agent-runtime/pricingSemanticDecompositionV6Verifier.js','maxInference':16}
SOURCE_FOLDERS=('server/agent-runtime','server/services','server/database/postgres','server/config','server/data','scripts/lib')
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def verify_source(manifest_path,expected_sha,profile):
 fixture=profile['fixture'];cases=profile['cases'];observed=profile['observed']
 path=Path(manifest_path)
 if not path.is_absolute() or path.resolve()!=path or path.is_symlink() or digest(path)!=expected_sha:raise RuntimeError('Pricing Judge manifest identity mismatch')
 value=json.loads(path.read_text())
 if set(value)!={'version','workspace','cohort','mode','sourcePins','dependencyInventory'} or value['version']!=1 or value['workspace']!=str(SOURCE) or value['cohort']!=profile['cohort'] or value['mode']!=profile['mode']:raise RuntimeError('Pricing Judge manifest scope mismatch')
 pins=value['sourcePins'];required={fixture,cases,'tests/fixtures/pricingDirectiveGroupsActualJudge.js','tests/postgres/run-pricing-grounding-judge-main.py','tests/postgres/pricing_runtime_pins.py','tests/postgres/mail_disclosure_cleanup_budget.py','tests/postgres/owned_diagnostic_process_cleanup.py',profile['verifier'],'server/agent-runtime/objectiveJudge.js','server/services/secureshopPricingAssessment.js'}
 if observed:required.add(observed)
 if profile in (PROFILES['manual70b'],PROFILES['manual70bv5'],PROFILES['manual70bv6']):required.add('tests/fixtures/pricingManualActualJudgeCalibration.js')
 if not required.issubset(pins):raise RuntimeError('Pricing Judge source closure missing')
 for folder in SOURCE_FOLDERS:
  base=SOURCE/folder
  if base.is_symlink() or not base.is_dir():raise RuntimeError('Pricing Judge source folder changed')
  found=set()
  for item in base.rglob('*'):
   if item.is_symlink():raise RuntimeError('Pricing Judge source link refused')
   if item.is_file():found.add(item.relative_to(SOURCE).as_posix())
   elif not item.is_dir():raise RuntimeError('Pricing Judge source entry invalid')
  if found!={name for name in pins if name.startswith(folder+'/')}:raise RuntimeError('Pricing Judge source folder inventory changed')
 if profile['verifierSha256'] and pins.get(profile['verifier'])!=profile['verifierSha256']:raise RuntimeError('Pricing Judge semantic verifier pin mismatch')
 for name,expected in pins.items():
  file=SOURCE/name;fd=os.open(file,os.O_RDONLY|os.O_NOFOLLOW)
  try:
   before=os.fstat(fd)
   if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1:raise RuntimeError('Pricing Judge source file invalid')
   h=hashlib.sha256()
   with os.fdopen(os.dup(fd),'rb') as stream:
    for chunk in iter(lambda:stream.read(1024*1024),b''):h.update(chunk)
   after=os.fstat(fd);named=file.lstat()
   if h.hexdigest()!=expected or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) or (named.st_dev,named.st_ino)!=(before.st_dev,before.st_ino):raise RuntimeError('Pricing Judge current source drift')
  finally:os.close(fd)
 return len(pins)

parser=argparse.ArgumentParser();parser.add_argument('--plan',action='store_true');mode=parser.add_mutually_exclusive_group();mode.add_argument('--manual-calibration',action='store_true');mode.add_argument('--manual-calibration-70b',action='store_true');mode.add_argument('--manual-calibration-70b-v5',action='store_true');mode.add_argument('--manual-calibration-70b-v6',action='store_true');parser.add_argument('--python-sha256',required=True)
for name in ('node-binary','node-sha256','node-version','dependency-root','dependency-hashes','dependency-byte-sha256','embedding-cache','embedding-manifest-sha256','manifest','manifest-sha256'):parser.add_argument('--'+name,required=True)
args=parser.parse_args()
PROFILE=PROFILES['manual70bv6' if args.manual_calibration_70b_v6 else 'manual70bv5' if args.manual_calibration_70b_v5 else 'manual70b' if args.manual_calibration_70b else 'manual' if args.manual_calibration else 'grounding'];NODE_FIXTURE=PROFILE['fixture'];MODEL=PROFILE.get('model','llama3.1:8b')
if digest(Path(os.path.realpath(__import__('sys').executable)))!=args.python_sha256:raise RuntimeError('Pricing Judge Python pin mismatch')
NODE,DEPENDENCIES,CACHE=validate_runtime_pins(args,SOURCE)
if DEPENDENCIES!=SOURCE or CACHE!=SOURCE/'tests/fixtures/fullBackendModelCache':raise RuntimeError('Pricing Judge current main runtime required')
count=verify_source(args.manifest,args.manifest_sha256,PROFILE)
if args.plan:
 print(json.dumps({'scope':PROFILE['scope'],'sourcePins':count,'maxInference':PROFILE['maxInference'],'ownedRuntime':False,'executed':False}));raise SystemExit(0)

root=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-pricing-'+('manual70bv6' if args.manual_calibration_70b_v6 else 'manual70bv5' if args.manual_calibration_70b_v5 else 'manual70b' if args.manual_calibration_70b else 'manual' if args.manual_calibration else 'grounding')+'-judge-')).resolve();root.chmod(0o700)
for name in ('home','tmp','output'):(root/name).mkdir(mode=0o700)
result=root/'output/result.json';log=root/'run.log';started=time.monotonic();state={'version':1,'status':'preparing','scope':PROFILE['runScope'],'sourceManifestSha256':args.manifest_sha256,'bounds':{'maxInference':PROFILE['maxInference'],'boundarySeconds':120,'childSeconds':PROFILE['childSeconds'],'cleanupSeconds':90,'maximumElapsedSeconds':PROFILE['overallSeconds']},'child':None,'cleanup':None};child=None
env={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':str(root/'home'),'TMPDIR':str(root/'tmp'),'NODE_ENV':'test','AI_PROVIDER':'ollama','JUDGE_PROVIDER':'ollama','OLLAMA_MODEL':MODEL,'JUDGE_MODEL':MODEL,'OLLAMA_BASE_URL':'http://127.0.0.1:11434','JUDGE_BASE_URL':'http://127.0.0.1:11434','HF_HUB_OFFLINE':'1','TRANSFORMERS_OFFLINE':'1','AWS_EC2_METADATA_DISABLED':'true','LANGCHAIN_TRACING_V2':'false','LANGSMITH_TRACING':'false',PROFILE['environment']:'1',PROFILE['resultEnvironment']:str(result)}
def save():
 temp=root/'ownership.tmp';temp.write_text(json.dumps(state,sort_keys=True,indent=2)+'\n');temp.chmod(0o600);temp.replace(root/'ownership.json')
def members(budget):
 if child is None:return []
 lines=subprocess.run(['ps','-axo','pid=,pgid=,uid='],env=env,capture_output=True,text=True,check=True,timeout=min(5,budget.remaining())).stdout.splitlines();found=[]
 for line in lines:
  parts=line.split()
  if len(parts)==3 and int(parts[1])==child.pid:
   if int(parts[2])!=os.getuid():raise RuntimeError('Foreign process in Pricing Judge group')
   found.append(int(parts[0]))
 return found
def available(reserve=0):
 left=PROFILE['overallSeconds']-(time.monotonic()-started)-reserve
 if left<=0:raise TimeoutError('Pricing Judge parent deadline')
 return left
def interrupted(*_):raise InterruptedError('Pricing Judge interrupted')
previous={name:signal.signal(name,interrupted) for name in (signal.SIGINT,signal.SIGTERM)};save()
try:
 boundary_source="const b=require('./scripts/lib/isolated-test-boundary');const [source,root,node,home,fixture]=process.argv.slice(1);const boundary=b.buildBoundary({source,directory:root,secrets:b.discoverSecrets(source,home),executable:node,args:[fixture]});process.stdout.write(JSON.stringify({command:boundary.command,args:boundary.args,cwd:boundary.cwd}));"
 bounded=json.loads(subprocess.run([str(NODE),'-e',boundary_source,str(SOURCE),str(root),str(NODE),os.environ['HOME'],NODE_FIXTURE],cwd=SOURCE,env=env,capture_output=True,text=True,check=True,timeout=min(120,available(90))).stdout)
 state['filesystemBoundary']='isolated-test-boundary';save()
 with log.open('x') as output:
  os.chmod(log,0o600);child=subprocess.Popen([bounded['command'],*bounded['args']],cwd=SOURCE,env=env,stdout=output,stderr=output,start_new_session=True)
  state['child']={'pid':child.pid,'pgid':child.pid};state['status']='running';save();state['exitCode']=child.wait(timeout=min(PROFILE['childSeconds'],available(90)))
 if result.exists():
  value=json.loads(result.read_text());state['resultSha256']=digest(result);state['technicalComplete']=value.get('technicalComplete') is True;state['semanticAccepted']=value.get('semanticAccepted') is True;state['status']=value.get('status')
 if state.get('exitCode')!=0 or state.get('status')!='semantic-accepted-controlled-inputs':raise RuntimeError('Pricing Judge calibration incomplete or semantic mismatch')
except BaseException as error:
 state['status']='failed';state['errorType']=type(error).__name__
finally:
 cleanup=CleanupBudget(min(90,max(1,PROFILE['overallSeconds']-(time.monotonic()-started))));errors=[]
 try:absent=stop_directive_child(child,members,cleanup)
 except Exception as error:errors.append('child:'+type(error).__name__);absent=False
 try:cleanup.run(lambda:verify_source(args.manifest,args.manifest_sha256,PROFILE));cleanup.run(lambda:validate_runtime_pins(args,SOURCE));state['postPinsVerified']=True
 except Exception as error:errors.append('source:'+type(error).__name__)
 if log.exists():state['logSha256']=digest(log)
 state['cleanup']={'processGroupAbsent':absent,'errors':errors};save()
 for name,handler in previous.items():signal.signal(name,handler)
print(json.dumps({'evidence':str(root),'status':state['status'],'cleanup':state['cleanup']}))
if state['status']!='semantic-accepted-controlled-inputs' or state['cleanup']['errors']:raise SystemExit(1)
