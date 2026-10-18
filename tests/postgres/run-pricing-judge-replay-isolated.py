#!/usr/bin/env python3
"""One bounded Judge-only diagnostic; no Docker, database, actor or credit writes."""
import argparse,hashlib,json,os,signal,subprocess,tempfile,time
from pathlib import Path
from owned_diagnostic_process_cleanup import stop_directive_child

def run_directive_groups(args,source):
 """Closed model-only branch; full package admission precedes any HTTP."""
 from pricing_runtime_pins import validate
 from full_backend_auth_contract import validate_package
 from owned_dependency_overlay import prepare_owned_runtime_directories
 from mail_disclosure_cleanup_budget import CleanupBudget
 required=['node_binary','node_sha256','node_version','dependency_root','dependency_hashes','dependency_byte_sha256','embedding_cache','embedding_manifest_sha256','manifest','manifest_sha256']
 if any(getattr(args,k,None) is None for k in required):raise ValueError('Explicit reviewed runtime and package pins required')
 diagnostic=bool(getattr(args,"whole_evidence_diagnostic",False))
 work=CleanupBudget(1800)
 node,donor,cache=work.run(lambda:validate(args,source))
 if donor!=source or cache!=source/'tests/fixtures/fullBackendModelCache':raise ValueError('Canonical frozen package dependency/cache layout required')
 work.run(lambda:validate_package(source,args.manifest,args.manifest_sha256,node,args.node_sha256))
 root=Path(tempfile.mkdtemp(prefix='dvaia-pricing-directive-judge-')).resolve();root.chmod(0o700)
 workspace=root/'source';(root/'home').mkdir(mode=0o700)
 env={'PATH':str(node.parent)+':/usr/bin:/bin','HOME':str(root/'home'),'TMPDIR':str(root),'NODE_ENV':'test','AI_PROVIDER':'ollama','JUDGE_PROVIDER':'ollama','OLLAMA_MODEL':'llama3.1:8b','JUDGE_MODEL':'llama3.1:8b','OLLAMA_BASE_URL':'http://127.0.0.1:11434','JUDGE_BASE_URL':'http://127.0.0.1:11434','HF_HUB_OFFLINE':'1','TRANSFORMERS_OFFLINE':'1','AWS_EC2_METADATA_DISABLED':'true','LANGCHAIN_TRACING_V2':'false','LANGSMITH_TRACING':'false','PYTHONDONTWRITEBYTECODE':'1','PRICING_DIRECTIVE_GROUPS_ACTUAL':'1','PRICING_DIRECTIVE_GROUPS_RESULT':str(root/'result.json')}
 if diagnostic:env['WHOLE_EVIDENCE_DIAGNOSTIC']='1'
 state={'scope':'12 whole-evidence synthetic diagnostic packets; no acceptance claim' if diagnostic else 'Actual Judge only on14 controlled inputs; no actor/database/credit','status':'preparing','bounds':{'workSeconds':1800,'childSeconds':1740,'cleanupSeconds':120,'allHttp':73 if diagnostic else 84},'launcherPid':os.getpid(),'child':None};child=None
 def persist():
  temporary=root/'ownership.tmp';temporary.write_text(json.dumps(state,indent=2)+'\n');temporary.chmod(0o600);temporary.replace(root/'ownership.json')
 def run(command,**kw):return subprocess.run(command,env=env,check=True,timeout=min(kw.pop('timeout',120),work.remaining()),**kw)
 def members(budget):
  if child is None:return []
  rows=subprocess.run(['ps','-axo','pid=,pgid=,uid='],env=env,text=True,capture_output=True,check=True,timeout=min(5,budget.remaining())).stdout.splitlines();found=[]
  for row in rows:
   fields=row.split()
   if len(fields)==3 and int(fields[1])==child.pid:
    if int(fields[2])!=os.getuid():raise RuntimeError('Foreign process in owned group')
    found.append(int(fields[0]))
  return found
 def interrupted(*_):raise InterruptedError('Owned diagnostic interrupted')
 previous={s:signal.signal(s,interrupted) for s in (signal.SIGTERM,signal.SIGINT)}
 persist()
 try:
  run([str(node),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(source),str(workspace)],cwd=source)
  work.run(lambda:prepare_owned_runtime_directories(source,workspace,root))
  (workspace/'node_modules').symlink_to(donor/'node_modules',target_is_directory=True)
  state['sourceManifestSha256']=args.manifest_sha256;state['dependencyBytesSha256']=args.dependency_byte_sha256;persist()
  with (root/'run.log').open('x') as output:
   os.chmod(root/'run.log',0o600)
   child=subprocess.Popen([str(node),'tests/fixtures/ragPricingWholeEvidenceDiagnostic.js' if diagnostic else 'tests/fixtures/pricingDirectiveGroupsActualJudge.js'],cwd=workspace,env=env,stdout=output,stderr=output,start_new_session=True)
   state['child']={'pid':child.pid,'pgid':child.pid};state['status']='running';persist()
   state['exitCode']=child.wait(timeout=min(1740,work.remaining()))
  result=json.loads((root/'result.json').read_text());state['technicalComplete']=result.get('technicalComplete') is True;state['semanticAccepted']=result.get('semanticAccepted') is True;state['status']=result['status']
 except BaseException as error:state['status']='incomplete';state['errorType']=type(error).__name__
 finally:
  cleanup=CleanupBudget(120);errors=[];absent=False
  try:
   absent=stop_directive_child(child,members,cleanup)
  except Exception as error:errors.append(type(error).__name__)
  try:
   cleanup.run(lambda:validate_package(source,args.manifest,args.manifest_sha256,node,args.node_sha256))
   cleanup.run(lambda:validate(args,source));state['postInventoryVerified']=True
  except Exception as error:errors.append(type(error).__name__)
  for name in ('run.log','result.json'):
   if (root/name).exists():
    try:state[name+'Sha256']=cleanup.run(lambda:hashlib.sha256((root/name).read_bytes()).hexdigest())
    except Exception as error:errors.append(type(error).__name__)
  state['cleanup']={'processGroupAbsent':absent,'errors':errors}
  if errors:state['status']='cleanup-or-integrity-failed'
  persist()
  for s,handler in previous.items():signal.signal(s,handler)
 print(json.dumps({'evidence':str(root),'status':state['status'],'cleanup':state['cleanup']}))
 if state.get('status')!=('technical-complete-diagnostic' if diagnostic else 'semantic-accepted-controlled-inputs') or state.get('exitCode')!=0:raise SystemExit(1)

parser=argparse.ArgumentParser();modes=parser.add_mutually_exclusive_group();modes.add_argument('--synthetic-positive',action='store_true');modes.add_argument('--directive-groups',action='store_true');modes.add_argument('--whole-evidence-diagnostic',action='store_true')
for name in ['node-binary','node-sha256','node-version','dependency-root','dependency-hashes','dependency-byte-sha256','embedding-cache','embedding-manifest-sha256','manifest','manifest-sha256']:parser.add_argument('--'+name)
args=parser.parse_args()
SOURCE=Path(__file__).resolve().parents[2]
if args.directive_groups or args.whole_evidence_diagnostic:
 run_directive_groups(args,SOURCE)
 raise SystemExit(0)
NODE=Path('/Users/averma5/.dvaia/runtimes/node-v26.9.0-darwin-arm64/bin/node')
RETAINED=Path('/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/dvaia-pricing-journal-zhi_1b2b/pricing-actual-result.json')
EXPECTED='d3135bbdaddfe9429ceef9d164fdbdc30ad1657337a1fed452ca8b3924305fbc'
root=Path(tempfile.mkdtemp(prefix='dvaia-pricing-judge-replay-'));root.chmod(0o700);workspace=root/'source'
env={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':str(root/'home'),'TMPDIR':str(root),'NODE_ENV':'test','AI_PROVIDER':'ollama','OLLAMA_BASE_URL':'http://127.0.0.1:11434','OLLAMA_MODEL':'llama3.1:8b','HF_HUB_OFFLINE':'1','TRANSFORMERS_OFFLINE':'1','AWS_EC2_METADATA_DISABLED':'true','LANGCHAIN_TRACING_V2':'false','LANGSMITH_TRACING':'false'}
(root/'home').mkdir(mode=0o700)
if args.synthetic_positive:env['PRICING_JUDGE_REPLAY_RESPONSE']='synthetic-positive'
state={'status':'preparing','scope':'Judge-only diagnostic; no actor, database, Docker or historical writes','evidence':str(root),'maxCalls':6,'responseMode':'synthetic-positive' if args.synthetic_positive else 'retained-negative','cleanup':None};child=None
manifest=root/'ownership.json';log=root/'replay.log';log.touch(mode=0o600)
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save():manifest.write_text(json.dumps(state,indent=2)+'\n');manifest.chmod(0o600)
def deadline(*_):raise TimeoutError('Owned Judge replay deadline')
def interrupted(*_):raise KeyboardInterrupt('Owned Judge replay interrupted')
def members():
 if child is None:return []
 rows=subprocess.check_output(['ps','-axo','pid=,pgid=,uid='],text=True,timeout=5).splitlines();owned=[]
 for row in rows:
  fields=row.split()
  if len(fields)==3 and int(fields[1])==child.pid:
   if int(fields[2])!=os.getuid():raise RuntimeError('Foreign process in owned group')
   owned.append(int(fields[0]))
 return owned
signal.signal(signal.SIGALRM,deadline);signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted);signal.alarm(180);save()
try:
 assert subprocess.check_output([str(NODE),'--version'],env=env,text=True,timeout=5).strip()=='v26.9.0'
 assert digest(RETAINED)==EXPECTED
 subprocess.run([str(NODE),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(SOURCE),str(workspace)],cwd=SOURCE,env=env,check=True,timeout=30)
 (workspace/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
 (workspace/'retained-actual.json').write_bytes(RETAINED.read_bytes());(workspace/'retained-actual.json').chmod(0o600)
 files=['tests/fixtures/secureshopPricingManualJudgeReplay.js','tests/postgres/run-pricing-judge-replay-isolated.py','package.json','package-lock.json']
 for directory in ['server/services','server/agent-runtime','server/config','server/data','shared']:
  files.extend(str(p.relative_to(workspace)) for p in (workspace/directory).rglob('*') if p.is_file())
 state['sourceSha256']={f:digest(workspace/f) for f in sorted(set(files))};state['retainedSha256']=EXPECTED;state['nodeSha256']=digest(NODE);save()
 with log.open('w') as stream:
  child=subprocess.Popen([str(NODE),'tests/fixtures/secureshopPricingManualJudgeReplay.js'],cwd=workspace,env=env,stdout=stream,stderr=stream,start_new_session=True)
  state.update(status='running',childPid=child.pid,childPgid=child.pid);save();code=child.wait(timeout=155)
 state['exitCode']=code
 artifact=workspace/'judge-replay-result.json'
 if artifact.exists():
  (root/'judge-replay-result.json').write_bytes(artifact.read_bytes());(root/'judge-replay-result.json').chmod(0o600);state['artifactSha256']=digest(root/'judge-replay-result.json')
  result=json.loads(artifact.read_text());state['status']=result['status'];state['actualJudgeCalls']=len(result['calls']);state['verdict']=result.get('result',{}).get('verdict')
 assert all(digest(workspace/f)==h for f,h in state['sourceSha256'].items());state['frozenHashesVerified']=True
 if code:raise RuntimeError('Retained refusal replay failed; inspect owned artifact')
 save()
except BaseException as error:state['errorType']=type(error).__name__;state['status']='failed';save();raise
finally:
 signal.alarm(0);errors=[]
 try:
  if members():os.killpg(child.pid,signal.SIGTERM)
  end=time.monotonic()+5
  while members() and time.monotonic()<end:time.sleep(.05)
  if members():os.killpg(child.pid,signal.SIGKILL)
  if child is not None:child.wait(timeout=5)
  if members():raise RuntimeError('Owned group still exists')
 except Exception as error:errors.append(type(error).__name__)
 artifact=workspace/'judge-replay-result.json'
 if artifact.exists():
  (root/'judge-replay-result.json').write_bytes(artifact.read_bytes());(root/'judge-replay-result.json').chmod(0o600);state['artifactSha256']=digest(root/'judge-replay-result.json')
 state['cleanup']={'nodePgidAbsent':not members(),'errors':errors};state['logSha256']=digest(log);save()
 if errors:raise RuntimeError('Owned Judge replay cleanup failed')
print(json.dumps({'evidence':str(root),'status':state['status'],'calls':state.get('actualJudgeCalls'),'cleanup':state['cleanup']}))
