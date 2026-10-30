#!/usr/bin/env python3
"""One bounded Judge-only diagnostic; no Docker, database, actor or credit writes."""
import argparse,hashlib,json,os,signal,subprocess,tempfile,time
from pathlib import Path
def stop_directive_child(child,members,cleanup):
 if members(cleanup):
  try:os.killpg(child.pid,signal.SIGTERM)
  except ProcessLookupError:pass
 end=time.monotonic()+min(5,cleanup.remaining())
 while members(cleanup) and time.monotonic()<end:
  child.poll();time.sleep(min(.05,cleanup.remaining()))
 if members(cleanup):
  try:os.killpg(child.pid,signal.SIGKILL)
  except ProcessLookupError:pass
 if child is not None:child.wait(timeout=min(5,cleanup.remaining()))
 end=time.monotonic()+min(5,cleanup.remaining())
 while members(cleanup) and time.monotonic()<end:time.sleep(min(.05,cleanup.remaining()))
 absent=not members(cleanup)
 if not absent:raise RuntimeError('Owned process group remains')
 return absent

def run_directive_groups(args,source):
 """Closed model-only branch; full package admission precedes any HTTP."""
 from pricing_runtime_pins import validate
 from full_backend_auth_contract import validate_package
 from owned_dependency_overlay import prepare_owned_runtime_directories
 from mail_disclosure_cleanup_budget import CleanupBudget
 required=['node_binary','node_sha256','node_version','dependency_root','dependency_hashes','dependency_byte_sha256','embedding_cache','embedding_manifest_sha256','manifest','manifest_sha256']
 if any(getattr(args,k,None) is None for k in required):raise ValueError('Explicit reviewed runtime and package pins required')
 work=CleanupBudget(3120)
 node,donor,cache=work.run(lambda:validate(args,source))
 if donor!=source or cache!=source/'tests/fixtures/fullBackendModelCache':raise ValueError('Canonical frozen package dependency/cache layout required')
 work.run(lambda:validate_package(source,args.manifest,args.manifest_sha256,node,args.node_sha256))
 root=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-rag-directive-judge-')).resolve();root.chmod(0o700)
 workspace=root/'source';(root/'home').mkdir(mode=0o700)
 env={'PATH':str(node.parent)+':/usr/bin:/bin','HOME':str(root/'home'),'TMPDIR':str(root),'NODE_ENV':'test','AI_PROVIDER':'ollama','JUDGE_PROVIDER':'ollama','OLLAMA_MODEL':'llama3.1:8b','JUDGE_MODEL':'llama3.1:8b','OLLAMA_BASE_URL':'http://127.0.0.1:11434','JUDGE_BASE_URL':'http://127.0.0.1:11434','HF_HUB_OFFLINE':'1','TRANSFORMERS_OFFLINE':'1','AWS_EC2_METADATA_DISABLED':'true','LANGCHAIN_TRACING_V2':'false','LANGSMITH_TRACING':'false','PYTHONDONTWRITEBYTECODE':'1','RAG_DIRECTIVE_GROUPS_ACTUAL':'1','RAG_DIRECTIVE_GROUPS_RESULT':str(root/'result.json')}
 state={'scope':'Actual Judge only on24 controlled inputs; no actor/database/credit','status':'preparing','bounds':{'workSeconds':3120,'childSeconds':3000,'cleanupSeconds':120,'allHttp':144},'launcherPid':os.getpid(),'child':None};child=None
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
   child=subprocess.Popen([str(node),'tests/fixtures/ragDirectiveGroupsActualJudge.js'],cwd=workspace,env=env,stdout=output,stderr=output,start_new_session=True)
   state['child']={'pid':child.pid,'pgid':child.pid};state['status']='running';persist()
   state['exitCode']=child.wait(timeout=min(3000,work.remaining()))
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
 if state.get('status')!='technical-complete-semantic-review-required' or state.get('exitCode')!=0:raise SystemExit(1)

parser=argparse.ArgumentParser();parser.add_argument('--rag-directive-groups',action='store_true',required=True)
for name in ['node-binary','node-sha256','node-version','dependency-root','dependency-hashes','dependency-byte-sha256','embedding-cache','embedding-manifest-sha256','manifest','manifest-sha256']:parser.add_argument('--'+name)
args=parser.parse_args()
run_directive_groups(args,Path(__file__).resolve().parents[2])
