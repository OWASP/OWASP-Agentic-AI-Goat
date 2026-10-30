#!/usr/bin/env python3
"""One bounded Judge-only diagnostic; no Docker, database, actor or credit writes."""
import argparse,hashlib,json,os,signal,subprocess,tempfile,time
from pathlib import Path
from owned_diagnostic_process_cleanup import stop_directive_child

def run_elementary(args,source):
 """Closed model-only branch; full package admission precedes any HTTP."""
 from pricing_runtime_pins import validate
 from full_backend_auth_contract import validate_package
 from owned_dependency_overlay import prepare_owned_runtime_directories
 from mail_disclosure_cleanup_budget import CleanupBudget
 required=['node_binary','node_sha256','node_version','dependency_root','dependency_hashes','dependency_byte_sha256','embedding_cache','embedding_manifest_sha256','manifest','manifest_sha256']
 if any(getattr(args,k,None) is None for k in required):raise ValueError('Explicit reviewed runtime and package pins required')
 diagnostic=True
 extraction=bool(getattr(args,"source_extraction_18",False))
 source_only=bool(getattr(args,"source_meaning_18",False)) or extraction
 work_seconds,child_seconds=(1200,1140) if source_only else (4560,4500)
 work=CleanupBudget(work_seconds)
 node,donor,cache=work.run(lambda:validate(args,source))
 if donor!=source or cache!=source/'tests/fixtures/fullBackendModelCache':raise ValueError('Canonical frozen package dependency/cache layout required')
 work.run(lambda:validate_package(source,args.manifest,args.manifest_sha256,node,args.node_sha256))
 expected={'tasks/objective-predicate-v2-elementary-corrected-inputs-2026-09-27.json':'a98fd4d13d88c7675a3e8f99854402c236c05c55661a1c91f5a670edd9aa501d','tasks/objective-predicate-v2-elementary-independent-labels-2026-09-27.json':'bafc6cdbadc5a06593f2ee0299e3a2eaaeaab43b1efca5e4f2a494cfa716170f','tasks/objective-predicate-v2-elementary-corrected-seal-2026-09-27.json':'bdb7979093ccf336321345261d4c2ce5bc5c8ff35f83e3808ab12996c1bd29e2','tasks/objective-predicate-v2-p35-replacement-label-review-2026-09-27.json':'78a8cebeef3c1e39e4b4d12ab4d0c777e43d2ec112d2ba38b97605a157700d84'}
 if source_only:expected={'tasks/source-meaning18-inputs-2026-09-27.json':'d2d5cca3d2644fed175df802e5ab784c2bf7c5cfb4569adb2c1d5877426b63d2','tasks/source-meaning18-independent-labels-2026-09-27.json':'473d391c4b1601d24333ee6c76287c7f740ae96e2204d4b460378a8f345507cb'}
 if extraction:expected={'tasks/source-extraction18-inputs-2026-09-27.json':'fee5792544c18382e05cda6d5d5499830075452194fb494a322c7e96a9d9508e'}
 for name,pin in expected.items():
  if hashlib.sha256((source/name).read_bytes()).hexdigest()!=pin:raise ValueError('Sealed elementary artifact mismatch')
 root=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-elementary-judge-')).resolve();root.chmod(0o700)
 workspace=root/'source';(root/'home').mkdir(mode=0o700)
 env={'PATH':str(node.parent)+':/usr/bin:/bin','HOME':str(root/'home'),'TMPDIR':str(root),'NODE_ENV':'test','AI_PROVIDER':'ollama','JUDGE_PROVIDER':'ollama','OLLAMA_MODEL':'llama3.1:8b','JUDGE_MODEL':'llama3.1:8b','OLLAMA_BASE_URL':'http://127.0.0.1:11434','JUDGE_BASE_URL':'http://127.0.0.1:11434','HF_HUB_OFFLINE':'1','TRANSFORMERS_OFFLINE':'1','AWS_EC2_METADATA_DISABLED':'true','LANGCHAIN_TRACING_V2':'false','LANGSMITH_TRACING':'false','PYTHONDONTWRITEBYTECODE':'1','OBJECTIVE_ELEMENTARY_ACTUAL':'1','OBJECTIVE_ELEMENTARY_RESULT':str(root/'result.json')}

 if source_only:
  env.pop('OBJECTIVE_ELEMENTARY_ACTUAL');env.pop('OBJECTIVE_ELEMENTARY_RESULT')
  env.update({'SOURCE_MEANING_ACTUAL':'1','SOURCE_MEANING_RESULT':str(root/'result.json')})
 if extraction:
  env.pop('SOURCE_MEANING_ACTUAL');env.pop('SOURCE_MEANING_RESULT')
  env.update({'SOURCE_EXTRACTION_ACTUAL':'1','SOURCE_EXTRACTION_RESULT':str(root/'result.json')})
 state={'scope':'72 elementary synthetic facets; no actor/effect/credit or production acceptance','status':'preparing','bounds':{'workSeconds':work_seconds,'childSeconds':child_seconds,'cleanupSeconds':120,'allHttp':19 if source_only else 73},'launcherPid':os.getpid(),'child':None};child=None
 if source_only:state['scope']='18 source-only synthetic classifications; no credit or generalization claim'
 if extraction:state['scope']='18 source-only extractions; mechanical validation only, semantic review pending'
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
   child=subprocess.Popen([str(node),'tests/fixtures/sourceExtractionActual18.js' if extraction else 'tests/fixtures/sourceMeaningActual18.js' if source_only else 'tests/fixtures/objectiveElementaryActual72.js'],cwd=workspace,env=env,stdout=output,stderr=output,start_new_session=True)
   state['child']={'pid':child.pid,'pgid':child.pid};state['status']='running';persist()
   state['exitCode']=child.wait(timeout=min(child_seconds,work.remaining()))
  if source_only:
   # Prediction child is fully exited before a distinct scorer can open labels.
   with (root/'scoring.log').open('x') as output:
    scorer=subprocess.run([str(node),'tests/fixtures/sourceExtractionMechanicalScoring.js' if extraction else 'tests/fixtures/sourceMeaningScoring.js',str(root/'result.json'),str(root/'scoring.json')],cwd=workspace,env=env,stdout=output,stderr=output,timeout=min(30,work.remaining()))
   state['scoringExitCode']=scorer.returncode
  result=json.loads((root/'result.json').read_text());state['technicalComplete']=result.get('technicalComplete') is True;state['semanticAccepted']=result.get('semanticAccepted') is True;state['status']=result['status']
  if source_only:
   scored=json.loads((root/'scoring.json').read_text());state['semanticAccepted']=scored.get('semanticAccepted') is True
   state['status']='semantic-accepted-elementary-diagnostic' if state['technicalComplete'] and state['semanticAccepted'] and state['scoringExitCode']==0 else 'semantic-mismatch'
   if extraction:
    state['semanticAccepted']=None;state['mechanicalComplete']=scored.get('mechanicalComplete') is True
    state['status']='mechanical-complete-semantic-review-pending' if state['technicalComplete'] and state['mechanicalComplete'] and state['scoringExitCode']==0 else 'mechanical-invalid'
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
  for name in ('run.log','result.json','scoring.json'):
   if (root/name).exists():
    try:state[name+'Sha256']=cleanup.run(lambda:hashlib.sha256((root/name).read_bytes()).hexdigest())
    except Exception as error:errors.append(type(error).__name__)
  state['cleanup']={'processGroupAbsent':absent,'errors':errors}
  if errors:state['status']='cleanup-or-integrity-failed'
  persist()
  for s,handler in previous.items():signal.signal(s,handler)
 print(json.dumps({'evidence':str(root),'status':state['status'],'cleanup':state['cleanup']}))
 if state.get('status')!=('mechanical-complete-semantic-review-pending' if extraction else 'semantic-accepted-elementary-diagnostic') or state.get('exitCode')!=0:raise SystemExit(1)

def semantic_digest(source):
 parts=[]
 for name in ['factoredJudgePrimitives.js','factoredJudgeSemanticContracts.js','factoredJudgeDiagnostic.js']:
  with (source/'tests/fixtures'/name).open('rb') as stream:raw=stream.read(65537)
  assert len(raw)<=65536
  parts.append(name+'\0'+hashlib.sha256(raw).hexdigest()+'\n')
 return hashlib.sha256(''.join(parts).encode()).hexdigest()

def validate_factored_gate(gate,pin,rhash,ahash,semantic):
 assert set(gate)=={'version','phase','inputSha256','resultSha256','auditSha256','modelDigest','protocol','semanticSha256','decision','reviewType'}
 assert type(gate['version']) is int and gate['version']==1
 assert gate['modelDigest']=='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'
 assert gate['protocol']=='factored-semantic-diagnostic.v1'
 assert gate['semanticSha256']==semantic
 for key in ['inputSha256','resultSha256','auditSha256']:
  assert isinstance(gate[key],str) and len(gate[key])==64 and all(c in '0123456789abcdef' for c in gate[key])
 assert gate['phase']=='simple6' and gate['decision']=='go' and gate['reviewType']=='independent-agent-provisional'
 assert gate['inputSha256']==pin and gate['resultSha256']==rhash and gate['auditSha256']==ahash

def factored_selection(args,source):
 phase=args.factored_phase
 if phase not in ('simple6','remaining18'):raise ValueError('Closed factored phase required')
 from full_backend_auth_contract import validate_manifest
 relative=Path(args.factored_input or '')
 if relative.is_absolute() or '..' in relative.parts or not str(relative).startswith('tasks/'):raise ValueError('Manifest-bound input required')
 pin=args.factored_input_sha256
 if not pin or len(pin)!=64 or any(c not in '0123456789abcdef' for c in pin):raise ValueError('Input pin required')
 manifest=json.loads(Path(args.manifest).read_text());validate_manifest(manifest)
 if manifest['files'].get(str(relative))!=pin or hashlib.sha256((source/relative).read_bytes()).hexdigest()!=pin:raise ValueError('Input binding mismatch')
 gate_keys=('factored_gate','factored_gate_sha256','factored_prior_result','factored_prior_audit')
 if phase=='simple6':
  if any(getattr(args,k,None) for k in gate_keys):raise ValueError('Phase1 cannot supply gate')
  return dict(work=2400,child=2280,http=37,input=str(source/relative),gate={})
 if not all(getattr(args,k,None) for k in gate_keys):raise ValueError('Phase2 requires external completed review gate')
 def pinned(file,pin=None):
  p=Path(file);assert p.is_absolute() and p.is_file() and not p.is_symlink()
  with p.open('rb') as stream:raw=stream.read(256*1024*1024+1)
  assert len(raw)<=256*1024*1024
  digest=hashlib.sha256(raw).hexdigest()
  if pin:assert digest==pin
  return json.loads(raw),digest
 gate,_=pinned(args.factored_gate,args.factored_gate_sha256);prior,rhash=pinned(args.factored_prior_result);audit,ahash=pinned(args.factored_prior_audit)
 validate_factored_gate(gate,pin,rhash,ahash,semantic_digest(source))
 assert prior['semanticSha256']==audit['semanticSha256']==semantic_digest(source)
 assert prior['phase']==audit['phase']=='simple6' and prior['inputSha256']==audit['inputSha256']==pin
 assert prior['technicalComplete'] is True and audit['mechanicalComplete'] is True and audit['semanticAccepted'] is None
 assert prior['creditAuthorized'] is False and audit['creditAuthorized'] is False
 return dict(work=6720,child=6600,http=109,input=str(source/relative),gate={'FACTORED_GATE':args.factored_gate,'FACTORED_GATE_SHA256':args.factored_gate_sha256,'FACTORED_PRIOR_RESULT_SHA256':rhash,'FACTORED_PRIOR_AUDIT_SHA256':ahash})

def factored_members(child,lines):
 found=[]
 for line in lines:
  parts=line.split()
  if len(parts)!=3 or not all(x.isdigit() for x in parts):raise RuntimeError('Unknown process roster')
  pid,pgid,uid=map(int,parts)
  if pgid==child.pid:
   if uid!=os.getuid() or os.getsid(pid)!=child.pid:raise RuntimeError('Foreign or unproven group session')
   found.append(pid)
 return found

def run_factored(args,source):
 from pricing_runtime_pins import validate
 from full_backend_auth_contract import validate_package
 from owned_dependency_overlay import prepare_owned_runtime_directories
 from mail_disclosure_cleanup_budget import CleanupBudget
 from sql_nosql_process_ownership import OwnedProcesses
 # All profile/gate checks and frozen admission precede owned copy or HTTP.
 spec=factored_selection(args,source);work=CleanupBudget(spec['work'])
 node,donor,cache=work.run(lambda:validate(args,source))
 if donor!=source or cache!=source/'tests/fixtures/fullBackendModelCache':raise ValueError('Canonical frozen layout required')
 work.run(lambda:validate_package(source,args.manifest,args.manifest_sha256,node,args.node_sha256))
 root=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-factored-judge-')).resolve();root.chmod(0o700);workspace=root/'source';(root/'home').mkdir(mode=0o700)
 env={'PATH':str(node.parent)+':/usr/bin:/bin','HOME':str(root/'home'),'TMPDIR':str(root),'NODE_ENV':'test','FACTORED_ACTUAL':'1','FACTORED_PHASE':args.factored_phase,'FACTORED_INPUT':spec['input'],'FACTORED_INPUT_SHA256':args.factored_input_sha256,'FACTORED_RESULT':str(root/'result.json'),**spec['gate']}
 state={'status':'preparing','phase':args.factored_phase,'semanticAccepted':None,'creditAuthorized':False,'bounds':spec|{'input':None,'gate':None},'children':[]};budget=work
 def persist():
  p=root/'ownership.tmp';p.write_text(json.dumps(state)+'\n');p.chmod(0o600);p.replace(root/'ownership.json')
 def record(value):state['children'].append(value);persist()
 def members(child,b):
  lines=subprocess.run(['/bin/ps','-axo','pid=,pgid=,uid='],capture_output=True,text=True,check=True,timeout=min(3,b.remaining())).stdout.splitlines();found=[]
  return factored_members(child,lines)
 def stop(child,pgid,sid):
  assert child.pid==pgid==sid
  if not budget.run(lambda:stop_directive_child(child,lambda b:members(child,b),budget)):raise RuntimeError('Owned group absence unavailable')
 owned=OwnedProcesses(stop,record);owned.install();persist()
 def child_run(command,name,seconds,cwd):
  with (root/(name+'.log')).open('x') as log:
   os.chmod(log.name,0o600);c=owned.launch(command,name=name,cwd=cwd,env=env,stdout=log,stderr=log,start_new_session=True);code=c.wait(timeout=min(seconds,work.remaining()));owned.finish(c);return code
 try:
  assert child_run([str(node),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(source),str(workspace)],'copy',120,source)==0
  work.run(lambda:prepare_owned_runtime_directories(source,workspace,root));(workspace/'node_modules').symlink_to(donor/'node_modules',target_is_directory=True)
  state['exitCode']=child_run([str(node),'tests/fixtures/factoredJudgeActual24.js'],'predict',spec['child'],workspace)
  state['auditExitCode']=child_run([str(node),'tests/fixtures/factoredJudgeActual24Audit.js',str(root/'result.json'),spec['input'],args.factored_input_sha256,str(root/'audit.json')],'audit',60,workspace)
  result=json.loads((root/'result.json').read_text());audit=json.loads((root/'audit.json').read_text());state['status']='phase-complete-review-pending' if state['exitCode']==state['auditExitCode']==0 and result['technicalComplete'] is True and audit['mechanicalComplete'] is True else 'phase-incomplete'
 except BaseException as error:state['status']='phase-incomplete';state['failure']=type(error).__name__
 finally:
  errors=[];budget=CleanupBudget(120);owned.mask_cleanup_signals()
  try:budget.run(owned.cleanup)
  except BaseException as error:errors.append('physical:'+type(error).__name__)
  integrity=CleanupBudget(120)
  try:integrity.run(lambda:validate_package(source,args.manifest,args.manifest_sha256,node,args.node_sha256));integrity.run(lambda:validate(args,source));state['postInventoryVerified']=True
  except BaseException as error:errors.append('integrity:'+type(error).__name__)
  state['cleanup']={'ownedGroupsAbsent':not owned.children,'errors':errors}
  if errors:state['status']='cleanup-or-integrity-failed'
  persist();owned.restore()
 print(json.dumps({'evidence':str(root),'status':state['status']}))
 if state['status']!='phase-complete-review-pending':raise SystemExit(1)

REQUIRED = ['node-binary','node-sha256','node-version','dependency-root','dependency-hashes','dependency-byte-sha256','embedding-cache','embedding-manifest-sha256','manifest','manifest-sha256']
def arguments(argv=None):
 parser=argparse.ArgumentParser()
 modes=parser.add_mutually_exclusive_group(required=True)
 modes.add_argument('--elementary-72',action='store_true')
 modes.add_argument('--source-meaning-18',action='store_true')
 modes.add_argument('--source-extraction-18',action='store_true')
 modes.add_argument('--factored-phase',choices=['simple6','remaining18'])
 for name in ['factored-input','factored-input-sha256','factored-gate','factored-gate-sha256','factored-prior-result','factored-prior-audit']:parser.add_argument('--'+name)
 for name in REQUIRED:parser.add_argument('--'+name,required=True)
 return parser.parse_args(argv)
def main():
 args=arguments()
 if args.factored_phase:run_factored(args,Path(__file__).resolve().parents[2])
 else:
  if any(getattr(args,k) for k in ['factored_input','factored_input_sha256','factored_gate','factored_gate_sha256','factored_prior_result','factored_prior_audit']):raise ValueError('Factored-only arguments')
  run_elementary(args,Path(__file__).resolve().parents[2])
if __name__=='__main__':main()
