#!/usr/bin/env python3
"""Run the bounded current RAG canonical-warning actor/Judge graph qualification."""
import argparse, hashlib, json, os, signal, subprocess, tempfile, time
from datetime import datetime, timezone
from pathlib import Path

NODE=Path('/Users/averma5/.owasp-ai-goat/runtimes/node-v26.9.0-darwin-arm64/bin/node')
SOURCE=Path(__file__).resolve().parents[1]
test_name='tests/ragCanonicalWarningActual8b.test.js'
root=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-rag-warning-'));os.chmod(root,0o700);workspace=root/'source'
env={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':os.environ['HOME'],'TMPDIR':str(root)}
state={'version':1,'mode':'canonical_warning_boundary','scope':'Actual actor/Judge graph boundary; controlled retrieval/completion callbacks; no database/application/startup mutation','evidence':str(root),'launcherPid':os.getpid(),'child':None,'runStatus':'preparing','createdAt':datetime.now(timezone.utc).isoformat(),'cleanup':None}
ownership=root/'ownership.json';log_path=root/'tests.log';log_path.touch(mode=0o600)
def persist():ownership.write_text(json.dumps(state,indent=2)+'\n');os.chmod(ownership,0o600)
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def run(command,**kwargs):kwargs.setdefault('timeout',120);return subprocess.run(command,check=True,env=kwargs.pop('env',env),**kwargs)
def members(pgid):
 output=subprocess.run(['ps','-axo','pid=,pgid=,uid='],env=env,stdout=subprocess.PIPE,text=True,check=True,timeout=5).stdout;found=[]
 for line in output.splitlines():
  fields=line.split()
  if len(fields)==3 and int(fields[1])==pgid:
   if int(fields[2])!=os.getuid():raise RuntimeError('foreign process in owned group')
   found.append(int(fields[0]))
 return found
child=None
def interrupted(signum,_frame):raise KeyboardInterrupt(f'signal {signum}')
signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
def stop():
 if child is None or not state.get('child'):return
 pgid=state['child']['pgid']
 if members(pgid):os.killpg(pgid,signal.SIGTERM)
 deadline=time.monotonic()+5
 while members(pgid) and time.monotonic()<deadline:
  child.poll();time.sleep(.05)
 if members(pgid):os.killpg(pgid,signal.SIGKILL)
 try:child.wait(timeout=5)
 except subprocess.TimeoutExpired:pass
 if members(pgid):raise RuntimeError('owned process group cleanup incomplete')
persist()
try:
 version=run([str(NODE),'--version'],stdout=subprocess.PIPE,text=True).stdout.strip()
 if version!='v26.9.0':raise RuntimeError('managed Node v26.9.0 required')
 state['nodeVersion']=version;persist()
 run([str(NODE),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(SOURCE),str(workspace)],cwd=SOURCE)
 (workspace/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
 inventory=[test_name,'tests/run-rag-warning-actual8b-isolated.py','server/routes/ragInjection.js','package.json','package-lock.json']
 for folder in ['server/agent-runtime','server/services','server/utils']:
  inventory.extend(str(item.relative_to(workspace)) for item in sorted((workspace/folder).rglob('*')) if item.is_file())
 state['sourceSha256']={name:digest(workspace/name) for name in inventory};persist()
 run([str(NODE),'--check',test_name],cwd=workspace)
 env.update(NODE_ENV='test',AI_PROVIDER='ollama',JUDGE_PROVIDER='ollama',OLLAMA_MODEL='llama3.1:8b',JUDGE_MODEL='llama3.1:8b',OLLAMA_BASE_URL='http://127.0.0.1:11434',JUDGE_BASE_URL='http://127.0.0.1:11434',AWS_EC2_METADATA_DISABLED='true')
 env.update(RAG_CANONICAL_WARNING_ACTUAL8B='1',RAG_CANONICAL_WARNING_EVIDENCE_PATH=str(root/'judge-evidence.json'))
 with log_path.open('w') as log:
  child=subprocess.Popen([str(NODE),'--test','--test-reporter=tap',test_name],cwd=workspace,env=env,stdout=log,stderr=log,start_new_session=True)
  state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid)};state['runStatus']='running';persist()
  try:code=child.wait(timeout=900)
  except subprocess.TimeoutExpired:stop();raise RuntimeError('Judge-only replay timed out')
 if code:raise RuntimeError(f'Judge-only replay failed ({code}); inspect retained private evidence')
 state.update(runStatus='passed',logSha256=digest(log_path),evidenceSha256=digest(root/'judge-evidence.json'));persist()
except BaseException as error:
 state.update(runStatus='failed',errorType=type(error).__name__,logSha256=digest(log_path));persist();raise
finally:
 errors=[]
 try:stop()
 except Exception as error:errors.append(type(error).__name__)
 absent=not state.get('child') or not members(state['child']['pgid'])
 state['cleanup']={'processGroupAbsent':absent,'errors':errors,'completedAt':datetime.now(timezone.utc).isoformat()}
 if state['runStatus']=='passed' and (not absent or errors):state['runStatus']='failed';state['errorType']='CleanupFailed'
 persist()
print(json.dumps({'evidence':str(root),'status':state['runStatus'],'cleanup':state['cleanup']}),flush=True)
if state['runStatus']!='passed':raise SystemExit(1)
