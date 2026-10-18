#!/usr/bin/env python3
"""Run the bounded IPI same-question Judge-only actual8B replay."""
import argparse, hashlib, json, os, signal, subprocess, tempfile, time
from datetime import datetime, timezone
from pathlib import Path

NODE=Path('/Users/averma5/.dvaia/runtimes/node-v26.9.0-darwin-arm64/bin/node')
SOURCE=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser();modes=parser.add_mutually_exclusive_group();modes.add_argument('--calibration',action='store_true');modes.add_argument('--semantic-calibration',action='store_true');args=parser.parse_args()
test_name='tests/ipiSemanticJudgeCalibrationActual8b.test.js' if args.semantic_calibration else 'tests/ipiSameQuestionJudgeCalibrationActual8b.test.js' if args.calibration else 'tests/ipiSameQuestionJudgeActual8b.test.js'
root=Path(tempfile.mkdtemp(prefix='dvaia-ipi-judge-replay-'));os.chmod(root,0o700);workspace=root/'source'
env={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':os.environ['HOME'],'TMPDIR':str(root)}
state={'version':1,'mode':'semantic_calibration' if args.semantic_calibration else 'calibration' if args.calibration else 'frozen_replay','scope':'Judge-only actual8B replay; no database/application/startup mutation','evidence':str(root),'launcherPid':os.getpid(),'child':None,'runStatus':'preparing','createdAt':datetime.now(timezone.utc).isoformat(),'cleanup':None}
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
 while members(pgid) and time.monotonic()<deadline:time.sleep(.05)
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
 inventory=['tests/ipiSemanticJudgeCalibrationActual8b.test.js','tests/fixtures/ipiSemanticJudgeCalibration.json','tests/ipiSameQuestionJudgeActual8b.test.js','tests/ipiSameQuestionJudgeCalibrationActual8b.test.js','tests/fixtures/ipiSameQuestionFalsePositiveActual8b.json','tests/fixtures/ipiSameQuestionJudgeCalibration.json','tests/run-ipi-same-question-judge-actual8b-isolated.py','server/agent-runtime/objectiveJudge.js','server/agent-runtime/indirectObjectiveJudge.js','server/agent-runtime/sourceComparisonVerifier.js','server/agent-runtime/providers/langchainProvider.js']
 state['sourceSha256']={name:digest(workspace/name) for name in inventory};persist()
 run([str(NODE),'--check',test_name],cwd=workspace)
 env.update(NODE_ENV='test',AI_PROVIDER='ollama',JUDGE_PROVIDER='ollama',OLLAMA_MODEL='llama3.1:8b',JUDGE_MODEL='llama3.1:8b',OLLAMA_BASE_URL='http://127.0.0.1:11434',JUDGE_BASE_URL='http://127.0.0.1:11434',AWS_EC2_METADATA_DISABLED='true')
 if args.semantic_calibration:env.update(IPI_SEMANTIC_JUDGE_CALIBRATION_ACTUAL8B='1',IPI_SEMANTIC_JUDGE_CALIBRATION_EVIDENCE_PATH=str(root/'judge-evidence.json'))
 elif args.calibration:env.update(IPI_SAME_QUESTION_JUDGE_CALIBRATION_ACTUAL8B='1',IPI_SAME_QUESTION_JUDGE_CALIBRATION_EVIDENCE_PATH=str(root/'judge-evidence.json'))
 else:env.update(IPI_SAME_QUESTION_JUDGE_ACTUAL8B='1',IPI_SAME_QUESTION_JUDGE_EVIDENCE_PATH=str(root/'judge-evidence.json'))
 with log_path.open('w') as log:
  child=subprocess.Popen([str(NODE),'--test','--test-reporter=tap',test_name],cwd=workspace,env=env,stdout=log,stderr=log,start_new_session=True)
  state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid)};state['runStatus']='running';persist()
  try:code=child.wait(timeout=960)
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
