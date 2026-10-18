#!/usr/bin/env python3
"""Owned model-only retained dpi-answer diagnostic. No database/browser/credit."""
import argparse,hashlib,json,os,signal,subprocess,tempfile,time
from pathlib import Path
NODE=Path('/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node')
EXPECTED_NODE='56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
SOURCE=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser();parser.add_argument('--preflight-only',action='store_true');args=parser.parse_args()
script='tests/postgres/dpiPublicationRetainedCalibration.js'
parent_seconds,child_seconds,max_http=(1020,960,20)
REPORT=SOURCE/'tasks/dpi-owned-decoder-v10-actual-2026-09-26.json'
retained=json.loads(REPORT.read_text());original=Path(retained['root'])/'candidate-result.json';expected_input=retained['artifactSha256']['candidate-result.json']
digest=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
if digest(NODE)!=EXPECTED_NODE or digest(original)!=expected_input:raise SystemExit('Reviewed runtime or immutable retained packet mismatch')
root=Path(tempfile.mkdtemp(prefix='dvaia-dpi-publication-calibration-'));os.chmod(root,0o700)
state={'mode':'dpi-publication-diagnostic','launcherPid':os.getpid(),'status':'preparing','bounds':{'parentSeconds':parent_seconds,'childSeconds':child_seconds,'maxActualHttp':max_http,'perHttpSeconds':60},'nodeSha256':EXPECTED_NODE,'noDatabase':True,'noBrowser':True,'noActor':True,'noCredit':True}
def persist(): (root/'ownership.json').write_text(json.dumps(state,indent=2)+'\n')
child=None
def interrupted(signum,_frame):raise InterruptedError(f'Calibration interrupted by signal {signum}')
signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
signal.signal(signal.SIGALRM,lambda *_: (_ for _ in ()).throw(TimeoutError('Calibration parent deadline')))
signal.alarm(parent_seconds)
try:
 for name in [script,'tests/dpiPublicationDefense.test.js','tests/fixtures/dpiRetainedActualTransport.js','tests/fixtures/dpiPublicationCases.js','tests/postgres/run-dpi-publication-retained-calibration.py']:
  dest=root/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes((SOURCE/name).read_bytes())
 subprocess.run([str(NODE),'-e',"const fs=require('node:fs'),path=require('node:path'),{createCopyFilter}=require('./scripts/lib/isolated-source-copy');for(const name of ['server','shared','db/postgres'])if(fs.existsSync(path.join(process.argv[1],name)))fs.cpSync(path.join(process.argv[1],name),path.join(process.argv[2],name),{recursive:true,filter:createCopyFilter(process.argv[1])});",str(SOURCE),str(root)],cwd=SOURCE,check=True,timeout=30)
 (root/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
 (root/'package.json').write_bytes((SOURCE/'package.json').read_bytes());(root/'package-lock.json').write_bytes((SOURCE/'package-lock.json').read_bytes())
 state['candidateMode']='categorical'
 (root/'retained-input.json').write_bytes(original.read_bytes());state['sourceSha256']={str(p.relative_to(root)):digest(p) for p in root.rglob('*') if p.is_file()};persist()
 env={'PATH':str(NODE.parent)+':/usr/bin:/bin','DPI_CALIBRATION_INPUT':str(root/'retained-input.json'),'DPI_CALIBRATION_INPUT_SHA':expected_input,'DPI_CALIBRATION_RESULT':str(root/'result.json')}
 subprocess.run([str(NODE),'-e',"require('./server/agent-runtime/objectiveJudge');require('./server/agent-runtime/dpiAnswerComparison');require('./tests/fixtures/dpiRetainedActualTransport');"],cwd=root,env=env,check=True,timeout=30)
 subprocess.run([str(NODE),'--test','tests/dpiPublicationDefense.test.js'],cwd=root,env=env,check=True,timeout=30)
 subprocess.run([str(NODE),str(root/script)],cwd=root,env={**env,'DPI_CALIBRATION_PREFLIGHT_ONLY':'1'},check=True,timeout=30)
 state['preflightResultSha256']=digest(root/'result.json')
 if args.preflight_only:state['status']='prepared'
 else:
  with (root/'run.log').open('w') as log:
   child=subprocess.Popen([str(NODE),str(root/script)],cwd=root,env=env,stdout=log,stderr=log,start_new_session=True)
   state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid)};state['status']='running';persist()
   code=child.wait(timeout=child_seconds)
  if code:raise RuntimeError('Judge calibration failed; inspect retained log')
  if any(digest(root/name)!=expected for name,expected in state['sourceSha256'].items()):raise RuntimeError('Frozen calibration source changed')
  state['status']=json.loads((root/'result.json').read_text())['status'];state['resultSha256']=digest(root/'result.json')
except BaseException as error:
 state['status']='failed';state['errorType']=type(error).__name__;raise
finally:
 signal.alarm(0)
 pgid=state.get('child',{}).get('pgid')
 def members():
  if not pgid:return []
  rows=subprocess.check_output(['ps','-axo','pid=,pgid=,uid='],text=True)
  found=[tuple(map(int,line.split())) for line in rows.splitlines() if len(line.split())==3 and int(line.split()[1])==pgid]
  if any(row[2]!=os.getuid() for row in found):raise RuntimeError('Foreign owned-group process')
  return found
 if members():
  os.killpg(pgid,signal.SIGTERM)
  deadline=time.monotonic()+5
  while members() and time.monotonic()<deadline:
   child.poll();time.sleep(.05)
  if members():os.killpg(pgid,signal.SIGKILL)
  child.wait(timeout=5)
 state['cleanup']={'wholeProcessGroupAbsent':not members()}
 if not state['cleanup']['wholeProcessGroupAbsent']:state['status']='failed';state['errorType']='CleanupFailed'
 persist()
 print(json.dumps({'evidence':str(root),'status':state['status'],'cleanup':state['cleanup']}))

if state['status']=='failed':raise SystemExit(1)
