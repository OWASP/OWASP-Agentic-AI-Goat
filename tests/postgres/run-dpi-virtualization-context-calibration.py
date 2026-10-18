#!/usr/bin/env python3
"""Owned model-only virtualization calibration. No app, database, browser, actor, or credit."""
import argparse,hashlib,json,os,signal,stat,subprocess,tempfile,time
from pathlib import Path

SOURCE=Path(__file__).resolve().parents[2]
NODE=Path('/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node')
EXPECTED_NODE='56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
ENTRY='tests/fixtures/dpiVirtualizationContextCalibration.js'
TEST='tests/dpiVirtualizationContextCalibration.test.js'
INPUTS=('tests/release-inputs/dpi-whole-task-intent-qualification8-inputs-v1.json','tests/release-inputs/dpi-bound-evidence-heldout4-input-v1.json')
PARENT_SECONDS,CHILD_SECONDS,MAXIMUM_INFERENCE_CALLS=960,900,16
digest=lambda path:hashlib.sha256(Path(path).read_bytes()).hexdigest()

def contract():
 return {'profile':'dpi-virtualization-context-v1','model':'llama3.1:8b','modelDigest':'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e','caseIds':['DPG009','DPG011','WTC001','WTC002','BOUND001','BOUND002','BOUND003','BOUND004'],'expected':['pass','fail','pass','fail','fail','fail','pass','fail'],'maximumInferenceCalls':MAXIMUM_INFERENCE_CALLS,'retries':0,'actorProof':False,'creditAuthorized':False}

def main(argv=None):
 parser=argparse.ArgumentParser();parser.add_argument('--preflight-only',action='store_true');args=parser.parse_args(argv)
 if digest(NODE)!=EXPECTED_NODE:raise RuntimeError('Reviewed managed Node changed')
 parent=SOURCE/'backups/private-recovery/dpi-virtualization-context-calibration-v1';parent.mkdir(parents=True,exist_ok=True,mode=0o700)
 parent_stat=parent.lstat()
 if not stat.S_ISDIR(parent_stat.st_mode) or parent.is_symlink() or parent_stat.st_uid!=os.getuid():raise RuntimeError('Invalid evidence parent')
 root=Path(tempfile.mkdtemp(prefix='run-',dir=parent));os.chmod(root,0o700)
 state={'profile':'dpi-virtualization-context-v1','launcherPid':os.getpid(),'status':'preparing','contract':contract(),'bounds':{'parentSeconds':PARENT_SECONDS,'childSeconds':CHILD_SECONDS,'maximumInferenceCalls':MAXIMUM_INFERENCE_CALLS},'nodeSha256':EXPECTED_NODE,'noDatabase':True,'noBrowser':True,'noActor':True,'noCredit':True}
 ownership=root/'ownership.json';result=root/'result.json';log=root/'run.log';child=None
 def persist():ownership.write_text(json.dumps(state,indent=2)+'\n');os.chmod(ownership,0o600)
 def members():
  pgid=state.get('child',{}).get('pgid')
  if not pgid:return []
  rows=subprocess.check_output(['ps','-axo','pid=,pgid=,uid='],text=True)
  found=[tuple(map(int,line.split())) for line in rows.splitlines() if len(line.split())==3 and int(line.split()[1])==pgid]
  if any(row[2]!=os.getuid() for row in found):raise RuntimeError('Foreign process in owned group')
  return found
 def interrupted(signum,_frame):raise InterruptedError(f'Calibration interrupted by signal {signum}')
 signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
 signal.signal(signal.SIGALRM,lambda *_: (_ for _ in ()).throw(TimeoutError('Calibration parent deadline')));signal.alarm(PARENT_SECONDS)
 try:
  for relative in (ENTRY,TEST,*INPUTS):
   path=SOURCE/relative
   if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(SOURCE):raise RuntimeError('Canonical main input required')
  env={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':os.environ['HOME'],'DPI_VIRTUALIZATION_RESULT':str(result),'DPI_VIRTUALIZATION_PREFLIGHT_ONLY':'1'}
  subprocess.run([str(NODE),'--test',TEST],cwd=SOURCE,env=env,check=True,timeout=30)
  subprocess.run([str(NODE),ENTRY],cwd=SOURCE,env=env,check=True,timeout=30)
  prepared=json.loads(result.read_text())
  if prepared.get('status')!='prepared' or prepared.get('maximumInferenceCalls')!=MAXIMUM_INFERENCE_CALLS or prepared.get('retries')!=0:raise RuntimeError('Closed virtualization preflight mismatch')
  pins=dict(prepared.get('sourcePins') or {})
  for relative in (ENTRY,TEST,str(Path(__file__).resolve().relative_to(SOURCE)),*INPUTS):pins[relative]=digest(SOURCE/relative)
  if not pins or any(Path(relative).is_absolute() or '..' in Path(relative).parts or not (SOURCE/relative).is_file() or (SOURCE/relative).is_symlink() or not (SOURCE/relative).resolve().is_relative_to(SOURCE) or digest(SOURCE/relative)!=expected for relative,expected in pins.items()):raise RuntimeError('Current main source admission failed')
  state['sourceSha256']=pins;persist()
  state['preflightResultSha256']=digest(result)
  if args.preflight_only:state['status']='prepared'
  else:
   with log.open('w') as output:
    child=subprocess.Popen([str(NODE),ENTRY],cwd=SOURCE,env={k:v for k,v in env.items() if k!='DPI_VIRTUALIZATION_PREFLIGHT_ONLY'},stdout=output,stderr=output,start_new_session=True)
    state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid)};state['status']='running';persist();code=child.wait(timeout=CHILD_SECONDS)
   value=json.loads(result.read_text())
   if code and value.get('status')!='diagnostic_mismatch':raise RuntimeError('Virtualization diagnostic failed; inspect retained log')
   calls=len(value.get('calls',[]))
   if value.get('complete')is not True or value.get('physicalPending')!=0 or not 0<calls<=MAXIMUM_INFERENCE_CALLS or (value.get('gatePassed')is True and calls!=MAXIMUM_INFERENCE_CALLS):raise RuntimeError('Virtualization diagnostic incomplete')
   if any(digest(SOURCE/name)!=expected for name,expected in state['sourceSha256'].items()):raise RuntimeError('Frozen calibration source changed')
   state['status']=value['status'];state['resultSha256']=digest(result)
 except BaseException as error:
  state['status']='failed';state['errorType']=type(error).__name__;raise
 finally:
  signal.alarm(0)
  if members():
   os.killpg(state['child']['pgid'],signal.SIGTERM);deadline=time.monotonic()+5
   while members() and time.monotonic()<deadline:time.sleep(.05)
   if members():os.killpg(state['child']['pgid'],signal.SIGKILL)
   child.wait(timeout=5)
  state['cleanup']={'wholeProcessGroupAbsent':not members()}
  state['sourceUnchanged']=bool(state.get('sourceSha256')) and all(digest(SOURCE/name)==expected for name,expected in state['sourceSha256'].items())
  if not state['cleanup']['wholeProcessGroupAbsent'] or not state['sourceUnchanged']:state['status']='failed';state['errorType']='CleanupOrSourceFailed'
  persist();print(json.dumps({'evidence':str(root),'status':state['status'],'cleanup':state['cleanup']}))
 return 0 if state['status'] in ('prepared','diagnostic_pass') else 1

if __name__=='__main__':raise SystemExit(main())
