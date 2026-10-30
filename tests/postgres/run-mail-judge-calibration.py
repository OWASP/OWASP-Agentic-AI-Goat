#!/usr/bin/env python3
"""Owned model-only retained mail diagnostic. No database/browser/credit."""
import argparse,hashlib,json,os,signal,subprocess,tempfile,time
from pathlib import Path
NODE=Path('/Users/averma5/.owasp-ai-goat/runtimes/node-v26.10.0-darwin-arm64/bin/node')
EXPECTED_NODE='56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
SOURCE=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser();parser.add_argument('--mode',choices=['baseline','observation','categorical','categorical-v2','grounded','keyed','source-only','sparse','compact','conditional','whole','paired-format','authority-v13','authority-v14','authority-v15'],default='baseline');parser.add_argument('--preflight-only',action='store_true');parser.add_argument('--reviewed-source-sha256');parser.add_argument('--reviewed-dependency-sha256');args=parser.parse_args()
script={'baseline':'tests/postgres/secureshopMailJudgeCalibration.js','observation':'tests/postgres/secureshopMailObservationCalibration.js','categorical':'tests/postgres/secureshopMailCategoricalCalibration.js','categorical-v2':'tests/postgres/secureshopMailCategoricalV2Calibration.js','grounded':'tests/postgres/secureshopMailGroundedCalibration.js','keyed':'tests/postgres/secureshopMailKeyedCalibration.js','source-only':'tests/postgres/secureshopMailSourceCalibration.js','sparse':'tests/postgres/secureshopMailSparseCalibration.js','compact':'tests/postgres/secureshopMailCompactCalibration.js','conditional':'tests/postgres/secureshopMailConditionalCalibration.js','whole':'tests/postgres/secureshopMailWholeCalibration.js','paired-format':'tests/postgres/secureshopMailPairedFormatDiagnostic.js','authority-v13':'tests/postgres/secureshopMailReplyAuthorityCalibration.js','authority-v14':'tests/postgres/secureshopMailReplyAuthorityHeldoutCalibration.js','authority-v15':'tests/postgres/secureshopMailSeparatedAuthorityCalibration.js'}[args.mode]
parent_seconds,child_seconds,max_http=(600,540,8) if args.mode in ['authority-v13','authority-v14','authority-v15'] else (960,900,14) if args.mode in ['categorical-v2','paired-format'] else (840,780,12) if args.mode in ['categorical','grounded','keyed','source-only','sparse','compact','conditional','whole','paired-format','authority-v13','authority-v14','authority-v15'] else (480,450,6)
if args.mode in ['authority-v13','authority-v14','authority-v15']:
 import re,mail_reply_authority_freeze as authority_freeze
 from mail_authority_calibration_copy import verify_files,verify_retained
 if not all(re.fullmatch(r'[0-9a-f]{64}',v or '') for v in [args.reviewed_source_sha256,args.reviewed_dependency_sha256]):parser.error('Authority calibration requires reviewed source/dependency byte digests')
 reviewed_rows=authority_freeze.verify(SOURCE,args.reviewed_source_sha256,args.reviewed_dependency_sha256)
if args.mode in ['authority-v14','authority-v15']:
 input_source='tests/fixtures/mailSeparatedAuthorityIdentities.json' if args.mode=='authority-v15' else 'tests/fixtures/mailAuthorityHeldoutIdentities.json'
 original=SOURCE/input_source
 review={'runtimeResultSha256':reviewed_rows[input_source]['sha256']}
else:
 REPORT=SOURCE/'tasks/secureshop-bound-mail-actual-v2-judge-failure-2026-09-26.json'
 review=json.loads(REPORT.read_text());original=Path(review['evidenceDirectory'])/'candidate-result.json'
 if args.mode=='paired-format':
  review=json.loads((SOURCE/'tasks/secureshop-bound-mail-whole-calibration-2026-09-26.json').read_text());original=Path(review['evidenceDirectory'])/'result.json';review['runtimeResultSha256']=review['resultSha256']
digest=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
if digest(NODE)!=EXPECTED_NODE or digest(original)!=review['runtimeResultSha256']:raise SystemExit('Reviewed runtime or immutable retained packet mismatch')
root=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-mail-judge-calibration-'));os.chmod(root,0o700)
state={'mode':'mail-judge-diagnostic','launcherPid':os.getpid(),'status':'preparing','bounds':{'parentSeconds':parent_seconds,'childSeconds':child_seconds,'maxActualHttp':max_http,'perHttpSeconds':60},'nodeSha256':EXPECTED_NODE,'noDatabase':True,'noBrowser':True,'noActor':True,'noCredit':True,'reviewedSourceSha256':args.reviewed_source_sha256,'reviewedDependencySha256':args.reviewed_dependency_sha256}
def persist(): (root/'ownership.json').write_text(json.dumps(state,indent=2)+'\n')
input_name='diagnostic-input.json' if args.mode in ['authority-v14','authority-v15'] else 'retained-input.json'
child=None;workspace=root/'source' if args.mode in ['authority-v13','authority-v14','authority-v15'] else root
def interrupted(signum,_frame):raise InterruptedError(f'Calibration interrupted by signal {signum}')
signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
signal.signal(signal.SIGALRM,lambda *_: (_ for _ in ()).throw(TimeoutError('Calibration parent deadline')))
signal.alarm(parent_seconds)
try:
 if args.mode in ['authority-v13','authority-v14','authority-v15']:
  authority_freeze.copy(SOURCE,workspace)
  (workspace/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
  authority_freeze.verify(workspace,args.reviewed_source_sha256,args.reviewed_dependency_sha256)
  verify_files(workspace,reviewed_rows)
 else:
  for name in [script,*(['tests/postgres/secureshopMailCategoricalCalibration.js'] if args.mode in ['categorical-v2','grounded','keyed','source-only','sparse','compact','conditional','whole','paired-format'] else []),*(['tests/postgres/secureshopMailGroundedPreflight.js'] if args.mode=='grounded' else []),*(['tests/postgres/secureshopMailKeyedPreflight.js'] if args.mode=='keyed' else []),*(['tests/postgres/secureshopMailSourcePreflight.js'] if args.mode=='source-only' else []),*(['tests/postgres/secureshopMailSparsePreflight.js'] if args.mode=='sparse' else []),*(['tests/postgres/secureshopMailCompactPreflight.js'] if args.mode=='compact' else []),*(['tests/postgres/secureshopMailConditionalPreflight.js'] if args.mode=='conditional' else []),*(['tests/postgres/secureshopMailWholePreflight.js'] if args.mode=='whole' else []),*(['tests/postgres/secureshopMailWholePreflight.js','tests/postgres/secureshopMailWholeCalibration.js'] if args.mode=='paired-format' else []),'tests/postgres/secureshopMailActualTransport.js','tests/postgres/run-mail-judge-calibration.py']:
   dest=root/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes((SOURCE/name).read_bytes())
  if args.mode in ['observation','categorical','categorical-v2','grounded','keyed','source-only','sparse','compact','conditional','whole','paired-format']:
   subprocess.run([str(NODE),'-e',"const fs=require('node:fs'),path=require('node:path'),{createCopyFilter}=require('./scripts/lib/isolated-source-copy');for(const name of ['server','shared','db/postgres'])if(fs.existsSync(path.join(process.argv[1],name)))fs.cpSync(path.join(process.argv[1],name),path.join(process.argv[2],name),{recursive:true,filter:createCopyFilter(process.argv[1])});",str(SOURCE),str(root)],cwd=SOURCE,check=True,timeout=30)
   (root/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
   (root/'package.json').write_bytes((SOURCE/'package.json').read_bytes());(root/'package-lock.json').write_bytes((SOURCE/'package-lock.json').read_bytes())
 state['candidateMode']=args.mode
 (root/input_name).write_bytes(original.read_bytes())
 if args.mode in ['authority-v13','authority-v14','authority-v15']:
  verify_retained(root/input_name,review['runtimeResultSha256'])
  state['sourceSha256']={'source/'+name:row['sha256'] for name,row in reviewed_rows.items()}
  state['diagnosticInputSha256' if args.mode in ['authority-v14','authority-v15'] else 'retainedInputSha256']=review['runtimeResultSha256']
 else:state['sourceSha256']={str(p.relative_to(root)):digest(p) for p in root.rglob('*') if p.is_file()}
 persist()
 env={'PYTHONDONTWRITEBYTECODE':'1','PATH':str(NODE.parent)+':/usr/bin:/bin','MAIL_CALIBRATION_INPUT':str(root/input_name),'MAIL_CALIBRATION_INPUT_SHA':review['runtimeResultSha256'],'MAIL_CALIBRATION_RESULT':str(root/'result.json')}
 if args.mode in ['observation','categorical','categorical-v2','grounded','keyed','source-only','sparse','compact','conditional','whole','paired-format','authority-v13','authority-v14','authority-v15']:subprocess.run([str(NODE),'-e',"require('./server/agent-runtime/objectiveJudge');require('./server/services/secureshopMailReplyAssessment');require('./tests/postgres/secureshopMailActualTransport');"],cwd=workspace,env=env,check=True,timeout=30)
 if args.mode in ['categorical','categorical-v2','grounded','keyed','source-only','sparse','compact','conditional','whole','paired-format','authority-v13','authority-v14','authority-v15']:
  subprocess.run([str(NODE),str(workspace/script)],cwd=workspace,env={**env,'MAIL_CALIBRATION_PREFLIGHT_ONLY':'1'},check=True,timeout=30)
  state['preflightResultSha256']=digest(root/'result.json')
 if args.mode in ['authority-v13','authority-v14','authority-v15']:
  authority_freeze.verify(SOURCE,args.reviewed_source_sha256,args.reviewed_dependency_sha256)
  authority_freeze.verify(workspace,args.reviewed_source_sha256,args.reviewed_dependency_sha256)
  verify_files(workspace,reviewed_rows)
  verify_retained(root/input_name,review['runtimeResultSha256'])
 if args.preflight_only:state['status']='prepared'
 else:
  with (root/'run.log').open('w') as log:
   child=subprocess.Popen([str(NODE),str(workspace/script)],cwd=workspace if args.mode in ['authority-v13','authority-v14','authority-v15'] else None,env=env,stdout=log,stderr=log,start_new_session=True)
   state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid)};state['status']='running';persist()
   code=child.wait(timeout=child_seconds)
  if code:raise RuntimeError('Judge calibration failed; inspect retained log')
  state['status']='completed';state['resultSha256']=digest(root/'result.json')
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
  try:child.wait(timeout=5)
  except subprocess.TimeoutExpired:os.killpg(pgid,signal.SIGKILL);child.wait(timeout=5)
 if args.mode in ['authority-v13','authority-v14','authority-v15']:
  try:
   authority_freeze.verify(SOURCE,args.reviewed_source_sha256,args.reviewed_dependency_sha256)
   if digest(NODE)!=EXPECTED_NODE:raise RuntimeError('Node executable changed')
   if workspace.exists():
    authority_freeze.verify(workspace,args.reviewed_source_sha256,args.reviewed_dependency_sha256)
    verify_files(workspace,reviewed_rows)
   if (root/input_name).exists():verify_retained(root/input_name,review['runtimeResultSha256'])
   state['finalIntegrityVerified']=True
  except Exception as error:state['status']='failed';state['integrityError']=type(error).__name__;state['finalIntegrityVerified']=False
 state['cleanup']={'wholeProcessGroupAbsent':not members()};persist()
 print(json.dumps({'evidence':str(root),'status':state['status'],'cleanup':state['cleanup']}))

if args.mode in ['authority-v13','authority-v14','authority-v15'] and (state['status'] not in ['prepared','completed'] or not state['cleanup']['wholeProcessGroupAbsent']):raise SystemExit(1)
