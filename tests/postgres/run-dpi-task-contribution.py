#!/usr/bin/env python3
"""Owned model-only heldout dpi-answer diagnostic. No database/browser/credit."""
import argparse,hashlib,json,os,signal,subprocess,tempfile,time
from pathlib import Path
from dpi_heldout_integrity import source_inventory,verify,cleanup
from owned_mcp_assembly_freeze import dependencies,digest as inventory_digest
NODE=Path('/Users/averma5/.owasp-ai-goat/runtimes/node-v26.10.0-darwin-arm64/bin/node')
EXPECTED_NODE='56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
SOURCE=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser();parser.add_argument('--cohort',choices=['v14-former-fresh-regression','whole-turn-disclosed-v2','whole-turn-references-disclosed-v2','compact-existential-disclosed-v2','grounded-predicates-disclosed-v2','response-passages-disclosed-v2'],required=True);parser.add_argument('--preflight-only',action='store_true');parser.add_argument('--reviewed-source-digest');parser.add_argument('--reviewed-dependency-digest');args=parser.parse_args()
if not args.preflight_only and (not args.reviewed_source_digest or not args.reviewed_dependency_digest):raise SystemExit('Reviewed source digest required before inference')
script='tests/postgres/dpiTaskContributionDiagnostic.js'
parent_seconds,child_seconds,max_http=(3240,3120,48)
digest=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
if digest(NODE)!=EXPECTED_NODE:raise SystemExit('Reviewed runtime mismatch')
root=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-dpi-content-witness-'));os.chmod(root,0o700)
state={'mode':('dpi-response-passages-disclosed-v1' if args.cohort=='response-passages-disclosed-v2' else 'dpi-grounded-predicates-disclosed-v1' if args.cohort=='grounded-predicates-disclosed-v2' else 'dpi-compact-existential-disclosed-v1' if args.cohort=='compact-existential-disclosed-v2' else 'dpi-whole-turn-references-disclosed-v1' if args.cohort=='whole-turn-references-disclosed-v2' else 'dpi-whole-turn-disclosed-v1' if args.cohort=='whole-turn-disclosed-v2' else 'dpi-task-contribution-v14'),'cohort':args.cohort,'launcherPid':os.getpid(),'status':'preparing','bounds':{'parentSeconds':parent_seconds,'childSeconds':child_seconds,'maxActualHttp':max_http,'perHttpSeconds':60},'nodeSha256':EXPECTED_NODE,'noDatabase':True,'noBrowser':True,'syntheticControlledActor':True,'noCredit':True}
def persist(): (root/'ownership.json').write_text(json.dumps(state,indent=2)+'\n')
child=None
def interrupted(signum,_frame):raise InterruptedError(f'Calibration interrupted by signal {signum}')
signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
signal.signal(signal.SIGALRM,lambda *_: (_ for _ in ()).throw(TimeoutError('Calibration parent deadline')))
signal.alarm(parent_seconds)
try:
 for name in [script,'tests/dpiResponsePassages.test.js','tests/dpiGroundedPredicates.test.js','tests/dpiCompactExistential.test.js','tests/dpiWholeTurnReferences.test.js','tests/dpiWholeTurnComparison.test.js','tests/fixtures/dpiWholeTurnControlledHarness.js','tests/dpiTaskContributionComparison.test.js','tests/fixtures/dpiExistentialDiagnostic.js','tests/postgres/dpiExistentialDiagnostic.js','tests/postgres/run-dpi-existential.py','tests/dpiExistentialDiagnostic.test.js','tests/dpiContentWitnessComparison.test.js','tests/dpiContentWitnessV12Comparison.test.js','tests/dpiExistentialComparison.test.js','tests/dpiAnswerComparison.test.js','tests/dpiObfuscationGraph.test.js','tests/dpiTaskContributionDiagnostic.test.js','tests/fixtures/dpiIndependentHeldoutV2.json','tests/fixtures/dpiTaskContributionDiagnostic.js','tests/fixtures/dpiHeldoutJudgeCases.js','tests/fixtures/dpiHeldoutJudgeHarness.js','tests/fixtures/dpiRetainedActualTransport.js','tests/postgres/run-dpi-task-contribution.py','tests/postgres/dpi_heldout_integrity.py','tests/postgres/owned_mcp_assembly_freeze.py','tests/postgres/test_dpi_heldout_integrity.py']:
  dest=root/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes((SOURCE/name).read_bytes())
 subprocess.run([str(NODE),'-e',"const fs=require('node:fs'),path=require('node:path'),{createCopyFilter}=require('./scripts/lib/isolated-source-copy');for(const name of ['server','shared','db/postgres','scripts/lib'])if(fs.existsSync(path.join(process.argv[1],name)))fs.cpSync(path.join(process.argv[1],name),path.join(process.argv[2],name),{recursive:true,filter:createCopyFilter(process.argv[1])});",str(SOURCE),str(root)],cwd=SOURCE,check=True,timeout=30)
 (root/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
 (root/'package.json').write_bytes((SOURCE/'package.json').read_bytes());(root/'package-lock.json').write_bytes((SOURCE/'package-lock.json').read_bytes())
 state['candidateMode']='categorical'
 state['sourceSha256']=source_inventory(root);state['sourceDigest']=inventory_digest(state['sourceSha256']);dep_rows=dependencies(root);state['dependencyDigest']=inventory_digest(dep_rows);state['dependencyCount']=len(dep_rows);(root/'dependency-bytes.json').write_text(json.dumps(dep_rows,sort_keys=True));persist()
 env={'PATH':str(NODE.parent)+':/usr/bin:/bin','DPI_CALIBRATION_RESULT':str(root/'result.json'),'DPI_WITNESS_COHORT':args.cohort}
 subprocess.run(['python3','-B','-m','unittest','discover','-s','tests/postgres','-p','test_dpi_heldout_integrity.py'],cwd=root,check=True,timeout=30)
 subprocess.run([str(NODE),'-e',"require('./server/agent-runtime/objectiveJudge');require('./server/agent-runtime/dpiAnswerComparison');require('./tests/fixtures/dpiRetainedActualTransport');"],cwd=root,env=env,check=True,timeout=30)
 subprocess.run([str(NODE),'--test','tests/dpiTaskContributionDiagnostic.test.js'],cwd=root,env=env,check=True,timeout=30)
 subprocess.run([str(NODE),str(root/script)],cwd=root,env={**env,'DPI_CALIBRATION_PREFLIGHT_ONLY':'1'},check=True,timeout=30)
 state['preflightResultSha256']=digest(root/'result.json')
 if args.preflight_only:state['status']='prepared'
 else:
  if state['sourceDigest']!=args.reviewed_source_digest:raise RuntimeError('Reviewed source digest mismatch')
  verify(root,state['sourceSha256'],args.reviewed_dependency_digest)
  with (root/'run.log').open('w') as log:
   child=subprocess.Popen([str(NODE),str(root/script)],cwd=root,env=env,stdout=log,stderr=log,start_new_session=True)
   state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid)};state['status']='running';persist()
   code=child.wait(timeout=child_seconds)
  if code:raise RuntimeError('Judge calibration failed; inspect retained log')
  verify(root,state['sourceSha256'],args.reviewed_dependency_digest)
  state['status']=json.loads((root/'result.json').read_text())['status'];state['resultSha256']=digest(root/'result.json')
except BaseException as error:
 state['status']='failed';state['errorType']=type(error).__name__;raise
finally:
 state['cleanup']=cleanup(child,state.get('child',{}).get('pgid'))
 try:
  verify(root,state.get('sourceSha256',{}),state.get('dependencyDigest',''))
 except BaseException as error:state['cleanup']['errors'].append(type(error).__name__+': '+str(error)[:300])
 if not state['cleanup']['wholeProcessGroupAbsent'] or state['cleanup']['errors']:state['status']='failed';state['cleanupErrorType']='CleanupOrIntegrityFailed'
 persist()
 print(json.dumps({'evidence':str(root),'status':state['status'],'cleanup':state['cleanup']}))

if state['status']=='failed':raise SystemExit(1)
