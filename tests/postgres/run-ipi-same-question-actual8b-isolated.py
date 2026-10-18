#!/usr/bin/env python3
"""Run IPI actual same-question clean/poison pair with real cached CPU embeddings and local8B actor/Judge in owned disposable stores."""
import argparse, hashlib, json, os, signal, subprocess, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from sensitive_info_recovery_safety import SignalGate

EXPECTED_DOCKER='unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
NODE=Path('/Users/averma5/.dvaia/runtimes/node-v26.9.0-darwin-arm64/bin/node')
DOCKER=Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')
IMAGE='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
SOURCE=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True);parser.add_argument('--receipt-replay',action='store_true');args=parser.parse_args()
if args.docker_host!=EXPECTED_DOCKER:raise SystemExit('reviewed isolated Docker host required')
root=Path(tempfile.mkdtemp(prefix='dvaia-ipi-same-question-'));os.chmod(root,0o700);workspace=root/'source'
container='dvaia-ipi-same-question-'+uuid.uuid4().hex[:12];owner=uuid.uuid4().hex
docker=[str(DOCKER),'--host',args.docker_host]
env={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':os.environ['HOME'],'TMPDIR':str(root)}
state={'container':container,'owner':owner,'image':IMAGE,'evidence':str(root),'launcherPid':os.getpid(),
 'nodeVersion':None,'containerCreationAttempted':False,'child':None,'runStatus':'preparing','cleanup':None,
 'mode':'retained_synthetic_receipt_replay' if args.receipt_replay else 'actual_same_question_actor_contrast',
 'createdAt':datetime.now(timezone.utc).isoformat()}
ownership=root/'ownership.json';log_path=root/'tests.log';log_path.touch(mode=0o600)
def persist():ownership.write_text(json.dumps(state,indent=2)+'\n');os.chmod(ownership,0o600)
def run(command,**kwargs):kwargs.setdefault('timeout',120);return subprocess.run(command,check=True,env=kwargs.pop('env',env),**kwargs)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def exact_absence():
 query=subprocess.run(docker+['ps','-a','--filter',f'name=^/{container}$','--format','{{.Names}}'],env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=30)
 if query.returncode:raise RuntimeError('exact-name container query failed')
 return not query.stdout.strip()
child=None;creation_attempted=False;gate=SignalGate();signal.signal(signal.SIGTERM,gate.handler);signal.signal(signal.SIGINT,gate.handler);persist()
def owned_group_members(pgid):
 listing=subprocess.run(['ps','-axo','pid=,pgid=,uid='],env=env,stdout=subprocess.PIPE,text=True,check=True,timeout=5).stdout
 members=[]
 for line in listing.splitlines():
  fields=line.split()
  if len(fields)==3 and int(fields[1])==pgid:
   if int(fields[2])!=os.getuid():raise RuntimeError(f'refusing foreign process in owned group {pgid}')
   members.append(int(fields[0]))
 return members
def stop_child():
 if child is None:return
 pgid=state.get('child',{}).get('pgid')
 if not pgid:return
 if owned_group_members(pgid):os.killpg(pgid,signal.SIGTERM)
 deadline=time.monotonic()+5
 while owned_group_members(pgid) and time.monotonic()<deadline:time.sleep(.05)
 if owned_group_members(pgid):os.killpg(pgid,signal.SIGKILL)
 try:child.wait(timeout=5)
 except subprocess.TimeoutExpired:pass
 if owned_group_members(pgid):raise RuntimeError('owned Node/browser process group cleanup incomplete')
try:
 version=run([str(NODE),'--version'],stdout=subprocess.PIPE,text=True).stdout.strip()
 if version!='v26.9.0':raise RuntimeError('managed Node v26.9.0 required')
 state['nodeVersion']=version;persist()
 daemon_name=run(docker+['info','--format','{{.Name}}'],stdout=subprocess.PIPE,text=True).stdout.strip()
 if daemon_name!='colima-dvaia-pg-verify':raise RuntimeError('reviewed isolated Docker daemon required')
 image_id=run(docker+['image','inspect','--format','{{.Id}}',IMAGE],stdout=subprocess.PIPE,text=True).stdout.strip()
 if image_id!=IMAGE:raise RuntimeError('immutable PostgreSQL image identity mismatch')
 state['dockerDaemon']=daemon_name;state['imageId']=image_id;persist()
 if not exact_absence():raise RuntimeError('owned container name unexpectedly exists')
 run([str(NODE),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(SOURCE),str(workspace)],cwd=SOURCE)
 (workspace/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
 (workspace/'client/node_modules').symlink_to(SOURCE/'client/node_modules',target_is_directory=True)
 inventory=['tests/postgres/run-ipi-same-question-actual8b-isolated.py',
  'server/routes/ragInjection.js','server/agent-runtime/ragIngestGraph.js','server/agent-runtime/ragQueryGraph.js',
  'server/agent-runtime/ragDecisionLoop.js','server/agent-runtime/ragDecisions.js','server/agent-runtime/indirectObjectiveJudge.js',
  'server/agent-runtime/objectiveJudge.js','server/agent-runtime/sourceComparisonVerifier.js','server/services/objectiveCompletionService.js',
  'server/services/objectiveRegradeService.js','server/database/postgres/objectiveJudgmentRepository.js',
  'server/services/workshopRagReadiness.js','server/services/workshopRagComposition.js','server/services/workshopRagStore.js',
  'server/services/ragVectorStore.js','server/services/secureshopProductEmbedder.js','server/services/embeddingRuntimeFingerprint.js',
  'server/database/postgres/workshopRagRepository.js','server/database/postgres/workshopRagRevisionRepository.js',
  'db/postgres/identity-migrations/0082_workshop_rag_sources.sql','db/postgres/identity-migrations/0095_teaching_sessions.sql',
  'db/postgres/identity-migrations/0097_mcp_protected_reconciliation.sql']
 if args.receipt_replay:
  inventory += ['tests/postgres/ipiObligationReceiptReplay.integration.test.js','tests/fixtures/ipiObligationV4CalibrationReceipt.json',
   'server/database/postgres/agentRunReadRepository.js','server/database/postgres/workshopProgressRepository.js',
   'server/database/postgres/identityRepository.js','server/database/postgres/workshopPlatformSeed.js',
   'server/database/postgres/workshopPlatformSeedCore.js','server/database/postgres/workshopPlatformSupport.js',
   'server/database/postgres/catalogDefaultProvenance.js','server/config/workshopCatalog.js',
   'db/postgres/workshopChallengeFixtures.js','db/postgres/migrate.js','scripts/lib/isolated-source-copy.js',
   'server/data/workshopHints.js','server/data/indirectPromptInjectionSolutions.js']
  inventory += [str(path.relative_to(workspace)) for path in sorted((workspace/'db/postgres/identity-migrations').glob('*.sql'))]
  inventory += [str(path.relative_to(workspace)) for base in ['server/data','server/config']
   for path in sorted((workspace/base).rglob('*.js'))]
 else:inventory += ['tests/postgres/ipiSameQuestionCleanPoisonActual8b.integration.test.js']
 state['sourceSha256']={name:digest(workspace/name) for name in sorted(set(inventory))};persist()
 test_file='tests/postgres/ipiObligationReceiptReplay.integration.test.js' if args.receipt_replay else 'tests/postgres/ipiSameQuestionCleanPoisonActual8b.integration.test.js'
 if not args.receipt_replay:
  cache=Path('/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/dvaia-embedding-430-255u6f1z/cache')
  if not cache.is_dir():raise RuntimeError('reviewed cached CPU embedding runtime unavailable')
  import shutil
  shutil.copytree(cache,workspace/'model-cache')
  env['XENOVA_CACHE']=str(workspace/'model-cache')
  cache_files={str(item.relative_to(workspace/'model-cache')):digest(item) for item in sorted((workspace/'model-cache').rglob('*')) if item.is_file()}
  cache_manifest=json.dumps(cache_files,sort_keys=True,separators=(',',':')).encode()
  state['embeddingCache']={'source':str(cache),'copiedPath':str(workspace/'model-cache'),'fileCount':len(cache_files),'manifestSha256':hashlib.sha256(cache_manifest).hexdigest()};persist()
 run([str(NODE),'--check',test_file],cwd=workspace)
 if not args.receipt_replay:run([str(NODE),'--check','server/routes/ragInjection.js'],cwd=workspace)
 creation_attempted=True;state['containerCreationAttempted']=True;persist()
 run(docker+['run','--detach','--pull','never','--name',container,'--label','dvaia.test.owner='+owner,
  '--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size=268435456','-e','POSTGRES_HOST_AUTH_METHOD=trust',
  '-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',IMAGE,'-c','shared_buffers=16MB','-c','max_connections=40',
  '-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL)
 details=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]
 if details.get('Mounts') or details['Config']['Labels'].get('dvaia.test.owner')!=owner:raise RuntimeError('owned PostgreSQL isolation/ownership check failed')
 for _ in range(100):
  ready=subprocess.run(docker+['exec',container,'pg_isready','-h','127.0.0.1','-U','postgres'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
  if ready.returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('owned PostgreSQL unavailable')
 port=int(run(docker+['port',container,'5432/tcp'],stdout=subprocess.PIPE,text=True).stdout.strip().rsplit(':',1)[1])
 psql=docker+['exec',container,'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-c']
 roles=['dvaia_identity_migration','dvaia_identity_runtime']
 run(psql+[';'.join(f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS' for role in roles)+';'],stdout=subprocess.DEVNULL)
 nonce=owner[:12]
 database=f'dvaia_test_workshop_rag_{nonce}'
 run(psql+[f'CREATE DATABASE {database} OWNER dvaia_identity_migration'],stdout=subprocess.DEVNULL)
 run(psql+[f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO dvaia_identity_migration,dvaia_identity_runtime'],stdout=subprocess.DEVNULL)
 env['WORKSHOP_RAG_MIGRATION_URL']=f'postgresql://dvaia_identity_migration@127.0.0.1:{port}/{database}'
 env['WORKSHOP_RAG_RUNTIME_URL']=f'postgresql://dvaia_identity_runtime@127.0.0.1:{port}/{database}'
 common=dict(NODE_ENV='test',PG_TEST_DISPOSABLE='yes',DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace),
  PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',AWS_EC2_METADATA_DISABLED='true',
  MCP_WORKSHOP_AUTOSTART='false',MCP_SIDECARS_AUTOSTART='false',SS_ENABLE='false')
 if args.receipt_replay:
  common.update(IPI_OBLIGATION_RECEIPT_REPLAY_NATIVE='1',IPI_RECEIPT_REPLAY_EVIDENCE_PATH=str(root/'receipt-replay-evidence.json'))
 else:
  common.update(IPI_SAME_QUESTION_ACTUAL8B='1',WORKSHOP_RAG_EVIDENCE_PATH=str(root/'service-evidence.json'),
   AI_PROVIDER='ollama',JUDGE_PROVIDER='ollama',OLLAMA_MODEL='llama3.1:8b',JUDGE_MODEL='llama3.1:8b',
   OLLAMA_BASE_URL='http://127.0.0.1:11434',JUDGE_BASE_URL='http://127.0.0.1:11434',TRANSFORMERS_OFFLINE='1',
   WORKSHOP_RAG_ACTUAL_EMBEDDING='1',JWT_SECRET=uuid.uuid4().hex+uuid.uuid4().hex,SESSION_SECRET=uuid.uuid4().hex+uuid.uuid4().hex,
   HF_HUB_OFFLINE='1',SANDBOX_RUNNER_URL='http://127.0.0.1:1',SSRF_TARGET_URL='http://127.0.0.1:1',
   ROGUE_MCP_URL='http://127.0.0.1:1',MAILPIT_API_URL='http://127.0.0.1:1',MAILPIT_SMTP_HOST='127.0.0.1',MAILPIT_SMTP_PORT='1')
 env.update(common)
 with log_path.open('w') as log:
  child=subprocess.Popen([str(NODE),'--test','--test-reporter=tap',test_file],cwd=workspace,env=env,stdout=log,stderr=log,start_new_session=True)
  state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid)};state['runStatus']='test_running';persist()
  try:code=child.wait(timeout=300 if args.receipt_replay else 1200)
  except subprocess.TimeoutExpired:stop_child();raise RuntimeError('IPI receipt replay timed out' if args.receipt_replay else 'IPI same-question actual8B timed out')
 if code:raise RuntimeError(f'IPI qualification failed ({code}); inspect retained tests.log')
 evidence_file=root/('receipt-replay-evidence.json' if args.receipt_replay else 'service-evidence.json')
 state['runStatus']='passed';state['resultSha256']=digest(log_path);state['serviceEvidenceSha256']=digest(evidence_file);persist()
except BaseException as error:
 if creation_attempted:
  try:
   diagnostic=subprocess.run(docker+['logs','--tail','120',container],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20)
   (root/'container.log').write_text(diagnostic.stdout);os.chmod(root/'container.log',0o600)
  except Exception as diagnostic_error:state['containerDiagnosticError']=type(diagnostic_error).__name__
 state.update({'runStatus':'failed','errorType':type(error).__name__,'resultSha256':digest(log_path)});persist();raise
finally:
 gate.protect_cleanup();errors=[];remove_code=None;absent=None
 try:stop_child()
 except Exception as error:errors.append('child:'+type(error).__name__)
 if creation_attempted:
  try:remove_code=subprocess.run(docker+['rm','-f','-v',container],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30).returncode
  except Exception as error:errors.append('remove:'+type(error).__name__)
 try:absent=exact_absence()
 except Exception as error:errors.append('absence:'+type(error).__name__)
 try:pgid_absent=not state.get('child') or not owned_group_members(state['child']['pgid'])
 except Exception as error:errors.append('pgid:'+type(error).__name__);pgid_absent=False
 state['cleanup']={'removeExitCode':remove_code,'containerAbsent':absent,'nodeBrowserPgidAbsent':pgid_absent,
  'errors':errors,'completedAt':datetime.now(timezone.utc).isoformat()}
 if state['runStatus']=='passed' and (errors or absent is not True or pgid_absent is not True or (creation_attempted and remove_code!=0)):state['runStatus']='failed';state['errorType']='CleanupFailed'
 persist()
print(json.dumps({'evidence':str(root),'status':state['runStatus'],'cleanup':state['cleanup']}),flush=True)
if state['runStatus']!='passed':raise SystemExit(1)
