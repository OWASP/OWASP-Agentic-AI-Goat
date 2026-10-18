#!/usr/bin/env python3
"""Single-use owned PG18 gate for the catalog provenance integration release candidates."""
import argparse, fcntl, hashlib, json, os, shutil, signal, subprocess, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from native_source_provenance import verify_source_copy
from sensitive_info_recovery_safety import SignalGate

EXPECTED_DOCKER='unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
OWNER='/root/secureshop_architecture'
SOURCE=Path(__file__).resolve().parents[2]
NODE_BIN=Path('/Users/averma5/.dvaia/runtimes/node-v26.8.2-darwin-arm64/bin')
TRACKED=[
 'tests/postgres/run-workshop-catalog-provenance-release-isolated.py',
 'tests/postgres/workshopCatalogProvenanceRelease.integration.test.js',
 'tests/postgres/native_source_provenance.py','tests/postgres/sensitive_info_recovery_safety.py',
 'tests/workshopCatalogProvenanceIntegrationPackage.test.js',
 'docs/modernization/drafts/workshop-catalog-provenance-integration-manifest-2026-09-14.json',
 'docs/modernization/drafts/secureshop-persona-inbox-catalog-transition.sql',
 'docs/modernization/drafts/workshop-catalog-field-provenance.sql',
 'docs/modernization/drafts/workshop-catalog-field-provenance-persona-adoption.sql',
 'docs/modernization/drafts/catalogDefaultProvenance.candidate.js',
 'docs/modernization/drafts/workshopPlatformSeed.provenance.candidate.js',
 'docs/modernization/drafts/workshopPlatformSeed.provenance.integration.candidate.js',
 'docs/modernization/drafts/workshopConfigProvenanceIntegration.candidate.js',
 'docs/modernization/drafts/secureshopPersonaCatalogCurriculumCandidate.js',
 'docs/modernization/drafts/secureshopPersonaInboxActivationCandidate.js',
 'server/database/postgres/workshopPlatformSeed.js','server/database/postgres/workshopConfigRepository.js',
 'server/database/postgres/workshopPlatformSupport.js','server/database/postgres/identityRepository.js',
 'server/database/postgres/index.js','server/config/workshopCatalog.js','server/config/secureshopCurriculum.js',
 'server/services/secureshopBoundApplication.js','server/services/secureshopBoundReviewComposition.js',
 'db/postgres/migrate.js','db/postgres/workshopChallengeFixtures.js',
 'server/data/workshopHints.js','server/data/xssWorkshopSolutions.js',
 'server/data/promptInjectionSolutions.js','server/data/indirectPromptInjectionSolutions.js',
 'server/data/csrfWorkshopSolutions.js','server/data/sensitiveInfoSolutions.js',
 'server/data/supplyChainSolutions.js','server/data/excessiveAgencySolutions.js',
 'server/data/mcpWorkshopSolutions.js','server/data/sqlInjectionWorkshopSolutions.js',
 'server/data/nosqlInjectionWorkshopSolutions.js',
 'server/data/postgres/sqlInjectionWorkshopSolutions.js','server/data/postgres/nosqlInjectionWorkshopSolutions.js',
 'package.json','package-lock.json',
]
TRACKED += [str(path.relative_to(SOURCE)) for path in
 sorted((SOURCE/'db/postgres/identity-migrations').glob('*.sql'))]
parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True)
parser.add_argument('--grant-file',required=True);parser.add_argument('--grant-id',required=True);args=parser.parse_args()
if args.docker_host!=EXPECTED_DOCKER:raise SystemExit('the reviewed isolated PostgreSQL Docker daemon is required')
grant_path=Path(args.grant_file).resolve()
if grant_path!=(SOURCE/'tasks/native-verification-slot.json').resolve():raise SystemExit('the durable repository grant file is required')
evidence=Path(tempfile.mkdtemp(prefix='dvaia-workshop-catalog-release-'));os.chmod(evidence,0o700)
workspace=evidence/'source';workspace.mkdir();container=f'dvaia-workshop-catalog-release-{uuid.uuid4().hex[:12]}'
ownership_path=evidence/'ownership.json';result_path=evidence/'result.log';result_path.touch();os.chmod(result_path,0o600)
base_env={key:os.environ[key] for key in ('PATH','HOME','TMPDIR') if key in os.environ}
base_env['PATH']=f'{NODE_BIN}:{base_env.get("PATH","")}'
docker=['docker','--host',args.docker_host]
state={'owner':OWNER,'grantId':args.grant_id,'dockerHost':args.docker_host,'container':container,
 'evidence':str(evidence),'launcherPid':os.getpid(),'consumerPid':os.getpid(),'ownerHandle':None,
 'createdAt':datetime.now(timezone.utc).isoformat(),'runStatus':'preparing','cleanup':None}
def write_state():ownership_path.write_text(json.dumps(state,indent=2)+'\n');os.chmod(ownership_path,0o600)
def run(command,**kwargs):kwargs.setdefault('timeout',90);return subprocess.run(command,check=True,env=kwargs.pop('env',base_env),**kwargs)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def exact_absence():
 q=subprocess.run(docker+['ps','-a','--filter',f'name=^/{container}$','--format','{{.Names}}'],env=base_env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=30)
 if q.returncode:raise RuntimeError('exact-name container query failed')
 return not q.stdout.strip()
child=None;creation_attempted=False;gate=SignalGate();signal.signal(signal.SIGTERM,gate.handler);signal.signal(signal.SIGINT,gate.handler)
def stop_child():
 global child
 if child is not None and child.poll() is None:
  os.killpg(os.getpgid(child.pid),signal.SIGTERM)
  try:child.wait(timeout=5)
  except subprocess.TimeoutExpired:os.killpg(os.getpgid(child.pid),signal.SIGKILL);child.wait(timeout=5)
write_state()
if run([str(NODE_BIN/'node'),'--version'],stdout=subprocess.PIPE,text=True).stdout.strip()!='v26.8.2':raise RuntimeError('managed Node 26.8.2 is required')
if not exact_absence():raise RuntimeError('owned container name unexpectedly exists')
def register_owner():
 for _ in range(600):
  with grant_path.open() as f:fcntl.flock(f.fileno(),fcntl.LOCK_SH);value=json.load(f)
  handle=value.get('ownerHandle')
  if value.get('grantId')==args.grant_id and value.get('consumerPid')==os.getpid() and isinstance(handle,int) and handle>0 and handle!=os.getpid():state.update({'ownerHandle':handle,'runStatus':'owner_registered'});write_state();return
  time.sleep(.1)
 raise RuntimeError('actual exec session owner handle was not registered before Docker')
def ignored(_directory,names):
 denied={'.git','node_modules','build','logs','uploads','sensitive_files','workshop_data','vector-indexes','coverage','.cache','__pycache__'}
 return [name for name in names if name in denied or name.startswith('.env') or any(name.endswith(s) for s in ('.db','.db-wal','.db-shm','.sqlite','.sqlite3','.log'))]
def prepare(granted_hashes):
 for directory in ('server','db','tests','docs'):shutil.copytree(SOURCE/directory,workspace/directory,ignore=ignored)
 for name in ('package.json','package-lock.json'):shutil.copy2(SOURCE/name,workspace/name)
 (workspace/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
 source_hashes=verify_source_copy(SOURCE,workspace,TRACKED,granted=granted_hashes)
 state['sourceHashes']=source_hashes
 state['copiedSourceHashes']={name:digest(workspace/name) for name in TRACKED}
 manifest=json.loads((workspace/'docs/modernization/drafts/workshop-catalog-provenance-integration-manifest-2026-09-14.json').read_text())
 expected_outputs=manifest.get('generatedProductionOutputs')
 if manifest.get('status')!='draft_unregistered_unpromoted' or not isinstance(expected_outputs,dict) or not expected_outputs:
  raise RuntimeError('catalog integration manifest is absent or incomplete')
 shutil.copy2(workspace/'server/database/postgres/workshopPlatformSeed.js',workspace/'server/database/postgres/workshopPlatformSeed.pre-provenance.js')
 shutil.copy2(workspace/'server/config/secureshopCurriculum.js',workspace/'server/config/secureshopCurriculum.pre-provenance.js')
 for source,target in (
  ('secureshop-persona-inbox-catalog-transition.sql','0047_secureshop_persona_inbox_catalog.sql'),
  ('workshop-catalog-field-provenance.sql','0048_workshop_catalog_field_provenance.sql'),
  ('workshop-catalog-field-provenance-persona-adoption.sql','0049_workshop_catalog_persona_adoption.sql')):
  shutil.copy2(workspace/'docs/modernization/drafts'/source,workspace/'db/postgres/identity-migrations'/target)
 program="""const fs=require('fs');
const activation=require('./docs/modernization/drafts/secureshopPersonaInboxActivationCandidate');
const curriculum=require('./docs/modernization/drafts/secureshopPersonaCatalogCurriculumCandidate');
const config=require('./docs/modernization/drafts/workshopConfigProvenanceIntegration.candidate');
const read=p=>fs.readFileSync(p,'utf8');
const paths={application:'server/services/secureshopBoundApplication.js',composition:'server/services/secureshopBoundReviewComposition.js',curriculum:'server/config/secureshopCurriculum.js'};
const activated=activation.buildCandidates(Object.fromEntries(Object.entries(paths).map(([k,p])=>[k,read(p)])));
fs.writeFileSync(paths.application,activated.application);fs.writeFileSync(paths.composition,activated.composition);
fs.writeFileSync(paths.curriculum,curriculum.buildCandidate(activated.curriculum));
fs.copyFileSync('docs/modernization/drafts/catalogDefaultProvenance.candidate.js','server/database/postgres/catalogDefaultProvenance.js');
fs.copyFileSync('docs/modernization/drafts/workshopPlatformSeed.provenance.candidate.js','server/database/postgres/workshopPlatformSeedCore.js');
fs.copyFileSync('docs/modernization/drafts/workshopPlatformSeed.provenance.integration.candidate.js','server/database/postgres/workshopPlatformSeed.js');
const configPath='server/database/postgres/workshopConfigRepository.js';fs.writeFileSync(configPath,config.buildCandidate(read(configPath)));"""
 run([str(NODE_BIN/'node'),'-e',program],cwd=workspace)
 actual_outputs={name:digest(workspace/name) for name in expected_outputs}
 if actual_outputs!=expected_outputs:raise RuntimeError('generated catalog integration outputs differ from the frozen manifest')
 expected_staged={
  '0047_secureshop_persona_inbox_catalog.sql':manifest['ordering'][1]['sha256'],
  '0048_workshop_catalog_field_provenance.sql':manifest['ordering'][2]['sha256'],
  '0049_workshop_catalog_persona_adoption.sql':manifest['ordering'][3]['sha256'],
 }
 actual_staged={name:digest(workspace/'db/postgres/identity-migrations'/name) for name in expected_staged}
 if actual_staged!=expected_staged:raise RuntimeError('staged catalog migration bytes differ from the frozen manifest')
 state['nodeVersion']='v26.8.2';state['generatedOutputHashes']=actual_outputs
 state['stagedMigrationHashes']=actual_staged;write_state()
cleanup_failed=False
with grant_path.open('r+') as f:
 fcntl.flock(f.fileno(),fcntl.LOCK_EX);grant=json.load(f)
 if grant.get('grantId')!=args.grant_id or grant.get('owner')!=OWNER or grant.get('status')!='granted' or grant.get('allowedLaunches')!=1 or grant.get('dockerHost')!=EXPECTED_DOCKER:raise RuntimeError('single-use catalog integration grant is absent, mismatched, or consumed')
 if not isinstance(grant.get('sourceHashes'),dict) or not grant['sourceHashes']:raise RuntimeError('nonempty exact grant source inventory is required')
 grant.update({'status':'consumed','consumedAt':datetime.now(timezone.utc).isoformat(),
  'launcherPid':os.getpid(),'consumerPid':os.getpid(),'ownerHandle':None,'container':container,
  'evidence':str(evidence),'runStatus':'preparing'})
 f.seek(0);json.dump(grant,f,indent=2);f.write('\n');f.truncate();f.flush();os.fsync(f.fileno())
try:
 register_owner();prepare(grant['sourceHashes']);creation_attempted=True;state['containerCreationAttempted']=True;write_state()
 run(docker+['run','--detach','--name',container,'--tmpfs','/var/lib/postgresql:rw,size=402653184','-e','POSTGRES_USER=persona_catalog_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432','postgres:18','-c','shared_buffers=16MB','-c','max_connections=40','-c','max_wal_size=24MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL)
 state['runStatus']='container_started';write_state();details=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]
 if details.get('Mounts'):raise RuntimeError('owned PostgreSQL unexpectedly has host mounts')
 port=int(run(docker+['port',container,'5432'],stdout=subprocess.PIPE,text=True).stdout.strip().rsplit(':',1)[1])
 for _ in range(120):
  q=subprocess.run(['psql','-h','127.0.0.1','-p',str(port),'-U','persona_catalog_admin','-d','postgres','-Atqc','SELECT 1'],env=base_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
  if q.returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('owned PostgreSQL did not become TCP SQL-ready')
 admin=['psql','-h','127.0.0.1','-p',str(port),'-U','persona_catalog_admin','-d','postgres','-v','ON_ERROR_STOP=1']
 for role in ('dvaia_identity_migration','dvaia_identity_runtime'):run(admin+['-c',f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],stdout=subprocess.DEVNULL)
 urls={}
 for variant in ('fresh','populated'):
  db=f'dvaia_test_secureshop_persona_catalog_{variant}';run(admin+['-c',f'CREATE DATABASE {db} OWNER dvaia_identity_migration'],stdout=subprocess.DEVNULL);run(admin+['-c',f'REVOKE CONNECT ON DATABASE {db} FROM PUBLIC; GRANT CONNECT ON DATABASE {db} TO dvaia_identity_migration,dvaia_identity_runtime'],stdout=subprocess.DEVNULL)
  urls[variant]={'migration':f'postgresql://{quote("dvaia_identity_migration")}@127.0.0.1:{port}/{db}','runtime':f'postgresql://{quote("dvaia_identity_runtime")}@127.0.0.1:{port}/{db}'}
 env=dict(base_env,NODE_ENV='test',PLATFORM_DATABASE_ENGINE='postgres',PG_TEST_DISPOSABLE='yes',DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace))
 for variant in ('fresh','populated'):
  prefix=f'PG_WORKSHOP_CATALOG_RELEASE_{variant.upper()}_';env[prefix+'MIGRATION_URL']=urls[variant]['migration'];env[prefix+'RUNTIME_URL']=urls[variant]['runtime']
 with result_path.open('w') as log:
  os.chmod(result_path,0o600);child=subprocess.Popen(['node','--test','--test-reporter=tap','tests/postgres/workshopCatalogProvenanceRelease.integration.test.js'],cwd=workspace,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);state.update({'testPid':child.pid,'runStatus':'test_running'});write_state()
  try:code=child.wait(timeout=100)
  except subprocess.TimeoutExpired:stop_child();raise RuntimeError('catalog provenance integration timed out')
 if code:raise RuntimeError(f'catalog provenance integration failed ({code})')
 state.update({'resultSha256':digest(result_path),'runStatus':'passed'});write_state()
except BaseException as error:
 state.update({'runStatus':'failed','errorType':type(error).__name__,'resultSha256':digest(result_path)})
 if creation_attempted:
  try:
   details=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0];state['containerFailure']={'oomKilled':details['State'].get('OOMKilled'),'exitCode':details['State'].get('ExitCode')}
   logs=subprocess.run(docker+['logs','--tail','80',container],env=base_env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20);(evidence/'container.log').write_text(logs.stdout);os.chmod(evidence/'container.log',0o600)
  except Exception as diagnostic:state['diagnosticError']=type(diagnostic).__name__
 write_state();raise
finally:
 gate.protect_cleanup();errors=[];remove_code=None;absent=None
 try:stop_child()
 except Exception as error:errors.append(f'child:{type(error).__name__}')
 if creation_attempted:
  try:remove_code=subprocess.run(docker+['rm','-f','-v',container],env=base_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30).returncode
  except Exception as error:errors.append(f'remove:{type(error).__name__}')
 try:absent=exact_absence()
 except Exception as error:errors.append(f'absence:{type(error).__name__}')
 state['cleanup']={'removeExitCode':remove_code,'containerAbsent':absent,'containerCleanupDebt':absent is not True,'errors':errors,'signals':gate.received,'completedAt':datetime.now(timezone.utc).isoformat()};cleanup_failed=bool(errors or absent is not True or (creation_attempted and remove_code!=0))
 if state['runStatus']=='passed' and cleanup_failed:state.update({'runStatus':'failed','errorType':'CleanupFailed'})
 write_state()
 try:
  with grant_path.open('r+') as f:
   fcntl.flock(f.fileno(),fcntl.LOCK_EX);grant=json.load(f)
   if grant.get('grantId')==args.grant_id:grant.update({'runStatus':state['runStatus'],'terminalAt':datetime.now(timezone.utc).isoformat(),'cleanup':state['cleanup'],'evidence':str(evidence)});f.seek(0);json.dump(grant,f,indent=2);f.write('\n');f.truncate();f.flush();os.fsync(f.fileno())
 except Exception:pass
print(evidence,flush=True)
if cleanup_failed:raise RuntimeError('owned qualifier cleanup is incomplete')
