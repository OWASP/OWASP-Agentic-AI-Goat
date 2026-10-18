#!/usr/bin/env python3
"""Single-use owned PG18 gate for the workshop catalog field provenance candidate."""
import argparse, fcntl, hashlib, json, os, shutil, signal, subprocess, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from sensitive_info_recovery_safety import SignalGate

EXPECTED_DOCKER='unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
OWNER='/root/secureshop_architecture'
SOURCE=Path(__file__).resolve().parents[2]
NODE_BIN=Path('/Users/averma5/.dvaia/runtimes/node-v26.8.2-darwin-arm64/bin')
parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True)
parser.add_argument('--grant-file',required=True);parser.add_argument('--grant-id',required=True);args=parser.parse_args()
if args.docker_host!=EXPECTED_DOCKER:raise SystemExit('the reviewed isolated PostgreSQL Docker daemon is required')
grant_path=Path(args.grant_file).resolve()
if grant_path!=(SOURCE/'tasks/native-verification-slot.json').resolve():raise SystemExit('the durable repository grant file is required')
evidence=Path(tempfile.mkdtemp(prefix='dvaia-workshop-catalog-provenance-'));os.chmod(evidence,0o700)
workspace=evidence/'source';workspace.mkdir();container=f'dvaia-workshop-catalog-provenance-{uuid.uuid4().hex[:12]}'
ownership_path=evidence/'ownership.json';result_path=evidence/'result.log';result_path.touch();os.chmod(result_path,0o600)
base_env={key:os.environ[key] for key in ('PATH','HOME','TMPDIR') if key in os.environ}
base_env['PATH']=f'{NODE_BIN}:{base_env.get("PATH","")}'
docker=['docker','--host',args.docker_host]
state={'owner':OWNER,'grantId':args.grant_id,'dockerHost':args.docker_host,'container':container,
 'evidence':str(evidence),'launcherPid':os.getpid(),'ownerHandle':None,
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
  if value.get('grantId')==args.grant_id and value.get('launcherPid')==os.getpid() and isinstance(handle,int) and handle>0 and handle!=os.getpid():state.update({'ownerHandle':handle,'runStatus':'owner_registered'});write_state();return
  time.sleep(.1)
 raise RuntimeError('actual exec session owner handle was not registered before Docker')
def ignored(_directory,names):
 denied={'.git','node_modules','build','logs','uploads','sensitive_files','workshop_data','vector-indexes','coverage','.cache','__pycache__'}
 return [name for name in names if name in denied or name.startswith('.env') or any(name.endswith(s) for s in ('.db','.db-wal','.db-shm','.sqlite','.sqlite3','.log'))]
def prepare():
 for directory in ('server','db','tests','docs'):shutil.copytree(SOURCE/directory,workspace/directory,ignore=ignored)
 (workspace/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
 target=workspace/'db/postgres/identity-migrations/9999_workshop_catalog_field_provenance.sql'
 shutil.copy2(workspace/'docs/modernization/drafts/workshop-catalog-field-provenance.sql',target)
 shutil.copy2(workspace/'docs/modernization/drafts/catalogDefaultProvenance.candidate.js',workspace/'server/database/postgres/catalogDefaultProvenance.js')
 program="const fs=require('fs'),c=require('./docs/modernization/drafts/workshopConfigProvenanceIntegration.candidate');const p='server/database/postgres/workshopConfigRepository.js';fs.writeFileSync(p,c.buildCandidate(fs.readFileSync(p,'utf8')));"
 run([str(NODE_BIN/'node'),'-e',program],cwd=workspace)
 inventory=set(['docs/modernization/drafts/workshop-catalog-field-provenance.sql','docs/modernization/drafts/catalogDefaultProvenance.candidate.js','docs/modernization/drafts/workshopPlatformSeed.provenance.candidate.js','docs/modernization/drafts/workshopConfigProvenanceIntegration.candidate.js','server/database/postgres/catalogDefaultProvenance.js','server/database/postgres/workshopConfigRepository.js','server/database/postgres/workshopPlatformSupport.js','server/database/postgres/index.js','server/config/workshopCatalog.js','server/data/xssWorkshopSolutions.js','tests/postgres/workshopCatalogFieldProvenance.integration.test.js','tests/postgres/run-workshop-catalog-field-provenance-isolated.py'])
 inventory.update(str(p.relative_to(workspace)) for p in workspace.glob('db/postgres/identity-migrations/*.sql'))
 state['nodeVersion']='v26.8.2';state['sourceSha256']={name:digest(workspace/name) for name in sorted(inventory)};write_state()
cleanup_failed=False
with grant_path.open('r+') as f:
 fcntl.flock(f.fileno(),fcntl.LOCK_EX);grant=json.load(f)
 if grant.get('grantId')!=args.grant_id or grant.get('owner')!=OWNER or grant.get('status')!='granted' or grant.get('allowedLaunches')!=1 or grant.get('dockerHost')!=EXPECTED_DOCKER:raise RuntimeError('single-use catalog provenance grant is absent, mismatched, or consumed')
 grant.update({'status':'consumed','consumedAt':datetime.now(timezone.utc).isoformat(),'launcherPid':os.getpid(),'ownerHandle':None,'container':container,'evidence':str(evidence),'runStatus':'preparing'})
 grant['consumerPid']=os.getpid()
 f.seek(0);json.dump(grant,f,indent=2);f.write('\n');f.truncate();f.flush();os.fsync(f.fileno())
try:
 register_owner();prepare();creation_attempted=True;state['containerCreationAttempted']=True;write_state()
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
 for variant in ('fresh',):
  db=f'dvaia_test_workshop_catalog_provenance_{variant}';run(admin+['-c',f'CREATE DATABASE {db} OWNER dvaia_identity_migration'],stdout=subprocess.DEVNULL);run(admin+['-c',f'REVOKE CONNECT ON DATABASE {db} FROM PUBLIC; GRANT CONNECT ON DATABASE {db} TO dvaia_identity_migration,dvaia_identity_runtime'],stdout=subprocess.DEVNULL)
  urls[variant]={'migration':f'postgresql://{quote("dvaia_identity_migration")}@127.0.0.1:{port}/{db}','runtime':f'postgresql://{quote("dvaia_identity_runtime")}@127.0.0.1:{port}/{db}'}
 env=dict(base_env,NODE_ENV='test',PLATFORM_DATABASE_ENGINE='postgres',PG_TEST_DISPOSABLE='yes',DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace))
 env['PG_CATALOG_PROVENANCE_MIGRATION_URL']=urls['fresh']['migration'];env['PG_CATALOG_PROVENANCE_RUNTIME_URL']=urls['fresh']['runtime']
 with result_path.open('w') as log:
  os.chmod(result_path,0o600);child=subprocess.Popen(['node','--test','--test-reporter=tap','tests/postgres/workshopCatalogFieldProvenance.integration.test.js'],cwd=workspace,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);state.update({'testPid':child.pid,'runStatus':'test_running'});write_state()
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
