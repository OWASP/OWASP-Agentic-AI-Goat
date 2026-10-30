#!/usr/bin/env python3
"""One-use PG18 copied-loader gate for draft identity0050 and MCP0004."""

import argparse, hashlib, json, os, shutil, subprocess, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path

parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True);parser.add_argument('--grant-id',required=True)
parser.add_argument('--grant-file',default='tasks/native-verification-slot.json');parser.add_argument('--owner-handle-file',required=True)
args=parser.parse_args();source=Path(__file__).resolve().parents[2];handshake=Path(args.owner_handle_file).resolve()
print(f'WAITING_OWNER_HANDLE {handshake}',flush=True);deadline=time.monotonic()+60;owner_text=''
while time.monotonic()<deadline:
 try: owner_text=handshake.read_text().strip()
 except FileNotFoundError: pass
 if owner_text: break
 time.sleep(.1)
if not owner_text.isdecimal() or int(owner_text)<=0: raise SystemExit('owner handle handshake timed out or invalid')
owner_handle=int(owner_text);grant_path=(source/args.grant_file).resolve();docker=['docker','--host',args.docker_host]
evidence_parent=Path.home()/'.owasp-ai-goat'/'native-verification';evidence_parent.mkdir(parents=True,exist_ok=True);os.chmod(evidence_parent,0o700)
root=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-mcp-owned-runtime-migrations-',dir=evidence_parent));os.chmod(root,0o700);workspace=root/'source'
def ignore(_directory,names):
 denied={'.git','node_modules','build','logs','uploads','sensitive_files','workshop_data','vector-indexes','coverage','.cache','__pycache__'}
 return [name for name in names if name in denied or name.startswith('.env') or name.endswith(('.db','.db-wal','.db-shm','.log'))]
for directory in ['server','db','tests','docs']: shutil.copytree(source/directory,workspace/directory,ignore=ignore)
for filename in ['package.json','package-lock.json']: shutil.copy2(source/filename,workspace/filename)
(workspace/'node_modules').symlink_to(source/'node_modules',target_is_directory=True)
tracked=[
 'docs/modernization/drafts/0050_mcp_conversation_history.sql','docs/modernization/drafts/0004_mcp_owned_resources.sql',
 'docs/modernization/drafts/secureshop-persona-inbox-catalog-transition.sql',
 'docs/modernization/drafts/workshop-catalog-field-provenance.sql',
 'docs/modernization/drafts/workshop-catalog-field-provenance-persona-adoption.sql',
 'tests/postgres/mcpOwnedRuntimeMigrations.integration.test.js','tests/postgres/run-mcp-owned-runtime-migrations-isolated.py',
 'tests/mcpOwnedRuntimeMigrationDraft.test.js',
 'tests/postgres/helpers/ownedMigrationStaging.js',
 'tests/postgres/ownedMigrationStaging.test.js',
 'server/database/postgres/index.js','server/database/postgres/workshopSupport.js','server/database/postgres/identityRepository.js',
 'server/database/postgres/identityValidation.js','server/database/postgres/mcpWorkshopDb.js',
 'server/database/postgres/mcpRequestRepository.js','server/database/postgres/mcpConversationRepository.js',
 'server/database/postgres/mcpResourceRepository.js','server/database/postgres/workshopProgressRepository.js',
 'server/database/postgres/workshopPlatformSeed.js','server/services/postgresIdentityAdapter.js',
 'server/services/mcp/ownedResourceProduction.js','server/services/mcp/ownedResourceComposition.js',
 'server/services/mcp/ownedResourceApplication.js','server/services/mcp/ownedQualification.js',
 'server/services/mcp/ownedTargetClient.js','server/services/mcp/durableMailResources.js','server/services/mcp/platformSessionBinding.js',
 'server/services/mcp/sandboxShell.js','server/services/mcp/toolRegistry.js','db/postgres/migrate.js',
 'server/config/workshopCatalog.js','db/postgres/workshopChallengeFixtures.js','server/data/workshopHints.js',
 'server/data/mcpWorkshopSolutions.js','package.json','package-lock.json']
for pattern in ['server/services/mcp/**/*.js','server/database/postgres/*.js','server/config/*.js','server/data/*.js',
 'db/postgres/*.js','db/postgres/identity-migrations/*.sql','db/postgres/workshop-migrations/mcp/*.sql']:
 for path in sorted(source.glob(pattern)):
  name=str(path.relative_to(source))
  if name not in tracked: tracked.append(name)
digest=lambda path:hashlib.sha256(path.read_bytes()).hexdigest();ownership_path=root/'ownership.json'
suffix=uuid.uuid4().hex[:12];container='owasp-ai-goat-mcp-owned-runtime-migrations-'+suffix
ownership={'version':1,'owner':'/root/workshop_authenticity','ownerHandle':owner_handle,'launcherPid':os.getpid(),
 'grantId':args.grant_id,'dockerHost':args.docker_host,'evidence':str(root),'status':'prepared','container':container,
 'createdAt':datetime.now(timezone.utc).isoformat(),'sourceHashes':{name:digest(source/name) for name in tracked},
 'boundary':{'database':'one owned PostgreSQL18 container with separate identity/MCP databases and runtime/migration roles','model':'none','smtp':'controlled readiness stub; no delivery'}}
def persist(path,value):
 data=(json.dumps(value,indent=2,sort_keys=True)+'\n').encode();pending=path.with_suffix(path.suffix+'.pending')
 fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
 try: os.write(fd,data);os.fsync(fd)
 finally: os.close(fd)
 os.replace(pending,path)
def save(): persist(ownership_path,ownership)
def run(command,**kwargs): kwargs.setdefault('timeout',120);return subprocess.run(command,check=True,env=base_env,**kwargs)
def safe(error):
 if isinstance(error,subprocess.CalledProcessError): return {'type':type(error).__name__,'returnCode':error.returncode}
 if isinstance(error,subprocess.TimeoutExpired): return {'type':type(error).__name__,'stage':'timeout'}
 return {'type':type(error).__name__,'message':str(error)[:200]}
base_env={key:os.environ[key] for key in ['PATH','HOME','TMPDIR'] if key in os.environ}
base_env['PATH']=str(Path.home()/'.owasp-ai-goat/runtimes/node-v26.8.2-darwin-arm64/bin')+os.pathsep+base_env.get('PATH','')
save();lock=grant_path.with_suffix(grant_path.suffix+'.consume-lock')
try: lock.mkdir(mode=0o700)
except FileExistsError as error: raise RuntimeError('grant already being consumed') from error
try:
 grant=json.loads(grant_path.read_text())
 if grant.get('grantId')!=args.grant_id or grant.get('status')!='granted' or grant.get('owner')!='/root/workshop_authenticity' or grant.get('allowedLaunches')!=1 or grant.get('dockerHost')!=args.docker_host: raise RuntimeError('exact MCP migration grant required')
 frozen=grant.get('sourceHashes')
 if not isinstance(frozen,dict) or set(frozen)!=set(tracked): raise RuntimeError('grant must freeze exact source inventory')
 for name in tracked:
  if frozen[name]!=digest(source/name) or frozen[name]!=digest(workspace/name): raise RuntimeError(f'frozen source differs: {name}')
 now=datetime.now(timezone.utc).isoformat();grant.update(status='consumed',runStatus='running',consumedAt=now,ownerHandle=owner_handle,launcherPid=os.getpid(),evidence=str(root),container=container);persist(grant_path,grant)
 ownership.update(status='running',consumedAt=now);save()
finally: lock.rmdir()
attempted=False;child=None
try:
 info=json.loads(run(docker+['info','--format','{{json .}}'],capture_output=True,text=True,timeout=30).stdout)
 if info.get('Name')!='colima-owasp-ai-goat-pg-verify' or info.get('Architecture')!='aarch64': raise RuntimeError('exact Colima verification daemon required')
 if run(docker+['ps','-a','--filter',f'name=^{container}$','--format','{{.Names}}'],capture_output=True,text=True,timeout=20).stdout.strip(): raise RuntimeError('owned name not absent')
 attempted=True;run(docker+['run','--detach','--pull','never','--name',container,'--tmpfs','/var/lib/postgresql:rw,size=268435456',
  '-e','POSTGRES_USER=mcp_integration_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust',
  '-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432','postgres:18',
  '-c','shared_buffers=16MB','-c','max_connections=32','-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL)
 ownership['containerId']=run(docker+['inspect','--format','{{.Id}}',container],capture_output=True,text=True).stdout.strip();save()
 stable=0;deadline=time.monotonic()+30
 while time.monotonic()<deadline:
  probe=subprocess.run(docker+['exec',container,'pg_isready','-h','127.0.0.1','-U','mcp_integration_admin'],env=base_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3)
  stable=stable+1 if probe.returncode==0 else 0
  if stable>=3: break
  time.sleep(.25)
 else:
  startup_log=root/'postgres-startup.log';fd=os.open(startup_log,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(fd,'wb') as log:
   captured=subprocess.run(docker+['logs','--tail','200',container],env=base_env,stdout=log,stderr=subprocess.STDOUT,timeout=20)
  ownership['postgresStartupLog']={'sha256':digest(startup_log),'byteCount':startup_log.stat().st_size,
   'mode':oct(startup_log.stat().st_mode&0o777),'dockerLogsReturnCode':captured.returncode};save()
  raise RuntimeError('PostgreSQL not stably ready')
 port=int(run(docker+['port',container,'5432/tcp'],capture_output=True,text=True).stdout.strip().rsplit(':',1)[1])
 psql=['psql','-h','127.0.0.1','-p',str(port),'-U','mcp_integration_admin','-d','postgres','-v','ON_ERROR_STOP=1']
 for role in ['dvaia_identity_migration','dvaia_identity_runtime','dvaia_mcp_migration','dvaia_mcp_runtime']:
  run(psql+['-c',f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],stdout=subprocess.DEVNULL)
 dbs={'identity':'dvaia_identity_migration','mcp':'dvaia_mcp_migration'}
 for label,owner in dbs.items():
  name=f'owasp_ai_goat_test_mcp_integration_{label}_{suffix}';run(psql+['-c',f'CREATE DATABASE {name} OWNER {owner}'],stdout=subprocess.DEVNULL)
  runtime=f'dvaia_{label}_runtime';run(psql+['-c',f'REVOKE CONNECT ON DATABASE {name} FROM PUBLIC; GRANT CONNECT ON DATABASE {name} TO {owner},{runtime}'],stdout=subprocess.DEVNULL)
 urls={label:{kind:f'postgresql://dvaia_{label}_{kind}@127.0.0.1:{port}/owasp_ai_goat_test_mcp_integration_{label}_{suffix}' for kind in ['runtime','migration']} for label in dbs}
 env=dict(base_env,NODE_ENV='test',PG_TEST_DISPOSABLE='yes',AWS_EC2_METADATA_DISABLED='true',
  PG_MCP_INTEGRATION_IDENTITY_RUNTIME_URL=urls['identity']['runtime'],PG_MCP_INTEGRATION_IDENTITY_MIGRATION_URL=urls['identity']['migration'],
  PG_MCP_INTEGRATION_RUNTIME_URL=urls['mcp']['runtime'],PG_MCP_INTEGRATION_MIGRATION_URL=urls['mcp']['migration'])
 result=root/'result.log';fd=os.open(result,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as log:
  log.write('HOST_NODE_VERSION='+run(['node','--version'],capture_output=True,text=True).stdout.strip()+'\n');log.flush()
  child=subprocess.Popen(['node','--test','--test-reporter=tap','tests/postgres/mcpOwnedRuntimeMigrations.integration.test.js'],cwd=workspace,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  ownership['testPid']=child.pid;save();code=child.wait(timeout=240)
 ownership.update(testExitCode=code,resultSha256=digest(result));print(f'MCP migration gate terminal rc={code}; private result {result}',flush=True)
 if code: raise RuntimeError('MCP migration qualification failed')
 ownership['status']='terminal_pass';save()
except Exception as error:
 ownership['status']='terminal_fail';ownership['failure']=safe(error);save()
finally:
 cleanup=[]
 if child is not None and child.poll() is None:
  try: child.terminate();child.wait(timeout=5)
  except Exception as error: cleanup.append({'stage':'test-stop','error':safe(error)})
 try: remove=subprocess.run(docker+['rm','--force',container],env=base_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30) if attempted else None
 except Exception as error: cleanup.append({'stage':'container-remove','error':safe(error)});remove=None
 try: query=subprocess.run(docker+['ps','-a','--filter',f'name=^{container}$','--format','{{.Names}}'],env=base_env,capture_output=True,text=True,timeout=20)
 except Exception as error: cleanup.append({'stage':'absence-query','error':safe(error)});query=None
 absent=query is not None and query.returncode==0 and not query.stdout.strip();clean=not cleanup and absent and (remove is None or remove.returncode==0)
 ownership['cleanup']={'errors':cleanup,'removeReturnCode':None if remove is None else remove.returncode,'absenceQueryReturnCode':None if query is None else query.returncode,'exactAbsent':absent}
 prior=ownership['status'];ownership['status']='terminal_pass_cleaned' if prior=='terminal_pass' and clean else 'terminal_fail';ownership['completedAt']=datetime.now(timezone.utc).isoformat();save()
 try:
  grant=json.loads(grant_path.read_text())
  if grant.get('grantId')==args.grant_id and grant.get('status')=='consumed' and grant.get('ownerHandle')==owner_handle:
   grant.update(runStatus='terminal_pass' if ownership['status']=='terminal_pass_cleaned' else 'terminal_fail',completedAt=ownership['completedAt'],cleanup=ownership['cleanup'],resultSha256=ownership.get('resultSha256'),containerId=ownership.get('containerId'));persist(grant_path,grant)
 except Exception as error: ownership['grantUpdateError']=safe(error);save()
 print(f'MCP migration evidence retained: {root}',flush=True)
if ownership['status']!='terminal_pass_cleaned': raise RuntimeError(str(ownership.get('failure') or 'cleanup not proven'))
