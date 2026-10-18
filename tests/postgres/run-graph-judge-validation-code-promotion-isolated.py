#!/usr/bin/env python3
"""One-use PG18 registered-loader/replay gate for reserved identity migration 0046."""

import argparse, hashlib, json, os, shutil, subprocess, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path

parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True);parser.add_argument('--grant-id',required=True)
parser.add_argument('--grant-file',default='tasks/native-verification-slot.json');parser.add_argument('--owner-handle');parser.add_argument('--owner-handle-file')
args=parser.parse_args();source=Path(__file__).resolve().parents[2]
if bool(args.owner_handle)==bool(args.owner_handle_file): raise SystemExit('supply exactly one owner handle or handshake file')
if args.owner_handle_file:
 handshake=Path(args.owner_handle_file).resolve();print(f'WAITING_OWNER_HANDLE {handshake}',flush=True);deadline=time.monotonic()+60
 while time.monotonic()<deadline:
  try:
   supplied=handshake.read_text().strip()
   if supplied: break
  except FileNotFoundError: pass
  time.sleep(.1)
 else: raise SystemExit('owner handle handshake timed out')
else: supplied=args.owner_handle
if not supplied.isdecimal() or int(supplied)<=0: raise SystemExit('owner handle must be the positive exec session ID')
owner_handle=int(supplied);grant_path=(source/args.grant_file).resolve() if not Path(args.grant_file).is_absolute() else Path(args.grant_file)
grant_lock=grant_path.with_suffix(grant_path.suffix+'.consume-lock');docker=['docker','--host',args.docker_host]
evidence_parent=Path.home()/'.dvaia'/'native-verification';evidence_parent.mkdir(parents=True,exist_ok=True);os.chmod(evidence_parent,0o700)
root=Path(tempfile.mkdtemp(prefix='dvaia-graph-judge-validation-promotion-',dir=evidence_parent));os.chmod(root,0o700);workspace=root/'source'
def ignore(_directory,names):
 denied={'.git','node_modules','build','logs','uploads','sensitive_files','workshop_data','vector-indexes','coverage','.cache','__pycache__'}
 return [name for name in names if name in denied or name.startswith('.env') or any(name.endswith(s) for s in ['.db','.db-wal','.db-shm','.db-journal','.sqlite','.sqlite3','.log'])]
for directory in ['server','db','tests','docs']: shutil.copytree(source/directory,workspace/directory,ignore=ignore)
for filename in ['package.json','package-lock.json']: shutil.copy2(source/filename,workspace/filename)
(workspace/'node_modules').symlink_to(source/'node_modules',target_is_directory=True)
base_env={key:os.environ[key] for key in ['PATH','HOME','TMPDIR'] if key in os.environ};managed=Path.home()/'.dvaia/runtimes/node-v26.8.2-darwin-arm64/bin';base_env['PATH']=str(managed)+os.pathsep+base_env.get('PATH','')
suffix=uuid.uuid4().hex[:12];container='dvaia-graph-judge-validation-promotion-'+suffix
tracked=['docs/modernization/drafts/graph-judge-validation-code.sql','db/postgres/identity-migrations/0016_graph_judge_trace_metadata.sql',
 'server/agent-runtime/objectiveJudge.js','server/agent-runtime/runTraceStore.js','server/agent-runtime/runCoordinator.js',
 'server/agent-runtime/postgresRunLedger.js','server/agent-runtime/judgeErrors.js',
 'server/database/postgres/index.js','server/database/postgres/identityRepository.js','server/database/postgres/identityValidation.js',
 'db/postgres/migrate.js',
 'tests/graphJudgeValidationCodeDraft.test.js','tests/postgres/graphJudgeValidationCodePromotion.integration.test.js',
 'tests/postgres/run-graph-judge-validation-code-promotion-isolated.py','package.json','package-lock.json']
tracked+=sorted(str(file.relative_to(source)) for file in (source/'db/postgres/identity-migrations').glob('*.sql'))
digest=lambda file:hashlib.sha256(file.read_bytes()).hexdigest();ownership_path=root/'ownership.json'
ownership={'version':1,'owner':'/root/workshop_authenticity','ownerHandle':owner_handle,'launcherPid':os.getpid(),
 'grantId':args.grant_id,'grantFile':str(grant_path),'dockerHost':args.docker_host,'evidence':str(root),'status':'prepared',
 'createdAt':datetime.now(timezone.utc).isoformat(),'container':container,'sourceHashes':{name:digest(source/name) for name in tracked},
 'boundary':{'database':'one disposable owned PostgreSQL 18 container','model':'none','migration':'staged registered 0046 in copied source only'}}
def persist(path,value):
 pending=path.with_suffix(path.suffix+'.pending');data=(json.dumps(value,indent=2,sort_keys=True)+'\n').encode()
 fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
 try: os.write(fd,data);os.fsync(fd)
 finally: os.close(fd)
 os.replace(pending,path)
def save(): persist(ownership_path,ownership)
def run(command,**kwargs): kwargs.setdefault('timeout',120);return subprocess.run(command,check=True,env=base_env,**kwargs)
def public_error(error):
 if isinstance(error,subprocess.CalledProcessError): return f'{type(error).__name__}: subprocess failed with return code {error.returncode}'
 if isinstance(error,subprocess.TimeoutExpired): return f'{type(error).__name__}: subprocess timed out'
 return f'{type(error).__name__}: {str(error)[:320]}'
save()
try: grant_lock.mkdir(mode=0o700)
except FileExistsError as error: raise RuntimeError('Native verification grant is already being consumed') from error
try:
 grant=json.loads(grant_path.read_text())
 if grant.get('grantId')!=args.grant_id or grant.get('status')!='granted' or grant.get('owner')!='/root/workshop_authenticity' or grant.get('allowedLaunches')!=1 or grant.get('dockerHost')!=args.docker_host: raise RuntimeError('Exact graph trace grant is required')
 frozen=grant.get('sourceHashes')
 if not isinstance(frozen,dict) or set(frozen)!=set(tracked): raise RuntimeError('Grant must freeze the exact graph trace source inventory')
 for name in tracked:
  if frozen[name]!=digest(source/name) or frozen[name]!=digest(workspace/name): raise RuntimeError(f'Frozen source differs for {name}')
 grant.update(status='consumed',runStatus='running',consumedAt=datetime.now(timezone.utc).isoformat(),ownerHandle=owner_handle,launcherPid=os.getpid(),evidence=str(root),container=container);persist(grant_path,grant)
 ownership.update(status='running',consumedAt=grant['consumedAt']);save()
finally: grant_lock.rmdir()
attempted=False;child=None
try:
 daemon=json.loads(run(docker+['info','--format','{{json .}}'],capture_output=True,text=True,timeout=30).stdout)
 if daemon.get('Name')!='colima-dvaia-pg-verify' or daemon.get('Architecture')!='aarch64': raise RuntimeError('Exact Colima verification daemon is required')
 prior=run(docker+['ps','-a','--filter',f'name=^{container}$','--format','{{.Names}}'],capture_output=True,text=True,timeout=20)
 if prior.stdout.strip(): raise RuntimeError('Owned PostgreSQL container name was not absent before use')
 attempted=True;run(docker+['run','--detach','--pull','never','--name',container,'--tmpfs','/var/lib/postgresql:rw,size=268435456',
  '-e','POSTGRES_USER=graph_validation_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1',
  '-p','127.0.0.1::5432','postgres:18','-c','shared_buffers=16MB','-c','max_connections=24','-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL)
 ownership['containerId']=run(docker+['inspect','--format','{{.Id}}',container],capture_output=True,text=True).stdout.strip();save()
 deadline=time.monotonic()+30;stable=0
 while time.monotonic()<deadline:
  probe=subprocess.run(docker+['exec',container,'pg_isready','-h','127.0.0.1','-U','graph_validation_admin'],env=base_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3)
  stable=stable+1 if probe.returncode==0 else 0
  if stable>=3: break
  time.sleep(.25)
 else: raise RuntimeError('Owned PostgreSQL did not remain SQL-ready')
 port=int(run(docker+['port',container,'5432/tcp'],capture_output=True,text=True,timeout=20).stdout.strip().rsplit(':',1)[1])
 psql=['psql','-h','127.0.0.1','-p',str(port),'-U','graph_validation_admin','-d','postgres','-v','ON_ERROR_STOP=1']
 for role in ['dvaia_identity_migration','dvaia_identity_runtime']: run(psql+['-c',f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],stdout=subprocess.DEVNULL)
 database='dvaia_test_graph_validation_promotion';run(psql+['-c',f'CREATE DATABASE {database} OWNER dvaia_identity_migration'],stdout=subprocess.DEVNULL)
 run(psql+['-c',f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO dvaia_identity_migration,dvaia_identity_runtime'],stdout=subprocess.DEVNULL)
 env=dict(base_env,NODE_ENV='test',PG_TEST_DISPOSABLE='yes',AWS_EC2_METADATA_DISABLED='true',
  PG_GRAPH_VALIDATION_PROMOTION_MIGRATION_URL=f'postgresql://dvaia_identity_migration@127.0.0.1:{port}/{database}',
  PG_GRAPH_VALIDATION_PROMOTION_RUNTIME_URL=f'postgresql://dvaia_identity_runtime@127.0.0.1:{port}/{database}')
 result=root/'result.log';fd=os.open(result,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as log:
  log.write('HOST_NODE_VERSION='+run(['node','--version'],capture_output=True,text=True).stdout.strip()+'\n');log.flush()
  child=subprocess.Popen(['node','--test','--test-reporter=tap','tests/postgres/graphJudgeValidationCodePromotion.integration.test.js'],cwd=workspace,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  ownership['testPid']=child.pid;save()
  try: code=child.wait(timeout=180)
  except subprocess.TimeoutExpired:
   child.terminate()
   try: child.wait(timeout=5)
   except subprocess.TimeoutExpired: child.kill();child.wait(timeout=5)
   raise RuntimeError('Graph Judge validation promotion qualification timed out')
 ownership.update(resultSha256=digest(result),testExitCode=code)
 print(f'Graph Judge validation promotion test terminal rc={code}; private result retained at {result}',flush=True)
 if code: raise RuntimeError(f'Graph Judge validation promotion qualification failed ({code})')
 ownership['status']='terminal_pass';save()
except Exception as error:
 ownership['status']='terminal_fail';ownership['failure']=public_error(error);save()
finally:
 cleanup_errors=[]
 if child is not None and child.poll() is None:
  try: child.terminate();child.wait(timeout=5)
  except Exception as error: cleanup_errors.append({'stage':'stop-test','error':public_error(error)})
 try:
  remove=subprocess.run(docker+['rm','--force',container],env=base_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30) if attempted else None
 except Exception as error: cleanup_errors.append({'stage':'remove','error':public_error(error)});remove=None
 try: query=subprocess.run(docker+['ps','-a','--filter',f'name=^{container}$','--format','{{.Names}}'],env=base_env,capture_output=True,text=True,timeout=20)
 except Exception as error: cleanup_errors.append({'stage':'absence-query','error':public_error(error)});query=None
 exact_absent=query is not None and query.returncode==0 and not query.stdout.strip();cleanup_ok=not cleanup_errors and exact_absent and (remove is None or remove.returncode==0)
 ownership['cleanup']={'errors':cleanup_errors,'removeReturnCode':None if remove is None else remove.returncode,
  'absenceQueryReturnCode':None if query is None else query.returncode,'exactAbsent':exact_absent}
 prior=ownership['status'];ownership['status']='terminal_pass_cleaned' if prior=='terminal_pass' and cleanup_ok else 'terminal_fail';ownership['completedAt']=datetime.now(timezone.utc).isoformat();save()
 try:
  grant=json.loads(grant_path.read_text())
  if grant.get('grantId')==args.grant_id and grant.get('status')=='consumed' and grant.get('ownerHandle')==owner_handle:
   grant.update(runStatus='terminal_pass' if ownership['status']=='terminal_pass_cleaned' else 'terminal_fail',completedAt=ownership['completedAt'],cleanup=ownership['cleanup'],sourceHashes=ownership['sourceHashes'],containerId=ownership.get('containerId'),resultSha256=ownership.get('resultSha256'));persist(grant_path,grant)
 except Exception as error: ownership['grantUpdateError']=public_error(error);save()
 print(f'Graph Judge validation promotion evidence retained: {root}',flush=True)
if ownership['status']!='terminal_pass_cleaned': raise RuntimeError(ownership.get('failure') or 'Graph Judge validation cleanup was not proven complete')
