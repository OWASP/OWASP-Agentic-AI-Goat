#!/usr/bin/env python3
"""Run the focused admin HTTP contract against one owned PostgreSQL 18 cluster."""
import argparse, hashlib, json, os, shutil, signal, subprocess, time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

parser=argparse.ArgumentParser()
parser.add_argument('--suite', choices=['admin', 'capacity'], default='admin')
parser.add_argument('--docker-host',required=True)
parser.add_argument('--evidence-dir',required=True)
parser.add_argument('--container',required=True)
parser.add_argument('--grant-id')
args=parser.parse_args()
source=Path(__file__).resolve().parents[2]
grant = None
if args.suite == 'capacity':
 grant=json.loads((source/'tasks/native-verification-slot.json').read_text())
 if not args.grant_id or grant.get('grantId') != args.grant_id or grant.get('status') != 'consumed' or grant.get('owner') != '/root' or grant.get('container') != args.container or Path(grant.get('evidence','')).resolve() != Path(args.evidence_dir).resolve():
  raise SystemExit('Matching consumed root capacity grant required')
root=Path(args.evidence_dir).resolve();root.mkdir(parents=True,exist_ok=False);os.chmod(root,0o700)
workspace=root/'source';workspace.mkdir()
container=args.container
prefix = 'owasp-ai-goat-admin-http-' if args.suite == 'admin' else 'owasp-ai-goat-capacity-'
if not container.startswith(prefix):raise SystemExit('owned container prefix required')
base_env={key:os.environ[key] for key in ['PATH','HOME','TMPDIR'] if key in os.environ}
docker=['docker','--host',args.docker_host];started=False;child=None
ownership_path=root/'ownership.json';log_path=root/'result.log';docker_log=root/'docker.log'
state={'container':container,'suite':args.suite,'launcherPid':os.getpid(),'dockerHost':args.docker_host,'evidence':str(root),'createdAt':datetime.now(timezone.utc).isoformat(),'started':False,'mounts':[],'cleanup':None}
if grant:state.update(grantId=grant['grantId'],consumedAt=grant['consumedAt'])
def save():
 tmp=ownership_path.with_suffix('.tmp');tmp.write_text(json.dumps(state,indent=2,sort_keys=True)+'\n');os.chmod(tmp,0o600);tmp.replace(ownership_path)
save()
def run(command,**kwargs):kwargs.setdefault('timeout',60);return subprocess.run(command,check=True,env=base_env,**kwargs)
def stop_child():
 global child
 if child is not None and child.poll() is None:
  os.killpg(os.getpgid(child.pid),signal.SIGTERM)
  try:child.wait(timeout=5)
  except subprocess.TimeoutExpired:os.killpg(os.getpgid(child.pid),signal.SIGKILL);child.wait(timeout=5)
def interrupted(signum,_frame):stop_child();raise SystemExit(128+signum)
signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
def ignore(_directory,names):
 denied={'.git','node_modules','build','logs','uploads','sensitive_files','workshop_data','vector-indexes','coverage','.cache','__pycache__'}
 return [name for name in names if name in denied or name.startswith('.env') or any(name.endswith(s) for s in ['.db','.db-wal','.db-shm','.log'])]
for directory in ['server','db','tests','docs']:shutil.copytree(source/directory,workspace/directory,ignore=ignore)
(workspace/'node_modules').symlink_to(source/'node_modules',target_is_directory=True)
state['sourceHashes']={name:hashlib.sha256((workspace/name).read_bytes()).hexdigest() for name in ['tests/postgres/run-admin-http-isolated.py','tests/postgres/'+('workshopCapacity.integration.test.js' if args.suite=='capacity' else 'adminHttp.integration.test.js')]}
state['nodeVersion']=run(['node','--version'],capture_output=True,text=True).stdout.strip()
save()
try:
 run(docker+['run','--detach','--name',container,'--tmpfs','/var/lib/postgresql:rw,size=268435456',
  '-e','POSTGRES_USER=admin_http_owner','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1',
  '-p','127.0.0.1::5432','postgres:18','-c','shared_buffers=16MB','-c','max_connections=32',
  '-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL);started=True
 inspect=json.loads(run(docker+['inspect',container],capture_output=True,text=True).stdout)[0]
 state.update(started=True,containerId=inspect['Id'],mounts=inspect.get('Mounts',[]));save()
 deadline=time.monotonic()+30
 while time.monotonic()<deadline:
  probe=subprocess.run(docker+['exec',container,'pg_isready','-h','127.0.0.1','-U','admin_http_owner'],env=base_env,
   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
  if probe.returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('Owned PostgreSQL container did not become TCP ready')
 port=int(run(docker+['port',container,'5432'],capture_output=True,text=True).stdout.strip().rsplit(':',1)[1])
 psql=['psql','-h','127.0.0.1','-p',str(port),'-U','admin_http_owner','-d','postgres','-v','ON_ERROR_STOP=1']
 migration='dvaia_identity_migration';runtime='dvaia_identity_runtime'
 database='owasp_ai_goat_test_admin_http' if args.suite == 'admin' else 'owasp_ai_goat_test_capacity_owned'
 for role in [migration,runtime]:run(psql+['-c',f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],stdout=subprocess.DEVNULL)
 run(psql+['-c',f'CREATE DATABASE {database} OWNER {migration}'],stdout=subprocess.DEVNULL)
 run(psql+['-c',f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime}'],stdout=subprocess.DEVNULL)
 env=dict(base_env,NODE_ENV='test',PG_TEST_DISPOSABLE='yes',OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(workspace),AWS_EC2_METADATA_DISABLED='true',
  PG_ADMIN_TEST_MIGRATION_URL=f'postgresql://{quote(migration)}@127.0.0.1:{port}/{database}',
  PG_ADMIN_TEST_RUNTIME_URL=f'postgresql://{quote(runtime)}@127.0.0.1:{port}/{database}')
 test_file='tests/postgres/adminHttp.integration.test.js'
 if args.suite == 'capacity':
  env.update(OWASP_AI_GOAT_CAPACITY_QUALIFICATION='yes',
   PG_CAPACITY_MIGRATION_URL=env['PG_ADMIN_TEST_MIGRATION_URL'],
   PG_CAPACITY_RUNTIME_URL=env['PG_ADMIN_TEST_RUNTIME_URL'])
  test_file='tests/postgres/workshopCapacity.integration.test.js'
 with log_path.open('w') as log:
  child=subprocess.Popen(['node','--test','--test-reporter=tap',test_file],cwd=workspace,env=env,
   stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  state.update(testPid=child.pid,runStatus='running');save()
  code=child.wait(timeout=240)
 print(log_path.read_text(),flush=True)
 if code:raise RuntimeError(f'{args.suite} HTTP integration failed ({code})')
 state['runStatus']='terminal_pass'
finally:
 stop_child()
 if log_path.exists():state['resultSha256']=hashlib.sha256(log_path.read_bytes()).hexdigest()
 if state.get('runStatus')!='terminal_pass':state['runStatus']='terminal_fail'
 if started:
  inspected=subprocess.run(docker+['inspect',container,'--format','{{json .State}}'],env=base_env,capture_output=True,text=True,timeout=10)
  if inspected.returncode==0:
   try:state['containerState']=json.loads(inspected.stdout)
   except json.JSONDecodeError:state['containerState']={'inspectUnavailable':True}
  logs=subprocess.run(docker+['logs',container],env=base_env,capture_output=True,text=True,timeout=20)
  docker_log.write_text(logs.stdout+logs.stderr);os.chmod(docker_log,0o600)
  removed=subprocess.run(docker+['rm','--force',container],env=base_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
  absence=subprocess.run(docker+['ps','-a','--filter',f'name=^{container}$','--format','{{.Names}}'],env=base_env,capture_output=True,text=True,timeout=20)
  remaining=absence.stdout.strip()
  state['cleanup']={'removeReturnCode':removed.returncode,'absenceQueryReturnCode':absence.returncode,
   'exactNameAbsent':absence.returncode==0 and not bool(remaining)}
  save()
  if removed.returncode or absence.returncode or remaining:raise RuntimeError('Owned PostgreSQL container cleanup did not complete')
 else:
  absence=subprocess.run(docker+['ps','-a','--filter',f'name=^{container}$','--format','{{.Names}}'],env=base_env,capture_output=True,text=True,timeout=20)
  state['cleanup']={'removeReturnCode':None,'absenceQueryReturnCode':absence.returncode,
   'exactNameAbsent':absence.returncode==0 and not bool(absence.stdout.strip()),'containerStartNotConfirmed':True};save()
 print(f'Owned container absence verified: {state["cleanup"]["exactNameAbsent"]}; evidence retained: {root}',flush=True)
