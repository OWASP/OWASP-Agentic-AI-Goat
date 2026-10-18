#!/usr/bin/env python3
"""Qualify historical platform imports in one owned PostgreSQL 18 database."""
import argparse, os, shutil, signal, subprocess, tempfile, time, uuid
from pathlib import Path
from urllib.parse import quote

parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True);args=parser.parse_args()
source=Path(__file__).resolve().parents[2];root=Path(tempfile.mkdtemp(prefix='dvaia-platform-import-'))
workspace=root/'source';workspace.mkdir();os.chmod(root,0o700)
base_env={key:os.environ[key] for key in ['PATH','HOME','TMPDIR'] if key in os.environ}
docker=['docker','--host',args.docker_host];run_id=uuid.uuid4().hex[:12]
container=f'dvaia-platform-import-{run_id}';started=False;child=None
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
try:
 run(docker+['run','--detach','--name',container,'--tmpfs','/var/lib/postgresql:rw,size=268435456',
  '-e','POSTGRES_USER=import_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1',
  '-p','127.0.0.1::5432','postgres:18','-c','shared_buffers=16MB','-c','max_connections=32',
  '-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL);started=True
 deadline=time.monotonic()+30
 while time.monotonic()<deadline:
  probe=subprocess.run(docker+['exec',container,'pg_isready','-U','import_admin'],env=base_env,
   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
  if probe.returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('Owned PostgreSQL container did not become ready')
 port=int(run(docker+['port',container,'5432'],capture_output=True,text=True).stdout.strip().rsplit(':',1)[1])
 psql=['psql','-h','127.0.0.1','-p',str(port),'-U','import_admin','-d','postgres','-v','ON_ERROR_STOP=1']
 migration='dvaia_identity_migration';runtime='dvaia_identity_runtime';database=f'dvaia_import_{run_id}'
 for role in [migration,runtime]:run(psql+['-c',f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],stdout=subprocess.DEVNULL)
 run(psql+['-c',f'CREATE DATABASE {database} OWNER {migration}'],stdout=subprocess.DEVNULL)
 run(psql+['-c',f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime}'],stdout=subprocess.DEVNULL)
 env=dict(base_env,NODE_ENV='test',PG_TEST_DISPOSABLE='yes',DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace),AWS_EC2_METADATA_DISABLED='true',
  PG_PLATFORM_IMPORT_TEST_MIGRATION_URL=f'postgresql://{quote(migration)}@127.0.0.1:{port}/{database}',
  PG_PLATFORM_IMPORT_TEST_RUNTIME_URL=f'postgresql://{quote(runtime)}@127.0.0.1:{port}/{database}')
 log_path=root/'result.log'
 with log_path.open('w') as log:
  child=subprocess.Popen(['node','--test','--test-reporter=tap','tests/postgres/platformImport.integration.test.js'],
   cwd=workspace,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  code=child.wait(timeout=120)
 print(log_path.read_text(),flush=True)
 if code:raise RuntimeError(f'Platform import integration failed ({code})')
finally:
 stop_child()
 if started:
  subprocess.run(docker+['rm','--force',container],env=base_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
  remaining=run(docker+['ps','-a','--filter',f'name=^{container}$','--format','{{.Names}}'],capture_output=True,text=True).stdout.strip()
  if remaining:raise RuntimeError('Owned PostgreSQL container cleanup did not complete')
 print(f'Owned container cleanup complete; evidence retained: {root}',flush=True)
