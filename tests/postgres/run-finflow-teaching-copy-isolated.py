#!/usr/bin/env python3
"""Qualify draft FinFlow teaching copy 0041 through the real PG loader."""
import argparse, os, shutil, signal, subprocess, tempfile, time, uuid
from pathlib import Path

parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True);args=parser.parse_args()
source=Path(__file__).resolve().parents[2];root=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-finflow-copy-'))
workspace=root/'source';workspace.mkdir();os.chmod(root,0o700)
base_env={key:os.environ[key] for key in ['PATH','HOME','TMPDIR'] if key in os.environ}
docker=['docker','--host',args.docker_host];token=uuid.uuid4().hex[:12]
container=f'owasp-ai-goat-finflow-copy-{token}';started=False;child=None
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
 run(docker+['run','--detach','--name',container,'--tmpfs','/var/lib/postgresql:rw,size=268435456','-e','POSTGRES_USER=finflow_copy_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432','postgres:18','-c','shared_buffers=16MB','-c','max_connections=24','-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL);started=True
 deadline=time.monotonic()+30
 while time.monotonic()<deadline:
  try:probe=subprocess.run(docker+['exec',container,'psql','-U','finflow_copy_admin','-d','postgres','-Atqc','SELECT 1'],env=base_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
  except subprocess.TimeoutExpired:probe=None
  if probe is not None and probe.returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('Owned PostgreSQL did not become SQL-ready')
 port=int(run(docker+['port',container,'5432'],capture_output=True,text=True).stdout.strip().rsplit(':',1)[1])
 psql=['psql','-h','127.0.0.1','-p',str(port),'-U','finflow_copy_admin','-d','postgres','-v','ON_ERROR_STOP=1']
 for role in ['dvaia_identity_migration','dvaia_identity_runtime']:run(psql+['-c',f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],stdout=subprocess.DEVNULL)
 run(psql+['-c','CREATE DATABASE owasp_ai_goat_finflow_copy OWNER dvaia_identity_migration'],stdout=subprocess.DEVNULL)
 run(psql+['-c','REVOKE CONNECT ON DATABASE owasp_ai_goat_finflow_copy FROM PUBLIC; GRANT CONNECT ON DATABASE owasp_ai_goat_finflow_copy TO dvaia_identity_migration,dvaia_identity_runtime'],stdout=subprocess.DEVNULL)
 env=dict(base_env,NODE_ENV='test',PG_TEST_DISPOSABLE='yes',OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(workspace),AWS_EC2_METADATA_DISABLED='true',PG_FINFLOW_COPY_MIGRATION_URL=f'postgresql://dvaia_identity_migration@127.0.0.1:{port}/owasp_ai_goat_finflow_copy',PG_FINFLOW_COPY_RUNTIME_URL=f'postgresql://dvaia_identity_runtime@127.0.0.1:{port}/owasp_ai_goat_finflow_copy')
 log_path=root/'result.log'
 with log_path.open('w') as log:
  child=subprocess.Popen(['node','--test','--test-reporter=tap','tests/postgres/finflowTeachingCopy.integration.test.js'],cwd=workspace,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  code=child.wait(timeout=90)
 print(log_path.read_text(),flush=True)
 if code:raise RuntimeError(f'FinFlow teaching-copy qualification failed ({code})')
finally:
 stop_child()
 if started:
  cleanup=subprocess.run(docker+['rm','--force',container],env=base_env,capture_output=True,text=True,timeout=30)
  remaining=run(docker+['ps','-a','--filter',f'name=^{container}$','--format','{{.Names}}'],capture_output=True,text=True).stdout.strip()
  (root/'container-cleanup.txt').write_text(f'returncode={cleanup.returncode}\nstdout={cleanup.stdout.strip()}\nstderr={cleanup.stderr.strip()}\nabsence_verified={not bool(remaining)}\n')
  if cleanup.returncode or remaining:raise RuntimeError('Owned PostgreSQL cleanup did not complete')
 print(f'Owned container cleanup complete; evidence retained: {root}',flush=True)
