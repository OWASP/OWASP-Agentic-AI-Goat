#!/usr/bin/env python3
"""Qualify exact-owner deletion across owned workshop PostgreSQL stores."""
import argparse, os, shutil, signal, subprocess, tempfile, time, uuid
from pathlib import Path

parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True);args=parser.parse_args()
source=Path(__file__).resolve().parents[2];root=Path(tempfile.mkdtemp(prefix='dvaia-student-deletion-stores-'));os.chmod(root,0o700)
workspace=root/'source';workspace.mkdir();base={k:os.environ[k] for k in ['PATH','HOME','TMPDIR'] if k in os.environ}
docker=['docker','--host',args.docker_host];tag=uuid.uuid4().hex[:12];container=f'dvaia-student-deletion-stores-{tag}';child=None;started=False
def run(cmd,**kwargs):kwargs.setdefault('timeout',60);return subprocess.run(cmd,check=True,env=base,**kwargs)
def stop_child():
 global child
 if child is not None and child.poll() is None:
  os.killpg(os.getpgid(child.pid),signal.SIGTERM)
  try:child.wait(timeout=5)
  except subprocess.TimeoutExpired:os.killpg(os.getpgid(child.pid),signal.SIGKILL);child.wait(timeout=5)
def interrupted(signum,_frame):stop_child();raise SystemExit(128+signum)
signal.signal(signal.SIGTERM,interrupted)
shutil.copytree(source/'server',workspace/'server',ignore=shutil.ignore_patterns('*.db','*.db-*','logs'))
shutil.copytree(source/'db'/'postgres',workspace/'db'/'postgres')
target=workspace/'tests/postgres/studentDeletionWorkshopStores.integration.test.js';target.parent.mkdir(parents=True);shutil.copy2(source/'tests/postgres/studentDeletionWorkshopStores.integration.test.js',target)
(workspace/'node_modules').symlink_to(source/'node_modules',target_is_directory=True)
try:
 run(docker+['run','--detach','--name',container,'--tmpfs','/var/lib/postgresql:rw,size=402653184','-e','POSTGRES_USER=deletion_stores_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432','postgres:18','-c','shared_buffers=16MB','-c','max_connections=40','-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL);started=True
 deadline=time.monotonic()+30
 while time.monotonic()<deadline:
  probe=subprocess.run(docker+['exec',container,'pg_isready','-h','127.0.0.1','-U','deletion_stores_admin'],env=base,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
  if probe.returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('Owned PostgreSQL container did not become ready')
 port=int(run(docker+['port',container,'5432'],capture_output=True,text=True).stdout.strip().rsplit(':',1)[1]);psql=['psql','-h','127.0.0.1','-p',str(port),'-U','deletion_stores_admin','-d','postgres','-v','ON_ERROR_STOP=1']
 env=dict(base,NODE_ENV='test',PG_TEST_DISPOSABLE='yes',AWS_EC2_METADATA_DISABLED='true',DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace))
 for key,schema in [('ARIA','aria'),('NOVA','nova'),('MCP','mcp'),('CSRF','csrf'),('SUPPLY','supply_chain'),('CTF','ctf')]:
  migration=f'dvaia_{schema}_migration';runtime=f'dvaia_{schema}_runtime';database=f'dvaia_test_deletion_{schema}_{tag}'
  for role in [migration,runtime]:run(psql+['-c',f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],stdout=subprocess.DEVNULL)
  run(psql+['-c',f'CREATE DATABASE {database} OWNER {migration}'],stdout=subprocess.DEVNULL)
  run(psql+['-c',f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime}'],stdout=subprocess.DEVNULL)
  env[f'PG_STUDENT_DELETION_STORES_{key}_MIGRATION_URL']=f'postgresql://{migration}@127.0.0.1:{port}/{database}';env[f'PG_STUDENT_DELETION_STORES_{key}_RUNTIME_URL']=f'postgresql://{runtime}@127.0.0.1:{port}/{database}'
 log_path=root/'result.log'
 with log_path.open('w') as log:
  child=subprocess.Popen(['node','--test','--test-reporter=tap','tests/postgres/studentDeletionWorkshopStores.integration.test.js'],cwd=workspace,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);code=child.wait(timeout=90)
 print(log_path.read_text(),flush=True)
 if code:raise RuntimeError(f'Student deletion store qualification failed ({code})')
except BaseException:
 if started:
  (root/'container-state.json').write_text(subprocess.run(docker+['inspect','--format','{"status":{{json .State.Status}},"exitCode":{{.State.ExitCode}},"oomKilled":{{.State.OOMKilled}}}',container],env=base,capture_output=True,text=True,timeout=10).stdout)
  (root/'container.log').write_text(subprocess.run(docker+['logs',container],env=base,capture_output=True,text=True,timeout=10).stdout)
 raise
finally:
 stop_child()
 if started:
  subprocess.run(docker+['rm','--force',container],env=base,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
  remaining=run(docker+['ps','-a','--filter',f'name=^{container}$','--format','{{.Names}}'],capture_output=True,text=True).stdout.strip()
  if remaining:raise RuntimeError('Owned PostgreSQL container cleanup did not complete')
 print(f'Owned container cleanup complete; evidence retained: {root}',flush=True)
