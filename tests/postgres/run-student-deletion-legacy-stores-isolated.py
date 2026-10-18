#!/usr/bin/env python3
"""Qualify owner deletion for legacy challenge and sensitive lookup in owned PostgreSQL 18 stores."""
import argparse,os,shutil,signal,subprocess,tempfile,time,uuid
from pathlib import Path
from urllib.parse import quote
parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True);args=parser.parse_args()
source=Path(__file__).resolve().parents[2];root=Path(tempfile.mkdtemp(prefix='dvaia-student-deletion-legacy-stores-'));os.chmod(root,0o700)
workspace=root/'source';workspace.mkdir();base={k:os.environ[k] for k in ['PATH','HOME','TMPDIR'] if k in os.environ}
managed=Path('/Users/averma5/.dvaia/runtimes/node-v26.8.2-darwin-arm64/bin');base['PATH']=f'{managed}:{base.get("PATH","")}'
docker=['docker','--host',args.docker_host];tag=uuid.uuid4().hex[:12];container=f'dvaia-student-deletion-legacy-{tag}';child=None;started=False
(root/'owned-container.txt').write_text(container+'\n')
def run(cmd,**kwargs):kwargs.setdefault('timeout',60);return subprocess.run(cmd,check=True,env=base,**kwargs)
def stop_child():
 global child
 if child is not None and child.poll() is None:
  os.killpg(os.getpgid(child.pid),signal.SIGTERM)
  try:child.wait(timeout=5)
  except subprocess.TimeoutExpired:os.killpg(os.getpgid(child.pid),signal.SIGKILL);child.wait(timeout=5)
def interrupted(signum,_frame):stop_child();raise SystemExit(128+signum)
signal.signal(signal.SIGTERM,interrupted)
shutil.copytree(source/'server',workspace/'server',ignore=shutil.ignore_patterns('*.db','*.db-*','logs','uploads'))
shutil.copytree(source/'db'/'postgres',workspace/'db'/'postgres')
for rel in ['docs/modernization/drafts/legacy-challenge-student-deletion.sql','docs/modernization/drafts/sensitive-lookup-student-deletion.sql','docs/modernization/drafts/legacy-upload-lifecycle.sql','tests/postgres/studentDeletionLegacyStores.integration.test.js']:
 target=workspace/rel;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source/rel,target)
(workspace/'node_modules').symlink_to(source/'node_modules',target_is_directory=True)
try:
 run(docker+['run','--detach','--name',container,'--tmpfs','/var/lib/postgresql:rw,size=402653184','-e','POSTGRES_USER=deletion_test_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust','-p','127.0.0.1::5432','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','postgres:18','-c','shared_buffers=16MB','-c','max_connections=30','-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL);started=True
 deadline=time.monotonic()+30
 while time.monotonic()<deadline:
  try:
   if subprocess.run(docker+['exec',container,'pg_isready','-h','127.0.0.1','-U','deletion_test_admin'],env=base,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2).returncode==0:break
  except subprocess.TimeoutExpired:pass
  time.sleep(.25)
 else:raise RuntimeError('Owned PostgreSQL container did not become TCP ready')
 port=int(run(docker+['port',container,'5432'],capture_output=True,text=True).stdout.strip().rsplit(':',1)[1]);psql=['psql','-h','127.0.0.1','-p',str(port),'-U','deletion_test_admin','-d','postgres','-v','ON_ERROR_STOP=1']
 env=dict(base,NODE_ENV='test',PG_TEST_DISPOSABLE='yes',AWS_EC2_METADATA_DISABLED='true',DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace),PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',LEGACY_PLATFORM_LIFECYCLE_ENABLED='true',JWT_SECRET='owned-legacy-lifecycle-secret')
 for key,migration_role,runtime_role in [('IDENTITY','dvaia_identity_migration','dvaia_identity_runtime'),('LEGACY','dvaia_legacy_challenge_migration','dvaia_legacy_challenge_runtime'),('LOOKUP','dvaia_sensitive_lookup_migration','dvaia_sensitive_lookup_runtime')]:
  for role in [migration_role,runtime_role]:run(psql+['-c',f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],stdout=subprocess.DEVNULL)
  if key in ('IDENTITY','LEGACY'):run(psql+['-c',f'GRANT pg_signal_backend TO {migration_role}'],stdout=subprocess.DEVNULL)
  database=f'dvaia_test_deletion_{key.lower()}_{tag}';run(psql+['-c',f'CREATE DATABASE {database} OWNER {migration_role}'],stdout=subprocess.DEVNULL);run(psql+['-c',f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration_role},{runtime_role}'],stdout=subprocess.DEVNULL)
  env[f'PG_STUDENT_DELETION_LEGACY_{key}_MIGRATION_URL']=f'postgresql://{quote(migration_role)}@127.0.0.1:{port}/{database}';env[f'PG_STUDENT_DELETION_LEGACY_{key}_RUNTIME_URL']=f'postgresql://{quote(runtime_role)}@127.0.0.1:{port}/{database}'
  prefix={'IDENTITY':'IDENTITY','LEGACY':'LEGACY_CHALLENGE','LOOKUP':'SENSITIVE_LOOKUP'}[key]
  env[f'{prefix}_MIGRATION_DATABASE_URL']=env[f'PG_STUDENT_DELETION_LEGACY_{key}_MIGRATION_URL'];env[f'{prefix}_DATABASE_URL']=env[f'PG_STUDENT_DELETION_LEGACY_{key}_RUNTIME_URL']
 log_path=root/'result.log'
 with log_path.open('w') as log:
  child=subprocess.Popen(['node','--test','--test-reporter=tap','tests/postgres/studentDeletionLegacyStores.integration.test.js'],cwd=workspace,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);code=child.wait(timeout=90)
 print(log_path.read_text(),flush=True)
 if code:raise RuntimeError(f'Legacy store deletion qualification failed ({code})')
except BaseException:
 if started:
  (root/'container-state.json').write_text(subprocess.run(docker+['inspect','--format','{"status":{{json .State.Status}},"exitCode":{{.State.ExitCode}},"oomKilled":{{.State.OOMKilled}}}',container],env=base,capture_output=True,text=True,timeout=10).stdout)
  (root/'container.log').write_text(subprocess.run(docker+['logs',container],env=base,capture_output=True,text=True,timeout=10).stdout)
 raise
finally:
 stop_child()
 if started:
  removed=subprocess.run(docker+['rm','--force',container],env=base,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30);remaining=run(docker+['ps','-a','--filter',f'name=^{container}$','--format','{{.Names}}'],capture_output=True,text=True).stdout.strip()
  (root/'cleanup-status.txt').write_text(f'container={container}\nremove_returncode={removed.returncode}\nremaining={remaining}\n')
  if removed.returncode or remaining:raise RuntimeError('Owned PostgreSQL container cleanup did not complete')
 print(f'Owned container cleanup complete; evidence retained: {root}',flush=True)
