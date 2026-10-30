#!/usr/bin/env python3
"""Qualify draft SecureShop account-deletion reset mapping in owned PostgreSQL 18."""
import argparse, os, shutil, signal, subprocess, tempfile, time, uuid
from pathlib import Path
from urllib.parse import quote

parser=argparse.ArgumentParser(); parser.add_argument('--docker-host',required=True); args=parser.parse_args()
source=Path(__file__).resolve().parents[2]
root=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-student-deletion-secureshop-')); os.chmod(root,0o700)
workspace=root/'source'; workspace.mkdir()
base={k:os.environ[k] for k in ['PATH','HOME','TMPDIR'] if k in os.environ}
docker=['docker','--host',args.docker_host]; token=uuid.uuid4().hex[:12]
container=f'owasp-ai-goat-student-deletion-secureshop-{token}'; child=None; started=False
def run(cmd,**kwargs): kwargs.setdefault('timeout',60); return subprocess.run(cmd,check=True,env=base,**kwargs)
def stop_child():
 global child
 if child is not None and child.poll() is None:
  os.killpg(os.getpgid(child.pid),signal.SIGTERM)
  try: child.wait(timeout=5)
  except subprocess.TimeoutExpired: os.killpg(os.getpgid(child.pid),signal.SIGKILL); child.wait(timeout=5)
def interrupted(signum,_frame): stop_child(); raise SystemExit(128+signum)
signal.signal(signal.SIGTERM,interrupted)
files=['server/database/postgres/studentDeletionRepository.js','server/database/postgres/identityRepository.js',
 'server/database/postgres/identityValidation.js','server/database/postgres/secureshopLaunchRepository.js',
 'server/database/postgres/secureshopResetCleanupAuthorityRepository.js','server/database/postgres/agentRunReadRepository.js',
 'server/services/secureshopConversationOwnershipResolver.js','server/database/postgres/index.js',
 'server/database/postgres/poolBudget.js','server/services/secureshopStudentDeletionCleanup.js',
 'db/postgres/migrate.js','docs/modernization/drafts/student-deletion-journal.sql',
 'tests/postgres/studentDeletionSecureShop.integration.test.js']
for rel in files:
 target=workspace/rel; target.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(source/rel,target)
shutil.copytree(source/'db/postgres/identity-migrations',workspace/'db/postgres/identity-migrations')
(workspace/'node_modules').symlink_to(source/'node_modules',target_is_directory=True)
try:
 run(docker+['run','--detach','--name',container,'--tmpfs','/var/lib/postgresql:rw,size=268435456',
  '-e','POSTGRES_USER=deletion_test_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust','-p','127.0.0.1::5432',
  'postgres:18','-c','shared_buffers=16MB','-c','max_connections=24'],stdout=subprocess.DEVNULL); started=True
 deadline=time.monotonic()+30
 while time.monotonic()<deadline:
  try:
   probe=subprocess.run(docker+['exec',container,'pg_isready','-U','deletion_test_admin'],env=base,
    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
   if probe.returncode==0: break
  except subprocess.TimeoutExpired: pass
  time.sleep(.25)
 else: raise RuntimeError('Owned PostgreSQL container did not become ready')
 port=int(run(docker+['port',container,'5432'],capture_output=True,text=True).stdout.strip().rsplit(':',1)[1])
 psql=['psql','-h','127.0.0.1','-p',str(port),'-U','deletion_test_admin','-d','postgres','-v','ON_ERROR_STOP=1']
 migration_role='dvaia_identity_migration'; runtime_role='dvaia_identity_runtime'; db=f'owasp_ai_goat_test_student_deletion_{token}'
 for role in [migration_role,runtime_role]:
  run(psql+['-c',f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],stdout=subprocess.DEVNULL)
 run(psql+['-c',f'CREATE DATABASE {db} OWNER {migration_role}'],stdout=subprocess.DEVNULL)
 run(psql+['-c',f'REVOKE CONNECT ON DATABASE {db} FROM PUBLIC; GRANT CONNECT ON DATABASE {db} TO {migration_role},{runtime_role}'],stdout=subprocess.DEVNULL)
 env=dict(base,NODE_ENV='test',PG_TEST_DISPOSABLE='yes',AWS_EC2_METADATA_DISABLED='true',
  PG_STUDENT_DELETION_SECURESHOP_TEST_MIGRATION_URL=f'postgresql://{quote(migration_role)}@127.0.0.1:{port}/{db}',
  PG_STUDENT_DELETION_SECURESHOP_TEST_RUNTIME_URL=f'postgresql://{quote(runtime_role)}@127.0.0.1:{port}/{db}')
 log_path=root/'result.log'
 with log_path.open('w') as log:
  child=subprocess.Popen(['node','--test','--test-reporter=tap','tests/postgres/studentDeletionSecureShop.integration.test.js'],
   cwd=workspace,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  code=child.wait(timeout=60)
 print(log_path.read_text(),flush=True)
 if code: raise RuntimeError(f'SecureShop deletion integration failed ({code})')
finally:
 stop_child()
 if started:
  subprocess.run(docker+['rm','--force',container],env=base,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
  remaining=run(docker+['ps','-a','--filter',f'name=^{container}$','--format','{{.Names}}'],capture_output=True,text=True).stdout.strip()
  if remaining: raise RuntimeError('Owned PostgreSQL container cleanup did not complete')
 print(f'Owned container cleanup complete; evidence retained: {root}',flush=True)
