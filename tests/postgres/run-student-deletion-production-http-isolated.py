#!/usr/bin/env python3
"""Qualify mounted production student deletion against all owned PostgreSQL stores."""
import argparse,hashlib,json,os,shutil,signal,subprocess,tempfile,time,uuid
from pathlib import Path
from urllib.parse import quote
parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True)
for option in ['node','node-sha256','docker-cli','docker-cli-sha256']:parser.add_argument('--'+option,required=True)
parser.add_argument('--run',action='store_true');args=parser.parse_args()
if not args.run:
 print('plan: no resources launched');raise SystemExit(0)
def executable(value,digest):
 path=Path(value).resolve(strict=True)
 if not path.is_file() or not os.access(path,os.X_OK) or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:raise RuntimeError('Executable identity mismatch')
 return str(path)
node=executable(args.node,args.node_sha256);docker_cli=executable(args.docker_cli,args.docker_cli_sha256)
source=Path(__file__).resolve().parents[2];root=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-student-deletion-production-http-'));os.chmod(root,0o700);workspace=root/'source';base={k:os.environ[k] for k in ['PATH','HOME','TMPDIR'] if k in os.environ};base['PATH']=f'{Path(node).parent}:{base.get("PATH","")}'
docker=[docker_cli,'--host',args.docker_host];tag=uuid.uuid4().hex[:10];container=f'owasp-ai-goat-student-deletion-http-{tag}';child=None;children=[];started=False;container_id=None
image='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
def receipt(name,value):
 path=root/name;path.write_text(json.dumps(value,sort_keys=True)+'\n');os.chmod(path,0o600)
(root/'owned-container.txt').write_text(container+'\n')
def run(cmd,**kwargs):kwargs.setdefault('timeout',120);return subprocess.run(cmd,check=True,env=kwargs.pop('env',base),**kwargs)
def stop_child():
 global child
 for owned in children:
  try:os.killpg(owned.pid,signal.SIGTERM)
  except ProcessLookupError:continue
  try:owned.wait(timeout=5)
  except subprocess.TimeoutExpired:os.killpg(owned.pid,signal.SIGKILL);owned.wait(timeout=5)
  deadline=time.monotonic()+5
  while time.monotonic()<deadline:
   try:os.killpg(owned.pid,0)
   except ProcessLookupError:break
   time.sleep(.05)
  else:os.killpg(owned.pid,signal.SIGKILL)
def owned_node(arguments,log,timeout):
 global child
 child=subprocess.Popen([node]+arguments,cwd=workspace,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
 children.append(child)
 receipt('child-intent.json',{'processes':[{'pid':p.pid,'pgid':p.pid} for p in children]})
 return child.wait(timeout=timeout)
def absent(pid,group=False):
 try:(os.killpg if group else os.kill)(pid,0);return False
 except ProcessLookupError:return True
def interrupted(signum,_frame):stop_child();raise SystemExit(128+signum)
signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
blocked={'.git','node_modules','build','logs','uploads','sensitive_files','workshop_data','vector-indexes','coverage','.cache','__pycache__'}
def ignore(_directory,names):return [name for name in names if name in blocked or name.startswith('.env') or name.endswith('.db') or '.db-' in name]
shutil.copytree(source,workspace,ignore=ignore);(workspace/'node_modules').symlink_to(source/'node_modules',target_is_directory=True)
shutil.copytree(source/'client/build/secureshop-review-renderer',workspace/'client/build/secureshop-review-renderer')
promotions=[('docs/modernization/drafts/legacy-upload-lifecycle.sql','db/postgres/identity-migrations/0040_legacy_upload_lifecycle.sql'),('docs/modernization/drafts/0041_finflow_response_repair_copy.sql','db/postgres/identity-migrations/0041_finflow_response_repair_copy.sql'),('docs/modernization/drafts/legacy-challenge-student-deletion.sql','db/postgres/workshop-migrations/legacy_challenge/0003_student_deletion.sql'),('docs/modernization/drafts/sensitive-lookup-student-deletion.sql','db/postgres/workshop-migrations/sensitive_lookup/0002_student_deletion.sql')]
for draft,target in promotions:
 destination=workspace/target
 if not destination.exists():raise RuntimeError(f'Current promoted migration is missing: {target}')
 if destination.read_bytes()!=(workspace/draft).read_bytes():raise RuntimeError(f'Promoted migration differs from qualified draft: {target}')
try:
 receipt('container-intent.json',{'name':container,'image':image});started=True
 container_id=run(docker+['run','--detach','--name',container,'--tmpfs','/var/lib/postgresql:rw,size=536870912','-e','POSTGRES_USER=deletion_test_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust','-p','127.0.0.1::5432','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1',image,'-c','shared_buffers=24MB','-c','max_connections=100','-c','max_wal_size=32MB','-c','min_wal_size=4MB'],capture_output=True,text=True).stdout.strip()
 receipt('container-created.json',{'name':container,'containerId':container_id,'image':image})
 deadline=time.monotonic()+40
 while time.monotonic()<deadline:
  try:
   if subprocess.run(docker+['exec',container,'pg_isready','-h','127.0.0.1','-U','deletion_test_admin'],env=base,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2).returncode==0:break
  except subprocess.TimeoutExpired:pass
  time.sleep(.25)
 else:raise RuntimeError('Owned PostgreSQL container did not become TCP ready')
 port=int(run(docker+['port',container,'5432'],capture_output=True,text=True).stdout.strip().rsplit(':',1)[1]);psql=['psql','-h','127.0.0.1','-p',str(port),'-U','deletion_test_admin','-d','postgres','-v','ON_ERROR_STOP=1']
 stores=[('IDENTITY','identity'),('SQL_WORKSHOP','aria'),('NOSQL_WORKSHOP','nova'),('XSS_WORKSHOP','xss'),('MCP_WORKSHOP','mcp'),('CSRF_WORKSHOP','csrf'),('SUPPLY_CHAIN_WORKSHOP','supply_chain'),('FINFLOW_WORKSHOP','finflow'),('EXCESSIVE_AGENCY','excessive_agency'),('CTF','ctf'),('LEGACY_CHALLENGE','legacy_challenge'),('SENSITIVE_LOOKUP','sensitive_lookup'),('SECURESHOP','secureshop'),('SECURESHOP_AGENTS','secureshop_agents'),('SESSION_DISCLOSURE','session_disclosure'),('SECURESHOP_REVIEW','secureshop_review')]
 env=dict(base,NODE_ENV='test',PG_TEST_DISPOSABLE='yes',AWS_EC2_METADATA_DISABLED='true',OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(workspace),PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',JWT_SECRET='owned-student-deletion-http-secret',MCP_SIDECARS_AUTOSTART='false')
 app_data=root/'app-data';app_data.mkdir(mode=0o700)
 for directory in ['finflow-traversal-targets','logs']:(app_data/directory).mkdir(mode=0o700)
 env.update(OWASP_AI_GOAT_APP_DATA_ROOT=str(app_data),LOGS_DIR=str(app_data/'logs'),FINFLOW_BACKUP_ROOT=str(app_data/'finflow-backups'),FINFLOW_TRAVERSAL_TARGET_ROOT=str(app_data/'finflow-traversal-targets'))
 env.pop('LEGACY_PLATFORM_LIFECYCLE_ENABLED',None)
 if 'LEGACY_PLATFORM_LIFECYCLE_ENABLED' in env:raise RuntimeError('Default-on qualification inherited a lifecycle flag')
 for prefix,schema in stores:
  migration=f'dvaia_{schema}_migration';runtime=f'dvaia_{schema}_runtime'
  for role in [migration,runtime]:run(psql+['-c',f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],stdout=subprocess.DEVNULL)
  database=f'owasp_ai_goat_test_delete_http_{schema}_{tag}';run(psql+['-c',f'CREATE DATABASE {database} OWNER {migration}'],stdout=subprocess.DEVNULL);run(psql+['-c',f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime}'],stdout=subprocess.DEVNULL)
  env[f'{prefix}_MIGRATION_DATABASE_URL']=f'postgresql://{quote(migration)}@127.0.0.1:{port}/{database}';env[f'{prefix}_DATABASE_URL']=f'postgresql://{quote(runtime)}@127.0.0.1:{port}/{database}'
 init_log=root/'initialize.log'
 with init_log.open('w') as log:
  if owned_node(['db/postgres/initialize-application.js'],log,180):raise RuntimeError('Owned store initialization failed')
 log_path=root/'result.log'
 with log_path.open('w') as log:
  code=owned_node(['--test','--test-reporter=tap','tests/postgres/studentDeletionProductionHttp.integration.test.js'],log,150)
 if code:raise RuntimeError(f'Production HTTP deletion qualification failed ({code})')
except BaseException:
 if started:
  (root/'container-state.json').write_text(subprocess.run(docker+['inspect','--format','{"status":{{json .State.Status}},"exitCode":{{.State.ExitCode}},"oomKilled":{{.State.OOMKilled}}}',container],env=base,capture_output=True,text=True,timeout=10).stdout)
  (root/'container.log').write_text(subprocess.run(docker+['logs',container],env=base,capture_output=True,text=True,timeout=10).stdout)
 raise
finally:
 stop_child()
 cleanup={'pidAbsent':all(absent(p.pid) for p in children),'pgidAbsent':all(absent(p.pid,True) for p in children)}
 if started:
  removed=subprocess.run(docker+['rm','--force',container_id or container],env=base,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30);remaining=run(docker+['ps','-a','--no-trunc','--format','{{.ID}} {{.Names}}'],capture_output=True,text=True).stdout
  (root/'cleanup-status.txt').write_text(f'container={container}\nremove_returncode={removed.returncode}\nremaining={remaining}\n')
  cleanup.update(containerId=container_id,containerName=container,containerAbsent=not any(line.split()[-1]==container or (container_id and line.split()[0]==container_id) for line in remaining.splitlines()))
 receipt('cleanup.json',cleanup)
 if not all(cleanup.get(key,True) for key in ['pidAbsent','pgidAbsent','containerAbsent']):raise RuntimeError('Owned resources remain')
 print(f'Owned container cleanup complete; evidence retained: {root}',flush=True)
