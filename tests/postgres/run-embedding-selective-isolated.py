#!/usr/bin/env python3
"""Qualify selective reindex in two launcher-owned review stores; controlled vectors, no model."""
import argparse, hashlib, http.client, json, os, signal, subprocess, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from sql_nosql_process_ownership import OwnedProcesses
import re

EXPECTED_DOCKER='unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
DOCKER=Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')
IMAGE='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
SOURCE=Path(__file__).resolve().parents[2]
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def parse_args(argv=None):
 parser=argparse.ArgumentParser(allow_abbrev=False)
 parser.add_argument('--docker-host',required=True)
 parser.add_argument('--node',required=True)
 parser.add_argument('--node-sha256',required=True)
 return parser.parse_args(argv)

def validate_node(value,pin):
 p=Path(value)
 if not p.is_absolute() or p.resolve()!=p or not p.is_file() or not re.fullmatch(r'[a-f0-9]{64}',pin) or digest(p)!=pin:raise RuntimeError('Canonical pinned Node required')
 return p

def source_inventory(source):
 source=Path(source)
 if source.resolve()!=source:raise RuntimeError('Canonical main source required')
 names={'package.json','package-lock.json','tests/postgres/secureshopEmbeddingSelective.integration.test.js','tests/postgres/run-embedding-selective-isolated.py','tests/postgres/sql_nosql_process_ownership.py'}
 for folder in ['server/database/postgres','server/services','server/agent-runtime','server/data','server/config','db/postgres','scripts/lib','shared','agent-host','server/routes','server/middleware','tests/fixtures']:
  for item in (source/folder).rglob('*'):
   if item.is_symlink():raise RuntimeError('Source symlink denied')
   if item.is_file() and '__pycache__' not in item.parts:names.add(item.relative_to(source).as_posix())
 return {name:digest(source/name) for name in sorted(names)}

def owned_group_members(pgid,sid,env):
 listing=subprocess.run(['/bin/ps','-axo','pid=,pgid=,uid='],env=env,stdout=subprocess.PIPE,text=True,check=True,timeout=5).stdout
 members=[]
 for line in listing.splitlines():
  fields=line.split()
  if len(fields)==3 and int(fields[1])==pgid:
   pid=int(fields[0])
   try:
    if int(fields[2])!=os.getuid() or os.getsid(pid)!=sid:raise RuntimeError('Refusing foreign process group identity')
   except ProcessLookupError:continue
   members.append(pid)
 return members

def main(argv=None):
 args=parse_args(argv)
 NODE=validate_node(args.node,args.node_sha256)
 source_before=source_inventory(SOURCE)
 mode='embedding-selective'
 test_file='tests/postgres/secureshopEmbeddingSelective.integration.test.js'
 if args.docker_host!=EXPECTED_DOCKER:raise SystemExit('reviewed isolated Docker host required')
 root=Path(tempfile.mkdtemp(prefix='dvaia-embedding-selective-')).resolve();os.chmod(root,0o700);runtime=root/'runtime';runtime.mkdir(mode=0o700)
 for name in ['home','tmp','logs']:(runtime/name).mkdir(mode=0o700)
 workspace=SOURCE
 container='dvaia-embedding-selective-'+uuid.uuid4().hex[:12];owner=uuid.uuid4().hex
 docker=[str(DOCKER),'--host',args.docker_host]
 env={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':str(runtime/'home'),'TMPDIR':str(runtime/'tmp'),'LOGS_DIR':str(runtime/'logs')}
 state={'container':container,'owner':owner,'image':IMAGE,'evidence':str(root),'launcherPid':os.getpid(),
  'sourceRoot':str(SOURCE),'sourceSha256':source_before,'nodeSha256':args.node_sha256,'nodeVersion':None,'containerCreationAttempted':False,'child':None,'runStatus':'preparing','cleanup':None,
  'mode':mode,'createdAt':datetime.now(timezone.utc).isoformat()}
 ownership=root/'ownership.json';log_path=root/'tests.log';log_path.touch(mode=0o600)
 def persist():ownership.write_text(json.dumps(state,indent=2)+'\n');os.chmod(ownership,0o600)
 def run(command,**kwargs):kwargs.setdefault('timeout',120);return subprocess.run(command,check=True,env=kwargs.pop('env',env),**kwargs)
 def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
 def exact_absence(name=container):
  query=subprocess.run(docker+['ps','-a','--filter',f'name=^/{name}$','--format','{{.Names}}'],env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=30)
  if query.returncode:raise RuntimeError('exact-name container query failed')
  return not query.stdout.strip()
 child=None;creation_attempted=False;persist()
 def stop_group(child,pgid,sid):
  if owned_group_members(pgid,sid,env):os.killpg(pgid,signal.SIGTERM)
  deadline=time.monotonic()+5
  while owned_group_members(pgid,sid,env) and time.monotonic()<deadline:
   child.poll();time.sleep(.05)
  if owned_group_members(pgid,sid,env):os.killpg(pgid,signal.SIGKILL)
  try:child.wait(timeout=5)
  except subprocess.TimeoutExpired:pass
  if owned_group_members(pgid,sid,env):raise RuntimeError('owned Node/browser process group cleanup incomplete')
 owned=OwnedProcesses(stop_group);owned.install()
 try:
  version=run([str(NODE),'--version'],stdout=subprocess.PIPE,text=True).stdout.strip()
  if not re.fullmatch(r'v26\.10\.[0-9]+',version):raise RuntimeError('Selected Node 26.10 required')
  state['nodeVersion']=version;persist()
  daemon_name=run(docker+['info','--format','{{.Name}}'],stdout=subprocess.PIPE,text=True).stdout.strip()
  if daemon_name!='colima-dvaia-pg-verify':raise RuntimeError('reviewed isolated Docker daemon required')
  image_id=run(docker+['image','inspect','--format','{{.Id}}',IMAGE],stdout=subprocess.PIPE,text=True).stdout.strip()
  if image_id!=IMAGE:raise RuntimeError('immutable PostgreSQL image identity mismatch')
  state['dockerDaemon']=daemon_name;state['daemonId']=run(docker+['info','--format','{{.ID}}'],stdout=subprocess.PIPE,text=True).stdout.strip();state['imageId']=image_id;persist()
  if not exact_absence():raise RuntimeError('owned container name unexpectedly exists')
  run([str(NODE),'--check',str(SOURCE/test_file)],cwd=runtime)
  if source_inventory(SOURCE)!=source_before:raise RuntimeError('Main source changed before allocation')
  creation_attempted=True;state['containerCreationAttempted']=True;persist()
  run(docker+['run','--detach','--pull','never','--name',container,'--label','dvaia.test.owner='+owner,
   '--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size=268435456','-e','POSTGRES_HOST_AUTH_METHOD=trust',
   '-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',IMAGE,'-c','shared_buffers=16MB','-c','max_connections=40',
   '-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL)
  details=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]
  state['containerId']=details['Id'];persist()
  if details.get('Mounts') or details['Config']['Labels'].get('dvaia.test.owner')!=owner:raise RuntimeError('owned PostgreSQL isolation/ownership check failed')
  for _ in range(100):
   ready=subprocess.run(docker+['exec',container,'pg_isready','-h','127.0.0.1','-U','postgres'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
   if ready.returncode==0:break
   time.sleep(.25)
  else:raise RuntimeError('owned PostgreSQL unavailable')
  port=int(run(docker+['port',container,'5432/tcp'],stdout=subprocess.PIPE,text=True).stdout.strip().rsplit(':',1)[1])
  psql=docker+['exec',container,'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-c']
  roles=['dvaia_secureshop_review_migration','dvaia_secureshop_review_runtime']
  run(psql+[';'.join(f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS' for role in roles)+';'],stdout=subprocess.DEVNULL)
  nonce=owner[:12]
  state['databases']=[];persist()
  for store in ['fresh','working']:
   database=f'dvaia_test_embedding_selective_{nonce}_{store}';migration=roles[0];runtime_role=roles[1]
   run(psql+[f'CREATE DATABASE {database} OWNER {migration}'],stdout=subprocess.DEVNULL)
   run(psql+[f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime_role}'],stdout=subprocess.DEVNULL)
   state['databases'].append(database);persist()
   env[f'EMBEDDING_SELECTIVE_{store.upper()}_MIGRATION_URL']=f'postgresql://{migration}@127.0.0.1:{port}/{database}'
   env[f'EMBEDDING_SELECTIVE_{store.upper()}_RUNTIME_URL']=f'postgresql://{runtime_role}@127.0.0.1:{port}/{database}'
  env['EMBEDDING_SELECTIVE_NATIVE']='1'
  env['EMBEDDING_SELECTIVE_OWNER']=nonce
  env['EMBEDDING_SELECTIVE_EVIDENCE_ROOT']=str(root)
  env.update(NODE_ENV='test',PG_TEST_DISPOSABLE='yes',DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace),
   PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',
   AI_PROVIDER='mock',TRANSFORMERS_OFFLINE='1',JWT_SECRET=uuid.uuid4().hex+uuid.uuid4().hex,SESSION_SECRET=uuid.uuid4().hex+uuid.uuid4().hex,
   AWS_EC2_METADATA_DISABLED='true',MCP_WORKSHOP_AUTOSTART='false',MCP_SIDECARS_AUTOSTART='false',SS_ENABLE='false',HF_HUB_OFFLINE='1',
   OLLAMA_BASE_URL='http://127.0.0.1:1',SANDBOX_RUNNER_URL='http://127.0.0.1:1',SSRF_TARGET_URL='http://127.0.0.1:1',
  ROGUE_MCP_URL='http://127.0.0.1:1',MAILPIT_API_URL='http://127.0.0.1:1',MAILPIT_SMTP_HOST='127.0.0.1',MAILPIT_SMTP_PORT='1')
  with log_path.open('w') as log:
   child=owned.launch([str(NODE),'--test','--test-reporter=tap',str(SOURCE/test_file)],name='selective',cwd=runtime,env=env,stdout=log,stderr=log,start_new_session=True)
   state['child']={'pid':child.pid,'pgid':child.pid};state['runStatus']='test_running';persist()
   try:code=child.wait(timeout=180)
   except subprocess.TimeoutExpired:owned.cleanup();raise RuntimeError('Selective embedding qualification timed out')
  if code:raise RuntimeError(f'Selective embedding qualification failed ({code}); inspect retained tests.log')
  result=json.loads((root/'embedding-selective-result.json').read_text())
  if result.get('status')!='passed' or result.get('modelCalls')!=0:raise RuntimeError('Selective receipt incomplete')
  state['runStatus']='passed';state['resultSha256']=digest(log_path);state['qualificationSha256']=digest(root/'embedding-selective-result.json');persist()
 except BaseException as error:
  if creation_attempted:
   try:
    diagnostic=subprocess.run(docker+['logs','--tail','120',container],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20)
    (root/'container.log').write_text(diagnostic.stdout);os.chmod(root/'container.log',0o600)
   except Exception as diagnostic_error:state['containerDiagnosticError']=type(diagnostic_error).__name__
  state.update({'runStatus':'failed','errorType':type(error).__name__,'resultSha256':digest(log_path)});persist();raise
 finally:
  owned.mask_cleanup_signals();errors=[];remove_code=None;absent=None
  try:owned.cleanup()
  except Exception as error:errors.append('child:'+type(error).__name__)
  if creation_attempted:
   try:
    if not exact_absence():
     info=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]
     if info['Config']['Labels'].get('dvaia.test.owner')!=owner or (state.get('containerId') is not None and info['Id']!=state['containerId']) or info['Image']!=IMAGE or run(docker+['info','--format','{{.ID}}'],stdout=subprocess.PIPE,text=True).stdout.strip()!=state.get('daemonId'):raise RuntimeError('refusing foreign container cleanup')
     remove_code=subprocess.run(docker+['rm','-f','-v',info['Id']],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30).returncode
    else:remove_code=0
   except Exception as error:errors.append('remove:'+type(error).__name__)
  try:absent=exact_absence()
  except Exception as error:errors.append('absence:'+type(error).__name__)
  try:pgid_absent=not state.get('child') or not owned_group_members(state['child']['pgid'],state['child']['pid'],env)
  except Exception as error:errors.append('pgid:'+type(error).__name__);pgid_absent=False
  try:
   if source_inventory(SOURCE)!=source_before or digest(NODE)!=args.node_sha256:raise RuntimeError('Main source/runtime changed')
   state['sourceUnchanged']=True
  except Exception as error:errors.append('source:'+type(error).__name__);state['sourceUnchanged']=False
  state['cleanup']={'removeExitCode':remove_code,'containerAbsent':absent,'nodeBrowserPgidAbsent':pgid_absent,
  'errors':errors,'completedAt':datetime.now(timezone.utc).isoformat()}
  if state['runStatus']=='passed' and (errors or absent is not True or pgid_absent is not True or (creation_attempted and remove_code!=0)):state['runStatus']='failed';state['errorType']='CleanupFailed'
  persist();owned.restore()
 print(json.dumps({'evidence':str(root),'status':state['runStatus'],'cleanup':state['cleanup']}),flush=True)
 if state['runStatus']!='passed':raise SystemExit(1)

if __name__=='__main__':main()
