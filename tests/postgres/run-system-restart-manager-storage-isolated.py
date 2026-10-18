#!/usr/bin/env python3
"""Qualify canonical 0021 restart-manager storage on fresh/populated/no-op stores; zero model."""
import argparse,hashlib,json,os,signal,subprocess,tempfile,time,uuid,shutil
from datetime import datetime,timezone
from pathlib import Path
HOST='unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock';NODE=Path('/Users/averma5/.dvaia/runtimes/node-v26.9.0-darwin-arm64/bin/node');DOCKER=Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker');IMAGE='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280';SOURCE=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--docker-host',required=True);a=p.parse_args()
if a.docker_host!=HOST:raise SystemExit('reviewed isolated Docker host required')
root=Path(tempfile.mkdtemp(prefix='dvaia-system-restart-manager-storage-')).resolve();root.chmod(0o700);workspace=root/'source';owner=uuid.uuid4().hex;container='dvaia-restart-manager-storage-'+owner[:12];docker=[str(DOCKER),'--host',HOST];env={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':os.environ['HOME'],'TMPDIR':str(root)};state={'status':'preparing','evidence':str(root),'owner':owner,'container':container,'image':IMAGE,'createdAt':datetime.now(timezone.utc).isoformat()};child=None;created=False
def save():(root/'ownership.json').write_text(json.dumps(state,indent=2)+'\n')
def run(cmd,timeout=120,check=True,**kw):
 r=subprocess.run(cmd,env=kw.pop('env',env),text=True,capture_output=True,timeout=timeout,**kw)
 if check and r.returncode:raise RuntimeError('owned command failed')
 return r
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def absent():return run(docker+['container','inspect',container],check=False,timeout=20).returncode!=0
def members(pgid):return [int(x.split()[0]) for x in run(['ps','-axo','pid=,pgid=,uid='],timeout=5).stdout.splitlines() if len(x.split())==3 and int(x.split()[1])==pgid and int(x.split()[2])==os.getuid()]
def stop_child():
 if not child:return
 pgid=state.get('child',{}).get('pgid')
 if pgid and members(pgid):os.killpg(pgid,signal.SIGTERM)
 deadline=time.monotonic()+5
 while pgid and members(pgid) and time.monotonic()<deadline:time.sleep(.05)
 if pgid and members(pgid):os.killpg(pgid,signal.SIGKILL)
 try:child.wait(timeout=5)
 except subprocess.TimeoutExpired:pass
save()
try:
 if run([str(NODE),'--version']).stdout.strip()!='v26.9.0':raise RuntimeError('managed Node required')
 if run(docker+['info','--format','{{.Name}}']).stdout.strip()!='colima-dvaia-pg-verify':raise RuntimeError('reviewed daemon required')
 image=json.loads(run(docker+['image','inspect',IMAGE]).stdout)[0]
 if image['Id']!=IMAGE or image['Architecture']!='arm64':raise RuntimeError('immutable PostgreSQL image mismatch')
 run([str(NODE),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(SOURCE),str(workspace)],cwd=SOURCE);(workspace/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
 full=workspace/'db/postgres/workshop-migrations/secureshop_review';prefix=workspace/'restart-manager-prefix-through-0020';prefix.mkdir()
 for item in full.glob('*.sql'):
  if item.name<'0021_':shutil.copy2(item,prefix/item.name)
 test_file='tests/postgres/secureshopSystemRestartManagerStorage.integration.test.js';launcher='tests/postgres/run-system-restart-manager-storage-isolated.py';inventory=[test_file,launcher,'db/postgres/workshop-migrations/secureshop_review/0020_bound_owned_system_restart.sql','db/postgres/workshop-migrations/secureshop_review/0021_bound_owned_system_restart_manager.sql','db/postgres/migrate.js','package.json','package-lock.json']
 state['sourceSha256']={name:digest(workspace/name) for name in inventory};state['migrationCount']={'prefix':len(list(prefix.glob('*.sql'))),'full':len(list(full.glob('*.sql')))};state['migrationSha256']={'0020':digest(full/'0020_bound_owned_system_restart.sql'),'0021':digest(full/'0021_bound_owned_system_restart_manager.sql')};save();run([str(NODE),'--check',test_file],cwd=workspace)
 created=True;run(docker+['run','-d','--pull','never','--name',container,'--label','dvaia.test.owner='+owner,'--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size=268435456','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',IMAGE,'-c','shared_buffers=16MB','-c','max_connections=32','-c','max_wal_size=16MB','-c','min_wal_size=4MB'])
 details=json.loads(run(docker+['inspect',container]).stdout)[0]
 if details['Mounts'] or details['Config']['Labels'].get('dvaia.test.owner')!=owner:raise RuntimeError('owned PostgreSQL isolation mismatch')
 for _ in range(120):
  if run(docker+['exec',container,'pg_isready','-h','127.0.0.1','-U','postgres'],check=False,timeout=3).returncode==0:break
  time.sleep(.2)
 else:raise RuntimeError('PostgreSQL unavailable')
 port=int(run(docker+['port',container,'5432/tcp']).stdout.strip().rsplit(':',1)[1]);migration='dvaia_secureshop_review_migration';runtime='dvaia_secureshop_review_runtime';psql=docker+['exec',container,'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-c'];run(psql+[f'CREATE ROLE {migration} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;CREATE ROLE {runtime} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;'])
 for mode in ['fresh','populated']:
  db='dvaia_restart_manager_'+owner[:10]+'_'+mode;run(psql+[f'CREATE DATABASE {db} OWNER {migration}']);run(psql+[f'REVOKE CONNECT ON DATABASE {db} FROM PUBLIC;GRANT CONNECT ON DATABASE {db} TO {migration},{runtime};']);env['SYSTEM_RESTART_'+mode.upper()+'_MIGRATION_URL']=f'postgresql://{migration}@127.0.0.1:{port}/{db}';env['SYSTEM_RESTART_'+mode.upper()+'_RUNTIME_URL']=f'postgresql://{runtime}@127.0.0.1:{port}/{db}'
 env.update(SYSTEM_RESTART_MANAGER_STORAGE_NATIVE='1',SYSTEM_RESTART_PREFIX_MIGRATIONS=str(prefix),SYSTEM_RESTART_MIGRATIONS=str(full),SYSTEM_RESTART_STORAGE_RESULT=str(root/'test-result.json'),NODE_ENV='test',PG_TEST_DISPOSABLE='yes',DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace),AI_PROVIDER='mock',TRANSFORMERS_OFFLINE='1',HF_HUB_OFFLINE='1',AWS_EC2_METADATA_DISABLED='true')
 with (root/'tests.log').open('w') as log:
  child=subprocess.Popen([str(NODE),'--test','--test-reporter=tap',test_file],cwd=workspace,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid)};state['status']='running';save();code=child.wait(timeout=240)
 if code:raise RuntimeError('storage qualification failed')
 state['postgresVersion']=run(docker+['exec',container,'psql','-U','postgres','-d','postgres','-Atc','SHOW server_version']).stdout.strip();state['testLogSha256']=digest(root/'tests.log');state['resultSha256']=digest(root/'test-result.json');state['status']='passed';save()
except BaseException as error:state['status']='failed';state['errorType']=type(error).__name__;state['error']=str(error)[:200];save();raise
finally:
 errors=[]
 try:stop_child()
 except BaseException as e:errors.append('child:'+type(e).__name__)
 if created and not absent():
  try:run(docker+['rm','-f','-v',container],check=False,timeout=40)
  except BaseException as e:errors.append('container:'+type(e).__name__)
 state['cleanup']={'errors':errors,'containerAbsent':absent(),'childPgidAbsent':not state.get('child') or not members(state['child']['pgid'])}
 if errors or not all(v for k,v in state['cleanup'].items() if k!='errors'):state['status']='failed'
 save()
print(json.dumps({'status':state['status'],'evidence':str(root),'cleanup':state['cleanup']}))
if state['status']!='passed':raise SystemExit(1)
