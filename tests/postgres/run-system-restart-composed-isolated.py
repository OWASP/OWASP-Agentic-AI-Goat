#!/usr/bin/env python3
"""Qualify canonical restart DB/service/client against the actual owned listener; zero model."""
import argparse,hashlib,json,os,secrets,shutil,signal,subprocess,tempfile,time,uuid
from datetime import datetime,timezone
from pathlib import Path
HOST='unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock';DOCKER=Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker');NODE=Path('/Users/averma5/.owasp-ai-goat/runtimes/node-v26.9.0-darwin-arm64/bin/node');PG='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280';BASE='sha256:3a771f83944bb763050c23c0225c260638c4b7899e7a72485ef75e5e570499e5';SOURCE=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--docker-host',required=True);a=p.parse_args()
if a.docker_host!=HOST:raise SystemExit('reviewed isolated Docker host required')
out=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-system-restart-composed-')).resolve();out.chmod(0o700);owner=uuid.uuid4().hex;prefix='owasp-ai-goat-restart-composed-'+owner[:12];pg=prefix+'-pg';listener=prefix+'-listener';network=prefix+'-network';tag=prefix+':owned';docker=[str(DOCKER),'--host',HOST];env={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':os.environ['HOME'],'TMPDIR':str(out)};state={'status':'preparing','evidence':str(out),'owner':owner,'pgContainer':pg,'listenerContainer':listener,'network':network,'tag':tag,'postgresImage':PG,'listenerBase':BASE,'createdAt':datetime.now(timezone.utc).isoformat(),'sourceSha256':{}};created=[];image_id=None;child=None
def save():(out/'ownership.json').write_text(json.dumps(state,indent=2)+'\n')
def run(cmd,timeout=120,check=True,**kw):
 r=subprocess.run(cmd,env=kw.pop('env',env),text=True,capture_output=True,timeout=timeout,**kw)
 if check and r.returncode:raise RuntimeError('command failed')
 return r
def drun(args,**kw):return run(docker+args,**kw)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def absent(kind,name):return drun([kind,'inspect',name],check=False,timeout=20).returncode!=0
def members(pgid):
 rows=run(['ps','-axo','pid=,pgid=,uid='],timeout=5).stdout.splitlines();return [int(x.split()[0]) for x in rows if len(x.split())==3 and int(x.split()[1])==pgid and int(x.split()[2])==os.getuid()]
def stop_child():
 if not child:return
 pgid=state.get('child',{}).get('pgid');
 if pgid and members(pgid):os.killpg(pgid,signal.SIGTERM)
 deadline=time.monotonic()+5
 while pgid and members(pgid) and time.monotonic()<deadline:time.sleep(.05)
 if pgid and members(pgid):os.killpg(pgid,signal.SIGKILL)
 try:child.wait(timeout=5)
 except subprocess.TimeoutExpired:pass
save()
try:
 if run([str(NODE),'--version']).stdout.strip()!='v26.9.0':raise RuntimeError('managed Node required')
 if drun(['info','--format','{{.Name}}']).stdout.strip()!='colima-owasp-ai-goat-pg-verify':raise RuntimeError('reviewed daemon required')
 for image,architecture in [(PG,'arm64'),(BASE,'arm64')]:
  info=json.loads(drun(['image','inspect',image]).stdout)[0]
  if info['Id']!=image or info['Architecture']!=architecture:raise RuntimeError('immutable image mismatch')
 workspace=out/'source';run([str(NODE),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(SOURCE),str(workspace)],timeout=120);(workspace/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
 inventory=['tests/postgres/secureshopSystemRestartComposed.integration.test.js','tests/postgres/run-system-restart-composed-isolated.py','db/postgres/workshop-migrations/secureshop_review/0019_bound_policy_retrieval_corpus.sql','db/postgres/workshop-migrations/secureshop_review/0020_bound_owned_system_restart.sql','package.json','package-lock.json']
 for folder in ['server/database/postgres','server/services','server/routes/secureshop','sidecars/sandbox-runner/owned-system','db/postgres','scripts/lib']:
  inventory.extend(str(x.relative_to(workspace)) for x in (workspace/folder).rglob('*') if x.is_file())
 state['sourceSha256']={name:digest(workspace/name) for name in sorted(set(inventory))};save()
 run([str(NODE),'--check','tests/postgres/secureshopSystemRestartComposed.integration.test.js'],cwd=workspace)
 pkg=workspace/'sidecars/sandbox-runner/owned-system'
 with (out/'build.log').open('w') as log:
  child=subprocess.Popen(docker+['build','--pull=false','--network=default','--label','owasp-ai-goat.test.owner='+owner,'-f','Dockerfile.local','-t',tag,'.'],cwd=pkg,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid),'purpose':'build'};save();code=child.wait(timeout=300)
 if code:raise RuntimeError('listener build failed')
 image=json.loads(drun(['image','inspect',tag]).stdout)[0];image_id=image['Id'];state['listenerImageId']=image_id
 drun(['network','create','--label','owasp-ai-goat.test.owner='+owner,network]);created.append(('network',network))
 drun(['run','-d','--pull','never','--name',pg,'--label','owasp-ai-goat.test.owner='+owner,'--network',network,'--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size=268435456','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',PG,'-c','shared_buffers=16MB','-c','max_connections=24','-c','max_wal_size=16MB','-c','min_wal_size=4MB']);created.append(('container',pg))
 for _ in range(120):
  if drun(['exec',pg,'pg_isready','-h','127.0.0.1','-U','postgres'],check=False,timeout=3).returncode==0:break
  time.sleep(.2)
 else:raise RuntimeError('PostgreSQL unavailable')
 port=int(drun(['port',pg,'5432/tcp']).stdout.strip().rsplit(':',1)[1]);database='owasp_ai_goat_restart_'+owner[:10];migration='dvaia_secureshop_review_migration';runtime='dvaia_secureshop_review_runtime';sql=f"CREATE ROLE {migration} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;CREATE ROLE {runtime} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;";drun(['exec',pg,'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-c',sql]);drun(['exec',pg,'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-c',f'CREATE DATABASE {database} OWNER {migration}']);drun(['exec',pg,'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-c',f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC;GRANT CONNECT ON DATABASE {database} TO {migration},{runtime};'])
 token=secrets.token_urlsafe(32);target=str(uuid.uuid4());envfile=out/'restart.env';envfile.write_text('SECURESHOP_SYSTEM_RESTART_HTTP_ENABLED=true\nSECURESHOP_SYSTEM_RESTART_TOKEN='+token+'\nSECURESHOP_SYSTEM_RESTART_TARGET_ID='+target+'\nSECURESHOP_SYSTEM_RESTART_HOST=0.0.0.0\nSECURESHOP_SYSTEM_RESTART_PORT=8090\n');envfile.chmod(0o600)
 drun(['run','-d','--pull','never','--name',listener,'--label','owasp-ai-goat.test.owner='+owner,'--network',network,'--read-only','--user','10001:10001','--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/tmp:rw,nosuid,nodev,size=128m','--tmpfs','/owned-restart:rw,nosuid,nodev,size=8m,mode=0700,uid=10001,gid=10001','--tmpfs','/var/lib/owasp-ai-goat-owned-restart:rw,nosuid,nodev,size=8m,mode=0700,uid=10001,gid=10001','--security-opt','seccomp=unconfined','--security-opt','apparmor=owasp-ai-goat-mcp-sandbox','-p','127.0.0.1::8090','--env-file',str(envfile),image_id,'restart']);created.append(('container',listener));envfile.unlink()
 listener_port=int(drun(['port',listener,'8090/tcp']).stdout.strip().rsplit(':',1)[1]);deadline=time.monotonic()+60
 while time.monotonic()<deadline:
  ready=run([str(NODE),'-e',"fetch(process.argv[1],{headers:{authorization:'Bearer '+process.argv[2]}}).then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))",f'http://127.0.0.1:{listener_port}/secureshop/system/restart-health',token],check=False,timeout=3)
  if ready.returncode==0:break
  time.sleep(.15)
 else:raise RuntimeError('restart listener unavailable')
 test_env={**env,'SYSTEM_RESTART_COMPOSED_NATIVE':'1','SYSTEM_RESTART_MIGRATION_URL':f'postgresql://{migration}@127.0.0.1:{port}/{database}','SYSTEM_RESTART_RUNTIME_URL':f'postgresql://{runtime}@127.0.0.1:{port}/{database}','SYSTEM_RESTART_MIGRATIONS':str(workspace/'db/postgres/workshop-migrations/secureshop_review'),'SYSTEM_RESTART_BASE_URL':f'http://127.0.0.1:{listener_port}','SYSTEM_RESTART_TOKEN':token,'SYSTEM_RESTART_TARGET_ID':target,'SYSTEM_RESTART_RESULT':str(out/'test-result.json'),'NODE_ENV':'test','PG_TEST_DISPOSABLE':'yes','OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE':str(workspace),'AI_PROVIDER':'mock','TRANSFORMERS_OFFLINE':'1','HF_HUB_OFFLINE':'1','AWS_EC2_METADATA_DISABLED':'true'}
 with (out/'tests.log').open('w') as log:
  child=subprocess.Popen([str(NODE),'--test','--test-reporter=tap','tests/postgres/secureshopSystemRestartComposed.integration.test.js'],cwd=workspace,env=test_env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid),'purpose':'test'};state['status']='running';save();code=child.wait(timeout=240)
 if code:raise RuntimeError('composed test failed')
 state['postgresVersion']=drun(['exec',pg,'psql','-U','postgres','-d','postgres','-Atc','SHOW server_version']).stdout.strip();state['testResultSha256']=digest(out/'test-result.json');state['testLogSha256']=digest(out/'tests.log');state['status']='passed';save()
except BaseException as error:
 state['status']='failed';state['errorType']=type(error).__name__;save();raise
finally:
 errors=[]
 try:stop_child()
 except BaseException as e:errors.append('child:'+type(e).__name__)
 for kind,name in reversed(created):
  try:
   if not absent(kind,name):drun(['rm','-f',name] if kind=='container' else ['network','rm',name],check=False,timeout=40)
  except BaseException as e:errors.append(kind+':'+type(e).__name__)
 try:
  if not absent('image',tag):drun(['image','rm',tag],check=False,timeout=40)
 except BaseException as e:errors.append('image:'+type(e).__name__)
 cleanup={'errors':errors,'pgAbsent':absent('container',pg),'listenerAbsent':absent('container',listener),'networkAbsent':absent('network',network),'imageTagAbsent':absent('image',tag),'imageIdAbsent':not image_id or absent('image',image_id),'childPgidAbsent':not state.get('child') or not members(state['child']['pgid'])};state['cleanup']=cleanup
 if errors or not all(v for k,v in cleanup.items() if k!='errors'):state['status']='failed';state['errorType']='CleanupFailed'
 save()
print(json.dumps({'status':state['status'],'evidence':str(out),'cleanup':state['cleanup']}))
if state['status']!='passed':raise SystemExit(1)
