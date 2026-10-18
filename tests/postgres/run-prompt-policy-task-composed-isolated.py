#!/usr/bin/env python3
"""One frozen composed task-policy gate; disposable PG/renderer and bounded local 8B."""
import argparse, hashlib, json, os, signal, subprocess, tempfile, time, uuid, urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
DOCKER = Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')
DOCKER_HOST = 'unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
NODE = Path('/Users/averma5/.dvaia/runtimes/node-v26.9.0-darwin-arm64/bin/node')
PG_IMAGE = 'sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'

parser = argparse.ArgumentParser()
parser.add_argument('--run', action='store_true')
parser.add_argument('--embedding-cache', required=True)
parser.add_argument('--provider-free-finalize', action='store_true')
args = parser.parse_args()
if not args.run: raise SystemExit('Explicit --run required')
cache = Path(args.embedding_cache)
if not cache.is_absolute() or not cache.resolve(strict=True).is_dir(): raise SystemExit('Absolute existing embedding cache required')
if not DOCKER.is_file() or not NODE.is_file(): raise SystemExit('Pinned native tools unavailable')

suffix = uuid.uuid4().hex[:12]
evidence = Path(tempfile.mkdtemp(prefix='dvaia-prompt-policy-task-composed-')); os.chmod(evidence, 0o700)
workspace = evidence / 'source'
pg_name = f'dvaia-task-policy-pg-{suffix}'
renderer_name = f'dvaia-task-policy-renderer-{suffix}'
renderer_image = f'dvaia-task-policy-renderer:{suffix}'
renderer_network = f'dvaia-task-policy-net-{suffix}'
docker = [str(DOCKER), '--host', DOCKER_HOST]
env = {'PATH': f'{NODE.parent}:/usr/bin:/bin', 'HOME': os.environ['HOME'], 'TMPDIR': str(evidence)}
state = {'version': 1, 'scope': 'secureshop_task_policy_composed_actual8b', 'status': 'preparing',
 'createdAt': datetime.now(timezone.utc).isoformat(), 'evidence': str(evidence), 'launcherPid': os.getpid(),
 'resources': {'postgres': pg_name, 'renderer': renderer_name, 'rendererImage': renderer_image, 'network': renderer_network},
 'bounds': {'postgres': {'memory': '512m', 'cpus': 1, 'pids': 128, 'maxConnections': 48},
  'renderer': {'memory': '512m', 'cpus': 1, 'pids': 128, 'maxConcurrent': 1},
  'model': {'name': 'llama3.1:8b', 'enabled': not args.provider_free_finalize,
    'maxPhysicalCalls': 0 if args.provider_free_finalize else 6, 'perCallSeconds': 60, 'aggregateSeconds': 300},
  'parentSeconds': 360}, 'child': None, 'cleanup': None}
ownership = evidence / 'ownership.json'; log_path = evidence / 'result.log'; build_log = evidence / 'renderer-build.log'
def save(): ownership.write_text(json.dumps(state, indent=2) + '\n'); os.chmod(ownership, 0o600)
def run(cmd, timeout=120, **kwargs): return subprocess.run(cmd, env=kwargs.pop('env', env), timeout=timeout, check=True, **kwargs)
def dcmd(parts, timeout=120, **kwargs): return run(docker + parts, timeout=timeout, **kwargs)
def sha(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as source:
  while chunk:=source.read(1024*1024):h.update(chunk)
 return h.hexdigest()
def container_absent(name):
 value=dcmd(['ps','-a','--filter',f'name=^/{name}$','--format','{{.Names}}'],stdout=subprocess.PIPE,text=True).stdout.strip()
 return value==''
def image_absent():
 value=subprocess.run(docker+['image','inspect',renderer_image],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
 return value.returncode!=0
def network_absent():
 value=subprocess.run(docker+['network','inspect',renderer_network],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
 return value.returncode!=0
def group_members(pgid):
 rows=run(['ps','-axo','pid=,pgid=,uid='],stdout=subprocess.PIPE,text=True,timeout=5).stdout.splitlines(); found=[]
 for row in rows:
  parts=row.split()
  if len(parts)==3 and int(parts[1])==pgid:
   if int(parts[2])!=os.getuid(): raise RuntimeError('foreign process in owned process group')
   found.append(int(parts[0]))
 return found
child=None; created=[]; interrupted={'signal':None}; save()
def stop_child():
 if not child or not state.get('child'): return
 pgid=state['child']['pgid']
 if group_members(pgid): os.killpg(pgid,signal.SIGTERM)
 end=time.monotonic()+8
 while group_members(pgid) and time.monotonic()<end: time.sleep(.05)
 if group_members(pgid): os.killpg(pgid,signal.SIGKILL)
 try: child.wait(timeout=5)
 except subprocess.TimeoutExpired: pass
 if group_members(pgid): raise RuntimeError('owned child process group did not drain')
def on_signal(signum,_frame): interrupted['signal']=signum; raise KeyboardInterrupt()
signal.signal(signal.SIGINT,on_signal);signal.signal(signal.SIGTERM,on_signal)
try:
 if run([str(NODE),'--version'],stdout=subprocess.PIPE,text=True).stdout.strip()!='v26.9.0': raise RuntimeError('Node v26.9.0 required')
 if dcmd(['info','--format','{{.Name}}'],stdout=subprocess.PIPE,text=True).stdout.strip()!='colima-dvaia-pg-verify': raise RuntimeError('reviewed Docker daemon required')
 if dcmd(['image','inspect','--format','{{.Id}}',PG_IMAGE],stdout=subprocess.PIPE,text=True).stdout.strip()!=PG_IMAGE: raise RuntimeError('pinned PG image unavailable')
 if not args.provider_free_finalize:
  with urllib.request.urlopen('http://127.0.0.1:11434/api/tags',timeout=5) as response: body=response.read(262145)
  if len(body)>262144: raise RuntimeError('Ollama inventory too large')
  model=next((row for row in json.loads(body).get('models',[]) if row.get('name')=='llama3.1:8b'),None)
  if model is None or model.get('digest')!=MODEL_DIGEST: raise RuntimeError('pinned llama3.1:8b unavailable')
 run([str(NODE),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(ROOT),str(workspace)],cwd=ROOT)
 (workspace/'node_modules').symlink_to(ROOT/'node_modules',target_is_directory=True)
 inventory=['tests/postgres/secureshopPromptPolicyTaskComposed.integration.test.js','tests/postgres/run-prompt-policy-task-composed-isolated.py','package.json','package-lock.json']
 for folder in ['server','db/postgres','sidecars/sandbox-runner','tests/postgres']:
  inventory.extend(str(item.relative_to(workspace)) for item in sorted((workspace/folder).rglob('*')) if item.is_file())
 state['sourceSha256']={name:sha(workspace/name) for name in sorted(set(inventory))};state['nodeSha256']=sha(NODE);save()
 run([str(NODE),'--check','tests/postgres/secureshopPromptPolicyTaskComposed.integration.test.js'],cwd=workspace)
 dcmd(['network','create','--label',f'dvaia.qualification={suffix}',renderer_network]);created.append(('network',renderer_network))
 with build_log.open('w') as output:
  built=subprocess.run(docker+['build','--pull=false','-f','sidecars/sandbox-runner/Dockerfile','-t',renderer_image,'sidecars/sandbox-runner'],cwd=workspace,env=env,stdout=output,stderr=subprocess.STDOUT,timeout=300)
 os.chmod(build_log,0o600)
 if built.returncode: raise RuntimeError('renderer image build failed')
 created.append(('image',renderer_image)); state['rendererImageId']=json.loads(dcmd(['image','inspect',renderer_image],stdout=subprocess.PIPE,text=True).stdout)[0]['Id'];save()
 dcmd(['run','--detach','--pull','never','--name',renderer_name,'--label',f'dvaia.qualification={suffix}','--network',renderer_network,
  '--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/tmp:rw,noexec,nosuid,size=32m','--security-opt','seccomp=unconfined',
  '--security-opt','apparmor=dvaia-mcp-sandbox','-e','SECURESHOP_POLICY_RENDER_ENABLED=true','-e','SECURESHOP_POLICY_RENDER_MAX_CONCURRENT=1',
  '-p','127.0.0.1::8090',renderer_image],stdout=subprocess.DEVNULL);created.append(('container',renderer_name))
 renderer_port=int(dcmd(['port',renderer_name,'8090/tcp'],stdout=subprocess.PIPE,text=True).stdout.strip().rsplit(':',1)[1])
 renderer_origin=f'http://127.0.0.1:{renderer_port}'
 for _ in range(100):
  try:
   with urllib.request.urlopen(renderer_origin+'/health',timeout=2) as response: health=json.loads(response.read(65537))
   if health.get('policyRenderer')=={'enabled':True,'available':True,'isolation':'bwrap-policy-template-v1'}:break
  except Exception: pass
  time.sleep(.2)
 else: raise RuntimeError('renderer readiness failed')
 dcmd(['run','--detach','--pull','never','--name',pg_name,'--label',f'dvaia.qualification={suffix}','--memory','512m','--cpus','1','--pids-limit','128',
  '--tmpfs','/var/lib/postgresql:rw,size=335544320','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1',
  '-p','127.0.0.1::5432',PG_IMAGE,'-c','shared_buffers=16MB','-c','max_connections=48','-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL);created.append(('container',pg_name))
 for _ in range(100):
  if subprocess.run(docker+['exec',pg_name,'pg_isready','-U','postgres'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2).returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('PostgreSQL readiness failed')
 port=int(dcmd(['port',pg_name,'5432/tcp'],stdout=subprocess.PIPE,text=True).stdout.strip().rsplit(':',1)[1])
 psql=docker+['exec',pg_name,'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-c']
 roles={'IDENTITY':('dvaia_identity_migration','dvaia_identity_runtime'),'AGENTS':('dvaia_secureshop_agents_migration','dvaia_secureshop_agents_runtime'),
  'REVIEW':('dvaia_secureshop_review_migration','dvaia_secureshop_review_runtime'),'COMMERCE':('dvaia_secureshop_migration','dvaia_secureshop_runtime')}
 dcmd(psql[len(docker):]+[';'.join(f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS' for pair in roles.values() for role in pair)+';'],stdout=subprocess.DEVNULL)
 for store,(migration,runtime) in roles.items():
  database=f'dvaia_test_task_policy_{suffix}_{store.lower()}'
  dcmd(psql[len(docker):]+[f'CREATE DATABASE {database} OWNER {migration}'],stdout=subprocess.DEVNULL)
  dcmd(psql[len(docker):]+[f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime}'],stdout=subprocess.DEVNULL)
  env[f'PG_PROMPT_POLICY_TASK_COMPOSED_{store}_MIGRATION_URL']=f'postgresql://{quote(migration)}@127.0.0.1:{port}/{database}'
  env[f'PG_PROMPT_POLICY_TASK_COMPOSED_{store}_RUNTIME_URL']=f'postgresql://{quote(runtime)}@127.0.0.1:{port}/{database}'
 env.update(NODE_ENV='test',PG_TEST_DISPOSABLE='yes',PROMPT_POLICY_TASK_COMPOSED_NATIVE='1',DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace),
  PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',PROMPT_POLICY_RENDERER_ORIGIN=renderer_origin,
  OLLAMA_BASE_URL='http://127.0.0.1:11434',OLLAMA_MODEL='llama3.1:8b',AI_PROVIDER='ollama',
  PROMPT_POLICY_TASK_ACTUAL_MODEL='0' if args.provider_free_finalize else '1',
  HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',XENOVA_CACHE=str(cache.resolve()),
  AWS_EC2_METADATA_DISABLED='true',MCP_WORKSHOP_AUTOSTART='false',MCP_SIDECARS_AUTOSTART='false',SS_ENABLE='false',JWT_SECRET=uuid.uuid4().hex+uuid.uuid4().hex)
 with log_path.open('w') as log:
  os.chmod(log_path,0o600);child=subprocess.Popen([str(NODE),'--test','--test-reporter=tap','tests/postgres/secureshopPromptPolicyTaskComposed.integration.test.js'],cwd=workspace,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid)};state['status']='running';save()
  try: code=child.wait(timeout=360)
  except subprocess.TimeoutExpired: stop_child();raise RuntimeError('composed task policy parent deadline exceeded')
 if code: raise RuntimeError(f'composed task policy test failed ({code})')
 state['status']='passed';state['resultSha256']=sha(log_path)
 if not args.provider_free_finalize:state['modelDigest']=MODEL_DIGEST
 save()
except BaseException as error:
 state['status']='failed';state['error']={'type':type(error).__name__,'message':str(error)[:1000]};
 if log_path.exists():state['resultSha256']=sha(log_path)
 save()
finally:
 errors=[]
 try:stop_child()
 except Exception as error:errors.append('child:'+type(error).__name__)
 for kind,name in reversed(created):
  try:
   if kind=='container' and not container_absent(name): dcmd(['rm','-f','-v',name],timeout=60,stdout=subprocess.DEVNULL)
   elif kind=='image' and not image_absent(): dcmd(['image','rm','-f',name],timeout=60,stdout=subprocess.DEVNULL)
   elif kind=='network' and not network_absent(): dcmd(['network','rm',name],timeout=30,stdout=subprocess.DEVNULL)
  except Exception as error:errors.append(kind+':'+type(error).__name__)
 try:pgid_absent=not state.get('child') or not group_members(state['child']['pgid'])
 except Exception as error:errors.append('pgid:'+type(error).__name__);pgid_absent=False
 cleanup={'postgresAbsent':container_absent(pg_name),'rendererAbsent':container_absent(renderer_name),'imageAbsent':image_absent(),'networkAbsent':network_absent(),'childPgidAbsent':pgid_absent,'errors':errors,'completedAt':datetime.now(timezone.utc).isoformat()}
 state['cleanup']=cleanup
 if state['status']=='passed' and (not all(value is True for key,value in cleanup.items() if key.endswith('Absent')) or errors):state['status']='failed';state['error']={'type':'CleanupFailed'}
 save()
print(json.dumps({'status':state['status'],'evidence':str(evidence),'cleanup':state['cleanup']}),flush=True)
if state['status']!='passed':raise SystemExit(1)
