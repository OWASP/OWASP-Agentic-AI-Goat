#!/usr/bin/env python3
"""One-use owned PG18 + local8B FinFlow route qualification."""
import argparse, fcntl, hashlib, json, os, shutil, signal, subprocess, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from native_source_provenance import verify_source_copy
from finflow_native_gate import cleanup_owned, fixture_override_hashes, postgres_store_setup, private_jwt_secret, stage_source_copy, validate_grant, validate_owner_handle, finflow_executable_closure, preflight_staged_imports, cohort_contract


def caller_selection(selected, profile):
 """Select execution entries separately from manifest closure inputs."""
 route='tests/postgres/finflowRoute.integration.test.js'
 if profile=='current':return (*selected['NATIVE_TESTS'],*selected['DETERMINISTIC_TESTS'],route)
 if profile=='historical-native':return tuple(selected['NATIVE_TESTS'])
 if profile=='historical-route':return (route,)
 if profile=='historical-route-controls':return ('tests/finflowLogArtifactAuthority.test.js','tests/finflowRouteNativeLauncher.test.js',route)
 raise RuntimeError('explicit FinFlow caller profile required')

def validate_policy_evidence(evidence, expected_cohort):
 """Retain the historical exact scenario and qualification acceptance gate."""
 expected={'admin_read_logs','admin_llm_logs'}
 rows=evidence.get('scenarios',[])
 if (evidence.get('version')!=1 or evidence.get('cohort')!=expected_cohort
     or evidence.get('verification')!='controls_passed' or evidence.get('qualification')!='qualified'
     or not isinstance(rows,list) or len(rows)!=len(expected)
     or any(not isinstance(row,dict) for row in rows)
     or {row.get('objectiveId') for row in rows}!=expected
     or any(row.get('controlsPassed') is not True or row.get('qualification')!='qualified' for row in rows)):
  raise RuntimeError('FinFlow tests passed but policy cohort qualification is incomplete')
 return {'qualification':evidence['qualification'],'verification':evidence['verification']}

p=argparse.ArgumentParser();p.add_argument('--docker-host',required=True);p.add_argument('--grant-id',required=True);p.add_argument('--grant-file',default='tasks/native-verification-slot.json');p.add_argument('--owner-handle');p.add_argument('--owner-handle-file');p.add_argument('--objectives');p.add_argument('--canonical-workspace',required=True);p.add_argument('--candidate-source-root',required=True);p.add_argument('--candidate-manifest',required=True);p.add_argument('--candidate-manifest-sha256',required=True);p.add_argument('--cohort',required=True,choices=('durable-v9','combined-admin-durable','admin-error-r2'));p.add_argument('--caller-profile',default='current',choices=('current','historical-native','historical-route','historical-route-controls'));p.add_argument('--policy-cohort',choices=('finflow-customer-policy-v6','finflow-customer-policy-v7'));a=p.parse_args()
if a.caller_profile=='current':raise SystemExit('FinFlow route launcher is retained for historical qualification only; use tests/postgres/run-setup-database-phase-isolated.py with owner-bound finflow-policy or finflow-0055 scenarios')
if a.objectives is None:a.objectives='tool_enum,llm_identify,tool_version,admin_enum' if a.caller_profile=='historical-route' else 'admin_read_logs,admin_llm_logs'
source=Path(__file__).resolve().parents[2];OWNER='/root/dpi_release_gate'
if a.caller_profile in ('current','historical-native') and set(filter(None,a.objectives.split(',')))!={'admin_read_logs','admin_llm_logs'}:raise SystemExit('FinFlow native cohort is exactly admin_read_logs,admin_llm_logs')
if (a.caller_profile=='historical-native') != bool(a.policy_cohort):raise SystemExit('historical-native requires its exact policy cohort; other profiles reject policy cohort')
if bool(a.owner_handle)==bool(a.owner_handle_file):raise SystemExit('supply exactly one owner handle or handshake file')
if a.owner_handle_file:
 h=Path(a.owner_handle_file).resolve();print(f'WAITING_OWNER_HANDLE {h}',flush=True);end=time.monotonic()+60
 while time.monotonic()<end:
  try:value=h.read_text().strip()
  except FileNotFoundError:value=''
  if value:break
  time.sleep(.1)
 else:raise SystemExit('owner handle handshake timed out')
else:value=a.owner_handle
owner_handle=validate_owner_handle(value)
from finflow_candidate_source import verify_launch_roots, verify_candidate_source
source,manifest_path,canonical_workspace,grant=verify_launch_roots(a.candidate_source_root,a.candidate_manifest,a.canonical_workspace,a.grant_file,launcher_root=source)
parent=Path.home()/'.dvaia'/'native-verification';parent.mkdir(parents=True,exist_ok=True);os.chmod(parent,0o700);root=Path(tempfile.mkdtemp(prefix='dvaia-finflow-route-',dir=parent));os.chmod(root,0o700);copy=root/'source';docker=['docker','--host',a.docker_host];container='dvaia-finflow-route-'+uuid.uuid4().hex[:12];lock=grant.with_suffix(grant.suffix+'.consume-lock');ownership=root/'ownership.json';result=root/'result.log'
env0={k:os.environ[k] for k in ['PATH','HOME','TMPDIR'] if k in os.environ};managed=Path.home()/'.dvaia/runtimes/node-v26.8.2-darwin-arm64/bin';env0['PATH']=str(managed)+os.pathsep+env0.get('PATH','')
def save(path,data):
 tmp=path.with_suffix('.pending');tmp.write_text(json.dumps(data,indent=2,sort_keys=True)+'\n');os.chmod(tmp,0o600);os.replace(tmp,path)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def run(command,**kw):kw.setdefault('timeout',120);return subprocess.run(command,check=True,env=env0,**kw)
def safe_error(error):
 if isinstance(error,subprocess.CalledProcessError):return f'{type(error).__name__}: returncode={error.returncode}'
 if isinstance(error,subprocess.TimeoutExpired):return f'{type(error).__name__}: timed out'
 return type(error).__name__
selected=cohort_contract(a.cohort)
execution_tests=caller_selection(selected,a.caller_profile)
tracked=finflow_executable_closure(source,cohort=a.cohort)
if any(name not in tracked for name in execution_tests):raise RuntimeError('selected FinFlow execution entrypoint is outside the verified closure')
prepared_grant=json.loads(grant.read_text())
prepared_hashes=verify_candidate_source(source,manifest_path,str(source),a.candidate_manifest_sha256,prepared_grant.get('sourceHashes'),required_paths=tracked)
validate_grant(prepared_grant,grant_id=a.grant_id,owner=OWNER,docker_host=a.docker_host,canonical_workspace=canonical_workspace,candidate_source_root=source,candidate_manifest_sha256=a.candidate_manifest_sha256,source_hashes=prepared_hashes)
stage_source_copy(source,copy,tracked,dependency_root=canonical_workspace/'node_modules',cohort=a.cohort)
fixture_baselines=['server/sensitive_files/logs/access.log','server/sensitive_files/logs/error.log','server/sensitive_files/logs/audit.log','server/sensitive_files/logs/llm_requests.log']
hashes=verify_source_copy(source,copy,tracked)
state={'version':1,'historicalCohort':a.cohort,'callerProfile':a.caller_profile,'executionTests':list(execution_tests),'owner':OWNER,'ownerHandle':owner_handle,'launcherPid':os.getpid(),'consumerPid':os.getpid(),'grantId':a.grant_id,'grantFile':str(grant),'dockerHost':a.docker_host,'evidence':str(root),'container':container,'createdAt':datetime.now(timezone.utc).isoformat(),'runStatus':'prepared','sourceInventoryCount':len(tracked),'sourceHashes':hashes,'copiedSourceHashes':dict(hashes),'approvedFixtureBaselines':{relative:{'sha256':hashes[relative],'byteLength':(source/relative).stat().st_size} for relative in fixture_baselines},'fixtureOverrides':{},'cleanup':None}
def persist():save(ownership,state)
persist()
try:lock.mkdir(mode=0o700)
except FileExistsError as e:raise RuntimeError('native verification grant is already being consumed') from e
try:
 g=json.loads(grant.read_text())
 verify_candidate_source(source,manifest_path,str(source),a.candidate_manifest_sha256,g.get('sourceHashes'),required_paths=tracked)
 validate_grant(g,grant_id=a.grant_id,owner=OWNER,docker_host=a.docker_host,canonical_workspace=canonical_workspace,candidate_source_root=source,candidate_manifest_sha256=a.candidate_manifest_sha256,source_hashes=hashes)
 verify_source_copy(source,copy,tracked,granted=g.get('sourceHashes'));g.update(status='consumed',runStatus='running',consumedAt=datetime.now(timezone.utc).isoformat(),ownerHandle=owner_handle,launcherPid=os.getpid(),consumerPid=os.getpid(),evidence=str(root),container=container);save(grant,g);state['runStatus']='running';persist()
finally:lock.rmdir()
child=None;attempted=False;child_pgid=None;child_session=None

def members(pgid,session_id):
 output=subprocess.run(['ps','-axo','pid=,pgid=,uid='],env=env0,capture_output=True,text=True,check=True,timeout=2).stdout
 result=[]
 for line in output.splitlines():
  fields=line.split()
  if len(fields)!=3 or int(fields[1])!=pgid:continue
  pid,uid=int(fields[0]),int(fields[2])
  try:
   if os.getsid(pid)!=session_id:raise RuntimeError('Refusing to signal a reused process group with another session')
   result.append((pid,uid))
  except ProcessLookupError:pass
 if any(uid!=os.getuid() for pid,uid in result):raise RuntimeError('Refusing to signal a process group containing foreign processes')
 return [pid for pid,uid in result]

def stop_child():
 if child is None:return True
 if child_pgid is None or child_session is None:raise RuntimeError('owned child process group was not bound')
 if members(child_pgid,child_session):
  try:os.killpg(child_pgid,signal.SIGTERM)
  except ProcessLookupError:pass
 deadline=time.monotonic()+5
 while members(child_pgid,child_session) and time.monotonic()<deadline:
  child.poll();time.sleep(.05)
 if members(child_pgid,child_session):
  try:os.killpg(child_pgid,signal.SIGKILL)
  except ProcessLookupError:pass
 child.wait(timeout=10)
 if members(child_pgid,child_session):raise RuntimeError('Owned Node process group cleanup did not complete')
 return child.poll() is not None

try:
 if run(['node','--version'],capture_output=True,text=True).stdout.strip()!='v26.8.2':raise RuntimeError('managed Node v26.8.2 is required')
 daemon=json.loads(run(docker+['info','--format','{{json .}}'],capture_output=True,text=True,timeout=30).stdout)
 if daemon.get('Name')!='colima-dvaia-pg-verify' or daemon.get('Architecture')!='aarch64':raise RuntimeError('exact Colima verification daemon is required')
 if run(docker+['ps','-a','--filter',f'name=^{container}$','--format','{{.Names}}'],capture_output=True,text=True,timeout=20).stdout.strip():raise RuntimeError('owned PostgreSQL name is not absent')
 attempted=True;run(docker+['run','--detach','--pull','never','--name',container,'--tmpfs','/var/lib/postgresql:rw,size=268435456','-e','POSTGRES_USER=finflow_route_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432','postgres:18','-c','shared_buffers=16MB','-c','max_connections=48','-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL)
 inspected=json.loads(run(docker+['inspect',container],capture_output=True,text=True).stdout)[0]
 if inspected.get('Mounts') or '/var/lib/postgresql' not in inspected.get('HostConfig',{}).get('Tmpfs',{}):raise RuntimeError('owned PostgreSQL must use tmpfs without mounts')
 state.update(containerId=inspected['Id'],mounts=inspected['Mounts'],nodeVersion='v26.8.2');persist();end=time.monotonic()+30
 while time.monotonic()<end:
  if subprocess.run(docker+['exec',container,'pg_isready','-h','127.0.0.1','-U','finflow_route_admin'],env=env0,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3).returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('owned PostgreSQL did not become ready')
 port=int(run(docker+['port',container,'5432/tcp'],capture_output=True,text=True,timeout=20).stdout.strip().rsplit(':',1)[1]);psql=['psql','-h','127.0.0.1','-p',str(port),'-U','finflow_route_admin','-d','postgres','-v','ON_ERROR_STOP=1']
 stores=[('identity','dvaia_test_finflow_route_identity'),('finflow','dvaia_test_finflow_route_store')]
 for command in postgres_store_setup(stores):run(psql+['-c',command],stdout=subprocess.DEVNULL)
 fixtures={'server/sensitive_files/config/secrets.env':'JWT_SECRET=owned_finflow_fixture_secret\nAPI_KEY=owned_fixture_key\n','server/sensitive_files/config/llm_config.yml':'provider: ollama\nmodel: llama3.1:8b\nendpoint: http://127.0.0.1:11434\n','server/sensitive_files/etc/passwd':'root:x:0:0:root:/root:/bin/bash\nfinflow:x:1001:1001:FinFlow:/var/app:/bin/sh\n','server/sensitive_files/logs/access.log':'127.0.0.1 GET /owned-finflow 200\n','server/config/secrets.env':'JWT_SECRET=owned_finflow_admin_secret\nAPI_KEY=owned_admin_fixture_key\n'}
 override_hashes=fixture_override_hashes(state['approvedFixtureBaselines'],fixtures)
 for relative,content in fixtures.items():
  target=copy/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(content);state['fixtureOverrides'][relative]=override_hashes[relative]
 persist();(copy/'server/workshop_data/transactions').mkdir(parents=True,exist_ok=True);(copy/'server/workshop_data/documents').mkdir(parents=True,exist_ok=True)
 if 'llama3.1:8b' not in run(['curl','--fail','--silent','--show-error','--max-time','5','http://127.0.0.1:11434/api/tags'],capture_output=True,text=True).stdout:raise RuntimeError('local Ollama does not advertise llama3.1:8b')
 jwt_secret=private_jwt_secret()
 env=dict(env0,NODE_ENV='test',PG_TEST_DISPOSABLE='yes',FINFLOW_ROUTE_ISOLATED='1',DVAIA_ISOLATED_TEST_WORKSPACE=str(copy),PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',AI_PROVIDER='ollama',JUDGE_PROVIDER='ollama',OLLAMA_MODEL='llama3.1:8b',JUDGE_MODEL='llama3.1:8b',OLLAMA_BASE_URL='http://127.0.0.1:11434',JWT_SECRET=jwt_secret,AWS_EC2_METADATA_DISABLED='true',MCP_WORKSHOP_AUTOSTART='false',MCP_SIDECARS_AUTOSTART='false',SS_ENABLE='false',HF_HUB_OFFLINE='1',SANDBOX_RUNNER_URL='http://127.0.0.1:1',SSRF_TARGET_URL='http://127.0.0.1:1',ROGUE_MCP_URL='http://127.0.0.1:1',MAILPIT_API_URL='http://127.0.0.1:1',MAILPIT_SMTP_HOST='127.0.0.1',MAILPIT_SMTP_PORT='1',LOGS_DIR=str(root/'logs'),FINFLOW_ROUTE_OBJECTIVES=a.objectives)
 for family,database in stores:
  prefix={'identity':'IDENTITY','finflow':'FINFLOW_WORKSHOP'}[family];env[f'{prefix}_MIGRATION_DATABASE_URL']=f'postgresql://dvaia_{family}_migration@127.0.0.1:{port}/{database}';env[f'{prefix}_DATABASE_URL']=f'postgresql://dvaia_{family}_runtime@127.0.0.1:{port}/{database}'
 preflight_staged_imports(copy,node_binary=managed/'node',environment=env)
 with result.open('w') as log:
  os.chmod(result,0o600);child=subprocess.Popen(['node','--test','--test-reporter=tap','--test-concurrency=1',*execution_tests],cwd=copy,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);child_pgid=os.getpgid(child.pid);child_session=os.getsid(child.pid);state.update(testPid=child.pid,testPgid=child_pgid,testSessionId=child_session);persist();code=child.wait(timeout=900)
 state.update(testExitCode=code,resultSha256=sha(result));persist()
 if code:raise RuntimeError(f'FinFlow route qualification failed ({code})')
 if a.caller_profile=='historical-native':
  cohort_evidence=root/'policy-cohort.json'
  if not cohort_evidence.is_file() or cohort_evidence.is_symlink():raise RuntimeError('FinFlow policy cohort evidence is missing')
  state.update(cohortEvidence=str(cohort_evidence),cohortEvidenceSha256=sha(cohort_evidence));persist()
  state.update(validate_policy_evidence(json.loads(cohort_evidence.read_text()),a.policy_cohort));persist()
 state['runStatus']='terminal_pass';persist()
except Exception as error:state['runStatus']='terminal_fail';state['failure']=safe_error(error);persist()
finally:
 if result.exists():state['resultSha256']=sha(result)
 cohort_evidence=root/'policy-cohort.json'
 if cohort_evidence.is_file() and not cohort_evidence.is_symlink():state.update(cohortEvidence=str(cohort_evidence),cohortEvidenceSha256=sha(cohort_evidence))
 def remove_container():
  if not attempted:return None
  return subprocess.run(docker+['rm','--force',container],env=env0,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30).returncode
 def container_absent():
  remaining=subprocess.run(docker+['ps','-a','--filter',f'name=^{container}$','--format','{{.Names}}'],env=env0,capture_output=True,text=True,timeout=20)
  return remaining.returncode==0 and not remaining.stdout.strip()
 cleanup=cleanup_owned(stop_child=stop_child,remove_container=remove_container,container_absent=container_absent);cleanup['childExitCode']=None if child is None else child.poll();state['cleanup']=cleanup;state['runStatus']='terminal_pass_cleaned' if state['runStatus']=='terminal_pass' and cleanup['clean'] else 'terminal_fail';state['completedAt']=datetime.now(timezone.utc).isoformat();persist()
 try:
  g=json.loads(grant.read_text())
  if g.get('grantId')==a.grant_id and g.get('status')=='consumed' and g.get('ownerHandle')==owner_handle and g.get('consumerPid')==os.getpid():g.update(runStatus='terminal_pass' if state['runStatus']=='terminal_pass_cleaned' else 'terminal_fail',completedAt=state['completedAt'],cleanup=state['cleanup'],sourceHashes=state['sourceHashes'],resultSha256=state.get('resultSha256'),cohortEvidenceSha256=state.get('cohortEvidenceSha256'),qualification=state.get('qualification'),verification=state.get('verification'));save(grant,g)
 except Exception as error:state['grantUpdateError']=safe_error(error);persist()
print(f'FinFlow qualification evidence retained: {root}',flush=True)
if state['runStatus']!='terminal_pass_cleaned':raise RuntimeError(state.get('failure') or 'FinFlow cleanup was not proven complete')
