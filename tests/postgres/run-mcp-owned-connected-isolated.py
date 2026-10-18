#!/usr/bin/env python3
"""One-use connected MCP gate: owned PG, Mailpit, strict target, actor and Judge."""

import argparse, hashlib, json, os, re, secrets, shutil, subprocess, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from native_copied_permissions import make_copied_directories_owner_writable
from native_source_provenance import verify_source_copy
from native_readiness_evidence import capture_failure, probe

parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True);parser.add_argument('--grant-id',required=True)
parser.add_argument('--candidate',choices=['protected-state','tool-poisoning','recon','recon-production'],default='protected-state')
parser.add_argument('--grant-file',default='tasks/native-verification-slot.json');parser.add_argument('--owner-handle');parser.add_argument('--owner-handle-file')
args=parser.parse_args();source=Path(__file__).resolve().parents[2]
if bool(args.owner_handle)==bool(args.owner_handle_file): raise SystemExit('supply exactly one owner handle or handshake file')
if args.owner_handle_file:
 handshake=Path(args.owner_handle_file).resolve();print(f'WAITING_OWNER_HANDLE {handshake}',flush=True);deadline=time.monotonic()+60
 while time.monotonic()<deadline:
  try:
   supplied=handshake.read_text().strip()
   if supplied: break
  except FileNotFoundError: pass
  time.sleep(.1)
 else: raise SystemExit('owner handle handshake timed out')
else: supplied=args.owner_handle
if not supplied.isdecimal() or int(supplied)<=0: raise SystemExit('owner handle must be the positive exec session ID')
owner_handle=int(supplied);grant_path=(source/args.grant_file).resolve() if not Path(args.grant_file).is_absolute() else Path(args.grant_file)
tool_poisoning_candidate=args.candidate=='tool-poisoning'
recon_candidate=args.candidate=='recon'
recon_production=args.candidate=='recon-production'
grant_lock=grant_path.with_suffix(grant_path.suffix+'.consume-lock');docker=['docker','--host',args.docker_host]
evidence_parent=Path.home()/'.dvaia'/'native-verification';evidence_parent.mkdir(parents=True,exist_ok=True);os.chmod(evidence_parent,0o700)
root=Path(tempfile.mkdtemp(prefix='dvaia-mcp-owned-connected-',dir=evidence_parent));os.chmod(root,0o700);workspace=root/'source'
def ignore(_directory,names):
 denied={'.git','node_modules','build','logs','uploads','sensitive_files','workshop_data','vector-indexes','coverage','.cache','__pycache__'}
 return [name for name in names if name in denied or name.startswith('.env') or any(name.endswith(suffix) for suffix in ['.db','.db-wal','.db-shm','.db-journal','.sqlite','.sqlite3','.log'])]
for directory in ['server','db','tests','docs','sidecars','scripts']: shutil.copytree(source/directory,workspace/directory,ignore=ignore)
make_copied_directories_owner_writable(workspace)
(workspace/'sidecars/sandbox-runner/labfs/opt/app/config/.env').write_bytes(
 (source/'sidecars/sandbox-runner/labfs/opt/app/config/.env').read_bytes())
(workspace/'sidecars/sandbox-runner/labfs/opt/app/config/.env').chmod(0o444)
(workspace/'package.json').write_bytes((source/'package.json').read_bytes())
(workspace/'package-lock.json').write_bytes((source/'package-lock.json').read_bytes())
(workspace/'node_modules').symlink_to(source/'node_modules',target_is_directory=True)
base_env={key:os.environ[key] for key in ['PATH','HOME','TMPDIR'] if key in os.environ};managed=Path.home()/'.dvaia/runtimes/node-v26.8.2-darwin-arm64/bin';base_env['PATH']=str(managed)+os.pathsep+base_env.get('PATH','')
suffix=uuid.uuid4().hex[:12];profile_name='dvaia-mcp-sandbox-'+suffix;token=secrets.token_urlsafe(48);jwt_secret=secrets.token_urlsafe(64)
profile_template=workspace/'sidecars/sandbox-runner/apparmor/dvaia-mcp-sandbox.apparmor.in';profile_path=root/f'{profile_name}.apparmor'
subprocess.run([str(managed/'node'),str(workspace/'scripts/render-mcp-sandbox-apparmor.js'),str(profile_template),str(profile_path),profile_name],check=True,env=base_env)
ssh_config=Path.home()/'.colima/_lima/colima-dvaia-pg-verify/ssh.config';ssh_host='lima-colima-dvaia-pg-verify'
remote_dir=f'/tmp/{profile_name}';remote_profile=f'{remote_dir}/policy.apparmor';remote_marker=f'{remote_dir}/owner';remote_owner=secrets.token_hex(64)
local_marker=root/'remote-owner';local_marker.write_text(remote_owner);os.chmod(local_marker,0o600)
ssh=['ssh','-F',str(ssh_config),ssh_host,'--'];scp=['scp','-F',str(ssh_config)]
containers={'postgres':'dvaia-mcp-connected-pg-'+suffix,'mailpit':'dvaia-mcp-connected-mailpit-'+suffix,'runner':'dvaia-mcp-connected-runner-'+suffix}
image=f'dvaia-mcp-connected-runner:{suffix}'
inventory_rel='docs/modernization/drafts/mcp-owned-connected-v20-tracked-files-2026-09-14.json'
inventory=json.loads((source/inventory_rel).read_text())
tracked=inventory.get('trackedFiles')
if (inventory.get('version')!=1 or not isinstance(tracked,list) or not tracked
    or tracked!=sorted(set(tracked)) or inventory_rel not in tracked
    or 'tests/postgres/run-mcp-owned-connected-isolated.py' not in tracked):
 raise RuntimeError('Exact connected MCP tracked-file inventory is required')
digest=lambda file:hashlib.sha256(file.read_bytes()).hexdigest();ownership_path=root/'ownership.json'
source_hashes=verify_source_copy(source,workspace,tracked)
copied_hashes=dict(source_hashes)
ownership={'version':1,'owner':'/root/workshop_authenticity','ownerHandle':owner_handle,'launcherPid':os.getpid(),'grantId':args.grant_id,'grantFile':str(grant_path),'dockerHost':args.docker_host,'evidence':str(root),'status':'prepared','createdAt':datetime.now(timezone.utc).isoformat(),'containers':containers,'images':{'runner':image},'apparmor':{'profileName':profile_name,'remoteDirectory':remote_dir,'loaded':False},'sourceHashes':source_hashes,'copiedSourceHashes':copied_hashes,'boundary':{'smtp':'real owned Mailpit','model':'actual local llama3.1:8b','runner':'scoped AppArmor + bwrap + final seccomp','migration':'normal copied loaders apply through registered identity 0061_mcp_supply_chain_curriculum_defaults.sql and MCP 0004_mcp_owned_resources.sql in disposable databases; no live registration','installerPath':'production' if recon_production else ('test-only-candidate' if recon_candidate else 'existing'), 'objectives':['mcp_recon'] if (recon_candidate or recon_production) else (['mcp_tool_poisoning'] if tool_poisoning_candidate else ['mcp_secret_exposure','mcp_broken_authz','mcp_audit_gap'])}}
def persist(path,value):
 pending=path.with_suffix(path.suffix+'.pending');pending.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n');os.chmod(pending,0o600);os.replace(pending,path)
def save(): persist(ownership_path,ownership)
def run(command,**kwargs): kwargs.setdefault('timeout',180);return subprocess.run(command,check=True,env=base_env,**kwargs)
def public_error(error):
 if isinstance(error,subprocess.CalledProcessError): return f'{type(error).__name__}: subprocess failed with return code {error.returncode}'
 if isinstance(error,subprocess.TimeoutExpired): return f'{type(error).__name__}: subprocess timed out'
 value=str(error).replace(token,'[redacted-token]').replace(jwt_secret,'[redacted-jwt-secret]')
 value=re.sub(r'(https?://[^\s?]+)\?[^\s]+',r'\1?[redacted]',value)
 return f'{type(error).__name__}: {value[:512]}'
def port(container,spec):
 value=run(docker+['port',container,spec],capture_output=True,text=True,timeout=20).stdout.strip()
 if not value: raise RuntimeError(f'{container} did not publish {spec}')
 return int(value.splitlines()[-1].rsplit(':',1)[1])
save()
try: grant_lock.mkdir(mode=0o700)
except FileExistsError as error: raise RuntimeError('Native verification grant is already being consumed') from error
try:
 grant=json.loads(grant_path.read_text())
 if grant.get('grantId')!=args.grant_id or grant.get('status')!='granted' or grant.get('owner')!='/root/workshop_authenticity' or grant.get('allowedLaunches')!=1 or grant.get('dockerHost')!=args.docker_host: raise RuntimeError('Exact connected MCP grant is required')
 source_hashes=verify_source_copy(source,workspace,tracked,granted=grant.get('sourceHashes'))
 grant.update(status='consumed',runStatus='running',consumedAt=datetime.now(timezone.utc).isoformat(),ownerHandle=owner_handle,launcherPid=os.getpid(),evidence=str(root),containers=containers,images={'runner':image});persist(grant_path,grant)
 ownership.update(status='running',consumedAt=grant['consumedAt']);save()
finally: grant_lock.rmdir()
started=[];container_attempted=[];built=False;build_attempted=False;remote_creation_attempted=False;marker_matches=False;profile_load_attempted=False
try:
 daemon=json.loads(run(docker+['info','--format','{{json .}}'],capture_output=True,text=True,timeout=30).stdout)
 if daemon.get('Name')!='colima-dvaia-pg-verify' or daemon.get('Architecture')!='aarch64': raise RuntimeError('Exact Colima verification daemon is required')
 for name,container in containers.items():
  prior_container=run(docker+['ps','-a','--filter',f'name=^{container}$','--format','{{.Names}}'],capture_output=True,text=True,timeout=20)
  if prior_container.stdout.strip(): raise RuntimeError(f'Owned {name} container name was not absent before use')
 prior_image=run(docker+['images','--filter',f'reference={image}','--format','{{.Repository}}:{{.Tag}}'],capture_output=True,text=True,timeout=20)
 if prior_image.stdout.strip(): raise RuntimeError('Owned runner image tag was not absent before use')
 if not ssh_config.is_file(): raise RuntimeError('Exact Colima verification SSH config is required')
 if subprocess.run(ssh+['sudo','grep','-F',profile_name,'/sys/kernel/security/apparmor/profiles'],env=base_env,capture_output=True,text=True,timeout=20).returncode!=1: raise RuntimeError('Unique AppArmor profile was not absent')
 if subprocess.run(ssh+['test','!','-e',remote_dir],env=base_env,timeout=20).returncode!=0: raise RuntimeError('Unique remote policy directory was not absent')
 remote_creation_attempted=True;run(ssh+['mkdir','-m','0700','--',remote_dir],timeout=20);run(scp+[str(local_marker),f'{ssh_host}:{remote_marker}'],timeout=20)
 marker_matches=run(ssh+['cat','--',remote_marker],capture_output=True,text=True,timeout=20).stdout==remote_owner
 if not marker_matches: raise RuntimeError('Remote policy ownership marker mismatch')
 run(scp+[str(profile_path),f'{ssh_host}:{remote_profile}'],timeout=30);run(ssh+['chmod','0600',remote_profile],timeout=20);run(ssh+['sudo','apparmor_parser','--skip-kernel-load',remote_profile],timeout=30)
 profile_load_attempted=True;run(ssh+['sudo','apparmor_parser','-r',remote_profile],timeout=30)
 label=run(ssh+['sudo','grep','-F',profile_name,'/sys/kernel/security/apparmor/profiles'],capture_output=True,text=True,timeout=20).stdout
 if f'{profile_name} (enforce)' not in label: raise RuntimeError('Owned AppArmor profile did not load in enforce mode')
 ownership['apparmor'].update(loaded=True,loadVerified=True);save()
 build_log=root/'runner-build.log'
 build_attempted=True
 with build_log.open('w') as log: run(docker+['build','--tag',image,str(workspace/'sidecars/sandbox-runner')],stdout=log,stderr=subprocess.STDOUT,timeout=600)
 os.chmod(build_log,0o600)
 built=True;ownership['imageId']=run(docker+['image','inspect','--format','{{.Id}}',image],capture_output=True,text=True).stdout.strip();ownership['buildSha256']=digest(build_log);save()
 pg=containers['postgres'];container_attempted.append(pg);run(docker+['run','--detach','--pull','never','--name',pg,'--tmpfs','/var/lib/postgresql:rw,size=268435456','-e','POSTGRES_USER=mcp_connected_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432','postgres:18','-c','shared_buffers=16MB','-c','max_connections=40','-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL);started.append(pg)
 mailpit=containers['mailpit'];container_attempted.append(mailpit);run(docker+['run','--detach','--pull','never','--name',mailpit,'--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=16777216','-p','127.0.0.1::1025','-p','127.0.0.1::8025','axllent/mailpit:latest'],stdout=subprocess.DEVNULL);started.append(mailpit)
 runner=containers['runner'];container_attempted.append(runner);run(docker+['run','--detach','--name',runner,'--security-opt','seccomp=unconfined','--security-opt',f'apparmor={profile_name}','--tmpfs','/sandbox:rw,uid=10001,gid=10001,mode=0700','-e','MCP_OWNED_TARGETS_ENABLED=true','-e',f'MCP_OWNED_TARGET_TOKEN={token}','-e',f'MCP_OWNED_TARGET_APPARMOR_PROFILE={profile_name}','-p','127.0.0.1::8090',image],stdout=subprocess.DEVNULL);started.append(runner)
 ownership['containerIds']={name:run(docker+['inspect','--format','{{.Id}}',container],capture_output=True,text=True).stdout.strip() for name,container in containers.items()};save()
 runner_node_version=run(docker+['exec',runner,'node','--version'],capture_output=True,text=True,timeout=20).stdout.strip()
 if runner_node_version!='v26.8.2': raise RuntimeError(f'Owned runner Node runtime differs: {runner_node_version}')
 ownership['runnerNodeVersion']=runner_node_version;save()
 pg_port=port(pg,'5432/tcp');smtp_port=port(mailpit,'1025/tcp');mail_api_port=port(mailpit,'8025/tcp');runner_port=port(runner,'8090/tcp')
 deadline=time.monotonic()+40
 last_readiness={}
 while time.monotonic()<deadline:
  last_readiness={
   'postgres':probe(docker+['exec',pg,'pg_isready','-h','127.0.0.1','-U','mcp_connected_admin'],base_env,3),
   'mailpit':probe(['curl','--fail','--silent','--max-time','2',f'http://127.0.0.1:{mail_api_port}/api/v1/info'],base_env,3),
   'runner':probe(['curl','--fail','--silent','--max-time','2','-H',f'Authorization: Bearer {token}',f'http://127.0.0.1:{runner_port}/owned-targets/health'],base_env,3,health=True),
  }
  if all(item['status']=='ready' for item in last_readiness.values()): break
  time.sleep(.25)
 else:
  ownership['readinessFailure']=capture_failure(root,last_readiness,containers,docker,base_env);save()
  failed=','.join(name for name,item in last_readiness.items() if item['status']!='ready')
  raise RuntimeError(f'Owned service readiness failed: {failed or "unknown"}')
 health=json.loads(last_readiness['runner']['stdout'])
 expected_health={'ready':True,'version':'mcp-owned-target-http.v1','isolation':'bwrap-seccomp-v1','supervisorProfile':f'{profile_name} (enforce)','protectedStateCapability':'mcp-owned-protected-state-transition.v2','observedActionCapability':'mcp-owned-observed-action.v1','packageInstallCapability':'mcp-owned-package-install.v1'}
 if health!=expected_health:
  ownership['readinessFailure']=capture_failure(root,last_readiness,containers,docker,base_env);save()
  raise RuntimeError('Strict runner readiness receipt differs')
 psql=['psql','-h','127.0.0.1','-p',str(pg_port),'-U','mcp_connected_admin','-d','postgres','-v','ON_ERROR_STOP=1']
 for role in ['dvaia_identity_migration','dvaia_identity_runtime','dvaia_mcp_migration','dvaia_mcp_runtime']: run(psql+['-c',f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],stdout=subprocess.DEVNULL)
 env=dict(base_env,NODE_ENV='test',EXPORT_INTERNALS='1',RUN_MCP_OWNED_CONNECTED='yes',MCP_PROTECTED_STATE_CANDIDATE='no' if tool_poisoning_candidate else 'yes',MCP_OBSERVED_ACTION_CANDIDATE='yes' if tool_poisoning_candidate else 'no',MCP_CATALOG_RECON_CANDIDATE='yes' if recon_candidate else 'no',MCP_CATALOG_RECON_PRODUCTION='yes' if recon_production else 'no',PG_TEST_DISPOSABLE='yes',PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',MCP_OWNED_RESOURCES_ENABLED='true',AI_PROVIDER='ollama',OLLAMA_BASE_URL='http://127.0.0.1:11434',OLLAMA_MODEL='llama3.1:8b',AWS_EC2_METADATA_DISABLED='true',JWT_SECRET=jwt_secret,PG_MCP_CONNECTED_ADMIN_URL=f'postgresql://mcp_connected_admin@127.0.0.1:{pg_port}/postgres',MCP_OWNED_TARGET_URL=f'http://127.0.0.1:{runner_port}',MCP_OWNED_TARGET_TOKEN=token,MAILPIT_SMTP_HOST='127.0.0.1',MAILPIT_SMTP_PORT=str(smtp_port),MAILPIT_API_URL=f'http://127.0.0.1:{mail_api_port}',SANDBOX_RUNNER_URL='http://127.0.0.1:1',SSRF_TARGET_URL='http://127.0.0.1:1',ROGUE_MCP_URL='http://127.0.0.1:1',LOGS_DIR=str(root/'logs'),MCP_JUDGE_INVALID_ATTEMPTS_PATH=str(root/'judge-invalid-attempts.jsonl'))
 result=root/'result.log';completed=subprocess.run(['node','--test','--test-reporter=tap','tests/postgres/mcpOwnedConnected.integration.test.js'],cwd=workspace,env=env,capture_output=True,text=True,timeout=780)
 result.write_text('HOST_NODE_VERSION='+run(['node','--version'],capture_output=True,text=True).stdout.strip()+'\nRUNNER_NODE_VERSION='+runner_node_version+'\nRUNNER_HEALTH='+json.dumps(health,sort_keys=True)+'\n'+completed.stdout+completed.stderr);os.chmod(result,0o600)
 invalid_attempts=root/'judge-invalid-attempts.jsonl'
 if invalid_attempts.is_file():
  raw_lines=[line for line in invalid_attempts.read_text().splitlines() if line.strip()]
  ownership['judgeInvalidAttempts']={'path':str(invalid_attempts),'sha256':digest(invalid_attempts),
    'byteCount':invalid_attempts.stat().st_size,'attemptCount':len(raw_lines),
    'mode':oct(invalid_attempts.stat().st_mode & 0o777)}
 for private_log in (root/'logs').glob('*.log'): os.chmod(private_log,0o600)
 print(f'Owned connected MCP test terminal rc={completed.returncode}; private result retained at {result}',flush=True)
 ownership.update(resultSha256=digest(result),testExitCode=completed.returncode)
 if completed.returncode: raise RuntimeError(f'Connected MCP qualification failed ({completed.returncode})')
 ownership['status']='terminal_pass';save()
except Exception as error:
 ownership['status']='terminal_fail';ownership['failure']=public_error(error);save()
finally:
 cleanup={};cleanup_errors=[]
 def cleanup_attempt(label,operation):
  try:return operation()
  except Exception as cleanup_error:
   cleanup_errors.append({'stage':label,'error':public_error(cleanup_error)});return None
 for name,container in reversed(list(containers.items())):
  remove=cleanup_attempt(f'remove-container-{name}',lambda container=container:subprocess.run(docker+['rm','--force',container],env=base_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)) if container in container_attempted else None
  query=cleanup_attempt(f'query-container-{name}',lambda container=container:subprocess.run(docker+['ps','-a','--filter',f'name=^{container}$','--format','{{.Names}}'],env=base_env,capture_output=True,text=True,timeout=20))
  cleanup[name]={'removeReturnCode':None if remove is None else remove.returncode,'absenceQueryReturnCode':None if query is None else query.returncode,'exactAbsent':query is not None and query.returncode==0 and not query.stdout.strip()}
 image_remove=cleanup_attempt('remove-runner-image',lambda:subprocess.run(docker+['image','rm','--force',image],env=base_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=60)) if build_attempted else None
 image_query=cleanup_attempt('query-runner-image',lambda:subprocess.run(docker+['images','--filter',f'reference={image}','--format','{{.Repository}}:{{.Tag}}'],env=base_env,capture_output=True,text=True,timeout=20))
 loaded_query=cleanup_attempt('query-profile-before-unload',lambda:subprocess.run(ssh+['sudo','grep','-F',profile_name,'/sys/kernel/security/apparmor/profiles'],env=base_env,capture_output=True,text=True,timeout=20))
 if profile_load_attempted and loaded_query is not None and loaded_query.returncode==0 and marker_matches: unload=cleanup_attempt('unload-profile',lambda:subprocess.run(ssh+['sudo','apparmor_parser','-R',remote_profile],env=base_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30))
 else: unload=None
 profile_query=cleanup_attempt('query-profile-after-unload',lambda:subprocess.run(ssh+['sudo','grep','-F',profile_name,'/sys/kernel/security/apparmor/profiles'],env=base_env,capture_output=True,text=True,timeout=20));profile_absent=profile_query is not None and profile_query.returncode==1 and not profile_query.stdout.strip()
 policy_delete=marker_delete=directory_delete=None
 if marker_matches and profile_absent:
  policy_delete=cleanup_attempt('delete-remote-policy',lambda:subprocess.run(ssh+['rm','-f','--',remote_profile],env=base_env,timeout=20))
  marker_delete=cleanup_attempt('delete-remote-marker',lambda:subprocess.run(ssh+['rm','-f','--',remote_marker],env=base_env,timeout=20))
  directory_delete=cleanup_attempt('delete-remote-directory',lambda:subprocess.run(ssh+['rmdir','--',remote_dir],env=base_env,timeout=20))
 remote_query=cleanup_attempt('query-remote-directory',lambda:subprocess.run(ssh+['test','!','-e',remote_dir],env=base_env,timeout=20));remote_absent=remote_query is not None and remote_query.returncode==0
 image_absent=image_query is not None and image_query.returncode==0 and not image_query.stdout.strip()
 cleanup_ok=not cleanup_errors and all(item['exactAbsent'] for item in cleanup.values()) and image_absent and profile_absent and remote_absent and (unload is None or unload.returncode==0) and all(item is not None and item.returncode==0 for item in [policy_delete,marker_delete,directory_delete])
 ownership['cleanup']={'errors':cleanup_errors,'containers':cleanup,'image':{'tag':image,'removeReturnCode':None if image_remove is None else image_remove.returncode,'absenceQueryReturnCode':None if image_query is None else image_query.returncode,'exactAbsent':image_absent},'apparmor':{'profileName':profile_name,'unloadReturnCode':None if unload is None else unload.returncode,'exactAbsent':profile_absent,'remoteDirectory':remote_dir,'remoteExactAbsent':remote_absent,'cleanupDebt':None if profile_absent and remote_absent else {'profileName':profile_name,'remoteDirectory':remote_dir}}}
 prior=ownership['status'];ownership['status']='terminal_pass_cleaned' if prior=='terminal_pass' and cleanup_ok else 'terminal_fail';ownership['completedAt']=datetime.now(timezone.utc).isoformat();save()
 try:
  grant=json.loads(grant_path.read_text())
  if grant.get('grantId')==args.grant_id and grant.get('status')=='consumed' and grant.get('ownerHandle')==owner_handle:
   grant.update(runStatus='terminal_pass' if ownership['status']=='terminal_pass_cleaned' else 'terminal_fail',completedAt=ownership['completedAt'],cleanup=ownership['cleanup'],sourceHashes=ownership['sourceHashes'],containerIds=ownership.get('containerIds'),imageId=ownership.get('imageId'),resultSha256=ownership.get('resultSha256'));persist(grant_path,grant)
 except Exception as grant_error: ownership['grantUpdateError']=public_error(grant_error);save()
 print(f'Owned connected MCP evidence retained: {root}',flush=True)
if ownership['status']!='terminal_pass_cleaned':
 raise RuntimeError(ownership.get('failure') or 'Owned connected MCP cleanup was not proven complete')
