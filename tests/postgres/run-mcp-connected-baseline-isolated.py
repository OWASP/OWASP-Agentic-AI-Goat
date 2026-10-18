#!/usr/bin/env python3
"""Frozen mounted MCP baseline qualification with PostgreSQL, Mailpit and local 8B."""
import sys
sys.dont_write_bytecode = True
import shlex, secrets, hashlib, re
import argparse, json, os, signal, subprocess, time, uuid, http.client
from pathlib import Path
from mcp_connected_baseline_contract import validate_package, prepare_evidence_root, digest, consume_control, validate_mailpit_layout, validate_docker_cli, validate_ssh, SCOPE
from mcp_strict_runner_ownership import StrictRunner, validate_health
from sql_nosql_docker_ownership import verify_daemon, verify_image, inspect_owned, validate_container_layout, cleanup_owned, CONTAINER
from sql_nosql_process_ownership import OwnedProcesses

base_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin") }

def members(pgid, session_id):
    output = subprocess.run(['/bin/ps', '-axo', 'pid=,pgid=,uid='], env=base_env,
                            capture_output=True, text=True, check=True, timeout=2).stdout
    result = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) != 3 or int(fields[1]) != pgid:
            continue
        pid, uid = int(fields[0]), int(fields[2])
        try:
            if os.getsid(pid) == session_id:
                result.append((pid, uid))
        except ProcessLookupError:
            pass
    if any(uid != os.getuid() for _pid, uid in result):
        raise RuntimeError('Refusing to signal a process group containing foreign processes')
    return [pid for pid, _uid in result]


def stop_group(child, pgid, session_id):
    if members(pgid, session_id):
        os.killpg(pgid, signal.SIGTERM)
    deadline = time.monotonic() + 5
    while members(pgid, session_id) and time.monotonic() < deadline:
        child.poll()
        time.sleep(0.05)
    if members(pgid, session_id):
        os.killpg(pgid, signal.SIGKILL)
    child.wait(timeout=5)
    if members(pgid, session_id):
        raise RuntimeError('Owned Node process group cleanup did not complete')


def wait_mailpit(port):
 deadline=time.monotonic()+25
 while time.monotonic()<deadline:
  connection=http.client.HTTPConnection('127.0.0.1',port,timeout=1)
  try:
   connection.request('GET','/api/v1/info')
   response=connection.getresponse()
   if response.status==200:return
  except (OSError,http.client.HTTPException):pass
  finally:connection.close()
  time.sleep(.25)
 raise RuntimeError('Mailpit readiness deadline')

def main():
 parser=argparse.ArgumentParser()
 for name in ['docker-cli','docker-cli-sha256','docker-host','docker-daemon-id','postgres-image-id','mailpit-image-id','package','manifest','manifest-sha256','node','node-sha256','evidence-root','control','owner-handle','ssh','ssh-sha256','ssh-config','ssh-config-sha256','ssh-host','runner-image-id','runner-build-receipt','runner-build-receipt-sha256','runner-context-sha256','model-digest']:
  parser.add_argument('--'+name,required=True)
 cohort=parser.add_mutually_exclusive_group(required=True)
 cohort.add_argument('--baseline-production',action='store_true')
 cohort.add_argument('--observed-action-candidate',action='store_true')
 cohort.add_argument('--indirect-injection-candidate',action='store_true')
 cohort.add_argument('--indirect-injection-production',action='store_true')
 args=parser.parse_args()
 if not args.owner_handle.isdecimal() or int(args.owner_handle)<=0:raise RuntimeError('Returned positive owner handle required')
 validate=lambda:validate_package(args.package,args.manifest,args.manifest_sha256,args.node,args.node_sha256)
 if not re.fullmatch(r'[a-f0-9]{64}',args.model_digest):raise RuntimeError('Pinned model digest required')
 validate();docker_cli=validate_docker_cli(args.docker_cli,args.docker_cli_sha256);source=Path(args.package)
 for filename in [Path(__file__).name,'mcp_connected_baseline_contract.py','mcp_strict_runner_ownership.py','sql_nosql_package_contract.py','sql_nosql_docker_ownership.py','sql_nosql_process_ownership.py']:
  if digest(Path(__file__).parent/filename)!=digest(source/'tests/postgres'/filename):raise RuntimeError('Executing launcher/helper differs from package')
 ssh=validate_ssh(args.ssh,args.ssh_sha256,args.ssh_config,args.ssh_config_sha256,args.ssh_host)
 receipt_path=Path(args.runner_build_receipt)
 if not receipt_path.is_absolute() or receipt_path.is_symlink() or digest(receipt_path)!=args.runner_build_receipt_sha256:raise RuntimeError('Runner build receipt identity mismatch')
 build_receipt=json.loads(receipt_path.read_text())
 root=prepare_evidence_root(args.evidence_root,[source.parent,Path(__file__).resolve().parents[2]])
 control=Path(args.control)
 if any(control.is_relative_to(boundary) for boundary in [source.parent,root,Path(__file__).resolve().parents[2]]):raise RuntimeError('Control must be outside package, workspace and evidence')
 expected={key:getattr(args,key) for key in ['docker_cli','docker_cli_sha256','docker_host','docker_daemon_id','postgres_image_id','mailpit_image_id','package','manifest','manifest_sha256','node','node_sha256','evidence_root','ssh','ssh_sha256','ssh_config','ssh_config_sha256','ssh_host','runner_image_id','runner_build_receipt','runner_build_receipt_sha256','runner_context_sha256','model_digest']}
 expected['baseline_production']=args.baseline_production
 if args.observed_action_candidate:expected['observed_action_candidate']=True
 if args.indirect_injection_candidate:expected['indirect_injection_candidate']=True
 if args.indirect_injection_production:expected['indirect_injection_production']=True
 expected['owner_handle']=int(args.owner_handle)
 consume_control(control,expected)
 docker=[docker_cli,'--host',args.docker_host]
 def command(arguments):return subprocess.run(docker+arguments,env=base_env,capture_output=True,text=True,timeout=30)
 def record(name,value):
  with (root/name).open('w') as output:
   os.chmod(root/name,0o600);json.dump(value,output,sort_keys=True);output.write('\n');output.flush();os.fsync(output.fileno())
 def run(arguments):
  value=command(arguments)
  if value.returncode:raise RuntimeError('Owned Docker operation failed')
  return value
 nonce=uuid.uuid4().hex
 resources={kind:dict(name='dvaia-mcp-owned-'+kind+'-'+nonce,image=image,labels={'dvaia.qualification':SCOPE,'dvaia.owner-uid':str(os.getuid()),'dvaia.run-nonce':nonce,'dvaia.resource':kind},intended=False,captured=None)
            for kind,image in [('postgres',args.postgres_image_id),('mailpit',args.mailpit_image_id)]}
 processes=OwnedProcesses(stop_group,lambda value:record('process-'+value['name']+'.json',value))
 def remote(arguments, **kwargs):
  # SSH sends a command string to the remote shell; quote each fixed argument.
  return subprocess.run(ssh+[shlex.join(arguments)],env=base_env,capture_output=True,text=True,timeout=30,**kwargs)
 template=(source/'sidecars/sandbox-runner/apparmor/dvaia-mcp-sandbox.apparmor.in').read_bytes()
 profile='dvaia-mcp-sandbox-'+nonce[:12]
 policy=template.replace(b'@@SUPERVISOR_PROFILE@@',profile.encode())
 runner=StrictRunner(docker=command,remote=remote,record=lambda name,value:record(name+'.json',value),daemon_id=args.docker_daemon_id,image=args.runner_image_id,nonce=nonce,uid=os.getuid(),policy=policy,policy_sha256=hashlib.sha256(policy).hexdigest(),build_receipt=build_receipt,context_sha256=args.runner_context_sha256,template_sha256=hashlib.sha256(template).hexdigest(),template=template)
 token=secrets.token_urlsafe(48)
 def inventory_model():
  connection=http.client.HTTPConnection('127.0.0.1',11434,timeout=10)
  try:
   connection.request('GET','/api/tags');response=connection.getresponse()
   if response.status!=200:raise RuntimeError('Model inventory unavailable')
   rows=json.loads(response.read())['models']
   if not any(row.get('name')=='llama3.1:8b' and row.get('digest')==args.model_digest for row in rows):raise RuntimeError('Pinned model missing')
  finally:connection.close()
 failures=[];passed=False;model_checked=False;processes.install()
 try:
  inventory_model();model_checked=True
  verify_daemon(command,args.docker_daemon_id)
  for resource in resources.values():verify_image(command,resource['image'])
  record('ownership.json',dict(scope=SCOPE,ownerHandle=int(args.owner_handle),launcherPid=os.getpid(),manifestSha256=args.manifest_sha256,daemonId=args.docker_daemon_id))
  for kind,resource in resources.items():
   record(kind+'-intent.json',dict(**resource,daemonId=args.docker_daemon_id));resource['intended']=True
   labels=[value for key,value in resource['labels'].items() for value in ['--label',key+'='+value]]
   layout=(['--tmpfs','/var/lib/postgresql:rw,size=268435456','-e','POSTGRES_USER=mcp_connected_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432'] if kind=='postgres' else
           ['--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=16777216','-p','127.0.0.1::1025','-p','127.0.0.1::8025'])
   tuning=['-c','shared_buffers=16MB','-c','max_connections=40','-c','max_wal_size=16MB','-c','min_wal_size=4MB'] if kind=='postgres' else []
   created=run(['run','--detach','--pull','never','--name',resource['name']]+labels+layout+[resource['image']]+tuning)
   if not CONTAINER.fullmatch(created.stdout.strip()):raise RuntimeError('Missing full container ID')
   resource['captured']=created.stdout.strip()
   row=inspect_owned(command,name=resource['name'],labels=resource['labels'],image=resource['image'],captured_id=resource['captured'])
   record(kind+'-layout.json',dict(containerId=resource['captured'],ports=row.get('NetworkSettings',{}).get('Ports'),
                                  readonlyRootfs=row.get('HostConfig',{}).get('ReadonlyRootfs'),tmpfs=row.get('HostConfig',{}).get('Tmpfs'),
                                  mountCount=len(row.get('Mounts',[]))))
   if kind=='postgres':
    pg_port=validate_container_layout(row)
    if pg_port in {5432,1025,8025}:raise RuntimeError('Default host port forbidden')
   else:smtp_port,api_port=validate_mailpit_layout(row)
   record(kind+'-created.json',resource)
  if len({pg_port,smtp_port,api_port})!=3:raise RuntimeError('Owned ports must differ')
  pg=resources['postgres']['captured'];deadline=time.monotonic()+30
  while time.monotonic()<deadline:
   if command(['exec',pg,'pg_isready','-U','mcp_connected_admin']).returncode==0:break
   time.sleep(.25)
  else:raise RuntimeError('PostgreSQL readiness deadline')
  wait_mailpit(api_port)
  def sql(statement):run(['exec',pg,'psql','-U','mcp_connected_admin','-d','postgres','-v','ON_ERROR_STOP=1','-c',statement])
  for role in ['dvaia_identity_migration','dvaia_identity_runtime','dvaia_mcp_migration','dvaia_mcp_runtime']:sql(f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
  runner.prepare_policy();runner_port=runner.launch(token)
  runtime_version=run(['exec',runner.captured,'/usr/local/bin/node','--version']).stdout.strip()
  if runtime_version!='v26.8.2':raise RuntimeError('Owned runner Node runtime mismatch')
  record('runner-runtime.json',dict(containerId=runner.captured,nodeVersion=runtime_version))
  deadline=time.monotonic()+40
  while time.monotonic()<deadline:
   connection=http.client.HTTPConnection('127.0.0.1',runner_port,timeout=2)
   try:
    connection.request('GET','/owned-targets/health',headers={'Authorization':'Bearer '+token});response=connection.getresponse()
    if response.status==200:
     health=json.loads(response.read());validate_health(health,runner.profile);record('runner-health.json',health);break
   except (OSError,http.client.HTTPException):pass
   finally:connection.close()
   time.sleep(.25)
  else:raise RuntimeError('Strict runner readiness deadline')
  env=dict(base_env,MCP_BASELINE_PRODUCTION='yes',MCP_CONNECTED_SOURCE_ROOT=str(source),MCP_CONNECTED_EVIDENCE_ROOT=str(root),MCP_CONNECTED_PG_PORT=str(pg_port),MCP_CONNECTED_SMTP_PORT=str(smtp_port),MCP_CONNECTED_API_PORT=str(api_port),MCP_CONNECTED_RUNNER_PORT=str(runner_port),MCP_CONNECTED_MODEL_DIGEST=args.model_digest,NODE_ENV='test',EXPORT_INTERNALS='1',RUN_MCP_OWNED_CONNECTED='yes',MCP_PROTECTED_STATE_CANDIDATE='no',MCP_OBSERVED_ACTION_CANDIDATE='yes' if args.observed_action_candidate else 'no',MCP_INDIRECT_INJECTION_CANDIDATE='yes' if args.indirect_injection_candidate else 'no',MCP_INDIRECT_INJECTION_PRODUCTION='yes' if args.indirect_injection_production else 'no',MCP_OBSERVED_ACTION_ENABLED='true' if args.indirect_injection_production else 'false',MCP_INDIRECT_INJECTION_ENABLED='true' if args.indirect_injection_production else 'false',MCP_SUPPLY_CHAIN_ENABLED='false',MCP_CONNECTED_COHORT='indirect_injection_production' if args.indirect_injection_production else ('indirect_injection' if args.indirect_injection_candidate else ('observed_action' if args.observed_action_candidate else 'baseline')),MCP_CATALOG_RECON_CANDIDATE='no',MCP_CATALOG_RECON_PRODUCTION='no',PG_TEST_DISPOSABLE='yes',PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',MCP_OWNED_RESOURCES_ENABLED='true',AI_PROVIDER='ollama',OLLAMA_BASE_URL='http://127.0.0.1:11434',OLLAMA_MODEL='llama3.1:8b',AWS_EC2_METADATA_DISABLED='true',JWT_SECRET=secrets.token_urlsafe(64),PG_MCP_CONNECTED_ADMIN_URL=f'postgresql://mcp_connected_admin@127.0.0.1:{pg_port}/postgres',MCP_OWNED_TARGET_URL=f'http://127.0.0.1:{runner_port}',MCP_OWNED_TARGET_TOKEN=token,MAILPIT_SMTP_HOST='127.0.0.1',MAILPIT_SMTP_PORT=str(smtp_port),MAILPIT_API_URL=f'http://127.0.0.1:{api_port}',SANDBOX_RUNNER_URL='http://127.0.0.1:1',SSRF_TARGET_URL='http://127.0.0.1:1',ROGUE_MCP_URL='http://127.0.0.1:1',LOGS_DIR=str(root/'logs'),MCP_JUDGE_INVALID_ATTEMPTS_PATH=str(root/'judge-invalid-attempts.jsonl'),DVAIA_ISOLATED_TEST_WORKSPACE=str(source))
  with (root/'result.log').open('w') as log:
   os.chmod(root/'result.log',0o600)
   child=processes.launch([args.node,'--test','--test-reporter=tap','tests/postgres/mcpOwnedConnected.integration.test.js'],name='qualification',cwd=source,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
   try:code=child.wait(timeout=2460 if (args.indirect_injection_candidate or args.indirect_injection_production) else 780)
   finally:processes.finish(child)
  if code:raise RuntimeError('Qualification test failed')
  passed=True
 finally:
  processes.mask_cleanup_signals()
  try:
   try:processes.cleanup()
   except BaseException:failures.append('process_cleanup')
   try:runner.cleanup()
   except BaseException:
    failures.append('runner_cleanup')
    try:record('runner-cleanup-debt.json',dict(status='cleanup_unverified',profile=runner.profile,directory=runner.directory,containerId=runner.captured))
    except BaseException:failures.append('runner_cleanup_record')
   for kind,resource in resources.items():
    if not resource['intended']:continue
    try:
     outcome=cleanup_owned(command,daemon_id=args.docker_daemon_id,name=resource['name'],labels=resource['labels'],image=resource['image'],captured_id=resource['captured'])
    except BaseException:
     failures.append(kind+'_cleanup');outcome=dict(status='cleanup_unverified',containerId=resource['captured'])
    try:record(kind+'-cleanup.json',outcome)
    except BaseException:failures.append(kind+'_cleanup_record')
   if model_checked:
    try:inventory_model()
    except BaseException:failures.append('model_postflight')
   try:validate()
   except BaseException:failures.append('immutable_postflight')
   record('terminal.json',dict(status='passed_cleaned' if passed and not failures else 'failed',failures=failures,ownerHandle=int(args.owner_handle),manifestSha256=args.manifest_sha256,
                              resultSha256=digest(root/'result.log') if (root/'result.log').exists() else None))
  finally:processes.restore()
  if failures:raise RuntimeError('Qualification cleanup/postflight failed')

if __name__=='__main__':main()
