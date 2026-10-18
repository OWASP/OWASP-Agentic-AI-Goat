#!/usr/bin/env python3
"""Frozen MCP resource fixture qualification; real PostgreSQL and Mailpit, no models."""
import sys
sys.dont_write_bytecode = True
import argparse, json, os, signal, subprocess, time, uuid, http.client
from pathlib import Path
from mcp_owned_mailpit_contract import validate_package, prepare_evidence_root, digest, consume_control, validate_mailpit_layout, validate_docker_cli, SCOPE
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
 for name in ['docker-cli','docker-cli-sha256','docker-host','docker-daemon-id','postgres-image-id','mailpit-image-id','package','manifest','manifest-sha256','node','node-sha256','evidence-root','control','owner-handle']:
  parser.add_argument('--'+name,required=True)
 args=parser.parse_args()
 if not args.owner_handle.isdecimal() or int(args.owner_handle)<=0:raise RuntimeError('Returned positive owner handle required')
 validate=lambda:validate_package(args.package,args.manifest,args.manifest_sha256,args.node,args.node_sha256)
 validate();docker_cli=validate_docker_cli(args.docker_cli,args.docker_cli_sha256);source=Path(args.package)
 for filename in [Path(__file__).name,'mcp_owned_mailpit_contract.py','sql_nosql_package_contract.py','sql_nosql_docker_ownership.py','sql_nosql_process_ownership.py']:
  if digest(Path(__file__).parent/filename)!=digest(source/'tests/postgres'/filename):raise RuntimeError('Executing launcher/helper differs from package')
 root=prepare_evidence_root(args.evidence_root,[source.parent,Path(__file__).resolve().parents[2]])
 control=Path(args.control)
 if any(control.is_relative_to(boundary) for boundary in [source.parent,root,Path(__file__).resolve().parents[2]]):raise RuntimeError('Control must be outside package, workspace and evidence')
 expected={key:getattr(args,key) for key in ['docker_cli','docker_cli_sha256','docker_host','docker_daemon_id','postgres_image_id','mailpit_image_id','package','manifest','manifest_sha256','node','node_sha256','evidence_root']}
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
 failures=[];passed=False;processes.install()
 try:
  verify_daemon(command,args.docker_daemon_id)
  for resource in resources.values():verify_image(command,resource['image'])
  record('ownership.json',dict(scope=SCOPE,ownerHandle=int(args.owner_handle),launcherPid=os.getpid(),manifestSha256=args.manifest_sha256,daemonId=args.docker_daemon_id))
  for kind,resource in resources.items():
   record(kind+'-intent.json',dict(**resource,daemonId=args.docker_daemon_id));resource['intended']=True
   labels=[value for key,value in resource['labels'].items() for value in ['--label',key+'='+value]]
   layout=(['--tmpfs','/var/lib/postgresql:rw,size=268435456','-e','POSTGRES_USER=mcp_owned_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432'] if kind=='postgres' else
           ['--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=16777216','-p','127.0.0.1::1025','-p','127.0.0.1::8025'])
   tuning=['-c','shared_buffers=16MB','-c','max_connections=24','-c','max_wal_size=16MB','-c','min_wal_size=4MB'] if kind=='postgres' else []
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
   if command(['exec',pg,'pg_isready','-U','mcp_owned_admin']).returncode==0:break
   time.sleep(.25)
  else:raise RuntimeError('PostgreSQL readiness deadline')
  wait_mailpit(api_port)
  def sql(statement):run(['exec',pg,'psql','-U','mcp_owned_admin','-d','postgres','-v','ON_ERROR_STOP=1','-c',statement])
  for role in ['dvaia_mcp_migration','dvaia_mcp_runtime']:sql(f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
  sql('CREATE DATABASE dvaia_test_mcp_owned_mailpit OWNER dvaia_mcp_migration')
  sql('REVOKE CONNECT ON DATABASE dvaia_test_mcp_owned_mailpit FROM PUBLIC; GRANT CONNECT ON DATABASE dvaia_test_mcp_owned_mailpit TO dvaia_mcp_migration,dvaia_mcp_runtime')
  env=dict(base_env,NODE_ENV='test',PG_TEST_DISPOSABLE='yes',MCP_OWNED_RESOURCES_MAILPIT='yes',AWS_EC2_METADATA_DISABLED='true',DVAIA_ISOLATED_TEST_WORKSPACE=str(source),
           MCP_OWNED_RESOURCES_SOURCE_ROOT=str(source),MCP_OWNED_RESOURCES_PG_PORT=str(pg_port),MCP_OWNED_RESOURCES_SMTP_PORT=str(smtp_port),MCP_OWNED_RESOURCES_API_PORT=str(api_port),
           MAILPIT_SMTP_HOST='127.0.0.1',MAILPIT_SMTP_PORT=str(smtp_port),MAILPIT_API_URL=f'http://127.0.0.1:{api_port}')
  for kind,role in [('MIGRATION','dvaia_mcp_migration'),('RUNTIME','dvaia_mcp_runtime')]:env['PG_MCP_OWNED_RESOURCES_TEST_'+kind+'_URL']=f'postgresql://{role}@127.0.0.1:{pg_port}/dvaia_test_mcp_owned_mailpit'
  with (root/'result.log').open('w') as log:
   os.chmod(root/'result.log',0o600)
   child=processes.launch([args.node,'--test','--test-reporter=tap','tests/postgres/mcpOwnedResourcesMailpit.integration.test.js'],name='qualification',cwd=source,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
   try:code=child.wait(timeout=180)
   finally:processes.finish(child)
  if code:raise RuntimeError('Qualification test failed')
  passed=True
 finally:
  processes.mask_cleanup_signals()
  try:
   try:processes.cleanup()
   except BaseException:failures.append('process_cleanup')
   for kind,resource in resources.items():
    if not resource['intended']:continue
    try:
     outcome=cleanup_owned(command,daemon_id=args.docker_daemon_id,name=resource['name'],labels=resource['labels'],image=resource['image'],captured_id=resource['captured'])
    except BaseException:
     failures.append(kind+'_cleanup');outcome=dict(status='cleanup_unverified',containerId=resource['captured'])
    try:record(kind+'-cleanup.json',outcome)
    except BaseException:failures.append(kind+'_cleanup_record')
   try:validate()
   except BaseException:failures.append('immutable_postflight')
   record('terminal.json',dict(status='passed_cleaned' if passed and not failures else 'failed',failures=failures,ownerHandle=int(args.owner_handle),manifestSha256=args.manifest_sha256,
                              resultSha256=digest(root/'result.log') if (root/'result.log').exists() else None))
  finally:processes.restore()
  if failures:raise RuntimeError('Qualification cleanup/postflight failed')

if __name__=='__main__':main()
