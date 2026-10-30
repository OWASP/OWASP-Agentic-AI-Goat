#!/usr/bin/env python3
"""Frozen authenticated Agent Runs qualification. No model configuration or calls."""
import sys
sys.dont_write_bytecode = True
import argparse, json, os, signal, subprocess, time, uuid
from pathlib import Path
from authenticated_run_ownership_contract import validate_package, prepare_evidence_root, digest
from sql_nosql_docker_ownership import verify_daemon, verify_image, inspect_owned, validate_container_layout, cleanup_owned, CONTAINER
from sql_nosql_process_ownership import OwnedProcesses

base_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin") }

def members(pgid, session_id):
    output = subprocess.run(['ps', '-axo', 'pid=,pgid=,uid='], env=base_env,
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


def main():
 parser=argparse.ArgumentParser()
 for name in ['docker-host','docker-daemon-id','postgres-image-id','package','manifest','manifest-sha256','node','node-sha256','evidence-root']:
  parser.add_argument('--'+name,required=True)
 args=parser.parse_args()
 validate=lambda: validate_package(args.package,args.manifest,args.manifest_sha256,args.node,args.node_sha256)
 validate()
 source=Path(args.package)
 for filename in [Path(__file__).name,'authenticated_run_ownership_contract.py','sql_nosql_package_contract.py','sql_nosql_docker_ownership.py','sql_nosql_process_ownership.py']:
  if digest(Path(__file__).parent/filename)!=digest(source/'tests/postgres'/filename):
   raise RuntimeError('Executing launcher/helper differs from frozen package')
 root=prepare_evidence_root(args.evidence_root,[source,Path(__file__).resolve().parents[2]])
 docker=['docker','--host',args.docker_host]
 def command(arguments):
  return subprocess.run(docker+arguments,env=base_env,capture_output=True,text=True,timeout=30)
 def record(name,value):
  with (root/name).open('w') as output:
   os.chmod(root/name,0o600);json.dump(value,output,sort_keys=True);output.write('\n');output.flush();os.fsync(output.fileno())
 def run(arguments):
  result=command(arguments)
  if result.returncode: raise RuntimeError('Owned Docker operation failed')
  return result
 nonce=str(uuid.uuid4());name='owasp-ai-goat-authenticated-runs-'+nonce
 labels={'owasp-ai-goat.qualification':'authenticated_agent_run_ownership','owasp-ai-goat.owner-uid':str(os.getuid()),'owasp-ai-goat.run-nonce':nonce}
 processes=OwnedProcesses(stop_group,lambda value:record('process-'+value['name']+'.json',value))
 intended=False;captured=None;failures=[];passed=False
 processes.install()
 try:
  verify_daemon(command,args.docker_daemon_id);verify_image(command,args.postgres_image_id)
  record('container-intent.json',dict(name=name,labels=labels,imageId=args.postgres_image_id,daemonId=args.docker_daemon_id))
  intended=True
  labelargs=[v for key,value in labels.items() for v in ['--label',key+'='+value]]
  result=run(['run','--detach','--name',name]+labelargs+['--tmpfs','/var/lib/postgresql:rw,size=268435456',
   '-e','POSTGRES_USER=ownership_test_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1',
   '-p','127.0.0.1::5432',args.postgres_image_id,'-c','shared_buffers=16MB','-c','max_connections=32','-c','max_wal_size=16MB','-c','min_wal_size=4MB'])
  if not CONTAINER.fullmatch(result.stdout.strip()): raise RuntimeError('Missing full container ID')
  captured=result.stdout.strip()
  row=inspect_owned(command,name=name,labels=labels,image=args.postgres_image_id,captured_id=captured)
  port=validate_container_layout(row)
  record('container-created.json',dict(containerId=captured,port=port,labels=labels))
  deadline=time.monotonic()+30;ready=0
  while time.monotonic()<deadline:
   probe=command(['exec',captured,'pg_isready','-U','ownership_test_admin'])
   ready=ready+1 if probe.returncode==0 else 0
   if ready>=5:break
   time.sleep(.25)
  else:raise RuntimeError('Database readiness deadline')
  def sql(statement):run(['exec',captured,'psql','-U','ownership_test_admin','-d','postgres','-v','ON_ERROR_STOP=1','-c',statement])
  env=dict(base_env,NODE_ENV='test',PG_TEST_DISPOSABLE='yes',PG_AUTHENTICATED_RUN_READS='1',AWS_EC2_METADATA_DISABLED='true',OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(source))
  for family,prefix in [('identity','PG_READS_TEST'),('secureshop_agents','PG_SECURESHOP_AGENTS_TEST')]:
   migration='dvaia_'+family+'_migration';runtime='dvaia_'+family+'_runtime';database='owasp_ai_goat_test_authenticated_runs_'+family
   for role in [migration,runtime]:sql(f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
   sql(f'CREATE DATABASE {database} OWNER {migration}')
   sql(f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime}')
   for kind,role in [('MIGRATION',migration),('RUNTIME',runtime)]:env[prefix+'_'+kind+'_URL']=f'postgresql://{role}@127.0.0.1:{port}/{database}'
  with (root/'result.tap').open('w') as log:
   os.chmod(root/'result.tap',0o600)
   child=processes.launch([args.node,'--test','--test-reporter=tap','tests/postgres/agentRunAuthenticatedOwnership.integration.test.js'],name='qualification',cwd=source,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
   try:code=child.wait(timeout=120)
   finally:processes.finish(child)
  if code:raise RuntimeError('Qualification test failed')
  passed=True
 finally:
  processes.mask_cleanup_signals()
  try:
   try:processes.cleanup()
   except BaseException:failures.append('process_cleanup')
   if intended:
    try:record('container-cleanup.json',cleanup_owned(command,daemon_id=args.docker_daemon_id,name=name,labels=labels,image=args.postgres_image_id,captured_id=captured))
    except BaseException:
     failures.append('container_cleanup')
     record('container-cleanup.json',dict(status='cleanup_unverified',containerId=captured))
   try:validate()
   except BaseException:failures.append('immutable_postflight')
   record('terminal.json',dict(status='passed_cleaned' if passed and not failures else 'failed',failures=failures,manifestSha256=args.manifest_sha256))
  finally:processes.restore()
  if failures:raise RuntimeError('Qualification cleanup/postflight failed')

if __name__=='__main__':main()
