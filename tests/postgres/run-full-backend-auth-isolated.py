#!/usr/bin/env python3
"""Frozen full-backend qualification with explicit rendered MCP/SecureShop cohorts."""
import sys
sys.dont_write_bytecode = True
import argparse, json, os, re, signal, subprocess, time, uuid, shlex
from pathlib import Path
from full_backend_auth_contract import validate_package, prepare_evidence_root, digest, STORES, validate_fullboot_layout, validate_rendered, validate_mcp_indirect_configuration, validate_mcp_rendered_manifest
from sql_nosql_docker_ownership import verify_daemon, verify_image, inspect_owned, cleanup_owned, CONTAINER
from sql_nosql_process_ownership import OwnedProcesses
from browser_process_ownership import cleanup_browser_profile, read_private_json

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


def assert_owned_children_absent(children):
    # Handles remain available after finish solely for read-only absence proof.
    # Never signal an old/reused PID or rely only on a cleanup journal.
    if not children:
        return
    for child in children:
        if child.poll() is None:
            raise RuntimeError('Owned child has not terminated')
    result = subprocess.run(['/bin/ps', '-axo', 'pid=,pgid=,uid='], env=base_env,
                            capture_output=True, text=True, check=True, timeout=2)
    ids = {child.pid for child in children}  # start_new_session => PID == PGID
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 3 or any(not field.lstrip('-').isdecimal() for field in fields):
            raise RuntimeError('Process roster is malformed')
        pid, pgid, _uid = map(int, fields)
        if pid in ids or pgid in ids:
            raise RuntimeError('Owned or reused child PID/process group remains')


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


def validate_sql_nova_catalog(args, manifest=None):
 if not args.sql_nova_catalog:return None
 if not args.rendered or args.capacity_200 or args.mcp_indirect or args.secureshop or args.model_digest is not None:
  raise ValueError('SQL/NOVA catalog requires exclusive rendered controlled cohort')
 if manifest is not None:
  required={'tests/fixtures/sqlNoSqlCatalogParity.js','tests/fixtures/sqlNoSqlCatalogProjection.js','tests/sqlNoSqlCatalogParity.test.js','client/src/pages/workshops/SQLWorkshop.js','client/src/pages/workshops/NoSQLWorkshop.js','client/src/components/HintPanel.js'}
  if not required <= set(manifest['files']):raise ValueError('SQL/NOVA catalog closure missing')
 return {'workSeconds':1200,'childSeconds':1080,'cleanupSeconds':120,'http':4000,'renderSeconds':900}

def main():
 parser=argparse.ArgumentParser()
 for name in ['docker-host','docker-daemon-id','postgres-image-id','package','manifest','manifest-sha256','node','node-sha256','evidence-root']:
  parser.add_argument('--'+name,required=True)
 parser.add_argument('--rendered',action='store_true')
 parser.add_argument('--capacity-200',action='store_true')
 parser.add_argument('--sql-nova-catalog',action='store_true')
 parser.add_argument('--mcp-indirect',action='store_true')
 parser.add_argument('--secureshop',action='store_true')
 parser.add_argument('--secureshop-private-failure-artifact',action='store_true')
 parser.add_argument('--secureshop-review-outcome',choices=['attack_success','defensive_control','observed_outcome'])
 parser.add_argument('--renderer-root')
 parser.add_argument('--renderer-manifest-sha256')
 for name in ['docker-cli','docker-cli-sha256','mailpit-image-id','ssh','ssh-sha256','ssh-config','ssh-config-sha256','ssh-host','runner-image-id','runner-build-receipt','runner-build-receipt-sha256','runner-context-sha256','model-digest','control','owner-handle']:
  parser.add_argument('--'+name)
 parser.add_argument('--browser')
 parser.add_argument('--browser-sha256')
 args=parser.parse_args()
 from application_capacity_contract import validate_capacity
 capacity=validate_capacity(args.capacity_200,rendered=args.rendered,mcp=args.mcp_indirect,secureshop=args.secureshop,model_digest=args.model_digest)
 catalog=validate_sql_nova_catalog(args)
 bounded_cohort=capacity or catalog
 mcp_keys=['docker_cli','docker_cli_sha256','mailpit_image_id','ssh','ssh_sha256','ssh_config','ssh_config_sha256','ssh_host','runner_image_id','runner_build_receipt','runner_build_receipt_sha256','runner_context_sha256','model_digest','control','owner_handle']
 if args.secureshop:
  from full_backend_secureshop_contract import validate_secureshop_arguments
  validate_secureshop_arguments(True,rendered=args.rendered,mcp_enabled=args.mcp_indirect,
   model_digest=args.model_digest,renderer_root=args.renderer_root,renderer_manifest_sha256=args.renderer_manifest_sha256,
   control=args.control,owner_handle=args.owner_handle,review_outcome=args.secureshop_review_outcome)
  if not args.docker_cli or not args.docker_cli_sha256:raise RuntimeError('SecureShop Docker executable pins required')
  if any(getattr(args,key) is not None for key in mcp_keys if key not in ['docker_cli','docker_cli_sha256','model_digest','control','owner_handle']):raise RuntimeError('MCP resources are not part of SecureShop cohort')
 elif args.mcp_indirect:
  if not args.rendered or any(not getattr(args,key) for key in mcp_keys):raise RuntimeError('Complete rendered MCP ownership pins required')
  if not args.owner_handle.isdecimal() or int(args.owner_handle)<=0:raise RuntimeError('Returned owner handle required')
  from full_backend_auth_contract import MCP_MODEL_DIGEST
  if args.model_digest!=MCP_MODEL_DIGEST:raise RuntimeError('Exact model digest required')
 elif any(getattr(args,key) is not None for key in mcp_keys):raise RuntimeError('MCP pins require explicit cohort')
 if not args.secureshop and (args.renderer_root is not None or args.renderer_manifest_sha256 is not None or args.secureshop_review_outcome is not None or args.secureshop_private_failure_artifact):raise RuntimeError('Renderer, review outcome and private failure evidence require SecureShop cohort')
 def validate():
  manifest=validate_package(args.package,args.manifest,args.manifest_sha256,args.node,args.node_sha256)
  validate_rendered(manifest,args.rendered,args.browser,args.browser_sha256)
  validate_sql_nova_catalog(args,manifest)
  validate_mcp_rendered_manifest(manifest,args.mcp_indirect)
  from full_backend_auth_contract import validate_secureshop_rendered_manifest
  validate_secureshop_rendered_manifest(manifest,args.secureshop,args.rendered,args.mcp_indirect)
  if args.secureshop:
   from full_backend_secureshop_resources import validate_renderer_bundle
   validate_renderer_bundle(source=args.package,renderer_root=args.renderer_root,manifest_sha256=args.renderer_manifest_sha256)
  return manifest
 validate()
 source=Path(args.package)
 for filename in [Path(__file__).name,'full_backend_auth_contract.py','sql_nosql_package_contract.py','sql_nosql_docker_ownership.py','sql_nosql_process_ownership.py','browser_process_ownership.py','application_capacity_contract.py']:
  if digest(Path(__file__).parent/filename)!=digest(source/'tests/postgres'/filename):
   raise RuntimeError('Executing launcher/helper differs from frozen package')
 if args.mcp_indirect:
  for filename in ['full_backend_mcp_resources.py','mcp_connected_baseline_contract.py','mcp_strict_runner_ownership.py']:
   if digest(Path(__file__).parent/filename)!=digest(source/'tests/postgres'/filename):raise RuntimeError('MCP helper differs from frozen package')
 root=prepare_evidence_root(args.evidence_root,[source,Path(__file__).resolve().parents[2]])
 if args.secureshop:
  for filename in ['full_backend_secureshop_contract.py','full_backend_secureshop_resources.py','mcp_connected_baseline_contract.py']:
   if digest(Path(__file__).parent/filename)!=digest(source/'tests/postgres'/filename):raise RuntimeError('SecureShop helper differs from frozen package')
  from mcp_connected_baseline_contract import validate_docker_cli
  from full_backend_secureshop_contract import consume_full_secureshop_control,validate_secureshop_configuration
  from full_backend_secureshop_resources import FullBackendSecureShopResources,validate_renderer_bundle
  docker_cli=validate_docker_cli(args.docker_cli,args.docker_cli_sha256)
  validate_renderer_bundle(source=source,renderer_root=args.renderer_root,manifest_sha256=args.renderer_manifest_sha256,evidence=root)
  consume_full_secureshop_control(args.control,vars(args),source,root)
 elif args.mcp_indirect:
  from mcp_connected_baseline_contract import validate_docker_cli,validate_ssh
  from full_backend_mcp_resources import FullBackendMcpResources
  from full_backend_auth_contract import consume_full_mcp_control
  docker_cli=validate_docker_cli(args.docker_cli,args.docker_cli_sha256)
  ssh=validate_ssh(args.ssh,args.ssh_sha256,args.ssh_config,args.ssh_config_sha256,args.ssh_host)
  receipt_path=Path(args.runner_build_receipt)
  if not receipt_path.is_absolute() or receipt_path.resolve()!=receipt_path or receipt_path.is_symlink() or digest(receipt_path)!=args.runner_build_receipt_sha256:raise RuntimeError('Runner receipt identity mismatch')
  build_receipt=json.loads(receipt_path.read_text())
  consume_full_mcp_control(args.control,vars(args),source,root)
 else:docker_cli='docker'
 docker=[docker_cli,'--host',args.docker_host]
 capacity_cleanup_deadline=None
 def capacity_remaining():
  if capacity_cleanup_deadline is None:return 30
  remaining=capacity_cleanup_deadline-time.monotonic()
  if remaining<=0:raise RuntimeError('Capacity cleanup deadline exceeded')
  return min(30,remaining)
 def cleanup_step(operation):
  if not bounded_cohort:return operation()
  remaining=capacity_remaining()
  signal.setitimer(signal.ITIMER_REAL,remaining)
  try:
   value=operation()
   capacity_remaining()
   return value
  finally:signal.setitimer(signal.ITIMER_REAL,0)
 def command(arguments):
  return subprocess.run(docker+arguments,env=base_env,capture_output=True,text=True,timeout=capacity_remaining())
 def record(name,value):
  with (root/name).open('w') as output:
   os.chmod(root/name,0o600);json.dump(value,output,sort_keys=True);output.write('\n');output.flush();os.fsync(output.fileno())
 def run(arguments):
  result=command(arguments)
  if result.returncode: raise RuntimeError('Owned Docker operation failed')
  return result
 nonce=str(uuid.uuid4());name='owasp-ai-goat-full-backend-auth-'+nonce
 labels={'owasp-ai-goat.qualification':'full_backend_auth','owasp-ai-goat.owner-uid':str(os.getuid()),'owasp-ai-goat.run-nonce':nonce}
 processes=OwnedProcesses(stop_group,lambda value:record('process-'+value['name']+'.json',value))
 intended=False;captured=None;failures=[];passed=False;mcp_resources=None;secureshop_resources=None;owned_children=[];runtime_root=None
 processes.install()
 prior_alarm=None
 if bounded_cohort:
  prior_alarm=signal.getsignal(signal.SIGALRM)
  signal.signal(signal.SIGALRM,processes._handle_signal)
  signal.alarm(bounded_cohort['workSeconds'])
 try:
  verify_daemon(command,args.docker_daemon_id);verify_image(command,args.postgres_image_id)
  if args.secureshop:record('ownership.json',dict(scope='full_backend_secureshop',ownerHandle=int(args.owner_handle),launcherPid=os.getpid(),manifestSha256=args.manifest_sha256,daemonId=args.docker_daemon_id))
  if args.mcp_indirect:record('ownership.json',dict(scope='full_backend_mcp_indirect',ownerHandle=int(args.owner_handle),launcherPid=os.getpid(),manifestSha256=args.manifest_sha256,daemonId=args.docker_daemon_id))
  record('container-intent.json',dict(name=name,labels=labels,imageId=args.postgres_image_id,daemonId=args.docker_daemon_id))
  intended=True
  labelargs=[v for key,value in labels.items() for v in ['--label',key+'='+value]]
  result=run(['run','--detach','--name',name]+labelargs+['--memory','512m','--cpus','2','--pids-limit','256','--tmpfs','/var/lib/postgresql:rw,size=1073741824',
   '-e','POSTGRES_USER=ownership_test_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1',
   '-p','127.0.0.1::5432',args.postgres_image_id,'-c','shared_buffers=16MB','-c','max_connections=96','-c','max_wal_size=16MB','-c','min_wal_size=4MB'])
  if not CONTAINER.fullmatch(result.stdout.strip()): raise RuntimeError('Missing full container ID')
  captured=result.stdout.strip()
  row=inspect_owned(command,name=name,labels=labels,image=args.postgres_image_id,captured_id=captured)
  port=validate_fullboot_layout(row)
  record('container-created.json',dict(containerId=captured,port=port,labels=labels))
  if args.secureshop:
   secureshop_resources=FullBackendSecureShopResources(record=record,source=source,evidence=root,
    renderer_root=args.renderer_root,renderer_manifest_sha256=args.renderer_manifest_sha256,model_digest=args.model_digest,
    assert_processes_absent=lambda:assert_owned_children_absent(owned_children))
   endpoint_manifest=secureshop_resources.prepare(port)
   validate_secureshop_configuration(True,rendered=args.rendered,mcp_enabled=args.mcp_indirect,model_digest=args.model_digest,endpoints=endpoint_manifest)
  if args.mcp_indirect:
   def remote(arguments,**kwargs):return subprocess.run(ssh+[shlex.join(arguments)],env=base_env,capture_output=True,text=True,timeout=30,**kwargs)
   mcp_resources=FullBackendMcpResources(command=command,remote=remote,record=record,source=source,
    daemon_id=args.docker_daemon_id,mailpit_image=args.mailpit_image_id,runner_image=args.runner_image_id,
    nonce=nonce.replace('-',''),build_receipt=build_receipt,context_sha256=args.runner_context_sha256,model_digest=args.model_digest)
   endpoint_manifest,target_token=mcp_resources.launch(port)
   validate_mcp_indirect_configuration(True,args.rendered,args.model_digest,endpoint_manifest)

  deadline=time.monotonic()+30;ready=0
  while time.monotonic()<deadline:
   probe=command(['exec',captured,'pg_isready','-h','127.0.0.1','-p','5432','-U','ownership_test_admin'])
   ready=ready+1 if probe.returncode==0 else 0
   if ready>=5:break
   time.sleep(.25)
  else:raise RuntimeError('Database readiness deadline')
  def sql(statement):run(['exec',captured,'psql','-U','ownership_test_admin','-d','postgres','-v','ON_ERROR_STOP=1','-c',statement])
  env=dict(base_env,NODE_ENV='test',PG_TEST_DISPOSABLE='yes',PG_FULL_BACKEND_AUTH='1',AWS_EC2_METADATA_DISABLED='true',OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(source))
  runtime_root=root/'runtime';runtime_root.mkdir(mode=0o700)
  env['OWASP_AI_GOAT_FULL_BACKEND_RUNTIME_ROOT']=str(runtime_root)
  if capacity:
   env['PG_FULL_BACKEND_CAPACITY']='1'
   env['PG_CAPACITY_OBSERVER_URL']=f'postgresql://ownership_test_admin@127.0.0.1:{port}/postgres'
  if catalog:env['PG_SQL_NOVA_CATALOG']='1'
  if args.rendered:
   env.update(PG_FULL_BACKEND_RENDERED='1',PG_FULL_BACKEND_BROWSER=args.browser,PG_FULL_BACKEND_BROWSER_SHA256=args.browser_sha256)
  if args.secureshop:
   env.update(PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',SS_ENABLE_REAL_MCP_SPAWN='false',
    PG_FULL_BACKEND_SECURESHOP='1',PG_FULL_BACKEND_SECURESHOP_MODEL_DIGEST=args.model_digest,
    PG_FULL_BACKEND_SECURESHOP_REVIEW_OUTCOME=args.secureshop_review_outcome,
    PG_FULL_BACKEND_SECURESHOP_ENDPOINTS_JSON=json.dumps(endpoint_manifest),
    PG_FULL_BACKEND_SECURESHOP_RENDERER_MANIFEST_SHA256=args.renderer_manifest_sha256,
    SECURESHOP_REVIEW_RENDERER_ROOT=args.renderer_root,SS_ENABLE='true',SS_BOUND_REVIEWS_ENABLED='true',
    SS_PERSONA_INBOX_READY='true',SS_MCP_TRUST_READY='true',SS_CONTROLLED_SSRF_READY='true',
    SS_AGENT_HOST_PORT=str(endpoint_manifest['agentHost']['port']),
    SS_MCP_TRUST_FIXTURE_ROOT=str(runtime_root/'secureshop-mcp-trust'),SS_CONTROLLED_SSRF_FIXTURE_ROOT=str(runtime_root/'secureshop-ssrf'),
    AI_PROVIDER='ollama',OLLAMA_BASE_URL='http://127.0.0.1:11434',OLLAMA_MODEL='llama3.1:8b',JUDGE_PROVIDER='ollama',JUDGE_MODEL='llama3.1:8b')
   if args.secureshop_private_failure_artifact:env['PG_FULL_BACKEND_SECURESHOP_PRIVATE_FAILURE_ARTIFACT']='1'
  if args.mcp_indirect:
   env.update(PG_FULL_BACKEND_MCP_INDIRECT='1',PG_FULL_BACKEND_MCP_MODEL_DIGEST=args.model_digest,
    PG_FULL_BACKEND_MCP_ENDPOINTS_JSON=json.dumps(endpoint_manifest),
    AI_PROVIDER='ollama',OLLAMA_BASE_URL='http://127.0.0.1:11434',OLLAMA_MODEL='llama3.1:8b',JUDGE_PROVIDER='ollama',JUDGE_MODEL='llama3.1:8b',
    MCP_OWNED_RESOURCES_ENABLED='true',MCP_OBSERVED_ACTION_ENABLED='true',MCP_INDIRECT_INJECTION_ENABLED='true',MCP_SUPPLY_CHAIN_ENABLED='false',
    MCP_OWNED_TARGET_URL='http://127.0.0.1:'+str(endpoint_manifest['runner']['port']),MCP_OWNED_TARGET_TOKEN=target_token,
    MAILPIT_SMTP_HOST='127.0.0.1',MAILPIT_SMTP_PORT=str(endpoint_manifest['smtp']['port']),MAILPIT_API_URL='http://127.0.0.1:'+str(endpoint_manifest['mailpit']['port']))
   for key in ['MCP_PROTECTED_STATE_CANDIDATE','MCP_OBSERVED_ACTION_CANDIDATE','MCP_INDIRECT_INJECTION_CANDIDATE','MCP_CATALOG_RECON_CANDIDATE','MCP_CATALOG_RECON_PRODUCTION']:env[key]='no'
  for family,prefix in STORES:
   migration='dvaia_'+family+'_migration';runtime='dvaia_'+family+'_runtime';database='owasp_ai_goat_test_full_backend_'+family
   for role in [migration,runtime]:sql(f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
   sql(f'CREATE DATABASE {database} OWNER {migration}')
   sql(f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime}')
   for suffix,role in [('_MIGRATION_DATABASE_URL',migration),('_DATABASE_URL',runtime)]:env[prefix+suffix]=f'postgresql://{role}@127.0.0.1:{port}/{database}'
  with (root/'result.tap').open('w') as log:
   os.chmod(root/'result.tap',0o600)
   if secureshop_resources is not None:secureshop_resources.release_for_launch()
   child=processes.launch([args.node,'--test','--test-reporter=tap','tests/postgres/fullApplicationBackendAuth.integration.test.js'],name='qualification',cwd=source,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
   owned_children.append(child)
   try:code=child.wait(timeout=bounded_cohort['childSeconds'] if bounded_cohort else 3600 if args.mcp_indirect or args.secureshop else 400 if args.rendered else 220)
   finally:processes.finish(child)
  if code:raise RuntimeError('Qualification test failed')
  passed=True
 finally:
  if bounded_cohort:
   signal.alarm(0);capacity_cleanup_deadline=time.monotonic()+bounded_cohort['cleanupSeconds']
   signal.signal(signal.SIGALRM,processes._handle_signal);signal.alarm(bounded_cohort['cleanupSeconds'])
  processes.mask_cleanup_signals()
  # launch may have registered a child before its journal/signal handling raises.
  for _name, registered_child in getattr(processes, 'children', []):
   if not any(value is registered_child for value in owned_children):owned_children.append(registered_child)
  try:
   processes_absent=False
   try:
    cleanup_step(processes.cleanup)
   except BaseException:failures.append('process_cleanup')
   try:
    cleanup_step(lambda:assert_owned_children_absent(owned_children));processes_absent=True
   except BaseException:
    if 'process_cleanup' not in failures:failures.append('process_cleanup')
   if args.rendered and runtime_root is not None:
    roles=['rendered'] + (['assessment'] if args.secureshop else [])
    for role in roles:
     prefix='browser' if role=='rendered' else 'assessment-browser'
     browser_journal=runtime_root/(prefix+'-process.json');browser_profile=runtime_root/(prefix+'-profile')
     if browser_journal.exists() or browser_journal.is_symlink():
      try:
       if not processes_absent:raise RuntimeError('Browser cleanup requires qualification process absence')
       def cleanup_profile():
        qualification=read_private_json(root/'process-qualification.json')
        record(prefix+'-outer-cleanup.json',cleanup_browser_profile(runtime_root,qualification,successful=passed,role=role))
       cleanup_step(cleanup_profile)
      except BaseException:failures.append(prefix+'_cleanup')
     elif browser_profile.exists() or browser_profile.is_symlink() or (passed and role=='assessment'):
      failures.append(prefix+'_cleanup')
   if secureshop_resources is not None:
    try:secureshop_resources.cleanup()
    except BaseException:failures.append('secureshop_resources_cleanup')
   if mcp_resources is not None:
    try:mcp_resources.cleanup()
    except BaseException:failures.append('mcp_resources_cleanup')
   if intended:
    try:record('container-cleanup.json',cleanup_step(lambda:cleanup_owned(command,daemon_id=args.docker_daemon_id,name=name,labels=labels,image=args.postgres_image_id,captured_id=captured)))
    except BaseException:
     failures.append('container_cleanup')
     record('container-cleanup.json',dict(status='cleanup_unverified',containerId=captured))
   try:cleanup_step(validate)
   except BaseException:failures.append('immutable_postflight')
   terminal=dict(status='passed_cleaned' if passed and not failures else 'failed',failures=failures,manifestSha256=args.manifest_sha256)
   if args.mcp_indirect:terminal.update(ownerHandle=int(args.owner_handle),resultSha256=digest(root/'result.tap') if (root/'result.tap').exists() else None)
   if args.secureshop:terminal.update(ownerHandle=int(args.owner_handle),modelDigest=args.model_digest,rendererManifestSha256=args.renderer_manifest_sha256,admittedReviewOutcome=args.secureshop_review_outcome,resultSha256=digest(root/'result.tap') if (root/'result.tap').exists() else None)
   record('terminal.json',terminal)
  finally:
   processes.restore()
   if bounded_cohort:
    signal.alarm(0);signal.signal(signal.SIGALRM,prior_alarm)
  if failures:raise RuntimeError('Qualification cleanup/postflight failed')

if __name__=='__main__':main()
