#!/usr/bin/env python3
"""Qualify persona judgment binding in owned stores; actual model is explicit opt-in."""
import argparse, hashlib, http.client, json, os, signal, subprocess, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from sensitive_info_recovery_safety import SignalGate

EXPECTED_DOCKER='unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock'
NODE=Path('/Users/averma5/.owasp-ai-goat/runtimes/node-v26.9.0-darwin-arm64/bin/node')
DOCKER=Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')
IMAGE='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
SOURCE=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True);parser.add_argument('--password-reset',action='store_true');parser.add_argument('--owned-user-lookup',action='store_true');parser.add_argument('--core',action='store_true');parser.add_argument('--acl-foundation',action='store_true');parser.add_argument('--acl-repository',action='store_true');parser.add_argument('--lifecycle',action='store_true');parser.add_argument('--mcp',action='store_true');parser.add_argument('--journal',action='store_true');parser.add_argument('--mcp-actual',action='store_true');parser.add_argument('--audit-actual',action='store_true');parser.add_argument('--audit-query',action='store_true');parser.add_argument('--audit-query-actual',action='store_true');parser.add_argument('--stored-browser',action='store_true');parser.add_argument('--assembled-core',action='store_true');parser.add_argument('--stored-browser-actual',action='store_true');parser.add_argument('--review-crud',action='store_true');parser.add_argument('--account-commerce',action='store_true');parser.add_argument('--assembled-external-actual',action='store_true');args=parser.parse_args()
if sum([args.password_reset,args.owned_user_lookup,args.acl_repository,args.acl_foundation,args.assembled_external_actual,args.core,args.lifecycle,args.mcp,args.journal,args.mcp_actual,args.audit_actual,args.audit_query,args.audit_query_actual,args.stored_browser,args.assembled_core,args.stored_browser_actual,args.review_crud,args.account_commerce])>1:raise SystemExit('Choose one qualification scope')
if args.acl_repository:args.acl_foundation=True
mode='password-reset' if args.password_reset else 'owned-user-lookup' if args.owned_user_lookup else 'acl-repository' if args.acl_repository else 'acl-foundation' if args.acl_foundation else 'account-commerce' if args.account_commerce else 'assembled-external-actual' if args.assembled_external_actual else 'review-crud' if args.review_crud else 'audit-query-actual' if args.audit_query_actual else 'stored-browser-actual' if args.stored_browser_actual else 'audit-query' if (args.audit_query or args.audit_query_actual) else 'stored-browser' if (args.stored_browser or args.stored_browser_actual) else 'assembled-core' if args.assembled_core else 'audit-actual' if args.audit_actual else 'mcp-actual' if args.mcp_actual else 'journal' if args.journal else 'mcp' if args.mcp else 'lifecycle' if args.lifecycle else 'core' if args.core else 'candidate'
test_file=('tests/postgres/secureshopBoundPasswordReset.integration.test.js' if args.password_reset else 'tests/postgres/secureshopOwnedUserLookup.integration.test.js' if args.owned_user_lookup else 'tests/postgres/secureshopBoundAclFoundation.integration.test.js' if args.acl_foundation else 'tests/postgres/secureshopPersonaAccountCommerce.integration.test.js' if args.account_commerce else 'tests/postgres/secureshopAssembledExternalActual.integration.test.js' if args.assembled_external_actual else 'tests/postgres/secureshopPersonaReviewCrud.integration.test.js' if args.review_crud else 'tests/postgres/secureshopPersonaAuditQuery.integration.test.js' if (args.audit_query or args.audit_query_actual) else 'tests/postgres/secureshopPersonaStoredBrowser.integration.test.js' if (args.stored_browser or args.stored_browser_actual) else 'tests/postgres/secureshopSharedGradingAssembly.integration.test.js' if args.assembled_core else 'tests/postgres/secureshopPersonaAuditActual.integration.test.js' if args.audit_actual else 'tests/postgres/secureshopPersonaMcpActual.integration.test.js' if args.mcp_actual else
 'tests/postgres/secureshopPersonaJournalAuthority.integration.test.js' if args.journal else
 'tests/postgres/secureshopPersonaMcpAuthority.integration.test.js' if args.mcp else
 'tests/postgres/secureshopPersonaJudgment'+('Lifecycle' if args.lifecycle else 'Core' if args.core else 'Candidate')+'.integration.test.js')
if args.docker_host!=EXPECTED_DOCKER:raise SystemExit('reviewed isolated Docker host required')
root=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-persona-judgments-'));os.chmod(root,0o700);workspace=root/'source'
container='owasp-ai-goat-persona-judgments-'+uuid.uuid4().hex[:12];owner=uuid.uuid4().hex
docker=[str(DOCKER),'--host',args.docker_host]
env={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':os.environ['HOME'],'TMPDIR':str(root)}
state={'container':container,'owner':owner,'image':IMAGE,'evidence':str(root),'launcherPid':os.getpid(),
 'nodeVersion':None,'containerCreationAttempted':False,'child':None,'runStatus':'preparing','cleanup':None,
 'mode':mode,'actualModel':None,'createdAt':datetime.now(timezone.utc).isoformat()}
ownership=root/'ownership.json';log_path=root/'tests.log';log_path.touch(mode=0o600)
def persist():ownership.write_text(json.dumps(state,indent=2)+'\n');os.chmod(ownership,0o600)
def run(command,**kwargs):kwargs.setdefault('timeout',120);return subprocess.run(command,check=True,env=kwargs.pop('env',env),**kwargs)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def exact_absence(name=container):
 query=subprocess.run(docker+['ps','-a','--filter',f'name=^/{name}$','--format','{{.Names}}'],env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=30)
 if query.returncode:raise RuntimeError('exact-name container query failed')
 return not query.stdout.strip()
audit_container=container+'-synthetic';audit_attempted=False
child=None;creation_attempted=False;gate=SignalGate();signal.signal(signal.SIGTERM,gate.handler);signal.signal(signal.SIGINT,gate.handler);persist()
def owned_group_members(pgid):
 listing=subprocess.run(['ps','-axo','pid=,pgid=,uid='],env=env,stdout=subprocess.PIPE,text=True,check=True,timeout=5).stdout
 members=[]
 for line in listing.splitlines():
  fields=line.split()
  if len(fields)==3 and int(fields[1])==pgid:
   if int(fields[2])!=os.getuid():raise RuntimeError(f'refusing foreign process in owned group {pgid}')
   members.append(int(fields[0]))
 return members
def stop_child():
 if child is None:return
 pgid=state.get('child',{}).get('pgid')
 if not pgid:return
 if owned_group_members(pgid):os.killpg(pgid,signal.SIGTERM)
 deadline=time.monotonic()+5
 while owned_group_members(pgid) and time.monotonic()<deadline:time.sleep(.05)
 if owned_group_members(pgid):os.killpg(pgid,signal.SIGKILL)
 try:child.wait(timeout=5)
 except subprocess.TimeoutExpired:pass
 if owned_group_members(pgid):raise RuntimeError('owned Node/browser process group cleanup incomplete')
try:
 version=run([str(NODE),'--version'],stdout=subprocess.PIPE,text=True).stdout.strip()
 if version!='v26.9.0':raise RuntimeError('managed Node v26.9.0 required')
 state['nodeVersion']=version;persist()
 if args.assembled_external_actual or args.mcp_actual or args.audit_actual or args.stored_browser_actual or args.audit_query_actual:
  connection=http.client.HTTPConnection('127.0.0.1',11434,timeout=5)
  try:
   connection.request('GET','/api/tags',headers={'Accept':'application/json'})
   response=connection.getresponse();payload=response.read(1048577)
   if response.status!=200 or len(payload)>1048576:raise RuntimeError('owned local Ollama tags preflight failed')
   tags=json.loads(payload.decode('utf-8'))
   names={row.get('name') for row in tags.get('models',[]) if isinstance(row,dict)}|{row.get('model') for row in tags.get('models',[]) if isinstance(row,dict)}
   if 'llama3.1:8b' not in names:raise RuntimeError('required local Ollama model llama3.1:8b unavailable')
  finally:connection.close()
  state['actualModel']={'provider':'ollama','model':'llama3.1:8b','baseURL':'http://127.0.0.1:11434','tagsPreflight':True};persist()
 daemon_name=run(docker+['info','--format','{{.Name}}'],stdout=subprocess.PIPE,text=True).stdout.strip()
 if daemon_name!='colima-owasp-ai-goat-pg-verify':raise RuntimeError('reviewed isolated Docker daemon required')
 image_id=run(docker+['image','inspect','--format','{{.Id}}',IMAGE],stdout=subprocess.PIPE,text=True).stdout.strip()
 if image_id!=IMAGE:raise RuntimeError('immutable PostgreSQL image identity mismatch')
 state['dockerDaemon']=daemon_name;state['imageId']=image_id;persist()
 if not exact_absence():raise RuntimeError('owned container name unexpectedly exists')
 run([str(NODE),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(SOURCE),str(workspace)],cwd=SOURCE)
 (workspace/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
 inventory=[test_file,'docs/modernization/drafts/secureshop-bound-password-reset/0026_password_reset.candidate.sql','docs/modernization/drafts/secureshop-owned-user-lookup/0025_owned_user_lookup.candidate.sql','tests/fixtures/secureshopAssembledExternalGrading.js','tests/postgres/secureshopPersonaAuditQueryActualGate.js','tests/postgres/secureshopPolicyTraceMigrationGate.js','tests/postgres/secureshopAuditSnapshotMigrationGate.js','tests/postgres/run-persona-judgments-isolated.py','tests/postgres/sensitive_info_recovery_safety.py','package-lock.json','package.json',
  'docs/modernization/drafts/secureshop-bound-access-control/schema.candidate.sql','docs/modernization/drafts/secureshop-persona-judgments/persona-judgments.candidate.sql','docs/modernization/drafts/secureshop-persona-judgments/repository.candidate.js','docs/modernization/drafts/secureshop-user-administration/persona-state.candidate.sql']
 for folder in ['server/database/postgres','server/services','server/agent-runtime','server/data','server/routes/secureshop','db/postgres','scripts/lib','shared','sidecars/audit-sql-target','agent-host']:
  inventory.extend(str(item.relative_to(workspace)) for item in sorted((workspace/folder).rglob('*')) if item.is_file())
 if args.stored_browser or args.stored_browser_actual:
  inventory.extend(str(item.relative_to(workspace)) for item in (workspace/'client').rglob('*') if item.is_file() and 'node_modules' not in item.parts)
 state['sourceSha256']={name:digest(workspace/name) for name in sorted(set(inventory))};state['nodeSha256']=digest(NODE);persist()
 run([str(NODE),'--check',test_file],cwd=workspace)
 creation_attempted=True;state['containerCreationAttempted']=True;persist()
 run(docker+['run','--detach','--pull','never','--name',container,'--label','owasp-ai-goat.test.owner='+owner,
  '--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size=268435456','-e','POSTGRES_HOST_AUTH_METHOD=trust',
  '-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',IMAGE,'-c','shared_buffers=16MB','-c','max_connections=40',
  '-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL)
 details=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]
 if details.get('Mounts') or details['Config']['Labels'].get('owasp-ai-goat.test.owner')!=owner:raise RuntimeError('owned PostgreSQL isolation/ownership check failed')
 for _ in range(100):
  ready=subprocess.run(docker+['exec',container,'pg_isready','-h','127.0.0.1','-U','postgres'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
  if ready.returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('owned PostgreSQL unavailable')
 port=int(run(docker+['port',container,'5432/tcp'],stdout=subprocess.PIPE,text=True).stdout.strip().rsplit(':',1)[1])
 psql=docker+['exec',container,'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-c']
 roles=[f'dvaia_{family}_{role}' for family in (['identity','secureshop','secureshop_agents']+(['secureshop_review'] if (args.audit_actual or args.stored_browser or args.stored_browser_actual or args.assembled_core or args.audit_query or args.audit_query_actual or args.review_crud or args.account_commerce or args.assembled_external_actual) else [])) for role in ['migration','runtime']]
 run(psql+[';'.join(f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS' for role in roles)+';'],stdout=subprocess.DEVNULL)
 nonce=owner[:12]
 for store,family in ([('identity','identity'),('identityfresh','identity'),('commerce','secureshop'),('fresh','secureshop_agents')]+([('aclfresh','secureshop_agents')] if (args.acl_foundation or args.owned_user_lookup or args.password_reset) else [])+([('review','secureshop_review')] if (args.audit_actual or args.stored_browser or args.stored_browser_actual or args.assembled_core or args.audit_query or args.audit_query_actual or args.review_crud or args.account_commerce or args.assembled_external_actual) else [])):
  database=f'owasp_ai_goat_test_persona_{nonce}_{store}';migration=f'dvaia_{family}_migration';runtime=f'dvaia_{family}_runtime'
  run(psql+[f'CREATE DATABASE {database} OWNER {migration}'],stdout=subprocess.DEVNULL)
  run(psql+[f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime}'],stdout=subprocess.DEVNULL)
  env[f'PERSONA_{store.upper()}_MIGRATION_URL']=f'postgresql://{migration}@127.0.0.1:{port}/{database}'
  env[f'PERSONA_{store.upper()}_RUNTIME_URL']=f'postgresql://{runtime}@127.0.0.1:{port}/{database}'
 if args.audit_query or args.audit_query_actual:
  if not exact_absence(audit_container):raise RuntimeError('synthetic container unexpectedly exists')
  audit_attempted=True;state['auditContainer']={'name':audit_container,'creationAttempted':True};persist()
  run(docker+['run','--detach','--pull','never','--name',audit_container,'--label','owasp-ai-goat.test.owner='+owner,
   '--memory','256m','--cpus','0.5','--pids-limit','64','--tmpfs','/var/lib/postgresql:rw,size=268435456','-e','POSTGRES_HOST_AUTH_METHOD=trust',
   '-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',IMAGE,'-c','shared_buffers=16MB','-c','max_connections=20','-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL)
  info=json.loads(run(docker+['inspect',audit_container],stdout=subprocess.PIPE,text=True).stdout)[0]
  if info.get('Mounts') or info['Config']['Labels'].get('owasp-ai-goat.test.owner')!=owner:raise RuntimeError('synthetic isolation check failed')
  for _ in range(100):
   ready=subprocess.run(docker+['exec',audit_container,'pg_isready','-h','127.0.0.1','-U','postgres'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
   if ready.returncode==0:break
   time.sleep(.25)
  else:raise RuntimeError('synthetic PostgreSQL unavailable')
  audit_port=int(run(docker+['port',audit_container,'5432/tcp'],stdout=subprocess.PIPE,text=True).stdout.strip().rsplit(':',1)[1])
  if audit_port==port:raise RuntimeError('synthetic target cluster must be separate')
  run(docker+['exec',audit_container,'psql','-U','postgres','-v','ON_ERROR_STOP=1','-c',f'CREATE DATABASE owasp_ai_goat_test_audit_search_{nonce}'],stdout=subprocess.DEVNULL)
  run(docker+['exec',audit_container,'psql','-U','postgres','-v','ON_ERROR_STOP=1','-c',f'REVOKE CONNECT ON DATABASE owasp_ai_goat_test_audit_search_{nonce} FROM PUBLIC'],stdout=subprocess.DEVNULL)
  env['PERSONA_AUDIT_CONTROL_URL']=f'postgresql://postgres@127.0.0.1:{audit_port}/owasp_ai_goat_test_audit_search_{nonce}'
  env['PERSONA_AUDIT_QUERY_NATIVE']='1'
 if args.assembled_external_actual:env['PERSONA_ASSEMBLED_EXTERNAL_ACTUAL']='1'
 if args.assembled_core:env['PERSONA_ASSEMBLED_CORE_NATIVE']='1'
 if args.review_crud:env['PERSONA_REVIEW_CRUD_NATIVE']='1'
 if args.account_commerce:env['PERSONA_ACCOUNT_COMMERCE_NATIVE']='1'
 if args.acl_foundation:env['PERSONA_ACL_FOUNDATION_NATIVE']='1'
 if args.password_reset:env['PERSONA_PASSWORD_RESET_NATIVE']='1'
 if args.owned_user_lookup:env['PERSONA_OWNED_USER_LOOKUP_NATIVE']='1'
 if args.acl_repository:env['PERSONA_ACL_REPOSITORY_NATIVE']='1'
 if args.stored_browser or args.stored_browser_actual:
  env['PERSONA_STORED_BROWSER_NATIVE']='1'
  (workspace/'client/node_modules').symlink_to(SOURCE/'client/node_modules',target_is_directory=True)
  with (root/'renderer-build.log').open('w') as build_log:
   child=subprocess.Popen([str(NODE.parent/'npm'),'--prefix','client','run','build:review-renderer'],cwd=workspace,env=env,stdout=build_log,stderr=build_log,start_new_session=True)
   state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid)};state['runStatus']='renderer_build';persist()
   try:build_code=child.wait(timeout=120)
   except subprocess.TimeoutExpired:stop_child();raise RuntimeError('Owned renderer build timed out')
   stop_child()
   if build_code:raise RuntimeError('Owned renderer build failed')
   state['rendererBuild']={'exitCode':build_code,'logSha256':digest(root/'renderer-build.log'),'pgidAbsent':not owned_group_members(state['child']['pgid'])};persist()
  state['rendererHashes']={str(item.relative_to(workspace)):digest(item) for item in (workspace/'client').rglob('*') if item.is_file() and 'build/secureshop-review-renderer/' in str(item)};persist()
 env.update(NODE_ENV='test',PG_TEST_DISPOSABLE='yes',PERSONA_REVIEW_CANONICAL_NATIVE='1',OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(workspace),
  PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',
  AI_PROVIDER='mock',TRANSFORMERS_OFFLINE='1',JWT_SECRET=uuid.uuid4().hex+uuid.uuid4().hex,SESSION_SECRET=uuid.uuid4().hex+uuid.uuid4().hex,
  AWS_EC2_METADATA_DISABLED='true',MCP_WORKSHOP_AUTOSTART='false',MCP_SIDECARS_AUTOSTART='false',SS_ENABLE='false',HF_HUB_OFFLINE='1',
  OLLAMA_BASE_URL='http://127.0.0.1:1',SANDBOX_RUNNER_URL='http://127.0.0.1:1',SSRF_TARGET_URL='http://127.0.0.1:1',
 ROGUE_MCP_URL='http://127.0.0.1:1',MAILPIT_API_URL='http://127.0.0.1:1',MAILPIT_SMTP_HOST='127.0.0.1',MAILPIT_SMTP_PORT='1')
 if args.assembled_external_actual or args.mcp_actual or args.audit_actual or args.stored_browser_actual or args.audit_query_actual:env.update(LIVE_OLLAMA_TEST='1',JUDGE_PROVIDER='ollama',OLLAMA_MODEL='llama3.1:8b',OLLAMA_BASE_URL='http://127.0.0.1:11434')
 if args.mcp_actual:env['PERSONA_MCP_ACTUAL_MODEL']='1'
 if args.audit_actual:env['PERSONA_AUDIT_ACTUAL_MODEL']='1'
 if args.audit_query_actual:env['PERSONA_AUDIT_QUERY_ACTUAL_MODEL']='1'
 if args.stored_browser_actual:env['PERSONA_STORED_BROWSER_ACTUAL_MODEL']='1'
 with log_path.open('w') as log:
  child=subprocess.Popen([str(NODE),'--test','--test-reporter=tap',test_file],cwd=workspace,env=env,stdout=log,stderr=log,start_new_session=True)
  state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid)};state['runStatus']='test_running';persist()
  try:code=child.wait(timeout=960 if args.mcp_actual else 660 if (args.audit_actual or args.audit_query_actual or args.assembled_external_actual) else 360 if args.stored_browser_actual else 300)
  except subprocess.TimeoutExpired:stop_child();raise RuntimeError('Persona judgment qualification timed out')
 if code:raise RuntimeError(f'Persona judgment foundation failed ({code}); inspect retained tests.log')
 state['runStatus']='passed';state['resultSha256']=digest(log_path);persist()
except BaseException as error:
 if creation_attempted:
  try:
   diagnostic=subprocess.run(docker+['logs','--tail','120',container],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20)
   (root/'container.log').write_text(diagnostic.stdout);os.chmod(root/'container.log',0o600)
  except Exception as diagnostic_error:state['containerDiagnosticError']=type(diagnostic_error).__name__
 state.update({'runStatus':'failed','errorType':type(error).__name__,'resultSha256':digest(log_path)});persist();raise
finally:
 gate.protect_cleanup();errors=[];remove_code=None;absent=None
 try:stop_child()
 except Exception as error:errors.append('child:'+type(error).__name__)
 if creation_attempted:
  try:
   if not exact_absence():
    info=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]
    if info['Config']['Labels'].get('owasp-ai-goat.test.owner')!=owner:raise RuntimeError('refusing foreign container cleanup')
    remove_code=subprocess.run(docker+['rm','-f','-v',container],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30).returncode
   else:remove_code=0
  except Exception as error:errors.append('remove:'+type(error).__name__)
 try:absent=exact_absence()
 except Exception as error:errors.append('absence:'+type(error).__name__)
 audit_absent=True
 if audit_attempted:
  try:
   if not exact_absence(audit_container):
    info=json.loads(run(docker+['inspect',audit_container],stdout=subprocess.PIPE,text=True).stdout)[0]
    if info['Config']['Labels'].get('owasp-ai-goat.test.owner')!=owner:raise RuntimeError('refusing foreign synthetic cleanup')
    run(docker+['rm','-f','-v',audit_container],stdout=subprocess.DEVNULL)
   audit_absent=exact_absence(audit_container)
  except Exception as error:errors.append('synthetic:'+type(error).__name__);audit_absent=False
 try:pgid_absent=not state.get('child') or not owned_group_members(state['child']['pgid'])
 except Exception as error:errors.append('pgid:'+type(error).__name__);pgid_absent=False
 state['cleanup']={'removeExitCode':remove_code,'containerAbsent':absent,'nodeBrowserPgidAbsent':pgid_absent,
  'syntheticContainerAbsent':audit_absent,'errors':errors,'completedAt':datetime.now(timezone.utc).isoformat()}
 if state['runStatus']=='passed' and (errors or audit_absent is not True or absent is not True or pgid_absent is not True or (creation_attempted and remove_code!=0)):state['runStatus']='failed';state['errorType']='CleanupFailed'
 persist()
print(json.dumps({'evidence':str(root),'status':state['runStatus'],'cleanup':state['cleanup']}),flush=True)
if state['runStatus']!='passed':raise SystemExit(1)
