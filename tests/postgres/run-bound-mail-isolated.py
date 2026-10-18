#!/usr/bin/env python3
"""Qualify drafts0038/0039 in owned fresh/populated agents stores with real identity/persona authority; no sidecar/model."""
import argparse, hashlib, http.client, json, os, signal, subprocess, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from sensitive_info_recovery_safety import SignalGate

EXPECTED_DOCKER='unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
NODE=Path('/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node')
DOCKER=Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')
IMAGE='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
SOURCE=Path(__file__).resolve().parents[2]
from bound_mail_modes import create_parser,bounds_for
parser=create_parser();args=parser.parse_args();disclosure=args.mode in ['disclosure-native','disclosure-actual']
if disclosure and (not args.disclosure_state or args.mode=='disclosure-actual' and args.disclosure_state!='fresh'):parser.error('disclosure requires explicit state; actual is fresh only')
if not disclosure and args.disclosure_state is not None:parser.error('disclosure state is mode-specific')
parent_seconds,child_seconds=bounds_for(args.mode)
if disclosure or args.mode in ['reply-authority','reply-authority-actual']:
 import re
 if disclosure:import mail_disclosure_freeze as reply_freeze
 else:import mail_reply_authority_freeze as reply_freeze
 if not all(re.fullmatch(r'[0-9a-f]{64}',value or '') for value in [args.reviewed_source_sha256,args.reviewed_dependency_sha256]):parser.error('reply-authority requires explicit reviewed source and dependency digests')
mode='bound-mail-'+args.mode
test_file={'disclosure-native':'tests/postgres/secureshopMailDisclosure.native.js','disclosure-actual':'tests/postgres/secureshopMailDisclosure.native.js','migration':'tests/postgres/secureshopBoundMail.native.js','lifecycle':'tests/postgres/secureshopBoundMailLifecycle.native.js','actual':'tests/postgres/secureshopBoundMailActual.native.js','header':'tests/postgres/secureshopMailHeader.native.js','header-actual':'tests/postgres/secureshopMailHeaderActual.native.js','reply-authority':'tests/postgres/secureshopMailHeader.native.js','reply-authority-actual':'tests/postgres/secureshopMailHeader.native.js'}[args.mode]
if args.docker_host!=EXPECTED_DOCKER:raise SystemExit('reviewed isolated Docker host required')
root=Path(tempfile.mkdtemp(prefix='dvaia-bound-mail-'));os.chmod(root,0o700);workspace=root/'source'
container='dvaia-bound-mail-'+uuid.uuid4().hex[:12];owner=uuid.uuid4().hex
docker=[str(DOCKER),'--host',args.docker_host]
env={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':os.environ['HOME'],'TMPDIR':str(root)}
state={'container':container,'owner':owner,'image':IMAGE,'evidence':str(root),'launcherPid':os.getpid(),
 'nodeVersion':None,'containerCreationAttempted':False,'child':None,'runStatus':'preparing','cleanup':None,
 'mode':mode,'createdAt':datetime.now(timezone.utc).isoformat()}
ownership=root/'ownership.json';log_path=root/'tests.log';log_path.touch(mode=0o600)
def persist():ownership.write_text(json.dumps(state,indent=2)+'\n');os.chmod(ownership,0o600)
cleanup_deadline=None
def cleanup_timeout(limit):
 if cleanup_deadline is None:return limit
 remaining=cleanup_deadline-time.monotonic()
 if remaining<=0:raise TimeoutError('Owned cleanup deadline exhausted')
 return min(limit,remaining)
def bounded_run(command,**kwargs):
 kwargs['timeout']=cleanup_timeout(kwargs.get('timeout',120))
 return subprocess.run(command,**kwargs)
def run(command,**kwargs):
 kwargs.setdefault('timeout',120);return bounded_run(command,check=True,env=kwargs.pop('env',env),**kwargs)
def attempt_cleanup(errors,label,action):
 try:return action()
 except Exception as error:errors.append(label+':'+type(error).__name__);return None
def cleanup_verify(root,expected_source,expected_dependencies):
 # Resource cleanup precedes these bounded, read-only inventory operations.
 from mail_reply_authority_freeze import SCRIPT
 from owned_mcp_assembly_freeze import record
 cleanup_timeout(60)
 names=json.loads(bounded_run([str(NODE),'-e',SCRIPT,str(root)],capture_output=True,text=True,check=True,timeout=60).stdout)
 rows={}
 for name in names:
  cleanup_timeout(60);rows[name]=record(root/name)
 if reply_freeze.digest(rows)!=expected_source:raise RuntimeError('Final source inventory mismatch')
 deps={}
 for path in (root/'node_modules').rglob('*'):
  cleanup_timeout(60)
  if path.is_file() or path.is_symlink():deps[path.relative_to(root).as_posix()]=record(path)
 if reply_freeze.digest(deps)!=expected_dependencies:raise RuntimeError('Final dependency inventory mismatch')
 cleanup_timeout(1)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def exact_absence(name=container):
 query=bounded_run(docker+['ps','-a','--filter',f'name=^/{name}$','--format','{{.Names}}'],env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=30)
 if query.returncode:raise RuntimeError('exact-name container query failed')
 return not query.stdout.strip()
executor=None;child=None;creation_attempted=False;gate=SignalGate();signal.signal(signal.SIGTERM,gate.handler);signal.signal(signal.SIGINT,gate.handler);signal.signal(signal.SIGALRM,gate.handler);signal.alarm(parent_seconds);persist()
def owned_group_members(pgid):
 listing=bounded_run(['ps','-axo','pid=,pgid=,uid='],env=env,stdout=subprocess.PIPE,text=True,check=True,timeout=5).stdout
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
 while owned_group_members(pgid) and time.monotonic()<deadline:
  child.poll();time.sleep(.05)
 if owned_group_members(pgid):os.killpg(pgid,signal.SIGKILL)
 try:child.wait(timeout=cleanup_timeout(5))
 except subprocess.TimeoutExpired:pass
 if owned_group_members(pgid):raise RuntimeError('owned Node/browser process group cleanup incomplete')
try:
 version=run([str(NODE),'--version'],stdout=subprocess.PIPE,text=True).stdout.strip()
 if version!='v26.10.0':raise RuntimeError('managed Node v26.10.0 required')
 if digest(NODE)!='56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861':raise RuntimeError('reviewed Node26.10 checksum mismatch')
 state['nodeVersion']=version;persist()
 if disclosure or args.mode in ['reply-authority','reply-authority-actual']:
  if digest(DOCKER)!=reply_freeze.DOCKER_SHA:raise RuntimeError('Reviewed Docker executable mismatch')
  reviewed_rows=reply_freeze.verify(SOURCE,args.reviewed_source_sha256,args.reviewed_dependency_sha256)
  expected_staged,staged_bytes=reply_freeze.stage_expected(reviewed_rows,SOURCE)
  state['reviewedIntegrity']={'sourceDigest':args.reviewed_source_sha256,'dependencyDigest':args.reviewed_dependency_sha256,'stagedSourceDigest':reply_freeze.digest(expected_staged),'sourceCount':len(reviewed_rows)}
 daemon_name=run(docker+['info','--format','{{.Name}}'],stdout=subprocess.PIPE,text=True).stdout.strip()
 if daemon_name!='colima-dvaia-pg-verify':raise RuntimeError('reviewed isolated Docker daemon required')
 if disclosure or args.mode in ['reply-authority','reply-authority-actual']:
  daemon_id=run(docker+['info','--format','{{.ID}}'],stdout=subprocess.PIPE,text=True,timeout=10).stdout.strip()
  reply_freeze.check_pins(NODE,DOCKER,daemon_id);state['dockerDaemonId']=daemon_id;state['dockerSha256']=digest(DOCKER)
 image_id=run(docker+['image','inspect','--format','{{.Id}}',IMAGE],stdout=subprocess.PIPE,text=True).stdout.strip()
 if image_id!=IMAGE:raise RuntimeError('immutable PostgreSQL image identity mismatch')
 state['dockerDaemon']=daemon_name;state['imageId']=image_id;persist()
 if not exact_absence():raise RuntimeError('owned container name unexpectedly exists')
 if disclosure or args.mode in ['reply-authority','reply-authority-actual']:reply_freeze.copy(SOURCE,workspace)
 else:
  run([str(NODE),'-e',"const fs=require('node:fs'),path=require('node:path'),{createCopyFilter}=require('./scripts/lib/isolated-source-copy');const [source,dest]=process.argv.slice(1),base=createCopyFilter(source),omitted=new Set(['server/platform_secrets.json','server/config/secrets.env']);fs.cpSync(source,dest,{recursive:true,filter:p=>base(p)&&!omitted.has(path.relative(source,p).split(path.sep).join('/'))});for(const p of omitted)if(fs.existsSync(path.join(dest,p)))throw Error('Unused secret fixture copied');",str(SOURCE),str(workspace)],cwd=SOURCE)
 # Only the newly owned copy root needs write permission for its dependency link.
 workspace.chmod(workspace.stat().st_mode | 0o200)
 state['omittedUnusedTeachingFixtures']=['server/platform_secrets.json','server/config/secrets.env']
 (workspace/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
 if disclosure or args.mode in ['reply-authority','reply-authority-actual']:
  reply_freeze.verify(workspace,args.reviewed_source_sha256,args.reviewed_dependency_sha256)
  reply_freeze.verify(SOURCE,args.reviewed_source_sha256,args.reviewed_dependency_sha256)
 if disclosure:
  candidate=workspace/'server/config/secureshopCurriculum.js';candidate.chmod(0o600);candidate.write_bytes(staged_bytes)
  state['candidateEligibility']={'objective':'ss_mail_cross_persona_read','candidateSha256':digest(candidate),'sharedSourceChanged':False}
 elif args.mode in ['actual','header','header-actual','reply-authority','reply-authority-actual']:
  candidate=workspace/'server/config/secureshopCurriculum.js'
  original=candidate.read_text();needle='function isQualifiedObjective(objectiveId) { return QUALIFIED_OBJECTIVE_SET.has(objectiveId); }'
  if original.count(needle)!=1:raise RuntimeError('candidate eligibility source mismatch')
  objective='ss_mail_reply_redirect' if args.mode in ['actual','reply-authority','reply-authority-actual'] else 'ss_mail_header_construction'
  if disclosure or args.mode in ['reply-authority','reply-authority-actual']:candidate.chmod(0o600)
  candidate.write_text(original.replace(needle,"function isQualifiedObjective(objectiveId) { return objectiveId === '"+objective+"' || QUALIFIED_OBJECTIVE_SET.has(objectiveId); }"))
  state['candidateEligibility']={'objective':objective,'originalSha256':hashlib.sha256(original.encode()).hexdigest(),'candidateSha256':digest(candidate),'sharedSourceChanged':False}
 if disclosure or args.mode in ['reply-authority','reply-authority-actual']:
  candidate.chmod(0o400)
  if candidate.read_bytes()!=staged_bytes:raise RuntimeError('Candidate staging differs from reviewed delta')
  reply_freeze.verify(workspace,reply_freeze.digest(expected_staged),args.reviewed_dependency_sha256)
 inventory=[test_file,'tests/postgres/secureshopMailActualTransport.js','tests/fixtures/secureshopMailQualificationContracts.js','tests/secureshopMailQualificationContracts.test.js','tests/postgres/run-bound-mail-isolated.py','tests/postgres/sensitive_info_recovery_safety.py','package-lock.json','package.json']
 if args.mode in ['reply-authority','reply-authority-actual']:inventory.extend(['tests/postgres/secureshopMailReplyAuthority.cohort.js','tests/fixtures/secureshopMailHistoricalRubrics.json','tests/secureshopMailReplyAuthorityNative.test.js','tests/postgres/prepare-mail-reply-authority-native.js'])
 if args.mode=='reply-authority-actual':inventory.extend(['tests/postgres/secureshopMailReplyAuthorityActual.cohort.js','tests/fixtures/secureshopMailReplyAuthorityActualCases.js','tests/secureshopMailReplyAuthorityActualCases.test.js'])
 if args.mode=='header-actual':inventory.extend(['tests/fixtures/secureshopMailHeaderMountedSequence.js','tests/secureshopMailHeaderMountedSequence.test.js','tests/postgres/prepare-mail-header-actual.js'])
 if args.mode=='header':inventory.extend(['tests/postgres/secureshopMailHeaderLifecycle.cohort.js','tests/secureshopMailHeaderLifecycle.test.js','tests/secureshopMailHeaderBoundarySelection.test.js','tests/secureshopMailHeaderEvidence.test.js','tests/secureshopMailHeaderCompletion.test.js','tests/secureshopMailHeaderAssessment.test.js','tests/postgres/prepare-mail-header-native.js'])
 for folder in ['server','db/postgres','docs/modernization/drafts/secureshop-owned-mail','docs/modernization/drafts/secureshop-owned-listings','docs/modernization/drafts/secureshop-owned-mcp-registry','scripts/lib','shared','agent-host']:
  inventory.extend(str(item.relative_to(workspace)) for item in sorted((workspace/folder).rglob('*')) if item.is_file())
 state['sourceSha256']={name:digest(workspace/name) for name in sorted(set(inventory))};state['nodeSha256']=digest(NODE);persist()
 run([str(NODE),'--check',test_file],cwd=workspace)
 if disclosure:run([str(NODE),'--test','tests/secureshopMailDisclosureNativeContract.test.js','tests/secureshopMailDisclosureEvidence.test.js','tests/secureshopMailDisclosureAssessment.test.js','tests/secureshopMailDisclosureRoute.test.js'],cwd=workspace,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 if args.mode in ['reply-authority','reply-authority-actual']:run([str(NODE),'--test','tests/secureshopMailReplyAuthorityNative.test.js','tests/secureshopMailEvidence.test.js','tests/secureshopMailAssessment.test.js'],cwd=workspace,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 if args.mode=='reply-authority-actual':run([str(NODE),'--test','tests/secureshopMailReplyAuthorityActualCases.test.js'],cwd=workspace,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 if args.mode=='header':run([str(NODE),'--test','tests/secureshopMailHeaderLifecycle.test.js','tests/secureshopMailHeaderBoundarySelection.test.js','tests/secureshopMailHeaderEvidence.test.js','tests/secureshopMailHeaderCompletion.test.js','tests/secureshopMailHeaderAssessment.test.js'],cwd=workspace,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 if args.mode in ['actual','header-actual']:run([str(NODE),'--test','tests/secureshopMailQualificationContracts.test.js'],cwd=workspace,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 if disclosure or args.mode in ['reply-authority','reply-authority-actual']:
  reply_freeze.verify(SOURCE,args.reviewed_source_sha256,args.reviewed_dependency_sha256)
  reply_freeze.verify(workspace,reply_freeze.digest(expected_staged),args.reviewed_dependency_sha256)
 creation_attempted=True;state['containerCreationAttempted']=True;persist()
 run(docker+['run','--detach','--pull','never','--name',container,'--label','dvaia.test.owner='+owner,
  '--memory','1g','--cpus','2','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size=268435456','-e','POSTGRES_HOST_AUTH_METHOD=trust',
  '-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',IMAGE,'-c','shared_buffers=16MB','-c','max_connections=40',
  '-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL)
 details=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]
 if details.get('Mounts') or details['Config']['Labels'].get('dvaia.test.owner')!=owner:raise RuntimeError('owned PostgreSQL isolation/ownership check failed')
 for _ in range(100):
  ready=subprocess.run(docker+['exec',container,'pg_isready','-h','127.0.0.1','-U','postgres'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
  if ready.returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('owned PostgreSQL unavailable')
 port=int(run(docker+['port',container,'5432/tcp'],stdout=subprocess.PIPE,text=True).stdout.strip().rsplit(':',1)[1])
 server_version=run(docker+['exec',container,'psql','-U','postgres','-d','postgres','-Atc','SHOW server_version'],stdout=subprocess.PIPE,text=True).stdout.strip()
 state['postgresServerVersion']=server_version;state['postgresImageMetadata']=json.loads(run(docker+['image','inspect',IMAGE],stdout=subprocess.PIPE,text=True).stdout)[0].get('Config',{}).get('Labels',{});persist()
 psql=docker+['exec',container,'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-c']
 nonce=owner[:12];state['databases']=[]
 for label,schema in [('IDENTITY','identity'),('COMMERCE','secureshop'),('AGENTS','secureshop_agents'),('REVIEW','secureshop_review') if args.mode!='migration' else ('FRESH','secureshop_agents')]:
  migration='dvaia_'+schema+'_migration';runtime='dvaia_'+schema+'_runtime'
  if label!='FRESH':run(psql+[f'CREATE ROLE {migration} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE {runtime} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],stdout=subprocess.DEVNULL)
  database=f'dvaia_test_mail_{nonce}_{label.lower()}'
  run(psql+[f'CREATE DATABASE {database} OWNER {migration}'],stdout=subprocess.DEVNULL)
  run(psql+[f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime}'],stdout=subprocess.DEVNULL)
  state['databases'].append(database)
  env[f'MAIL_{label}_MIGRATION_URL']=f'postgresql://{migration}@127.0.0.1:{port}/{database}'
  env[f'MAIL_{label}_RUNTIME_URL']=f'postgresql://{runtime}@127.0.0.1:{port}/{database}'
 persist()
 env['MAIL_NATIVE']='1'
 if disclosure:
  (root/'logs').mkdir(mode=0o700)
  env.update(MAIL_DISCLOSURE_STATE=args.disclosure_state,MAIL_DISCLOSURE_ACTUAL='1' if args.mode=='disclosure-actual' else '0',LOGS_DIR=str(root/'logs'))
 if args.mode=='reply-authority':env['MAIL_REPLY_AUTHORITY_NATIVE']='1'
 if args.mode=='reply-authority-actual':env['MAIL_REPLY_AUTHORITY_ACTUAL']='1'
 env['MAIL_RESULT']=str(root/'candidate-result.json')
 env.update(NODE_ENV='test',PG_TEST_DISPOSABLE='yes',DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace),
  PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',
  AI_PROVIDER='mock',TRANSFORMERS_OFFLINE='1',JWT_SECRET=uuid.uuid4().hex+uuid.uuid4().hex,SESSION_SECRET=uuid.uuid4().hex+uuid.uuid4().hex,
  AWS_EC2_METADATA_DISABLED='true',MCP_WORKSHOP_AUTOSTART='false',MCP_SIDECARS_AUTOSTART='false',SS_ENABLE='false',HF_HUB_OFFLINE='1',
  OLLAMA_BASE_URL='http://127.0.0.1:1',SANDBOX_RUNNER_URL='http://127.0.0.1:1',SSRF_TARGET_URL='http://127.0.0.1:1',
 ROGUE_MCP_URL='http://127.0.0.1:1',MAILPIT_API_URL='http://127.0.0.1:1',MAILPIT_SMTP_HOST='127.0.0.1',MAILPIT_SMTP_PORT='1')
 with log_path.open('w') as log:
  child=subprocess.Popen([str(NODE),'--test','--test-reporter=tap',test_file],cwd=workspace,env=env,stdout=log,stderr=log,start_new_session=True)
  state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid)};state['runStatus']='test_running';persist()
  try:code=child.wait(timeout=child_seconds)
  except subprocess.TimeoutExpired:stop_child();raise RuntimeError('Bound mail native qualification timed out')
 if code:raise RuntimeError(f'Bound mail native qualification failed ({code}); inspect retained tests.log')
 state['runStatus']='passed';state['logSha256']=digest(log_path);state['runtimeResultSha256']=digest(root/'candidate-result.json');persist()
except BaseException as error:
 if creation_attempted:
  try:
   diagnostic=subprocess.run(docker+['logs','--tail','120',container],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20)
   (root/'container.log').write_text(diagnostic.stdout);os.chmod(root/'container.log',0o600)
  except Exception as diagnostic_error:state['containerDiagnosticError']=type(diagnostic_error).__name__
 state.update({'runStatus':'failed','errorType':type(error).__name__,'resultSha256':digest(log_path)});persist();raise
finally:
 signal.alarm(0);gate.protect_cleanup();errors=[];remove_code=None;absent=None
 cleanup_started=time.monotonic()
 if disclosure:cleanup_deadline=cleanup_started+120
 attempt_cleanup(errors,'child',stop_child)
 if executor:
  try:executor.close()
  except Exception as error:errors.append('executor:'+type(error).__name__)
 if creation_attempted:
  try:
   if not exact_absence():
    info=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True,timeout=10).stdout)[0]
    if info['Config']['Labels'].get('dvaia.test.owner')!=owner:raise RuntimeError('refusing foreign container cleanup')
    remove_code=bounded_run(docker+['rm','-f','-v',container],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30).returncode
   else:remove_code=0
  except Exception as error:errors.append('remove:'+type(error).__name__)
 absent=attempt_cleanup(errors,'absence',exact_absence)
 try:pgid_absent=not state.get('child') or not owned_group_members(state['child']['pgid'])
 except Exception as error:errors.append('pgid:'+type(error).__name__);pgid_absent=False
 state['cleanup']={'removeExitCode':remove_code,'containerAbsent':absent,'nodeBrowserPgidAbsent':pgid_absent,
 'errors':errors,'budgetSeconds':120 if disclosure else None,'elapsedSeconds':time.monotonic()-cleanup_started,'completedAt':datetime.now(timezone.utc).isoformat()}
 if (disclosure or args.mode in ['reply-authority','reply-authority-actual']) and 'reviewed_rows' in locals():
  try:
   cleanup_verify(SOURCE,args.reviewed_source_sha256,args.reviewed_dependency_sha256)
   if workspace.exists():cleanup_verify(workspace,reply_freeze.digest(expected_staged),args.reviewed_dependency_sha256)
   state['finalIntegrityVerified']=True
  except Exception as error:
   errors.append('integrity:'+type(error).__name__);state['finalIntegrityVerified']=False
 state['cleanup']['elapsedSeconds']=time.monotonic()-cleanup_started
 state['cleanup']['deadlineExceeded']=cleanup_deadline is not None and time.monotonic()>=cleanup_deadline
 if state['runStatus']=='passed' and (errors or absent is not True or pgid_absent is not True or (creation_attempted and remove_code!=0)):state['runStatus']='failed';state['errorType']='CleanupFailed'
 persist()
print(json.dumps({'evidence':str(root),'status':state['runStatus'],'cleanup':state['cleanup']}),flush=True)
if state['runStatus']!='passed':raise SystemExit(1)
