#!/usr/bin/env python3
"""One-use, rollback-capable rollout of the qualified observed-action MCP profile."""
import argparse, fcntl, hashlib, json, os, pathlib, signal, subprocess, tempfile, time, urllib.error, urllib.request
from datetime import datetime, timezone
from mcp_owned_live_promotion_safety import select_backend_pid
from sensitive_info_recovery_safety import SignalGate, classify_process_state, wait_for_exit
from mcp_owned_runner_upgrade_safety import smoke_login_payload, validate_recovery
from mcp_owned_observed_action_rollout_safety import (RetryingPauseSet, attempt_all,
 exact_image_absent, private_cookie_opener, validate_logout_result,
 load_exact_source_manifest, rollback_retention_decision, validate_revoked_status,
 validate_owner_handle, validate_terminal_grant)

ROOT=pathlib.Path(__file__).resolve().parents[2]; OWNER='/root/workshop_authenticity'
DOCKER_HOST='unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
RUNNER='damn-vulnerable-ai-application-mcp-owned-sandbox-1'; MAILPIT='damn-vulnerable-ai-application-mailpit-1'
IMAGE='mcp-owned-sandbox-runner:dev'; VOLUME_DEST='/sandbox/owned-targets'
CAPABILITY='mcp-owned-protected-state-transition.v2'; QUALIFICATION='mcp-owned-connected.protected-v2'
OBSERVED_CAPABILITY='mcp-owned-observed-action.v1'; OBSERVED_QUALIFICATION='mcp-owned-connected.observed-action-v1'
SOURCE_MANIFEST='docs/modernization/drafts/mcp-owned-observed-action-rollout-source-hashes.json'
FIVE=('mcp_cmd_injection','mcp_confused_deputy','mcp_broken_authz','mcp_secret_exposure','mcp_audit_gap')
SIX=FIVE+('mcp_tool_poisoning',)
NODE=pathlib.Path.home()/'.dvaia/runtimes/node-v26.8.2-darwin-arm64/bin/node'
MANAGED=pathlib.Path.home()/'.dvaia/c231599fa8cd/mcp-owned.env'

def sha(path): return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
def private_file(path):
 st=path.lstat()
 if not path.is_file() or path.is_symlink() or st.st_uid!=os.getuid() or st.st_mode&0o077: raise RuntimeError('private input trust invalid')
 return path.read_bytes()
def parse_env(data):
 out={}
 for raw in data.decode().splitlines():
  line=raw.strip()
  if not line or line.startswith('#'): continue
  key,sep,value=line.partition('=')
  if not sep or not key.replace('_','A').isalnum(): continue
  value=value.strip()
  if value.startswith(('"',"'")):
   if value.startswith('"'): value=json.loads(value)
   elif value.endswith("'"): value=value[1:-1]
  out[key]=value
 return out
def write_private_atomic(path,data,clear_owned_pending=False):
 pending=path.with_suffix(path.suffix+'.pending')
 if clear_owned_pending:pending.unlink(missing_ok=True)
 if pending.exists():raise RuntimeError('managed configuration recovery required')
 handle=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 try:os.write(handle,data);os.fsync(handle)
 finally:os.close(handle)
 os.replace(pending,path)
 directory=os.open(path.parent,os.O_RDONLY)
 try:os.fsync(directory)
 finally:os.close(directory)

ap=argparse.ArgumentParser();ap.add_argument('--grant-file',required=True);ap.add_argument('--grant-id',required=True)
ap.add_argument('--owner-handle-file',required=True);ap.add_argument('--watcher-pid',type=int,required=True);ap.add_argument('--backend-pid',type=int,required=True)
ap.add_argument('--smoke-credentials-file',required=True);a=ap.parse_args();os.umask(0o077)
evidence=pathlib.Path(tempfile.mkdtemp(prefix='dvaia-mcp-runner-upgrade-')); ownership=evidence/'ownership.json'; result=evidence/'result.json'; diagnostics=evidence/'diagnostics.jsonl'
state={'owner':OWNER,'grantId':a.grant_id,'ownerHandle':None,'launcherPid':os.getpid(),'runStatus':'preparing','evidence':str(evidence),'cleanup':None}
signal_gate=SignalGate()
for signum in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(signum,signal_gate.handler)
def save():
 h=os.open(ownership,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
 try: os.write(h,(json.dumps(state,indent=2)+'\n').encode());os.fsync(h)
 finally: os.close(h)
def diagnostic(stage,error,stdout='',stderr=''):
 row={'stage':stage,'type':type(error).__name__,'returnCode':getattr(error,'returncode',None),'stdout':str(stdout or '')[-16384:],'stderr':str(stderr or '')[-16384:]}
 h=os.open(diagnostics,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
 try: os.write(h,(json.dumps(row,separators=(',',':'))+'\n').encode());os.fsync(h)
 finally: os.close(h)

env_bytes=private_file(ROOT/'.env'); managed_bytes=private_file(MANAGED);managed_pending=MANAGED.with_suffix(MANAGED.suffix+'.pending')
if managed_pending.exists():raise RuntimeError('managed configuration recovery required')
config=parse_env(managed_bytes)
base={k:os.environ[k] for k in ('PATH','HOME','TMPDIR') if k in os.environ};base.update(config);base['PATH']=str(NODE.parent)+os.pathsep+base.get('PATH','')
docker=['docker','--host',DOCKER_HOST]
no_redirect=urllib.request.build_opener(type('NoRedirect',(urllib.request.HTTPRedirectHandler,),{'redirect_request':lambda self,*_args:None})())
def run(cmd,timeout=90,ok=(0,),stage='command'):
 try:p=subprocess.run(cmd,cwd=ROOT,env=base,capture_output=True,text=True,timeout=timeout)
 except subprocess.TimeoutExpired as error: diagnostic(stage,error,error.stdout,error.stderr);raise RuntimeError(f'{stage} timed out') from error
 if p.returncode not in ok:
  error=subprocess.CalledProcessError(p.returncode,cmd,p.stdout,p.stderr);diagnostic(stage,error,p.stdout,p.stderr);raise RuntimeError(f'{stage} failed') from error
 return p
def inspect(name):
 p=run(docker+['inspect',name,'--format','{{json .}}'],ok=(0,1),stage='inspect');return None if p.returncode else json.loads(p.stdout)
def image_ref(name):
 p=run(docker+['image','inspect',name,'--format','{{.Id}}'],ok=(0,1),stage='image-inspect');return None if p.returncode else p.stdout.strip()
def mail_count():
 with no_redirect.open('http://127.0.0.1:8025/api/v1/messages',timeout=5) as response:return int(json.load(response)['total'])
def volume_digest():
 command="cd /sandbox/owned-targets && tar --numeric-owner -cf - . | sha256sum"
 value=run(docker+['exec',RUNNER,'/bin/sh','-ceu',command],stage='target-volume-digest').stdout.split()[0]
 if len(value)!=64:return (_ for _ in ()).throw(RuntimeError('target volume digest invalid'))
 return value
def runner_health():
 req=urllib.request.Request('http://127.0.0.1:8092/owned-targets/health',headers={'authorization':'Bearer '+config['MCP_OWNED_TARGET_TOKEN']})
 with no_redirect.open(req,timeout=8) as response:return response.status,json.load(response)
def runner_status():
 with no_redirect.open('http://127.0.0.1:8092/health',timeout=8) as response:return response.status,json.load(response)
def process_state(pid):
 p=subprocess.run(['ps','-p',str(pid),'-o','stat='],env=base,capture_output=True,text=True);return classify_process_state(p.returncode,p.stdout,probe_pid=lambda:os.kill(pid,0))
def process_cwd(pid):
 p=run(['lsof','-a','-p',str(pid),'-d','cwd','-Fn'],stage='process-cwd');paths=[x[1:] for x in p.stdout.splitlines() if x.startswith('n')]
 return str(pathlib.Path(paths[0]).resolve()) if len(paths)==1 else ''
def proc(pid):
 p=run(['ps','-p',str(pid),'-o','ppid=,stat=,command='],ok=(0,1),stage='process-identity');return p.stdout.strip() if p.returncode==0 else None
def resolve_backend(watcher,exclude):
 rows=[]
 for line in run(['ps','-axo','pid=,ppid=,stat=,command='],stage='process-list').stdout.splitlines():
  fields=line.strip().split(None,3)
  if len(fields)==4 and fields[0].isdigit() and fields[1].isdigit() and int(fields[1])==watcher and fields[3].endswith('node server/index.js'):
   rows.append({'pid':int(fields[0]),'ppid':watcher,'state':fields[2],'command':fields[3],'cwd':process_cwd(int(fields[0]))})
 return select_backend_pid(rows,watcher_pid=watcher,source=str(ROOT),excluded_pid=exclude,require_running=True)
def healthy():
 try:
  with no_redirect.open('http://127.0.0.1:8081/api/monitoring/health',timeout=3) as response:return response.status==200
 except Exception:return False
def wait_stopped(pid):
 for _ in range(100):
  state_value=process_state(pid)
  if state_value and state_value.startswith('T'):return
  time.sleep(.05)
 raise RuntimeError('owned process did not enter stopped state')
def require_drained():
 script="""const fs=require('fs'),dotenv=require('dotenv'),{Pool}=require('pg');const e=dotenv.parse(fs.readFileSync('.env'));(async()=>{const p=new Pool({connectionString:e.IDENTITY_MIGRATION_DATABASE_URL,application_name:'dvaia-owned-runner-upgrade-drain'});try{const q=await p.query(\"SELECT (SELECT count(*)::int FROM graph_runtime.runs WHERE status='running') runs,(SELECT count(*)::int FROM graph_runtime.effects WHERE status='started') effects,(SELECT count(*)::int FROM graph_runtime.codebot_requests WHERE status='started') codebot\");console.log(JSON.stringify(q.rows[0]))}finally{await p.end()}})().catch(()=>process.exit(31))"""
 values=json.loads(run([str(NODE),'-e',script],stage='durable-drain').stdout)
 if values!={'runs':0,'effects':0,'codebot':0}:raise RuntimeError('owned work has not drained')
 run(docker+['exec',RUNNER,'/bin/sh','-ceu',"find /sandbox/owned-targets -type f -name '*.lock' -exec flock -n '{}' true ';'"],stage='target-lock-drain')
def http_json(url,method='GET',body=None,token=None,opener=no_redirect):
 headers={'content-type':'application/json'}
 if token:headers['authorization']='Bearer '+token
 request=urllib.request.Request(url,data=None if body is None else json.dumps(body).encode(),headers=headers,method=method)
 try:
  with opener.open(request,timeout=10) as response:return response.status,json.load(response)
 except urllib.error.HTTPError as error:return error.code,json.load(error)
def smoke(expected_qualification,expected_objectives):
 opener=private_cookie_opener(
  type('NoRedirect',(urllib.request.HTTPRedirectHandler,),{'redirect_request':lambda self,*_args:None})())
 credentials=smoke_login_payload(json.loads(private_file(pathlib.Path(a.smoke_credentials_file).resolve())))
 status,login=http_json('http://127.0.0.1:8081/api/auth/login','POST',credentials,opener=opener)
 token=login.get('token') if isinstance(login,dict) else None
 if status!=200 or not isinstance(token,str):raise RuntimeError('authenticated smoke login failed')
 try:
  status,infra=http_json('http://127.0.0.1:8081/api/workshop/mcp/infra',token=token,opener=opener)
  qualified=infra.get('runtimeQualification',{}).get('qualifiedObjectives',[]) if isinstance(infra,dict) else []
  if status!=200 or infra.get('mode')!='real' or infra.get('runtimeQualification',{}).get('version')!=expected_qualification:raise RuntimeError('authenticated infra did not report expected qualification')
  if tuple(qualified)!=tuple(expected_objectives):raise RuntimeError('authenticated infra objective set invalid')
  progress_status,progress=http_json('http://127.0.0.1:8081/api/workshop/mcp/progress',token=token,opener=opener)
  if progress_status!=200 or not isinstance(progress,dict):raise RuntimeError('authenticated progress unavailable')
  projection={key:value for key,value in progress.items() if key!='runtimeQualification'}
  progress_digest=hashlib.sha256(json.dumps(projection,sort_keys=True,separators=(',',':')).encode()).hexdigest()
  return {'infraStatus':status,'mode':'real','qualification':expected_qualification,
    'qualifiedObjectives':list(qualified),'progressDigest':progress_digest}
 finally:
  logout_status,logout=http_json('http://127.0.0.1:8081/api/auth/logout','POST',{},token,opener=opener)
  validate_logout_result(logout_status,logout)
  revoked_status,revoked=http_json('http://127.0.0.1:8081/api/auth/status',token=token,opener=opener)
  validate_revoked_status(revoked_status,revoked)

save();grant_path=pathlib.Path(a.grant_file).resolve();handle_path=pathlib.Path(a.owner_handle_file).resolve()
if grant_path!=(ROOT/'tasks/native-verification-slot.json').resolve():raise RuntimeError('canonical grant required')
current=load_exact_source_manifest(ROOT,SOURCE_MANIFEST)
mail_before=inspect(MAILPIT);old=inspect(RUNNER)
if not mail_before or mail_before['State']['Running'] is not True or not old or old['State']['Running'] is not True:raise RuntimeError('live owned resource precondition failed')
mounts=[m for m in old['Mounts'] if m['Destination']==VOLUME_DEST]
if len(mounts)!=1 or mounts[0]['Type']!='volume' or mounts[0]['RW'] is not True:raise RuntimeError('persistent target volume precondition failed')
old_image=old['Image'];volume_name=mounts[0]['Name'];private_sha=sha(ROOT/'.env');managed_sha=sha(MANAGED);mail_identity={'id':mail_before['Id'],'image':mail_before['Image'],'count':mail_count()}
rollback_tag=f'mcp-owned-sandbox-runner:rollback-{hashlib.sha256(a.grant_id.encode()).hexdigest()[:12]}'
if image_ref(rollback_tag) is not None:raise RuntimeError('owned rollback image tag already exists')
watcher_identity=proc(a.watcher_pid)
if (not watcher_identity or 'nodemon' not in watcher_identity or process_cwd(a.watcher_pid)!=str(ROOT)
    or resolve_backend(a.watcher_pid,None)!=a.backend_pid):raise RuntimeError('application process identity changed')
print(f'WAITING_OWNER_HANDLE {handle_path}',flush=True)
for _ in range(600):
 try:owner_text=handle_path.read_text().strip()
 except FileNotFoundError:owner_text=''
 if owner_text:break
 time.sleep(.1)
state['ownerHandle']=validate_owner_handle(owner_text,consumer_pid=os.getpid());save()
with grant_path.open('r+') as f:
 fcntl.flock(f,fcntl.LOCK_EX);g=json.load(f)
 if g.get('grantId')!=a.grant_id or g.get('status')!='granted' or g.get('owner')!=OWNER or g.get('allowedLaunches')!=1 or g.get('sourceHashes')!=current:raise RuntimeError('exact runner upgrade grant unavailable')
 g.update(status='consumed',runStatus='running',consumerPid=os.getpid(),launcherPid=os.getpid(),ownerHandle=state['ownerHandle'],evidence=str(evidence),consumedAt=datetime.now(timezone.utc).isoformat());f.seek(0);json.dump(g,f,indent=2);f.write('\n');f.truncate();f.flush();os.fsync(f.fileno())
state['runStatus']='running';save();pause=RetryingPauseSet();runner_replaced=False;replacement=None;active_backend=None;managed_transition_attempted=False;rollback_pinned=False
try:
 before_smoke=smoke(QUALIFICATION,FIVE)
 run(docker+['tag',old_image,rollback_tag],stage='rollback-image-pin')
 rollback_pinned=True
 run(docker+['build','--tag',IMAGE,'sidecars/sandbox-runner'],timeout=900,stage='candidate-build')
 if proc(a.watcher_pid)!=watcher_identity or process_cwd(a.watcher_pid)!=str(ROOT):raise RuntimeError('watcher identity changed during build')
 pause.stop(a.watcher_pid,os.kill);wait_stopped(a.watcher_pid)
 active_backend=resolve_backend(a.watcher_pid,None)
 pause.stop(active_backend,os.kill);wait_stopped(active_backend)
 require_drained();volume_before=volume_digest();mail_identity['count']=mail_count()
 runner_replaced=True
 run(docker+['compose','--profile','mcp-owned','up','--no-deps','--force-recreate','--no-build','--wait','mcp-owned-sandbox'],timeout=300,stage='runner-replace')
 status,health=runner_health();runner_status_code,runner=runner_status()
 if (status!=200 or health.get('ready') is not True or health.get('isolation')!='bwrap-seccomp-v1'
     or health.get('protectedStateCapability')!=CAPABILITY
     or health.get('observedActionCapability')!=OBSERVED_CAPABILITY
     or runner_status_code!=200 or runner.get('status')!='ok'
     or runner.get('codebotAvailable') is not True or runner.get('codebotIsolation')!='bwrap-codebot-v1'):
  raise RuntimeError('runner capability readiness failed')
 if volume_digest()!=volume_before:raise RuntimeError('persistent target volume changed')
 now_mail=inspect(MAILPIT)
 if not now_mail or now_mail['Id']!=mail_identity['id'] or now_mail['Image']!=mail_identity['image'] or mail_count()!=mail_identity['count']:raise RuntimeError('Mailpit identity or learner messages changed')
 if sha(ROOT/'.env')!=private_sha or sha(MANAGED)!=managed_sha:raise RuntimeError('private configuration changed')
 activation="""const path=require('path');const {prepareOwnedManagedConfiguration}=require('./scripts/install/mcp-owned-local');prepareOwnedManagedConfiguration({envPath:path.resolve('.env'),managedPath:process.argv[1],activateQualified:true,activateObservedAction:true}).then(result=>{if(result.values.MCP_OBSERVED_ACTION_ENABLED!=='true')process.exit(41)}).catch(()=>process.exit(42))"""
 managed_transition_attempted=True
 run([str(NODE),'-e',activation,str(MANAGED)],stage='managed-observed-action-activation')
 expected_config={**config,'MCP_OBSERVED_ACTION_ENABLED':'true'}
 if parse_env(private_file(MANAGED))!=expected_config:raise RuntimeError('managed configuration transition invalid')
 managed_after_sha=sha(MANAGED)
 if pause.resume_all(os.kill):raise RuntimeError('application resume signal failed')
 os.kill(a.watcher_pid,signal.SIGHUP)
 for _ in range(180):
  try: wait_for_exit(lambda:process_state(active_backend),timeout_seconds=.1);candidate=resolve_backend(a.watcher_pid,active_backend)
  except (RuntimeError,TimeoutError):candidate=None
  if candidate and healthy():replacement=candidate;break
  time.sleep(.5)
 if replacement is None:raise RuntimeError('backend replacement unavailable')
 validate_recovery(prior_pid=active_backend,candidate_pid=replacement,healthy=healthy(),replacement_required=True)
 smoke_result=smoke(OBSERVED_QUALIFICATION,SIX)
 if smoke_result['progressDigest']!=before_smoke['progressDigest']:raise RuntimeError('instructor or learner progress projection changed')
 if volume_digest()!=volume_before or sha(ROOT/'.env')!=private_sha or sha(MANAGED)!=managed_after_sha:raise RuntimeError('post-restart preservation failed')
 final_mail=inspect(MAILPIT)
 if not final_mail or final_mail['Id']!=mail_identity['id'] or mail_count()!=mail_identity['count']:raise RuntimeError('post-restart Mailpit preservation failed')
 run(docker+['image','rm',rollback_tag],stage='rollback-pin-cleanup')
 exact_image_absent(image_ref(rollback_tag))
 summary={'oldRunnerId':old['Id'],'oldImageId':old_image,'newRunnerId':inspect(RUNNER)['Id'],'newImageId':inspect(RUNNER)['Image'],'targetVolume':volume_name,'targetVolumeSha256':volume_before,'mailpit':mail_identity,'privateEnvSha256':private_sha,'priorManagedConfigSha256':managed_sha,'managedConfigSha256':managed_after_sha,'replacementBackendPid':replacement,'runnerCapability':CAPABILITY,'observedActionCapability':OBSERVED_CAPABILITY,'codeBotIsolation':'bwrap-codebot-v1',**smoke_result}
 h=os.open(result,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 try:os.write(h,(json.dumps(summary,indent=2)+'\n').encode());os.fsync(h)
 finally:os.close(h)
 state.update(runStatus='terminal_pass',resultSha256=sha(result),summary=summary,cleanup={'rollbackImageTagRemoved':True,'rollbackImageRetention':'absent','runnerRetained':True,'mailpitPreserved':True,'targetVolumePreserved':True});save()
except BaseException as error:
 signal_gate.protect_cleanup()
 cleanup={'oldImageRestored':not runner_replaced,'serviceRestored':not runner_replaced,'mailpitPreserved':False,'targetVolumePreserved':False,'privateConfigurationPreserved':False,'applicationHealthy':False,'rollbackTagRemoved':False,'rollbackImageRetention':'not-evaluated'}
 def restore_managed():
  if managed_transition_attempted:write_private_atomic(MANAGED,managed_bytes,clear_owned_pending=True)
  return True
 def restore_image():run(docker+['tag',old_image,IMAGE],stage='rollback-image-restore');return True
 def restore_service():
  if runner_replaced:run(docker+['compose','--profile','mcp-owned','up','--no-deps','--force-recreate','--no-build','--wait','mcp-owned-sandbox'],timeout=300,stage='rollback-service')
  restored=inspect(RUNNER);cleanup['oldImageRestored']=bool(restored and restored['Image']==old_image);cleanup['serviceRestored']=bool(restored and restored['State']['Running']);return True
 def resume_owned():
  if pause.resume_all(os.kill):raise RuntimeError('application resume signal failed')
  return True
 def recover_backend():
  if runner_replaced and active_backend is not None:
   os.kill(a.watcher_pid,signal.SIGHUP);rollback_backend=None
   for _ in range(90):
    try:
     wait_for_exit(lambda:process_state(active_backend),timeout_seconds=.1)
     rollback_backend=resolve_backend(a.watcher_pid,active_backend)
    except (RuntimeError,TimeoutError):rollback_backend=None
    if rollback_backend and healthy():break
    time.sleep(.5)
   validate_recovery(prior_pid=active_backend,candidate_pid=rollback_backend,healthy=healthy(),replacement_required=True)
   cleanup['applicationHealthy']=True
  else:
   resumed=active_backend if active_backend is not None else a.backend_pid
   if proc(resumed) and process_state(resumed) and not process_state(resumed).startswith('T'):
    validate_recovery(prior_pid=resumed,candidate_pid=resumed,healthy=healthy(),replacement_required=False)
    cleanup['applicationHealthy']=True
  return True
 def verify_target():cleanup['targetVolumePreserved']=('volume_before' not in globals() or volume_digest()==volume_before);return True
 def verify_mail():
  now=inspect(MAILPIT);cleanup['mailpitPreserved']=bool(now and now['Id']==mail_identity['id'] and now['Image']==mail_identity['image'] and mail_count()==mail_identity['count']);return True
 def verify_private():cleanup['privateConfigurationPreserved']=sha(ROOT/'.env')==private_sha and sha(MANAGED)==managed_sha;return True
 def remove_rollback():
  decision=rollback_retention_decision(cleanup,rollback_pinned=rollback_pinned,image_id=image_ref(rollback_tag))
  cleanup['rollbackImageRetention']=decision['retention']
  if not decision['remove']:
   return False
  run(docker+['image','rm',rollback_tag],ok=(0,1),stage='rollback-tag-cleanup');exact_image_absent(image_ref(rollback_tag));cleanup['rollbackTagRemoved']=True;cleanup['rollbackImageRetention']='absent';return True
 _,recovery_errors=attempt_all([('restore-managed',restore_managed),('restore-image',restore_image),
  ('restore-runner',restore_service),('resume-processes',resume_owned),('recover-backend',recover_backend),
  ('verify-target-volume',verify_target),('verify-mailpit',verify_mail),('verify-private-configuration',verify_private),
  ('remove-rollback-tag',remove_rollback)])
 cleanup['errors']=recovery_errors
 state.update(runStatus='terminal_fail',failure=type(error).__name__,cleanup=cleanup);save();raise
finally:
 signal_gate.protect_cleanup()
 final_resume_errors=pause.resume_all(os.kill)
 if final_resume_errors:
  state.update(runStatus='terminal_fail',failure='application resume signal failed')
  state.setdefault('cleanup',{})['finalResumeErrors']=[{'pid':pid,'type':kind} for pid,kind in final_resume_errors];save()
 with grant_path.open('r+') as f:
  fcntl.flock(f,fcntl.LOCK_EX);g=json.load(f)
  validate_terminal_grant(g,grant_id=a.grant_id,owner=OWNER,owner_handle=state['ownerHandle'],consumer_pid=os.getpid())
  g.update(runStatus=state['runStatus'],evidence=str(evidence),resultSha256=state.get('resultSha256'),cleanup=state.get('cleanup'),completedAt=datetime.now(timezone.utc).isoformat());f.seek(0);json.dump(g,f,indent=2);f.write('\n');f.truncate();f.flush();os.fsync(f.fileno())
print(evidence)
