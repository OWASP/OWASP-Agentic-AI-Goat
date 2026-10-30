#!/usr/bin/env python3
"""One-use local MCP/CodeBot activation; preserves Mailpit and private .env."""
import argparse, fcntl, hashlib, json, os, pathlib, signal, subprocess, tempfile, time, urllib.request
from datetime import datetime, timezone
from mcp_owned_live_promotion_safety import select_backend_pid
from sensitive_info_recovery_safety import classify_process_state, wait_for_exit

ROOT=pathlib.Path(__file__).resolve().parents[2]; OWNER='/root/workshop_authenticity'
DOCKER_HOST='unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock'; PROFILE='colima-owasp-ai-goat-pg-verify'
MAILPIT='OWASP Agentic AI GOAT-mailpit-1'; RUNNER='OWASP Agentic AI GOAT-mcp-owned-sandbox-1'
IMAGE='mcp-owned-sandbox-runner:dev'; NODE=pathlib.Path.home()/'.owasp-ai-goat/runtimes/node-v26.8.2-darwin-arm64/bin/node'
ap=argparse.ArgumentParser(); ap.add_argument('--grant-file',required=True);ap.add_argument('--grant-id',required=True)
ap.add_argument('--owner-handle-file',required=True);ap.add_argument('--watcher-pid',type=int,required=True);ap.add_argument('--backend-pid',type=int,required=True)
a=ap.parse_args();os.umask(0o077);docker=['docker','--host',DOCKER_HOST]
base={k:os.environ[k] for k in ('PATH','HOME','TMPDIR') if k in os.environ};base['PATH']=str(NODE.parent)+os.pathsep+base.get('PATH','')
evidence=pathlib.Path(tempfile.mkdtemp(prefix='owasp-ai-goat-mcp-owned-activation-'));ownership=evidence/'ownership.json';result=evidence/'result.json'
diagnostics=evidence/'command-diagnostics.jsonl'
state={'owner':OWNER,'grantId':a.grant_id,'launcherPid':os.getpid(),'ownerHandle':None,'evidence':str(evidence),'runStatus':'preparing','cleanup':None}
def save():
 h=os.open(ownership,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
 try:os.write(h,(json.dumps(state,indent=2)+'\n').encode());os.fsync(h)
 finally:os.close(h)
def record_diagnostic(stage,error,stdout='',stderr=''):
 row={'stage':stage,'type':type(error).__name__,'returnCode':getattr(error,'returncode',None),
      'stdout':str(stdout or '')[-16384:],'stderr':str(stderr or '')[-16384:]}
 h=os.open(diagnostics,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
 try:os.write(h,(json.dumps(row,separators=(',',':'))+'\n').encode());os.fsync(h)
 finally:os.close(h)
def run(cmd,timeout=90,ok=(0,),stage=None):
 stage=stage or pathlib.Path(cmd[0]).name
 try:p=subprocess.run(cmd,cwd=ROOT,env=base,capture_output=True,text=True,timeout=timeout)
 except subprocess.TimeoutExpired as error:
  record_diagnostic(stage,error,error.stdout,error.stderr);raise RuntimeError('controlled command timed out') from error
 if p.returncode not in ok:
  error=subprocess.CalledProcessError(p.returncode,cmd,p.stdout,p.stderr);record_diagnostic(stage,error,p.stdout,p.stderr)
  raise RuntimeError('controlled command failed') from error
 return p
def inspect(name):
 p=run(docker+['inspect',name,'--format','{{json .}}'],ok=(0,1));return None if p.returncode else json.loads(p.stdout)
def image_id():
 p=run(docker+['image','inspect',IMAGE,'--format','{{.Id}}'],ok=(0,1));return None if p.returncode else p.stdout.strip()
def mail_count():
 with urllib.request.urlopen('http://127.0.0.1:8025/api/v1/messages',timeout=5) as response:
  value=json.load(response);return int(value['total'])
def process_state(pid):
 p=subprocess.run(['ps','-p',str(pid),'-o','stat='],env=base,capture_output=True,text=True)
 return classify_process_state(p.returncode,p.stdout,probe_pid=lambda:os.kill(pid,0))
def process_cwd(pid):
 p=run(['lsof','-a','-p',str(pid),'-d','cwd','-Fn'],stage='process-cwd');paths=[x[1:] for x in p.stdout.splitlines() if x.startswith('n')]
 return str(pathlib.Path(paths[0]).resolve()) if len(paths)==1 else ''
def proc(pid):
 p=run(['ps','-p',str(pid),'-o','ppid=,stat=,command='],ok=(0,1),stage='process-identity');return p.stdout.strip() if p.returncode==0 else None
def resolve_backend(watcher,exclude):
 rows=[]
 for line in run(['ps','-axo','pid=,ppid=,stat=,command='],stage='process-list').stdout.splitlines():
  fields=line.strip().split(None,3)
  if len(fields)!=4:continue
  pid,ppid,state,command=fields
  if ppid.isdigit() and int(ppid)==watcher and pid.isdigit() and command.endswith('node server/index.js'):
   rows.append({'pid':int(pid),'ppid':int(ppid),'state':state,'command':command,'cwd':process_cwd(int(pid))})
 return select_backend_pid(rows,watcher_pid=watcher,source=str(ROOT),excluded_pid=exclude,require_running=True)
def healthy():
 try:
  with urllib.request.urlopen('http://127.0.0.1:8081/api/monitoring/health',timeout=3) as r:return r.status==200
 except Exception:return False
def sha(file):return hashlib.sha256(pathlib.Path(file).read_bytes()).hexdigest()
save();grant_path=pathlib.Path(a.grant_file).resolve();handle_path=pathlib.Path(a.owner_handle_file).resolve()
if grant_path!=(ROOT/'tasks/native-verification-slot.json').resolve():raise RuntimeError('canonical grant required')
manifest=json.loads((ROOT/'docs/modernization/drafts/mcp-owned-local-activation-source-hashes.json').read_text())
current={name:sha(ROOT/name) for name in manifest['sourceHashes']}
if current!=manifest['sourceHashes']:raise RuntimeError('activation source changed')
private_sha=sha(ROOT/'.env');mail_before=inspect(MAILPIT);runner_before=inspect(RUNNER);image_before=image_id()
if not mail_before or mail_before['State']['Running'] is not True or runner_before is not None:raise RuntimeError('activation resource precondition failed')
mail_identity={'id':mail_before['Id'],'image':mail_before['Image'],'count':mail_count()}
watch=proc(a.watcher_pid);backend=proc(a.backend_pid)
if not watch or 'nodemon' not in watch or not backend or not backend.startswith(f'{a.watcher_pid} ') or not backend.endswith('node server/index.js'):raise RuntimeError('application process identity changed')
print(f'WAITING_OWNER_HANDLE {handle_path}',flush=True)
for _ in range(600):
 try:owner_text=handle_path.read_text().strip()
 except FileNotFoundError:owner_text=''
 if owner_text:break
 time.sleep(.1)
if not owner_text.isdecimal() or int(owner_text)<=0:raise RuntimeError('actual owner handle unavailable')
state['ownerHandle']=int(owner_text);save()
with grant_path.open('r+') as f:
 fcntl.flock(f,fcntl.LOCK_EX);g=json.load(f)
 if g.get('grantId')!=a.grant_id or g.get('status')!='granted' or g.get('owner')!=OWNER or g.get('allowedLaunches')!=1 or g.get('sourceHashes')!=current:raise RuntimeError('exact activation grant unavailable')
 g.update(status='consumed',consumerPid=os.getpid(),launcherPid=os.getpid(),ownerHandle=state['ownerHandle'],evidence=str(evidence),consumedAt=datetime.now(timezone.utc).isoformat());f.seek(0);json.dump(g,f,indent=2);f.write('\n');f.truncate();f.flush();os.fsync(f.fileno())
created_runner=False;created_image=False
try:
 command=[str(NODE),'scripts/install/mcp-owned-provision.js','--env',str(ROOT/'.env'),'--managed-config',str(pathlib.Path.home()/'.owasp-ai-goat/c231599fa8cd/mcp-owned.env'),'--colima-profile',PROFILE,'--activate-qualified']
 run(command,timeout=900,stage='owned-provision');created_runner=runner_before is None and inspect(RUNNER) is not None;created_image=image_before is None and image_id() is not None
 after_mail=inspect(MAILPIT)
 if not after_mail or after_mail['Id']!=mail_identity['id'] or after_mail['Image']!=mail_identity['image'] or mail_count()!=mail_identity['count']:raise RuntimeError('Mailpit identity or learner messages changed')
 if sha(ROOT/'.env')!=private_sha:raise RuntimeError('private environment changed')
 os.kill(a.watcher_pid,signal.SIGHUP)
 replacement=None
 for _ in range(120):
  try:
   exited=wait_for_exit(lambda:process_state(a.backend_pid),timeout_seconds=.1)
   candidate=resolve_backend(a.watcher_pid,a.backend_pid)
  except (RuntimeError,TimeoutError):candidate=None
  if candidate and healthy():replacement=candidate;break
  time.sleep(.5)
 if replacement is None or not proc(replacement).endswith('node server/index.js'):raise RuntimeError('activated backend replacement unavailable')
 summary={'mailpit':mail_identity,'runnerId':inspect(RUNNER)['Id'],'runnerImage':image_id(),'privateEnvSha256':private_sha,'replacementBackendPid':replacement,'health200':True,'activationEnabled':True}
 h=os.open(result,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 try:os.write(h,(json.dumps(summary,indent=2)+'\n').encode());os.fsync(h)
 finally:os.close(h)
 state.update(runStatus='terminal_pass',resultSha256=sha(result),summary=summary,
  cleanup={'runnerRetainedForActivation':True,'mailpitPreserved':True});save()
except BaseException as error:
 cleanup={'managedDisabled':False,'runnerRemoved':False,'imageRemoved':False,'mailpitPreserved':False,'healthyAfterRollback':False}
 try:
  code="const p=require('./scripts/install/mcp-owned-local');p.prepareOwnedManagedConfiguration({envPath:process.argv[1],managedPath:process.argv[2],forceDisabled:true}).catch(()=>process.exit(1))"
  run([str(NODE),'-e',code,str(ROOT/'.env'),str(pathlib.Path.home()/'.owasp-ai-goat/c231599fa8cd/mcp-owned.env')])
  cleanup['managedDisabled']=True
 except Exception:pass
 created_runner=runner_before is None and inspect(RUNNER) is not None
 created_image=image_before is None and image_id() is not None
 if created_runner:
  try:run(docker+['rm','--force',RUNNER]);cleanup['runnerRemoved']=inspect(RUNNER) is None
  except Exception:pass
 if created_image:
  try:run(docker+['image','rm',IMAGE]);cleanup['imageRemoved']=image_id() is None
  except Exception:pass
 now=inspect(MAILPIT);cleanup['mailpitPreserved']=bool(now and now['Id']==mail_identity['id'] and now['Image']==mail_identity['image'])
 try:
  os.kill(a.watcher_pid,signal.SIGHUP)
  for _ in range(60):
   if healthy():cleanup['healthyAfterRollback']=True;break
   time.sleep(.5)
 except Exception:pass
 state.update(runStatus='terminal_fail',failure=type(error).__name__,cleanup=cleanup);save();raise
finally:
 with grant_path.open('r+') as f:
  fcntl.flock(f,fcntl.LOCK_EX);g=json.load(f);g.update(runStatus=state['runStatus'],evidence=str(evidence),resultSha256=state.get('resultSha256'),cleanup=state.get('cleanup'),completedAt=datetime.now(timezone.utc).isoformat());f.seek(0);json.dump(g,f,indent=2);f.write('\n');f.truncate();f.flush();os.fsync(f.fileno())
print(evidence)
