#!/usr/bin/env python3
"""Restore the retained identity backup and run only the catalog seed audit."""
import argparse, fcntl, hashlib, json, os, signal, stat, subprocess, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from sensitive_info_recovery_safety import SignalGate, protected_cleanup

ROOT=Path(__file__).resolve().parents[2]
OWNER='/root/workshop_authenticity'
DOCKER_HOST='unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock'
NODE=Path('/Users/averma5/.owasp-ai-goat/runtimes/node-v26.8.2-darwin-arm64/bin/node')
os.umask(0o077)
p=argparse.ArgumentParser();p.add_argument('--docker-host',required=True);p.add_argument('--grant-file',required=True)
p.add_argument('--grant-id',required=True);p.add_argument('--source-manifest',required=True);p.add_argument('--identity-dump',required=True)
a=p.parse_args()
if a.docker_host!=DOCKER_HOST: raise SystemExit('reviewed isolated Docker daemon required')
docker=['docker','--host',a.docker_host];grant_path=Path(a.grant_file).resolve();dump=Path(a.identity_dump).resolve()
base_env={'PATH':f'{NODE.parent}:{Path.home()}/.local/bin:{Path.home()}/.rd/bin:/usr/local/bin:/usr/bin:/bin',
 'HOME':str(Path.home()),'TMPDIR':os.environ.get('TMPDIR','/tmp'),'LANG':'C'}
manifest_path=Path(a.source_manifest).resolve(); evidence=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-mcp-seed-restore-'))
os.chmod(evidence,0o700); ownership=evidence/'ownership.json'; result=evidence/'result.log'
container=f'owasp-ai-goat-mcp-seed-restore-{uuid.uuid4().hex[:12]}'
state={'owner':OWNER,'grantId':a.grant_id,'ownerHandle':None,'launcherPid':os.getpid(),'container':container,
 'dockerHost':a.docker_host,'evidence':str(evidence),'runStatus':'preparing','cleanup':None}
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def save():
 with ownership.open('w') as f: json.dump(state,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
 os.chmod(ownership,0o600)
def run(cmd,**kw): return subprocess.run(cmd,check=True,env=kw.pop('env',base_env),
 stdout=kw.pop('stdout',subprocess.PIPE),stderr=subprocess.PIPE,**kw)
def private_failure(error):
 payload={'type':type(error).__name__,'returnCode':getattr(error,'returncode',None)}
 text=getattr(error,'stderr','') or ''
 if isinstance(text,bytes): text=text.decode('utf-8','replace')
 text=text[-262144:]; payload['stderr']=text
 path=evidence/'private-error.json'
 with path.open('x') as f: json.dump(payload,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
 os.chmod(path,0o600);state['privateError']={'sha256':sha(path),'bytes':path.stat().st_size}

if not dump.is_file() or dump.is_symlink() or stat.S_IMODE(dump.stat().st_mode)&0o077: raise SystemExit('private retained dump invalid')
manifest=json.loads(manifest_path.read_text()); sources=manifest.get('sourceHashes')
if not isinstance(sources,dict) or not sources: raise SystemExit('source manifest invalid')
observed={name:sha(ROOT/name) for name in sources}
if observed!=sources: raise SystemExit('source manifest differs from current files')
manifest_sha=sha(manifest_path);dump_sha=sha(dump);state.update({'sourceManifestSha256':manifest_sha,
 'sourceHashes':sources,'identityDumpSha256':dump_sha});save()

with grant_path.open('r+') as f:
 fcntl.flock(f.fileno(),fcntl.LOCK_EX);g=json.load(f)
 if (g.get('grantId')!=a.grant_id or g.get('owner')!=OWNER or g.get('status')!='granted'
   or g.get('allowedLaunches')!=1 or g.get('dockerHost')!=DOCKER_HOST or g.get('sourceHashes')!=sources
   or g.get('sourceManifestSha256')!=manifest_sha or g.get('identityDumpSha256')!=dump_sha):
  raise RuntimeError('restore-only grant absent, mismatched, or consumed')
 g.update({'status':'consumed','consumedAt':datetime.now(timezone.utc).isoformat(),'launcherPid':os.getpid(),
  'ownerHandle':None,'container':container,'evidence':str(evidence),'runStatus':'preparing'})
 f.seek(0);json.dump(g,f,indent=2);f.write('\n');f.truncate();f.flush();os.fsync(f.fileno())
for _ in range(600):
 with grant_path.open() as f: fcntl.flock(f.fileno(),fcntl.LOCK_SH);g=json.load(f)
 handle=g.get('ownerHandle')
 if g.get('launcherPid')==os.getpid() and isinstance(handle,int) and handle>0 and handle!=os.getpid():
  state['ownerHandle']=handle;state['runStatus']='owner_registered';save();break
 time.sleep(.1)
else: raise RuntimeError('actual exec owner handle not registered')

signal_gate=SignalGate()
for handled in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP): signal.signal(handled,signal_gate.handler)
creation_attempted=False
try:
 creation_attempted=True;state['containerCreationAttempted']=True;save()
 run(docker+['run','--detach','--name',container,'--tmpfs','/var/lib/postgresql:rw,size=536870912',
  '-e','POSTGRES_USER=reset_restore_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust',
  '-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432','postgres:18',
  '-c','shared_buffers=16MB','-c','max_connections=24','-c','max_wal_size=32MB','-c','min_wal_size=4MB'],
  timeout=120)
 state['runStatus']='container_started';save();port=None
 for _ in range(120):
  detail=json.loads(run(docker+['inspect',container],text=True).stdout)[0]
  bindings=detail.get('NetworkSettings',{}).get('Ports',{}).get('5432/tcp')
  if bindings: port=bindings[0]['HostPort']
  if port and subprocess.run(['pg_isready','-h','127.0.0.1','-p',port,'-U','reset_restore_admin'],env=base_env,
    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0: break
  time.sleep(.25)
 else: raise RuntimeError('owned PostgreSQL did not become ready')
 env={**base_env,'PGHOST':'127.0.0.1','PGPORT':port,'PGUSER':'reset_restore_admin','PGDATABASE':'postgres'}
 run(['psql','-X','-v','ON_ERROR_STOP=1','-c','CREATE ROLE dvaia_identity_migration LOGIN; CREATE ROLE dvaia_identity_runtime LOGIN'],env=env)
 run(['psql','-X','-v','ON_ERROR_STOP=1','-c','CREATE DATABASE owasp_ai_goat_seed_restore OWNER dvaia_identity_migration'],env=env)
 env['PGDATABASE']='owasp_ai_goat_seed_restore';run(['pg_restore','--exit-on-error','--dbname','owasp_ai_goat_seed_restore',str(dump)],env=env,timeout=180)
 url=f'postgresql://dvaia_identity_migration@127.0.0.1:{port}/owasp_ai_goat_seed_restore'
 try: completed=run([str(NODE),'scripts/audit-mcp-promotion-seed-transition.js',url],cwd=ROOT,text=True,timeout=180)
 except (subprocess.CalledProcessError,subprocess.TimeoutExpired) as error: private_failure(error);raise
 markers=[x.removeprefix('MCP_SEED_TRANSITION=') for x in completed.stdout.splitlines() if x.startswith('MCP_SEED_TRANSITION=')]
 if len(markers)!=1: raise RuntimeError('seed audit marker invalid')
 audit=json.loads(markers[0]);state['audit']=audit;state['runStatus']='passed';result.write_text(json.dumps(audit,sort_keys=True)+'\n');os.chmod(result,0o600)
except Exception as error:
 state['runStatus']='failed';state['errorType']=type(error).__name__
 if 'privateError' not in state: private_failure(error)
finally:
 signal_gate.protect_cleanup()
 def remove_container():
  return subprocess.run(docker+['rm','-f',container],env=base_env,
   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30).returncode
 def exact_absence():
  query=subprocess.run(docker+['ps','-a','--filter',f'name=^/{container}$','--format','{{.Names}}'],
   env=base_env,capture_output=True,text=True,timeout=30)
  if query.returncode!=0: raise RuntimeError('exact container query failed')
  return query.stdout.strip()==''
 cleanup=protected_cleanup(started=creation_attempted,paused=False,remove_container=remove_container,
  exact_absence=exact_absence,resume_watcher=lambda:True,health_check=lambda:True)
 cleanup.update({'containerCreationAttempted':creation_attempted,'signals':signal_gate.received,
  'completedAt':datetime.now(timezone.utc).isoformat()});state['cleanup']=cleanup
 if (cleanup['errors'] or cleanup['containerAbsent'] is not True) and state['runStatus']=='passed':
  state['runStatus']='failed';state['errorType']='CleanupFailed'
 save()
 with grant_path.open('r+') as f:
  fcntl.flock(f.fileno(),fcntl.LOCK_EX);g=json.load(f)
  if g.get('grantId')==a.grant_id and g.get('launcherPid')==os.getpid():
   g.update({'runStatus':state['runStatus'],'terminalAt':datetime.now(timezone.utc).isoformat(),
    'cleanup':state['cleanup'],'evidence':str(evidence)})
   f.seek(0);json.dump(g,f,indent=2);f.write('\n');f.truncate();f.flush();os.fsync(f.fileno())
if state['runStatus']!='passed': raise RuntimeError('restore-only seed transition qualification failed')
print(evidence)
