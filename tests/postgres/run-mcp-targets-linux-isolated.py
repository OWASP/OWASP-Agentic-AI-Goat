#!/usr/bin/env python3
"""One-use native Linux qualification for the default-off MCP target primitive."""

import argparse, hashlib, json, os, re, shutil, subprocess, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path

parser=argparse.ArgumentParser()
parser.add_argument('--docker-host',required=True);parser.add_argument('--grant-id',required=True)
parser.add_argument('--grant-file',default='tasks/native-verification-slot.json')
parser.add_argument('--owner-handle');parser.add_argument('--owner-handle-file')
args=parser.parse_args();source=Path(__file__).resolve().parents[2]
if bool(args.owner_handle)==bool(args.owner_handle_file): raise SystemExit('supply exactly one owner handle or handshake file')
if args.owner_handle_file:
 handshake=Path(args.owner_handle_file).resolve();print(f'WAITING_OWNER_HANDLE {handshake}',flush=True)
 deadline=time.monotonic()+60
 while time.monotonic()<deadline:
  try:
   supplied=handshake.read_text().strip()
   if supplied: break
  except FileNotFoundError: pass
  time.sleep(.1)
 else: raise SystemExit('owner handle handshake timed out')
else: supplied=args.owner_handle
if not supplied.isdecimal() or int(supplied)<=0: raise SystemExit('owner handle must be the positive exec session ID')
owner_handle=int(supplied)
grant_path=(source/args.grant_file).resolve() if not Path(args.grant_file).is_absolute() else Path(args.grant_file)
grant_lock=grant_path.with_suffix(grant_path.suffix+'.consume-lock')
# Keep retained evidence outside the repository. Test input reaches the owned
# container through `docker cp`, so qualification does not depend on any host
# directory being mounted into the Colima VM.
evidence_parent=Path.home()/'.owasp-ai-goat'/'native-verification';evidence_parent.mkdir(parents=True,exist_ok=True);os.chmod(evidence_parent,0o700)
root=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-mcp-targets-linux-',dir=evidence_parent));os.chmod(root,0o700)
workspace=root/'source';workspace.mkdir();sidecar=workspace/'sidecars/sandbox-runner';sidecar.mkdir(parents=True)
for name in ['Dockerfile','package.json','index.js','entrypoint.sh','mcpTargets.js','mcpSeccompFilter.c','mcpSeccompProbe.c']:
    shutil.copy2(source/'sidecars/sandbox-runner'/name,sidecar/name)
shutil.copytree(source/'sidecars/sandbox-runner/labfs',sidecar/'labfs')
for name in ['rogue-mcp','ssrf-target']: shutil.copytree(source/'sidecars'/name,workspace/'sidecars'/name)
tests=workspace/'tests';tests.mkdir();shutil.copy2(source/'tests/mcpTargetsLinux.integration.test.js',tests/'mcpTargetsLinux.integration.test.js')
fixtures=tests/'fixtures';fixtures.mkdir();shutil.copy2(source/'tests/fixtures/mcpTargetStopProbe.js',fixtures/'mcpTargetStopProbe.js')
base_env={k:os.environ[k] for k in ['PATH','HOME','TMPDIR'] if k in os.environ}
managed=Path(base_env.get('HOME','/none'))/'.owasp-ai-goat/runtimes/node-v26.8.2-darwin-arm64/bin';base_env['PATH']=str(managed)+os.pathsep+base_env.get('PATH','')
docker=['docker','--host',args.docker_host];suffix=uuid.uuid4().hex[:12]
profile_name='owasp-ai-goat-mcp-sandbox-'+suffix
profile_template=source/'sidecars/sandbox-runner/apparmor/owasp-ai-goat-mcp-sandbox.apparmor.in'
profile_path=root/f'{profile_name}.apparmor'
renderer=source/'scripts/render-mcp-sandbox-apparmor.js'
subprocess.run([str(managed/'node'),str(renderer),str(profile_template.resolve()),str(profile_path.resolve()),profile_name],check=True,env=base_env)
ssh_config=Path.home()/'.colima/_lima/colima-owasp-ai-goat-pg-verify/ssh.config'
ssh_host='lima-colima-owasp-ai-goat-pg-verify';remote_dir=f'/tmp/{profile_name}';remote_profile=f'{remote_dir}/policy.apparmor';remote_marker=f'{remote_dir}/owner'
remote_owner=uuid.uuid4().hex+uuid.uuid4().hex
local_marker=root/'remote-owner';local_marker.write_text(remote_owner);os.chmod(local_marker,0o600)
ssh=['ssh','-F',str(ssh_config),ssh_host,'--'];scp=['scp','-F',str(ssh_config)]
containers={
 'sandbox-runner':'owasp-ai-goat-mcp-targets-linux-'+suffix,
 'sandbox-stop':'owasp-ai-goat-mcp-targets-stop-'+suffix,
 'rogue-mcp':'owasp-ai-goat-mcp-rogue-smoke-'+suffix,
 'ssrf-target':'owasp-ai-goat-mcp-ssrf-smoke-'+suffix,
}
container=containers['sandbox-runner']
images={name:f'owasp-ai-goat-mcp-{name}-node26:{suffix}' for name in ['sandbox-runner','rogue-mcp','ssrf-target']};image=images['sandbox-runner']
ownership_path=root/'ownership.json'
tracked=['sidecars/sandbox-runner/Dockerfile','sidecars/rogue-mcp/Dockerfile','sidecars/ssrf-target/Dockerfile',
 'sidecars/sandbox-runner/mcpTargets.js','sidecars/sandbox-runner/mcpSeccompFilter.c','sidecars/sandbox-runner/mcpSeccompProbe.c',
 'sidecars/sandbox-runner/apparmor/owasp-ai-goat-mcp-sandbox.apparmor.in',
 'scripts/render-mcp-sandbox-apparmor.js','tests/mcpTargetsLinux.integration.test.js','tests/fixtures/mcpTargetStopProbe.js',
 'tests/postgres/run-mcp-targets-linux-isolated.py']
digest=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
def public_error(error):
 # Build logs remain in the mode-0700 evidence directory. Never copy signed
 # registry query strings into the ownership/grant summaries that are shared.
 return re.sub(r'(https?://[^\s?]+)\?[^\s]+',r'\1?[redacted]',str(error))
ownership={'version':1,'owner':'/root/workshop_authenticity','launcherPid':os.getpid(),'ownerHandle':owner_handle,
 'workspace':str(root),'container':container,'containers':containers,'images':images,'dockerHost':args.docker_host,'grantId':args.grant_id,
 'grantFile':str(grant_path),'status':'prepared','startedAt':datetime.now(timezone.utc).isoformat(),
 'apparmor':{'profileName':profile_name,'remoteDirectory':remote_dir,'remotePolicy':remote_profile,
  'remoteOwnerSha256':hashlib.sha256(remote_owner.encode()).hexdigest(),'loaded':False},
 'sourceSha256':{name:digest(source/name) for name in tracked},
 'runtime':{'hostNodeTarget':'26.8.2','containerBase':'docker.io/library/node:26.8.2-slim'},'cleanup':None}
def persist():
 p=ownership_path.with_suffix('.json.pending');p.write_text(json.dumps(ownership,sort_keys=True)+'\n');os.replace(p,ownership_path)
persist()
try: grant_lock.mkdir(mode=0o700)
except FileExistsError as error: raise RuntimeError('Native verification grant is already being consumed') from error
try:
 grant=json.loads(grant_path.read_text())
 if grant.get('grantId')!=args.grant_id or grant.get('status')!='granted' or grant.get('owner')!='/root/workshop_authenticity' or grant.get('allowedLaunches')!=1 or grant.get('dockerHost')!=args.docker_host:
  raise RuntimeError('Exact unconsumed native verification grant is required')
 grant.update(status='consumed',runStatus='running',consumedAt=datetime.now(timezone.utc).isoformat(),consumerPid=os.getpid(),
  launcherPid=os.getpid(),ownerHandle=owner_handle,evidence=str(root),container=container,containers=containers,images=images)
 pending=grant_path.with_suffix(grant_path.suffix+'.pending');pending.write_text(json.dumps(grant,indent=2,sort_keys=True)+'\n');os.replace(pending,grant_path)
 ownership.update(status='grant_consumed',grantConsumedAt=grant['consumedAt']);persist()
finally: grant_lock.rmdir()
def run(command,**kwargs): kwargs.setdefault('timeout',180);return subprocess.run(command,check=True,env=base_env,**kwargs)
started_containers=[];built_images=[];remote_creation_attempted=False;remote_dir_owned=False;profile_copied=False;profile_load_attempted=False;profile_loaded=False
try:
 daemon=json.loads(run(docker+['info','--format','{{json .}}'],capture_output=True,text=True,timeout=30).stdout)
 if daemon.get('Name')!='colima-owasp-ai-goat-pg-verify' or daemon.get('Architecture')!='aarch64':
  raise RuntimeError('Exact Colima verification daemon identity is required')
 if not ssh_config.is_file(): raise RuntimeError('Exact Colima verification SSH config is required')
 prior_profile=subprocess.run(ssh+['sudo','grep','-F',profile_name,'/sys/kernel/security/apparmor/profiles'],env=base_env,capture_output=True,text=True,timeout=20)
 if prior_profile.returncode!=1 or prior_profile.stdout.strip(): raise RuntimeError('Unique AppArmor profile name was not absent before load')
 remote_dir_prior=subprocess.run(ssh+['test','!','-e',remote_dir],env=base_env,timeout=20)
 if remote_dir_prior.returncode!=0: raise RuntimeError('Unique remote AppArmor directory was not absent before creation')
 remote_creation_attempted=True;ownership['apparmor']['remoteCreationAttempted']=True;persist()
 run(ssh+['mkdir','-m','0700','--',remote_dir],timeout=20)
 run(scp+[str(local_marker),f'{ssh_host}:{remote_marker}'],timeout=20)
 marker_value=run(ssh+['cat','--',remote_marker],capture_output=True,text=True,timeout=20).stdout
 if marker_value!=remote_owner: raise RuntimeError('Owned remote AppArmor directory marker mismatch')
 remote_dir_owned=True;ownership['apparmor']['remoteOwnershipVerified']=True;persist()
 remote_prior=subprocess.run(ssh+['test','!','-e',remote_profile],env=base_env,timeout=20)
 if remote_prior.returncode!=0: raise RuntimeError('Owned remote AppArmor policy path was not absent')
 run(scp+[str(profile_path),f'{ssh_host}:{remote_profile}'],timeout=30);profile_copied=True
 run(ssh+['chmod','0600',remote_profile],timeout=20)
 run(ssh+['sudo','apparmor_parser','--skip-kernel-load',remote_profile],timeout=30)
 profile_load_attempted=True;ownership['apparmor']['loadAttempted']=True;persist()
 run(ssh+['sudo','apparmor_parser','-r',remote_profile],timeout=30);profile_loaded=True
 present=run(ssh+['sudo','grep','-F',profile_name,'/sys/kernel/security/apparmor/profiles'],capture_output=True,text=True,timeout=20).stdout
 if profile_name not in present: raise RuntimeError('Owned AppArmor profile was not loaded')
 ownership['apparmor'].update(loaded=True,loadVerified=True);persist()
 ownership['status']='image_building';persist()
 ownership['imageIds']={};ownership['buildSha256']={}
 for name,tag in images.items():
  build_log=root/f'{name}-build.log'
  with build_log.open('w') as log: run(docker+['build','--tag',tag,str(workspace/'sidecars'/name)],stdout=log,stderr=subprocess.STDOUT,timeout=600)
  built_images.append(tag);ownership['imageIds'][name]=run(docker+['image','inspect','--format','{{.Id}}',tag],capture_output=True,text=True).stdout.strip()
  ownership['buildSha256'][name]=digest(build_log);persist()
 ownership['status']='images_built';persist()
 ownership['containerIds']={};ownership['processVersions']={};ownership['smokeSha256']={}
 for name,port in [('rogue-mcp',8091),('ssrf-target',9099)]:
  smoke_container=containers[name]
  run(docker+['run','--detach','--name',smoke_container,images[name]],stdout=subprocess.DEVNULL)
  started_containers.append(smoke_container)
  ownership['containerIds'][name]=run(docker+['inspect','--format','{{.Id}}',smoke_container],capture_output=True,text=True).stdout.strip();persist()
  version=run(docker+['exec',smoke_container,'node','-p','process.version'],capture_output=True,text=True,timeout=20).stdout.strip()
  if version!='v26.8.2': raise RuntimeError(f'{name} reported unexpected Node version {version!r}')
  ownership['processVersions'][name]=version
  deadline=time.monotonic()+15
  while time.monotonic()<deadline:
   probe=subprocess.run(docker+['exec',smoke_container,'node','-e',f"fetch('http://127.0.0.1:{port}/health').then(r=>{{if(!r.ok)process.exit(2);return r.text()}}).then(x=>console.log(x)).catch(()=>process.exit(3))"],env=base_env,capture_output=True,text=True,timeout=5)
   if probe.returncode==0: break
   time.sleep(.2)
  else: raise RuntimeError(f'{name} did not pass its owned HTTP smoke probe')
  smoke_log=root/f'{name}-smoke.log';smoke_log.write_text(probe.stdout+run(docker+['logs',smoke_container],capture_output=True,text=True,timeout=20).stdout)
  ownership['smokeSha256'][name]=digest(smoke_log);persist()
 command="groupadd -g 10001 sandbox 2>/dev/null || true; useradd -u 10001 -g 10001 -M -s /bin/bash sandbox 2>/dev/null || true; mkdir -p /owned /qualification; chown -R 10001:10001 /owned /qualification; exec sleep infinity"
 run(docker+['run','--detach','--name',container,'--security-opt','seccomp=unconfined','--security-opt',f'apparmor={profile_name}','--tmpfs','/owned:rw,uid=10001,gid=10001,mode=0700',
  '--entrypoint','/bin/bash',image,'-lc',command],stdout=subprocess.DEVNULL)
 started_containers.append(container);ownership['status']='container_started';persist()
 ownership['containerId']=run(docker+['inspect','--format','{{.Id}}',container],capture_output=True,text=True).stdout.strip()
 ownership['containerIds']['sandbox-runner']=ownership['containerId'];persist()
 version=run(docker+['exec',container,'node','-p','process.version'],capture_output=True,text=True,timeout=20).stdout.strip()
 if version!='v26.8.2': raise RuntimeError(f'sandbox-runner reported unexpected Node version {version!r}')
 ownership['processVersions']['sandbox-runner']=version;persist()
 parent_label=run(docker+['exec','--user','10001:10001',container,'cat','/proc/self/attr/current'],capture_output=True,text=True,timeout=20).stdout.strip()
 if profile_name not in parent_label or '//bwrap' in parent_label: raise RuntimeError(f'unexpected supervisor AppArmor label {parent_label!r}')
 audit_since=int(time.time())
 direct_userns=subprocess.run(docker+['exec','--user','10001:10001',container,'/usr/bin/unshare','--user','--map-root-user','/bin/true'],env=base_env,capture_output=True,text=True,timeout=20)
 direct_log=root/'supervisor-userns-negative.log';direct_log.write_text(direct_userns.stdout+direct_userns.stderr)
 if direct_userns.returncode==0: raise RuntimeError('Node supervisor profile unexpectedly admitted direct userns creation')
 audit=run(ssh+['sudo','journalctl','-k','--since',f'@{audit_since}','--no-pager','-o','cat'],capture_output=True,text=True,timeout=30).stdout
 audit_log=root/'supervisor-userns-audit.log';audit_log.write_text(audit)
 denial_fragments=['apparmor="DENIED"','operation="userns_create"',f'profile="{profile_name}"','comm="unshare"']
 matching_denials=[line for line in audit.splitlines() if all(fragment in line for fragment in denial_fragments)]
 denial_pids={match.group(1) for line in matching_denials if (match:=re.search(r'\bpid=(\d+)\b',line))}
 if not matching_denials or len(denial_pids)!=1:
  raise RuntimeError('Direct supervisor userns rejection lacked exact AppArmor audit proof')
 ownership['apparmor'].update(supervisorLabel=parent_label,directUsernsReturnCode=direct_userns.returncode,
  directUsernsSha256=digest(direct_log),directUsernsAuditSha256=digest(audit_log),directUsernsDenialPid=next(iter(denial_pids)),
  directUsernsDenialSha256=hashlib.sha256('\n'.join(matching_denials).encode()).hexdigest());persist()
 run(docker+['cp',str(tests/'mcpTargetsLinux.integration.test.js'),f'{container}:/qualification/mcpTargetsLinux.integration.test.js'],timeout=30)
 test_command=docker+['exec','--user','10001:10001','-e','MCP_TARGET_LINUX_NATIVE=yes','-e','MCP_TARGET_ROOT=/owned',
  '-e','MCP_TARGET_FIXTURE_ROOT=/opt/lab-template','-e','MCP_TARGET_MODULE=/app/mcpTargets.js',container,
  'node','--test','--test-reporter=tap','/qualification/mcpTargetsLinux.integration.test.js']
 completed=subprocess.run(test_command,env=base_env,capture_output=True,text=True,timeout=120)
 result=root/'result.log';result.write_text(f'CONTAINER_NODE_VERSION={version}\n'+completed.stdout+completed.stderr)
 print(result.read_text(),flush=True);ownership['resultSha256']=digest(result)
 if 'CONTAINER_NODE_VERSION=v26.8.2' not in result.read_text().splitlines():
  raise RuntimeError('sandbox-runner did not report the exact Node 26.8.2 runtime')
 if completed.returncode: raise RuntimeError(f'Native Linux target qualification failed ({completed.returncode})')
 stop_container=containers['sandbox-stop']
 run(docker+['run','--detach','--name',stop_container,'--security-opt','seccomp=unconfined','--security-opt',f'apparmor={profile_name}',
  '--tmpfs','/owned:rw,uid=10001,gid=10001,mode=0700','--entrypoint','/bin/bash',image,'-lc',command],stdout=subprocess.DEVNULL)
 started_containers.append(stop_container)
 ownership['containerIds']['sandbox-stop']=run(docker+['inspect','--format','{{.Id}}',stop_container],capture_output=True,text=True).stdout.strip();persist()
 run(docker+['cp',str(fixtures/'mcpTargetStopProbe.js'),f'{stop_container}:/qualification/mcpTargetStopProbe.js'],timeout=30)
 stop_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
 run(docker+['exec','--detach','--user','10001:10001','-e','MCP_TARGET_ROOT=/owned','-e','MCP_TARGET_FIXTURE_ROOT=/opt/lab-template',
  '-e','MCP_TARGET_MODULE=/app/mcpTargets.js','-e',f'MCP_TARGET_STOP_ID={stop_id}',stop_container,'node','/qualification/mcpTargetStopProbe.js'],timeout=20)
 stop_pid_path=f'/owned/targets/{stop_id}/rootfs/tmp/bwrap-outer-pid';ready_path=f'/owned/targets/{stop_id}/rootfs/tmp/container-stop-ready'
 deadline=time.monotonic()+10
 while time.monotonic()<deadline:
  probe=subprocess.run(docker+['exec',stop_container,'cat',ready_path],env=base_env,capture_output=True,text=True,timeout=5)
  if probe.returncode==0 and probe.stdout=='READY': break
  time.sleep(.1)
 else: raise RuntimeError('Long-running bwrap stop probe did not become ready')
 child_pid=run(docker+['exec',stop_container,'cat',stop_pid_path],capture_output=True,text=True,timeout=20).stdout.strip()
 if not child_pid.isdecimal() or int(child_pid)<=1: raise RuntimeError(f'invalid bubblewrap outer PID {child_pid!r}')
 child_comm=run(docker+['exec','--user','10001:10001',stop_container,'cat',f'/proc/{child_pid}/comm'],capture_output=True,text=True,timeout=20).stdout.strip()
 if child_comm!='bwrap': raise RuntimeError(f'outer PID {child_pid} is not bubblewrap ({child_comm!r})')
 child_label=run(docker+['exec','--user','10001:10001',stop_container,'cat',f'/proc/{child_pid}/attr/current'],capture_output=True,text=True,timeout=20).stdout.strip()
 if f'{profile_name}//bwrap' not in child_label: raise RuntimeError(f'unexpected bubblewrap child AppArmor label {child_label!r}')
 stop_started=time.monotonic();run(docker+['stop','--time','3',stop_container],timeout=15);stop_elapsed=time.monotonic()-stop_started
 state=run(docker+['inspect','--format','{{.State.Running}}',stop_container],capture_output=True,text=True,timeout=20).stdout.strip()
 if state!='false' or stop_elapsed>=15: raise RuntimeError('Container stop did not terminate the long-running bubblewrap child')
 ownership['apparmor'].update(childOuterPid=int(child_pid),childLabel=child_label,containerStopSeconds=stop_elapsed,longRunningChildStopped=True);persist()
 ownership['status']='terminal_pass';persist()
except Exception as error:
 ownership['status']='terminal_fail';ownership['failure']=public_error(error);persist();raise
finally:
 remove_rc=None;container_absent=None;image_remove_rc=None;image_absent=None
 container_cleanup={}
 for name,candidate in reversed(list(containers.items())):
  rc=subprocess.run(docker+['rm','--force',candidate],env=base_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30).returncode if candidate in started_containers else None
  query=subprocess.run(docker+['ps','-a','--filter',f'name=^{candidate}$','--format','{{.Names}}'],env=base_env,capture_output=True,text=True,timeout=20)
  container_cleanup[name]={'name':candidate,'removeReturnCode':rc,'absenceQueryReturnCode':query.returncode,
   'exactAbsent':query.returncode==0 and not query.stdout.strip()}
 remove_rc=0 if all(value['removeReturnCode'] in (None,0) for value in container_cleanup.values()) else 1
 container_absent=all(value['exactAbsent'] for value in container_cleanup.values())
 image_cleanup={}
 for tag in reversed(list(images.values())):
  rc=subprocess.run(docker+['image','rm','--force',tag],env=base_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=60).returncode if tag in built_images else None
  query=subprocess.run(docker+['images','--filter',f'reference={tag}','--format','{{.Repository}}:{{.Tag}}'],env=base_env,capture_output=True,text=True,timeout=20)
  image_cleanup[tag]={'removeReturnCode':rc,'absenceQueryReturnCode':query.returncode,'exactAbsent':query.returncode==0 and not query.stdout.strip()}
 image_remove_rc=0 if all(value['removeReturnCode'] in (None,0) for value in image_cleanup.values()) else 1
 image_absent=all(value['exactAbsent'] for value in image_cleanup.values())
 profile_unload_rc=None;profile_delete_rc=None;remote_dir_delete_rc=None;remote_absence_rc=None;remote_absent=False;profile_absence_rc=None;profile_absent=False
 marker_query=subprocess.run(ssh+['cat','--',remote_marker],env=base_env,capture_output=True,text=True,timeout=20) if remote_creation_attempted else None
 marker_matches=marker_query is not None and marker_query.returncode==0 and marker_query.stdout==remote_owner
 loaded_query=subprocess.run(ssh+['sudo','grep','-F',profile_name,'/sys/kernel/security/apparmor/profiles'],env=base_env,capture_output=True,text=True,timeout=20)
 loaded_after_attempt=loaded_query.returncode==0 and bool(loaded_query.stdout.strip())
 if profile_load_attempted and loaded_after_attempt and marker_matches:
  profile_unload_rc=subprocess.run(ssh+['sudo','apparmor_parser','-R',remote_profile],env=base_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30).returncode
 elif profile_load_attempted and loaded_query.returncode==1 and not loaded_query.stdout.strip():
  profile_unload_rc=0
 # The owned policy is the recovery input for an incomplete unload. Prove the
 # kernel profile absent before deleting the policy, marker or directory.
 profile_query=subprocess.run(ssh+['sudo','grep','-F',profile_name,'/sys/kernel/security/apparmor/profiles'],env=base_env,capture_output=True,text=True,timeout=20)
 profile_absence_rc=profile_query.returncode;profile_absent=profile_query.returncode==1 and not profile_query.stdout.strip()
 if marker_matches and profile_absent:
  profile_delete_rc=subprocess.run(ssh+['rm','-f','--',remote_profile],env=base_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20).returncode
  marker_delete_rc=subprocess.run(ssh+['rm','-f','--',remote_marker],env=base_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20).returncode
  remote_dir_delete_rc=subprocess.run(ssh+['rmdir','--',remote_dir],env=base_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20).returncode
 else: marker_delete_rc=None
 remote_query=subprocess.run(ssh+['test','!','-e',remote_dir],env=base_env,timeout=20)
 remote_absence_rc=remote_query.returncode;remote_absent=remote_query.returncode==0
 ownership['cleanup']={'containerRemoveReturnCode':remove_rc,'exactContainerAbsent':container_absent,
  'containers':container_cleanup,'imageRemoveReturnCode':image_remove_rc,'exactImageAbsent':image_absent,'images':image_cleanup,
  'apparmor':{'profileName':profile_name,'unloadReturnCode':profile_unload_rc,'policyDeleteReturnCode':profile_delete_rc,
   'remoteMarkerMatched':marker_matches,'remoteMarkerDeleteReturnCode':marker_delete_rc,'remoteDirectoryDeleteReturnCode':remote_dir_delete_rc,
   'remoteAbsenceQueryReturnCode':remote_absence_rc,'remoteExactAbsent':remote_absent,
   'cleanupDebt':None if remote_absent and profile_absent else {'profileName':profile_name,'remoteDirectory':remote_dir,
    'reason':'AppArmor profile absence or owned policy cleanup was not established; retain recovery inputs'},
   'loadedAfterAttempt':loaded_after_attempt,'absenceQueryReturnCode':profile_absence_rc,'exactAbsent':profile_absent}}
 prior=ownership['status'];ownership['status']='terminal_pass_cleaned' if prior=='terminal_pass' and container_absent is True \
  and remove_rc==0 and image_absent is True and image_remove_rc==0 and profile_unload_rc==0 \
  and profile_delete_rc==0 and marker_delete_rc==0 and remote_dir_delete_rc==0 and remote_absent is True and profile_absent is True else 'terminal_fail'
 ownership['finishedAt']=datetime.now(timezone.utc).isoformat();persist()
 try:
  grant=json.loads(grant_path.read_text())
  if grant.get('grantId')==args.grant_id and grant.get('status')=='consumed' and grant.get('ownerHandle')==owner_handle:
   grant.update(runStatus='terminal_pass' if ownership['status']=='terminal_pass_cleaned' else 'terminal_fail',completedAt=ownership['finishedAt'],
    cleanup=ownership['cleanup'],sourceHashes=ownership['sourceSha256'],containerId=ownership.get('containerId'),imageIds=ownership.get('imageIds'))
   grant['containerIds']=ownership.get('containerIds');grant['processVersions']=ownership.get('processVersions')
   if ownership.get('resultSha256'): grant['resultSha256']=ownership['resultSha256']
   p=grant_path.with_suffix(grant_path.suffix+'.pending');p.write_text(json.dumps(grant,indent=2,sort_keys=True)+'\n');os.replace(p,grant_path)
 except Exception as grant_error:
  ownership['grantUpdateError']=str(grant_error);persist()
 print(f'Owned Linux target evidence retained: {root}',flush=True)
