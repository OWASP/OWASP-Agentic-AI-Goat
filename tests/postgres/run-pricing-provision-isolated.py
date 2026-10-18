#!/usr/bin/env python3
"""Owned Pricing installer rehearsal; no installed records, DB, models or AWS."""
import hashlib,json,os,signal,socket,subprocess,tempfile,time,shlex
from pathlib import Path
SOURCE=Path(__file__).resolve().parents[2];NODE=Path('/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node');DOCKER='/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker';REALHOME=Path.home();HOST='unix://'+str(REALHOME/'.colima/dvaia-pg-verify/docker.sock')
root=Path(tempfile.mkdtemp(prefix='dvaia-pricing-provision-native-'));root.chmod(0o700);workspace=root/'source';home=root/'home';home.mkdir(mode=0o700);(home/'.colima').symlink_to(REALHOME/'.colima',target_is_directory=True)
env={'PATH':str(NODE.parent)+':'+str(Path(DOCKER).parent)+':/usr/bin:/bin','HOME':str(home),'TMPDIR':str(root),'NODE_ENV':'test','AWS_EC2_METADATA_DISABLED':'true'}
state={'status':'preparing','evidence':str(root),'scope':'actual supported ARM64 provisioner; no DB/model/full setup/browser proof','cleanup':None};child=None;wid=None;directory=None
ssh=['/usr/bin/ssh','-F',str(REALHOME/'.colima/_lima/colima-dvaia-pg-verify/ssh.config'),'lima-colima-dvaia-pg-verify']
def run(args,**kw):return subprocess.run(args,env=env,check=True,capture_output=True,text=True,timeout=kw.pop('timeout',30),**kw)
def docker(args):return run([DOCKER,'--host',HOST,*args])
def remote(args):return run(ssh+[shlex.join(args)])
def save():(root/'ownership.json').write_text(json.dumps(state,indent=2)+'\n');(root/'ownership.json').chmod(0o600)
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def alarm(*_):raise TimeoutError('Owned Pricing provisioning deadline')
signal.signal(signal.SIGALRM,alarm);signal.alarm(420)
try:
 run([str(NODE),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(SOURCE),str(workspace)],cwd=SOURCE,timeout=30);(workspace/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
 wid=run([str(NODE),'-e',"process.stdout.write(require('./scripts/application-data-root').workspaceId(process.cwd()))"],cwd=workspace).stdout;directory=home/'.dvaia'/wid;directory.mkdir(parents=True,mode=0o700);directoryIdentity=(directory.stat().st_dev,directory.stat().st_ino)
 daemon=json.loads(docker(['info','--format','{{json .ID}}']).stdout);authority={'version':1,'workspaceId':wid,'host':HOST,'daemonId':daemon,'source':'environment-host'}
 auth=directory/'local-docker.json';auth.write_text(json.dumps(authority));auth.chmod(0o600)
 name='dvaia-pricing-'+wid;network=name+'-network';tag='dvaia-owned-pricing-'+wid+':local';profile='dvaia-owned-pricing-http-'+wid
 assert not docker(['ps','-aq','--filter','name=^/'+name+'$']).stdout.strip();assert not docker(['images','-q',tag]).stdout.strip();assert not docker(['network','ls','--filter','name=^'+network+'$','--format','{{.Name}}']).stdout.strip()
 assert subprocess.run(ssh+[shlex.join(['sudo','test','-e','/etc/apparmor.d/'+profile])],env=env,capture_output=True,timeout=20).returncode==1
 files=[]
 for d in ['scripts','server/services','sidecars/sandbox-runner/owned-pricing-http']:
  files.extend(p for p in (workspace/d).rglob('*') if p.is_file())
 files.extend([workspace/'sidecars/sandbox-runner/mcpSeccompFilter.c',workspace/'tests/fixtures/secureshopPricingProvision.js',workspace/'tests/postgres/run-pricing-provision-isolated.py'])
 state['sourceSha256']={str(p.relative_to(workspace)):digest(p) for p in files};state['workspaceId']=wid;state['authorityDigest']=hashlib.sha256(json.dumps(authority,sort_keys=True).encode()).hexdigest();save()
 with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
 env.update(PRICING_PORT=str(port),PRICING_RESULT=str(root/'result.json'))
 with (root/'run.log').open('w') as log:
  child=subprocess.Popen([str(NODE),'tests/fixtures/secureshopPricingProvision.js'],cwd=workspace,env=env,stdout=log,stderr=log,start_new_session=True);state.update(status='running',childPgid=child.pid);save();code=child.wait(timeout=380)
 state['exitCode']=code
 if code:raise RuntimeError('Provisioning fixture failed; retained bounded log')
 assert all(digest(workspace/f)==h for f,h in state['sourceSha256'].items());state['status']='passed';save()
except BaseException as e:state.update(status='failed',errorType=type(e).__name__);save()
finally:
 signal.alarm(0);errors=[]
 if child:
  try:
   os.killpg(child.pid,signal.SIGTERM);time.sleep(.3);os.killpg(child.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  child.wait(timeout=5)
 if wid:
  try:
   staged=json.loads((directory/'pricing-provisioning.json').read_text()) if (directory/'pricing-provisioning.json').exists() else None
   rows=docker(['ps','-aq','--filter','name=^/'+name+'$']).stdout.strip()
   if rows:
    c=json.loads(docker(['inspect',rows]).stdout)[0];state['terminalContainerState']=c['State'];save();assert staged and c['Config']['Labels']['dvaia.pricing.owner']==staged['ownerId'] and c['Config']['Labels']['dvaia.pricing.workspace']==wid and c['Config']['Labels']['dvaia.pricing.package']==staged['packageSha256'];
    if not c['State']['Running'] and c['State']['ExitCode']!=0:
     try:
      diagnostic=name+'-diagnostic';assert not docker(['ps','-aq','--filter','name=^/'+diagnostic+'$']).stdout.strip()
      script="const e=require('./sidecars/sandbox-runner/owned-pricing-http/executor').createOwnedPricingHttpExecutor({expectedProfile:process.argv[1]});(async()=>{for(const method of ['checkReadiness','assertReady']){try{await e[method]();console.log(JSON.stringify({method,ready:true}));}catch(x){console.log(JSON.stringify({method,code:x.code||x.name,diagnostic:x.diagnostic||null}));break;}}})()"
      try:
       d=run([DOCKER,'--host',HOST,'run','--rm','--name',diagnostic,'--label','dvaia.pricing.owner='+staged['ownerId'],'--network','none','--read-only','--user','10001:10001','--memory','512m','--cpus','1','--pids-limit','128','--cap-drop','ALL','--tmpfs','/tmp:rw,nosuid,nodev,size=134217728','--security-opt','seccomp=unconfined','--security-opt','apparmor='+profile,'--entrypoint','node',c['Image'],'-e',script,profile],timeout=30);state['readinessDiagnostic']=d.stdout[:8192];save()
      finally:
       leftover=docker(['ps','-aq','--filter','name=^/'+diagnostic+'$']).stdout.strip()
       if leftover:
        dc=json.loads(docker(['inspect',leftover]).stdout)[0];assert dc['Config']['Labels'].get('dvaia.pricing.owner')==staged['ownerId'];docker(['rm','-f',dc['Id']])
     except Exception as diagnostic_error:
      errors.append('ReadinessDiagnostic:'+type(diagnostic_error).__name__);save()
    docker(['rm','-f',c['Id']])
   nets=docker(['network','ls','--filter','name=^'+network+'$','--format','{{.ID}}']).stdout.strip()
   if nets:
    n=json.loads(docker(['network','inspect',nets]).stdout)[0];assert staged and n['Labels']['dvaia.pricing.owner']==staged['ownerId'] and n['Labels']['dvaia.pricing.workspace']==wid;docker(['network','rm',n['Id']])
   image=docker(['images','-q',tag]).stdout.strip()
   if image:
    im=json.loads(docker(['image','inspect',tag]).stdout)[0];package=json.loads((workspace/'sidecars/sandbox-runner/owned-pricing-http/local-package-manifest.json').read_text());assert im['Config']['Labels']['dvaia.pricing.package']==package['sha256'];assert im.get('RepoTags')==[tag];docker(['image','rm',tag]);assert subprocess.run([DOCKER,'--host',HOST,'image','inspect',im['Id']],env=env,capture_output=True,timeout=10).returncode!=0;assert not docker(['images','-q',tag]).stdout.strip()
   check=subprocess.run(ssh+[shlex.join(['sudo','test','-e','/etc/apparmor.d/'+profile])],env=env,capture_output=True,timeout=20)
   if check.returncode==0:
    expected=(workspace/'sidecars/sandbox-runner/owned-pricing-http/http-profile.apparmor.in').read_text().replace('@@SUPERVISOR_PROFILE@@',profile);actual=remote(['sudo','cat','/etc/apparmor.d/'+profile]).stdout;assert actual==expected;remote(['sudo','apparmor_parser','-R','/etc/apparmor.d/'+profile]);remote(['sudo','rm','--','/etc/apparmor.d/'+profile])
   assert not docker(['ps','-aq','--filter','name=^/'+name+'$']).stdout.strip();assert not docker(['network','ls','--filter','name=^'+network+'$','--format','{{.ID}}']).stdout.strip()
   if directory.exists():
    assert not directory.is_symlink() and (directory.stat().st_dev,directory.stat().st_ino)==directoryIdentity
    for f in directory.iterdir():assert f.name in ['local-docker.json','pricing-provisioning.json','pricing-managed.json'] and f.is_file() and not f.is_symlink();f.unlink()
    directory.rmdir()
  except Exception as e:errors.append(type(e).__name__)
 rows=subprocess.check_output(['ps','-axo','pid=,pgid=,uid=,command='],text=True,timeout=5).splitlines();remaining=[]
 for row in rows:
  fields=row.split(None,3)
  if len(fields)==4 and int(fields[0])!=os.getpid() and int(fields[2])==os.getuid() and ((child and int(fields[1])==child.pid) or str(root) in fields[3]):remaining.append(int(fields[0]))
 if remaining:errors.append('OwnedLocalProcessRemains')
 state['cleanup']={'errors':errors,'ownedResourcesAbsent':not errors,'localProcessesAbsent':not remaining};state['logSha256']=digest(root/'run.log') if (root/'run.log').exists() else None;save()
print(json.dumps({'status':state['status'],'evidence':str(root),'cleanup':state['cleanup']}))
if state['status']!='passed' or state['cleanup']['errors']:raise SystemExit(1)
