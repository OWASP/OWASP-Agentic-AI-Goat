#!/usr/bin/env python3
import argparse,hashlib,json,os,pathlib,shlex,shutil,signal,subprocess,tempfile,time,uuid

ROOT=pathlib.Path(__file__).resolve().parents[1]
DOCKER=pathlib.Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')
HOST='unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
SSH=['/usr/bin/ssh','-F',str(pathlib.Path.home()/'.colima/_lima/colima-dvaia-pg-verify/ssh.config'),'lima-colima-dvaia-pg-verify']
FILES=['sidecars/sandbox-runner/owned-mcp-registry','sidecars/sandbox-runner/owned-http/namespace-init.c','sidecars/sandbox-runner/mcpSeccompFilter.c','server/services/secureshopMcpRegistryContract.js','server/services/secureshopMcpRegistryDiscovery.js','server/services/secureshopMcpSchemaDigest.js','server/services/mcp/protocolContext.js','tests/fixtures/secureshopOwnedMcpRegistryPackaged.native.cjs']
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def run(argv,timeout=30,**kw):return subprocess.run(argv,text=True,capture_output=True,timeout=timeout,**kw)
def checked(argv,timeout=30,**kw):
 r=run(argv,timeout=timeout,**kw)
 if r.returncode:raise RuntimeError(f"command failed {argv[0]}: {r.stderr[-2000:]}")
 return r.stdout
def ssh(argv,**kw):return run(SSH+[shlex.join(argv)],**kw)
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True);args=parser.parse_args()
 if args.docker_host!=HOST:raise SystemExit('reviewed isolated Docker host required')
 nonce=uuid.uuid4().hex[:12];name='dvaia-owned-mcp-registry-'+nonce;profile=name;tag=name+':candidate';remote='/tmp/'+name
 evidence_dir=pathlib.Path(tempfile.mkdtemp(prefix='dvaia-owned-mcp-registry-executor-'));closure=evidence_dir/'source';result={'name':name,'profile':profile,'evidence':str(evidence_dir),'status':'running','cleanup':{},'sourceSha256':{}}
 container_started=image_id=None;profile_loaded=remote_created=False;build=None;test=None;ca_file=None
 docker=[str(DOCKER),'--host',HOST]
 try:
  for rel in FILES:
   src=ROOT/rel;dst=closure/rel
   if src.is_dir():shutil.copytree(src,dst)
   else:dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)
  for path in sorted(p for p in closure.rglob('*') if p.is_file()):result['sourceSha256'][str(path.relative_to(closure))]=sha(path)
  template=(closure/'sidecars/sandbox-runner/owned-mcp-registry/profile.apparmor.in').read_text();policy=template.replace('@@SUPERVISOR_PROFILE@@',profile)
  result['policySha256']=hashlib.sha256(policy.encode()).hexdigest();(evidence_dir/'policy.apparmor').write_text(policy)
  labels=checked(SSH+[shlex.join(['sudo','cat','/sys/kernel/security/apparmor/profiles'])]);assert not any(v.startswith(profile+' ') or v.startswith(profile+'//') for v in labels.splitlines())
  checked(SSH+[shlex.join(['test','!','-e',remote])]);checked(SSH+[shlex.join(['mkdir','-m','0700',remote])]);remote_created=True
  checked(SSH+[shlex.join(['tee',remote+'/owner'])],input=nonce+'\n');checked(SSH+[shlex.join(['tee',remote+'/policy'])],input=policy)
  checked(SSH+[shlex.join(['sudo','apparmor_parser','--skip-kernel-load',remote+'/policy'])]);checked(SSH+[shlex.join(['sudo','apparmor_parser','-r',remote+'/policy'])]);profile_loaded=True
  certificates=checked(['/usr/bin/security','find-certificate','-a','-p','/Library/Keychains/System.keychain'])+checked(['/usr/bin/security','find-certificate','-a','-p',str(pathlib.Path.home()/'Library/Keychains/login.keychain-db')])
  if certificates.count('-----BEGIN CERTIFICATE-----')<1:raise RuntimeError('trusted build certificate bundle unavailable')
  ca_file=evidence_dir/'npm-ca.pem';ca_file.write_text(certificates);ca_file.chmod(0o600);result['buildCaSha256']=sha(ca_file)
  build_log=(evidence_dir/'build.log').open('w')
  build=subprocess.Popen(docker+['build','--platform','linux/arm64','--secret',f'id=npm_ca,src={ca_file}','--tag',tag,'--file',str(closure/'sidecars/sandbox-runner/owned-mcp-registry/Dockerfile.candidate'),str(closure)],stdout=build_log,stderr=subprocess.STDOUT,text=True,start_new_session=True)
  result['build']={'pid':build.pid,'pgid':os.getpgid(build.pid)};result['buildExitCode']=build.wait(timeout=300);build_log.close()
  if result['buildExitCode']!=0:raise RuntimeError('candidate image build failed')
  image_id=checked(docker+['image','inspect',tag,'--format','{{.Id}}']).strip();result['imageId']=image_id
  command=docker+['run','--name',name,'--label','dvaia.owner='+nonce,'--network','none','--read-only','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=16m','--memory','512m','--cpus','1','--pids-limit','128','--cap-drop','ALL','--security-opt','apparmor='+profile,'--security-opt','seccomp=unconfined','--user','10001:10001','--env','SECURESHOP_MCP_REGISTRY_PROFILE='+profile,'--entrypoint','node',image_id,'/app/tests/fixtures/secureshopOwnedMcpRegistryPackaged.native.cjs']
  test=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True);result['test']={'pid':test.pid,'pgid':os.getpgid(test.pid)};container_started=True
  stdout,stderr=test.communicate(timeout=120);result['testExitCode']=test.returncode;(evidence_dir/'test.stdout').write_text(stdout);(evidence_dir/'test.stderr').write_text(stderr)
  if test.returncode!=0:raise RuntimeError('packaged executor gate failed')
  payload=json.loads(stdout.strip().splitlines()[-1]);assert payload['status']=='passed' and payload['modelCalls']==0;result['result']=payload;result['status']='passed'
 except Exception as error:
  result['status']='failed';result['errorType']=type(error).__name__;result['error']=str(error)
 finally:
  for child in (test,build):
   if child and child.poll() is None:
    try:os.killpg(os.getpgid(child.pid),signal.SIGTERM);child.wait(timeout=5)
    except Exception:
     try:os.killpg(os.getpgid(child.pid),signal.SIGKILL)
     except Exception:pass
  rm=run(docker+['rm','-f',name],timeout=20);result['cleanup']['containerRemoveExitCode']=rm.returncode
  result['cleanup']['containerAbsent']=not checked(docker+['ps','-aq','--filter','name=^/'+name+'$']).strip()
  if image_id:run(docker+['image','rm','-f',image_id],timeout=30)
  run(docker+['image','rm','-f',tag],timeout=20);result['cleanup']['imageAbsent']=run(docker+['image','inspect',image_id or tag],timeout=10).returncode!=0
  if profile_loaded and result['cleanup']['containerAbsent']:run(SSH+[shlex.join(['sudo','apparmor_parser','-R',remote+'/policy'])],timeout=20)
  labels=run(SSH+[shlex.join(['sudo','cat','/sys/kernel/security/apparmor/profiles'])],timeout=20).stdout;result['cleanup']['profileAbsent']=not any(v.startswith(profile+' ') or v.startswith(profile+'//') for v in labels.splitlines())
  if remote_created and result['cleanup']['profileAbsent']:
   owner=run(SSH+[shlex.join(['cat',remote+'/owner'])]).stdout
   if owner==nonce+'\n':run(SSH+[shlex.join(['rm','-f',remote+'/owner',remote+'/policy'])]);run(SSH+[shlex.join(['rmdir',remote])])
  result['cleanup']['remoteAbsent']=run(SSH+[shlex.join(['test','!','-e',remote])]).returncode==0
  if ca_file and ca_file.exists():ca_file.unlink()
  result['cleanup']['buildCaAbsent']=not ca_file or not ca_file.exists()
  for key in ('build','test'):
   pgid=result.get(key,{}).get('pgid');result['cleanup'][key+'PgidAbsent']=not pgid or not run(['/bin/ps','-axo','pgid=']).stdout.split().count(str(pgid))
  result['cleanup']['errors']=[] if all(result['cleanup'].get(k) is True for k in ('containerAbsent','imageAbsent','profileAbsent','remoteAbsent','buildCaAbsent','buildPgidAbsent','testPgidAbsent')) else ['owned resource remains']
  (evidence_dir/'ownership.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({'evidence':str(evidence_dir),'status':result['status'],'cleanup':result['cleanup']}))
 if result['status']!='passed' or result['cleanup']['errors']:raise SystemExit(1)
if __name__=='__main__':main()
