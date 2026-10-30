#!/usr/bin/env python3
import argparse,hashlib,json,os,pathlib,shlex,shutil,signal,socket,subprocess,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[1]
DOCKER='/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker'
HOST='unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock'
SSH=['/usr/bin/ssh','-F',str(pathlib.Path.home()/'.colima/_lima/colima-owasp-ai-goat-pg-verify/ssh.config'),'lima-colima-owasp-ai-goat-pg-verify']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(a,timeout=30,**kw):return subprocess.run(a,capture_output=True,text=True,timeout=timeout,**kw)
def checked(a,timeout=30,**kw):
 r=run(a,timeout,**kw)
 if r.returncode:raise RuntimeError('command failed '+a[0]+': '+r.stderr[-1000:])
 return r.stdout

def main():
 p=argparse.ArgumentParser();p.add_argument('--docker-host',required=True);a=p.parse_args()
 if a.docker_host!=HOST:raise SystemExit('Reviewed isolated authority required')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError('parent deadline')));signal.alarm(600)
 docker=[DOCKER,'--host',HOST]
 if checked(docker+['info','--format','{{.Name}}']).strip()!='colima-owasp-ai-goat-pg-verify':raise RuntimeError('Unexpected daemon')
 evidence=pathlib.Path(tempfile.mkdtemp(prefix='owasp-ai-goat-listings-install-native-'));closure=evidence/'source';home=evidence/'home';home.mkdir(mode=0o700)
 result={'status':'running','evidence':str(evidence),'cleanup':{},'sourceSha256':{}};child=None;profile_owned=False;managed_dir=None;image_id=None;ca=evidence/'npm-ca.pem'
 try:
  script="const fs=require('fs'),p=require('path');const candidate=require('./scripts/install/secureshop-owned-listings-qualified-candidate');candidate.qualifiedPackage({architecture:'arm64'});const source=require('./scripts/install/secureshop-owned-listings').sourceManifest(process.cwd());console.log(JSON.stringify([...new Set([...Object.keys(require.cache).filter(x=>x.startsWith(process.cwd()+'/')&&!x.includes('/node_modules/')).map(x=>p.relative(process.cwd(),x)),...Object.keys(source.files),'scripts/install/manifests/owned-listings-arm64.candidate.json',candidate._internals.QUALIFICATION_REPORT,'tests/fixtures/secureshopListingsInstaller.native.cjs'])]));"
  files=json.loads(checked(['node','-e',script],cwd=ROOT))
  for rel in files:
   target=closure/rel;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/rel,target);result['sourceSha256'][rel]=sha(target)
  (closure/'node_modules').symlink_to(ROOT/'node_modules',target_is_directory=True)
  workspace_id=checked(['node','-e',"console.log(require('./scripts/application-data-root').workspaceId(process.cwd()))"],cwd=closure).strip()
  name='owasp-ai-goat-owned-listings-'+workspace_id;network=name+'-bridge';volume=name+'-journal';tag=name+':local';profile=name;lock='/etc/apparmor.d/.'+profile+'.install-lock'
  result.update({'name':name,'network':network,'volume':volume,'tag':tag,'profile':profile,'lock':lock})
  result['profileSha256']=hashlib.sha256((closure/'sidecars/sandbox-runner/owned-listings/profile.apparmor.in').read_text().replace('@@SUPERVISOR_PROFILE@@',profile).encode()).hexdigest()
  for kind,identity in [('container',name),('network',network),('volume',volume),('image',tag)]:
   if run(docker+[kind,'inspect',identity]).returncode==0:raise RuntimeError('preexisting owned identity')
  labels=checked(SSH+[shlex.join(['sudo','cat','/sys/kernel/security/apparmor/profiles'])])
  if any(v.startswith(profile+' ')or v.startswith(profile+'//')for v in labels.splitlines()):raise RuntimeError('preexisting profile')
  for identity in ['/etc/apparmor.d/'+profile,lock]:
   if run(SSH+[shlex.join(['sudo','test','-e',identity])]).returncode!=1:raise RuntimeError('preexisting profile file/lock')
  profile_owned=True
  managed_dir=home/'.owasp-ai-goat'/workspace_id;managed_dir.mkdir(parents=True,mode=0o700)
  daemon_id=json.loads(checked(docker+['info','--format','{{json .ID}}']))
  authority=managed_dir/'local-docker.json';authority.write_text(json.dumps({'version':1,'workspaceId':workspace_id,'host':HOST,'daemonId':daemon_id,'source':'environment-host'}));authority.chmod(0o600)
  certs=checked(['/usr/bin/security','find-certificate','-a','-p','/Library/Keychains/System.keychain'])
  if '-----BEGIN CERTIFICATE-----'not in certs:raise RuntimeError('Trusted CA unavailable')
  ca.write_text(certs);ca.chmod(0o600);result['buildCaSha256']=sha(ca)
  with socket.socket()as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
  result['port']=port
  env=dict(os.environ);env.update({'LISTINGS_TEST_HOME':str(home),'LISTINGS_TEST_PORT':str(port),'LISTINGS_TEST_CA':str(ca),'LISTINGS_TEST_CA_SHA':sha(ca),'PATH':str(pathlib.Path(DOCKER).parent)+os.pathsep+env.get('PATH','')})
  with (evidence/'test.stdout').open('w')as out,(evidence/'test.stderr').open('w')as err:
   child=subprocess.Popen(['node',str(closure/'tests/fixtures/secureshopListingsInstaller.native.cjs')],cwd=closure,env=env,stdout=out,stderr=err,start_new_session=True);result['child']={'pid':child.pid,'pgid':child.pid};result['exitCode']=child.wait(timeout=420)
  if result['exitCode']!=0:raise RuntimeError('Native installer failed; see bounded stderr')
  result['result']=json.loads((evidence/'test.stdout').read_text().strip().splitlines()[-1]);image_id=result['result']['imageId'];result['status']='passed'
 except BaseException as error:result['status']='failed';result['error']=str(error)
 finally:
  signal.alarm(120)
  if child:
   try:os.killpg(child.pid,signal.SIGTERM)
   except ProcessLookupError:pass
   time.sleep(.2)
   try:os.killpg(child.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   try:child.wait(timeout=5)
   except Exception:pass
  if profile_owned:
   state=run(docker+['container','inspect','--format','{{json .State}}',name]);(evidence/'container-state.json').write_text(state.stdout if state.returncode==0 else '{}\n')
   logs=run(docker+['logs','--tail','20',name]);(evidence/'manager.log').write_text(logs.stdout+logs.stderr)
   inspected=run(docker+['image','inspect',tag]);
   if inspected.returncode==0:image_id=json.loads(inspected.stdout)[0]['Id']
   run(docker+['rm','-f',name]);result['cleanup']['containerAbsent']=run(docker+['container','inspect',name]).returncode!=0
   run(docker+['network','rm',network]);result['cleanup']['networkAbsent']=run(docker+['network','inspect',network]).returncode!=0
   run(docker+['volume','rm',volume]);result['cleanup']['volumeAbsent']=run(docker+['volume','inspect',volume]).returncode!=0
   run(docker+['image','rm',tag]);result['cleanup']['imageAbsent']=run(docker+['image','inspect',image_id or tag]).returncode!=0
   if result['cleanup']['containerAbsent']:
    profile_file=run(SSH+[shlex.join(['sudo','sha256sum','/etc/apparmor.d/'+profile])])
    if profile_file.returncode==0 and profile_file.stdout.split()[0]!=result['profileSha256']:raise RuntimeError('Owned profile bytes changed; preserve for recovery')
    run(SSH+[shlex.join(['sudo','apparmor_parser','-R','/etc/apparmor.d/'+profile])]);labels=checked(SSH+[shlex.join(['sudo','cat','/sys/kernel/security/apparmor/profiles'])]);result['cleanup']['profileAbsent']=not any(v.startswith(profile+' ')or v.startswith(profile+'//')for v in labels.splitlines())
    if result['cleanup']['profileAbsent']:
     checked(SSH+[shlex.join(['sudo','rm','-f','/etc/apparmor.d/'+profile,lock])]);result['cleanup']['profileFileAbsent']=run(SSH+[shlex.join(['sudo','test','-e','/etc/apparmor.d/'+profile])]).returncode==1;result['cleanup']['lockAbsent']=run(SSH+[shlex.join(['sudo','test','-e',lock])]).returncode==1
  if managed_dir and managed_dir.exists():
   for filename in managed_dir.iterdir():
    if filename.name not in ['local-docker.json','secureshop-owned-listings.json']:raise RuntimeError('unexpected private config')
    filename.unlink()
   managed_dir.rmdir()
  result['cleanup']['privateConfigAbsent']=not managed_dir or not managed_dir.exists()
  if ca.exists():ca.unlink()
  result['cleanup']['buildCaAbsent']=not ca.exists()
  if child:
   try:os.killpg(child.pid,0);result['cleanup']['childPgidAbsent']=False
   except ProcessLookupError:result['cleanup']['childPgidAbsent']=True
  else:result['cleanup']['childPgidAbsent']=True
  result['cleanup']['errors']=[k for k,v in result['cleanup'].items()if v is not True]
  (evidence/'ownership.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'evidence':str(evidence),'cleanup':result['cleanup']}));signal.alarm(0)
 if result['status']!='passed'or result['cleanup']['errors']:raise SystemExit(1)
if __name__=='__main__':main()
