import argparse
argparse.ArgumentParser(description='Owned System config native qualification; no installed state').parse_args()
import os,pathlib,tempfile,subprocess,json,hashlib,shutil,uuid,time
root=pathlib.Path.cwd();out=pathlib.Path(tempfile.mkdtemp(prefix='owasp-ai-goat-system-config-native-'));token=uuid.uuid4().hex[:12];name='owasp-ai-goat-system-config-'+token;tag=name+':owned';base='sha256:3a771f83944bb763050c23c0225c260638c4b7899e7a72485ef75e5e570499e5';docker=['/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker','--host','unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock'];receipt={'out':str(out),'container':name,'imageTag':tag,'base':base,'token':token,'sourceHashes':{},'cleanup':{}};image=None
shutil.copytree(root/'sidecars/sandbox-runner/owned-system',out/'owned-system')
for p in (out/'owned-system').glob('*'):
 if p.is_file():receipt['sourceHashes']['sidecars/sandbox-runner/owned-system/'+p.name]=hashlib.sha256(p.read_bytes()).hexdigest()
client=root/'server/services/secureshopSystemConfigClient.js'
shutil.copyfile(client,out/'secureshopSystemConfigClient.js')
receipt['sourceHashes']['server/services/secureshopSystemConfigClient.js']=hashlib.sha256(client.read_bytes()).hexdigest()
(out/'Dockerfile').write_text('''FROM '''+'node@'+base+'''\nRUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev bubblewrap && rm -rf /var/lib/apt/lists/*
COPY owned-system /qualification/owned-system
COPY secureshopSystemConfigClient.js /server/services/secureshopSystemConfigClient.js
RUN mkdir -p /sidecars/sandbox-runner && ln -s /qualification/owned-system /sidecars/sandbox-runner/owned-system
RUN mkdir -p /usr/local/libexec && gcc -static -O2 -Wall -Wextra -Werror /qualification/owned-system/system-init.c -o /usr/local/libexec/owasp-ai-goat-system-config-init && gcc -static -O2 -Wall -Wextra -Werror /qualification/owned-system/process-supervisor.c -o /usr/local/libexec/owasp-ai-goat-system-config-supervisor && chmod 0555 /usr/local/libexec/owasp-ai-goat-system-config-* /usr/bin/bwrap && printf synthetic-private-sentinel > /private-qualification-sentinel && dpkg-query -W > /qualification/packages.txt
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/node","/qualification/owned-system/native-qualification.js"]
''')
def run(args,timeout=30,check=True):
 r=subprocess.run(docker+args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=timeout)
 if check and r.returncode:raise RuntimeError(r.stdout[-5000:])
 return r
try:
 assert run(['info','--format','{{.Name}}']).stdout.strip()=='colima-owasp-ai-goat-pg-verify'
 inspected=json.loads(run(['image','inspect',base]).stdout)[0];assert inspected['Architecture']=='arm64';receipt['baseInspect']=inspected['Id']
 with (out/'build.log').open('w') as log:
  p=subprocess.Popen(docker+['build','--pull=false','--network=default','--label','owasp-ai-goat.system-config.owner='+token,'-t',tag,str(out)],stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  try:assert p.wait(timeout=300)==0
  except BaseException:
   import signal
   try:os.killpg(p.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   p.wait();raise
 image=json.loads(run(['image','inspect',tag]).stdout)[0]['Id'];receipt['imageId']=image
 args=['run','--name',name,'--label','owasp-ai-goat.system-config.owner='+token,'--network','none','--read-only','--user','10001:10001','--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/tmp:rw,nosuid,nodev,size=128m','--security-opt','seccomp=unconfined','--security-opt','apparmor=owasp-ai-goat-mcp-sandbox',image];receipt['runArgs']=args
 try:r=run(args,timeout=120,check=False);(out/'run.log').write_text(r.stdout);receipt['exitCode']=r.returncode;receipt['status']='passed' if r.returncode==0 else 'failed'
 except BaseException:receipt['status']='failed';raise
 receipt['containerInspect']=json.loads(run(['inspect',name]).stdout)[0]
 run(['cp',name+':/qualification/packages.txt',str(out/'packages.txt')]);assert receipt['exitCode']==0
except BaseException as e:receipt['status']='failed';receipt['error']=str(e)
finally:
 r=run(['rm','-f',name],check=False);receipt['cleanup']['containerAbsent']=run(['inspect',name],check=False).returncode!=0
 if image:
  obj=json.loads(run(['image','inspect',tag]).stdout)[0];assert obj['Config']['Labels'].get('owasp-ai-goat.system-config.owner')==token
 run(['image','rm',tag],check=False)
 receipt['cleanup']['imageTagAbsent']=run(['image','inspect',tag],check=False).returncode!=0
 receipt['cleanup']['imageIdAbsent']=not image or run(['image','inspect',image],check=False).returncode!=0
 (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({'out':str(out),'status':receipt['status'],'cleanup':receipt['cleanup']}),flush=True)
if receipt['status']!='passed' or not all(receipt['cleanup'].values()):raise SystemExit(1)
