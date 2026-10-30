"""Explicit owned diagnostic-only Linux qualification. No installed state or model."""
import argparse, hashlib, json, os, pathlib, shutil, signal, subprocess, tempfile, time, uuid
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--docker-host',required=True)
parser.add_argument('--http',action='store_true',help='Actual private loopback HTTP composition inside network-none container')
args=parser.parse_args()
EXPECTED='unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock'
if args.docker_host!=EXPECTED:parser.error('Reviewed owned Docker host required')
ROOT=pathlib.Path(__file__).resolve().parents[1]
OUT=pathlib.Path(tempfile.mkdtemp(prefix='owasp-ai-goat-system-diagnostic-native-'));os.chmod(OUT,0o700)
OWNER=uuid.uuid4().hex;NAME='owasp-ai-goat-system-diagnostic-'+OWNER[:12];TAG=NAME+':owned'
BASE='sha256:3a771f83944bb763050c23c0225c260638c4b7899e7a72485ef75e5e570499e5'
DOCKER=['/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker','--host',args.docker_host]
ENV={k:v for k,v in os.environ.items() if k in ['PATH','HOME','TMPDIR']}
state={'out':str(OUT),'owner':OWNER,'container':NAME,'imageTag':TAG,'base':BASE,'sourceHashes':{},'status':'preparing','cleanup':{}}
image=None;build=None;created=False

def persist(): (OUT/'result.json').write_text(json.dumps(state,indent=2)+'\n')
def run(argv,timeout=30,check=True):
 r=subprocess.run(DOCKER+argv,env=ENV,capture_output=True,text=True,timeout=timeout)
 if check and r.returncode:raise RuntimeError('Docker operation failed: '+r.stderr[-2000:])
 return r
def inspect(kind,name):return json.loads(run([kind,'inspect',name]).stdout)[0]
def members():
 if not build:return []
 rows=subprocess.run(['ps','-axo','pid=,pgid=,uid='],capture_output=True,text=True,timeout=5,check=True).stdout.splitlines()
 found=[]
 for row in rows:
  parts=row.split()
  if len(parts)==3 and int(parts[1])==build.pid:
   if int(parts[2])!=os.getuid():raise RuntimeError('Foreign process group')
   found.append(int(parts[0]))
 return found
try:
 assert run(['info','--format','{{.Name}}']).stdout.strip()=='colima-owasp-ai-goat-pg-verify'
 base=inspect('image',BASE);assert base['Id']==BASE and base['Architecture']=='arm64'
 assert run(['container','inspect',NAME],check=False).returncode!=0
 assert run(['image','inspect',TAG],check=False).returncode!=0
 context=OUT/'build';target=context/'owned-system';target.mkdir(parents=True)
 for name in ['diagnostic-contract.js','diagnostic-executor.js','diagnostic-receipt.js','diagnostic-result.js','diagnostic-wire.js','diagnostic-init.c','diagnostic-supervisor.c','diagnostic-native-qualification.js','diagnostic-native-attack.c','diagnostic-http-native-qualification.js','diagnostic-http-listener.js','diagnostic-http-handler.js']:
  source=ROOT/'sidecars/sandbox-runner/owned-system'/name;shutil.copyfile(source,target/name);state['sourceHashes'][str(source.relative_to(ROOT))]=hashlib.sha256((target/name).read_bytes()).hexdigest()
 client=ROOT/'server/services/secureshopSystemDiagnosticClient.js';shutil.copyfile(client,context/'secureshopSystemDiagnosticClient.js');state['sourceHashes'][str(client.relative_to(ROOT))]=hashlib.sha256(client.read_bytes()).hexdigest()
 state['mode']='http' if args.http else 'executor'
 shutil.copyfile(__file__,OUT/'launcher.py');state['sourceHashes'][str(pathlib.Path(__file__).resolve().relative_to(ROOT))]=hashlib.sha256((OUT/'launcher.py').read_bytes()).hexdigest()
 dockerfile='''FROM node@'''+BASE+'''
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev bubblewrap util-linux && rm -rf /var/lib/apt/lists/*
COPY owned-system /qualification/owned-system
COPY secureshopSystemDiagnosticClient.js /server/services/secureshopSystemDiagnosticClient.js
RUN mkdir -p /sidecars/sandbox-runner && ln -s /qualification/owned-system /sidecars/sandbox-runner/owned-system
RUN mkdir -p /usr/local/libexec && gcc -static -O2 -Wall -Wextra -Werror /qualification/owned-system/diagnostic-init.c -o /usr/local/libexec/owasp-ai-goat-system-diagnostic-init && gcc -static -O2 -Wall -Wextra -Werror /qualification/owned-system/diagnostic-supervisor.c -o /usr/local/libexec/owasp-ai-goat-system-diagnostic-supervisor && gcc -static -O2 -Wall -Wextra -Werror /qualification/owned-system/diagnostic-native-attack.c -o /usr/bin/diagnostic-native-attack && chmod 0555 /usr/bin/diagnostic-native-attack /usr/local/libexec/owasp-ai-goat-system-diagnostic-* /usr/bin/bwrap && for f in /usr/local/libexec/owasp-ai-goat-system-diagnostic-init /usr/local/libexec/owasp-ai-goat-system-diagnostic-supervisor; do sha256sum "$f" | cut -d' ' -f1 > "$f.sha256"; chmod 0444 "$f.sha256"; done && printf synthetic-private-sentinel > /private-qualification-sentinel && dpkg-query -W > /qualification/packages.txt
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/node","/qualification/owned-system/diagnostic-native-qualification.js"]
'''
 if args.http:dockerfile=dockerfile.replace('/qualification/owned-system/diagnostic-native-qualification.js','/qualification/owned-system/diagnostic-http-native-qualification.js')
 (context/'Dockerfile').write_text(dockerfile);state['dockerfileSha256']=hashlib.sha256(dockerfile.encode()).hexdigest();persist()
 with (OUT/'build.log').open('w') as log:
  build=subprocess.Popen(DOCKER+['build','--pull=false','--network=default','--label','owasp-ai-goat.diagnostic.owner='+OWNER,'-t',TAG,str(context)],env=ENV,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  state['buildPgid']=build.pid;persist();assert build.wait(timeout=300)==0
 image=inspect('image',TAG);assert image['Config']['Labels']['owasp-ai-goat.diagnostic.owner']==OWNER;image=image['Id'];state['imageId']=image
 create=['create','--name',NAME,'--label','owasp-ai-goat.diagnostic.owner='+OWNER,'--network','none','--read-only','--user','10001:10001','--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/tmp:rw,nosuid,nodev,size=128m','--security-opt','seccomp=unconfined','--security-opt','apparmor=owasp-ai-goat-mcp-sandbox',image]
 created=True;run(create);actual=inspect('container',NAME);host=actual['HostConfig']
 assert actual['Config']['Labels']['owasp-ai-goat.diagnostic.owner']==OWNER and not actual['Mounts'] and not host.get('PortBindings') and host['NetworkMode']=='none'
 assert host['Memory']==536870912 and host['NanoCpus']==1000000000 and host['PidsLimit']==128 and host['ReadonlyRootfs'] and actual['Config']['User']=='10001:10001'
 state['runtime']={'hostConfig':host,'mounts':actual['Mounts'],'user':actual['Config']['User']};state['status']='running';persist()
 run(['start',NAME]);wait=run(['wait',NAME],timeout=120);state['exitCode']=int(wait.stdout.strip());logs=run(['logs',NAME],check=False);(OUT/'run.log').write_text(logs.stdout+logs.stderr)
 run(['cp',NAME+':/qualification/packages.txt',str(OUT/'packages.txt')]);state['packagesSha256']=hashlib.sha256((OUT/'packages.txt').read_bytes()).hexdigest();assert state['exitCode']==0
 state['status']='passed'
except BaseException as error:state['status']='failed';state['error']=type(error).__name__+': '+str(error)
finally:
 errors=[]
 try:
  if members():os.killpg(build.pid,signal.SIGTERM);time.sleep(.2)
  if members():os.killpg(build.pid,signal.SIGKILL)
  if build:build.wait(timeout=5)
  state['cleanup']['buildGroupAbsent']=not members()
 except BaseException as e:errors.append('build:'+type(e).__name__)
 try:
  if created and run(['container','inspect',NAME],check=False).returncode==0:
   assert inspect('container',NAME)['Config']['Labels']['owasp-ai-goat.diagnostic.owner']==OWNER
   logs=run(['logs',NAME],check=False);(OUT/'run.log').write_text(logs.stdout+logs.stderr);run(['rm','-f',NAME])
  state['cleanup']['containerAbsent']=run(['container','inspect',NAME],check=False).returncode!=0
 except BaseException as e:errors.append('container:'+type(e).__name__)
 try:
  if run(['image','inspect',TAG],check=False).returncode==0:
   obj=inspect('image',TAG);assert obj['Config']['Labels']['owasp-ai-goat.diagnostic.owner']==OWNER;image=obj['Id'];run(['image','rm',TAG])
  state['cleanup']['imageTagAbsent']=run(['image','inspect',TAG],check=False).returncode!=0
  state['cleanup']['imageIdAbsent']=not image or run(['image','inspect',image],check=False).returncode!=0
 except BaseException as e:errors.append('image:'+type(e).__name__)
 state['cleanup']['errors']=errors;persist();print(json.dumps({'out':str(OUT),'status':state['status'],'cleanup':state['cleanup']}),flush=True)
if state['status']!='passed' or state['cleanup'].get('errors') or not all(state['cleanup'].get(k) for k in ['buildGroupAbsent','containerAbsent','imageTagAbsent','imageIdAbsent']):raise SystemExit(1)
