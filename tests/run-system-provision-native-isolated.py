"""Single owned local System provisioning rehearsal; no installed activation."""
import argparse,hashlib,json,os,re,shutil,signal,subprocess,tempfile,time
from pathlib import Path
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--docker-host',required=True);parser.add_argument('--activate',action='store_true');args=parser.parse_args()
HOST='unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
if args.docker_host!=HOST:parser.error('reviewed explicit Docker authority required')
SOURCE=Path(__file__).resolve().parents[1];OUT=Path(tempfile.mkdtemp(prefix='dvaia-system-provision-native-')).resolve();OUT.chmod(0o700);WORK=OUT/'source';WORK.mkdir()
NODE=Path('/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node');CLI=Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker');DOCKER=[str(CLI),'--host',HOST]
ENV={'PATH':str(NODE.parent)+':'+str(CLI.parent)+':/usr/bin:/bin','HOME':'/Users/averma5','TMPDIR':str(OUT)}
state={'version':1,'out':str(OUT),'status':'preparing','sourceHashes':{},'cleanup':{},'resources':{'buildSeconds':300,'parentSeconds':900,'listenerCount':3,'eachMemoryBytes':536870912,'eachCpu':1,'eachPids':128,'baseTmpfsBytes':134217728,'restartExtraTmpfsBytes':16777216,'drainSeconds':25},'installedActivation':False,'activationAdapterGate':args.activate};child=None

def persist():(OUT/'result.json').write_text(json.dumps(state,indent=2)+'\n')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def docker(args,check=True):
 r=subprocess.run(DOCKER+args,env=ENV,capture_output=True,text=True,timeout=40)
 if check and r.returncode:raise RuntimeError('Docker command failed')
 return r
def inspect(kind,name):
 r=docker([kind,'inspect',name],False)
 if r.returncode:
  if 'No such' in r.stderr or 'not found' in r.stderr:return None
  raise RuntimeError('ambiguous Docker inspection')
 return json.loads(r.stdout)[0]
def copy(relative):
 src=SOURCE/relative;dst=WORK/relative;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)
def closure(relative):
 if (WORK/relative).exists():return
 copy(relative)
 if Path(relative).suffix not in ['.js','.cjs']:return
 for name in re.findall(r"require\(['\"]([^'\"]+)['\"]\)",(SOURCE/relative).read_text()):
  if name.startswith('node:') or name in ['fs','path','os','crypto','child_process','util','net','http','https','stream','events']:continue
  if name.startswith('.'):
   p=(SOURCE/relative).parent/name
   if not p.suffix:p=p.with_suffix('.js')
   if not p.is_file():raise RuntimeError('unresolved relative dependency '+name)
   closure(str(p.resolve().relative_to(SOURCE)))
  else:
   package=name.split('/')[0] if not name.startswith('@') else '/'.join(name.split('/')[:2]);src=SOURCE/'node_modules'/package;dst=WORK/'node_modules'/package
   if not dst.exists():shutil.copytree(src,dst,symlinks=False)
def group_alive(pid):
 r=subprocess.run(['ps','-axo','pgid='],capture_output=True,text=True,timeout=5);return str(pid) in r.stdout.split()
def join():
 if not child:return
 child.poll()
 if group_alive(child.pid):os.killpg(child.pid,signal.SIGTERM)
 deadline=time.monotonic()+5
 while group_alive(child.pid) and time.monotonic()<deadline:child.poll();time.sleep(.05)
 if group_alive(child.pid):os.killpg(child.pid,signal.SIGKILL)
 child.wait(timeout=5)
 if group_alive(child.pid):raise RuntimeError('process group remains')
def interrupted(signum,frame):raise InterruptedError('qualification interrupted')
signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted);persist()
try:
 assert docker(['info','--format','{{.Name}}']).stdout.strip()=='colima-dvaia-pg-verify'
 closure('tests/fixtures/secureshopSystemProvisionNative.js')
 closure('scripts/install/secureshop-owned-system-activate.js')
 closure('server/services/secureshopSystemManagedEnvironment.js')
 for p in (SOURCE/'sidecars/sandbox-runner/owned-system').iterdir():
  if p.is_file():copy(str(p.relative_to(SOURCE)))
 copy('sidecars/sandbox-runner/apparmor/dvaia-mcp-sandbox.apparmor.in');copy('tests/run-system-provision-native-isolated.py')
 for relative in ['scripts/setup-application.js','scripts/start-application.js','server/index.js']:copy(relative)
 state['sourceHashes']={str(p.relative_to(WORK)):sha(p) for p in WORK.rglob('*') if p.is_file()};state['nodeSha256']=sha(NODE)
 wid=hashlib.sha256(str(WORK.resolve()).encode()).hexdigest()[:12];state['workspaceId']=wid;private=Path('/Users/averma5/.dvaia')/wid
 assert not private.exists();state['privateDirectory']=str(private);state['containers']=[f'dvaia-owned-system-{wid}-{m}' for m in ['config','diagnostic','restart']];state['network']=f'dvaia-owned-system-{wid}-bridge';state['imageTag']=f'dvaia-owned-system-{wid}:local'
 for name in state['containers']:assert inspect('container',name) is None
 assert inspect('network',state['network']) is None and inspect('image',state['imageTag']) is None
 persist();env={**ENV,'SYSTEM_PROVISION_NATIVE':'1','SYSTEM_PROVISION_NATIVE_OUT':str(OUT),'SYSTEM_PROVISION_ACTIVATION':'1' if args.activate else '0'}
 with (OUT/'fixture.log').open('w') as log:
  child=subprocess.Popen([str(NODE),'tests/fixtures/secureshopSystemProvisionNative.js'],cwd=WORK,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);state['pgid']=child.pid;state['status']='running';persist();code=child.wait(timeout=650)
 join();fixture=json.loads((OUT/'fixture-result.json').read_text());state['fixture']=fixture
 if code or fixture['status']!='passed':raise RuntimeError('native fixture failed')
 state['status']='passed'
except BaseException as error:
 state['status']='failed';state['errorType']=type(error).__name__
finally:
 signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN);errors=[]
 try:join();state['cleanup']['processGroupAbsent']=True
 except BaseException as error:errors.append('process:'+type(error).__name__)
 fixture={}
 if (OUT/'fixture-result.json').exists():
  fixture=json.loads((OUT/'fixture-result.json').read_text());state['fixture']=fixture
 expected={'dvaia.system.workspace':state.get('workspaceId'),'dvaia.system.authority':fixture.get('authoritySha256'),'dvaia.system.source':fixture.get('sourceSha256')}
 def owned(labels):return all(v is not None and labels.get(k)==v for k,v in expected.items())
 for name in state.get('containers',[]):
  try:
   c=inspect('container',name)
   if c:
    assert owned(c['Config']['Labels']);assert c['Name']=='/'+name
    if fixture.get('containerIds',{}).get(name):assert c['Id']==fixture['containerIds'][name]
    if c['State']['Running']:docker(['stop','--time','25',c['Id']])
    docker(['rm',c['Id']])
   assert inspect('container',name) is None;state['cleanup'][name]='absent'
  except BaseException as error:errors.append('container:'+name+':'+type(error).__name__)
 try:
  name=state.get('network');n=inspect('network',name) if name else None
  if n:assert owned(n['Labels']);docker(['network','rm',n['Id']])
  if name:assert inspect('network',name) is None
  state['cleanup']['networkAbsent']=True
 except BaseException as error:errors.append('network:'+type(error).__name__)
 try:
  tag=state.get('imageTag');i=inspect('image',tag) if tag else None
  if i:
   assert owned(i['Config']['Labels']);state['imageId']=i['Id'];docker(['image','rm',tag]);assert inspect('image',i['Id']) is None
  state['cleanup']['imageAbsent']=True
 except BaseException as error:errors.append('image:'+type(error).__name__)
 try:
  private=Path(state['privateDirectory']) if state.get('privateDirectory') else None
  if private and private.exists():
   st=private.lstat();identity=fixture.get('privateIdentity');assert identity and st.st_dev==identity['dev'] and st.st_ino==identity['ino'] and st.st_uid==os.getuid() and not private.is_symlink()
   allowed={'local-docker.json','secureshop-owned-system.json','secureshop-qualified.env','secureshop-mcp-targets','secureshop-ssrf-targets'};assert set(p.name for p in private.iterdir())<=allowed
   for p in private.iterdir():
    stat=p.lstat();assert not p.is_symlink() and stat.st_uid==os.getuid()
    if p.name in ['secureshop-mcp-targets','secureshop-ssrf-targets']:
     assert p.is_dir() and not list(p.iterdir());p.rmdir()
    else:
     assert p.is_file() and stat.st_nlink==1;p.unlink()
   private.rmdir()
  state['cleanup']['privateDirectoryAbsent']=not(private and private.exists())
 except BaseException as error:errors.append('private:'+type(error).__name__)
 state['cleanup']['errors']=errors;state['cleanup']['clean']=not errors;persist()
print(json.dumps({'out':str(OUT),'status':state['status'],'cleanup':state['cleanup']['clean']}))
raise SystemExit(0 if state['status']=='passed' and not errors else 1)
