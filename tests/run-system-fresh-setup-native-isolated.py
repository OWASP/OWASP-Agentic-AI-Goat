"""Owned16-store fresh combined setup prerequisite-present qualification; no installed application changes."""
import argparse,hashlib,json,os,re,shutil,signal,subprocess,tempfile,time
from pathlib import Path
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--docker-host',required=True);args=parser.parse_args()
HOST='unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock'
if args.docker_host!=HOST:parser.error('reviewed explicit Docker authority required')
SOURCE=Path(__file__).resolve().parents[1];OUT=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-system-fresh-setup-')).resolve();OUT.chmod(0o700);WORK=OUT/'source';WORK.mkdir()
NODE=Path('/Users/averma5/.owasp-ai-goat/runtimes/node-v26.9.0-darwin-arm64/bin/node');CLI=Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker');DOCKER=[str(CLI),'--host',HOST]
ENV={'PATH':str(NODE.parent)+':'+str(CLI.parent)+':/usr/local/bin:/usr/bin:/bin','HOME':'/Users/averma5','TMPDIR':str(OUT)}
state={'version':1,'out':str(OUT),'status':'preparing','sourceHashes':{},'cleanup':{},'resources':{'buildSeconds':300,'parentSeconds':1200,'listenerCount':2,'eachMemoryBytes':536870912,'eachCpu':1,'eachPids':128,'eachTmpfsBytes':134217728,'drainSeconds':25},'installedActivation':False,'freshPrerequisitesPresentGate':True};child=None

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
signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted);signal.signal(signal.SIGALRM,interrupted);signal.alarm(1200);persist()
try:
 # Read-only preflight: model must already exist; no pull/profile installation.
 assert subprocess.run(['/usr/local/bin/ollama','show','llama3.1:8b'],env={**ENV,'OLLAMA_HOST':'http://127.0.0.1:11434'},capture_output=True,timeout=15).returncode==0
 cache_source=Path('/Users/averma5/.owasp-ai-goat/c231599fa8cd/model-cache/Xenova/all-MiniLM-L6-v2')
 assert cache_source.is_dir() and (cache_source/'onnx/model_quantized.onnx').is_file()
 cache=OUT/'embedding-cache';target=cache/'Xenova/all-MiniLM-L6-v2';target.parent.mkdir(parents=True)
 state['embeddingSourceHashes']={str(p.relative_to(cache_source)):sha(p) for p in cache_source.rglob('*') if p.is_file()}
 shutil.copytree(cache_source,target,symlinks=False)
 state['cacheIdentity']={'dev':cache.stat().st_dev,'ino':cache.stat().st_ino}
 assert state['embeddingSourceHashes']=={str(p.relative_to(target)):sha(p) for p in target.rglob('*') if p.is_file()}
 browser=Path('/Users/averma5/.cache/puppeteer/chrome-headless-shell/mac_arm-153.0.8010.36/chrome-headless-shell-mac-arm64/chrome-headless-shell');assert browser.is_file()
 state['browserSha256']=sha(browser)
 shim=OUT/'bin';shim.mkdir();ollama=shim/'ollama';ollama.write_text('#!/bin/sh\nif [ "$1" != show ]; then exit 91; fi\nexec /usr/local/bin/ollama "$@"\n');ollama.chmod(0o700);ENV['PATH']=str(shim)+':'+ENV['PATH']
 assert docker(['info','--format','{{.Name}}']).stdout.strip()=='colima-owasp-ai-goat-pg-verify'
 subprocess.run([str(NODE),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(SOURCE),str(WORK)],cwd=SOURCE,env=ENV,check=True,timeout=60)
 (WORK/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
 (WORK/'client/node_modules').symlink_to(SOURCE/'client/node_modules',target_is_directory=True)
 state['sourceHashes']={str(p.relative_to(WORK)):sha(p) for p in WORK.rglob('*') if p.is_file()};state['nodeSha256']=sha(NODE)
 wid=hashlib.sha256(str(WORK.resolve()).encode()).hexdigest()[:12];state['workspaceId']=wid;private=Path('/Users/averma5/.owasp-ai-goat')/wid
 assert not private.exists();state['privateDirectory']=str(private);state['containers']=[f'owasp-ai-goat-owned-system-{wid}-{m}' for m in ['config','diagnostic']];state['network']=f'owasp-ai-goat-owned-system-{wid}-bridge';state['imageTag']=f'owasp-ai-goat-owned-system-{wid}:local'
 for name in state['containers']:assert inspect('container',name) is None
 assert inspect('network',state['network']) is None and inspect('image',state['imageTag']) is None
 pg_name='owasp-ai-goat-system-supported-pg-'+wid;state['postgresContainer']=pg_name;persist()
 assert inspect('container',pg_name) is None
 pg_image='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
 assert inspect('image',pg_image)['Id']==pg_image
 docker(['run','--detach','--pull','never','--name',pg_name,'--label','owasp-ai-goat.test.workspace='+wid,'--memory','1g','--cpus','2','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size=1073741824','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',pg_image,'-c','shared_buffers=16MB','-c','max_connections=100','-c','max_wal_size=16MB','-c','min_wal_size=4MB'])
 pg=inspect('container',pg_name);assert not pg.get('Mounts') and pg['Config']['Labels']['owasp-ai-goat.test.workspace']==wid;state['postgresId']=pg['Id'];persist()
 for _ in range(100):
  if docker(['exec',pg_name,'pg_isready','-h','127.0.0.1','-U','postgres'],False).returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('PG readiness deadline')
 pg_port=inspect('container',pg_name)['NetworkSettings']['Ports']['5432/tcp'][0]['HostPort'];pg_url='postgresql://postgres@127.0.0.1:'+pg_port+'/postgres'
 # Build only the existing review renderer; the supported frontend starts Vite.
 with (OUT/'review-build.log').open('w') as log:
  build=subprocess.Popen([str(NODE),str(WORK/'client/node_modules/vite/bin/vite.js'),'build','--config','vite.review-renderer.config.mjs'],cwd=WORK/'client',env={**ENV,'NODE_OPTIONS':'--max-old-space-size=1024'},stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  state['buildPgid']=build.pid;persist()
  try:assert build.wait(timeout=120)==0
  finally:
   if build.poll() is None:os.killpg(build.pid,signal.SIGKILL);build.wait(timeout=5)
 persist();env={**ENV,'SYSTEM_PROVISION_NATIVE':'1','SYSTEM_PROVISION_NATIVE_OUT':str(OUT),'SYSTEM_STARTUP_PG_ADMIN_URL':pg_url,'SYSTEM_FRESH_EMBEDDING_CACHE':str(cache),'SYSTEM_FRESH_BROWSER':str(browser)}
 with (OUT/'fixture.log').open('w') as log:
  child=subprocess.Popen([str(NODE),'tests/fixtures/secureshopSystemFreshSetupNative.js'],cwd=WORK,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);state['pgid']=child.pid;state['status']='running';persist();deadline=time.monotonic()+900
  while child.poll() is None:
   if time.monotonic()>deadline:raise TimeoutError('supported fixture deadline')
   time.sleep(.2)
  code=child.returncode
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
 for pgid in fixture.get('ownedProcessGroups',[]):
  if pgid==state.get('pgid'):continue
  try:
   if group_alive(pgid):
    rows=subprocess.check_output(['ps','-axo','pgid=,uid='],text=True,timeout=5).splitlines()
    assert all(int(r.split()[1])==os.getuid() for r in rows if r.split() and int(r.split()[0])==pgid)
    os.killpg(pgid,signal.SIGTERM);deadline=time.monotonic()+5
    while group_alive(pgid) and time.monotonic()<deadline:time.sleep(.05)
    if group_alive(pgid):os.killpg(pgid,signal.SIGKILL)
   assert not group_alive(pgid)
  except BaseException as error:errors.append('application-group:'+str(pgid)+':'+type(error).__name__)
 expected={'owasp-ai-goat.system.workspace':state.get('workspaceId'),'owasp-ai-goat.system.authority':fixture.get('authoritySha256'),'owasp-ai-goat.system.source':fixture.get('sourceSha256')}
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
  pg_name=state.get('postgresContainer');pg=inspect('container',pg_name) if pg_name else None
  if pg:
   assert pg['Config']['Labels'].get('owasp-ai-goat.test.workspace')==state['workspaceId']
   if state.get('postgresId'):assert pg['Id']==state['postgresId']
   docker(['rm','--force',pg['Id']])
  if pg_name:assert inspect('container',pg_name) is None
  state['cleanup']['postgresAbsent']=True
 except BaseException as error:errors.append('postgres:'+type(error).__name__)
 try:
  if errors:raise RuntimeError('Preserve private authority records until exact resource cleanup succeeds')
  private=Path(state['privateDirectory']) if state.get('privateDirectory') else None
  if private and private.exists():
   st=private.lstat();identity=fixture.get('privateIdentity');assert identity and st.st_dev==identity['dev'] and st.st_ino==identity['ino'] and st.st_uid==os.getuid() and not private.is_symlink()
   secrets=[]
   manifest=private/'provisioning.json'
   if manifest.exists():
    for url in json.loads(manifest.read_text()).get('configuration',{}).values():
     from urllib.parse import urlparse
     secrets.extend([url,urlparse(url).password or ''])
   administrator=private/'administrator.json'
   if administrator.exists():secrets.append(json.loads(administrator.read_text()).get('password',''))
   managed=private/'secureshop-owned-system.json'
   if managed.exists():
    record=json.loads(managed.read_text());secrets.extend([record['config']['token'],record['diagnostic']['token']])
   for logfile in OUT.glob('*.log'):
    text=logfile.read_text(errors='replace')
    for secret in secrets:
     if secret:text=text.replace(secret,'[REDACTED]')
    logfile.write_text(text)
   if (WORK/'.env').exists():(WORK/'.env').unlink()
   allowed={'local-docker.json','secureshop-owned-system.json','secureshop-qualified.env','secureshop-mcp-targets','secureshop-ssrf-targets','provisioning.json','secureshop-reset-key.json','administrator.json'};assert set(p.name for p in private.iterdir())<=allowed
   for p in private.iterdir():
    stat=p.lstat();assert not p.is_symlink() and stat.st_uid==os.getuid()
    if p.name in ['secureshop-mcp-targets','secureshop-ssrf-targets']:
     assert p.is_dir() and not list(p.iterdir());p.rmdir()
    else:
     assert p.is_file() and stat.st_nlink==1;p.unlink()
   private.rmdir()
  state['cleanup']['privateDirectoryAbsent']=not(private and private.exists())
 except BaseException as error:errors.append('private:'+type(error).__name__)
 try:
  cache=OUT/'embedding-cache'
  if cache.exists():
   st=cache.lstat();assert not cache.is_symlink() and state['cacheIdentity']=={'dev':st.st_dev,'ino':st.st_ino};shutil.rmtree(cache)
  state['cleanup']['ownedEmbeddingCacheAbsent']=not cache.exists()
 except BaseException as error:errors.append('cache:'+type(error).__name__)
 signal.alarm(0)
 state['cleanup']['errors']=errors;state['cleanup']['clean']=not errors;persist()
print(json.dumps({'out':str(OUT),'status':state['status'],'cleanup':state['cleanup']['clean']}))
raise SystemExit(0 if state['status']=='passed' and not errors else 1)
