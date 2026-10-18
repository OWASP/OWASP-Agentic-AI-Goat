"""Owned local System image qualification; no database, model or installed state."""
import argparse,hashlib,json,os,secrets,shutil,signal,subprocess,tempfile,time,uuid
from pathlib import Path
def validate_upload_preview_native(receipt):
 flags=['fullDecodeBounded','sameByteExecution','externalEffectObserved','freshCanaryPerOperation','fixedNoOriginalInterpreter','stdoutForgeryDenied','copiedMarkerDenied','unsafeFileDenied','fifoDenied','timeoutFenced','outputLimitFenced','cleanupEmpty']
 keys=['version','status','scope','controlled','actualModel','genuineCredit','fullFlowQualified','isolation','runtime','cases']+flags
 assert type(receipt) is dict and set(receipt)==set(keys)
 assert type(receipt['version']) is int and receipt['version']==1 and receipt['status']=='passed'
 assert receipt['scope']=='Actual ARM64 owned-system namespace full GIF decode, exact-byte Node preview and externally observed synthetic effect only; no graph, model, Judge or objective credit'
 assert receipt['controlled'] is True and receipt['actualModel'] is False and receipt['genuineCredit'] is False and receipt['fullFlowQualified'] is False
 assert all(receipt[name] is True for name in flags) and receipt['isolation']=='bwrap-upload-preview-v1'
 runtime=receipt['runtime'];assert type(runtime) is dict and set(runtime)=={'nodeVersion','platform','arch'} and runtime['platform']=='linux' and runtime['arch']=='arm64'
 assert type(runtime['nodeVersion']) is str and __import__('re').fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+',runtime['nodeVersion'])
 expected=[('ordinary_gif','image_only'),('valid_dual_format_without_effect','executed'),('same_stored_bytes_external_effect','executed'),('fresh_unpredictable_external_effect','executed'),('fixed_same_original_bytes','fixed_reencoded'),('truncated','invalid_image'),('logical_dimensions','invalid_image'),('multiple_frames','invalid_image'),('stdout_cannot_create_external_effect','executed'),('copied_marker_cannot_match_external_canary','executed'),('bounded_original_interpreter_time','failed'),('bounded_original_interpreter_output','failed')]
 assert type(receipt['cases']) is list and len(receipt['cases'])==len(expected)
 rows={}
 for case,(name,status) in zip(receipt['cases'],expected):
  assert type(case) is dict and set(case)=={'id','request','requestSha256','bodySha256','receipt'} and case['id']==name
  row=case['receipt'];assert type(row) is dict and row['status']==status and row['runtime']==runtime and row['isolation']==receipt['isolation']
  assert row['requestSha256']==case['requestSha256'] and row['bodySha256']==case['bodySha256'] and row['workerAttested'] is True and row['drained'] is True
  for key in ['requestSha256','bodySha256']:assert type(case[key]) is str and __import__('re').fullmatch('[a-f0-9]{64}',case[key])
  assert row['mode']==('fixed' if name=='fixed_same_original_bytes' else 'vuln')
  assert row['codeEffectObserved'] is (name in ['same_stored_bytes_external_effect','fresh_unpredictable_external_effect'])
  assert row['originalInterpreterStarted'] is (status in ['executed','failed'])
  assert row['timedOut'] is (name=='bounded_original_interpreter_time') and row['truncated'] is (name=='bounded_original_interpreter_output')
  rows[name]=row
 attack=rows['same_stored_bytes_external_effect'];fresh=rows['fresh_unpredictable_external_effect'];fixed=rows['fixed_same_original_bytes']
 assert attack['bodySha256']==fresh['bodySha256']==fixed['bodySha256'] and attack['effectSha256']!=fresh['effectSha256']
 assert fixed['scriptSyntaxValid'] is None and fixed['decoder']['rawSha256']==attack['decoder']['rawSha256'] and fixed['reencoded']['bodySha256']!=attack['bodySha256']
 return receipt

parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--docker-host',required=True);parser.add_argument('--upload-preview',action='store_true');parser.add_argument('--plan',action='store_true');args=parser.parse_args()
HOST='unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
if args.docker_host!=HOST:parser.error('reviewed owned Docker daemon required')
SOURCE=Path(__file__).resolve().parents[1]
NODE=Path('/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node')
assert hashlib.sha256(NODE.read_bytes()).hexdigest()=='56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
if args.upload_preview:
 subprocess.run([str(NODE),'-e',"require('./scripts/install/secureshop-owned-system').sourceManifest(process.cwd())"],cwd=SOURCE,check=True,capture_output=True,text=True,timeout=10)
if args.plan:
 package=SOURCE/'sidecars/sandbox-runner/owned-system'
 manifest=json.loads((package/'local-package-manifest.json').read_text())
 for name,digest in manifest['files'].items():
  file=package/name
  assert file.is_file() and not file.is_symlink() and hashlib.sha256(file.read_bytes()).hexdigest()==digest
 print(json.dumps({'plan':True,'mutating':False,'mode':'upload-preview' if args.upload_preview else 'system-local','architecture':'arm64','sourceRoot':str(SOURCE),'packageManifestSha256':hashlib.sha256((package/'local-package-manifest.json').read_bytes()).hexdigest(),'sourceHashes':manifest['files'],'launcherSha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'nodeSha256':hashlib.sha256(NODE.read_bytes()).hexdigest(),'modelCalls':0,'databases':0,'sourceCopy':False if args.upload_preview else 'legacy-default'}))
 raise SystemExit(0)
OUT=Path(tempfile.mkdtemp(prefix='dvaia-system-local-package-')).resolve();OUT.chmod(0o700)
NODE=Path('/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node');DOCKER=['/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker','--host',HOST]
BASE='sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1';OWNER=uuid.uuid4().hex;PREFIX='dvaia-system-package-'+OWNER[:12];TAG=PREFIX+':owned';NETWORK=PREFIX+'-bridge'
ENV={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':os.environ['HOME'],'TMPDIR':str(OUT)}
state={'out':str(OUT),'owner':OWNER,'tag':TAG,'network':NETWORK,'base':BASE,'status':'preparing','sourceHashes':{},'containers':[],'children':[]};handles=[];image=None;network=False;building=False;tokens=[]
def persist():(OUT/'result.json').write_text(json.dumps(state,indent=2)+'\n')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(args,timeout=30,check=True):
 r=subprocess.run(DOCKER+args,env=ENV,capture_output=True,text=True,timeout=timeout)
 if check and r.returncode:raise RuntimeError('owned Docker command failed')
 return r
def inspect(kind,name):return json.loads(run([kind,'inspect',name]).stdout)[0]
def absent(kind,name):
 r=run([kind,'inspect',name],check=False)
 return r.returncode!=0 and ('No such' in r.stderr or 'not found' in r.stderr)
def members(pgid):
 rows=subprocess.check_output(['ps','-axo','pid=,pgid=,uid='],env=ENV,text=True,timeout=5).splitlines();result=[]
 for row in rows:
  fields=row.split()
  if len(fields)==3 and int(fields[1])==pgid:
   if int(fields[2])!=os.getuid():raise RuntimeError('foreign process group')
   result.append(int(fields[0]))
 return result
def join(child):
 child.poll()
 if members(child.pid):os.killpg(child.pid,signal.SIGTERM)
 deadline=time.monotonic()+5
 while members(child.pid) and time.monotonic()<deadline:child.poll();time.sleep(.05)
 if members(child.pid):os.killpg(child.pid,signal.SIGKILL)
 child.wait(timeout=5)
 if members(child.pid):raise RuntimeError('owned process group not drained')
def tracked(command,cwd,environment,log,timeout):
 with log.open('w') as stream:
  child=subprocess.Popen(command,cwd=cwd,env=environment,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True);handles.append(child);state['children'].append(child.pid);persist()
  try:code=child.wait(timeout=timeout)
  finally:join(child)
  if code:raise RuntimeError('owned child failed; inspect retained log')
def remove_container(name):
 if not absent('container',name):
  info=inspect('container',name)
  if info['Config']['Labels'].get('dvaia.test.owner')!=OWNER:raise RuntimeError('foreign container')
  if info['State']['Running']:run(['stop','--time','25',name],timeout=35)
  info=inspect('container',name);state.setdefault('containerExits',{})[name]=info['State']['ExitCode']
  logs=run(['logs',name],check=False);text=logs.stdout+logs.stderr
  for token in tokens:text=text.replace(token,'[REDACTED]')
  (OUT/(name+'.log')).write_text(text)
  run(['rm','-f','-v',name])
 if not absent('container',name):raise RuntimeError('container remains')
def interrupted(signum,frame):raise InterruptedError('owned package qualifier interrupted')
signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted);persist()
try:
 assert sha(Path(DOCKER[0]))=='95fab203ab36bd2b4f3cd8a1d0dc6d084252f2ec224dc76bfbaebe1540cdd15e'
 assert run(['info','--format','{{.ID}}']).stdout.strip()=='2c9da9a7-1f8c-490b-af98-87bbf6bf83db'
 assert run(['info','--format','{{.Name}}']).stdout.strip()=='colima-dvaia-pg-verify'
 base=inspect('image',BASE);assert base['Id']==BASE and base['Architecture']=='arm64'
 assert absent('image',TAG) and absent('network',NETWORK)
 workspace=SOURCE if args.upload_preview else OUT/'source';package=OUT/'package-context' if args.upload_preview else workspace/'sidecars/sandbox-runner/owned-system';package.mkdir(parents=True)
 package_source=SOURCE/'sidecars/sandbox-runner/owned-system'
 if args.upload_preview:
  manifest=json.loads((package_source/'local-package-manifest.json').read_text())
  for name,digest in manifest['files'].items():
   file=package_source/name;assert file.is_file() and not file.is_symlink() and sha(file)==digest
   destination=package/name;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(file,destination)
 else:
  for file in package_source.iterdir():
   if file.is_file():shutil.copy2(file,package/file.name)
  shutil.copytree(package_source/'upload-preview-runtime',package/'upload-preview-runtime')
 for relative in ([] if args.upload_preview else ['server/services/secureshopSystemConfigClient.js','server/services/secureshopSystemDiagnosticClient.js','tests/fixtures/secureshopSystemLocalPackageNative.js','tests/run-system-local-package-native-isolated.py']):
  dest=workspace/relative;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(SOURCE/relative,dest)
 state['sourceHashes']=({str((package_source/name).relative_to(SOURCE)):sha(package_source/name) for name in manifest['files']} if args.upload_preview else {str(p.relative_to(workspace)):sha(p) for p in workspace.rglob('*') if p.is_file()});state['sourceCopy']=not args.upload_preview;
 if args.upload_preview:state['sourceHashes']['tests/run-system-local-package-native-isolated.py']=sha(SOURCE/'tests/run-system-local-package-native-isolated.py');state['sourceHashes']['sidecars/sandbox-runner/owned-system/local-package-manifest.json']=sha(package_source/'local-package-manifest.json');state['sourceHashes']['scripts/install/secureshop-owned-system.js']=sha(SOURCE/'scripts/install/secureshop-owned-system.js')
 state['nodeSha256']=sha(NODE);persist()
 build_secrets=[]
 if args.upload_preview:
  certificates=''
  for keychain in ['/Library/Keychains/System.keychain',str(Path.home()/'Library/Keychains/login.keychain-db')]:
   result=subprocess.run(['/usr/bin/security','find-certificate','-a','-p',keychain],env=ENV,capture_output=True,text=True,timeout=30,check=True);certificates+=result.stdout
  if '-----BEGIN CERTIFICATE-----' not in certificates or len(certificates.encode())>1048576:raise RuntimeError('Bounded build CA unavailable')
  ca=OUT/'build-ca.pem';ca.write_text(certificates);ca.chmod(0o600);state['buildCaSha256']=sha(ca);persist();build_secrets=['--secret','id=npm_ca,src='+str(ca)]
 building=True
 tracked(DOCKER+['build',*build_secrets,'--pull=false','--network=default','--label','dvaia.test.owner='+OWNER,'-f','Dockerfile.local','-t',TAG,'.'],package,ENV,OUT/'build.log',300)
 image=inspect('image',TAG);assert image['Config']['Labels'].get('dvaia.test.owner')==OWNER;assert image['Architecture']=='arm64';state['imageId']=image['Id'];persist()
 if not args.upload_preview:
  network=True;run(['network','create','--label','dvaia.test.owner='+OWNER,NETWORK]);ni=inspect('network',NETWORK);assert ni['Internal'] is False and ni['Labels'].get('dvaia.test.owner')==OWNER
 state['outerEgressIsolationEstablished']=args.upload_preview
 for mode in (['upload-preview-native'] if args.upload_preview else ['invalid','missing-enable','config','diagnostic']):
  name=PREFIX+'-'+mode;assert absent('container',name);state['containers'].append(name);persist();token=secrets.token_urlsafe(32);tokens.append(token)
  if args.upload_preview:
   run(['run','--detach','--pull','never','--name',name,'--label','dvaia.test.owner='+OWNER,'--network','none','--read-only','--user','10001:10001','--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/tmp:rw,nosuid,nodev,size=128m','--tmpfs','/var/lib/dvaia-owned-upload-preview:rw,nosuid,nodev,size=32m,mode=0700,uid=10001,gid=10001','--security-opt','seccomp=unconfined','--security-opt','apparmor=dvaia-mcp-sandbox','--env','UPLOAD_PREVIEW_NATIVE_QUALIFICATION=1','--entrypoint','/usr/local/bin/node',image['Id'],'/opt/dvaia-owned-system/upload-preview-native-qualification.js'])
   actual=inspect('container',name);hc=actual['HostConfig']
   assert actual['Config']['User']=='10001:10001' and hc['ReadonlyRootfs'] is True and hc['NetworkMode']=='none' and not actual.get('Mounts') and hc['Memory']==536870912 and hc['NanoCpus']==1000000000 and hc['PidsLimit']==128
   code=run(['wait',name],timeout=180).stdout.strip();logs=run(['logs',name],check=False)
   (OUT/'upload-preview-native.log').write_text(logs.stdout+logs.stderr)
   if code!='0':raise RuntimeError('owned upload preview native failed; inspect retained log')
   receipt=validate_upload_preview_native(json.loads(logs.stdout))
   subprocess.run([str(NODE),'-e',"const C=require('./sidecars/sandbox-runner/owned-system/upload-preview-contract');const r=JSON.parse(require('node:fs').readFileSync(0,'utf8'));for(const c of r.cases){C.validateUploadPreviewReceipt(c.receipt,c.request);require('node:assert/strict').equal(C.requestDigest(c.request),c.requestSha256);require('node:assert/strict').equal(c.request.bodySha256,c.bodySha256)}"],cwd=SOURCE,env=ENV,input=logs.stdout,capture_output=True,text=True,check=True,timeout=10)
   state['modes']={'upload-preview':receipt};remove_container(name);persist();continue
  private=OUT/'private.env';private.touch(mode=0o600)
  if mode in ['config','diagnostic']:
   prefix='SECURESHOP_SYSTEM_'+mode.upper();private.write_text(prefix+'_HTTP_ENABLED=true\n'+prefix+'_TOKEN='+token+'\n'+prefix+'_HOST=0.0.0.0\n'+prefix+'_PORT=8090\n')
  commandMode='config' if mode=='missing-enable' else mode
  run(['run','--detach','--pull','never','--name',name,'--label','dvaia.test.owner='+OWNER,'--network',NETWORK,'--read-only','--user','10001:10001','--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/tmp:rw,nosuid,nodev,size=128m','--security-opt','seccomp=unconfined','--security-opt','apparmor=dvaia-mcp-sandbox','-p','127.0.0.1::8090','--env-file',str(private),image['Id'],commandMode]);private.unlink()
  deadline=time.monotonic()+5
  while True:
   actual=inspect('container',name);ports=actual['NetworkSettings']['Ports'] or {};bindings=ports.get('8090/tcp') or []
   if bindings or not actual['State']['Running'] or time.monotonic()>=deadline:break
   time.sleep(.1)
  hc=actual['HostConfig'];assert not actual.get('Mounts') and actual['Config']['User']=='10001:10001' and hc['ReadonlyRootfs'] is True and hc['Memory']==536870912 and hc['NanoCpus']==1000000000 and hc['PidsLimit']==128
  assert set(actual['NetworkSettings']['Networks'])=={NETWORK};assert hc['PortBindings']=={'8090/tcp':[{'HostIp':'127.0.0.1','HostPort':''}]}
  if mode in ['invalid','missing-enable']:
   exitcode=run(['wait',name],timeout=10).stdout.strip();assert exitcode=='1';log=run(['logs',name]).stdout;assert 'READY' not in log
   state.setdefault('negativeModes',{})[mode]={'exitCode':1,'noReadyMarker':True}
  else:
   assert len(bindings)==1 and bindings[0]['HostIp']=='127.0.0.1';url='http://127.0.0.1:'+bindings[0]['HostPort']
   # The fixed listener starts only after its bounded actual readiness probe.
   import http.client
   ready_deadline=time.monotonic()+40
   while time.monotonic()<ready_deadline:
    connection=http.client.HTTPConnection('127.0.0.1',int(bindings[0]['HostPort']),timeout=2)
    try:
     endpoint='/secureshop/system/health' if mode=='config' else '/secureshop/system/diagnostic-health';connection.request('GET',endpoint,headers={'Authorization':'Bearer '+token});response=connection.getresponse();response.read(32769)
     if response.status==200:break
    except (OSError,http.client.HTTPException):pass
    finally:connection.close()
    time.sleep(.1)
   else:raise RuntimeError('listener readiness timed out')
   output=OUT/(mode+'-result.json');childenv={**ENV,'OWNED_PACKAGE_MODE':mode,'OWNED_PACKAGE_URL':url,'OWNED_PACKAGE_TOKEN':token,'OWNED_PACKAGE_RESULT':str(output)}
   tracked([str(NODE),'tests/fixtures/secureshopSystemLocalPackageNative.js'],workspace,childenv,OUT/(mode+'-client.log'),25)
   state.setdefault('modes',{})[mode]=json.loads(output.read_text())
   run(['cp',name+':/opt/dvaia-owned-system/packages.txt',str(OUT/'packages.txt')]);state['packagesSha256']=sha(OUT/'packages.txt')
  remove_container(name);persist()
 state['sourceUnchanged']=all(sha(SOURCE/name)==digest for name,digest in state['sourceHashes'].items()) if args.upload_preview else True
 state['nodeUnchanged']=sha(NODE)==state['nodeSha256']
 assert state['sourceUnchanged'] and state['nodeUnchanged']
 state['status']='passed'
except BaseException as error:
 state['status']='failed';state['errorType']=type(error).__name__;persist();raise
finally:
 signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN);errors=[]
 for child in handles:
  try:join(child)
  except BaseException as error:errors.append('process:'+type(error).__name__)
 for name in state['containers']:
  try:remove_container(name)
  except BaseException as error:errors.append('container:'+type(error).__name__)
 if network:
  try:
   if not absent('network',NETWORK):
    assert inspect('network',NETWORK)['Labels'].get('dvaia.test.owner')==OWNER;run(['network','rm',NETWORK])
  except BaseException as error:errors.append('network:'+type(error).__name__)
 if building:
  try:
   if not absent('image',TAG):
    actual=inspect('image',TAG);assert actual['Config']['Labels'].get('dvaia.test.owner')==OWNER;state['imageId']=actual['Id'];run(['image','rm',TAG])
  except BaseException as error:errors.append('image:'+type(error).__name__)
 private=OUT/'private.env'
 if private.exists():private.unlink()
 ca=OUT/'build-ca.pem'
 if ca.exists():
  st=ca.lstat()
  if not ca.is_symlink() and st.st_uid==os.getuid() and st.st_nlink==1 and st.st_mode&0o777==0o600 and sha(ca)==state.get('buildCaSha256'):ca.unlink()
  else:errors.append('build-ca:identity-changed')
 state['cleanup']={'errors':errors,'containersAbsent':all(absent('container',n) for n in state['containers']),'networkAbsent':absent('network',NETWORK),'imageTagAbsent':absent('image',TAG),'imageIdAbsent':not state.get('imageId') or absent('image',state['imageId']),'pgidsAbsent':all(not members(c.pid) for c in handles),'buildCaAbsent':not ca.exists()}
 if errors or not all(v for k,v in state['cleanup'].items() if k!='errors'):state['status']='failed'
 persist()
print(json.dumps({'evidence':str(OUT),'status':state['status'],'cleanup':state['cleanup']}),flush=True)
if state['status']!='passed':raise SystemExit(1)
