"""Disposable multi-target owned System restart manager qualification; no model or application stores."""
import argparse,concurrent.futures,hashlib,http.client,json,os,secrets,shutil,subprocess,tempfile,time,uuid
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--docker-host',required=True);a=p.parse_args();HOST='unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
if a.docker_host!=HOST:p.error('reviewed owned daemon required')
ROOT=Path(__file__).resolve().parents[1];OUT=Path(tempfile.mkdtemp(prefix='dvaia-system-restart-manager-native-')).resolve();OUT.chmod(0o700)
DOCKER=['/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker','--host',HOST];NODE=Path('/Users/averma5/.dvaia/runtimes/node-v26.9.0-darwin-arm64/bin/node');OWNER=uuid.uuid4().hex;PREFIX='dvaia-system-restart-manager-'+OWNER[:12];TAG=PREFIX+':owned';NET=PREFIX+'-bridge';NAME=PREFIX+'-listener';VOLUME=PREFIX+'-state';BASE='sha256:3a771f83944bb763050c23c0225c260638c4b7899e7a72485ef75e5e570499e5';ENV={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':os.environ['HOME'],'TMPDIR':str(OUT)}
state={'status':'preparing','evidence':str(OUT),'owner':OWNER,'tag':TAG,'network':NET,'container':NAME,'volume':VOLUME,'base':BASE,'sourceHashes':{}};child=None;image=None;network=False;container=False;volume=False
def save():(OUT/'result.json').write_text(json.dumps(state,indent=2)+'\n')
def run(x,timeout=30,check=True):
 r=subprocess.run(DOCKER+x,env=ENV,text=True,capture_output=True,timeout=timeout)
 if check and r.returncode:raise RuntimeError('owned docker command failed')
 return r
def inspect(k,n):return json.loads(run([k,'inspect',n]).stdout)[0]
def absent(k,n):return run([k,'inspect',n],check=False).returncode!=0
def request(port,method,path,token,body=None,timeout=15):
 c=http.client.HTTPConnection('127.0.0.1',port,timeout=timeout);headers={'Authorization':'Bearer '+token};payload=None
 if body is not None:payload=json.dumps(body);headers['Content-Type']='application/json'
 c.request(method,path,body=payload,headers=headers);r=c.getresponse();raw=r.read(1024*1024);c.close();return r.status,json.loads(raw)
def members(pid):
 return [int(row.split()[0]) for row in subprocess.check_output(['ps','-axo','pid=,pgid='],text=True).splitlines() if len(row.split())==2 and int(row.split()[1])==pid]
def cleanup():
 errors=[]
 if container and not absent('container',NAME):
  try:run(['stop','--time','25',NAME],timeout=35,check=False);(OUT/'container.log').write_text(run(['logs',NAME],check=False).stdout);run(['rm','-f',NAME])
  except BaseException as e:errors.append('container:'+type(e).__name__)
 if network and not absent('network',NET):
  try:run(['network','rm',NET])
  except BaseException as e:errors.append('network:'+type(e).__name__)
 if volume and not absent('volume',VOLUME):
  try:run(['volume','rm',VOLUME])
  except BaseException as e:errors.append('volume:'+type(e).__name__)
 if image and not absent('image',TAG):
  try:run(['image','rm',TAG])
  except BaseException as e:errors.append('image:'+type(e).__name__)
 state['cleanup']={'errors':errors,'containerAbsent':absent('container',NAME),'networkAbsent':absent('network',NET),'volumeAbsent':absent('volume',VOLUME),'imageTagAbsent':absent('image',TAG),'imageIdAbsent':not state.get('imageId') or absent('image',state['imageId']),'buildPgidAbsent':not child or not members(child.pid)}
 if errors or not all(v for k,v in state['cleanup'].items() if k!='errors'):state['status']='failed'
 save()
save()
try:
 assert run(['info','--format','{{.Name}}']).stdout.strip()=='colima-dvaia-pg-verify';base=inspect('image',BASE);assert base['Architecture']=='arm64'
 ws=OUT/'source';pkg=ws/'sidecars/sandbox-runner/owned-system';pkg.mkdir(parents=True)
 for f in (ROOT/'sidecars/sandbox-runner/owned-system').iterdir():
  if f.is_file():shutil.copy2(f,pkg/f.name)
 state['sourceHashes']={str(f.relative_to(ws)):hashlib.sha256(f.read_bytes()).hexdigest() for f in ws.rglob('*') if f.is_file()};save()
 with (OUT/'build.log').open('w') as log:
  child=subprocess.Popen(DOCKER+['build','--pull=false','--network=default','--label','dvaia.test.owner='+OWNER,'-f','Dockerfile.local','-t',TAG,'.'],cwd=pkg,env=ENV,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);code=child.wait(timeout=300)
 if code:raise RuntimeError('build failed')
 image=inspect('image',TAG);state['imageId']=image['Id'];assert image['Architecture']=='arm64' and image['Config']['Labels']['dvaia.test.owner']==OWNER
 run(['network','create','--label','dvaia.test.owner='+OWNER,NET]);network=True
 run(['volume','create','--label','dvaia.test.owner='+OWNER,VOLUME]);volume=True
 token=secrets.token_urlsafe(32);envfile=OUT/'private.env';envfile.write_text('SECURESHOP_SYSTEM_RESTART_HTTP_ENABLED=true\nSECURESHOP_SYSTEM_RESTART_TOKEN='+token+'\nSECURESHOP_SYSTEM_RESTART_HOST=0.0.0.0\nSECURESHOP_SYSTEM_RESTART_PORT=8090\n');envfile.chmod(0o600)
 run(['run','-d','--pull','never','--name',NAME,'--label','dvaia.test.owner='+OWNER,'--network',NET,'--read-only','--user','10001:10001','--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/tmp:rw,nosuid,nodev,size=128m','--tmpfs','/owned-restart:rw,nosuid,nodev,size=8m,mode=0700,uid=10001,gid=10001','--mount','type=volume,source='+VOLUME+',target=/var/lib/dvaia-owned-restart','--security-opt','seccomp=unconfined','--security-opt','apparmor=dvaia-mcp-sandbox','-p','127.0.0.1::8090','--env-file',str(envfile),image['Id'],'restart']);container=True;envfile.unlink()
 deadline=time.monotonic()+45;port=None
 while time.monotonic()<deadline:
  info=inspect('container',NAME);bindings=(info['NetworkSettings']['Ports'] or {}).get('8090/tcp') or []
  if bindings:
   port=int(bindings[0]['HostPort'])
   try:
    status,health=request(port,'GET','/secureshop/system/restart-health',token)
    if status==200:break
   except OSError:pass
  time.sleep(.1)
 else:raise RuntimeError('readiness failed')
 assert health['restartCapability']=='secureshop-owned-system-restart.v2' and health['limits']=={'maxPersistedTargets':200,'maxResidentTargets':32,'maxConcurrentExecutions':4,'maxQueuedExecutions':16}
 targets=[str(uuid.uuid4()) for _ in range(200)];initial={}
 for target in targets:
  status,value=request(port,'POST','/secureshop/system/restart-target',token,{'targetId':target});assert status==200 and value['resident'] is True;initial[target]=value
 metrics=json.loads(run(['exec',NAME,'node','-e',"const m=require('/opt/dvaia-owned-system/restart-manager');const fs=require('fs');console.log(JSON.stringify({pids:Number(fs.readFileSync('/sys/fs/cgroup/pids.current')),memory:Number(fs.readFileSync('/sys/fs/cgroup/memory.current'))}))"]).stdout)
 assert metrics['pids']<=128 and metrics['memory']<=536870912
 target=targets[0];status,resumed=request(port,'POST','/secureshop/system/restart-target',token,{'targetId':target});assert status==200 and resumed['instanceId']==initial[target]['instanceId'] and resumed['generation']==1
 op=str(uuid.uuid4());status,receipt=request(port,'POST','/secureshop/system/restart',token,{'targetId':target,'request':{'version':1,'operationId':op,'name':'nginx; whoami'}},25)
 state['commandProbe']={'status':status,'receipt':receipt};save()
 assert status==200 and receipt['version']=='secureshop-owned-system-restart-http.v2' and receipt['outputText'].strip()=='owned-system' and hashlib.sha256(receipt['outputText'].encode()).hexdigest()==receipt['outputSha256'] and len(receipt['outputText'].encode())==receipt['outputBytes'] and receipt['afterGeneration']==2
 # Four actual namespaces plus sixteen queued are accepted; the twenty-first is refused categorically.
 def dispatch(pair):
  target_id,operation_id=pair
  return request(port,'POST','/secureshop/system/restart',token,{'targetId':target_id,'request':{'version':1,'operationId':operation_id,'name':'nginx; sleep 2; whoami'}},35)
 pairs=[(targets[i+1],str(uuid.uuid4())) for i in range(21)]
 with concurrent.futures.ThreadPoolExecutor(max_workers=21) as pool:
  futures=[pool.submit(dispatch,pair) for pair in pairs];time.sleep(.4)
  high={'pids':int(run(['exec',NAME,'cat','/sys/fs/cgroup/pids.current']).stdout.strip()),'memory':int(run(['exec',NAME,'cat','/sys/fs/cgroup/memory.current']).stdout.strip())}
  results=[f.result() for f in futures]
 assert high['pids']<=128 and high['memory']<=536870912 and sum(status==429 for status,_ in results)>=1 and all(status in (200,429) for status,_ in results)
 retire_op=str(uuid.uuid4());status,retired=request(port,'POST','/secureshop/system/restart-retire',token,{'targetId':target,'operationId':retire_op});assert status==200 and retired['retired'] is True
 status,recovered=request(port,'POST','/secureshop/system/restart-retirement',token,{'targetId':target,'operationId':retire_op});assert status==200 and recovered['receiptSha256']==retired['receiptSha256'] and recovered['replayed'] is True
 sibling=targets[-1];status,sibling_before=request(port,'POST','/secureshop/system/restart-target',token,{'targetId':sibling});assert status==200
 run(['restart',NAME],timeout=35)
 deadline=time.monotonic()+45
 while time.monotonic()<deadline:
  info=inspect('container',NAME);bindings=(info['NetworkSettings']['Ports'] or {}).get('8090/tcp') or []
  if bindings:port=int(bindings[0]['HostPort'])
  try:
   status,_=request(port,'GET','/secureshop/system/restart-health',token)
   if status==200:break
  except OSError:pass
  time.sleep(.1)
 else:raise RuntimeError('restart readiness failed')
 status,sibling_after=request(port,'POST','/secureshop/system/restart-target',token,{'targetId':sibling});assert status==200 and sibling_after['instanceId']==sibling_before['instanceId'] and sibling_after['generation']==sibling_before['generation']
 status,recovered2=request(port,'POST','/secureshop/system/restart-retirement',token,{'targetId':target,'operationId':retire_op});assert status==200 and recovered2['receiptSha256']==retired['receiptSha256']
 canonical_cleanup_sha256='e'*64;status,forgotten=request(port,'POST','/secureshop/system/restart-forget',token,{'targetId':target,'operationId':retire_op,'canonicalReceiptSha256':canonical_cleanup_sha256});assert status==200 and forgotten=={'version':1,'targetId':target,'operationId':retire_op,'forgotten':True,'replayed':False,'canonicalReceiptSha256':canonical_cleanup_sha256}
 status,forgotten_replay=request(port,'POST','/secureshop/system/restart-forget',token,{'targetId':target,'operationId':retire_op,'canonicalReceiptSha256':canonical_cleanup_sha256});assert status==200 and forgotten_replay['replayed'] is True
 info=inspect('container',NAME);hc=info['HostConfig'];mounts=info['Mounts'];assert info['Config']['User']=='10001:10001' and hc['ReadonlyRootfs'] and hc['Memory']==536870912 and hc['PidsLimit']==128 and len(mounts)==1 and mounts[0]['Name']==VOLUME and mounts[0]['Destination']=='/var/lib/dvaia-owned-restart'
 state['runtime']={'imageArchitecture':image['Architecture'],'outerUser':info['Config']['User'],'memoryLimit':hc['Memory'],'pidsLimit':hc['PidsLimit'],'initialMeasured':metrics,'concurrentMeasured':high,'persistedTargets':200,'residentLimit':32,'acceptedConcurrent':sum(status==200 for status,_ in results),'capacityRefusals':sum(status==429 for status,_ in results)}
 state['receipt']=receipt;state['retirement']=retired;state['retirementForget']={'acknowledgement':forgotten,'replay':forgotten_replay,'authorityBoundary':'private transport mechanics only; canonical cleanup receipt validation is qualified at the backend/storage boundary'};state['durableSibling']={'before':sibling_before,'after':sibling_after};state['status']='passed';save()
except BaseException as e:
 state['status']='failed';state['errorType']=type(e).__name__;state['error']=str(e)[:200];save();raise
finally:cleanup()
print(json.dumps({'status':state['status'],'evidence':str(OUT),'cleanup':state['cleanup']}))
if state['status']!='passed':raise SystemExit(1)
