#!/usr/bin/env python3
"""Explicit owned ARM64 pricing namespace qualification; no installed service/DB/model."""
import argparse,hashlib,json,os,secrets,shlex,signal,subprocess,tempfile,time,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
HOST='unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock'
NODE=Path.home()/'.owasp-ai-goat/runtimes/node-v26.10.0-darwin-arm64/bin/node'
DOCKER='/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker'
BASE='node:26.10.0-slim@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1'
a=argparse.ArgumentParser();a.add_argument('--docker-host',required=True);args=a.parse_args()
if args.docker_host!=HOST:raise SystemExit('reviewed daemon required')
w=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-pricing-http-'));w.chmod(0o700);source=w/'source';nonce=uuid.uuid4().hex[:12]
profile='owasp-ai-goat-owned-pricing-http-'+nonce;container='owasp-ai-goat-pricing-http-'+nonce;tag='owasp-ai-goat-pricing-http:'+nonce
owner=secrets.token_hex(32);remote='/tmp/'+profile;label='owasp-ai-goat.pricing.owner'
D=[DOCKER,'--host',HOST];sshconf=str(Path.home()/'.colima/_lima/colima-owasp-ai-goat-pg-verify/ssh.config');sshhost='lima-colima-owasp-ai-goat-pg-verify'
S=['/usr/bin/ssh','-F',sshconf,sshhost,'--']
env={'HOME':str(Path.home()),'PATH':str(NODE.parent)+':/usr/bin:/bin:/usr/sbin:/sbin','TMPDIR':str(w)}
state={'status':'preparing','evidence':str(w),'container':container,'imageTag':tag,'profile':profile,'owner':owner,'base':BASE,'cleanup':{},'actualModelCalls':0}
remoteOwned=False;profileAttempted=False;buildAttempted=False;createAttempted=False

def run(cmd,**kw):return subprocess.run(cmd,check=True,capture_output=True,text=True,timeout=kw.pop('timeout',30),env=env,**kw)
def remote_run(argv,**kw):return run(S+[shlex.join(argv)],**kw)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save():
 (w/'ownership.json').write_text(json.dumps(state,indent=2)+'\n');(w/'ownership.json').chmod(0o600)
def stop(*_):raise InterruptedError('owned qualification interrupted')
def profiles():return remote_run(['sudo','cat','/sys/kernel/security/apparmor/profiles']).stdout.splitlines()
def profile_rows():return [x for x in profiles() if x.startswith(profile+' ') or x.startswith(profile+'//')]
def absent():return not run(D+['ps','-aq','--filter','name=^/'+container+'$']).stdout.strip()
for sig in [signal.SIGTERM,signal.SIGINT,signal.SIGALRM]:signal.signal(sig,stop)
signal.alarm(480);save()
try:
 if run([str(NODE),'--version']).stdout.strip()!='v26.10.0':raise RuntimeError('exact Node required')
 daemon=json.loads(run(D+['info','--format','{{json .}}']).stdout)
 if daemon['Name']!='colima-owasp-ai-goat-pg-verify' or daemon['Architecture'] not in ['aarch64','arm64']:raise RuntimeError('wrong reviewed daemon/architecture')
 base=json.loads(run(D+['image','inspect',BASE]).stdout)[0]
 if base['Architecture']!='arm64' or not any(x.endswith(BASE.split('@')[1]) for x in base.get('RepoDigests',[])):raise RuntimeError('reviewed immutable base unavailable; no pull')
 state['baseId']=base['Id'];state['baseRepoDigests']=base['RepoDigests'];save()
 if not absent() or run(D+['images','-q',tag]).stdout.strip() or profile_rows():raise RuntimeError('exclusive identity exists')
 exists=subprocess.run(S+[shlex.join(['test','-e',remote])],capture_output=True,timeout=20,env=env).returncode
 if exists!=1:raise RuntimeError('remote identity exists or unreadable')
 run([str(NODE),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(ROOT),str(source)],cwd=ROOT,timeout=120)
 files=list((source/'sidecars/sandbox-runner/owned-pricing-http').glob('*'))+[source/'sidecars/sandbox-runner/mcpSeccompFilter.c',source/'tests/fixtures/secureshopPricingHttpNative.js',source/'tests/postgres/run-pricing-http-isolated.py',source/'server/services/mcp/protocolContext.js']
 files += [source/'server/services'/name for name in ['secureshopPricingHttpClient.js','secureshopOwnedCompetitorObservation.js','secureshopPricingReceipt.js','secureshopPricingContract.js','secureshopPricingExecutionConfig.js']]
 state['sourceSha256']={str(x.relative_to(source)):sha(x) for x in files if x.is_file()};save()
 rendered=run([str(NODE),'-e',"process.stdout.write(require('./sidecars/sandbox-runner/owned-pricing-http/profile').renderOwnedPricingHttpProfile(process.argv[1]))",profile],cwd=source).stdout
 policy=w/'policy.apparmor';policy.write_text(rendered);policy.chmod(0o600);state['profileSha256']=sha(policy);save()
 remote_run(['mkdir','-m','0700','--',remote]);remoteOwned=True
 remote_run(['tee',remote+'/owner'],input=owner+'\n');remote_run(['tee',remote+'/policy'],input=rendered)
 remote_run(['sudo','apparmor_parser','--skip-kernel-load',remote+'/policy'])
 profileAttempted=True;save();remote_run(['sudo','apparmor_parser','-r',remote+'/policy'])
 if sorted(profile_rows())!=sorted([profile+' (enforce)',profile+'//bwrap (enforce)']):raise RuntimeError('dedicated profile not enforcing')
 buildAttempted=True;save()
 with (w/'build.log').open('w') as log:
  subprocess.run(D+['build','--pull=false','--network=default','--label',label+'='+owner,'-f',str(source/'sidecars/sandbox-runner/owned-pricing-http/Dockerfile.native'),'-t',tag,str(source)],check=True,stdout=log,stderr=subprocess.STDOUT,timeout=300,env=env)
 image=json.loads(run(D+['image','inspect',tag]).stdout)[0]
 if image['Architecture']!='arm64' or image['Config']['Labels'].get(label)!=owner:raise RuntimeError('image identity mismatch')
 state['imageId']=image['Id'];save()
 createAttempted=True;save()
 run(D+['create','--pull','never','--name',container,'--label',label+'='+owner,'--memory','512m','--cpus','1','--pids-limit','128','--read-only','--user','10001:10001','--network','none','--cap-drop','ALL','--security-opt','seccomp=unconfined','--security-opt','apparmor='+profile,'--tmpfs','/tmp:rw,nosuid,nodev,size=134217728','-e','PRICING_PROFILE='+profile,image['Id']])
 info=json.loads(run(D+['inspect',container]).stdout)[0];h=info['HostConfig']
 if info['Image']!=image['Id'] or info['Config']['Labels'].get(label)!=owner or info['Config']['User']!='10001:10001' or info['Mounts'] or h['Memory']!=536870912 or h['NanoCpus']!=1000000000 or h['PidsLimit']!=128 or not h['ReadonlyRootfs'] or h['NetworkMode']!='none' or h.get('PortBindings') or h['Privileged'] or h.get('CapAdd') or h['CapDrop']!=['ALL'] or set(h['SecurityOpt'])!={'seccomp=unconfined','apparmor='+profile}:raise RuntimeError('actual isolation mismatch')
 state['containerId']=info['Id'];state['resources']={key:h[key] for key in ['Memory','NanoCpus','PidsLimit','ReadonlyRootfs','NetworkMode','Tmpfs','SecurityOpt','CapDrop']};state['status']='running';save()
 with (w/'run.log').open('w') as log:
  subprocess.run(D+['start','-a',container],check=True,stdout=log,stderr=subprocess.STDOUT,timeout=120,env=env)
 finished=json.loads(run(D+['inspect',container]).stdout)[0]
 if finished['State']['ExitCode']!=0 or finished['State']['Running']:raise RuntimeError('native fixture failed')
 rows=[json.loads(x) for x in (w/'run.log').read_text().splitlines() if x.startswith('{')]
 if not rows or rows[-1].get('status')!='passed':raise RuntimeError('missing native result')
 (w/'result.json').write_text(json.dumps(rows[-1],indent=2)+'\n');state['resultSha256']=sha(w/'result.json');state['status']='passed';save()
except BaseException as error:
 state['status']='failed';state['errorType']=type(error).__name__;state['error']=str(error)[:500];save()
finally:
 signal.alarm(0);signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN);errors=[]
 try:
  if createAttempted and not absent():
   info=json.loads(run(D+['inspect',container]).stdout)[0]
   if info['Config']['Labels'].get(label)!=owner or info['Image']!=state.get('imageId') or state.get('containerId',info['Id'])!=info['Id']:raise RuntimeError('container ownership mismatch')
   run(D+['rm','-f','-v',container])
  state['cleanup']['containerAbsent']=absent()
 except Exception as error:errors.append('container:'+str(error))
 try:
  if buildAttempted and run(D+['images','-q',tag]).stdout.strip():
   image=json.loads(run(D+['image','inspect',tag]).stdout)[0]
   if image['Config']['Labels'].get(label)!=owner or state.get('imageId',image['Id'])!=image['Id']:raise RuntimeError('image ownership mismatch')
   run(D+['image','rm',tag])
  state['cleanup']['imageTagAbsent']=not run(D+['images','-q',tag]).stdout.strip()
  state['cleanup']['imageIdAbsent']=not state.get('imageId') or subprocess.run(D+['image','inspect',state['imageId']],capture_output=True,env=env,timeout=30).returncode!=0
 except Exception as error:errors.append('image:'+str(error))
 try:
  if profileAttempted:
   if not state['cleanup'].get('containerAbsent'):raise RuntimeError('container absence required before profile removal')
   if remote_run(['cat',remote+'/owner']).stdout.strip()!=owner or remote_run(['cat',remote+'/policy']).stdout!=rendered:raise RuntimeError('profile ownership mismatch')
   remote_run(['sudo','apparmor_parser','-R',remote+'/policy'])
  state['cleanup']['profileAbsent']=not profile_rows()
 except Exception as error:errors.append('profile:'+str(error))
 try:
  if remoteOwned:
   if not state['cleanup'].get('profileAbsent') or remote_run(['cat',remote+'/owner']).stdout.strip()!=owner:raise RuntimeError('remote ownership mismatch')
   remote_run(['rm','--',remote+'/policy',remote+'/owner']);remote_run(['rmdir','--',remote])
  state['cleanup']['remoteAbsent']=subprocess.run(S+[shlex.join(['test','-e',remote])],capture_output=True,timeout=20,env=env).returncode==1
 except Exception as error:errors.append('remote:'+str(error))
 state['cleanup']['errors']=errors
 for name in ['build.log','run.log']:
  if (w/name).exists():state[name+'Sha256']=sha(w/name)
 if errors or not all(state['cleanup'].get(k) for k in ['containerAbsent','imageTagAbsent','imageIdAbsent','profileAbsent','remoteAbsent']):state['status']='failed'
 save()
print(json.dumps({'status':state['status'],'evidence':str(w),'cleanup':state['cleanup']}),flush=True)
if state['status']!='passed':raise SystemExit(1)
