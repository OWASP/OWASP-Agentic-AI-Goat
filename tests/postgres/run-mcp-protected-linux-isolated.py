#!/usr/bin/env python3
"""Prepare only by default; actual launch requires an exact one-use root grant."""
import argparse,hashlib,json,os,secrets,shutil,signal,subprocess,tempfile,time,uuid
from pathlib import Path
from mcp_protected_profile_checks import expected_profiles, assert_enforcing, assert_absent
ROOT=Path(__file__).resolve().parents[2]
OWNER='/root/embedding_upgrade_review'
HOST='unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
NODE=Path.home()/'.dvaia/runtimes/node-v26.9.0-darwin-arm64/bin/node'
DOCKER='/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker'
D=[DOCKER,'--host',HOST]
PG_IMAGE='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
BASE_ENV={k:os.environ[k] for k in ('HOME','TMPDIR') if k in os.environ};BASE_ENV['PATH']=str(NODE.parent)+':/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def write(p,v):
 q=p.with_suffix('.pending');q.write_text(json.dumps(v,indent=2)+'\n');q.chmod(0o600);os.replace(q,p)
def run(a,**kw):return subprocess.run(a,check=True,text=True,capture_output=True,timeout=kw.pop('timeout',30),env=kw.pop('env',BASE_ENV),**kw)
def inventory(root):
 return {str(p.relative_to(root)):sha(p) for p in sorted(root.rglob('*')) if p.is_file() and 'node_modules' not in p.parts and not p.is_symlink()}
p=argparse.ArgumentParser();p.add_argument('--prepare',action='store_true');p.add_argument('--plan');p.add_argument('--grant-file');p.add_argument('--grant-id');args=p.parse_args()
if args.prepare:
 w=Path(tempfile.mkdtemp(prefix='dvaia-protected-linux-plan-',dir='/private/tmp'));w.chmod(0o700);source=w/'source'
 code="const fs=require('fs'),path=require('path'),{createCopyFilter}=require('./scripts/lib/isolated-source-copy');for(const n of ['server','db','tests','sidecars','scripts','docs'])fs.cpSync(n,path.join(process.argv[1],n),{recursive:true,filter:createCopyFilter(process.cwd())});for(const n of ['package.json','package-lock.json'])fs.copyFileSync(n,path.join(process.argv[1],n));"
 run([str(NODE),'-e',code,str(source)],cwd=ROOT,timeout=120)
 # Reviewed synthetic hidden fixture is intentionally required by image labfs.
 fixture=Path('sidecars/sandbox-runner/labfs/opt/app/config/.env');shutil.copy2(ROOT/fixture,source/fixture)
 suffix=uuid.uuid4().hex[:12];plan={'postgresImage':PG_IMAGE,'version':1,'owner':OWNER,'dockerHost':HOST,'source':str(source),'evidence':str(w),'sourceHashes':inventory(source),'containers':{'runner':'dvaia-protected-linux-runner-'+suffix,'postgres':'dvaia-protected-linux-pg-'+suffix},'volume':'dvaia-protected-linux-data-'+suffix,'image':'dvaia-protected-linux:'+suffix,'profile':'dvaia-mcp-sandbox-'+suffix,'allowedLaunches':1,'actualModel':False}
 write(w/'plan.json',plan);print(w/'plan.json');raise SystemExit(0)
if not all([args.plan,args.grant_file,args.grant_id]):p.error('prepare first; plan and exact grant required')
planPath=Path(args.plan).resolve();plan=json.loads(planPath.read_text());grantPath=Path(args.grant_file).resolve()
if grantPath!=ROOT/'tasks/native-verification-slot.json':raise SystemExit('canonical grant path required')
w=Path(plan['evidence']);source=Path(plan['source']);label='dvaia.protected.owner';names=plan['containers'];profile=plan['profile'];volume=plan['volume'];image=plan['image']
if sha(Path(__file__))!=plan['sourceHashes'].get(str(Path(__file__).relative_to(ROOT))):raise SystemExit('launcher differs from frozen source')
if sha(Path(__file__).with_name('mcp_protected_profile_checks.py'))!=plan['sourceHashes'].get('tests/postgres/mcp_protected_profile_checks.py'):raise SystemExit('profile helper differs from frozen source')
if plan['owner']!=OWNER or plan['dockerHost']!=HOST or inventory(source)!=plan['sourceHashes']:raise SystemExit('plan/source mismatch')
lock=grantPath.with_suffix('.consume-lock');lock.mkdir(mode=0o700)
try:
 grant=json.loads(grantPath.read_text())
 if any([grant.get('grantId')!=args.grant_id,grant.get('status')!='granted',grant.get('owner')!=OWNER,grant.get('allowedLaunches')!=1,grant.get('planSha256')!=sha(planPath),grant.get('dockerHost')!=HOST]):raise RuntimeError('matching one-use root grant required')
 grant.update(status='consumed',consumerPid=os.getpid(),launcherPid=os.getpid(),evidence=str(w),runStatus='preflight');write(grantPath,grant)
finally:lock.rmdir()
state={'owner':OWNER,'grantId':args.grant_id,'planSha256':sha(planPath),'sourceHashes':plan['sourceHashes'],'actualModel':False,'cleanup':{},'status':'preflight'};created=[];loaded=False;remoteOwned=False;built=False;volumeCreated=False;child=None
sshhost='lima-colima-dvaia-pg-verify';sshconf=str(Path.home()/'.colima/_lima/colima-dvaia-pg-verify/ssh.config');ssh=['ssh','-F',sshconf,sshhost,'--'];remote='/tmp/'+profile;marker=secrets.token_hex(32);(w/'owner-marker').write_text(marker);remoteProfile=remote+'/policy.apparmor';token=secrets.token_urlsafe(32)
def save():write(w/'ownership.json',state)
def stop(*_):raise KeyboardInterrupt()
signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
try:
 if run([str(NODE),'--version']).stdout.strip()!='v26.9.0':raise RuntimeError('exact Node26.9 required')
 # Parent must register this actual launcher process/handle before VM changes.
 for _ in range(600):
  current=json.loads(grantPath.read_text())
  if current.get('consumerPid')==os.getpid() and isinstance(current.get('ownerHandle'),int):break
  time.sleep(.1)
 else:raise RuntimeError('owner handle registration timeout')
 state['ownerHandle']=current['ownerHandle'];save()
 daemon=json.loads(run(D+['info','--format','{{json .}}']).stdout)
 if daemon.get('Name')!='colima-dvaia-pg-verify' or daemon.get('Architecture')!='aarch64':raise RuntimeError('wrong verification daemon')
 for name in names.values():
  if run(D+['ps','-aq','--filter','name=^/'+name+'$']).stdout.strip():raise RuntimeError('container already exists')
 if run(D+['volume','ls','-q','--filter','name=^'+volume+'$']).stdout.strip():raise RuntimeError('volume already exists')
 if run(D+['images','-q',image]).stdout.strip():raise RuntimeError('image already exists')
 if subprocess.run(ssh+['test','-e',remote],capture_output=True,timeout=20,env=BASE_ENV).returncode!=1:raise RuntimeError('remote directory exists')
 if subprocess.run(ssh+['sudo','grep','-F',profile,'/sys/kernel/security/apparmor/profiles'],capture_output=True,timeout=20,env=BASE_ENV).returncode!=1:raise RuntimeError('profile exists')
 profilePath=w/'policy.apparmor';run([str(NODE),str(source/'scripts/render-mcp-sandbox-apparmor.js'),str(source/'sidecars/sandbox-runner/apparmor/dvaia-mcp-sandbox.apparmor.in'),str(profilePath),profile])
 expectedProfileNames=expected_profiles(profilePath.read_text(),profile);state['expectedProfileNames']=sorted(expectedProfileNames);save()
 run(ssh+['mkdir','-m','0700','--',remote]);remoteOwned=True
 run(['scp','-F',sshconf,str(w/'owner-marker'),sshhost+':'+remote+'/owner']);run(['scp','-F',sshconf,str(profilePath),sshhost+':'+remoteProfile]);run(ssh+['sudo','apparmor_parser','--skip-kernel-load',remoteProfile]);loaded=True;state['profileLoadAttempted']=True;save();run(ssh+['sudo','apparmor_parser','-r',remoteProfile]);state['profileLoadConfirmed']=True;save()
 listing=run(ssh+['sudo','cat','/sys/kernel/security/apparmor/profiles']).stdout
 enforce=assert_enforcing(listing,expectedProfileNames,profile)
 state.update(profileSha256=sha(profilePath),profileEnforce=enforce);save()
 built=True
 with (w/'build.log').open('w') as out:subprocess.run(D+['build','--label',label+'='+args.grant_id,'-t',image,str(source/'sidecars/sandbox-runner')],check=True,stdout=out,stderr=subprocess.STDOUT,timeout=600,env=BASE_ENV)
 imageId=run(D+['image','inspect','--format','{{.Id}}',image]).stdout.strip();state['imageId']=imageId
 volumeCreated=True;state['volumeCreationAttempted']=True;save();run(D+['volume','create','--label',label+'='+args.grant_id,volume]);state['volumeCreated']=True;save()
 created.append(names['runner']);state['containerCreationAttempted']=list(created);save();run(D+['run','-d','--pull','never','--name',names['runner'],'--label',label+'='+args.grant_id,'--cpus','2','--memory','768m','--pids-limit','256','--security-opt','seccomp=unconfined','--security-opt','apparmor='+profile,'--mount','type=volume,src='+volume+',dst=/sandbox/owned-targets','-p','127.0.0.1::8090','-e','MCP_OWNED_TARGETS_ENABLED=true','-e','MCP_OWNED_TARGET_TOKEN='+token,'-e','MCP_OWNED_TARGET_APPARMOR_PROFILE='+profile,imageId])
 created.append(names['postgres']);state['containerCreationAttempted']=list(created);save();run(D+['run','-d','--pull','never','--name',names['postgres'],'--label',label+'='+args.grant_id,'--cpus','1','--memory','512m','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size=536870912','-e','POSTGRES_USER=owned_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',PG_IMAGE,'-c','max_connections=60','-c','shared_buffers=16MB','-c','max_wal_size=16MB','-c','min_wal_size=2MB'])
 for key,name in names.items():
  details=json.loads(run(D+['inspect',name]).stdout)[0];host=details['HostConfig'];mounts=details.get('Mounts',[])
  if details['Config']['Labels'].get(label)!=args.grant_id:raise RuntimeError('actual container owner differs')
  if host.get('Privileged') or host.get('CapAdd'):raise RuntimeError('unexpected privilege')
  if key=='runner':
   if details['Image']!=imageId or set(host.get('SecurityOpt',[]))!={'seccomp=unconfined','apparmor='+profile}:raise RuntimeError('runner image/profile differs')
   if len(mounts)!=1 or mounts[0].get('Type')!='volume' or mounts[0].get('Name')!=volume or mounts[0].get('Destination')!='/sandbox/owned-targets':raise RuntimeError('unexpected runner mount')
  elif any(m.get('Type')!='tmpfs' for m in mounts):raise RuntimeError('unexpected PG mount')
  state.setdefault('actualContainers',{})[key]={'id':details['Id'],'image':details['Image'],'memory':host.get('Memory'),'nanoCpus':host.get('NanoCpus'),'pidsLimit':host.get('PidsLimit')}
 save()
 for _ in range(120):
  if subprocess.run(D+['exec',names['postgres'],'pg_isready','-h','127.0.0.1','-U','owned_admin'],capture_output=True,timeout=20,env=BASE_ENV).returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('PG TCP unavailable')
 sql='CREATE ROLE dvaia_identity_migration LOGIN;CREATE ROLE dvaia_identity_runtime LOGIN;CREATE ROLE dvaia_mcp_migration LOGIN;CREATE ROLE dvaia_mcp_runtime LOGIN;CREATE DATABASE dvaia_test_lostack OWNER dvaia_identity_migration;CREATE DATABASE dvaia_test_protected_mcp OWNER dvaia_mcp_migration;'
 run(D+['exec','-i',names['postgres'],'psql','-h','127.0.0.1','-U','owned_admin','-v','ON_ERROR_STOP=1','-d','postgres'],input=sql)
 pgport=run(D+['port',names['postgres'],'5432/tcp']).stdout.strip().rsplit(':',1)[1];port=run(D+['port',names['runner'],'8090/tcp']).stdout.strip().rsplit(':',1)[1]
 (source/'node_modules').symlink_to(ROOT/'node_modules',target_is_directory=True)
 env=dict(BASE_ENV);env.update(NODE_ENV='test',PG_TEST_DISPOSABLE='yes',PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',PROTECTED_LINUX_URL='http://127.0.0.1:'+port,PROTECTED_LINUX_TOKEN=token,PROTECTED_LINUX_CONTAINER=names['runner'],PROTECTED_GRANT_ID=args.grant_id,PROTECTED_IMAGE_ID=imageId,PROTECTED_VOLUME=volume,PROTECTED_PROFILE=profile)
 for key,role,db in [('PG_GRAPH_TEST_RUNTIME_URL','dvaia_identity_runtime','dvaia_test_lostack'),('PG_GRAPH_TEST_MIGRATION_URL','dvaia_identity_migration','dvaia_test_lostack'),('PG_MCP_RUNTIME_URL','dvaia_mcp_runtime','dvaia_test_protected_mcp'),('PG_MCP_MIGRATION_URL','dvaia_mcp_migration','dvaia_test_protected_mcp')]:env[key]=f'postgresql://{role}@127.0.0.1:{pgport}/{db}'
 state['status']='test_running';save()
 with (w/'result.log').open('w') as out:
  child=subprocess.Popen([str(NODE),'--test','tests/postgres/mcpProtectedLinuxRecovery.integration.test.js'],cwd=source,env=env,stdout=out,stderr=subprocess.STDOUT,start_new_session=True);state['childPid']=child.pid;state['childPgid']=os.getpgid(child.pid);save();code=child.wait(timeout=180)
 if code:raise RuntimeError('native cohort failed; inspect private result.log')
 state['status']='passed'
except BaseException as e:state['status']='failed';state['error']=type(e).__name__+': '+str(e)
finally:
 errors=[]
 if child:
  pgid=state.get('childPgid',child.pid)
  def group_alive():
   try:os.killpg(pgid,0);return True
   except ProcessLookupError:return False
  try:
   if group_alive():os.killpg(pgid,signal.SIGTERM)
   try:child.wait(timeout=5)
   except subprocess.TimeoutExpired:pass
   for _ in range(25):
    if not group_alive():break
    time.sleep(.1)
   if group_alive():os.killpg(pgid,signal.SIGKILL)
   child.wait(timeout=5)
   for _ in range(25):
    if not group_alive():break
    time.sleep(.1)
   state['cleanup']['childPidAbsent']=child.poll() is not None
   state['cleanup']['childPgidAbsent']=not group_alive()
   if not all([state['cleanup']['childPidAbsent'],state['cleanup']['childPgidAbsent']]):raise RuntimeError('owned process group remains')
  except Exception as e:errors.append(str(e))
 for name in reversed(created):
  try:
   actual=run(D+['inspect','--format','{{index .Config.Labels "'+label+'"}}',name]).stdout.strip()
   if actual!=args.grant_id:raise RuntimeError('container ownership mismatch')
   
   if state['status']!='passed':
    try:
     log=run(D+['logs','--tail','150',name]);(w/(name+'.log')).write_text(log.stdout+log.stderr)
    except Exception as e:errors.append('container diagnostics: '+str(e))
   run(D+['rm','-f',name]);absent=not run(D+['ps','-aq','--filter','name=^/'+name+'$']).stdout.strip();state['cleanup'][name]=absent
   if not absent:raise RuntimeError('container remains')
  except Exception as e:errors.append(str(e))
 if volumeCreated:
  try:
   if run(D+['volume','inspect','--format','{{index .Labels "'+label+'"}}',volume]).stdout.strip()!=args.grant_id:raise RuntimeError('volume ownership mismatch')
   run(D+['volume','rm',volume]);state['cleanup']['volumeAbsent']=not run(D+['volume','ls','-q','--filter','name=^'+volume+'$']).stdout.strip()
  except Exception as e:errors.append(str(e))
 if volumeCreated and not state['cleanup'].get('volumeAbsent'):errors.append('volume absence not proven')
 if built:
  try:
   if run(D+['image','inspect','--format','{{index .Config.Labels "'+label+'"}}',image]).stdout.strip()!=args.grant_id:raise RuntimeError('image ownership mismatch')
   run(D+['image','rm',image]);state['cleanup']['imageTagAbsent']=not run(D+['images','-q',image]).stdout.strip()
  except Exception as e:errors.append(str(e))
 if built and not state['cleanup'].get('imageTagAbsent'):errors.append('image tag absence not proven')
 if loaded and not errors:
  try:
   run(ssh+['sudo','apparmor_parser','-R',remoteProfile]);listing=run(ssh+['sudo','cat','/sys/kernel/security/apparmor/profiles']).stdout
   state['cleanup']['exactProfileAbsence']=assert_absent(listing,expectedProfileNames,profile);state['cleanup']['profileAbsent']=True
  except Exception as e:errors.append(str(e))
 if loaded and not state['cleanup'].get('profileAbsent'):errors.append('profile absence not proven')
 if remoteOwned and not errors:
  try:
   if run(ssh+['cat',remote+'/owner']).stdout!=marker:raise RuntimeError('remote ownership mismatch')
   run(ssh+['rm','--',remoteProfile,remote+'/owner']);run(ssh+['rmdir','--',remote]);state['cleanup']['remoteAbsent']=subprocess.run(ssh+['test','-e',remote],capture_output=True,timeout=20,env=BASE_ENV).returncode==1
  except Exception as e:errors.append(str(e))
 if remoteOwned and not state['cleanup'].get('remoteAbsent'):errors.append('remote directory absence not proven')
 state['cleanup']['errors']=errors;save();grant=json.loads(grantPath.read_text())
 if grant.get('consumerPid')==os.getpid():grant.update(runStatus=state['status'],cleanup=state['cleanup']);write(grantPath,grant)
 print(str(w/'ownership.json'))
raise SystemExit(0 if state['status']=='passed' and not state['cleanup']['errors'] else 1)
