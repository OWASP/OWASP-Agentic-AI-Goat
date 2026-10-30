'use strict';
// Fixed guest publication only. This does not authorize host dispatch or runtime
// startup; the authenticated builder must supply its observed image identity.
const fail=code=>Object.assign(new Error(code),{code});
const lease=require('./ownedPricingRuntimeLease');
function program({runId,ownerId,packageSha256,imageId,sharedDaemonId},profile='v33'){
 const p=lease.profile(profile);
 if(!/^[a-f0-9]{32}$/.test(runId)||!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(ownerId)||
  !/^[a-f0-9]{64}$/.test(packageSha256)||!/^sha256:[a-f0-9]{64}$/.test(imageId)||!/^[A-Za-z0-9][A-Za-z0-9:-]{0,127}$/.test(sharedDaemonId))throw fail('PRICING_HANDOFF_INPUT');
 let source=GUEST;
 if(profile!=='v33')for(const [before,after]of [
  ["lease['target']=='original-v33-pricing-total-lease-v1'",`lease['target']=='${p.target}'`],
  ['==2616000 and time.monotonic()*1000+1200000',`==${p.totalMs} and time.monotonic()*1000+${p.budget.cohort+p.budget.retirement}`],
  ['0<float(seconds)<=2616',`0<float(seconds)<=${p.totalMs/1000}`],
 ]){if(source.split(before).length!==2)throw fail('PRICING_HANDOFF_PROFILE_ANCHOR');source=source.replace(before,after);}
 return 'B='+JSON.stringify({runId,ownerId,packageSha256,imageId,sharedDaemonId})+'\n'+source;
}
const GUEST=String.raw`
import json,os,stat,time,selectors,subprocess,re,sys
from pathlib import Path
root=Path('/var/tmp/owasp-ai-goat-v23-build-'+B['runId']);mount=root/'fs'
deadline=time.monotonic()+30
def need(ok):
 if not ok:raise RuntimeError('PRICING_HANDOFF_NOT_PROVEN')
def read(directory,name,json_value=False):
 fd=os.open(directory/name,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  expected_mode=0o400 if directory==mount/'pricing-closure' and name=='terminal.json' else 0o600
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==expected_mode and 0<s.st_size<=65536)
  value=os.read(fd,65537);need(len(value)==s.st_size)
  return json.loads(value) if json_value else value.decode().strip()
 finally:os.close(fd)
def docker(socket,*args):
 p=subprocess.Popen(['/usr/bin/docker','--host','unix://'+socket,*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env={'PATH':'/usr/bin:/bin'})
 sel=None;out=bytearray();err=bytearray()
 try:
  sel=selectors.DefaultSelector()
  for stream,buffer in ((p.stdout,out),(p.stderr,err)):
   os.set_blocking(stream.fileno(),False);sel.register(stream,selectors.EVENT_READ,buffer)
  while sel.get_map():
   need(time.monotonic()<deadline)
   for key,_ in sel.select(.05):
    part=os.read(key.fd,4096)
    if not part:sel.unregister(key.fileobj);continue
    need(len(out)+len(err)+len(part)<=65536);key.data.extend(part)
  p.wait(timeout=max(.001,deadline-time.monotonic()));need(p.returncode==0)
  return bytes(out).decode().strip()
 finally:
  primary=sys.exc_info()[1];debt=[]
  if p.poll() is None:
   try:p.kill();p.wait(timeout=3)
   except BaseException as error:debt.append(error)
  for close in ([sel.close] if sel else [])+[p.stdout.close,p.stderr.close]:
   try:close()
   except BaseException as error:debt.append(error)
  if debt:
   if primary is not None:primary.cleanupDebt=True
   else:raise RuntimeError('PRICING_HANDOFF_COMMAND_RETIREMENT_UNPROVEN') from debt[0]
def process(name,exe,namespace):
 pid=int(read(mount,name+'.pid'));start=read(mount,name+'.start');need(pid>1)
 proc=Path('/proc')/str(pid)
 need(proc.joinpath('stat').read_text().rsplit(')',1)[1].split()[19]==start)
 need(os.readlink(proc/'exe')==exe and os.stat(proc/'ns/net').st_ino==namespace)
 need(proc.joinpath('stat').read_text().rsplit(')',1)[1].split()[19]==start)
 return dict(pid=pid,startTicks=start,exe=exe)
def write(name,value):
 raw=json.dumps(value,sort_keys=True).encode();need(len(raw)<=65536)
 fd=os.open(mount/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  at=0
  while at<len(raw):
   n=os.write(fd,raw[at:]);need(n>0);at+=n
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(mount,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
need(os.geteuid()==0)
current=Path('/')
for part in mount.parts[1:]:
 current=current/part;s=current.lstat();need(stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode) and s.st_uid==0)
need(read(root,'owner')==B['runId'])
lease=read(root,'pricing-lease.json',True)
need(set(lease)=={'version','target','runId','clock','startedAtMs','expiresAtMs'} and type(lease['version']) is int and lease['version']==1)
need(lease['runId']==B['runId'] and lease['target']=='original-v33-pricing-total-lease-v1' and lease['clock']=='linux-monotonic-ms')
need(type(lease['startedAtMs']) is int and type(lease['expiresAtMs']) is int and 0<=lease['startedAtMs']<=time.monotonic()*1000)
need(lease['expiresAtMs']-lease['startedAtMs']==2616000 and time.monotonic()*1000+1200000<lease['expiresAtMs'])
seconds=read(root,'pricing-holder.seconds');need(re.fullmatch(r'[1-9][0-9]*\.[0-9]{3}',seconds) and 0<float(seconds)<=2616)
ns=int(read(mount,'namespace.inode').removeprefix('net:[').removesuffix(']'))
shared=os.stat('/proc/1/ns/net').st_ino;need(ns!=shared)
daemon=process('daemon','/usr/bin/dockerd',ns);holder=process('namespace','/usr/bin/sleep',ns)
need(Path('/proc/'+str(holder['pid'])+'/cmdline').read_bytes()==b'/usr/bin/sleep\x00'+seconds.encode()+b'\x00')
socket=str(mount/'docker.sock');info=json.loads(docker(socket,'info','--format','{{json .}}'))
need(info['ID']!=B['sharedDaemonId'] and info['DockerRootDir']==str(mount/'data'))
need(docker('/run/docker.sock','info','--format','{{.ID}}')==B['sharedDaemonId'])
images=json.loads(docker(socket,'image','inspect',B['imageId']));need(len(images)==1)
image=images[0];need(image['Id']==B['imageId'] and image['Architecture']=='arm64' and image['Os']=='linux')
need(image['Config']['User']=='10001:10001' and image['Config']['Entrypoint']==['node','sidecars/sandbox-runner/owned-pricing-http/http-listener.js'])
need(image['Config']['Labels'].get('owasp-ai-goat.pricing.package')==B['packageSha256'] and image['Config']['Labels'].get('owasp-ai-goat.build-run')==B['runId'])
# The caller's fixed phase must retire the replay/egress before publication.
# Do not infer retirement from an absent PID; require original retained receipt.
terminal=read(mount/'pricing-closure','terminal.json',True)
need(terminal['failure'] is None and terminal['cleanupErrors']==[] and terminal['result']['absenceVerified'] is True and terminal['result']['failure'] is None)
need(terminal['binding']['target']=='v33-pricing' and terminal['binding']['runId']==B['runId'])
handoff=dict(version=1,runId=B['runId'],ownerId=B['ownerId'],packageSha256=B['packageSha256'],daemonId=info['ID'],namespaceInode=ns,sharedNamespaceInode=shared,imageId=B['imageId'],relayRetired=True,daemonProcess=daemon,namespaceHolder=holder)
token=json.loads(sys.stdin.buffer.read(257))
need(type(token) is dict and set(token)=={'token'} and type(token['token']) is str and re.fullmatch(r'[A-Za-z0-9_-]{43,128}',token['token']))
write('pricing-token.json',token)
write('pricing-handoff.json',handoff)
print(json.dumps(dict(version=1,runId=B['runId'],published=True,runtimeStarted=False)))
`;
module.exports={program};
