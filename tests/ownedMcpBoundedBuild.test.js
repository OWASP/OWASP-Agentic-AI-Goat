'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto');
const syncFs=require('node:fs'),os=require('node:os');
const {spawnSync}=require('node:child_process');
const {EventEmitter}=require('node:events');
const {PassThrough}=require('node:stream');
const {runBoundedBuild,specification,LIMITS,PINS,_internals:i}=require('./postgres/ownedMcpBoundedBuild');
const source=require('../scripts/install/secureshop-owned-mcp-registry-setup')._internals;
test('Listings plan reuses capped private lifecycle and binds actual source without execution authority',async()=>{
 const root=path.resolve(__dirname,'..'),run='d'.repeat(32);
 const plan=await i.listingsMetadataQualificationPlan(root,run),prior=await i.pricingMetadataQualificationPlan(root,run);
 assert.equal(plan.binding.target,'listings-package');assert.equal(plan.kind,'private-listings-metadata');
 assert.equal(plan.storageCapBytes,6*1024**3);assert.equal(plan.buildApproved,false);assert.equal(plan.executionApproved,false);
 for(const phase of ['prepare','namespace','daemonStart','stop','cleanup'])assert.equal(plan.phases[phase],prior.phases[phase],phase);
 const manifest=require('../scripts/install/secureshop-owned-listings').sourceManifest(root);
 for(const [file,hash] of Object.entries(manifest.files))assert.equal(plan.buildSources[file],hash);
 assert.match(plan.phases.prepare,/os\.ftruncate\(fd,6442450944\)/);
 assert.match(plan.phases.retainedExport,/listings-original-apt-retention/);
 assert.match(plan.phases.cleanup,/losetup --detach/);
 assert.throws(()=>require('./postgres/ownedMcpBoundedBuild').validateClosedBuildTarget('listings-package'),{code:'DEPENDENCY_LOCK_NOT_APPROVED'});
});
const relayIdentity={account:'fixture',uid:501,gid:502,python:'/usr/bin/python3.13',pythonSha256:'a'.repeat(64),setprivSha256:'b'.repeat(64)};
test('renderer metadata factory captures actual eleven-file recipe with a distinct two-stage target and unchanged resource lifecycle',async()=>{
 const root=path.resolve(__dirname,'..'),run='f'.repeat(32);
 const renderer=await i.policyRendererMetadataQualificationPlan(root,run),old=await i.metadataQualificationPlan(root,run);
 assert.equal(renderer.kind,'private-v24-policy-metadata');assert.equal(renderer.binding.target,'v24-policy');
 assert.equal(renderer.binding.base,renderer.rendererInputs.recipe.base);
 assert.equal(renderer.rendererInputs.context.files.length,11);
 assert.deepEqual(renderer.rendererInputs.sourceManifest,require('../scripts/install/secureshop-owned-policy-renderer').sourceManifest(root));
 for(const [name,digest]of Object.entries(renderer.rendererInputs.sourceManifest.files))assert.equal(renderer.buildSources[name],digest);
 assert.equal(renderer.metadataRetention.mode,'v24-policy-metadata-retention-v1');
 assert.match(renderer.phases.retainedExport,/v24-policy-original-apt-retention/);
 assert.match(renderer.commands.acquire,/v24-policy-trixie-freshness-v1/);
 assert.match(renderer.commands.acquire,/"name":"build","packages":\["gcc","libc6-dev"\]/);
 assert.match(renderer.commands.acquire,/"name":"runtime","packages":\["bubblewrap"\]/);
 for(const name of ['preflight','prepare','namespace','relayStart','daemonStart','stop','evidence','cleanup'])assert.equal(renderer.phases[name],old.phases[name]);
 assert.equal(renderer.acquisitionSeconds,300);assert.equal(renderer.storageCapBytes,old.storageCapBytes);
 assert.equal(renderer.buildApproved,false);assert.equal(renderer.executionApproved,false);assert.equal(renderer.candidateOnly,true);
 assert.equal(old.rendererInputs,undefined);
});
test('Pricing metadata factory is separately bound and preserves existing lifecycle scripts',async()=>{
 const root=path.resolve(__dirname,'..'),run='e'.repeat(32);
 const pricing=await i.pricingMetadataQualificationPlan(root,run),old=await i.metadataQualificationPlan(root,run);
 assert.equal(pricing.kind,'private-v33-pricing-metadata');assert.equal(pricing.binding.target,'v33-pricing');
 assert.equal(pricing.binding.base,require('./postgres/ownedPricingOriginalBuild').BASE);
 assert.equal(pricing.metadataRetention.mode,'v33-pricing-metadata-retention-v1');
 assert.equal(pricing.executionApproved,false);assert.equal(pricing.buildApproved,false);assert.equal(pricing.candidateOnly,true);
 assert.deepEqual(Object.keys(pricing.phases),Object.keys(old.phases));
 for(const name of ['preflight','prepare','namespace','relayStart','daemonStart','stop','evidence','cleanup'])assert.equal(pricing.phases[name],old.phases[name]);
 assert.match(pricing.phases.retainedExport,/v33-pricing-original-apt-retention/);
 assert.match(pricing.commands.acquire,/v33-pricing-metadata-retention-v1/);
 assert.equal(pricing.acquisitionSeconds,300);assert.equal(pricing.storageCapBytes,old.storageCapBytes);
 assert.deepEqual(require('./postgres/ownedPolicySystemBuild').metadataRetentionSpecification('v33-pricing').stages,require('./postgres/ownedPricingOriginalBuild').STAGES);
});
test('System metadata is a closed single-stage prerequisite, not System build authority',async()=>{
 const root=path.resolve(__dirname,'..'),run='d'.repeat(32);
 const old=await i.metadataQualificationPlan(root,run),system=await i.systemMetadataQualificationPlan(root,run);
 assert.equal(system.kind,'private-v24-system-metadata');
 assert.equal(system.binding.target,'v24-system');
 assert.equal(system.binding.base,require('./postgres/ownedPolicySystemBuild').targetSpecification('v24-system').base);
 assert.equal(system.metadataRetention.mode,'v24-system-metadata-retention-v1');
 assert.equal(system.buildApproved,false);assert.equal(system.executionApproved,false);
 assert.deepEqual(Object.keys(system.phases),Object.keys(old.phases));
 for(const name of ['preflight','prepare','namespace','relayStart','daemonStart','stop','evidence','cleanup'])assert.equal(system.phases[name],old.phases[name]);
 assert.match(system.phases.retainedExport,/v24-system-original-apt-retention/);
 assert.match(old.phases.retainedExport,/v23-original-apt-retention/);
 assert.match(system.commands.acquire,/v24-system-metadata-retention-v1/);
 assert.deepEqual(require('./postgres/ownedPolicySystemBuild').metadataRetentionSpecification('v24-system').stages,
  [{name:'system',packages:['gcc','libc6-dev','bubblewrap']}]);
 assert.equal(system.acquisitionSeconds,300);assert.equal(system.storageCapBytes,old.storageCapBytes);
});
test('metadata-only plan pins real transport and original V23 base without enabling build',async()=>{
 const plan=await i.metadataQualificationPlan(path.resolve(__dirname,'..'),'b'.repeat(32));
 assert.equal(plan.binding.target,'v23-registry');
 assert.equal(plan.variant,'metadata-idle-barrier-v4');
 assert.equal(plan.binding.base,'sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1');
 assert.equal(plan.transportProof.sha256,'c38c0b87f71dd1fa732a15f9a85b9498ade49a21721984348e1829b53b4868a8');
 assert.equal(plan.executionApproved,false);assert.equal(plan.buildApproved,false);assert.equal(plan.acquisitionSeconds,300);
 assert.deepEqual(Object.keys(plan.commands),['inventory','acquire','inspect','stop','evidence','retainedExport','cleanup']);
 assert.deepEqual(plan.metadataRetention,{version:1,mode:'v23-metadata-retention-v1',guestPath:plan.guest+'/fs/metadata-retained',containerPath:'/metadata-retained',bytes:144*1024**2,archiveBytes:145*1024**2,objects:64});
 assert.deepEqual(Object.keys(plan.phases),['version','preflight','prepare','namespace','relayStart','daemonStart','metadataFetch','stop','evidence','retainedExport','cleanup']);
 assert.equal(plan.phases.version,1);
 assert.match(plan.phases.metadataFetch,/source=\$root\/fs\/metadata-retained,target=\/metadata-retained,bind-propagation=rprivate/);
 assert.match(plan.phases.prepare,/mkdir -m 0700 "\$root\/fs\/metadata-retained"/);
 assert.match(plan.commands.retainedExport,/assert self.count<=145\*1048576/);
 assert.match(plan.commands.retainedExport,/hashlib.file_digest\(f,'sha256'\)/);
 const exporter=plan.commands.retainedExport.split("<<'OWASP_AI_GOAT_METADATA_ARCHIVE'\n")[1].split('\nOWASP_AI_GOAT_METADATA_ARCHIVE')[0];
 const compiled=spawnSync('python3',['-B','-W','error::SyntaxWarning','-c','import sys;compile(sys.stdin.read(),"<archive>","exec")'],{input:exporter,encoding:'utf8'});
 assert.equal(compiled.status,0,compiled.stderr);
 assert.equal(plan.storageAllocation,'sparse-fixed-size');assert.equal(plan.storageCapBytes,6442450944);
 assert.equal(Object.keys(plan.buildSources).length,20);
 assert.equal(plan.buildSources['sidecars/sandbox-runner/owned-mcp-registry/Dockerfile.candidate'],
  crypto.createHash('sha256').update(syncFs.readFileSync(path.join(__dirname,'../sidecars/sandbox-runner/owned-mcp-registry/Dockerfile.candidate'))).digest('hex'));
 for(const script of Object.values(plan.commands)){
  const result=spawnSync('/bin/sh',['-n'],{input:script,encoding:'utf8'});assert.equal(result.status,0,result.stderr);
 }
 const acquire=plan.commands.acquire;
 assert.match(acquire,/os\.ftruncate\(fd,6442450944\)/);
 assert.match(acquire,/st_blocks\*512<=1048576/);
 assert.ok(!acquire.includes('fallocate -l 6442450944'));
 assert.ok(i.scripts.prepare.includes('fallocate -l 6442450944'));
 assert.match(acquire,/DOCKER_CONFIG="\$root\/fs\/docker-client" \/usr\/bin\/docker/);
 assert.match(acquire,/env -i PATH=\/usr\/bin:\/bin TMPDIR=/);
 assert.match(acquire,/check_metadata_proxy_env/);
 assert.match(acquire,/OWASP_AI_GOAT_METADATA_PROXY_PORT=\$proxy_port/);
 assert.match(acquire,/metadata-relay/);assert.match(acquire,/metadata-daemons/);
 assert.match(acquire,/metadata-idle-barrier-v4/);
 assert.match(acquire,/relay_control checkpoint >&2/);
 assert.match(acquire,/relay_control idle >&2/);
 assert.ok(acquire.lastIndexOf('metadata-relay')<acquire.lastIndexOf('metadata-daemons'));
 assert.ok(acquire.lastIndexOf('metadata-daemons')<acquire.lastIndexOf('metadata-fetch'));
 assert.ok(!acquire.includes('docker build --'));
 assert.match(plan.commands.stop,/stop_metadata_daemon daemon\nstop_metadata_daemon containerd\nstop_private_relay/);
 assert.match(plan.commands.cleanup,/unmount_metadata_namespace/);
 assert.match(i.scripts['metadata-acquire'],/require_private_egress/);
});
test('metadata Docker client clears inherited credentials and context before any CLI invocation',async()=>{
 const plan=await i.metadataQualificationPlan(path.resolve(__dirname,'..'),'c'.repeat(32));
 const script=plan.commands.inspect;
 const start=script.indexOf('\ndocker() {'),end=script.indexOf('\nmetadata_proxy_port() {',start);
 assert.ok(start>0&&end>start);
 let definition=script.slice(start,end);
 assert.equal(definition.split('/usr/bin/docker "$@"').length,2);
 definition=definition.replace('/usr/bin/docker "$@"','/usr/bin/env');
 const output=spawnSync('/bin/sh',['-s'],{input:'root=/controlled/nonexistent-metadata-client\n'+definition+'\ndocker\n',encoding:'utf8',
  env:{PATH:'/usr/bin:/bin',DOCKER_CONFIG:'/inherited/credentials',DOCKER_CONTEXT:'foreign',HTTPS_PROXY:'http://foreign.invalid',SYNTHETIC_TOKEN:'do-not-inherit'}});
 assert.equal(output.status,0,output.stderr);
 assert.deepEqual(output.stdout.trim().split('\n').sort(),['DOCKER_CONFIG=/controlled/nonexistent-metadata-client/fs/docker-client','PATH=/usr/bin:/bin']);
});
test('fixed retained exporter executes bounded USTAR and rejects partial or substituted objects',async()=>{
 const plan=await i.metadataQualificationPlan(path.resolve(__dirname,'..'),'b'.repeat(32));
 const exporter=plan.commands.retainedExport.split("<<'OWASP_AI_GOAT_METADATA_ARCHIVE'\n")[1].split('\nOWASP_AI_GOAT_METADATA_ARCHIVE')[0];
 const harness=String.raw`
import sys,json,tempfile,os,hashlib,io,contextlib,tarfile,stat
packet=json.load(sys.stdin)
# Controlled host-only UID projection; real files, hashes and tar writer run.
original_lstat,original_fstat=os.lstat,os.fstat
def owned(s):
 class S:
  def __getattr__(self,name): return 0 if name=='st_uid' else getattr(s,name)
 return S()
os.lstat=lambda *a,**k:owned(original_lstat(*a,**k))
os.fstat=lambda *a,**k:owned(original_fstat(*a,**k))
if not hasattr(hashlib,'file_digest'):
 def digest_file(f,algorithm):
  result=hashlib.new(algorithm)
  for chunk in iter(lambda:f.read(65536),b''):result.update(chunk)
  return result
 hashlib.file_digest=digest_file
with tempfile.TemporaryDirectory() as root:
 os.chmod(root,0o700);os.mkdir(root+'/objects',0o700);os.mkdir(root+'/partial',0o700)
 rows=[]
 for n in range(8):
  raw=('controlled raw object '+str(n)).encode();sha=hashlib.sha256(raw).hexdigest();name='objects/'+sha
  with open(root+'/'+name,'wb') as f:f.write(raw)
  os.chmod(root+'/'+name,0o444);rows.append({'file':name,'sha256':sha,'bytes':len(raw)})
 manifest={'version':1,'kind':'v23-original-apt-retention','binding':{'runId':'b'*32},'objects':rows}
 for name,value in [('manifest.json',manifest),('result.json',{'controlled':True})]:
  with open(root+'/'+name,'w') as f:json.dump(value,f)
  os.chmod(root+'/'+name,0o444)
 mode=packet['scenario'];target=root+'/'+rows[0]['file']
 if mode=='partial':open(root+'/partial/0001','w').close()
 if mode=='changed':
  os.chmod(target,0o600)
  with open(target,'wb') as f:f.write(b'wrong')
  os.chmod(target,0o444)
 if mode=='symlink':os.unlink(target);os.symlink(root+'/result.json',target)
 if mode=='extra':open(root+'/objects/extra','w').close()
 if mode=='hardlink':os.link(target,root+'/second-link')
 sys.argv=['fixed-exporter',root,'b'*32]
 class Output:
  def __init__(self):self.buffer=io.BytesIO()
 output=Output();failed=False
 try:
  with contextlib.redirect_stdout(output):exec(compile(packet['source'],'<fixed-exporter>','exec'),{})
 except (AssertionError,OSError):failed=True
 if mode=='success':
  assert not failed
  archive=tarfile.open(fileobj=io.BytesIO(output.buffer.getvalue()),mode='r:')
  assert len(archive.getmembers())==10
  assert all(member.isfile() and member.mode==0o444 for member in archive)
 else:assert failed
print('controlled-ok')
`;
 for(const scenario of ['success','partial','changed','symlink','extra','hardlink']){
  const result=spawnSync('python3',['-B','-W','error::SyntaxWarning','-c',harness],{input:JSON.stringify({source:exporter,scenario}),encoding:'utf8',timeout:10000,maxBuffer:1024**2});
  assert.equal(result.status,0,scenario+': '+result.stderr);assert.equal(result.stdout.trim(),'controlled-ok');
 }
});
test('actual-admitted lifecycle plan wires only small tmpfs namespace relay and retirement',async()=>{
 const root=path.resolve(__dirname,'..'),plan=await i.lifecycleQualificationPlan(root,'b'.repeat(32));
 assert.equal(plan.admission.uid,501);assert.equal(plan.admission.gid,1000);
 assert.equal(plan.storageCapBytes,16777216);assert.equal(plan.acquisitionApproved,false);
 assert.deepEqual(Object.keys(plan.commands),['inventory','preflight','prepare','namespace','start','authority','evidence','stop','cleanup']);
 const body=command=>plan.commands[command].slice(plan.commands[command].lastIndexOf('\n}\n')+3);
 assert.match(body('prepare'),/mount -t tmpfs -o size=16m,nosuid,nodev,noexec,mode=700/);
 for(const forbidden of ['fallocate','losetup','mkfs.ext4','containerd --','dockerd --','docker build','docker pull','docker run']){
  assert.ok(!body('prepare').includes(forbidden));assert.ok(!body('namespace').includes(forbidden));
 }
 assert.match(plan.commands.namespace,/namespace_exec \/usr\/sbin\/ip link set lo up/);
 assert.match(plan.commands.cleanup,/stop_private_relay\nstop_namespace/);
 assert.match(plan.commands.cleanup,/check_network \|\| network_status=94/);
 assert.match(plan.commands.start,/LIFECYCLE_ONLY_NO_ACQUISITION/);
 assert.ok(!plan.commands.start.includes('\nrequire_private_egress\ncheck_mount; check_namespace'));
 assert.match(i.scripts.prepare,/fallocate -l 6442450944/);
 assert.match(i.scripts['metadata-acquire'],/\nrequire_private_egress\n/);
 for(const command of Object.values(plan.commands)){
  const parsed=spawnSync('/bin/sh',['-n'],{input:command,encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
 }
 const source=plan.commands.start.split("<<'OWASP_AI_GOAT_RELAY_LIFECYCLE'\n")[1].split('\nOWASP_AI_GOAT_RELAY_LIFECYCLE\n')[0]+'\n';
 assert.equal(crypto.createHash('sha256').update(source).digest('hex'),plan.lifecycleSourceSha256);
 const compiled=spawnSync('/opt/homebrew/bin/python3',['-I','-S','-B','-c','import sys; s={"__name__":"controlled"};exec(compile(sys.stdin.read(),"<lifecycle>","exec"),s);assert "evidence" in s;assert all("LIFECYCLE_ONLY_NO_ACQUISITION" in p for p in s["CHILDREN"].values())'],{input:source,encoding:'utf8'});
 assert.equal(compiled.status,0,compiled.stderr);
});
test('lifecycle-only audit rejects DNS sockets and resolver child effects before dispatch',()=>{
 const code='import sys\n'+i.lifecycleNoConnect+String.raw`
for event in ('socket.connect','socket.getaddrinfo','subprocess.Popen'):
    try: sys.audit(event, None)
    except PermissionError as error: assert str(error)=='LIFECYCLE_ONLY_NO_ACQUISITION'
    else: raise AssertionError(event)
sys.audit('socket.bind', None)
`;
 const result=spawnSync('/opt/homebrew/bin/python3',['-I','-S','-B','-'],{input:code,encoding:'utf8'});
 assert.equal(result.status,0,result.stderr);
});
test('real transport is a distinct pinned instrumented variant with fixed anonymous clients and unchanged gates',async()=>{
 const root=path.resolve(__dirname,'..'),plan=await i.lifecycleQualificationPlan(root,'b'.repeat(32),'transport');
 assert.equal(plan.kind,'private-relay-real-transport');assert.equal(plan.variant,'connect-audit-v1');
 assert.equal(plan.executionApproved,false);assert.equal(plan.acquisitionApproved,false);
 assert.equal(plan.storageCapBytes,16777216);assert.equal(plan.clientSha256,i.TRANSPORT_CLIENT_SHA);
 assert.ok(!plan.commands.start.includes('LIFECYCLE_ONLY_NO_ACQUISITION'));
 assert.match(plan.commands.start,/TRANSPORT_ONLY=True/);
 assert.match(plan.commands.checkpoint,/relay_control checkpoint/);
 for(const name of ['deny-peer','deny-host','registry','auth','debian']){
  const shellSource=plan.commands['client-'+name].split("<<'OWASP_AI_GOAT_TRANSPORT_CLIENT'")[0];
  const tail=shellSource.slice(shellSource.lastIndexOf('\n}\n')+3);
  assert.match(tail,/namespace_exec \/usr\/bin\/env -i PATH=\/usr\/bin:\/bin/);
  if(name==='deny-peer')assert.ok(!tail.includes('/usr/bin/setpriv'));
  else assert.match(tail,/--reuid=501 --regid=1000 --clear-groups --no-new-privs/);
  const shell=spawnSync('/bin/sh',['-n'],{input:plan.commands['client-'+name],encoding:'utf8'});
  assert.equal(shell.status,0,shell.stderr);
 }
 const source=plan.commands.start.split("<<'OWASP_AI_GOAT_RELAY_LIFECYCLE'\n")[1].split('\nOWASP_AI_GOAT_RELAY_LIFECYCLE\n')[0]+'\n';
 const compiled=spawnSync('/opt/homebrew/bin/python3',['-I','-S','-B','-c','import sys; s={"__name__":"controlled"};exec(compile(sys.stdin.read(),"<transport>","exec"),s);assert "checkpoint" in s;assert all("connect-audit-v1" in p and "LIFECYCLE_ONLY_NO_ACQUISITION" not in p for p in s["CHILDREN"].values())'],{input:source,encoding:'utf8'});
 assert.equal(compiled.status,0,compiled.stderr);
 await assert.rejects(i.lifecycleQualificationPlan(root,'b'.repeat(32),'metadata'),{code:'BUILD_RELAY_PHASE'});
 assert.match(i.scripts['metadata-acquire'],/\nrequire_private_egress\n/);
});
test('transport audit delegates real peer checks and observes resolver/connect without replacing dispatch',()=>{
 const relay=require('./postgres/ownedMcpPrivateEgress');
 const code=relay._internals.program+`\nTRANSPORT_MODE='connector';TRANSPORT_RUN='${'b'.repeat(32)}'\n`+i.transportAudit+String.raw`
from unittest.mock import Mock,patch
sys.argv=['-',str(time.monotonic()+100)]
sock=Mock();sock.getsockopt.return_value=struct.pack('3i',123,501,1000)
# macOS has no Linux SO_PEERCRED; this is explicitly a controlled constant,
# not a claim that the real credential boundary ran on the host.
with patch.object(socket,'SO_PEERCRED',17,create=True):
    peer_uid(sock,501)
    sock.getsockopt.assert_called_with(socket.SOL_SOCKET,17,12)
    sock.getsockopt.return_value=struct.pack('3i',123,0,0)
    try:peer_uid(sock,501)
    except Denied:pass
    else:raise AssertionError('wrong UID admitted')
sys.audit('subprocess.Popen',None)
sys.audit('socket.connect',Mock(family=socket.AF_INET),('203.0.113.1',443))
assert TRANSPORT_COUNTS==dict(dnsSubprocesses=1,externalConnectAttempts=1,unixConnectAttempts=0,peerChecks=2,peerDenied=1)
atexit.unregister(transport_snapshot)
`;
 const result=spawnSync('/opt/homebrew/bin/python3',['-I','-S','-B','-'],{input:code,encoding:'utf8'});
 assert.equal(result.status,0,result.stderr);
});
test('metadata diagnostic variant delegates unchanged authority and retains only bounded rejected DNS hostnames',()=>{
 const relay=require('./postgres/ownedMcpPrivateEgress');
 const code=relay._internals.program+`\nTRANSPORT_MODE='adapter';TRANSPORT_RUN='${'b'.repeat(32)}'\n`+i.metadataAuthorityAudit+String.raw`
from unittest.mock import patch
import contextlib,io
sys.argv=['-',str(time.monotonic()+100)]
original_limits=dict(HOST_LIMITS)
def request(host):return ('CONNECT '+host+':443 HTTP/1.1\r\nHost: '+host+':443\r\n\r\n').encode()
with patch.object(socket,'getaddrinfo',side_effect=AssertionError('unexpected DNS')),patch.object(socket.socket,'connect',side_effect=AssertionError('unexpected outgoing')):
    for host in HOST_LIMITS:
        assert authority(request(host))==host
    assert metadata_denied_snapshot()==dict(hosts={},unclassified=0,overflow=0)
    packets=[request('blob.invalid'),request('blob.invalid')]
    packets += [request('blob'+str(n)+'.invalid') for n in range(10)]
    packets += [request('blob.invalid?token=SECRET'),request('user:SECRET@blob.invalid'),request('127.0.0.1'),
                request('a..invalid'),request('a'*64+'.invalid'),request('UPPER.invalid'),
                request('singlelabel'),request('trailing.invalid.'),b'GET https://blob.invalid/SECRET HTTP/1.1\r\n\r\n',
                b'CONNECT blob.invalid:443 HTTP/1.1\r\n\r\n'+b'SECRET',b'\xff\r\n\r\n',b'x'*8193]
    for packet in packets:
        try:_original_metadata_authority(packet)
        except Denied as original:
            try:authority(packet)
            except Denied as actual:assert type(actual) is type(original) and actual.args==original.args
            else:raise AssertionError('diagnostics admitted rejected authority')
        else:raise AssertionError('negative control accepted')
    # An opaque header is never copied, even when the destination is rejected.
    try:authority(b'CONNECT blob.invalid:443 HTTP/1.1\r\nAuthorization: Bearer SECRET\r\n\r\n')
    except Denied:pass
    else:raise AssertionError('secret header admitted')
assert HOST_LIMITS==original_limits
snapshot=metadata_denied_snapshot()
assert len(snapshot['hosts'])==8 and snapshot['hosts']['blob.invalid']==3
assert snapshot['overflow']==3 and snapshot['unclassified']==12
assert TRANSPORT_COUNTS==dict(dnsSubprocesses=0,externalConnectAttempts=0,unixConnectAttempts=0,peerChecks=0,peerDenied=0)
out=io.StringIO()
with contextlib.redirect_stdout(out):transport_snapshot('terminal')
packet=json.loads(out.getvalue())
assert packet['variant']=='metadata-authority-audit-v1' and packet['deniedAuthorities']==snapshot
assert 'SECRET' not in out.getvalue() and 'Authorization' not in out.getvalue()
assert len(out.getvalue())<4096
atexit.unregister(transport_snapshot)
`;
 const result=spawnSync('/opt/homebrew/bin/python3',['-I','-S','-B','-W','error::SyntaxWarning','-'],{input:code,encoding:'utf8',timeout:10000,maxBuffer:131072});
 assert.equal(result.status,0,result.stderr);
 assert.ok(!i.transportAudit.includes('metadata-authority-audit-v1'));
 assert.ok(!i.transportAudit.includes('deniedAuthorities'));
});
test('metadata blob variant admits only the observed exact public origin within unchanged aggregate caps',async()=>{
 const relay=require('./postgres/ownedMcpPrivateEgress');
 assert.deepEqual(relay.HOSTS,['registry-1.docker.io','auth.docker.io','deb.debian.org']);
 const plan=await i.privateRelayPlan(specification('/controlled/repo','a'.repeat(32)),relayIdentity,{transportOnly:true,metadataOnly:true});
 const parse=spawnSync('/opt/homebrew/bin/python3',['-I','-S','-B','-c',
  'import sys;scope={"__name__":"controlled"};exec(compile(sys.stdin.read(),"<metadata>","exec"),scope);assert scope["HOSTS"]==["registry-1.docker.io","auth.docker.io","deb.debian.org","production.cloudfront.docker.com"];assert all("metadata-idle-barrier-v4" in c for c in scope["CHILDREN"].values());assert "idle" in scope'],{input:plan.source,encoding:'utf8'});
 assert.equal(parse.status,0,parse.stderr);
 const code=relay._internals.program+`\nTRANSPORT_MODE='connector';TRANSPORT_RUN='${'b'.repeat(32)}'\n`+i.metadataBlobAuthorityAudit+String.raw`
from unittest.mock import patch,Mock
sys.argv=['-',str(time.monotonic()+100)]
host='production.cloudfront.docker.com'
assert HOST_LIMITS=={'registry-1.docker.io':128*1024**2,'auth.docker.io':1024**2,'deb.debian.org':132*1024**2,host:128*1024**2}
assert TOTAL==261*1024**2
assert authority(('CONNECT '+host+':443 HTTP/1.1\r\nHost: '+host+':443\r\n\r\n').encode())==host
for other in ['cloudfront.docker.com','production.cloudfront.docker.com.evil.invalid','other.cloudfront.docker.com',
              'production.cloudflare.docker.com','docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com',
              '127.0.0.1','production.cloudfront.docker.com.','production.cloudfront.docker.com?secret=x']:
    with patch.object(subprocess,'Popen') as launched,patch.object(socket,'socket') as connected:
        for call in (lambda:authority(('CONNECT '+other+':443 HTTP/1.1\r\n\r\n').encode()),lambda:resolve(other,time.monotonic()+1)):
            try:call()
            except Denied:pass
            else:raise AssertionError('alternate origin accepted')
        launched.assert_not_called();connected.assert_not_called()
# Actual resolver parsing/public-address admission, with only its subprocess doubled.
for answer,accepted in [(['8.8.8.8'],True),(['8.8.8.8','127.0.0.1'],False),(['169.254.169.254'],False),([],False)]:
    read,write=os.pipe();os.write(write,json.dumps(answer).encode());os.close(write)
    child=Mock();child.stdout=os.fdopen(read,'rb');child.wait.return_value=0;child.poll.return_value=0
    with patch.object(subprocess,'Popen',return_value=child) as launch:
        try:result=resolve(host,time.monotonic()+2)
        except Denied:assert not accepted
        else:assert accepted and result==answer
        assert child.wait.called and child.stdout.closed
        assert launch.call_args.args[0][-1]==host
for peer,accepted in [('8.8.8.8',True),('8.8.4.4',False),('127.0.0.1',False)]:
    remote=Mock();remote.getpeername.return_value=(peer,443)
    with patch('__main__.resolve',return_value=['8.8.8.8']) as lookup,patch.object(socket,'socket',return_value=remote):
        try:result=connect_public(host,time.monotonic()+2)
        except Denied:assert not accepted;remote.close.assert_called_once()
        else:assert accepted and result is remote
        lookup.assert_called_once();remote.connect.assert_called_once_with(('8.8.8.8',443))
sock=Mock()
with patch.object(socket,'SO_PEERCRED',17,create=True):
    for uid in (501,0):
        sock.getsockopt.return_value=struct.pack('3i',123,uid,1000)
        try:peer_uid(sock,501)
        except Denied:assert uid==0
        else:assert uid==501
b=Budget();b.charge(host,128*1024**2)
try:b.charge(host,1)
except Denied:pass
else:raise AssertionError('blob host cap relaxed')
assert b.total==128*1024**2 and b.hosts[host]==128*1024**2
b.charge('registry-1.docker.io',128*1024**2);b.charge('auth.docker.io',1024**2);b.charge('deb.debian.org',4*1024**2)
assert b.total==TOTAL
try:b.charge('deb.debian.org',1)
except Denied:pass
else:raise AssertionError('aggregate cap relaxed')
for _ in range(32):b.admit()
try:b.admit()
except Denied:pass
else:raise AssertionError('connection cap relaxed')
assert b.total==TOTAL and b.connections==32
atexit.unregister(transport_snapshot)
`;
 const result=spawnSync('/opt/homebrew/bin/python3',['-I','-S','-B','-W','error::SyntaxWarning','-'],{input:code,encoding:'utf8',timeout:10000,maxBuffer:131072});
 assert.equal(result.status,0,result.stderr);
});
test('metadata-only admission diagnostics expose pre-budget saturation without changing rejection or waiting',()=>{
 const relay=require('./postgres/ownedMcpPrivateEgress');
 const code=i.metadataAdmissionProgram(relay._internals.program)+`\nTRANSPORT_MODE='adapter';TRANSPORT_RUN='${'b'.repeat(32)}'\n`+i.metadataAdmissionAudit+String.raw`
from unittest.mock import patch,Mock
import io,contextlib
sys.argv=['-',str(time.monotonic()+100)]
for cause in ('workerLimitRejected','connectionLimitRejected'):
    METADATA_ADMISSION.update(workerLimitRejected=0,connectionLimitRejected=0,saturated=False)
    stop=threading.Event();listener=Mock();client=Mock();gate=Mock();gate.acquire.return_value=cause!='workerLimitRejected'
    listener.getsockname.return_value=('127.0.0.1',12345)
    calls=[]
    def accepted():
        if not calls:calls.append(1);return client,('127.0.0.1',11111)
        stop.set();raise socket.timeout()
    listener.accept.side_effect=accepted
    budget=Budget()
    if cause=='connectionLimitRejected':budget.connections=32
    out=io.StringIO()
    with patch('__main__.private_directory'),patch('__main__.socket_identity',return_value=(1,2)),\
         patch.object(signal,'signal'),patch.object(threading,'Event',return_value=stop),\
         patch.object(threading,'BoundedSemaphore',return_value=gate),patch.object(socket,'socket',return_value=listener),\
         patch('__main__.Budget',return_value=budget),patch.object(threading,'Thread') as worker,contextlib.redirect_stdout(out):
        serve('adapter','/controlled',501,time.monotonic()+10)
    client.close.assert_called_once();worker.assert_not_called()
    assert METADATA_ADMISSION[cause]==1 and sum(METADATA_ADMISSION[k] for k in ('workerLimitRejected','connectionLimitRejected'))==1
    terminal=json.loads(out.getvalue().splitlines()[-1])
    assert terminal['records']==[] and terminal['bytes']==0 and terminal['cleanupVerified'] is True
    assert terminal['connections']==(32 if cause=='connectionLimitRejected' else 0)
    # Snapshot is current active workers, not a fresh wait/grace or gate change.
    out=io.StringIO()
    with patch.object(threading,'active_count',return_value=5),patch.object(time,'sleep',side_effect=AssertionError('diagnostic waited')),contextlib.redirect_stdout(out):
        transport_snapshot('checkpoint')
    row=json.loads(out.getvalue());assert row['variant']=='metadata-admission-audit-v3' and row['activeWorkers']==4
    assert row['admission'][cause]==1
METADATA_ADMISSION['workerLimitRejected']=65535
metadata_admission_rejected('workerLimitRejected')
assert METADATA_ADMISSION['workerLimitRejected']==65535 and METADATA_ADMISSION['saturated'] is True
atexit.unregister(transport_snapshot)
`;
 const result=spawnSync('/opt/homebrew/bin/python3',['-I','-S','-B','-W','error::SyntaxWarning','-'],{input:code,encoding:'utf8',timeout:10000,maxBuffer:131072});
 assert.equal(result.status,0,result.stderr);
 assert.ok(!relay._internals.program.includes('metadata_admission_rejected'));
 assert.throws(()=>i.metadataAdmissionProgram('unexpected source'),{code:'BUILD_METADATA_SOURCE_SHAPE'});
});
function relayPython(body){
 const result=spawnSync('/opt/homebrew/bin/python3',['-I','-S','-B','-'],{
  input:i.relayLifecycleProgram+`\nROOT='/controlled';RUN='${'a'.repeat(32)}';RELAY='/controlled-relay';SOURCE_SHA='pinned';DNS_CODE='fixed-resolver';HOSTS=['deb.debian.org'];CHILDREN={'connector':'source','adapter':'source'}\nADMISSION=json.loads(${JSON.stringify(JSON.stringify(relayIdentity))})\n`+body,
  encoding:'utf8',timeout:10000,maxBuffer:131072});
 assert.equal(result.status,0,result.stderr);return result.stdout;
}
test('metadata idle barrier observes owned thread retirement within original deadline without tunnel kills or retries',()=>relayPython(i.metadataIdleProgram+String.raw`
from unittest.mock import patch
import contextlib,io
rows={mode:dict(pid=100+index,start=10+index,net='net:[2]',deadline='1300.000000') for index,mode in enumerate(('connector','adapter'))}
for scenario in ('drain','short-deadline','interrupt','unknown','late-active','after-checkpoint-active','no-clock-advance','reused-pid'):
    clock=[1000.0];saved={};observed=[];checkpoints=[];checked=[]
    original='1001.000000' if scenario=='short-deadline' else '1300.000000'
    def reader(path):
        if path.endswith('/acquisition.deadline'):observed.append(original);return original
        return json.dumps(rows['connector' if 'connector' in path else 'adapter'])
    def saver(name,value):assert name not in saved;saved[name]=value
    def identity(row,current):
        checked.append((row['pid'],current['start']))
        require(row==current)
        if scenario=='reused-pid' and len(checked)>2:raise RelayFailure('identity')
    def listing(path):
        pid=path.split('/')[2]
        if scenario=='unknown':return [pid,'unknown']
        if scenario=='after-checkpoint-active' and checkpoints:return [pid,'200']
        busy=clock[0]<1015 and scenario!='late-active'
        return [pid]+(['200','201','202','203'] if busy else [])
    def pause(seconds):
        assert 0<seconds<=.5
        if scenario=='interrupt':raise KeyboardInterrupt()
        if scenario!='no-clock-advance':clock[0]+=seconds
    def snapshot(end):
        checkpoints.append(end)
        assert end==min(float(original),1000+16)
        return {'rows':{mode:{'activeWorkers':1 if scenario=='late-active' else 0,'sequence':2} for mode in rows}}
    with patch('__main__.authority',return_value=1234),patch('__main__.read',side_effect=reader),\
         patch('__main__.save',side_effect=saver),patch('__main__.proc',side_effect=lambda pid:next(row for row in rows.values() if row['pid']==pid)),\
         patch('__main__.check_child',side_effect=identity),patch('__main__.checkpoint',side_effect=snapshot,create=True),\
         patch.object(os,'listdir',side_effect=listing),patch.object(os,'kill',side_effect=AssertionError('barrier must not kill')) ,\
         patch.object(time,'monotonic',side_effect=lambda:clock[0]),patch.object(time,'sleep',side_effect=pause),contextlib.redirect_stdout(io.StringIO()):
        try:idle()
        except (RelayFailure,KeyboardInterrupt):assert scenario!='drain'
        else:assert scenario=='drain'
    intent=saved['relay.idle.intent'];result=saved['relay.idle.result']
    assert intent['deadline']==original and intent['end']==min(float(original),1016)
    assert all(value==original for value in observed)
    assert clock[0]<=intent['end'] and len(checked)>=2
    if scenario=='drain':
        assert result['quiescent'] is True and result['completedAt']==1015 and result['attempts']==31
        assert result['checkpointSequences']=={'connector':2,'adapter':2} and len(checkpoints)==1
    else:
        assert result['quiescent'] is False and 'completedAt' not in result
        if scenario=='interrupt':assert result['failure']=='interrupted'
        if scenario=='short-deadline':assert result['failure']=='deadline' and not checkpoints
`));
test('private relay plan requires explicit existing account and binary admission without enabling execution',async()=>{
 const spec=specification('/controlled/repo','a'.repeat(32));
 for(const bad of [undefined,{}, {...relayIdentity,uid:0},{...relayIdentity,gid:0},{...relayIdentity,python:'/tmp/python'},
  {...relayIdentity,account:'root/escape'},{...relayIdentity,pythonSha256:'unknown'},{...relayIdentity,approved:true}]){
  await assert.rejects(i.privateRelayPlan(spec,bad),{code:'BUILD_RELAY_ADMISSION_REQUIRED'});
 }
 const plan=await i.privateRelayPlan(spec,relayIdentity);
 assert.equal(plan.executionApproved,false);assert.equal(plan.relaySourceSha256,i.RELAY_SOURCE_SHA);
 assert.equal(crypto.createHash('sha256').update(plan.source).digest('hex'),plan.sourceSha256);
 assert.match(plan.install,/require_private_egress\ncheck_mount; check_namespace/);
 const literal=plan.install.split("<<'OWASP_AI_GOAT_RELAY_LIFECYCLE'\n")[1].split('\nOWASP_AI_GOAT_RELAY_LIFECYCLE\n')[0]+'\n';
 assert.equal(literal,plan.source,'installed bytes equal the independently hashed source');
 const parsed=spawnSync('/opt/homebrew/bin/python3',['-I','-S','-B','-c','import sys; scope={"__name__":"controlled"};exec(compile(sys.stdin.read(),"<relay-plan>","exec"),scope);assert set(scope["CHILDREN"])=={"connector","adapter"}'],{input:plan.source,encoding:'utf8',timeout:10000,maxBuffer:131072});
 assert.equal(parsed.status,0,parsed.stderr);
 const shell=spawnSync('/bin/sh',['-n'],{input:plan.install,encoding:'utf8'});assert.equal(shell.status,0,shell.stderr);
});
test('relay absolute deadline rejects reset/expired/nonfinite before startup effects',()=>relayPython(String.raw`
from unittest.mock import patch,Mock
for value in ['999.0','1301.0','nan','inf','1e3','01001','1001\n','1001.1234567890']:
    with patch('__main__.context'),patch('__main__.coordinates',return_value=('net:[2]','net:[1]')),patch('__main__.read',return_value=value),patch.object(time,'monotonic',return_value=1000),patch('__main__.save') as saved,patch.object(os,'mkdir') as mkdir:
        try: start()
        except RelayFailure: pass
        else: raise AssertionError(value)
        saved.assert_not_called();mkdir.assert_not_called()
`));
test('retained failed lifecycle readlink journals admit exactly one terminal LF, not malformed namespaces',()=>{
 const retained=JSON.parse(syncFs.readFileSync(path.join(__dirname,'../tasks/qualification/relay-lifecycle-72f0ca8b1a694a909e03bd2898434f2e/terminal.json'),'utf8'));
 assert.ok(retained.files['namespace.inode'].endsWith('\n'));
 assert.equal(retained.files['relay.intent'],null,'historical failed startup is not rewritten as success');
 relayPython(`\nretained=json.loads(${JSON.stringify(JSON.stringify(retained.files))})\n`+String.raw`
from unittest.mock import patch
def reader(path): return retained[path.rsplit('/',1)[1]]
shared=retained['shared.inode'][:-1]
with patch('__main__.read',side_effect=reader),patch('__main__.proc',return_value={'start':int(retained['shared.start']),'exe':'/usr/bin/dockerd','net':shared}),patch.object(os,'readlink',return_value=shared):
    assert coordinates()==(retained['namespace.inode'][:-1],shared)
assert namespace_coordinate('net:[2]')=='net:[2]'
assert namespace_coordinate('net:[2]\n')=='net:[2]'
for value in ('net:[2]\n\n','net:[2]\r\n',' net:[2]\n','net:[2] ','net:[]','net:[0]','net:[x]'):
    try: namespace_coordinate(value)
    except RelayFailure: pass
    else: raise AssertionError(value)
`);
});
test('relay startup retains original deadline for both children and journals before effects',()=>relayPython(String.raw`
from unittest.mock import patch
events=[];saved={};deadline='1234.500000'
def capture(name,value): events.append(('save',name));saved[name]=value
def launched(mode,value,net):
    assert value==deadline;events.append(('launch',mode));return None,dict(mode=mode,deadline=value,net=net)
def readiness(row,value): return dict(kind='relay-ready',mode=row['mode'],port=12345 if row['mode']=='adapter' else None)
with patch('__main__.context'),patch('__main__.coordinates',return_value=('net:[2]','net:[1]')),patch('__main__.read',return_value=deadline),patch.object(time,'monotonic',return_value=1000),patch('__main__.save',side_effect=capture),patch('__main__.proc',return_value={'pid':123,'start':456}),patch.object(os.path,'lexists',return_value=False),patch.object(os,'mkdir',side_effect=lambda *a:events.append(('mkdir',))),patch.object(os,'chown'),patch('__main__.directory_record',return_value=[1,2]),patch('__main__.socket_record',return_value=[3,4]),patch('__main__.launch',side_effect=launched),patch('__main__.ready',side_effect=readiness): start()
assert events.index(('save','relay.intent'))<events.index(('mkdir',))<events.index(('launch','connector'))<events.index(('launch','adapter'))
assert saved['relay.ready']['deadline']==deadline and saved['relay.ready']['socket']==[3,4]
assert saved['relay.controller']=={'pid':123,'start':456}
`));
test('relay launch enters only adapter namespace then drops all privilege before frozen Python source',()=>relayPython(String.raw`
from unittest.mock import patch,Mock,mock_open
for mode in ('connector','adapter'):
    child=Mock(pid=123);events=[]
    fields=['S','1','123','123']+['0']*15+['456']
    opener=mock_open(read_data='123 (python) '+' '.join(fields))
    def saved(name,value): events.append(('save',name))
    def launched(*args,**kwargs):
        events.append(('launch',mode));assert events[0]==('save','relay.'+mode+'.intent')
        assert kwargs['start_new_session'] is True and kwargs['env']=={'PATH':'/usr/bin:/bin'}
        command=args[0]
        if mode=='adapter': assert command[:3]==['/usr/bin/nsenter','--net=/proc/100/ns/net','--'];command=command[3:]
        else: assert '/usr/bin/nsenter' not in command
        assert command[:4]==['/usr/bin/setpriv','--reuid=501','--regid=502','--clear-groups']
        for flag in ['--no-new-privs','--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all']: assert flag in command
        assert command[-6:]==[ADMISSION['python'],'-I','-S','-B','-','1234.5']
        return child
    with patch('__main__.remaining',return_value=100),patch('__main__.proc',return_value={'start':100,'exe':'/usr/bin/sleep','argv':['/usr/bin/sleep','900'],'net':'net:[2]'}),patch('__main__.save',side_effect=saved),patch('__main__.read',return_value='100'),patch('builtins.open',opener),patch.object(subprocess,'Popen',side_effect=launched),patch('__main__.send_source') as send:
        _,row=launch(mode,'1234.5','net:[2]');assert row['start']==456
        send.assert_called_once_with(child,'source','1234.5')
        assert events[-1]==('save','relay.'+mode+'.process')
`));
test('relay identity rejects wrong UID groups capabilities namespace birth or command before signaling',()=>relayPython(String.raw`
import copy
row=dict(pid=100,start=11,mode='adapter',net='net:[2]',deadline='1234.5')
current=dict(pid=100,start=11,pgid=100,sid=100,exe=ADMISSION['python'],argv=[ADMISSION['python'],'-I','-S','-B','-','1234.5'],net='net:[2]',uids=[501]*4,gids=[502]*4,groups=[],caps=[0]*5,noNewPrivs=1)
check_child(row,current)
for key,value in [('uids',[0]*4),('gids',[0]*4),('groups',['1']),('caps',[1]*5),('net','net:[1]'),('start',99),('argv',['foreign']),('pgid',99),('sid',99),('noNewPrivs',0)]:
    bad=copy.deepcopy(current);bad[key]=value
    try: check_child(row,bad)
    except RelayFailure: pass
    else: raise AssertionError(key)
`));
test('adapter holder reuse is refused before spawn intent or child allocation',()=>relayPython(String.raw`
from unittest.mock import patch
for changed in ('start','net','exe','argv'):
    current=dict(start=100,net='net:[2]',exe='/usr/bin/sleep',argv=['/usr/bin/sleep','900']);current[changed]='wrong'
    with patch('__main__.remaining',return_value=10),patch('__main__.read',return_value='100'),patch('__main__.proc',return_value=current),patch('__main__.save') as saved,patch.object(subprocess,'Popen') as spawn:
        try:launch('adapter','1234.5','net:[2]')
        except RelayFailure:pass
        else:raise AssertionError(changed)
        saved.assert_not_called();spawn.assert_not_called()
`));
test('stalled relay source pipe honors aggregate deadline and closes stdin without blocking write',()=>relayPython(String.raw`
from unittest.mock import patch,Mock
child=Mock();child.poll.return_value=None;child.stdin.fileno.return_value=42
selector=Mock();selector.__enter__=Mock(return_value=selector);selector.__exit__=Mock(return_value=False);selector.select.return_value=[]
with patch.object(os,'set_blocking'),patch.object(selectors,'DefaultSelector',return_value=selector),patch('__main__.remaining',side_effect=[.1,RelayFailure('expired')]),patch.object(os,'write') as write:
    try:send_source(child,'payload','1234.5')
    except RelayFailure:pass
    else:raise AssertionError('unbounded source transfer')
    write.assert_not_called();child.stdin.close.assert_called_once()
`));
test('relay port authority joins run source deadline directory socket and both live process identities',()=>relayPython(String.raw`
from unittest.mock import patch
import copy
packet=dict(version=1,runId=RUN,sourceSha256=SOURCE_SHA,port=12345,deadline='1234.5',socket=[3,4])
rows={mode:dict(mode=mode,pid=100+index,start=11+index,deadline='1234.5',net='net:[1]' if mode=='connector' else 'net:[2]') for index,mode in enumerate(('connector','adapter'))}
for scenario in ('valid','run','source','deadline','port','socket','directory','process-birth','process-net'):
    changed=copy.deepcopy(packet)
    if scenario=='run':changed['runId']='other'
    if scenario=='source':changed['sourceSha256']='other'
    if scenario=='deadline':changed['deadline']='999'
    if scenario=='port':changed['port']=0
    if scenario=='socket':changed['socket']=[3,99]
    records={ROOT+'/fs/relay.ready':json.dumps(changed),ROOT+'/fs/relay.directory':'[1,2]',ROOT+'/fs/relay.socket':'[3,4]'}
    records.update({ROOT+'/fs/relay.'+mode+'.process':json.dumps(row) for mode,row in rows.items()})
    def current(pid):
        row=rows['connector' if pid==100 else 'adapter'];value=dict(row,pgid=pid,sid=pid,exe=ADMISSION['python'],argv=[ADMISSION['python'],'-I','-S','-B','-',row['deadline']],uids=[501]*4,gids=[502]*4,groups=[],caps=[0]*5,noNewPrivs=1)
        if scenario=='process-birth':value['start']=99
        if scenario=='process-net':value['net']='net:[9]'
        return value
    with patch('__main__.context'),patch('__main__.journal'),patch('__main__.coordinates',return_value=('net:[2]','net:[1]')),patch('__main__.read',side_effect=lambda p:records[p]),patch('__main__.directory_record',return_value=[1,99] if scenario=='directory' else [1,2]),patch('__main__.socket_record',return_value=[3,4]),patch('__main__.proc',side_effect=current),patch.object(time,'monotonic',return_value=1000):
        try:port=authority();accepted=True
        except RelayFailure:accepted=False
        assert accepted==(scenario=='valid'),scenario
        if accepted:assert port==12345
`));
for(const scenario of ['success','exit-transition','exit-timeout','nonzombie-unreadable','missing-record','missing-controller','reused','moved-group','live-controller','unresponsive','socket-replaced','extra-file'])test(`relay retirement owns every child and preserves uncertainty: ${scenario}`,()=>relayPython(`
from unittest.mock import patch
scenario=${JSON.stringify(scenario)}
rows={mode:dict(mode=mode,pid=100+index,start=11+index,deadline='1234.5',net='net:[2]' if mode=='adapter' else 'net:[1]') for index,mode in enumerate(('adapter','connector'))}
live={100,101};clock=[1000.0];events=[];directory=[True];exiting=set()
records={ROOT+'/fs/relay.'+mode+'.process':json.dumps(row) for mode,row in rows.items()}
records.update({ROOT+'/fs/relay.'+mode+'.intent':'intent' for mode in rows})
records.update({ROOT+'/fs/relay.directory':'[1,2]',ROOT+'/fs/relay.socket':'[3,4]'})
if scenario!='missing-controller': records[ROOT+'/fs/relay.controller']='{"pid":300,"start":99}'
if scenario=='missing-record': del records[ROOT+'/fs/relay.adapter.process']
if scenario=='live-controller': records[ROOT+'/fs/relay.controller']='{"pid":200,"start":99}'
def current(pid):
    if pid==200:return {'pid':200,'start':99}
    row=rows['adapter' if pid==100 else 'connector'];result=dict(row,pgid=pid,sid=pid,exe=ADMISSION['python'],argv=[ADMISSION['python'],'-I','-S','-B','-',row['deadline']],uids=[501]*4,gids=[502]*4,groups=[],caps=[0]*5,noNewPrivs=1)
    if scenario=='reused' and pid==100: result['start']=999
    return result
def members(pid):
    if scenario=='moved-group' and pid==100:return []
    if pid in exiting:raise RelayExitTransition('controlled exit transition, not absence')
    if scenario=='nonzombie-unreadable' and pid==100:raise FileNotFoundError('live exe unreadable')
    return [current(pid)] if pid in live else []
def kill(pid,sig):
    assert sig==signal.SIGTERM;events.append(('signal',pid))
    if scenario in ('exit-transition','exit-timeout'):exiting.add(pid)
    elif scenario!='unresponsive':live.remove(pid)
def pause(n):
    clock[0]+=n
    if scenario=='exit-transition' and clock[0]>1000.05:live.clear();exiting.clear()
def lexists(path):
    if path in records:return True
    if path in (RELAY,RELAY+'/connector.sock'):return directory[0]
    return False
def remove(path):events.append(('rmdir',path));directory[0]=False
with patch('__main__.context'),patch('__main__.journal'),patch('__main__.read',side_effect=lambda p:records[p]),patch('__main__.proc',side_effect=current),patch('__main__.exists',side_effect=lambda p:p in live or p==200),patch('__main__.group_members',side_effect=members),patch('__main__.directory_record',return_value=[1,2]),patch('__main__.socket_record',return_value=[3,99] if scenario=='socket-replaced' else [3,4]),patch.object(os.path,'lexists',side_effect=lexists),patch.object(os,'killpg',side_effect=kill),patch.object(os,'unlink'),patch.object(os,'listdir',return_value=['foreign'] if scenario=='extra-file' else []),patch.object(os,'rmdir',side_effect=remove),patch.object(time,'monotonic',side_effect=lambda:clock[0]),patch.object(time,'sleep',side_effect=pause):
    try:cleanup();passed=True
    except RelayFailure:passed=False
assert passed==(scenario in ('success','exit-transition'))
assert directory[0]!=(scenario in ('success','exit-transition'))
if scenario in ('reused','moved-group','missing-record','nonzombie-unreadable'):assert ('signal',100) not in events and ('signal',101) in events
if scenario in ('live-controller','missing-controller'):assert not events
if scenario in ('unresponsive','exit-timeout'):assert events==[('signal',100),('signal',101)] and clock[0]<1010.1
`));
test('emitted relay cleanup reports bounded closed reasons without changing signaling, joins or deletion vetoes',()=>relayPython(String.raw`
from unittest.mock import patch
import io
cases={
 'missing-record':('record','record_missing'), 'bad-json':('record','record_invalid'),
 'wrong-mode':('record','record_invalid'), 'birth':('group_check','birth_group_session'),
 'pgid':('group_check','birth_group_session'), 'sid':('group_check','birth_group_session'),
 'exe':('group_check','executable_argv'), 'argv':('group_check','executable_argv'),
 'net':('group_check','namespace_identity'), 'uid':('group_check','namespace_identity'),
 'gid':('group_check','namespace_identity'), 'groups':('group_check','privilege_state'),
 'caps':('group_check','privilege_state'), 'no-new-privs':('group_check','privilege_state'),
 'descendant':('group_check','descendant_identity'),
 'lookup':('group_check','process_lookup_unproven'), 'signal':('signal','signal_failed'),
 'leader-race':('leader_check','birth_group_session'), 'join-birth':('join','birth_group_session'),
 'timeout':('join','deadline_exhausted'), 'exit-timeout':('join','deadline_exhausted'),
 'success':None,'exit-transition':None,
}
for scenario,expected in cases.items():
 rows={mode:dict(mode=mode,pid=100+index,start=11+index,deadline='1234.5',net='net:[2]' if mode=='adapter' else 'net:[1]') for index,mode in enumerate(('adapter','connector'))}
 bad=101 if scenario=='descendant' else 100
 live={100,101};clock=[1000.0];events=[];directory=[True];exiting=set();reads={100:0,101:0}
 records={ROOT+'/fs/relay.'+mode+'.process':json.dumps(row) for mode,row in rows.items()}
 records.update({ROOT+'/fs/relay.'+mode+'.intent':'intent' for mode in rows})
 records.update({ROOT+'/fs/relay.directory':'[1,2]',ROOT+'/fs/relay.socket':'[3,4]',ROOT+'/fs/relay.controller':'{"pid":300,"start":99}'})
 if scenario=='missing-record':del records[ROOT+'/fs/relay.adapter.process']
 if scenario=='bad-json':records[ROOT+'/fs/relay.adapter.process']='private-token://credential@host/path?secret=one'
 if scenario=='wrong-mode':records[ROOT+'/fs/relay.adapter.process']=json.dumps(dict(rows['adapter'],mode='private-token'))
 def current(pid):
  row=rows['adapter' if pid==100 else 'connector'];reads[pid]+=1
  value=dict(row,pgid=pid,sid=pid,exe=ADMISSION['python'],argv=[ADMISSION['python'],'-I','-S','-B','-',row['deadline']],uids=[501]*4,gids=[502]*4,groups=[],caps=[0]*5,noNewPrivs=1)
  if pid==bad:
   mutations={'birth':('start',999),'pgid':('pgid',999),'sid':('sid',999),'exe':('exe','/secret/executable'),
    'argv':('argv',['private-token']),'net':('net','net:[999]'),'uid':('uids',[0]*4),'gid':('gids',[0]*4),
    'groups':('groups',['0']),'caps':('caps',[1]*5),'no-new-privs':('noNewPrivs',0)}
   if scenario in mutations:key,val=mutations[scenario];value[key]=val
   if scenario=='join-birth' and ('signal',pid) in events:value['start']=999
   if scenario=='leader-race' and reads[pid]>2:value['start']=999
  return value
 def members(pid):
  if pid in exiting:raise RelayExitTransition('private-token must not be logged')
  if scenario=='lookup' and pid==bad:raise FileNotFoundError('private-token missing exe')
  if pid not in live:return []
  value=current(pid)
  if scenario=='descendant' and pid==bad:
   return [value,dict(value,pid=999,start=value['start']+1,exe='/secret/foreign',argv=['private-token'])]
  return [value]
 def kill(pid,sig):
  assert sig==signal.SIGTERM;events.append(('signal',pid))
  if scenario=='signal' and pid==bad:raise PermissionError('private-token signal denied')
  if scenario in ('exit-transition','exit-timeout'):exiting.add(pid)
  elif scenario=='timeout' or scenario=='join-birth' and pid==bad:pass
  else:live.remove(pid)
 def pause(n):
  clock[0]+=n
  if scenario=='exit-transition' and clock[0]>1000.05:live.clear();exiting.clear()
 def lexists(p):return p in records or p in (RELAY,RELAY+'/connector.sock') and directory[0]
 def remove(p):events.append(('rmdir',p));directory[0]=False
 stderr=io.StringIO()
 with patch('__main__.context'),patch('__main__.journal'),patch('__main__.read',side_effect=lambda p:records[p]),patch('__main__.proc',side_effect=current),patch('__main__.exists',side_effect=lambda p:p in live),patch('__main__.group_members',side_effect=members),patch('__main__.directory_record',return_value=[1,2]),patch('__main__.socket_record',return_value=[3,4]),patch.object(os.path,'lexists',side_effect=lexists),patch.object(os,'killpg',side_effect=kill),patch.object(os,'unlink') as unlink,patch.object(os,'listdir',return_value=[]),patch.object(os,'rmdir',side_effect=remove),patch.object(time,'monotonic',side_effect=lambda:clock[0]),patch.object(time,'sleep',side_effect=pause),patch.object(sys,'stderr',stderr):
  try:cleanup();passed=True
  except RelayFailure as error:
   assert type(error) is RelayFailure and str(error)=='BUILD_RELAY_OWNERSHIP_UNPROVEN'
   passed=False
  assert passed==(expected is None),scenario
  if not passed:unlink.assert_not_called()
 assert directory[0]==(expected is not None),scenario
 lines=stderr.getvalue().splitlines()
 if expected is None:assert lines==[];continue
 assert len(lines)==1 and len(lines[0])<=1024
 assert 'private-token' not in lines[0] and '/secret' not in lines[0] and '999' not in lines[0]
 packet=json.loads(lines[0]);assert set(packet)=={'kind','version','failures'}
 assert packet['kind']=='relay-cleanup-failure' and packet['version']==1
 failures=packet['failures'];assert 1<=len(failures)<=2
 assert len({r['mode'] for r in failures})==len(failures)
 assert all(set(r)=={'mode','stage','reason'} for r in failures)
 mode='connector' if bad==101 else 'adapter'
 assert dict(mode=mode,stage=expected[0],reason=expected[1]) in failures,(scenario,failures)
 signals=[e for e in events if e[0]=='signal']
 if scenario in ('timeout','exit-timeout','join-birth'):
  assert signals==[('signal',100),('signal',101)]
 if scenario in ('timeout','exit-timeout'):
  assert 1010<=clock[0]<1010.1 and len(failures)==2
 elif scenario not in ('signal','join-birth'):
  assert ('signal',bad) not in signals and ('signal',101 if bad==100 else 100) in signals
`));
test('relay diagnostic failure cannot mask ownership failure or serialize arbitrary data',()=>relayPython(String.raw`
from unittest.mock import patch
import io
stderr=io.StringIO()
with patch.object(sys,'stderr',stderr):
 cleanup_diagnostic({'adapter':('secret'*10000,'secret'*10000,'private-token'),'foreign':('record','private-token','private-token')})
value=stderr.getvalue();assert len(value)<=1024 and 'secret' not in value and 'private-token' not in value
assert json.loads(value)['failures']==[dict(mode='adapter',stage='join',reason='unexpected_failure')]
class Broken:
 def write(self,value):raise OSError('private-token')
 def flush(self):raise OSError('private-token')
with patch.object(sys,'stderr',Broken()):
 cleanup_diagnostic({'connector':('join','deadline_exhausted',None)})
 try:require(False)
 except RelayFailure as error:assert type(error) is RelayFailure and str(error)=='BUILD_RELAY_OWNERSHIP_UNPROVEN'
 else:raise AssertionError('diagnostic masked ownership failure')
def reader(p):
 if p.endswith('/relay.controller'):return '{"pid":300,"start":99}'
 return 'private-token invalid JSON'
with patch('__main__.context'),patch('__main__.journal'),patch('__main__.read',side_effect=reader),patch('__main__.exists',return_value=False),patch.object(os.path,'lexists',return_value=True),patch.object(os,'killpg') as kill,patch.object(os,'unlink') as unlink,patch.object(os,'rmdir') as remove,patch.object(sys,'stderr',Broken()):
 try:cleanup()
 except RelayFailure as error:assert type(error) is RelayFailure and str(error)=='BUILD_RELAY_OWNERSHIP_UNPROVEN'
 else:raise AssertionError('failed diagnostic allowed actual cleanup to succeed')
 kill.assert_not_called();unlink.assert_not_called();remove.assert_not_called()
`));
test('relay proc races retain exact exception identity and emit only closed lookup sites',()=>relayPython(String.raw`
from unittest.mock import patch
import io
def statline(state='S',birth=11):
 fields=['0']*20;fields[0]=state;fields[2]='77';fields[3]='77';fields[19]=str(birth)
 return '77 (synthetic) '+' '.join(fields)
def file_for(path,stat_reads):
 if path=='/proc/77/stat':return io.StringIO(next(stat_reads))
 if path=='/proc/77/cmdline':return io.BytesIO(b'python\0')
 if path=='/proc/77/status':return io.StringIO('Uid:\t1 1 1 1\n')
 raise AssertionError(path)
for kind in (FileNotFoundError,ProcessLookupError):
 sentinel=kind('private-token')
 with patch('builtins.open',side_effect=sentinel):
  try:proc(77)
  except kind as error:assert error is sentinel and error.lookupSite=='proc_stat'
  else:raise AssertionError('initial stat absence accepted')
 stat_reads=iter([statline()])
 def recheck(path,*args,**kwargs):
  if path=='/proc/77/stat':
   try:return io.StringIO(next(stat_reads))
   except StopIteration:raise sentinel
  return file_for(path,iter(()))
 with patch('builtins.open',side_effect=recheck),patch.object(os,'readlink',side_effect=kind('link unavailable')):
  try:proc(77)
  except kind as error:assert error is sentinel and error.lookupSite=='proc_recheck_stat'
  else:raise AssertionError('recheck absence accepted')
 stat_reads=iter([statline(),statline()]);link=kind('private-token link')
 with patch('builtins.open',side_effect=lambda p,*a,**k:file_for(p,stat_reads)),patch.object(os,'readlink',side_effect=link):
  try:proc(77)
  except kind as error:assert error is link and error.lookupSite=='proc_link'
  else:raise AssertionError('same-birth live link absence accepted')
 with patch.object(os,'listdir',return_value=['77']),patch('builtins.open',side_effect=sentinel),patch.object(os.path,'isdir',return_value=True):
  try:group_members(77)
  except RelayFailure as error:
   assert type(error) is RelayFailure and str(error)=='BUILD_RELAY_OWNERSHIP_UNPROVEN'
   assert error.lookupSite=='group_stat'
  else:raise AssertionError('present group stat disappearance accepted')
 with patch.object(os,'listdir',return_value=['77']),patch('builtins.open',side_effect=sentinel),patch.object(os.path,'isdir',return_value=False):
  assert group_members(77)==[]
 stat_reads=iter([statline(),statline(birth=12)])
 with patch('builtins.open',side_effect=lambda p,*a,**k:file_for(p,stat_reads)),patch.object(os,'readlink',side_effect=kind('private-token link')):
  try:proc(77)
  except RelayFailure as error:
   assert type(error) is RelayFailure and str(error)=='BUILD_RELAY_OWNERSHIP_UNPROVEN'
   assert error.lookupSite=='proc_recheck_stat'
  else:raise AssertionError('reused birth accepted')
 stat_reads=iter([statline(),statline(state='Z')])
 with patch('builtins.open',side_effect=lambda p,*a,**k:file_for(p,stat_reads)),patch.object(os,'readlink',side_effect=kind('private-token link')):
  try:proc(77)
  except RelayExitTransition:pass
  else:raise AssertionError('same-birth zombie treated as absent')
 output=io.StringIO()
 with patch.object(sys,'stderr',output):
  cleanup_diagnostic({'connector':('join','ownership_unproven','proc_recheck_stat'),
    'adapter':('group_check','private-token','private-token')})
 packet=json.loads(output.getvalue());assert len(packet['failures'])==2
 assert packet['failures']==[
  dict(mode='adapter',stage='group_check',reason='unexpected_failure'),
  dict(mode='connector',stage='join',reason='ownership_unproven',lookupSite='proc_recheck_stat')]
 assert len(output.getvalue())<=1025 and 'private-token' not in output.getvalue()
`));
test('relay join rescans only transient census uncertainty within original shutdown end',()=>relayPython(String.raw`
from unittest.mock import patch,Mock
import contextlib,io
def uncertain(site='group_stat'):
 error=RelayFailure('BUILD_RELAY_OWNERSHIP_UNPROVEN');error.reason='ownership_unproven';error.lookupSite=site;return error
def reader(path):
 if path.endswith('.process'):return json.dumps(dict(pid=77,mode='connector'))
 if path.endswith('relay.controller'):return json.dumps(dict(pid=900))
 if path.endswith('relay.directory'):return '[1,2]'
 if path.endswith('relay.socket'):return '[3,4]'
 raise AssertionError(path)
def run(checks,ticks=None,relay=False,socket=False,actual=False):
 actual_check_group=check_group;calls=[0]
 def checked(row):
  calls[0]+=1
  if calls[0]==1 and actual:raise RelayExitTransition('pending')
  if actual:return actual_check_group(row)
  value=checks[calls[0]-1]
  if isinstance(value,BaseException):raise value
  return value
 def lexists(path):
  if path.endswith(('relay.controller','relay.connector.intent','relay.connector.process')):return True
  if path==RELAY:return relay
  if path==RELAY+'/connector.sock':return socket
  return False
 clock=iter(ticks) if ticks is not None else None
 output=io.StringIO();diagnostic=io.StringIO()
 with patch('__main__.context'),patch('__main__.journal'),patch('__main__.read',side_effect=reader),\
      patch('__main__.check_group',side_effect=checked),patch('__main__.exists',side_effect=lambda pid:actual and pid==88),\
      patch.object(os.path,'lexists',side_effect=lexists),patch.object(os,'killpg') as signals,\
      patch.object(os,'unlink') as unlink,patch.object(os,'rmdir') as rmdir,\
      patch.object(time,'sleep') as sleep,patch.object(sys,'stdout',output),patch.object(sys,'stderr',diagnostic):
  if clock is not None:
   with patch.object(time,'monotonic',side_effect=lambda:next(clock)):
    try:cleanup();failure=None
    except RelayFailure as error:failure=error
  else:
   try:cleanup();failure=None
   except RelayFailure as error:failure=error
 return failure,output.getvalue(),diagnostic.getvalue(),calls[0],signals,unlink,rmdir,sleep
with patch.object(os,'listdir',side_effect=[['88'],[]]),patch('builtins.open',side_effect=FileNotFoundError),\
     patch.object(os.path,'isdir',side_effect=lambda path:path=='/proc/88'):
 failure,out,diag,calls,signals,unlink,rmdir,sleep=run([],actual=True)
 assert failure is None and out=='relay-absent\n' and calls==3
 signals.assert_not_called();unlink.assert_not_called();rmdir.assert_not_called();sleep.assert_called_once_with(.02)
for checks,ticks,site in (([RelayExitTransition('pending'),uncertain(),uncertain()],[0,1,2,10],'group_stat'),
                          ([RelayExitTransition('pending'),uncertain(),[]],[0,1,2,9.99,10.01],'group_stat'),
                          ([RelayExitTransition('pending'),uncertain('proc_recheck_stat'),[]],None,'proc_recheck_stat')):
 failure,out,diag,calls,signals,unlink,rmdir,sleep=run(checks,ticks)
 assert isinstance(failure,RelayFailure) and out=='' and calls<=3
 signals.assert_not_called();unlink.assert_not_called();rmdir.assert_not_called()
 if site=='proc_recheck_stat':assert calls==2 and sleep.call_count==0
for ticks,relay,socket in (([0,1,2,10],False,False),([0,1,2,3,11],True,True),
                           ([0,1,2,3,11],True,False),([0,1,2,3,11],False,False)):
 with patch('__main__.directory_record',return_value=[1,2]),patch('__main__.socket_record',return_value=[3,4]),\
      patch.object(os,'listdir',return_value=[]):
  failure,out,diag,calls,signals,unlink,rmdir,sleep=run([[],[]],ticks,relay,socket)
 assert isinstance(failure,RelayFailure) and out==''
 signals.assert_not_called();unlink.assert_not_called();rmdir.assert_not_called()
`));
test('retained transport failure stays failed despite independently successful recovery',()=>{
 const directory=path.join(__dirname,'../tasks/qualification/relay-transport-b13d72a8104c43e2b56f3e01d748a09c');
 const read=name=>JSON.parse(syncFs.readFileSync(path.join(directory,name),'utf8'));
 const original=read('result.json'),terminal=read('terminal.json'),recovery=read('recovery-result.json');
 assert.equal(original.passed,false);assert.equal(original.realTransportVerified,true);
 assert.deepEqual(original.commandFailures,[{code:'COMMAND_EXIT_1',operation:'stop'}]);
 for(const mode of ['adapter','connector']){
  const lines=terminal.files[`relay.${mode}.log`].trimEnd().split('\n').map(JSON.parse);
  const last=lines.find(row=>row.kind==='relay-terminal');
  assert.equal(last.cleanupVerified,true);assert.equal(last.unjoinedWorkers,0);
 }
 assert.equal(recovery.kind,'owned-cleanup-recovery-only');assert.equal(recovery.passed,true);
 assert.equal(recovery.guestAbsent,true);assert.deepEqual(recovery.errors,[]);
 assert.ok(recovery.children.every(row=>row.reaped&&row.groupAbsent));
});
test('process inspection distinguishes verified exit transitions from live unreadability and birth reuse',()=>relayPython(String.raw`
from unittest.mock import patch
import io
def statline(state,birth=11):
    fields=[state,'1','100','100']+['0']*15+[str(birth)]
    return '100 (python) '+' '.join(fields)
for scenario in ('zombie','exit-race','live-unreadable','birth-reused'):
    reads=[0]
    def opened(path,*args):
        if path.endswith('/stat'):
            reads[0]+=1
            return io.StringIO(statline('Z' if scenario=='zombie' or reads[0]>1 and scenario!='live-unreadable' else 'S',99 if scenario=='birth-reused' and reads[0]>1 else 11))
        if path.endswith('/cmdline'):return io.BytesIO(b'python\0')
        if path.endswith('/status'):return io.StringIO('Uid: 501 501 501 501\n')
        raise AssertionError(path)
    with patch('builtins.open',side_effect=opened),patch.object(os,'readlink',side_effect=FileNotFoundError) as links:
        try:proc(100)
        except RelayExitTransition:assert scenario in ('zombie','exit-race')
        except (FileNotFoundError,RelayFailure):assert scenario in ('live-unreadable','birth-reused')
        else:raise AssertionError('transition reported as live')
        if scenario=='zombie':links.assert_not_called()
`));
test('original acquisition deadline precedes preflight and cleanup retires relay before namespace and disk',()=>{
 assert.ok(i.scripts['metadata-acquire'].indexOf('acquisition_deadline=$(')<i.scripts['metadata-acquire'].indexOf("printf 'OWASP_AI_GOAT_METADATA_STAGE=preflight"));
 assert.match(i.scripts['metadata-acquire'],/metadata-prepare "\$root" "\$nonce" "\$acquisition_deadline"/);
 assert.match(i.scripts.prepare,/sys\.argv\[1\].*acquisition\.deadline/);
 const cleanup=i.scripts.cleanup.slice(i.guard.length);
 assert.ok(cleanup.indexOf('stop_private_relay')<cleanup.indexOf('stop_owned daemon'));
 assert.ok(cleanup.indexOf('stop_private_relay')<cleanup.indexOf('stop_namespace'));
 assert.match(i.guard,/relay_control cleanup >&2/);
 assert.match(i.scripts['metadata-cleanup'],/OWASP_AI_GOAT_METADATA_STAGE=cleanup-owner/);
 assert.match(i.scripts.metadata,/proxy_port=\$\(relay_control authority\)/);
 assert.match(i.scripts.metadata,/--env "OWASP_AI_GOAT_METADATA_PROXY_PORT=\$proxy_port"/);
});
test('unapproved closed V24 targets fail before source capture, verification or any runner effect',async()=>{
 let effects=0;const effect=async()=>{effects++;throw Error('must not run');};
 for(const target of ['v24-system','v24-policy'])await assert.rejects(runBoundedBuild({target,verify:effect,capture:effect,runner:effect}),{code:'DEPENDENCY_LOCK_NOT_APPROVED'});
 await assert.rejects(runBoundedBuild({target:'arbitrary',verify:effect}),{code:'BUILD_TARGET_UNKNOWN'});
 assert.equal(effects,0);
 require('./postgres/ownedMcpBoundedBuild').validateClosedBuildTarget('mcp-registry');
});
test('real build entry remains unavailable before host/source/resource work',async()=>{
 const effect=()=>assert.fail('no work before relay qualification');
 await assert.rejects(runBoundedBuild({verify:effect,capture:effect}),{code:'BUILD_PRIVATE_EGRESS_UNAVAILABLE'});
});
test('private daemon recipes join one holder namespace and never configure shared networking',()=>{
 assert.match(i.scripts.start,/unshare --net -- \/usr\/bin\/sleep 900/);
 assert.match(i.scripts.start,/namespace_exec \/usr\/sbin\/ip link set lo up/);
 for(const executable of ['containerd','dockerd'])assert.ok(i.scripts.start.includes(`setsid /usr/bin/nsenter --net="/proc/$holder/ns/net" -- /usr/bin/${executable}`));
 assert.match(i.guard,/process_net "\$pid"\)" = "\$private_net"/);
 assert.match(i.guard,/\[ "\$private_net" != "\$shared_net" \]/);
 const cleanup=i.scripts.cleanup.slice(i.guard.length);
 assert.ok(cleanup.indexOf('stop_owned containerd')<cleanup.indexOf('stop_namespace'));
 assert.ok(cleanup.indexOf('stop_namespace')<cleanup.indexOf('umount "$root/fs"'));
 assert.doesNotMatch(i.scripts.start,/ip (?:link add|route add|netns add)|iptables .*-[AFDX]|nft add/);
});
for(const scenario of ['valid','shared-inode','holder-reused','shared-reused','wrong-holder-argv','daemon-wrong-net','retained-member'])test(`owned namespace lifecycle rejects identity drift: ${scenario}`,async t=>{
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'private-netns-control-'));
 t.after(()=>fs.rm(directory,{recursive:true,force:true}));await fs.mkdir(path.join(directory,'fs'));
 for(const [name,value] of Object.entries({'namespace.pid':'100','namespace.start':'11','shared.pid':'200','shared.start':'22','namespace.inode':scenario==='shared-inode'?'net:[1]':'net:[2]','shared.inode':'net:[1]'}))await fs.writeFile(path.join(directory,'fs',name),value);
 const body=i.guard+`
root="$3"; scenario="$4"; holder_live=1
process_start() { if [ "$1" = 100 ]; then if [ "$scenario" = holder-reused ]; then printf 99; else printf 11; fi; else if [ "$scenario" = shared-reused ]; then printf 99; else printf 22; fi; fi; }
process_exe() { if [ "$1" = 100 ]; then printf /usr/bin/sleep; else printf /usr/bin/dockerd; fi; }
process_args() { if [ "$scenario" = wrong-holder-argv ]; then printf foreign; else printf '/usr/bin/sleep\\n900'; fi; }
process_net() { if [ "$1" = 100 ]; then if [ "$scenario" = shared-inode ]; then printf 'net:[1]'; else printf 'net:[2]'; fi; elif [ "$1" = 300 ] && [ "$scenario" = retained-member ]; then printf 'net:[2]'; else printf 'net:[1]'; fi; }
process_exists() { [ "$holder_live" = 1 ]; }
namespace_members() { printf '/proc/100\\n/proc/300\\n'; }
kill() { [ "$1" = -TERM ] && [ "$2" = 100 ]; holder_live=0; printf holder-stopped; }
check_namespace
if [ "$scenario" = daemon-wrong-net ]; then pid=300; [ "$(process_net "$pid")" = "$private_net" ]; fi
stop_namespace
printf joined
`;
 const result=spawnSync('/bin/sh',['-c',body,'netns-test','/var/tmp/owasp-ai-goat-v23-build-'+'a'.repeat(32),'a'.repeat(32),directory,scenario],{encoding:'utf8'});
 if(scenario==='valid'){assert.equal(result.status,0,result.stderr);assert.equal(result.stdout,'holder-stoppedjoined');}
 else{assert.notEqual(result.status,0);assert.doesNotMatch(result.stdout,/holder-stopped|joined/);}
});
test('unqualified private egress rejects build and metadata before launch; cleanup remains available',async()=>{
 const execute=i.createExecutor({launch:()=>assert.fail('no launch without qualified relay'),
  kill:()=>assert.fail('no kill'),delay:()=>assert.fail('no wait')});
 for(const operation of ['metadata','metadata-acquire','build'])await assert.rejects(execute(specification('/controlled/repo','a'.repeat(32)),operation),{code:'BUILD_PRIVATE_EGRESS_UNAVAILABLE'});
 const script=i.scripts['metadata-acquire'];
 assert.match(script,/require_private_egress\nacquisition_deadline=/);
 for(const label of ['metadata-preflight','metadata-prepare','metadata-start','metadata-fetch'])assert.ok(script.includes(label));
 assert.ok(script.indexOf('metadata-prepare')<script.indexOf('metadata-start'));
 assert.match(i.scripts.metadata,/--cidfile/);assert.match(i.scripts.metadata,/rm -f "\$cid"/);
 assert.match(i.scripts.metadata,/\.Image/);assert.match(i.scripts.metadata,/trap 'exit 124' TERM INT/);
 const syntax=spawnSync('/bin/sh',['-n'],{input:script,encoding:'utf8'});assert.equal(syntax.status,0,syntax.stderr);
});
for(const scenario of ['expired','partial-absent','partial-live','partial-no-birth-live','missing-pid-intent','reused-midscan','expired-midscan','unreadable-live','vanished-member','retained-member'])test(`namespace cleanup preserves safe absence and signal boundaries: ${scenario}`,async t=>{
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'netns-cleanup-control-'));
 t.after(()=>fs.rm(directory,{recursive:true,force:true}));const root=path.join(directory,'owned');await fs.mkdir(path.join(root,'fs'),{recursive:true});
 for(const [name,value] of Object.entries({'namespace.pid':'100','namespace.start':'11','shared.pid':'200','shared.start':'22','namespace.inode':'net:[2]','shared.inode':'net:[1]','live.start':'11'}))await fs.writeFile(path.join(root,'fs',name),value);
 await fs.writeFile(path.join(root,'owner'),'fixture');await fs.writeFile(path.join(root,'network.before.json'),'baseline\n');
 if(scenario.startsWith('partial'))await fs.unlink(path.join(root,'fs/namespace.inode'));
 if(['partial-absent','partial-no-birth-live'].includes(scenario))await fs.unlink(path.join(root,'fs/namespace.start'));
 if(scenario==='missing-pid-intent'){await fs.unlink(path.join(root,'fs/namespace.pid'));await fs.writeFile(path.join(root,'fs/namespace.intent'),'attempted');}
 const overrides=`
root="$3"; scenario="$4"
check_owner() { [ -f "$root/owner" ]; }
check_mount() { :; }
mountpoint() { return 1; }
findmnt() { :; }
network_snapshot() { printf 'baseline\\n'; }
namespace_members() { printf '/proc/100\\n/proc/300\\n'; }
process_start() { if [ "$1" = 100 ]; then cat "$root/fs/live.start"; else printf 22; fi; }
process_exe() { if [ "$1" = 100 ]; then printf /usr/bin/sleep; else printf /usr/bin/dockerd; fi; }
process_args() { printf '/usr/bin/sleep\\n900'; }
process_exists() {
 if [ "$1" = 100 ]; then
  [ "$scenario" != expired ] && [ "$scenario" != partial-absent ] && [ ! -f "$root/fs/retired" ]
 elif [ "$1" = 300 ]; then [ "$scenario" != vanished-member ]; else return 0; fi
}
process_net() {
 if [ "$1" = 100 ]; then printf 'net:[2]';
 elif [ "$1" = 300 ]; then
  case "$scenario" in
   reused-midscan) printf 99 > "$root/fs/live.start";;
   expired-midscan) printf retired > "$root/fs/retired";;
   unreadable-live|vanished-member) return 1;;
   retained-member) printf 'net:[2]'; return 0;;
  esac
  printf 'net:[1]'
 else printf 'net:[1]'; fi
}
kill() { [ "$1" = -TERM ] && [ "$2" = 100 ]; printf retired > "$root/fs/retired"; printf 'signal-holder\\n'; }
`;
 const script=i.scripts.cleanup.replace(i.guard,i.guard+overrides);
 const result=spawnSync('/bin/sh',['-c',script,'netns-cleanup','/var/tmp/owasp-ai-goat-v23-build-'+'a'.repeat(32),'a'.repeat(32),root,scenario],{encoding:'utf8'});
 const allowed=['expired','partial-absent','partial-live','expired-midscan','vanished-member'].includes(scenario);
 if(allowed){assert.equal(result.status,0,result.stderr);assert.equal(syncFs.existsSync(root),false);assert.match(result.stdout,/absent/);}
 else{assert.notEqual(result.status,0);assert.equal(syncFs.existsSync(root),true);assert.doesNotMatch(result.stdout,/absent/);}
 if(['partial-live','vanished-member'].includes(scenario))assert.match(result.stdout,/signal-holder/);
 else assert.doesNotMatch(result.stdout,/signal-holder/,'no signal with stale, missing or uncertain ownership');
});
test('composed metadata shell isolates phase diagnostics from the JSON report channel',()=>{
 const quote=value=>"'"+value.replace(/'/g,"'\\''")+"'";
 // Egress gate remains closed in production. This composition-only control
 // removes that call and replaces every effectful phase with inert output.
 let script=i.scripts['metadata-acquire'].replace('require_private_egress\nacquisition_deadline=', 'acquisition_deadline=');
 // Clock is an inert fixture too: do not invoke the macOS /usr/bin Python shim.
 script=script.replace(/acquisition_deadline=\$\([^\n]+\)/,'acquisition_deadline=1234.500000');
 // Execute the real composition/redirections, replacing only its separately
 // reviewed effectful phase bodies. No Docker, filesystem or network effects.
 for(const phase of ['preflight','prepare','start','metadata']){
  const original=quote(i.scripts[phase]);assert.ok(script.includes(original));
  const body=phase==='metadata'?"printf '%s' '{\"candidateOnly\":true}'":`printf '%s\\n' '${phase}-diagnostic'`;
  script=script.replace(original,quote(body));
 }
 const spec=specification('/controlled/repo','a'.repeat(32));
 const invoke=body=>spawnSync('/bin/sh',['-c',body,'metadata-control',spec.guest,spec.runId,'pinned-base'],{encoding:'utf8'});
 const clean=invoke(script);assert.equal(clean.status,0,clean.stderr);
 assert.deepEqual(JSON.parse(clean.stdout),{candidateOnly:true});
 assert.equal(clean.stderr.split('\n').filter(line=>line&&!line.startsWith('OWASP_AI_GOAT_METADATA_STAGE=')).join('\n'),
  'preflight-diagnostic\nprepare-diagnostic\nstart-diagnostic');
 const broken=invoke(script.replace('metadata-preflight "$root" "$nonce" >&2','metadata-preflight "$root" "$nonce"'));
 assert.equal(broken.status,0);assert.throws(()=>JSON.parse(broken.stdout));
 assert.match(broken.stdout,/^preflight-diagnostic/);
});
test('metadata stderr keeps only bounded stage/code provenance, never raw error text',async()=>{
 const child=new EventEmitter();Object.assign(child,{pid:12345,stdin:new PassThrough(),stdout:new PassThrough(),stderr:new PassThrough()});
 let observed;
 const execute=i.createExecutor({launch:()=>child,kill:()=>{},delay:async()=>{}});
 const promise=execute(specification('/controlled/repo','a'.repeat(32)),'metadata-cleanup',{onDiagnostics:value=>{observed=value;}});
 child.stderr.emit('data',Buffer.from('OWASP_AI_GOAT_METADATA_STA'));
 child.stderr.emit('data',Buffer.from('GE=apt-update\nprivate-url-token\nOWASP_AI_GOAT_METADATA_ERROR=ENOSPC\n'));
 child.stderr.emit('data',Buffer.from('x'.repeat(600)+'OWASP_AI_GOAT_METADATA_STAGE=report\nOWASP_AI_GOAT_METADATA_ERROR=secret-value\n'));
 child.emit('close',1,'SIGTERM');
 await assert.rejects(promise,error=>error.metadataDiagnostics===observed);
 assert.equal(observed.lastStage,'apt-update');assert.equal(observed.errorCode,'ENOSPC');
 assert.equal(observed.exitCode,1);assert.equal(observed.signal,'SIGTERM');assert.ok(observed.stderrBytes>600);
 assert.match(observed.stderrSha256,/^[a-f0-9]{64}$/);assert.equal(observed.rawStderrRetained,false);
 assert.doesNotMatch(JSON.stringify(observed),/private-url|secret-value/);
});

for(const scenario of ['exact','none','extra','wrong-source','wrong-parent','wrong-fstype','changed','symlink','unmount-failed'])test(`metadata namespace cleanup refuses unrelated mounts: ${scenario}`,async t=>{
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'metadata-mount-control-'));
 t.after(()=>fs.rm(root,{recursive:true,force:true}));
 await fs.mkdir(path.join(root,'fs/exec/netns'),{recursive:true});
 if(scenario==='symlink')await fs.symlink('/foreign',path.join(root,'fs/exec/netns/default'));
 else await fs.writeFile(path.join(root,'fs/exec/netns/default'),'');
 const body=i.guard+`
root="$3"; scenario="$4"; checks=0; removed=0
check_mount() { checks=$((checks+1)); }
readlink() { printf '%s' "$2"; }
findmnt() {
 case "$*" in
  '-rn -R -o TARGET --mountpoint '*)
   printf '%s\\n' "$root/fs"
   if [ "$scenario" != none ] && [ "$removed" = 0 ]; then printf '%s\\n' "$root/fs/exec/netns/default"; fi
   if [ "$scenario" = extra ]; then printf '%s\\n' "$root/fs/foreign"; fi;;
  '-rn -o ID,PARENT,FSTYPE,SOURCE --mountpoint '*)
   if [ "$scenario" = wrong-source ]; then printf '208 192 nsfs foreign';
   elif [ "$scenario" = wrong-parent ]; then printf '208 999 nsfs nsfs[net:[4026531840]]';
   elif [ "$scenario" = wrong-fstype ]; then printf '208 192 ext4 nsfs[net:[4026531840]]';
   elif [ "$scenario" = changed ] && [ "$checks" -gt 1 ]; then printf '209 192 nsfs nsfs[net:[4026531840]]';
   else printf '208 192 nsfs nsfs[net:[4026531840]]'; fi;;
  '-rn -o ID --mountpoint '*) printf 192;;
  '-rn --mountpoint '*) if [ "$removed" = 0 ]; then printf present; fi;;
  *) return 99;;
 esac
}
umount() { [ "$1" = -- ] && [ "$2" = "$root/fs/exec/netns/default" ]; printf 'child-unmount\\n'; [ "$scenario" != unmount-failed ] || return 1; removed=1; }
`+i.metadataNamespaceCleanup+'\nunmount_metadata_namespace\nprintf parent-unmount';
 const result=spawnSync('/bin/sh',['-c',body,'metadata-mount-test','/var/tmp/owasp-ai-goat-v23-build-'+'a'.repeat(32),'a'.repeat(32),root,scenario],{encoding:'utf8'});
 if(['exact','none'].includes(scenario)){assert.equal(result.status,0,result.stderr);assert.equal(result.stdout,scenario==='exact'?'child-unmount\nparent-unmount':'parent-unmount');}
 else{assert.notEqual(result.status,0);assert.doesNotMatch(result.stdout,/parent-unmount/);if(scenario!=='unmount-failed')assert.doesNotMatch(result.stdout,/child-unmount/);}
 assert.ok(i.scripts['metadata-cleanup'].indexOf('for proc in /proc/')<i.scripts['metadata-cleanup'].indexOf('unmount_metadata_namespace'));
 assert.doesNotMatch(i.scripts.cleanup,/unmount_metadata_namespace/,'MCP default cleanup is unchanged');
});
test('metadata stderr cap fails before success and retains only bounded diagnostic fields',async()=>{
 const child=new EventEmitter();Object.assign(child,{pid:12345,stdin:new PassThrough(),stdout:new PassThrough(),stderr:new PassThrough()});
 const kills=[];const execute=i.createExecutor({launch:()=>child,kill:(...args)=>kills.push(args),delay:async()=>{}});
 const promise=execute(specification('/controlled/repo','a'.repeat(32)),'metadata-cleanup');
 child.stderr.emit('data',Buffer.from('OWASP_AI_GOAT_METADATA_STAGE=base-pull\n'));
 child.stderr.emit('data',Buffer.alloc(LIMITS.output,120));child.emit('close',0);
 await assert.rejects(promise,error=>{
  assert.equal(error.code,'BUILD_OUTPUT_LIMIT');assert.equal(error.metadataDiagnostics.lastStage,'base-pull');
  assert.ok(error.metadataDiagnostics.stderrBytes>LIMITS.output/2);
  assert.equal(error.metadataDiagnostics.rawStderrRetained,false);
  assert.ok(JSON.stringify(error.metadataDiagnostics).length<512);return true;
 });
 assert.deepEqual(kills,[[-12345,'SIGKILL']]);
});

const network={version:1,bridge:{Id:'controlled-bridge'},links:[{ifname:'docker0'}],addresses:[],routes4:[],routes6:[],rules4:[],rules6:[],firewall4:'',firewall6:'',nft:{nftables:[]},forwarding:'1\n0\n'};
const inventory=JSON.stringify(PINS.daemon)+'\n'+PINS.postgres+' postgres:18\n\nCONTAINERS\n\nVOLUMES\n\nNETWORK\n'+JSON.stringify(network)+'\n';
function fixture(t,options={}) {
  // Empty artifact fixture only: no source checkout or runtime is copied.
  const root=syncFs.mkdtempSync(path.join(os.tmpdir(),'bounded-build-control-'));
  syncFs.mkdirSync(path.join(root,'tasks/tmp'),{recursive:true});
  const runId=crypto.randomBytes(16).toString('hex'),spec=specification(root,runId);
  const calls=[];
  t.after(()=>fs.rm(root,{recursive:true,force:true}));
  let inventoryReads=0;
  const daemon={ID:'private-daemon',DockerRootDir:spec.mount+'/data',Driver:'overlay2',Architecture:'aarch64'};
  const image={Id:'sha256:'+'b'.repeat(64),Architecture:'arm64',Os:'linux',Config:{Labels:{'owasp-ai-goat.registry.package':source.packageDigest(),'owasp-ai-goat.build-run':runId}}};
  const runner=async(actual,operation,operationOptions={})=>{
    assert.deepEqual(actual,spec);calls.push(operation);
    if(operation===options.failure)throw Object.assign(Error(options.code||'controlled'),{code:options.code||'CONTROLLED'});
    switch(operation){
      case 'inventory': return ++inventoryReads>1&&options.sharedChanged?inventory+'foreign-volume\n':inventory;
      case 'preflight':case 'prepare':return '';
      case 'start':return JSON.stringify(daemon);
      case 'inspect':return JSON.stringify({...daemon,...options.changedDaemon});
      case 'build':{
        assert.deepEqual(operationOptions.args,[source.packageDigest(),require('../scripts/install/manifests/secureshop-owned-mcp-registry-build.json').dockerfile]);
        const chunks=[];for await(const chunk of operationOptions.input)chunks.push(chunk);
        assert(Buffer.concat(chunks).includes(Buffer.from('controlled.txt')));return '';
      }
      case 'image':return JSON.stringify([{...image,...options.changedImage}]);
      case 'export':
        if(!options.empty)await operationOptions.sink(Buffer.from('controlled-image-archive'));
        return '';
      case 'cleanup':return options.cleanupUncertain?'unknown':'absent\n';
      default:assert.fail(operation);
    }
  };
  return {spec,calls,run:()=>runBoundedBuild({root,runId,runner,verify:async()=>{},capture:async()=>[{name:'controlled.txt',bytes:Buffer.from('fixture')} ]})};
}
test('bounded build validates identity, exports bounded artifact, verifies cleanup and preserves shared assets',async t=>{
  const f=fixture(t),result=await f.run();
  assert.equal(result.cleanupVerified,true);assert.equal(result.qualificationComplete,false);
  assert.equal(result.archiveBytes,24);
  assert.equal(result.archiveSha256,crypto.createHash('sha256').update('controlled-image-archive').digest('hex'));
  assert.deepEqual(f.calls,['inventory','preflight','prepare','start','inspect','build','inspect','image','export','cleanup','inventory']);
  assert.equal((await fs.stat(path.join(f.spec.artifact,'image.tar'))).mode&0o777,0o600);
});
test('invalid paths and run identities cannot form a destructive specification',()=>{
  for(const root of ['/', '.', '/tmp/../tmp','relative'])assert.throws(()=>specification(root,'a'.repeat(32)));
  for(const run of ['../foreign','A'.repeat(32),'a'.repeat(31),'a; rm -rf /'])assert.throws(()=>specification('/tmp/repo',run));
  assert.equal(specification('/tmp/repo','a'.repeat(32)).guest,'/var/tmp/owasp-ai-goat-v23-build-'+'a'.repeat(32));
});
test('host runtime identity fails before runner contact',async()=>{
  let called=false;
  await assert.rejects(runBoundedBuild({root:path.resolve(__dirname,'..'),runId:'a'.repeat(32),verify:async()=>{throw Error('pin');},runner:async()=>{called=true;}}),/pin/);
  assert.equal(called,false);
});
for(const [failure,code] of [['prepare','ENOSPC'],['start','BUILD_TIMEOUT'],['build','BUILD_TIMEOUT'],['export','BUILD_TIMEOUT']])test(`${failure} ${code} still joins cleanup and verifies preservation`,async t=>{
  const f=fixture(t,{failure,code});await assert.rejects(f.run(),AggregateError);
  assert.deepEqual(f.calls.slice(-2),['cleanup','inventory']);
  const receipt=JSON.parse(await fs.readFile(path.join(f.spec.artifact,'result.json')));
  assert.equal(receipt.error,code);assert.equal(receipt.result,null);assert.equal(receipt.cleanupVerified,true);
});
for(const changedDaemon of [{ID:PINS.daemon},{ID:'replacement'},{DockerRootDir:'/var/lib/docker'},{Driver:'overlayfs'}])test('foreign or changed private daemon prevents build',async t=>{
  const f=fixture(t,{changedDaemon});await assert.rejects(f.run(),AggregateError);assert(!f.calls.includes('build'));
});
test('empty export never becomes a successful artifact',async t=>{
  const f=fixture(t,{empty:true});await assert.rejects(f.run(),AggregateError);
  assert.deepEqual(f.calls.slice(-2),['cleanup','inventory']);
});
for(const options of [{cleanupUncertain:true},{failure:'cleanup'},{sharedChanged:true}])test('cleanup uncertainty or changed PostgreSQL inventory prevents success',async t=>{
  const f=fixture(t,options);await assert.rejects(f.run(),AggregateError);
  const receipt=JSON.parse(await fs.readFile(path.join(f.spec.artifact,'result.json')));
  assert.equal(receipt.cleanupVerified,false);assert(receipt.cleanupErrors.length);
});
test('image identity mismatch cannot be exported',async t=>{
  const f=fixture(t,{changedImage:{Architecture:'amd64'}});await assert.rejects(f.run(),AggregateError);assert(!f.calls.includes('export'));
});
test('shared daemon and PostgreSQL pin are mandatory',()=>{
  assert.equal(i.checkInventory(inventory),inventory);
  assert.throws(()=>i.checkInventory(inventory.replace(PINS.postgres,'sha256:'+'c'.repeat(64))));
  assert.throws(()=>i.checkInventory(inventory.replace(PINS.daemon,'another-daemon')));
  assert.throws(()=>i.checkInventory(inventory.split('\nNETWORK\n')[0]),{code:'BUILD_SHARED_NETWORK_UNPROVEN'});
  assert.throws(()=>i.checkInventory(inventory.replace('docker0','missing')),{code:'BUILD_SHARED_NETWORK_UNPROVEN'});
});
test('shared network witness preserves stable configuration and rejects absent bridge/address',()=>{
 const fixture={
  'docker --host unix:///run/docker.sock network inspect bridge':[{Id:'exact',Containers:{},Options:{'com.docker.network.bridge.name':'docker0'},IPAM:{Config:[{Gateway:'172.17.0.1'}]}}],
  'ip -json -details link show':[{ifindex:3,ifname:'docker0',linkinfo:{info_kind:'bridge',info_data:{hello_timer:99,hello_time:200}}}],
  'ip -json address show':[{ifname:'docker0',addr_info:[{local:'172.17.0.1',prefixlen:16,valid_life_time:99,preferred_life_time:98}]}],
  'ip -json -4 route show table all':[{dst:'default',gateway:'192.168.5.2',expires:55}],
  'ip -json -6 route show table all':[], 'ip -json -4 rule show':[{priority:0,table:'local'}], 'ip -json -6 rule show':[],
  'iptables-save':'# Generated now\n*filter\n:INPUT ACCEPT [7:9]\n-A INPUT -j ACCEPT\nCOMMIT\n',
  'ip6tables-save':'*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n',
  'nft -json list ruleset':{nftables:[{metainfo:{version:'moving'}},{rule:{handle:7,expr:[{counter:{packets:3,bytes:9}},{accept:null}]}}]},
  'sysctl -n net.ipv4.ip_forward net.ipv6.conf.all.forwarding':'1\n0\n'
 };
 const invoke=data=>spawnSync('python3',['-B','-c',i.networkSnapshotProgram.replace("print(json.dumps(snapshot(), sort_keys=True, separators=(',', ':')))",`
fixtures=json.loads(${JSON.stringify(JSON.stringify(data))})
def read(args):
    value=fixtures[' '.join(args)]
    return value if isinstance(value,str) else json.dumps(value)
print(json.dumps(snapshot(),sort_keys=True))`)],{encoding:'utf8'});
 const clean=invoke(fixture);assert.equal(clean.status,0,clean.stderr);const captured=JSON.parse(clean.stdout);
 assert.equal(captured.links[0].ifindex,3);assert.equal(captured.links[0].linkinfo.info_data.hello_time,200);
 assert.equal(captured.links[0].linkinfo.info_data.hello_timer,undefined);
 assert.equal(captured.addresses[0].addr_info[0].valid_life_time,undefined);
 assert.match(captured.firewall4,/:INPUT ACCEPT \[0:0\]/);
 assert.equal(captured.nft.nftables[0].rule.handle,7);assert.deepEqual(captured.nft.nftables[0].rule.expr[0].counter,{});
 for(const [key,value] of [['ip -json -details link show',[]],['ip -json address show',[]]]){
  const result=invoke({...fixture,[key]:value});assert.notEqual(result.status,0);assert.equal(result.stdout,'');
 }
 for(const [key,value] of [['ip -json -4 route show table all',[{dst:'default',gateway:'foreign'}]],['iptables-save','*filter\n:INPUT DROP [0:0]\nCOMMIT\n']]){
  const result=invoke({...fixture,[key]:value});assert.equal(result.status,0,result.stderr);assert.notEqual(result.stdout,clean.stdout);
 }
});
test('startup witness runs after daemon admission and before returning startup success',()=>{
 assert.ok(i.scripts.prepare.indexOf('network_snapshot >')<i.scripts.prepare.indexOf('fallocate -l'));
 assert.match(i.scripts.start,/check_runtime\ncheck_network\ndocker --host/);
 assert.ok(i.scripts['metadata-acquire'].includes(i.scripts.start.replace(/'/g,"'\\''")));
 assert.doesNotMatch(i.networkShell,/restart|link (add|delete|set)|iptables .*-[AFDX]|network (create|rm)/);
});
test('network witness command reader stops oversized output and rejects failed commands',()=>{
 const prefix=i.networkSnapshotProgram.slice(0,i.networkSnapshotProgram.lastIndexOf('print(json.dumps(snapshot()'));
 for(const command of ["import sys; sys.stdout.write('x'*524289)","import sys; sys.stderr.write('failure'); sys.exit(2)"]){
  const script=prefix+`\nimport sys\nread([sys.executable,'-c',${JSON.stringify(command)}])\n`;
  const result=spawnSync('python3',['-B','-c',script],{encoding:'utf8',timeout:10000,maxBuffer:4096});
  assert.notEqual(result.status,0);assert.equal(result.stdout,'');assert.match(result.stderr,/network witness (bound|command failed)/);
 }
});
for(const scenario of ['unchanged','changed','unavailable'])test(`cleanup still removes exact owned disk root after network witness ${scenario}`,async t=>{
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'network-cleanup-control-'));
 t.after(()=>fs.rm(directory,{recursive:true,force:true}));
 const root=path.join(directory,'owned');await fs.mkdir(root);await fs.writeFile(path.join(root,'owner'),'controlled');
 await fs.writeFile(path.join(root,'network.before.json'),'baseline\n');
 const overrides=`\nroot="$3"\ncheck_owner() { [ "$root" = "$3" ]; }\nstop_owned() { printf 'joined:%s\\n' "$1"; }\nmountpoint() { return 1; }\nfindmnt() { :; }\nnetwork_snapshot() { ${scenario==='unavailable'?'return 1':`printf '${scenario==='changed'?'changed':'baseline'}\\n'`}; }\n`;
 // Only platform probes are replaced. Execute actual comparison and final
 // owned-directory cleanup against this empty controlled artifact directory.
 const script=i.scripts.cleanup.replace(i.guard,i.guard+overrides.replace('check_owner() { [ "$root" = "$3" ]; }','check_owner() { [ -f "$root/owner" ]; }'));
 const result=spawnSync('/bin/sh',['-c',script,'network-cleanup','/var/tmp/owasp-ai-goat-v23-build-'+'a'.repeat(32),'a'.repeat(32),root],{encoding:'utf8'});
 assert.equal(result.status,scenario==='unchanged'?0:94,result.stderr);
 assert.equal(syncFs.existsSync(root),false,'network mismatch must not retain owned disk root');
 assert.match(result.stdout,/joined:daemon\njoined:containerd/);
 if(scenario!=='unchanged')assert.doesNotMatch(result.stdout,/absent/);
});
test('post-start network mismatch never reaches build and preserves cleanup failure evidence',async t=>{
 const f=fixture(t,{failure:'start',code:'BUILD_SHARED_NETWORK_CHANGED'});
 await assert.rejects(f.run(),AggregateError);assert(!f.calls.includes('build'));
 assert.deepEqual(f.calls.slice(-2),['cleanup','inventory']);
 const receipt=JSON.parse(await fs.readFile(path.join(f.spec.artifact,'result.json')));
 assert.equal(receipt.error,'BUILD_SHARED_NETWORK_CHANGED');assert.equal(receipt.result,null);
});
test('export overflow rejects before writing excess bytes, including cumulative chunks',async()=>{
  const written=[],sink=i.boundedSink(async chunk=>written.push(chunk.toString()),4);
  await sink(Buffer.from('ab'));await sink(Buffer.from('cd'));
  await assert.rejects(sink(Buffer.from('e')),{code:'BUILD_EXPORT_LIMIT'});
  assert.deepEqual(written,['ab','cd']);
  await assert.rejects(i.boundedSink(()=>assert.fail('must not write'),4)(Buffer.alloc(5)),{code:'BUILD_EXPORT_LIMIT'});
});
test('guest recipes bound disk and avoid shared containerd or destructive wildcard targets',()=>{
  assert.equal(LIMITS.disk,6*1024**3);assert.equal(LIMITS.export,1024**3);
  assert.match(i.scripts.prepare,/fallocate -l 6442450944/);
  assert.match(i.scripts.start,/--feature=containerd-snapshotter=false/);
  assert.match(i.scripts.start,/--containerd="\$root\/fs\/containerd.sock"/);
  assert.doesNotMatch(i.scripts.start,/\/run\/containerd\/containerd.sock/);
  assert.match(i.scripts.cleanup,/check_owner\n\[ -z/);
  assert.match(i.scripts.cleanup,/rm -rf -- "\$root"/);
});
test('all fixed guest recipes parse without executing VM operations',()=>{
  for(const [name,script] of Object.entries(i.scripts)){
    const result=spawnSync('/bin/sh',['-n'],{input:script,encoding:'utf8'});
    assert.equal(result.status,0,name+': '+result.stderr);
  }
});

for(const scenario of ['stdout-limit','stderr-limit','stdin-error','lost-reply','sink-error'])test(`remote timeout window joins before cleanup after ${scenario}`,async()=>{
  const child=new EventEmitter();Object.assign(child,{pid:12345,stdin:new PassThrough(),stdout:new PassThrough(),stderr:new PassThrough()});
  const kills=[],waits=[];let release,settled=false;
  const remoteWindow=new Promise(resolve=>{release=resolve;});
  const execute=i.createExecutor({launch:()=>child,kill:(...args)=>kills.push(args),delay:async ms=>{waits.push(ms);await remoteWindow;}});
  const operation='export';
  const promise=execute(specification('/tmp/controlled-repo','a'.repeat(32)),operation,
    scenario==='sink-error'?{sink:async()=>{throw Error('sink overflow');}}:{});
  // A caller's catch/finally is where remote cleanup could otherwise race.
  const outcome=promise.then(value=>{settled=true;return{value};},error=>{settled=true;return{error};});
  if(scenario==='stdout-limit')child.stdout.emit('data',Buffer.alloc(LIMITS.output+1));
  if(scenario==='stderr-limit')child.stderr.emit('data',Buffer.alloc(LIMITS.output+1));
  if(scenario==='stdin-error')child.stdin.emit('error',Error('EPIPE'));
  if(scenario==='sink-error')child.stdout.emit('data',Buffer.from('x'));
  child.emit('close',scenario==='lost-reply'?255:0);
  await new Promise(setImmediate);
  assert.equal(settled,false,'local close must not release caller cleanup');
  assert.deepEqual(waits,[operation==='build'?330000:170000]);
  if(scenario!=='lost-reply')assert(kills.some(([pid,signal])=>pid===-12345&&signal==='SIGKILL'));
  release();assert((await outcome).error);assert.equal(settled,true);
});

test('successful remote acknowledgement does not wait or kill the client',async()=>{
  const child=new EventEmitter();Object.assign(child,{pid:12345,stdin:new PassThrough(),stdout:new PassThrough(),stderr:new PassThrough()});
  const execute=i.createExecutor({launch:()=>child,kill:()=>assert.fail('no kill'),delay:()=>assert.fail('no wait')});
  const promise=execute(specification('/tmp/controlled-repo','a'.repeat(32)),'inspect');
  child.stdout.emit('data',Buffer.from('ack'));child.emit('close',0);
  assert.equal(await promise,'ack');
});

test('actual shell loop validation accepts only a nonempty numeric suffix',()=>{
  for(const device of ['/dev/loop0','/dev/loop123','/dev/loop','/dev/loop1x','/dev/loop1/foreign','/dev/loop1;echo bad','/dev/loop1\n2','/dev/sda']){
    const result=spawnSync('/bin/sh',['-c',i.guard+'\nvalidate_loop "$3"\nprintf accepted\n','loop-test','/var/tmp/owasp-ai-goat-v23-build-'+'a'.repeat(32),'a'.repeat(32),device],{encoding:'utf8'});
    if(['/dev/loop0','/dev/loop123'].includes(device)){assert.equal(result.status,0,result.stderr);assert.equal(result.stdout,'accepted');}
    else{assert.notEqual(result.status,0,device);assert.equal(result.stdout,'');}
  }
});

for(const scenario of ['both','containerd-only','daemon-only','bad-start','bad-argv','bad-config','retained-process'])test(`private sibling cleanup executes exact identity gates: ${scenario}`,async t=>{
  const fixtureRoot=await fs.mkdtemp(path.join(os.tmpdir(),'private-containerd-control-'));
  t.after(()=>fs.rm(fixtureRoot,{recursive:true,force:true}));
  await fs.mkdir(path.join(fixtureRoot,'fs'));
  for(const [name,pid] of [['daemon','101'],['containerd','102']]){
    if(scenario==='containerd-only'&&name==='daemon'||scenario==='daemon-only'&&name==='containerd')continue;
    await fs.writeFile(path.join(fixtureRoot,'fs',name+'.pid'),pid);
    await fs.writeFile(path.join(fixtureRoot,'fs',name+'.start'),'77');
  }
  await fs.writeFile(path.join(fixtureRoot,'fs/daemon.json'),'{}\n');
  const body=i.guard+`
root="$3"
write_containerd_config
if [ "$4" = bad-config ]; then printf 'foreign\\n' >> "$root/fs/containerd.toml"; fi
scenario="$4"
daemon_live=1; containerd_live=1
check_mount() { :; }
check_binary() { :; }
check_namespace_record() { private_net='net:[77]'; }
process_net() { printf 'net:[77]'; }
process_exists() { if [ "$1" = 101 ]; then [ "$daemon_live" = 1 ]; else [ "$containerd_live" = 1 ]; fi; }
process_start() { if [ "$scenario" = bad-start ] && [ "$1" = 102 ]; then printf 78; else printf 77; fi; }
process_comm() { if [ "$1" = 101 ]; then printf dockerd; else printf containerd; fi; }
process_exe() { printf '/usr/bin/'; process_comm "$1"; }
process_args() {
 if [ "$1" = 101 ]; then daemon_arguments;
 elif [ "$scenario" = bad-argv ]; then printf '/usr/bin/containerd\\n--address=/run/containerd/containerd.sock\\n';
 else containerd_arguments; fi
}
sleep() { :; }
kill() {
 printf 'signal:%s:%s\\n' "$1" "$2"
 if [ "$scenario" != retained-process ]; then
  if [ "$2" = 101 ]; then daemon_live=0; else containerd_live=0; fi
 fi
}
stop_owned daemon
stop_owned containerd
printf joined
`;
  const result=spawnSync('/bin/sh',['-c',body,'cleanup-test','/var/tmp/owasp-ai-goat-v23-build-'+'a'.repeat(32),'a'.repeat(32),fixtureRoot,scenario],{encoding:'utf8'});
  if(['both','containerd-only','daemon-only'].includes(scenario)){
    assert.equal(result.status,0,result.stderr);assert.match(result.stdout,/joined$/);
    const expected=scenario==='both'?['signal:-TERM:101','signal:-TERM:102']:scenario==='containerd-only'?['signal:-TERM:102']:['signal:-TERM:101'];
    assert.deepEqual(result.stdout.split('\n').filter(x=>x.startsWith('signal:')),expected);
  }else{
    assert.notEqual(result.status,0);assert.doesNotMatch(result.stdout,/joined/);
    if(scenario!=='retained-process')assert.doesNotMatch(result.stdout,/signal:.*:102/,'foreign private containerd must not be killed');
    else assert.match(result.stdout,/signal:-KILL:101/);
  }
  const config=await fs.readFile(path.join(fixtureRoot,'fs/containerd.toml'),'utf8');
  assert(config.includes(`root = "${fixtureRoot}/fs/containerd-root"`));
  assert(config.includes(`state = "${fixtureRoot}/fs/containerd-state"`));
  assert(config.includes(`address = "${fixtureRoot}/fs/containerd.sock"`));
  assert(config.includes('imports = []\ndisabled_plugins = ["io.containerd.grpc.v1.cri", "io.containerd.cri.v1.images", "io.containerd.cri.v1.runtime", "io.containerd.nri.v1.nri"]'));
  assert(!config.includes('/var/lib/containerd'));assert(!config.includes('/run/containerd'));
});
