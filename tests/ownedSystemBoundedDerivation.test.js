'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises');
const path=require('node:path'),crypto=require('node:crypto');
const {spawnSync}=require('node:child_process');
const derive=require('./postgres/ownedSystemBoundedDerivation');
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');

function pairPython(program,extra){
 const result=spawnSync('/opt/homebrew/bin/python3',['-I','-S','-B','-c',program+'\n'+extra],
  {encoding:'utf8',timeout:5000,maxBuffer:32768});assert.equal(result.status,0,result.stderr);
}
function childProgram(){
 return derive._internals.pairChild(require('./postgres/ownedMcpPrivateEgress')._internals.program+
  '\nTRANSPORT_RUN="'+ 'a'.repeat(32)+'"\nTRANSPORT_MODE="adapter"\ndef snapshot():\n return dict(activeWorkers=threading.active_count()-1,other=0)\n');
}
test('actual paired child hard quotas preserve cumulative admissions and burn unused phase capacity',()=>{
 pairPython(childProgram(),String.raw`
import copy
row=dict(version=1,policy=PAIR_POLICY,runId=TRANSPORT_RUN,sequence=0,phase='system-overhead',allocation=32,starts=dict(adapter=0,connector=0),quota=32,artifactCount=0)
pair_read=lambda *args:copy.deepcopy(row)
b=Budget();PAIR_BUDGET=b
for _ in range(14):b.admit()
row.update(sequence=1,phase='system-artifacts',allocation=33,starts=dict(adapter=14,connector=14),quota=1,artifactCount=1)
b.admit()
try:b.admit();raise AssertionError('unused overhead carried over')
except Denied:pass
assert b.connections==15
row.update(sequence=2,phase='policy-overhead',allocation=65,starts=dict(adapter=15,connector=15),quota=32,artifactCount=0)
for _ in range(32):b.admit()
try:b.admit();raise AssertionError('overhead overflow')
except Denied:pass
row.update(sequence=3,phase='policy-artifacts',allocation=193,starts=dict(adapter=47,connector=47),quota=128,artifactCount=128)
for _ in range(128):b.admit()
assert b.connections==175
row.update(sequence=4,phase='sealed',starts=dict(adapter=175,connector=175),quota=0,artifactCount=0)
assert pair_budget_snapshot()['connections']==175
try:b.admit();raise AssertionError('postseal connect')
except Denied:pass
assert b.connections==175 and b.total==0
`);
});
test('actual relay admits lifetime320 then rejects321 and invalid grants',()=>{
 pairPython(childProgram(),String.raw`
import copy
initial=dict(version=1,policy=PAIR_POLICY,runId=TRANSPORT_RUN,sequence=0,phase='system-overhead',allocation=32,starts=dict(adapter=0,connector=0),quota=32,artifactCount=0)
row=copy.deepcopy(initial);pair_read=lambda *args:copy.deepcopy(row)
b=Budget();PAIR_BUDGET=b
for seq,quota in enumerate((32,128,32,128)):
 if seq:row.update(sequence=seq,phase=PAIR_PHASES[seq],allocation=row['allocation']+quota,starts=dict(adapter=b.connections,connector=b.connections),quota=quota,artifactCount=quota if seq in (1,3) else 0)
 for _ in range(quota):b.admit()
 try:b.admit();raise AssertionError('quota overflow')
 except Denied:pass
assert b.connections==320
row.update(sequence=4,phase='sealed',starts=dict(adapter=320,connector=320),quota=0,artifactCount=0)
assert pair_budget_snapshot()['connections']==320
for field,value in (('sequence',0),('sequence',3),('allocation',321),('runId','b'*32),('quota',True)):
 invalid=copy.deepcopy(row);invalid[field]=value;pair_read=lambda *args:copy.deepcopy(invalid)
 try:b.admit();raise AssertionError('invalid record')
 except (ValueError,Denied):pass
 assert b.connections==320
row=copy.deepcopy(initial);pair_read=lambda *args:copy.deepcopy(row);b=Budget();PAIR_BUDGET=b;b.admit()
row.update(sequence=2,phase='policy-overhead',allocation=64,starts=dict(adapter=1,connector=1))
try:b.admit();raise AssertionError('skipped phase')
except Denied:pass
row=copy.deepcopy(initial);row['starts']['adapter']=1
try:b.admit();raise AssertionError('same-phase rewrite')
except (ValueError,Denied):pass
def missing(*args):raise FileNotFoundError()
pair_read=missing
try:b.admit();raise AssertionError('missing grant')
except (FileNotFoundError,Denied):pass
assert b.connections==1
`);
});
const CONTROLLER_FILES=String.raw`
import tempfile,types,copy,contextlib,io
workspace=tempfile.TemporaryDirectory();ROOT=workspace.name;RUN='a'*32;RELAY=ROOT+'/relay'
os.mkdir(ROOT+'/fs');os.mkdir(RELAY)
def require(v,reason='CONTROL_DENIED'):
 if not v:raise RuntimeError(reason)
def read(p):return open(p).read()
def save(name,value):
 fd=os.open(ROOT+'/fs/'+name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 try:os.write(fd,json.dumps(value).encode());os.fsync(fd)
 finally:os.close(fd)
# Only root ownership is doubled; real descriptor IO, caps, exclusive writes,
# fsync and atomic rename execute on repository-local temporary files.
real_fstat=os.fstat
def fstat(fd):
 s=real_fstat(fd)
 return types.SimpleNamespace(**{k:(0 if k=='st_uid' else getattr(s,k)) for k in ('st_mode','st_uid','st_nlink','st_size','st_dev','st_ino','st_mtime_ns','st_ctime_ns')})
os.fstat=fstat
authority=lambda:None
counts=dict(adapter=0,connector=0)
rejections=dict(adapter=0,connector=0)
def observe():
 r=pair_shape(pair_read(RELAY+'/pair-credit.json',0o444),RUN)
 return r,copy.deepcopy(counts),dict(row=r,counts=copy.deepcopy(counts),rows={mode:dict(admission=dict(workerLimitRejected=rejections[mode],connectionLimitRejected=0,saturated=False)) for mode in rejections})
pair_observe=observe
def candidate(slot,count):
 d=ROOT+'/fs/'+slot+'-metadata-retained';os.mkdir(d)
 p=d+'/result.json'
 with open(p,'x') as f:json.dump(dict(version=3,ok=True,binding=dict(base=PAIR_BASES[slot],runId=RUN,target='v24-'+slot),candidate=dict(selected=[dict(sha256=format(i,'064x')) for i in range(count)])),f)
 os.chmod(p,0o444)
 d=ROOT+'/fs/'+slot+'-closure';os.mkdir(d)
 with open(d+'/closure.json','x') as f:json.dump(dict(acquired=dict(artifacts=[dict(kind='deb',digest=format(i,'064x')) for i in range(count)],attemptProof=dict(version=1,attempts=[dict(index=i,kind='deb',digest=format(i,'064x'),ordinal=1,outcome='verified') for i in range(count)]))),f)
 os.chmod(d+'/closure.json',0o400)
def run(sequence):
 with contextlib.redirect_stdout(io.StringIO()):pair_advance(sequence)
`;
function controllerProgram(){return 'import os,sys,stat,json,time,re\n'+derive._internals.pairController()+CONTROLLER_FILES;}
test('actual controller publishes atomic capacity, separate idle records and one-shot advances',()=>{
 pairPython(controllerProgram(),String.raw`
pair_initialize();candidate('system',35);candidate('policy',31)
pair_idle_save('intent',dict(stage='system'));pair_idle_save('result',dict(done=True))
counts.update(adapter=14,connector=14);run(1)
try:run(1);raise AssertionError('repeat')
except RuntimeError:pass
try:run(3);raise AssertionError('skip')
except RuntimeError:pass
counts.update(adapter=49,connector=49);run(2)
pair_idle_save('intent',dict(stage='policy'));pair_idle_save('result',dict(done=True))
assert os.path.isfile(ROOT+'/fs/pair.idle.0.intent') and os.path.isfile(ROOT+'/fs/pair.idle.2.intent')
counts.update(adapter=63,connector=63);run(3)
counts.update(adapter=94,connector=94);run(4)
assert pair_read(RELAY+'/pair-credit.json',0o444)['allocation']==130
assert len([x for x in os.listdir(ROOT+'/fs') if x.endswith('.ack')])==4
pair_remove(time.monotonic()+10);assert not os.listdir(RELAY)
`);
});
test('failed grant fsync or second-process ACK never permits retry/reset',()=>{
 pairPython(controllerProgram(),String.raw`
pair_initialize();candidate('system',35);counts.update(adapter=14,connector=14)
original_sync=os.fsync
def fail_sync(fd):raise OSError('durability failed')
os.fsync=fail_sync
try:run(1);raise AssertionError('fsync succeeded')
except OSError:pass
os.fsync=original_sync
assert pair_read(RELAY+'/pair-credit.json',0o444)['sequence']==0
try:run(1);raise AssertionError('repeated failed intent')
except FileExistsError:pass
assert not os.path.exists(ROOT+'/fs/pair.credit.1.ack')
`);
 pairPython(controllerProgram(),String.raw`
pair_initialize();candidate('system',35);counts.update(adapter=14,connector=14)
first=observe;calls=[0]
def partial():
 calls[0]+=1
 if calls[0]==2:raise RuntimeError('second process did not ACK')
 return first()
pair_observe=partial
try:run(1);raise AssertionError('partial ACK accepted')
except RuntimeError:pass
assert pair_read(RELAY+'/pair-credit.json',0o444)['sequence']==1
assert not os.path.exists(ROOT+'/fs/pair.credit.1.ack')
try:run(1);raise AssertionError('rollback/retry accepted')
except RuntimeError:pass
`);
});
test('actual controller permits retained overhead saturation counts but no artifact or ACK rejection delta',()=>{
 pairPython(controllerProgram(),String.raw`
pair_initialize();candidate('system',1);candidate('policy',1)
# Successful retained 1c9dd0 overhead had seven adapter worker-slot rejections,
# zero connector rejections, and no admitted connection-limit rejection.
counts.update(adapter=14,connector=14);rejections['adapter']=7;run(1)
counts.update(adapter=15,connector=15);run(2)
counts.update(adapter=29,connector=29);rejections['adapter']=10;run(3)
counts.update(adapter=30,connector=30);run(4)
assert pair_read(RELAY+'/pair-credit.json',0o444)['sequence']==4
`);
 for(const change of ["rejections['adapter']+=1","rejections['adapter']-=1"]){
  pairPython(controllerProgram(),String.raw`
pair_initialize();candidate('system',1);counts.update(adapter=14,connector=14);rejections['adapter']=7;run(1)
counts.update(adapter=15,connector=15)
`+change+String.raw`
try:run(2);raise AssertionError('artifact rejection change')
except RuntimeError:pass
assert pair_read(RELAY+'/pair-credit.json',0o444)['sequence']==1
assert not os.path.exists(ROOT+'/fs/pair.credit.2.intent')
`);
 }
 pairPython(controllerProgram(),String.raw`
pair_initialize();candidate('system',1);counts.update(adapter=14,connector=14);rejections['adapter']=7
first=observe;calls=[0]
def raced():
 calls[0]+=1
 if calls[0]==2:rejections['adapter']+=1
 return first()
pair_observe=raced
try:run(1);raise AssertionError('ACK rejection race')
except RuntimeError:pass
assert not os.path.exists(ROOT+'/fs/pair.credit.1.ack')
`);
 for(const bad of ['True','-1','65536']){
  pairPython(controllerProgram(),String.raw`
pair_initialize();candidate('system',1);counts.update(adapter=14,connector=14)
rejections['adapter']=`+bad+String.raw`
try:run(1);raise AssertionError('invalid overhead count')
except RuntimeError:pass
assert not os.path.exists(ROOT+'/fs/pair.credit.1.intent')
`);
 }
});
test('real control file reader rejects symlinks, oversized files and unbounded candidate counts',()=>{
 pairPython(controllerProgram(),String.raw`
pair_initialize();candidate('system',129);counts.update(adapter=14,connector=14)
try:run(1);raise AssertionError('129 rows')
except RuntimeError:pass
assert not os.path.exists(ROOT+'/fs/pair.credit.1.intent')
p=RELAY+'/pair-credit.json';os.chmod(p,0o644)
try:pair_read(p,0o444);raise AssertionError('mode')
except ValueError:pass
os.unlink(p);os.symlink(ROOT+'/fs/pair.credit.0.intent',p)
try:pair_read(p,0o444);raise AssertionError('symlink')
except OSError:pass
os.unlink(p)
with open(p,'wb') as f:f.write(b' '*4097)
os.chmod(p,0o444)
try:pair_read(p,0o444);raise AssertionError('oversize')
except ValueError:pass
`);
});
test('paired derivation is closed and leaves single-System/default32 unchanged',async()=>{
 const plain=await derive.loadSystemBounded(),paired=await derive.loadSystemBounded(true);
 assert.notEqual(plain.derivedSha256,paired.derivedSha256);
 assert.deepEqual(Object.keys(paired.bounded._internals).sort(),['policyRendererMetadataQualificationPlan','systemMetadataQualificationPlan']);
 assert.equal(plain.pairPolicy,undefined);assert.equal(paired.pairPolicy.lifetime,320);
 assert.equal(plain.pairWirePolicy,undefined);assert.equal(paired.pairWirePolicy,derive.PAIR_WIRE_POLICY);
 const wire=derive.PAIR_WIRE_POLICY,unit=1024**2;
 assert(Object.isFrozen(wire));assert.equal(wire.cloudfrontBytes,Math.ceil((141550808+unit)/unit)*unit);
 assert.equal(wire.cloudfrontBytes-141550808,1055528);
 assert.deepEqual([wire.registryBytes,wire.authBytes,wire.aptBytes,wire.totalBytes],[128,1,132,261].map(n=>n*unit));
 const source=await fs.readFile(path.join(__dirname,'postgres/ownedMcpBoundedBuild.js'),'utf8');
 const retirementAnchor="        require(not os.listdir(RELAY))\n        require(time.monotonic()<end,'deadline_exhausted');os.rmdir(RELAY)";
 assert.equal(source.split(retirementAnchor).length,2,'paired insertion has one guarded retirement anchor');
 assert(derive._internals.deriveSource(source,true).includes("        pair_remove(end)\n"+retirementAnchor));
 for(const changed of [source.replace(retirementAnchor,'        require(not os.listdir(RELAY));os.rmdir(RELAY)'),
                       source.replace(retirementAnchor,"        require(not os.listdir(RELAY));os.rmdir(RELAY)\n        require(time.monotonic()<end,'deadline_exhausted')")]){
  assert.throws(()=>derive._internals.replaceOnce(changed,retirementAnchor,'sentinel'),/SYSTEM_DERIVATION_ANCHOR/);
 }
 const original='HOST_LIMITS[${JSON.stringify(METADATA_BLOB_HOST)}]=134217728';
 assert(source.includes(original));assert(derive._internals.deriveSource(source).includes(original));
 assert(derive._internals.deriveSource(source,true).includes('HOST_LIMITS[${JSON.stringify(METADATA_BLOB_HOST)}]=142606336'));
 assert.equal(sha(await fs.readFile(path.join(__dirname,'postgres/ownedMcpBoundedBuild.js'))),derive.SOURCE_SHA);
 assert(require('./postgres/ownedMcpPrivateEgress')._internals.program.includes("if self.connections>=32: raise Denied('connections')"));
 await assert.rejects(derive.loadSystemBounded('paired'),/TARGET/);
});
test('paired retirement checks the original end after reads and before each unlink',()=>{
 pairPython('import os,sys,stat,json,time,re\n'+derive._internals.PAIR_CONTROLLER,String.raw`
import os,time,json
from unittest.mock import patch,Mock
ROOT='/controlled';RELAY=ROOT+'/relay';RUN='a'*32
row={'sequence':0};late=[False]
def require(ok,reason='ownership_unproven'):
 if not ok:raise RuntimeError(reason)
def pair_read(file,mode):
 late[0]=True
 return row
def pair_shape(value,run):return value
def read(path):return json.dumps(row)
with patch.object(os.path,'lexists',return_value=True),patch.object(time,'monotonic',side_effect=lambda:10 if late[0] else 9),patch.object(os,'unlink') as unlink:
 try:pair_remove(10);raise AssertionError('late read allowed unlink')
 except RuntimeError as error:assert str(error)=='deadline_exhausted'
 unlink.assert_not_called()
late[0]=False
with patch.object(os.path,'lexists',return_value=True),patch.object(time,'monotonic',side_effect=[9,10]),patch.object(os,'unlink') as unlink:
 try:pair_remove(10);raise AssertionError('second late unlink allowed')
 except RuntimeError as error:assert str(error)=='deadline_exhausted'
 assert unlink.call_count==1 and unlink.call_args_list[0].args[0].endswith('/pair-credit.json')
`);
});
test('exact shared source derives all holder coordinates in memory and preserves original bytes',async()=>{
 const filename=path.join(__dirname,'postgres/ownedMcpBoundedBuild.js'),before=await fs.readFile(filename);
 const d=await derive.loadSystemBounded();assert.equal(sha(before),derive.SOURCE_SHA);
 assert.equal(d.totalMs,3636000);assert.equal(d.leaseTarget,'original-v24-system-total-lease-v1');
 const emitted=d.bounded._internals.scripts;
 assert(emitted.prepare.includes('system-lease.json'));assert(emitted.prepare.includes('O_EXCL'));
 assert(emitted.start.includes('holder_seconds='));assert(emitted.start.includes('/usr/bin/sleep "$holder_seconds"'));
 assert(!emitted.start.includes("printf '/usr/bin/sleep\\n900'"));
 assert(d.bounded._internals.relayLifecycleProgram.includes("read(ROOT+'/system-holder.seconds')"));
 assert(!d.bounded._internals.relayLifecycleProgram.includes("['/usr/bin/sleep','900']"));
 assert.equal(sha(await fs.readFile(filename)),sha(before));
 assert(require('./postgres/ownedMcpBoundedBuild')._internals.relayLifecycleProgram.includes("['/usr/bin/sleep','900']"));
 for(const script of [emitted.prepare,emitted.start,emitted.cleanup]){
  const syntax=spawnSync('/bin/sh',['-n'],{input:script,encoding:'utf8',timeout:5000,maxBuffer:8192});
  assert.equal(syntax.status,0,syntax.stderr);
 }
});
function guestControl(extra){
 const source=String.raw`import os,sys,stat,time,types,io,contextlib,json
ROOT='/var/tmp/dvaia-v23-build-'+'a'*32
RUN='a'*32
files={};fds={};events=[];clock=[100000000000];nextfd=[10]
def info(directory=False,size=0):return types.SimpleNamespace(st_mode=(stat.S_IFDIR|0o700) if directory else (stat.S_IFREG|0o600),st_uid=0,st_nlink=1,st_size=size)
os.path.realpath=lambda p:p
os.lstat=lambda p:info(True)
def opened(p,flags,mode=None):
 nextfd[0]+=1;fd=nextfd[0]
 if flags&os.O_CREAT:
  if p in files:raise FileExistsError()
  files[p]=b'';events.append(('create',p))
 elif p!=ROOT and p not in files:raise FileNotFoundError()
 fds[fd]=p;return fd
os.open=opened
os.fstat=lambda fd:info(fds[fd]==ROOT,len(files.get(fds[fd],b'')))
os.read=lambda fd,n:files[fds[fd]][:n]
def write(fd,b):files[fds[fd]]+=b;return len(b)
os.write=write
os.fsync=lambda fd:events.append(('sync',fds[fd]))
os.close=lambda fd:events.append(('close',fds[fd]))
time.monotonic_ns=lambda:clock[0]
PROGRAM=__SOURCE__
def run(op):
 sys.argv=['fixed',ROOT,RUN,op]
 out=io.StringIO()
 with contextlib.redirect_stdout(out):exec(PROGRAM,{})
 return out.getvalue()
`;
 const result=spawnSync('/opt/homebrew/bin/python3',['-I','-S','-B','-c',source.replace('__SOURCE__',JSON.stringify(derive._internals.LEASE_PY))+'\n'+extra],
  {encoding:'utf8',timeout:5000,maxBuffer:8192});assert.equal(result.status,0,result.stderr);
}
test('actual emitted guest lease is exclusive, durable and never refreshes on claim/read',()=>{
 guestControl(String.raw`run('create')
initial=files[ROOT+'/system-lease.json'];row=json.loads(initial)
assert row['expiresAtMs']==3736000
assert events[-2:]==[('sync',ROOT),('close',ROOT)]
clock[0]+=2000000000
assert run('claim')=='3633.999'
assert run('read')=='3633.999'
for op in ('create','claim'):
 try:run(op);raise AssertionError('duplicate accepted')
 except FileExistsError:pass
assert files[ROOT+'/system-lease.json']==initial
clock[0]=row['expiresAtMs']*1000000
try:run('active');raise AssertionError('expired authority')
except RuntimeError:pass
# Read identity still works after expiry for retirement only.
assert run('read')=='3633.999'
`);
});
test('guest partial publication failure leaves a consumed obligation, not a reusable lease',()=>{
 guestControl(String.raw`def broken(fd):raise OSError('sync denied')
os.fsync=broken
try:run('create');raise AssertionError('sync accepted')
except OSError:pass
assert ROOT+'/system-lease.json' in files
try:run('create');raise AssertionError('reset accepted')
except FileExistsError:pass
`);
});
test('changed source or repeated/missing anchor is not a selectable weaker derivation',async()=>{
 const text=await fs.readFile(path.join(__dirname,'postgres/ownedMcpBoundedBuild.js'),'utf8');
 assert.throws(()=>derive._internals.deriveSource(text+'\n'),/SOURCE/);
 assert.throws(()=>derive._internals.replaceOnce('x x','x','y'),/ANCHOR/);
 assert.throws(()=>derive._internals.replaceOnce('z','x','y'),/ANCHOR/);
});
