'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {spawnSync}=require('node:child_process');
const lease=require('./postgres/ownedMcpOriginalServiceLease');
test('closed phase arithmetic preserves original cohort and separate startup',()=>{
 assert.equal(lease.TOTAL_MS,7400000);
 assert.deepEqual(Object.values(lease.PHASES),[1800000,680000,120000,1200000,1080000,2520000]);
 assert.equal(lease.windowFor(1000,1000,'build').deadlineMs,1801000);
 assert.equal(lease.windowFor(1000,2601000,'cohort').deadlineMs,3801000);
 assert.throws(()=>lease.windowFor(1000,2601001,'cohort'),/RESERVE/);
 assert.throws(()=>lease.windowFor(1000,999,'cleanup'),/INPUT/);
 assert.throws(()=>lease.windowFor(1000,7401000,'cleanup'),/RESERVE/);
 assert.throws(()=>lease.windowFor(1000,1000,'__proto__'),/INPUT/);
 assert.equal(lease.windowFor(1000,1000,'cleanup').resourceAbsenceProven,false);
});
function guestControl(extra,profile='original-service'){
 const source=String.raw`import os,sys,stat,time,types,io,contextlib,json
ROOT='/var/tmp/dvaia-v23-build-'+'a'*32
RUN='a'*32
files={ROOT+'/owner':RUN.encode()};fds={};events=[];clock=[100000000000];nextfd=[10]
def info(directory=False,size=0):return types.SimpleNamespace(st_mode=(stat.S_IFDIR|0o700) if directory else (stat.S_IFREG|0o600),st_uid=0,st_nlink=1,st_size=size)
os.path.realpath=lambda p:p
os.lstat=lambda p:info(True)
def opened(p,flags,mode=None):
 nextfd[0]+=1;fd=nextfd[0]
 if flags&os.O_CREAT:
  assert flags&os.O_EXCL and flags&os.O_NOFOLLOW and mode==0o600
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
def denied(op):
 try:run(op)
 except (RuntimeError,FileExistsError,FileNotFoundError):return
 raise AssertionError('accepted '+op)
`;
 const result=spawnSync('/opt/homebrew/bin/python3',['-I','-S','-B','-c',source.replace('__SOURCE__',JSON.stringify(lease.guestSource(profile)))+'\n'+extra],
  {encoding:'utf8',timeout:5000,maxBuffer:8192});assert.equal(result.status,0,result.stderr);
}
test('Listings manager preserves original540s browser with separate startup and immutable cleanup reserves',()=>{
 const profile='listings-manager-browser',spec=lease.specification(profile);
 assert.equal(spec.target,'original-listings-manager-total-lease-v1');
 assert.equal(spec.totalMs,6680000);assert.equal(spec.workMs,null);
 assert.deepEqual(Object.values(spec.phases),[1800000,680000,60000,540000,1080000,2520000]);
 assert.equal(lease.windowFor(1000,2541000,'cohort',profile).deadlineMs,3081000);
 assert.throws(()=>lease.windowFor(1000,2541001,'cohort',profile),/RESERVE/);
 guestControl(String.raw`run('create')
original=files[ROOT+'/original-service-lease.json']
assert json.loads(original)['expiresAtMs']==6780000
run('holder-claim');denied('holder-claim')
for phase in ('build','settlement','startup'):run('claim-'+phase)
clock[0]=2640000*1000000
row=json.loads(run('claim-cohort'));assert row['deadlineMs']-row['startedAtMs']==540000
run('claim-retirement');denied('check-cohort');run('claim-cleanup');denied('claim-cleanup')
assert files[ROOT+'/original-service-lease.json']==original
`,profile);
 guestControl(String.raw`run('create')
for phase in ('build','settlement','startup'):run('claim-'+phase)
clock[0]=2640001*1000000;denied('claim-cohort')
assert ROOT+'/original-service-phase-cohort.json' not in files
`,profile);
});
test('V39 all work shares original960s parent, child480s can only shrink, cleanup is separate',()=>{
 const profile='v39-atomic-pair',spec=lease.specification(profile);
 assert.equal(spec.totalMs,4560000);assert.equal(spec.phases.cohort,480000);
 assert.equal(lease.windowFor(1000,901000,'cohort',profile).deadlineMs,961000);
 assert.throws(()=>lease.windowFor(1000,961000,'cohort',profile),/RESERVE/);
 assert.throws(()=>lease.specification('other'),/PROFILE/);
 guestControl(String.raw`run('create')
initial=files[ROOT+'/original-service-lease.json'];row=json.loads(initial)
assert row['target']=='v39-atomic-pair-total-lease-v1' and row['expiresAtMs']==4660000
for phase in ('build','settlement','startup'):run('claim-'+phase)
clock[0]=1000000*1000000
cohort=json.loads(run('claim-cohort'));assert cohort['deadlineMs']==1060000
assert cohort['deadlineMs']-cohort['startedAtMs']==60000
denied('claim-cohort')
clock[0]=1060000*1000000;denied('check-cohort');denied('check-build')
run('claim-retirement');denied('check-cohort');run('claim-cleanup')
assert files[ROOT+'/original-service-lease.json']==initial
`,profile);
});
test('Q05 private lease is separate identity with the same nonrenewable 960s/480s ceilings',()=>{
 const profile='q05-registered-pair',value=lease.specification(profile);
 assert.equal(value.target,'q05-registered-pair-total-lease-v1');
 assert.equal(value.workMs,960000);assert.equal(value.phases.cohort,480000);
 assert.equal(lease.windowFor(1000,901000,'cohort',profile).deadlineMs,961000);
 assert.throws(()=>lease.windowFor(1000,961000,'cohort',profile),/RESERVE/);
 guestControl(String.raw`run('create')
row=json.loads(files[ROOT+'/original-service-lease.json'])
assert row['target']=='q05-registered-pair-total-lease-v1'
for phase in ('build','settlement','startup'):run('claim-'+phase)
clock[0]=1000000*1000000
cohort=json.loads(run('claim-cohort'));assert cohort['deadlineMs']==1060000
denied('claim-cohort')
`,profile);
});
test('emitted guest exclusively persists lease and holder without renewal',()=>{
 guestControl(String.raw`run('create')
initial=files[ROOT+'/original-service-lease.json'];row=json.loads(initial)
assert row['expiresAtMs']==7500000
assert events[-2:]==[('sync',ROOT),('close',ROOT)]
clock[0]+=2000000000
assert run('holder-claim')=='7397.999'
assert run('holder-read')=='7397.999'
denied('create');denied('holder-claim')
assert files[ROOT+'/original-service-lease.json']==initial
clock[0]=row['expiresAtMs']*1000000
denied('active');denied('claim-cleanup')
assert run('holder-read')=='7397.999'
`);
});
test('emitted phase claims are durable, capped, one-shot and require full original cohort reserve',()=>{
 guestControl(String.raw`run('create')
denied('claim-cohort')
for phase in ('build','settlement','startup'):
 result=json.loads(run('claim-'+phase));assert result['phase']==phase
 assert events[-2:]==[('sync',ROOT),('close',ROOT)]
 denied('claim-'+phase)
clock[0]=2700000*1000000
row=json.loads(run('claim-cohort'));assert row['deadlineMs']==3900000
initial=files[ROOT+'/original-service-phase-cohort.json']
clock[0]+=1000000
assert json.loads(run('check-cohort'))['deadlineMs']==3900000
assert files[ROOT+'/original-service-phase-cohort.json']==initial
denied('claim-cohort')
clock[0]=3900000*1000000;denied('check-cohort')
run('claim-retirement');run('claim-cleanup');denied('claim-cleanup')
`);
 guestControl(String.raw`run('create')
for phase in ('build','settlement','startup'):run('claim-'+phase)
clock[0]=2700001*1000000
denied('claim-cohort')
assert ROOT+'/original-service-phase-cohort.json' not in files
`);
});
test('guest failed fsync consumes claim and cannot restart a lease',()=>{
 guestControl(String.raw`def broken(fd):raise OSError('sync denied')
os.fsync=broken
try:run('create');raise AssertionError('sync accepted')
except OSError:pass
assert ROOT+'/original-service-lease.json' in files
denied('create')
`);
});
test('cleanup claim fences later work and forged prior phase cannot admit cohort',()=>{
 guestControl(String.raw`run('create');run('claim-cleanup')
denied('claim-build');denied('claim-startup');denied('claim-cohort')
`);
 guestControl(String.raw`run('create')
for phase in ('build','settlement','startup'):run('claim-'+phase)
p=ROOT+'/original-service-phase-startup.json';row=json.loads(files[p]);row['deadlineMs']+=1
files[p]=json.dumps(row).encode();denied('claim-cohort')
files[ROOT+'/owner']=b'wrong';denied('active')
`);
});
test('emitted guest rejects build dispatch replay after cleanup claim',()=>{
 guestControl(String.raw`run('create');run('claim-build')
assert json.loads(run('check-build'))['phase']=='build'
run('claim-cleanup')
denied('check-build')
assert json.loads(run('check-cleanup'))['phase']=='cleanup'
`);
});
test('emitted guest rejects still-unexpired cohort dispatch after retirement claim',()=>{
 guestControl(String.raw`run('create')
for phase in ('build','settlement','startup','cohort'):run('claim-'+phase)
assert json.loads(run('check-cohort'))['phase']=='cohort'
run('claim-retirement')
denied('check-cohort')
assert json.loads(run('check-retirement'))['phase']=='retirement'
`);
});
test('guest rejects foreign, malformed, unsafe-file and regressing-clock timing records',()=>{
 guestControl(String.raw`run('create')
p=ROOT+'/original-service-lease.json';original=files[p]
for key,value in [('target','other'),('runId','b'*32),('expiresAtMs',7500001),('version',True),('extra',1)]:
 row=json.loads(original);row[key]=value;files[p]=json.dumps(row).encode();denied('active')
files[p]=original;clock[0]=99999999999;denied('active')
clock[0]=100000000000
old=os.fstat
def unsafe(fd):
 s=old(fd);s.st_nlink=2;return s
os.fstat=unsafe;denied('active')
`);
});
