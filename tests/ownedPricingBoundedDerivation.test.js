'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const d=require('./postgres/ownedPricingBoundedDerivation'),root=path.resolve(__dirname,'..');
test('V34 derives only its lease and holder guards; package and legacy factory stay unchanged',async()=>{
 const a=d.loadPricingBounded(),b=d.loadPricingBounded('v34-browser');
 assert.equal(b.totalMs,3016000);assert.notEqual(a.derivedSha256,b.derivedSha256);
 const old=await a.pricingMetadataQualificationPlan(root,'f'.repeat(32)),next=await b.pricingMetadataQualificationPlan(root,'f'.repeat(32));
 assert.deepEqual(next.binding,old.binding);
 for(const name of ['prepare','namespace'])assert.match(next.phases[name],/original-v34-pricing-total-lease-v1/);
 assert.match(next.phases.cleanup,/pricing-holder\.seconds/);
 assert.equal(d._internals.leaseProgram(),d._internals.LEASE_PY);
 assert.throws(()=>d.loadPricingBounded('unreviewed'),/PROFILE/);
});
test('actual emitted lease program rejects cross-profile records, renewal and expiry',()=>{
 const script=String.raw`
import sys,json,stat,types,os
from unittest.mock import patch
source=sys.stdin.read();run='f'*32;root='/var/tmp/dvaia-v23-build-'+run
files={'owner':run.encode()};fds={};counter=[10];clock=[1000000000];synced=[]
def opened(path,flags,*args):
 name=str(path).rsplit('/',1)[-1]
 if flags&os.O_DIRECTORY:name='directory'
 if flags&os.O_CREAT:
  assert flags&os.O_EXCL and flags&os.O_NOFOLLOW
  if name in files:raise FileExistsError(name)
  files[name]=b''
 counter[0]+=1;fds[counter[0]]=name;return counter[0]
def info(fd):return types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1,st_size=len(files[fds[fd]]))
def write(fd,b):files[fds[fd]]+=b;return len(b)
def invoke(op):
 with patch('sys.argv',['lease',root,run,op]),patch('os.path.realpath',side_effect=lambda p:p),patch('os.lstat',return_value=types.SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=0)),patch('os.open',side_effect=opened),patch('os.fstat',side_effect=info),patch('os.read',side_effect=lambda fd,n:files[fds[fd]][:n]),patch('os.write',side_effect=write),patch('os.close'),patch('os.fsync',side_effect=lambda fd:synced.append(fd)),patch('time.monotonic_ns',side_effect=lambda:clock[0]):
  exec(compile(source,'<actual-lease>','exec'),{})
invoke('create');record=json.loads(files['pricing-lease.json']);assert record['expiresAtMs']-record['startedAtMs']==3016000
assert record['target']=='original-v34-pricing-total-lease-v1' and len(synced)==2
original=files['pricing-lease.json']
for op in ['create']:
 try:invoke(op);raise AssertionError('renewed')
 except FileExistsError:pass
invoke('claim');assert float(files['pricing-holder.seconds'])<3016
try:invoke('claim');raise AssertionError('renewed-holder')
except FileExistsError:pass
invoke('active')
for delta in [dict(target='original-v33-pricing-total-lease-v1'),dict(expiresAtMs=record['expiresAtMs']+1),dict(version=True)]:
 files['pricing-lease.json']=json.dumps(dict(record,**delta)).encode()
 try:invoke('active');raise AssertionError('accepted wrong profile')
 except RuntimeError:pass
files['pricing-lease.json']=original;clock[0]=record['expiresAtMs']*1000000
try:invoke('active');raise AssertionError('accepted expiry')
except RuntimeError:pass
assert files['pricing-lease.json']==original
`;
 for(const profile of ['v34-browser','v25-manual']){
  const program=profile==='v34-browser'?script:script.replaceAll('3016000','2856000').replaceAll('3016','2856').replaceAll('original-v34-pricing','original-v25-pricing');
  const r=require('node:child_process').spawnSync('/opt/homebrew/bin/python3',['-B','-c',program],{input:d._internals.leaseProgram(profile),encoding:'utf8'});
  assert.equal(r.status,0,r.stderr);
 }
});
test('Pricing derivation is pinned and rejects even harmless unexpected source changes',()=>{
 const source=fs.readFileSync(path.join(root,'tests/postgres/ownedMcpBoundedBuild.js'),'utf8');
 assert.equal(crypto.createHash('sha256').update(source).digest('hex'),d.SOURCE_SHA);
 assert.throws(()=>d._internals.deriveSource(source+'\n'),/DERIVATION_SOURCE/);
 assert.throws(()=>d._internals.once('xx','x','y'),/ANCHOR/);
});
test('Pricing lease commands derive in memory; original900 holder stays byte unchanged',async()=>{
 const name=path.join(root,'tests/postgres/ownedMcpBoundedBuild.js'),before=fs.readFileSync(name);
 const bound=d.loadPricingBounded();assert.equal(bound.totalMs,2616000);
 assert.deepEqual(Object.keys(bound).sort(),['derivedSha256','pricingMetadataQualificationPlan','sourceSha256','totalMs']);
 const p=await bound.pricingMetadataQualificationPlan(root,'f'.repeat(32));
 assert.equal(p.binding.target,'v33-pricing');assert.equal(p.executionApproved,false);
 assert.match(p.phases.prepare,/pricing-lease\.json/);assert.match(p.phases.namespace,/pricing-holder\.seconds/);
 assert.match(p.phases.namespace,/sleep "\$holder_seconds"/);assert.match(p.phases.cleanup,/pricing-holder\.seconds/);
 assert.deepEqual(fs.readFileSync(name),before);
 const original=await require('./postgres/ownedMcpBoundedBuild')._internals.metadataQualificationPlan(root,'f'.repeat(32));
 assert.match(original.phases.namespace,/sleep 900/);assert.doesNotMatch(original.phases.namespace,/pricing-holder/);
});
