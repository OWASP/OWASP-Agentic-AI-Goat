'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const source=fs.readFileSync(require.resolve('./postgres/ownedV03ListingsProducer'),'utf8');
function fixture(){
 const calls=[];let revoked=false;
 const owner={producerBinding:()=>({runId:'a'.repeat(32),parentRunId:'b'.repeat(32)}),isRevoked:()=>revoked,phaseWindow:()=>({})};
 const driver=Object.fromEntries(['prepare','settle','startRuntime','claimCohort','join','retire'].map(name=>[name,async()=>{
  calls.push(name);return name==='join'?{localRetired:true}:name==='retire'?{cleanupVerified:true,resourceAbsenceProven:true}:{ready:true};
 }]));
 const deps={createListingsDriver:async()=>driver,assertListingsDriver:()=>{}};
 const requireMock=name=>name==='node:crypto'?{createHash:()=>({update(){return this;},digest:()=> 'c'.repeat(64)})}:
  name==='./ownedV03ListingsDriver'?deps:name==='./ownedV03PrivateExecutors'?{assertCombinedOwner:value=>{assert.equal(value,owner);return owner;}}:
  {_internals:{regular:async()=>Buffer.from('source')}};
 const module={exports:{}};new Function('require','module','__filename',source)(requireMock,module,'/synthetic/producer');
 const options={root:'/synthetic',runId:'a'.repeat(32),parentRunId:'b'.repeat(32),combinedOwner:owner,sourcePins:{}};
 for(const field of ['expectedDriverSha256','expectedHostPythonSha256','expectedPlanSha256','expectedProducerSha256','expectedPythonSha256','expectedTransportSha256'])options[field]='c'.repeat(64);
 return {value:module.exports.createListingsProducer(options),calls,driver,deps,revoke(){revoked=true;}};
}
test('actual producer orders concrete prepare, settlement, startup and claim before retirement',async()=>{
 const f=fixture();await f.value.prepare();await f.value.settle();await f.value.start();await f.value.claimCohort();
 f.revoke();await f.value.join();assert.equal((await f.value.retire()).cleanupVerified,true);
 assert.deepEqual(f.calls,['prepare','settle','startRuntime','claimCohort','join','retire']);
});
test('failed construction retains debt instead of no-driver cleanup success',async()=>{
 const f=fixture();f.deps.createListingsDriver=async()=>{throw Error('construction');};
 await assert.rejects(f.value.prepare());f.revoke();await assert.rejects(f.value.join(),{code:'V03_LISTINGS_JOIN_UNPROVEN'});
 assert.equal(f.value.publicStatus().cleanupDebt,true);assert.deepEqual(f.calls,[]);
});
test('unjoined concrete driver never reaches destructive retirement',async()=>{
 const f=fixture();await f.value.prepare();f.driver.join=async()=>({localRetired:false});f.revoke();
 await assert.rejects(f.value.join());assert.throws(()=>f.value.retire(),{code:'V03_LISTINGS_RETIREMENT_ORDER'});
 assert.equal(f.calls.includes('retire'),false);
});
test('false concrete cleanup proof remains failure and repeat cannot renew cleanup',async()=>{
 const f=fixture();await f.value.prepare();f.revoke();await f.value.join();
 let count=0;f.driver.retire=async()=>{count++;return {cleanupVerified:false,resourceAbsenceProven:true};};
 await assert.rejects(f.value.retire(),{code:'V03_LISTINGS_RETIREMENT_UNPROVEN'});
 await assert.rejects(f.value.retire());assert.equal(count,1);
});
