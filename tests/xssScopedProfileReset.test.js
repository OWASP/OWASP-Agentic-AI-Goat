'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {createXssScopedProfileReset} = require('../server/services/xssScopedProfileReset');
function fixture(overrides={}) {
  const calls=[];
  const operation={operationId:'op',ownerId:42,graphParentGeneration:'0',workshopGeneration:'0',
    children:{stored_user:{from:'0',to:'1'},stored_llm:{from:'0',to:'1'}},status:'pending'};
  const lease={...operation,leaseToken:'lease'};
  const journal={
    begin:async()=>{calls.push('begin');return operation;},
    read:async()=>operation,
    readNonterminalForOwner:async()=>null,
    claim:async()=>{calls.push('claim');return lease;},
    assertCurrent:async()=>{calls.push('current');},
    acknowledgeStore:async({receipt})=>{assert.equal(receipt,'receipt');calls.push('ack');},
    fail:async()=>{calls.push('fail');},
    complete:async()=>{calls.push('complete');return {...operation,status:'completed'};},
  };
  const store={apply:async coordinates=>{assert.deepEqual(coordinates.children,operation.children);calls.push('effect');return 'receipt';}};
  const guard={check:async()=>{calls.push('guard');}};
  const canonicalReader={read:async()=>'1'};
  const service=createXssScopedProfileReset({pool:{connect(){}},journal,store,readWorkshopGeneration:owner=>canonicalReader.read(owner),
    ledger:{withOwnerLease:async({ownerKey},work)=>{
      assert.equal(ownerKey,'[\"XSS\",\"42\"]');
      return work({durableGeneration:'0',check:async()=>{}});
    }},
    runs:{cancelScopes(){},withScopesQuiesced:async(owner,scopes,work)=>{
      assert.equal(owner,42);assert.deepEqual(scopes,['stored_user','stored_llm']);
      calls.push('quiesce');return work();
    }}, lifecycle:async(_,owner,work)=>{assert.equal(owner,42);return work(null,guard);},...overrides});
  return {calls,operation,journal,store,guard,service,canonicalReader};
}
test('scoped reset fences each effect and acknowledges before completion',async()=>{
  const f=fixture(); assert.equal((await f.service.reset({operationId:'op',ownerId:42,graphParentGeneration:'0',workshopGeneration:'0'})).status,'completed');
  assert.deepEqual(f.calls.filter(x=>x!=='guard'),
    ['quiesce','begin','claim','current','effect','current','ack','current','complete']);
});
test('post-effect stale authority preserves recoverability without crediting completion',async()=>{
  const f=fixture();let checks=0;
  f.journal.assertCurrent=async()=>{if(++checks===2)throw Object.assign(new Error('stale'),{code:'STALE'});};
  await assert.rejects(f.service.reset({operationId:'op',ownerId:42,graphParentGeneration:'0',workshopGeneration:'0'}),{code:'STALE'});
  assert.ok(f.calls.includes('effect'));assert.ok(f.calls.includes('fail'));
  assert.ok(!f.calls.includes('ack'));assert.ok(!f.calls.includes('complete'));
});
test('completed recovery does not touch store',async()=>{
  const f=fixture();f.operation.status='completed';
  await f.service.recover({ownerId:42,operationId:'op'});
  assert.ok(!f.calls.includes('claim'));assert.ok(!f.calls.includes('effect'));
});
test('different owner recovery never claims or executes',async()=>{
  const f=fixture();f.operation.ownerId=43;
  await assert.rejects(f.service.recover({ownerId:42,operationId:'op'}),{code:'XSS_PROFILE_RESET_CONFLICT'});
  assert.ok(!f.calls.includes('claim'));
});
test('lost lifecycle authority before store prevents mutation',async()=>{
  const f=fixture();f.journal.claim=async()=>{
    f.guard.check=async()=>{throw Object.assign(new Error('lost'),{code:'LOCK_LOST'});};
    return {...f.operation,leaseToken:'lease'};
  };
  await assert.rejects(f.service.reset({operationId:'op',ownerId:42,graphParentGeneration:'0',workshopGeneration:'0'}),{code:'LOCK_LOST'});
  assert.ok(!f.calls.includes('effect'));assert.ok(f.calls.includes('fail'));
});

test('unknown reset fields are rejected before lifecycle admission',()=>{
  const f=fixture();
  assert.throws(()=>f.service.reset({ownerId:42,children:{}}),TypeError);
  assert.deepEqual(f.calls,[]);
});
test('lost guard after completion preserves terminal state for recovery',async()=>{
  const f=fixture();
  f.journal.complete=async()=>{
    f.operation.status='completed';
    f.guard.check=async()=>{throw Object.assign(new Error('lost'),{code:'LOCK_LOST'});};
    return f.operation;
  };
  f.journal.fail=async()=>{throw Object.assign(new Error('terminal'),{code:'STALE'});};
  await assert.rejects(f.service.reset({operationId:'op',ownerId:42,graphParentGeneration:'0',workshopGeneration:'0'}),
    error=>error.code==='LOCK_LOST' && error.resetJournalError.code==='STALE');
  assert.equal(f.operation.status,'completed');
  f.guard.check=async()=>{};
  assert.equal((await f.service.recover({ownerId:42,operationId:'op'})).status,'completed');
});

test('completed operation recovery survives a later parent generation without store replay',async()=>{
 const f=fixture();f.operation.status='completed';f.operation.graphParentGeneration='9';
 const result=await f.service.recover({ownerId:42,operationId:'op'});
 assert.equal(result.status,'completed');assert.equal(result.graphParentGeneration,'9');
 assert.ok(!f.calls.includes('claim'));assert.ok(!f.calls.includes('effect'));
});

test('parent recovery uses only private store outcome before identity reconciliation',async()=>{
 const f=fixture();const outcome=Object.freeze({kind:'retired_no_effect'});
 f.store.retireOrRead=async input=>{assert.equal(input.operationId,'op');f.calls.push('retire');return outcome;};
 f.journal.reconcileAfterParentReset=async input=>{
  assert.equal(input.outcome,outcome);assert.equal(input.observedWorkshopGeneration,'1');
  assert.equal(input.observedGraphParentGeneration,'0');f.calls.push('reconcile');return{...f.operation,status:'superseded'};
 };
 assert.equal((await f.service.recoverAfterParentReset({ownerId:42,operationId:'op'})).status,'superseded');
 assert.ok(f.calls.indexOf('retire')<f.calls.indexOf('reconcile'));
 assert.ok(!f.calls.includes('effect'));assert.ok(!f.calls.includes('claim'));
});
test('parent recovery rejects caller-supplied authority and current parents',async()=>{
 const f=fixture();f.store.retireOrRead=async()=>assert.fail('retire');
 f.journal.reconcileAfterParentReset=async()=>assert.fail('reconcile');
 await assert.rejects(f.service.recoverAfterParentReset({ownerId:42,operationId:'op',outcome:{}}),TypeError);
 f.operation.workshopGeneration='1';
 await assert.rejects(f.service.recoverAfterParentReset({ownerId:42,operationId:'op'}),{code:'XSS_PARENT_NOT_SUPERSEDED'});
});
test('loss after retirement leaves recovery retryable without reactivating identity children',async()=>{
 const f=fixture();
 f.store.retireOrRead=async()=>{f.guard.check=async()=>{throw Object.assign(new Error('lost'),{code:'LOCK_LOST'});};return{kind:'retired_no_effect'};};
 f.journal.reconcileAfterParentReset=async()=>assert.fail('must not reconcile under lost authority');
 await assert.rejects(f.service.recoverAfterParentReset({ownerId:42,operationId:'op'}),{code:'LOCK_LOST'});
});

test('committed store outcome is reconciled without repeating a reset effect',async()=>{
 const f=fixture();const receipt=Object.freeze({operationId:'op',ownerId:42});
 const outcome=Object.freeze({kind:'committed',receipt});
 f.store.retireOrRead=async()=>outcome;
 f.journal.reconcileAfterParentReset=async input=>{
  assert.equal(input.outcome,outcome);assert.equal(input.outcome.receipt,receipt);
  return {...f.operation,status:'superseded',reconciliation:{kind:'committed'}};
 };
 const result=await f.service.recoverAfterParentReset({ownerId:42,operationId:'op'});
 assert.equal(result.status,'superseded');assert.equal(result.reconciliation.kind,'committed');
 assert.ok(!f.calls.includes('effect'));assert.ok(!f.calls.includes('ack'));
});
test('superseded operation is immutable recovery history across parent changes',async()=>{
 const f=fixture();f.operation.status='superseded';f.operation.graphParentGeneration='9';
 f.store.retireOrRead=async()=>assert.fail('retirement repeated');
 f.journal.reconcileAfterParentReset=async()=>assert.fail('reconciliation repeated');
 assert.equal((await f.service.recoverAfterParentReset({ownerId:42,operationId:'op'})).status,'superseded');
 assert.equal((await f.service.recover({ownerId:42,operationId:'op'})).status,'superseded');
 assert.ok(!f.calls.includes('claim'));assert.ok(!f.calls.includes('effect'));
});


test('current reset derives parent coordinates under authority instead of accepting caller generations',async()=>{
 const f=fixture();f.operation.workshopGeneration='1';
 f.journal.read=async()=>null;
 f.journal.begin=async input=>{
  assert.deepEqual(input,{ownerId:42,operationId:'op',graphParentGeneration:'0',workshopGeneration:'1'});
  assert.ok(f.calls.includes('quiesce'));
  return f.operation;
 };
 assert.equal((await f.service.resetCurrent({ownerId:42,operationId:'op'})).status,'completed');
});
test('headerless current reset resumes the matching nonterminal operation',async()=>{
 const f=fixture();f.operation.workshopGeneration='1';
 f.journal.begin=async()=>assert.fail('must not allocate another operation');
 f.journal.readNonterminalForOwner=async owner=>{assert.equal(owner,42);f.calls.push('owner-read');return f.operation;};
 const result=await f.service.resetCurrent({ownerId:42});
 assert.equal(result.status,'completed');
 assert.ok(f.calls.indexOf('owner-read')<f.calls.indexOf('claim'));
 assert.ok(!f.calls.includes('begin'));
});
test('headerless current reset allocates a UUID only when no operation is pending',async()=>{
 const f=fixture();f.operation.workshopGeneration='1';
 f.journal.begin=async input=>{
  assert.equal(input.ownerId,42);assert.equal(input.graphParentGeneration,'0');assert.equal(input.workshopGeneration,'1');
  assert.match(input.operationId,/^[0-9a-f]{8}-[0-9a-f-]{27}$/);f.calls.push('begin');
  f.operation.operationId=input.operationId;return f.operation;
 };
 await f.service.resetCurrent({ownerId:42});
 assert.ok(f.calls.includes('begin'));assert.ok(f.calls.includes('effect'));
});
test('headerless current reset does not adopt a pending operation from stale parents',async()=>{
 const f=fixture();f.operation.graphParentGeneration='9';
 f.journal.readNonterminalForOwner=async()=>f.operation;
 await assert.rejects(f.service.resetCurrent({ownerId:42}),{code:'XSS_PROFILE_RESET_CONFLICT'});
 assert.ok(!f.calls.includes('claim'));assert.ok(!f.calls.includes('effect'));
});
test('explicit completed operation is returned without another begin or store effect',async()=>{
 const f=fixture();f.operation.status='completed';f.operation.graphParentGeneration='9';
 f.journal.begin=async()=>assert.fail('must not begin completed operation again');
 const result=await f.service.resetCurrent({ownerId:42,operationId:'op'});
 assert.equal(result.status,'completed');assert.ok(!f.calls.includes('claim'));assert.ok(!f.calls.includes('effect'));
});
test('current reset rejects caller-supplied parent authority before admission',()=>{
 const f=fixture();
 assert.throws(()=>f.service.resetCurrent({ownerId:42,operationId:'op',graphParentGeneration:'0'}),TypeError);
 assert.deepEqual(f.calls,[]);
});

test('current reset refuses admission after authority loss during canonical read',async()=>{
 const f=fixture();
 f.canonicalReader.read=async()=>{
  f.guard.check=async()=>{throw Object.assign(new Error('lost'),{code:'LOCK_LOST'});};
  return '1';
 };
 await assert.rejects(f.service.resetCurrent({ownerId:42,operationId:'op'}),{code:'LOCK_LOST'});
 assert.ok(!f.calls.includes('begin'));assert.ok(!f.calls.includes('effect'));
});

test('active scoped request is cancelled before lifecycle wait without installing a barrier',async()=>{
 let held=true;const order=[];
 const f=fixture({runs:{cancelScopes(owner,scopes){assert.equal(owner,42);assert.deepEqual(scopes,['stored_user','stored_llm']);order.push('cancel');held=false;},withScopesQuiesced:async(_owner,_scopes,work)=>{order.push('quiesce');return work();}},lifecycle:async(_pool,_owner,work)=>{order.push('lock');if(held)throw Object.assign(Error('lock busy'),{code:'55P03'});return work(null,{check:async()=>{}});}});
 assert.equal((await f.service.resetCurrent({ownerId:42})).status,'completed');
 assert.deepEqual(order,['cancel','lock','quiesce']);
});

test('new arrival busy denial installs no barrier, mutates no journal, and remains retryable',async()=>{
 let busy=true;const order=[];
 const f=fixture({runs:{cancelScopes(){order.push('cancel');},withScopesQuiesced:async(_owner,_scopes,work)=>{order.push('quiesce');return work();}},lifecycle:async(_pool,_owner,work)=>{order.push('lock');if(busy)throw Object.assign(Error('new request owns lock'),{code:'55P03'});return work(null,{check:async()=>{}});}});
 await assert.rejects(f.service.resetCurrent({ownerId:42}),{code:'55P03'});assert.deepEqual(order,['cancel','lock']);assert.deepEqual(f.calls,[]);
 busy=false;assert.equal((await f.service.resetCurrent({ownerId:42})).status,'completed');assert.deepEqual(order,['cancel','lock','cancel','lock','quiesce']);
});
test('invalid owner cannot cancel runs before lifecycle authority',async()=>{
 let cancelled=0;const f=fixture({runs:{cancelScopes(){cancelled++;},withScopesQuiesced:async()=>{throw Error('unexpected');}}});
 for(const ownerId of [0,-1,'42',null,2147483648])await assert.rejects(f.service.resetCurrent({ownerId}),TypeError);
 assert.equal(cancelled,0);
});

test('actual profile-reset handler rechecks canonical session after readiness before cancellation',async()=>{
 const fs=require('node:fs'),path=require('node:path');const source=fs.readFileSync(path.join(__dirname,'../server/routes/xssWorkshop.js'),'utf8');
 const marker="router.post('/profile/reset', async (req, res, next) => {";const start=source.indexOf(marker)+marker.length,end=source.indexOf('\n});',start);assert(start>=marker.length&&end>start);
 const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
 for(const scenario of ['valid','revoked','foreign']){
  let resets=0,ready=false;const composition={assertReady:async()=>{ready=true;},reset:async()=>{resets++;return {operationId:'owned',status:'completed'};}};
  const load=name=>{if(name==='../agent-runtime/admittedPlatformSession')return require('../server/agent-runtime/admittedPlatformSession');if(name==='../services/xssScopedProfileResetComposition')return {getXssScopedProfileResetComposition:async()=>composition};if(name==='../services/postgresIdentityAdapter')return {getPostgresIdentityAdapter:()=>({validateSession:async()=>{assert(ready);return scenario==='revoked'?null:{user:{id:scenario==='foreign'?43:42},session:{id:9,user_id:42}};}})};throw Error('Unexpected dependency');};
  const handler=new AsyncFunction('req','res','next','require','getPlatformUserId','process','xssWorkshopDb','resetNoncanonicalProfile',source.slice(start,end));
  const req={user:{id:42},identitySession:{id:9},headers:{authorization:'Bearer controlled'},get:name=>name==='authorization'?'Bearer controlled':undefined};let status=200;const res={status(n){status=n;return this;},json(){return this;}};
  await handler(req,res,()=>{},load,()=>42,{env:{PLATFORM_DATABASE_ENGINE:'postgres'}},{getProfile:async()=>({})},()=>{throw Error('Unexpected legacy');});
  assert.equal(status,scenario==='valid'?200:401);assert.equal(resets,scenario==='valid'?1:0);
 }
});

test('actual coordinator cancellation drains held admitted work before reset store effect',async()=>{
 const {createRunCoordinator}=require('../server/agent-runtime/runCoordinator');
 const {createXssMutationAdmission}=require('../server/services/xssMutationAdmission');
 const order=[];let tail=Promise.resolve(),entered;const started=new Promise(r=>{entered=r;});
 const lifecycle=async(_pool,_owner,work)=>{const previous=tail;let release;tail=new Promise(r=>{release=r;});await previous;try{return await work(null,{check:async()=>{}});}finally{order.push('lock-release');release();}};
 const coordinator=createRunCoordinator({family:'XSS_RESET_CONTROL',ledger:{supportsScopedAdmission:true,begin:async c=>({durableGeneration:'0',scopeBinding:Object.freeze({runId:c.runId,ownerKey:c.ownerKey,ownerId:42,scopeKey:c.scope.scopeKey,parentGeneration:'0',childGeneration:'0'})}),assertCurrent:async()=>{},finish:async()=>{order.push('run-finish');}}});
 const admit=createXssMutationAdmission({pool:{connect(){}},journal:{assertMutationAdmitted:async()=>{}},lifecycle});
 const run=admit(42,()=>coordinator.run(42,{scope:{userId:42,scopeKey:'stored_user'},timeoutMs:5000},async({signal})=>{entered();try{await new Promise((resolve,reject)=>signal.addEventListener('abort',()=>reject(signal.reason),{once:true}));}finally{await Promise.resolve();order.push('work-retired');}}));
 const rejected=assert.rejects(run,{name:'AbortError'});await started;
 const f=fixture({runs:coordinator,lifecycle});f.store.apply=async()=>{order.push('store-effect');assert(order.includes('work-retired'));assert(order.includes('run-finish'));return 'receipt';};
 assert.equal((await f.service.resetCurrent({ownerId:42})).status,'completed');await rejected;
 assert.deepEqual(order.slice(0,4),['work-retired','run-finish','lock-release','store-effect']);
});
