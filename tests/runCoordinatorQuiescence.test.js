'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createRunCoordinator } = require('../server/agent-runtime/runCoordinator');

function ledger() {
  return {
    supportsScopedAdmission: true,
    async begin(context) {
      return { durableGeneration: '0', scopeBinding: Object.freeze({
        runId: context.runId, ownerKey: context.ownerKey, ownerId: context.scope.userId,
        scopeKey: context.scope.scopeKey, parentGeneration: '0', childGeneration: '0',
      }) };
    },
    async assertCurrent() {}, async finish() {},
  };
}

function scope(scopeKey) { return { scope: { userId: 7, scopeKey }, timeoutMs: 5000 }; }

test('scoped quiescence cancels selected prior runs, drains siblings, and queues arrivals', async () => {
  const coordinator = createRunCoordinator({ family: 'QUIESCENCE', ledger: ledger() });
  const order = [];
  let releaseSibling;
  const siblingGate = new Promise(resolve => { releaseSibling = resolve; });
  const selected = coordinator.run(7, scope('email'), async ({ signal }) => {
    await new Promise((resolve, reject) => {
      signal.addEventListener('abort', () => reject(signal.reason), { once: true });
    });
  });
  const sibling = coordinator.run(7, scope('profile'), async () => {
    order.push('profile-start'); await siblingGate; order.push('profile-end');
  });
  await new Promise(resolve => setImmediate(resolve));
  const barrier = coordinator.withScopesQuiesced(7, ['email'], async ({ scopeKeys }) => {
    order.push(`barrier:${scopeKeys.join(',')}`);
  });
  const arrival = coordinator.run(7, scope('email'), async () => { order.push('arrival'); return 'arrival'; });
  releaseSibling();
  await assert.rejects(selected, { name: 'AbortError' });
  await sibling;
  await barrier;
  assert.equal(await arrival, 'arrival');
  assert.deepEqual(order, ['profile-start', 'profile-end', 'barrier:email', 'arrival']);
});

test('scoped quiescence validates arguments and releases its barrier after callback failure', async () => {
  const coordinator = createRunCoordinator({ family: 'QUIESCENCE_INVALID', ledger: ledger() });
  for (const args of [[[], async () => {}], [['email', 'email'], async () => {}], [['bad-key!'], async () => {}], [['email'], null]]) {
    await assert.rejects(coordinator.withScopesQuiesced(7, args[0], args[1]), TypeError);
  }
  await assert.rejects(coordinator.withScopesQuiesced(7, ['email'], async () => { throw new Error('callback-failed'); }), /callback-failed/);
  assert.equal(await coordinator.run(7, scope('email'), async () => 'released'), 'released');
});

test('barrier is installed before abort listeners can enqueue and scope input is snapshotted', async () => {
  const coordinator = createRunCoordinator({ family: 'QUIESCENCE_ADVERSARIAL', ledger: ledger() });
  const order = [];
  let enqueued;
  const selected = coordinator.run(7, scope('email'), async ({ signal }) => {
    await new Promise((resolve, reject) => signal.addEventListener('abort', () => {
      enqueued = coordinator.run(7, scope('email'), async () => { order.push('enqueued'); });
      reject(signal.reason);
    }, { once: true }));
  });
  await new Promise(resolve => setImmediate(resolve));
  const keys = ['email'];
  const barrier = coordinator.withScopesQuiesced(7, keys, async ({ scopeKeys }) => {
    order.push(`barrier:${scopeKeys.join(',')}`);
    keys[0] = 'profile';
  });
  await assert.rejects(selected, { name: 'AbortError' });
  await barrier;
  await enqueued;
  assert.deepEqual(order, ['barrier:email', 'enqueued']);
});

test('whole-owner reset queues abort-listener arrivals after reset without cancelling them',async()=>{
 const coordinator=createRunCoordinator({family:'RESET_REENTRANT',ledger:null});
 const order=[];let arrival;
 const prior=coordinator.run(7,{timeoutMs:5000},async({signal})=>{
  await new Promise((resolve,reject)=>signal.addEventListener('abort',()=>{
   arrival=coordinator.run(7,{timeoutMs:5000},async()=>{order.push('arrival');return 'ok';});
   arrival.catch(()=>{});
   reject(signal.reason);
  },{once:true}));
 });
 await new Promise(resolve=>setImmediate(resolve));
 const reset=coordinator.reset(7,async()=>{order.push('reset');});
 await assert.rejects(prior,{name:'AbortError'});await reset;
 assert.equal(await arrival,'ok');assert.deepEqual(order,['reset','arrival']);
});

test('cancelScopes snapshots selected owner runs without retaining a barrier or cancelling reentrant arrivals',async()=>{
 const c=createRunCoordinator({family:'SCOPED_CANCEL',ledger:ledger()});let arrival,foreignAborted=false,releaseForeign;const foreignGate=new Promise(r=>{releaseForeign=r;});
 const foreign=c.run(8,{scope:{userId:8,scopeKey:'email'},timeoutMs:5000},async({signal})=>{signal.addEventListener('abort',()=>{foreignAborted=true;});await foreignGate;});
 const prior=c.run(7,scope('email'),async({signal})=>new Promise((resolve,reject)=>signal.addEventListener('abort',()=>{arrival=c.run(7,scope('email'),async()=> 'new-arrival');arrival.catch(()=>{});reject(signal.reason);},{once:true})));
 const caught=assert.rejects(prior,{name:'AbortError'});await new Promise(r=>setImmediate(r));
 c.cancelScopes(7,['profile']);await new Promise(r=>setImmediate(r));assert.equal(arrival,undefined);
 c.cancelScopes(7,['email']);await caught;assert.equal(await arrival,'new-arrival');assert.equal(foreignAborted,false);releaseForeign();await foreign;
 for(const keys of [[],['email','email'],['bad-key!']])assert.throws(()=>c.cancelScopes(7,keys),TypeError);
});
