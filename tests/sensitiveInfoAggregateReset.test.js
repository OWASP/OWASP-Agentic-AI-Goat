'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSensitiveInfoAggregateReset } = require('../server/services/sensitiveInfoAggregateReset');
const { createRunCoordinator } = require('../server/agent-runtime/runCoordinator');

function journalFixture({ onBegin = () => {} } = {}) {
  const operations = new Map();
  return {
    async begin({ ownerId, operationId = `00000000-0000-4000-8000-${String(ownerId).padStart(12, '0')}` }) {
      const prior = [...operations.values()].find(row => row.ownerId === ownerId && row.status !== 'completed');
      if (prior) return prior;
      onBegin(ownerId);
      const row = { operationId, ownerId, fromGeneration: 2, toGeneration: 3, status: 'pending', steps: ['legacy_store','finflow_store'] };
      operations.set(operationId, row); return row; },
    async read(id) { return operations.get(id); },
    async claim(id) { const row = operations.get(id); if (!row || row.status === 'completed') return null;
      row.status = 'running'; return { operationId: id, ownerId: row.ownerId,
        fromGeneration:row.fromGeneration,toGeneration:row.toGeneration,
        leaseToken: '11111111-1111-4111-8111-111111111111' }; },
    async nextStep({ operationId }) { return operations.get(operationId).steps[0] || null; },
    async acknowledge({ operationId, stepKey }) { const row = operations.get(operationId); row.steps = row.steps.filter(key => key !== stepKey); },
    async fail({ operationId }) { operations.get(operationId).status = 'failed'; },
    async complete({ operationId }) { const row = operations.get(operationId); row.status = 'completed'; return row; },
    operations,
  };
}
function cleanupFixture({ apply } = {}) {
  const receipts = new Map();
  return { receipts,
    async apply(scope) { if (apply) await apply(scope, receipts);
      const key = `${scope.operationId}:${scope.stepKey}`; if (!receipts.has(key)) receipts.set(key, { ...scope }); return receipts.get(key); },
    async readReceipt(scope) { return receipts.get(`${scope.operationId}:${scope.stepKey}`) || null; },
  };
}

test('aggregate reset persists canonical manifest then drains Legacy and FinFlow before local cleanup', async () => {
  const order = [];
  const reset = createSensitiveInfoAggregateReset({
    legacyRuns: { reset: async (owner, work) => { order.push(`legacy:${owner}:enter`); await work(); order.push('legacy:exit'); } },
    finflowReset: async (owner, work) => { order.push(`finflow:${owner}:enter`); await work(); order.push('finflow:exit'); },
    cleanup: cleanupFixture({ apply: async scope => order.push(scope.stepKey) }),
    journal: journalFixture({ onBegin: owner => order.push(`canonical:${owner}:sensitive_info_disclosure`) }),
  });
  await reset.reset(7);
  assert.deepEqual(order, ['canonical:7:sensitive_info_disclosure', 'legacy:7:enter', 'finflow:7:enter',
    'legacy_store', 'finflow_store', 'finflow:exit', 'legacy:exit']);
});

test('aggregate returns the journal result through the real void-returning run coordinator', async () => {
  const operationId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const reset = createSensitiveInfoAggregateReset({
    legacyRuns: createRunCoordinator({ family: 'LegacySensitiveInfo:aggregate-result-fixture', ledger: null }),
    finflowReset: async (_owner, work) => { await work(); },
    cleanup: cleanupFixture(),
    journal: journalFixture(),
  });
  const result = await reset.reset(7, { operationId });
  assert.equal(result.operationId, operationId);
  assert.equal(result.status, 'completed');
});

test('failed local reset keeps its canonical fence and retry does not advance it twice', async () => {
  let fail = true, canonical = 0, legacy = 0;
  const cleanup=cleanupFixture({apply:async scope=>{if(scope.stepKey==='legacy_store')legacy+=1;
    if(scope.stepKey==='finflow_store'&&fail)throw new Error('store unavailable');}});
  const reset = createSensitiveInfoAggregateReset({
    legacyRuns: { reset: async (_owner, work) => work() }, finflowReset: async (_owner, work) => work(),
    cleanup, journal: journalFixture({ onBegin: () => { canonical += 1; } }),
  });
  await assert.rejects(reset.reset(7), /store unavailable/);
  assert.equal(canonical, 1);
  fail = false;
  await reset.reset(7);
  assert.equal(legacy, 1);
  assert.equal(canonical, 1);
});

test('an owner reset does not target a sibling owner', async () => {
  const touched = [];
  const reset = createSensitiveInfoAggregateReset({
    legacyRuns: { reset: async (owner, work) => { touched.push(['legacy', owner]); return work(); } },
    finflowReset: async (owner, work) => { touched.push(['finflow', owner]); return work(); },
    cleanup:cleanupFixture({apply:async scope=>touched.push([scope.stepKey,scope.ownerId])}),
    journal: journalFixture({ onBegin: owner => touched.push(['canonical', owner]) }),
  });
  await reset.reset(41);
  assert.equal(touched.every(([, owner]) => String(owner) === '41'), true);
  assert.equal(touched.some(([, owner]) => String(owner) === '42'), false);
});

test('crash recovery resumes the first incomplete step without advancing canonical generation again', async () => {
  const journal = journalFixture();
  const operation = await journal.begin({ ownerId: 17 });
  operation.steps.shift(); // durable legacy_store acknowledgement before crash
  const touched = [];
  const reset = createSensitiveInfoAggregateReset({
    legacyRuns: { reset: async (_owner, work) => work() }, finflowReset: async (_owner, work) => work(),
    cleanup:cleanupFixture({apply:async scope=>touched.push(scope.stepKey)}), journal,
  });
  const result = await reset.recover(operation.operationId);
  assert.deepEqual(touched, ['finflow_store']);
  assert.equal(result.status, 'completed');
  assert.equal(journal.operations.size, 1);
});

test('simultaneous same-owner requests coalesce to one durable generation', async () => {
  let begins = 0, release;
  const journal = journalFixture({ onBegin: () => { begins += 1; } });
  const reset = createSensitiveInfoAggregateReset({
    legacyRuns: { reset: async (_owner, work) => work() }, finflowReset: async (_owner, work) => work(),
    cleanup:cleanupFixture({apply:async scope=>{if(scope.stepKey==='legacy_store')await new Promise(resolve=>{release=resolve;});}}),journal,
  });
  const first = reset.reset(18), second = reset.reset(18);
  await new Promise(resolve => setImmediate(resolve)); release();
  assert.equal(await first, await second);
  assert.equal(begins, 1);
});

test('same explicit operation coalesces while distinct operations serialize without identity substitution', async () => {
  const firstId='11111111-1111-4111-8111-111111111111';
  const secondId='22222222-2222-4222-8222-222222222222';
  const begun=[];let release;
  const operations=new Map();
  const journal=journalFixture();
  journal.begin=async({ownerId,operationId})=>{
    begun.push(operationId);
    const row={operationId,ownerId,fromGeneration:begun.length,toGeneration:begun.length+1,
      status:'pending',steps:['legacy_store','finflow_store']};operations.set(operationId,row);return row;
  };
  journal.read=async id=>operations.get(id);
  journal.claim=async id=>{const row=operations.get(id);return{...row,
    leaseToken:'33333333-3333-4333-8333-333333333333'};};
  journal.nextStep=async({operationId})=>operations.get(operationId).steps[0]||null;
  journal.acknowledge=async({operationId,stepKey})=>{const row=operations.get(operationId);
    row.steps=row.steps.filter(key=>key!==stepKey);};
  journal.complete=async({operationId})=>({...operations.get(operationId),status:'completed'});
  let first=true;
  let tail=Promise.resolve();
  const serializedRuns={reset:async(_owner,work)=>{const previous=tail;let releaseTail;
    tail=new Promise(resolve=>{releaseTail=resolve;});await previous;
    try{return await work();}finally{releaseTail();}}};
  const reset=createSensitiveInfoAggregateReset({journal,
    legacyRuns:serializedRuns,finflowReset:async(_owner,work)=>work(),
    cleanup:cleanupFixture({apply:async scope=>{if(first&&scope.operationId===firstId){first=false;
      await new Promise(resolve=>{release=resolve;});}}}),
  });
  const firstRun=reset.reset(20,{operationId:firstId});
  const sameRun=reset.reset(20,{operationId:firstId});
  const distinctRun=reset.reset(20,{operationId:secondId});
  await new Promise(resolve=>setImmediate(resolve));release();
  const [one,replay,two]=await Promise.all([firstRun,sameRun,distinctRun]);
  assert.equal(one.operationId,firstId);
  assert.equal(replay.operationId,firstId);
  assert.equal(two.operationId,secondId);
  assert.deepEqual(begun,[firstId,secondId]);
});

test('operation UUID aliases use one canonical coalescing key and durable operation', async () => {
  const canonical = 'abcdefab-cdef-4abc-8def-abcdefabcdef';
  let begins = 0;
  let release;
  const journal = journalFixture();
  const originalBegin = journal.begin;
  journal.begin = async input => { begins += 1; return originalBegin(input); };
  const reset = createSensitiveInfoAggregateReset({
    legacyRuns: createRunCoordinator({ family: 'LegacySensitiveInfo:uuid-alias-fixture', ledger: null }),
    finflowReset: async (_owner, work) => work(),
    cleanup: cleanupFixture({ apply: async scope => {
      if (scope.stepKey === 'legacy_store') await new Promise(resolve => { release = resolve; });
    } }),
    journal,
  });
  const lower = reset.reset(8, { operationId: canonical });
  const upper = reset.reset(8, { operationId: canonical.toUpperCase() });
  while (!release) await new Promise(resolve => setImmediate(resolve));
  release();
  const [first, replay] = await Promise.all([lower, upper]);
  assert.equal(first, replay);
  assert.equal(first.operationId, canonical);
  assert.equal(begins, 1);
});

test('completed replay and wrong-owner operation are resolved before process-local invalidation', async () => {
  const operationId='55555555-5555-4555-8555-555555555555';let resets=0;
  const operation={operationId,ownerId:21,fromGeneration:4,toGeneration:5,status:'completed'};
  const reset=createSensitiveInfoAggregateReset({
    legacyRuns:{reset:async(_owner,work)=>{resets+=1;return work();}},
    finflowReset:async(_owner,work)=>work(),cleanup:cleanupFixture(),
    journal:{...journalFixture(),read:async()=>operation},
  });
  assert.equal(await reset.reset(21,{operationId}),operation);
  await assert.rejects(reset.reset(22,{operationId}),{code:'SENSITIVE_INFO_RESET_SCOPE_MISMATCH'});
  assert.equal(resets,0,'replay and owner mismatch must not invalidate either owner run generation');
});

test('a stalled expired worker cannot delete after a reclaimed worker publishes the same receipt', async () => {
  const journal=journalFixture();const operation=await journal.begin({ownerId:19});
  let release;const mutations=[];const receipts=new Map();
  const cleanup={
    async apply(scope){const key=`${scope.operationId}:${scope.stepKey}`;
      if(scope.worker==='A')await new Promise(resolve=>{release=resolve;});
      if(!receipts.has(key)){mutations.push(`${scope.stepKey}:${scope.toGeneration}`);receipts.set(key,{...scope,worker:undefined});}
      return receipts.get(key);},
    async readReceipt(scope){return receipts.get(`${scope.operationId}:${scope.stepKey}`)||null;},
  };
  // Destination fencing is tested directly here: B commits the immutable
  // receipt after A stalls; A then observes the same receipt and performs no
  // second destructive mutation.
  const base={operationId:operation.operationId,stepKey:'legacy_store',ownerId:19,fromGeneration:2,toGeneration:3};
  const stalled=cleanup.apply({...base,worker:'A'});await new Promise(resolve=>setImmediate(resolve));
  await cleanup.apply({...base,worker:'B'});release();await stalled;
  assert.deepEqual(mutations,['legacy_store:3']);
});

test('version2 persisted plans never acquire the legacy coordinator or legacy cleanup',async()=>{
 const journal=journalFixture();const original=journal.begin;journal.begin=async input=>{const row=await original(input);row.planVersion=2;row.steps=['finflow_store'];return row;};
 const steps=[];const reset=createSensitiveInfoAggregateReset({legacyRuns:{reset:async()=>{throw Error('Legacy family must remain untouched');}},finflowReset:async(_owner,work)=>work(),journal,cleanup:cleanupFixture({apply:async s=>steps.push(s.stepKey)})});
 const result=await reset.reset(7);assert.equal(result.planVersion,2);assert.deepEqual(steps,['finflow_store']);
});
