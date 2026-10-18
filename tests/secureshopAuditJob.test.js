'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createRunCoordinator } = require('../server/agent-runtime/runCoordinator');
const { createBoundTurns } = require('../server/services/secureshopBoundTurns');
const { createSecureShopAuditJob } = require('../server/services/secureshopAuditJob');

const scope = Object.freeze({
  launchId: '11111111-1111-4111-8111-111111111111',
  scenarioId: '22222222-2222-4222-8222-222222222222', generation: 1,
  platformOwnerId: 7, platformSessionId: 8,
});
const admin = Object.freeze({ id: 3, role: 'admin' });
const requestId = '33333333-3333-4333-8333-333333333333';

function fixture({ workerError, publishError, disposeError, readerError, consumeError, workerBarrier, capturePromptPolicy,
  inspectWorker, mode='vuln', inspectSpool, sceneSource, sceneBinding, checkScene, taskRequestVersion } = {}) {
  const events = [];
  const effects = new Map();
  const ownershipChecks = [];
  let activeRun;
  let stale = false;
  const ledger = {
    async begin() { return { durableGeneration: '1' }; },
    async assertCurrent() { if (stale) throw Object.assign(new Error('retired generation'), { code: 'STALE_GENERATION' }); },
    async effect(context, key, callback) {
      events.push('effect:start');
      activeRun = { context, key };
      effects.set(key, 'started');
      try {
        const value = await callback();
        effects.set(key, 'completed');
        events.push('effect:completed');
        return value;
      } catch (error) {
        effects.set(key, 'uncertain');
        events.push('effect:uncertain');
        throw error;
      }
    },
    async readCompletedEffect(context, key) {
      const status = effects.get(key);
      if (status !== 'completed') return null;
      return { ownerKey: context.ownerKey, generation: String(context.durableGeneration),
        runId: context.runId, effectKey: key, status };
    },
    async finish(_context, { status }) { events.push(`finish:${status}`); },
  };
  const turns = createBoundTurns({ coordinator: createRunCoordinator({ family: 'AuditJobTest', ledger }),
    conversations: { async assertOwned(sessionId, binding, persona, purpose) {
      ownershipChecks.push({ sessionId, binding, persona, purpose });
      assert.equal(purpose, 'secureshop_audit_summary');
    } } });
  const snapshot = { async *rows() { events.push('snapshot'); yield {
    id: 'agents:11111111-1111-4111-8111-111111111111', store: 'agents', ts: '2026-01-01T00:00:00.000000Z', actor: 'a', action: 'read',
    target: null, params_json: '{}', outcome: 'completed', source_kind: 'test', source_id: '1',
  }; } };
  const spoolObservation = async ({ runId, rows,maxBytes }) => {
    for await (const row of rows) {events.push('spool:row');inspectSpool?.(row,maxBytes);}
    return { directory: '/private/audit', manifest: { runId },
      async dispose() { events.push('spool:dispose'); if (disposeError) throw disposeError; } };
  };
  const runWorker = async (input) => {
    const {spool}=input;inspectWorker?.(input);
    events.push('worker');
    if (workerBarrier) await workerBarrier();
    if (workerError) throw workerError;
    return { runId: spool.manifest.runId, provider: 'ollama', model: 'controlled', summary: 'summary',
      logSha256: 'a'.repeat(64), sourcesSha256: 'b'.repeat(64), rowCount: 1, objectiveCredit: false,
      artifacts: {} };
  };
  const repository = { async publish({ execution, requestId: id }) {
    events.push('publish');
    if (publishError) throw publishError;
    return { runId: execution.runId, requestId: id, published: true, objectiveCredit: false };
  } };
  const reader = { async open({ runId }) {
    events.push('reader');
    if (readerError) throw readerError;
    return { runId, summary: 'summary', provider: 'ollama', model: 'controlled', requestedCount: 1,
      rowCount: 1, objectiveCredit: false };
  } };
  const consumeEvidence = async (evidence, options) => {
    events.push('consume');
    if (consumeError) throw consumeError;
    assert.equal(evidence.objectiveCredit, false);
    assert.equal(options.execution.runId, activeRun.context.runId);
    assert.equal(typeof options.check, 'function');
  };
  const job = createSecureShopAuditJob({ snapshot, repository, reader, consumeEvidence,
    spoolObservation, runWorker, capturePromptPolicy, mode, sceneSource, sceneBinding, checkScene,
    ...(taskRequestVersion === undefined ? {} : { taskRequestVersion }), root: '/private', baseUrl: 'http://ollama', model: 'controlled' });
  return { events, effects, ownershipChecks, ledger, turns, job, retire: () => { stale = true; }, get activeRun() { return activeRun; } };
}

async function run(fixtureValue, input = {}) {
  return fixtureValue.turns.run('owner', scope, admin,
    { idempotencyKey: requestId, conversationPurpose: 'secureshop_audit_summary' },
    boundary => fixtureValue.job({ scope, persona: admin, requestId, requestedCount: 1,
      boundary, ...input }));
}

test('audit job publishes and disposes before completed effect, then consumes reader evidence in lease', async () => {
  let workerInput;
  const f = fixture({ inspectWorker(input) { workerInput = input; } });
  const result = await run(f);
  assert.deepEqual(f.events.slice(0, 8), [
    'effect:start', 'snapshot', 'spool:row', 'worker', 'publish', 'spool:dispose',
    'effect:completed', 'reader',
  ]);
  assert.ok(f.events.indexOf('consume') > f.events.indexOf('reader'));
  assert.ok(f.events.indexOf('consume') < f.events.indexOf('finish:completed'));
  assert.equal(result.runId, f.activeRun.context.runId);
  assert.deepEqual(result, {
    runId: f.activeRun.context.runId, summary: 'summary', provider: 'ollama', model: 'controlled',
    requestedCount: 1, rowCount: 1, objectiveCredit: false,
  });
  assert.equal(f.effects.get(f.activeRun.key), 'completed');
  assert.equal(workerInput.taskRequestVersion, 1);
  assert.ok(f.ownershipChecks.length > 1, 'admission and retained-run ownership are both checked');
  for (const check of f.ownershipChecks) {
    assert.equal(check.sessionId, 'owner');
    assert.equal(check.purpose, 'secureshop_audit_summary');
    assert.deepEqual(check.persona, admin);
  }
});

test('audit job forwards only the closed objective task version', async () => {
  let workerInput;
  await run(fixture({ taskRequestVersion: 2, inspectWorker(input) { workerInput = input; } }));
  assert.equal(workerInput.taskRequestVersion, 2);
  for (const taskRequestVersion of [0, 3, '2', true, null]) {
    assert.throws(() => fixture({ taskRequestVersion }), /task request version/);
  }
});

for (const [name, option] of [['worker', 'workerError'], ['publisher', 'publishError'], ['cleanup', 'disposeError']]) {
  test(`audit ${name} failure prevents reader evidence and marks parent effect uncertain`, async () => {
    const error = new Error(`${name} failed`);
    const f = fixture({ [option]: error });
    await assert.rejects(run(f), error);
    assert.equal(f.events.includes('reader'), false);
    assert.equal(f.events.includes('consume'), false);
    assert.equal(f.events.at(-2), 'effect:uncertain');
    assert.equal(f.events.at(-1), 'finish:failed');
  });
}

test('audit reader receipt failure rejects after publication and completed effect', async () => {
  const f = fixture({ readerError: Object.assign(new Error('wrong receipt'), { code: 'AUDIT_RUN_EFFECT_UNVERIFIED' }) });
  await assert.rejects(run(f), { code: 'AUDIT_RUN_EFFECT_UNVERIFIED' });
  assert.equal(f.effects.get(f.activeRun.key), 'completed');
  assert.ok(f.events.indexOf('reader') > f.events.indexOf('effect:completed'));
  assert.equal(f.events.includes('consume'), false);
});

test('invalid admin persona and count reject before snapshot/effect', async () => {
  const f = fixture();
  await assert.rejects(f.turns.run('owner', scope, { id: 3, role: 'customer' },
    { idempotencyKey: requestId, conversationPurpose: 'secureshop_audit_summary' },
    boundary => f.job({ scope, persona: { id: 3, role: 'customer' }, requestId, requestedCount: 1, boundary })));
  await assert.rejects(run(f, { requestedCount: 0 }), TypeError);
  assert.equal(f.events.includes('snapshot'), false);
  assert.equal(f.events.includes('effect:start'), false);
});

test('late worker completion after a generation fence cannot publish or reach assessment', async () => {
  let releaseWorker, enteredWorker;
  const entered = new Promise(resolve => { enteredWorker = resolve; });
  const release = new Promise(resolve => { releaseWorker = resolve; });
  const f = fixture({ workerBarrier: async () => { enteredWorker(); await release; } });
  let assessed = false;
  const pending = run(f, { assessment: { consume: async () => { assessed = true; } } });
  const rejection = assert.rejects(pending, { code: 'STALE_GENERATION' });
  await entered;
  f.retire();
  releaseWorker();
  await rejection;
  assert.equal(f.events.includes('publish'), false);
  assert.equal(f.events.includes('reader'), false);
  assert.equal(f.events.includes('consume'), false);
  assert.equal(assessed, false);
  assert.ok(f.events.includes('spool:dispose'));
  assert.equal(f.effects.get(f.activeRun.key), 'uncertain');
});

test('job admits policy only through trusted closure under retained run before worker',async()=>{
 const snapshot=require('../server/services/secureshopPromptPolicySnapshot').buildPolicySnapshot({policyVersion:'3',role:'admin',policies:[]});let captured,observed;
 const f=fixture({capturePromptPolicy:async execution=>{captured=execution;return snapshot;},inspectWorker:input=>{observed=input.promptPolicySnapshot;}});
 await run(f,{promptPolicySnapshot:{forged:true}});assert.equal(captured.runId,f.activeRun.context.runId);assert.deepEqual(observed,snapshot);
});
test('invalid policy capture prevents spool, worker and publication',async()=>{
 const f=fixture({capturePromptPolicy:async()=>({forged:true})});await assert.rejects(run(f));assert.ok(!f.events.includes('worker'));assert.ok(!f.events.includes('snapshot'));assert.ok(!f.events.includes('publish'));
});

test('fixed audit job projects bounded source metadata before worker while vulnerable source is unchanged',async()=>{
 let projected;const f=fixture({mode:'fixed',inspectSpool:(row,maxBytes)=>{projected=row;assert.equal(maxBytes,131072);}});await run(f);
 assert.equal(projected.actor,'recorded_actor');assert.equal(projected.action,'recorded_event');assert.match(projected.source_id,/^[a-f0-9]{64}$/);assert.deepEqual(JSON.parse(projected.params_json),{outcome:'completed',store:'agents'});
 let raw;await run(fixture({inspectSpool:row=>{raw=row;}}));assert.equal(raw.actor,'a');assert.equal(raw.action,'read');
 const denied=fixture({mode:'fixed'});await assert.rejects(run(denied,{requestedCount:101}),{code:'AUDIT_FIXED_COUNT_LIMIT'});assert.equal(denied.events.includes('worker'),false);assert.equal(denied.events.includes('snapshot'),false);
});

test('scene stream closes before scene checks, and retirement blocks worker/publication',async()=>{
  let held=false,retired=false,scans=0,sceneChecks=0;
  const sceneSource={async *rows(input){scans++;assert.equal(input.sceneBinding,sceneBinding);held=true;
    try{await input.checkCurrent();yield {id:'review:22222222-2222-4222-8222-222222222222',store:'review',ts:'2026-01-01T00:00:01.000000Z',actor:'merchant',action:'listing_update',target:'17',params_json:'{}',outcome:'completed',source_kind:'product',source_id:'17'};}
    finally{held=false;retired=true;}}};
  const sceneBinding={scene:{}};
  const f=fixture({sceneSource,sceneBinding,checkScene:async()=>{sceneChecks++;assert.equal(held,false,'scene lease must not be reacquired per row');if(retired)throw Object.assign(Error('scene retired'),{code:'SHOP_SCENE_STALE'});}});
  await assert.rejects(run(f),{code:'SHOP_SCENE_STALE'});
  assert.equal(scans,1);assert.ok(sceneChecks>=3);assert.equal(held,false);
  assert.equal(f.events.includes('worker'),false);assert.equal(f.events.includes('publish'),false);
  assert.equal(f.events.includes('spool:dispose'),true);
});

test('completed whole-job replay does not scan either source or repeat model/publication',async()=>{
  let scans=0,workers=0,publishes=0,sceneChecks=0;
  const runId='44444444-4444-4444-8444-444444444444',ownerKey='owned',generation='1';
  const rows={async *rows(){scans++;throw Error('replay rescan');}};
  const job=createSecureShopAuditJob({snapshot:rows,sceneSource:rows,sceneBinding:{scene:{}},checkScene:async()=>{sceneChecks++;},
    repository:{publish:async()=>{publishes++;}},reader:{open:async()=>({runId,summary:'original',provider:'ollama',model:'actual',requestedCount:1,rowCount:1})},consumeEvidence:async()=>{},
    root:'/private',baseUrl:'http://ollama',model:'actual',runWorker:async()=>{workers++;}});
  const boundary={identity:{runId,ownerKey,durableGeneration:generation},check:async()=>{},
    effectWithReceipt:async(_node,_callback)=>({receipt:{status:'completed',runId,ownerKey,generation,effectKey:`${requestId}:audit-summary-job`}})};
  const result=await job({scope,persona:admin,requestId,requestedCount:1,boundary});
  assert.equal(result.summary,'original');assert.deepEqual([scans,workers,publishes],[0,0,0]);assert.ok(sceneChecks>0);
});
