'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { CRITERIA, observed, createCsrfObjectiveGrader: createGraderFactory } = require('../server/services/csrfObjectiveGrader');
const createCsrfObjectiveGrader = (options = {}) => createGraderFactory({ ...options,
  inspectMailProof: options.inspectMailProof || (receipt => receipt?.mailProof || null) });
const { createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
const execution = { check: async () => {}, runId: 'fixture', ownerKey: '["CSRF","7"]', generation: 0 };
const { issueCsrfBrowserReceipt } = require('../server/services/csrfBrowserReceipt');
// Explicit trusted-workflow fixture; real browser provenance is tested separately.
function browserReceipt(objectiveId, activity) {
  return issueCsrfBrowserReceipt({ execution, activity, binding: { ...execution, objectiveId,
    tab: objectiveId.startsWith('csrf_g') ? 'get' : 'post', payloadDigest: 'a'.repeat(64) },
    observation: { method: 'GET', resourceType: 'image', frameOrigin: 'http://attacker.csrf.invalid', cookiePresent: true },
    responseStatus: 403 });
}
const surface = { actions: [{ id: 'change_email' }], vectors: [{ id: 'direct_get' }] };
const snapshot = { reconCount: 2, xssEmailRead: true, ragFiredCount: 2 };
const pass = { verdict: 'pass', explanation: 'The server action records the stated outcome.',
  criteria: [{ id: 'observed_outcome', satisfied: true, evidenceRefs: ['action'] }] };

test('all twelve CSRF objectives have explicit observed outcomes and attack/defense proof gates', () => {
  assert.equal(Object.keys(CRITERIA).length, 12);
  assert.equal(observed('csrf_g1', snapshot, { result: { kind: 'recon', surface } }), true);
  assert.equal(observed('csrf_g2', snapshot, { result: { vector: 'direct_get', blocked: false, executed: true, stateChanged: true, changed: { email: 'fixture' } } }), true);
  assert.equal(observed('csrf_g2', snapshot, { result: { vector: 'direct_get', blocked: true, defenses: {csrfToken:true,sameSite:'None'} } }), false);
  assert.equal(observed('csrf_g3', snapshot, { result: { vector: 'direct_get', blocked: true, defenses: {csrfToken:true,sameSite:'None'} } }), true);
  assert.equal(observed('csrf_p3', snapshot, { result: { vector: 'fetch', blocked: true, defenses: {csrfToken:true,sameSite:'None'} } }), true);
  assert.equal(observed('csrf_x2', snapshot, null, null, { mailProof: { state: 'accepted', hasEventHandler: true } }), true);
  assert.equal(observed('csrf_x2', snapshot, null, { type: 'email_sent', success: true, hasEventHandler: true }), false,
    'a receipt-shaped public object has no authority');
  assert.equal(observed('csrf_i1', snapshot, null, { type: 'document_stored', chunks: 0 }), false);
  assert.equal(observed('csrf_i3', { ragFiredCount: 1 }, { name: 'rag', result: { blocked: false, executed: true, stateChanged: true, changed: { balance: 1 } } }), false);
});

test('passing model output cannot override missing observed action; blocked defense is a valid objective', async () => {
  const judge = createObjectiveJudge({ model: { generate: async () => ({ response: JSON.stringify(pass) }) } });
  const grader = createCsrfObjectiveGrader({ postgres: false, judge });
  const base = { userId: 7, execution, snapshot, activity: { result: { blocked: true, defenses: {csrfToken:true,sameSite:'None'}, vector: 'direct_get' } } };
  assert.equal((await grader.evaluate({ ...base, objectiveId: 'csrf_g2' })).completed, false);
  const defended = await grader.evaluate({ ...base, objectiveId: 'csrf_g3', receipt: browserReceipt('csrf_g3', base.activity) });
  assert.equal(defended.completed, true); assert.equal(defended.judgment.mode, 'fixed');
});
test('fixed attack-success objectives cannot earn credit from fabricated positive effects',async()=>{
 let modelCalls=0;
 const judge=createObjectiveJudge({model:{generate:async()=>{modelCalls++;return{response:JSON.stringify(pass),provider:'ollama',model:'controlled'};}}});
 const grader=createCsrfObjectiveGrader({postgres:true,completionService:{evaluate:async packet=>{
  assert.equal(packet.rubric.mode,'fixed');assert.equal(packet.facts.required_observation,false);
  const judgment=await judge({...packet,execution});return{completed:false,judgment};
 }}});
 for(const [objectiveId,vector] of [['csrf_g2','direct_get'],['csrf_p1','direct_post'],['csrf_p2','fetch'],['csrf_i2','indirect'],['csrf_i3','indirect']]){
  const activity={name:'rag gadget',result:{kind:'attack',vector,blocked:false,executed:true,stateChanged:true,changed:{balance:1}}};
  const result=await grader.evaluate({userId:7,objectiveId,execution,attempt:{mode:'fixed',generation:0},snapshot,activity});
  assert.notEqual(result.judgment.verdict,'pass');assert.equal(result.completed,false);
 }
 assert.ok(modelCalls>0,'fabricated positive model output cannot override fixed authority');
});

test('durable CSRF receipt decides completion and is captured before grading', async () => {
  const calls = [], attempt = {};
  const grader = createCsrfObjectiveGrader({ postgres: true, completionService: {
    beginAttempt: async args => { calls.push('begin'); assert.equal(args.workshopKey, 'csrf_workshop'); return attempt; },
    evaluate: async args => { calls.push('evaluate'); assert.equal(args.attempt, attempt); return { completed: false, judgment: { verdict: 'pass' } }; },
  } });
  const captured = await grader.begin(7, execution);
  const result = await grader.evaluate({ userId: 7, objectiveId: 'csrf_g3', execution, attempt: captured, snapshot,
    activity: { result: { blocked: true, defenses: {csrfToken:true,sameSite:'None'}, vector: 'direct_get' } } });
  assert.equal(result.completed, false); assert.equal(result.durable, true); assert.deepEqual(calls, ['begin', 'evaluate']);
});

test('mail authority is opaque and Judge evidence projects digests instead of addresses or payloads', async () => {
  let packet;
  const privateReceipt = {};
  const grader = createGraderFactory({ postgres: false,
    inspectMailProof: receipt => receipt === privateReceipt ? {
      kind: 'accepted', state: 'accepted', dispatchId: 'dispatch-fixture',
      dispatchRunId: execution.runId, recipient: 'private-owner@example.test', sender: 'private-sender@example.test',
      providerMessageId: 'provider-fixture', hasEventHandler: true,
      expected: { subjectDigest: 'a'.repeat(64), logicalBodyDigest: 'b'.repeat(64), payloadDigest: 'c'.repeat(64) },
    } : null,
    judge: async input => { packet = input; return { verdict: 'pass', criteria: [] }; },
  });
  const result = await grader.evaluate({ userId: 7, objectiveId: 'csrf_x2', execution,
    attempt: { generation: execution.generation }, snapshot, receipt: privateReceipt });
  assert.equal(result.completed, true);
  const encoded = JSON.stringify(packet.evidence);
  assert.equal(encoded.includes('private-owner'), false);
  assert.equal(encoded.includes('private-sender'), false);
  assert.equal(encoded.includes('recipientDigest'), true);
  assert.equal(encoded.includes('payloadDigest'), true);
});

test('every objective requires its own positive server observation and rejects an empty outcome', async () => {
  const change = vector => ({ result: { vector, blocked: false, executed: true, stateChanged: true, changed: { email: 'fixture' } } });
  const fixtures = {
    csrf_g1: [{ result: { kind: 'recon', surface } }],
    csrf_g2: [change('direct_get')],
    csrf_g3: [{ result: { vector: 'direct_get', blocked: true, defenses: {csrfToken:true,sameSite:'None'} } }],
    csrf_p1: [change('direct_post')],
    csrf_p2: [change('fetch')],
    csrf_p3: [{ result: { vector: 'direct_post', blocked: true, defenses: {csrfToken:true,sameSite:'None'} } }],
    csrf_x1: [null, { type: 'inbox_verified', success: true }],
    csrf_x2: [null, { mailProof: { state: 'accepted', hasEventHandler: true } }],
    csrf_x3: [{ ...change('email'), name: 'email_gadget' }, { mailProof: { state: 'retrieved', hasEventHandler: true } }],
    csrf_i1: [null, { type: 'document_stored', chunks: 1 }],
    csrf_i2: [{ ...change('rag'), name: 'rag_gadget' }],
    csrf_i3: [{ ...change('rag'), name: 'rag_gadget' }],
  };
  const judge = createObjectiveJudge({ model: { generate: async () => ({ response: JSON.stringify(pass) }) } });
  const grader = createCsrfObjectiveGrader({ postgres: false, judge });
  for (const objectiveId of Object.keys(CRITERIA)) {
    const [activity, receipt] = fixtures[objectiveId];
    assert.equal(observed(objectiveId, snapshot, activity, receipt, { mailProof: receipt?.mailProof || null }), true, objectiveId);
    assert.equal(observed(objectiveId, {}, {}, {}), false, `${objectiveId} empty evidence`);
    const denied = await grader.evaluate({ userId: 7, objectiveId, execution, snapshot: {}, activity: {}, receipt: {} });
    assert.equal(denied.completed, false, `${objectiveId} model cannot invent observation`);
  }
});


test('defense objectives reject contradictory blocked records with changed victim state', () => {
  for (const [id, vector] of [['csrf_g3', 'direct_get'], ['csrf_p3', 'fetch']]) {
    assert.equal(observed(id, snapshot, { result: { blocked: true, defenses: {csrfToken:true,sameSite:'None'}, vector, changed: { email: 'changed' } } }), false);
  }
});

test('optional undefined runtime DTO fields do not invalidate observed action evidence', async () => {
  const judge = createObjectiveJudge({ model: { generate: async () => ({ response: JSON.stringify(pass) }) } });
  const grader = createCsrfObjectiveGrader({ postgres: false, judge });
  const activity = { name: 'CSRF POST', args: { optional: undefined }, result: {
    blocked: false, executed: true, stateChanged: true, vector: 'direct_post', changed: { field: 'email', from: 'old', to: 'new' }, note: undefined,
  } };
  const result = await grader.evaluate({ userId: 7, objectiveId: 'csrf_p1', execution, snapshot,
    activity, receipt: browserReceipt('csrf_p1', activity) });
  assert.equal(result.completed, true);
});

test('invalid action rejection is not evidence of a working CSRF defense',()=>{
 for(const [id,vector] of [['csrf_g3','direct_get'],['csrf_p3','fetch']]){
  assert.equal(observed(id,{}, {result:{blocked:true,vector,error:'Unknown action'}}),false);
  assert.equal(observed(id,{}, {result:{blocked:true,vector,defenses:{csrfToken:false,sameSite:'None'}}}),false);
  assert.equal(observed(id,{}, {result:{blocked:true,vector,defenses:{csrfToken:false,sameSite:'Strict'}}}),false,
    'synthetic Strict metadata is not evidence of a real browser cookie defense');
 }
});
test('recon retains actual nested attack surface in judge evidence',async()=>{
 let packet;const surface={actions:[{id:'change_email'}],vectors:[{id:'direct_get'}]};
 const grader=createCsrfObjectiveGrader({postgres:false,judge:async p=>{packet=p;return {verdict:'fail'};}});
 await grader.evaluate({userId:7,objectiveId:'csrf_g1',execution,snapshot,activity:{result:{kind:'recon',surface}}});
 assert.deepEqual(packet.evidence.find(e=>e.id==='action').content.result.surface,surface);
});


test('mutation objectives reject missing, contradictory and malformed execution evidence', async () => {
  const judge = createObjectiveJudge({ model: { generate: async () => ({ response: JSON.stringify(pass) }) } });
  const grader = createCsrfObjectiveGrader({ postgres: false, judge });
  for (const [objectiveId, vector, name] of [
    ['csrf_g2', 'direct_get', 'GET'], ['csrf_p1', 'direct_post', 'POST'],
    ['csrf_p2', 'fetch', 'fetch'], ['csrf_x3', 'email', 'email gadget'],
    ['csrf_i2', 'rag', 'rag gadget'],
  ]) {
    const valid = { vector, executed: true, stateChanged: true, blocked: false, changed: { from: 'old', to: 'new' } };
    for (const patch of [
      { executed: undefined }, { executed: false }, { stateChanged: undefined },
      { stateChanged: false }, { error: 'effect failed' }, { changed: 'success' },
      { changed: ['success'] }, { changed: {} }, { changed: { from: 'same', to: 'same' } },
    ]) {
      const result = await grader.evaluate({ userId: 7, objectiveId, execution, snapshot,
        activity: { name, result: { ...valid, ...patch } } });
      assert.equal(result.completed, false, `${objectiveId}: ${JSON.stringify(patch)}`);
    }
  }
});

test('defense cannot pass when explicit mutation contradicts a missing delta', () => {
  for (const [id, vector] of [['csrf_g3', 'direct_get'], ['csrf_p3', 'fetch']]) {
    assert.equal(observed(id, snapshot, { result: {
      blocked: true, stateChanged: true, changed: null, vector, defenses: { csrfToken: true },
    } }), false);
  }
});


test('recon requires the returned attack surface, not only a classification label', async () => {
  const grader = createCsrfObjectiveGrader({ postgres: false,
    judge: createObjectiveJudge({ model: { generate: async () => ({ response: JSON.stringify(pass) }) } }) });
  for (const returnedSurface of [null, {}, { actions: [], vectors: [] },
    { actions: [{ id: 'change_email' }], vectors: [{ id: '' }] }]) {
    const result = await grader.evaluate({ userId: 7, objectiveId: 'csrf_g1', execution, snapshot,
      activity: { result: { kind: 'recon', surface: returnedSurface } } });
    assert.equal(result.completed, false);
  }
});

test('counts must be finite nonnegative whole observations rather than coercible claims', () => {
  for (const count of ['2', 2.5, Infinity, NaN, -1]) {
    assert.equal(observed('csrf_g1', { reconCount: count }, { result: { kind: 'recon', surface } }), false);
    assert.equal(observed('csrf_i1', {}, null, { type: 'document_stored', chunks: count }), false);
    assert.equal(observed('csrf_i3', { ragFiredCount: count }, { name: 'rag', result: { executed: true, blocked: false } }), false);
  }
});
