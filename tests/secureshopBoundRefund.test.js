'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createSecureShopBoundRefundRepository } = require('../server/database/postgres/secureshopBoundRefundRepository');
const { createSecureShopBoundRefundTools } = require('../server/services/secureshopBoundRefundTools');
const { createBoundRefundRouter } = require('../server/routes/secureshop/boundRefund');
const { createSecureShopBoundRefundRuntime } = require('../server/services/secureshopBoundRefundRuntime');
const { createSecureShopBoundCatalog } = require('../server/services/secureshopBoundCatalog');

test('refund provider admission requires a current retained product scene despite a live launch and persona',async t=>{
 for(const mutation of ['retired','sceneGeneration','grantId','targetId','duringProvider','resolverError','healthy'])await t.test(mutation,async()=>{
  const {randomUUID}=require('node:crypto');
  const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
  const credential={sessionId:randomUUID(),authorityVersion:'1'},sessions=new Map(),messages=new Map();
  const tuple={sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID()};
  let targetId=scope.targetId,retired=false,reads=0,providerCalls=0,effects=0,claims=0;
  const retained=async()=>{reads++;return retired?null:createSceneBinding({...scope,targetId},{...tuple,execution:scope,withLease:work=>work()});};
  const repository={
   async getBoundSession(id){return sessions.get(id)||null;},
   async acquireBoundSession({id,binding,purpose}){const row={id,binding,purpose,state:'pending'};sessions.set(id,row);return row;},
   async activateBoundSession(id){sessions.get(id).state='active';return true;},
   async getMessages(id){return messages.get(id)||[];},async runExclusive(_id,work){return work();},
   async appendMessage(id,_binding,message){messages.set(id,[...(messages.get(id)||[]),message]);},
   async getTokens(){return 0;},async addTokens(){},async appendTraces(){},
  };
  let capturedReads;
  const runtime=createSecureShopBoundRefundRuntime({
   launches:{async assertCurrent(){}},authenticatePersona(){},conversationRepository:repository,
   personaAuthority:{capture:({scope:s,personaId,role,sessionId,authorityVersion})=>({
    binding:{...s,personaId,role,sessionId,authorityVersion},async assertRemoteAdmission(){},
    async withPersonaEffect(work){return work();},async withCrossStoreEffect(work){return work();}})},
   resolveRetainedTarget:async binding=>{
    if(mutation==='resolverError'&&providerCalls)throw Object.assign(Error('Scene grant retired'),{code:'SHOP_SCENE_STALE'});
    const value=await retained(binding);
    if(capturedReads!==undefined&&reads===capturedReads+1){
     if(mutation==='sceneGeneration')tuple.sceneGeneration++;
     if(mutation==='grantId')tuple.grantId=randomUUID();
     if(mutation==='targetId')targetId=randomUUID();
    }
    return value;
   },resolveTarget:async()=>{effects++;throw Error('No target provisioning expected');},
   refundRepository:{async create(){effects++;throw Error('No refund effect expected');}},commerce:{async order(){effects++;throw Error('No commerce read expected');}},
   journal:{async claim(){claims++;return{status:'claimed',claimId:'c'};},async complete(){},async markUncertain(){}},
   coordinator:{async run(_id,_options,work){return work({runId:randomUUID(),ownerKey:'refund-owner',generation:1,durableGeneration:1,
    async check(){},async effectWithReceipt(){effects++;throw Error('No graph effect expected');},async trace(){}});}},
   provider:{async chat(){providerCalls++;if(mutation==='duringProvider')retired=true;return{stop_reason:'end_turn',text:'Please supply the order number.'};},async finalResponse(){throw Error('Unexpected final provider');}},
   buildBasePrompt:()=> 'Refund support',buildPolicyBlock:async()=>'',checkToolAcl:async()=>({allowed:true,action:'dispatch'}),
  });
  const session=await runtime.createSession(scope,{id:41,role:'customer'},credential);
  capturedReads=reads;if(mutation==='retired')retired=true;
  const run=runtime.runner.run({sessionId:session.id,requestId:randomUUID(),scope,persona:{id:41,role:'customer'},personaSession:credential,
   message:'Please refund my synthetic practice order for the saved reason.'});
  if(mutation==='healthy'){assert.equal((await run).text,'Please supply the order number.');assert.equal(providerCalls,1);}
  else{await assert.rejects(run,{code:'SHOP_SCENE_STALE',executionBoundary:true});assert.equal(providerCalls,['duringProvider','resolverError'].includes(mutation)?1:0);}
  assert.equal(effects,0);if(mutation==='retired')assert.equal(claims,0);
 });
});

const scope = Object.freeze({ targetId: '10000000-0000-4000-8000-000000000001', launchId: '20000000-0000-4000-8000-000000000001', scenarioId: '30000000-0000-4000-8000-000000000001', generation: 1, platformOwnerId: 9, platformSessionId: 19 });
function fakePool({ orderOwner = 41, paymentStatus = 'approved', lifecycle = 'active', orderStatus = 'confirmed', ticketId = '77' } = {}) {
  let ticket = 0;
  const client = { async release() {}, async query(sql, args = []) {
    if (/^(BEGIN|COMMIT|ROLLBACK)/.test(sql)) return { rows: [], rowCount: 0 };
    if (sql.includes('FROM secureshop_review.product_targets')) return { rows: [{ lifecycle }], rowCount: 1 };
    if (sql.includes('FROM secureshop_review.product_target_orders') && sql.includes('FOR UPDATE')) {
      return args[1] === orderOwner ? { rows: [{ order_id: args[2], status: orderStatus, payment_status: paymentStatus }], rowCount: 1 } : { rows: [], rowCount: 0 };
    }
    if (sql.includes('INSERT INTO secureshop_review.product_target_refund_requests')) {
      if (ticket) return { rows: [], rowCount: 0 };
      ticket = ticketId; return { rows: [{ ticket_id: ticket, order_id: args[2] }], rowCount: 1 };
    }
    if (sql.includes('FROM secureshop_review.product_target_refund_requests')) {
      if (/FOR\s+(SHARE|UPDATE)/i.test(sql)) throw Object.assign(new Error('Runtime has no UPDATE privilege on refund tickets'), { code: '42501' });
      return ticket
      ? { rows: [{ ticket_id: ticket, order_id: args[2], status: 'open' }], rowCount: 1 } : { rows: [], rowCount: 0 };
    }
    throw new Error(`unexpected refund SQL: ${sql.slice(0, 100)}`);
  } };
  return { async query(...args) { return client.query(...args); }, async connect() { return client; } };
}
function ids() { return { requestId: '40000000-0000-4000-8000-000000000001', runId: null }; }

test('refund target preparation upgrades a raw reservation to the full launch binding', async () => {
  const rawReservation = { targetId: scope.targetId, launchId: scope.launchId,
    scenarioId: scope.scenarioId, generation: scope.generation, kind: 'products' };
  let opened;
  const repository = {
    async open(target) { opened = target; return { ownMerchantId: 12 }; },
    async provision() {}, async list() {}, async get() {}, async categories() {},
    async createListing() {}, async updateListing() {}, async archiveListing() {},
  };
  const catalog = createSecureShopBoundCatalog({
    sourcePool: { async query() { return { rows: [] }; } }, repository,
    resolveTarget: async () => rawReservation, checkCurrent: async () => {}, ownMerchantId: 12,
  });
  const binding = await catalog.prepareTarget({ scope: { ...scope, shopUserId: 41, role: 'customer' },
    persona: { id: 41, role: 'customer' } });
  assert.deepEqual(binding, scope);
  assert.deepEqual(opened, scope);
  assert.equal(opened.platformOwnerId, scope.platformOwnerId);
  assert.equal(opened.platformSessionId, scope.platformSessionId);
});

test('repository accepts eligible owned order and replays duplicate idempotently', async () => {
  const repo = createSecureShopBoundRefundRepository(fakePool(), { checkCurrent: async () => {} });
  const first = await repo.create(scope, { shopUserId: 41, orderId: 12, ...ids(), reason: 'duplicate charge' });
  const second = await repo.create(scope, { shopUserId: 41, orderId: 12, requestId: '40000000-0000-4000-8000-000000000002', reason: 'retry' });
  assert.deepEqual(first, { ticket_id: '77', order_id: '12', ok: true, replayed: false });
  assert.deepEqual(second, { ticket_id: '77', order_id: '12', ok: true, replayed: true });
});

test('repository rejects foreign, unpaid, cancelled, stale and malformed requests', async () => {
  await assert.rejects(() => createSecureShopBoundRefundRepository(fakePool(), { checkCurrent: async () => {} }).create(scope, { shopUserId: 99, orderId: 12, ...ids(), reason: 'x' }), { code: 'ORDER_NOT_FOUND' });
  await assert.rejects(() => createSecureShopBoundRefundRepository(fakePool({ paymentStatus: 'pending' }), { checkCurrent: async () => {} }).create(scope, { shopUserId: 41, orderId: 12, ...ids(), reason: 'x' }), { code: 'REFUND_NOT_ELIGIBLE' });
  await assert.rejects(() => createSecureShopBoundRefundRepository(fakePool({ lifecycle: 'retired' }), { checkCurrent: async () => {} }).create(scope, { shopUserId: 41, orderId: 12, ...ids(), reason: 'x' }), { code: 'PRODUCT_TARGET_UNAVAILABLE' });
  await assert.rejects(() => createSecureShopBoundRefundRepository(fakePool(), { checkCurrent: async () => { throw Object.assign(new Error('stale'), { code: 'STALE_LAUNCH' }); } }).create(scope, { shopUserId: 41, orderId: 12, ...ids(), reason: 'x' }), { code: 'STALE_LAUNCH' });
});

test('refund tool adapter preserves the effect DTO and closes stale scope', async () => {
  const calls = [];
  const tools = createSecureShopBoundRefundTools({
    repository: { async create(target, input) { calls.push(['refund', target, input]); return { ticket_id: '8', order_id: '12', ok: true, replayed: false }; } },
    commerce: { async order() { return { order: { id: 12, payment_status: 'approved' } }; } },
    binding: ids(), persona: { id: 41, role: 'customer' }, scope,
    fixedIntent: { orderId: 12, reason: 'please refund' },
    checkCurrent: async () => {}, resolveTarget: async value => value,
  });
  const status = JSON.parse((await tools['support.order_status']({ order_id: 12 })).content[0].text);
  assert.equal(status.ok, true);
  const result = JSON.parse((await tools['support.refund_request']({ order_id: 12, reason: 'please refund' })).content[0].text);
  assert.deepEqual(result, { ticket_id: '8', order_id: '12', ok: true, replayed: false }); assert.equal(calls[0][1].targetId, scope.targetId);
  const denied = createSecureShopBoundRefundTools({ ...({}), repository: { async create() { throw Object.assign(new Error('stale'), { code: 'STALE_LAUNCH' }); } }, commerce: { async order() { return {}; } }, binding: ids(), persona: { id: 41, role: 'customer' }, scope, fixedIntent: { orderId: 12, reason: 'please refund' }, checkCurrent: async () => { throw Object.assign(new Error('stale'), { code: 'STALE_LAUNCH' }); }, resolveTarget: async value => value });
  await assert.rejects(() => denied['support.order_status']({ order_id: 12 }), { code: 'STALE_LAUNCH' });
  let stale = false, refundWrites = 0;
  const previouslyAdmitted = createSecureShopBoundRefundTools({
    repository: { async create() { refundWrites++; return { ok: true }; } },
    commerce: { async order() { return { order: { id: 12, payment_status: 'approved' } }; } },
    binding: ids(), persona: { id: 41, role: 'customer' }, scope,
    fixedIntent: { orderId: 12, reason: 'please refund' },
    checkCurrent: async () => { if (stale) throw Object.assign(Error('stale'), { code: 'STALE_LAUNCH' }); },
    resolveTarget: async value => value,
  });
  assert.equal(JSON.parse((await previouslyAdmitted['support.order_status']({ order_id: 12 })).content[0].text).ok, true);
  stale = true;
  await assert.rejects(previouslyAdmitted['support.refund_request']({ order_id: 12, reason: 'please refund' }), { code: 'STALE_LAUNCH' });
  assert.equal(refundWrites, 0);

});

test('order status keeps current execution scope when the product target has an older birth', async () => {
  const current = Object.freeze({ ...scope, launchId: '10000000-0000-4000-8000-000000000010', platformSessionId: 24 });
  const birth = Object.freeze({ ...scope, launchId: '10000000-0000-4000-8000-000000000001', platformSessionId: 23 });
  const seen = [];
  const tools = createSecureShopBoundRefundTools({
    repository: { async create() { throw new Error('unexpected refund write'); } },
    commerce: { async order(input) { seen.push(input); return { order: { id: 12, payment_status: 'approved' } }; } },
    binding: ids(), persona: { id: 41, role: 'customer' }, scope: current,
    fixedIntent: { orderId: 12, reason: 'x' },
    checkCurrent: async value => assert.equal(value, current),
    resolveTarget: async value => { assert.equal(value, current); return birth; },
  });
  assert.equal(JSON.parse((await tools['support.order_status']({ order_id: 12 })).content[0].text).ok, true);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].scope, current);
});

test('refund requires a matching owned order status in the current tool context', async () => {
  const calls = [];
  const make = (orders = new Map([[12, { id: 12, payment_status: 'approved' }]])) =>
    createSecureShopBoundRefundTools({
      repository: { async create() { calls.push('create'); return { ok: true, ticket_id: '1', order_id: '12' }; } },
      commerce: { async order({ orderId }) { return { order: orders.get(orderId) || null }; } },
      binding: ids(), persona: { id: 41, role: 'customer' }, scope,
      fixedIntent: { orderId: 12, reason: 'x' },
      checkCurrent: async () => {}, resolveTarget: async value => value,
    });
  const early = make();
  assert.equal(JSON.parse((await early['support.refund_request']({ order_id: 12, reason: 'x' })).content[0].text).code, 'ORDER_STATUS_REQUIRED');
  assert.deepEqual(calls, []);
  const matching = make();
  assert.equal(JSON.parse((await matching['support.order_status']({ order_id: 12 })).content[0].text).ok, true);
  assert.equal(JSON.parse((await matching['support.refund_request']({ order_id: 12, reason: 'x' })).content[0].text).ok, true);
  assert.deepEqual(calls, ['create']);
  const other = make(new Map([[13, { id: 13, payment_status: 'approved' }]]));
  assert.equal(JSON.parse((await other['support.order_status']({ order_id: 13 })).content[0].text).code, 'REQUESTED_ORDER_MISMATCH');
  assert.equal(JSON.parse((await other['support.refund_request']({ order_id: 12, reason: 'x' })).content[0].text).code, 'ORDER_STATUS_REQUIRED');
  const fresh = make();
  assert.equal(JSON.parse((await fresh['support.refund_request']({ order_id: 12, reason: 'x' })).content[0].text).code, 'ORDER_STATUS_REQUIRED');
});

for (const mode of ['vuln', 'fixed']) {
  test(`ordinary refund in ${mode} requires the exact human order and raw reason`, async () => {
    const rawReason = '<img src=x onerror="owned_training()">\r\nHuman-authored reason: café';
    const intent = { orderId: 12, reason: rawReason };
    const writes = [], reads = [];
    const options = {
      repository: { async create(target, input) {
        writes.push({ target, input });
        return { ok: true, ticket_id: '1', order_id: '12' };
      } },
      commerce: { async order(input) {
        reads.push(input);
        return { order: { id: input.orderId, payment_status: 'approved',
          status: 'confirmed', privateTeachingField: 'raw owned projection' } };
      } },
      binding: ids(), persona: { id: 41, role: 'customer' }, scope,
      checkCurrent: async () => {}, resolveTarget: async value => value,
      mode, fixedIntent: intent,
    };
    const decode = value => JSON.parse(value.content[0].text);
    const tools = createSecureShopBoundRefundTools(options);
    // Even a caller mutation cannot change the captured human intent.
    intent.reason = 'Later substituted intent';
    assert.equal(decode(await tools['support.order_status']({ order_id: 13 })).code,
      'REQUESTED_ORDER_MISMATCH');
    assert.equal(reads.length, 0);
    assert.equal(decode(await tools['support.refund_request']({ order_id: 13,
      reason: rawReason })).code, 'REQUESTED_ORDER_MISMATCH');
    assert.equal(decode(await tools['support.refund_request']({ order_id: 12,
      reason: rawReason })).code, 'ORDER_STATUS_REQUIRED');
    const observed = decode(await tools['support.order_status']({ order_id: 12 }));
    assert.equal(observed.ok, true);
    assert.equal(Object.hasOwn(observed.order, 'privateTeachingField'), mode === 'vuln');
    for (const reason of ['Model-invented reason', rawReason.toUpperCase(),
      rawReason.replace('\r\n', '\n'), `${rawReason} `]) {
      assert.equal(decode(await tools['support.refund_request']({ order_id: 12,
        reason })).code, 'REQUESTED_REASON_MISMATCH');
    }
    assert.deepEqual(writes, []);
    assert.equal(decode(await tools['support.refund_request']({ order_id: 12,
      reason: rawReason })).ok, true);
    assert.equal(writes.length, 1);
    assert.equal(writes[0].input.orderId, 12);
    assert.equal(writes[0].input.reason, rawReason,
      'human-authored teaching content is retained byte-for-byte');
    assert.equal(writes[0].input.requestId, ids().requestId);
    const withoutIntent = createSecureShopBoundRefundTools({ ...options, fixedIntent: null });
    assert.equal(decode(await withoutIntent['support.order_status']({ order_id: 12 })).code,
      'REFUND_REQUEST_UNCLEAR');
    assert.equal(decode(await withoutIntent['support.refund_request']({ order_id: 12,
      reason: rawReason })).code, 'REFUND_REQUEST_UNCLEAR');
    assert.equal(writes.length, 1, 'model arguments cannot establish missing human intent');
  });
}

test('refund router forwards injected SSE and refuses an invalid launch', async t => {
  const app = express(); app.use(express.json());
  const goodLaunch = 'g'.repeat(43);
  const launches = { async resolveCapability(value) { return value === goodLaunch ? scope : null; } };
  const personaSession = Object.freeze({ sessionId: 'persona-session', authorityVersion: '7' });
  let sessionInput, runInput, readInput;
  const router = createBoundRefundRouter({ launches, authenticatePersona(req, res, next) { req.ssUser = { id: 41, role: 'customer' }; req.ssPersonaSession = personaSession; next(); }, runtime: { async createSession(...input) { sessionInput = input; return { id: 'session-1' }; }, async readRequest(...input) { readInput = input; return { requestId: input[4], status: 'unconfirmed' }; }, runner: { async run(input) { runInput = input; input.stream.send('result', { committed: true, ticketId: 77 }); input.stream.send('done', { stopReason: 'end_turn' }); } } } });
  app.use('/api', router); const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); }); t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}/api`;
  const admitted = await fetch(`${base}/agents/customer/refund/session`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-dvaia-secureshop-launch': goodLaunch }, body: '{}' });
  assert.equal(admitted.status, 200); assert.equal((await admitted.json()).sessionId, 'session-1');
  assert.equal(sessionInput[2], personaSession);
  const good = await fetch(`${base}/agents/customer/refund/chat`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-dvaia-secureshop-launch': goodLaunch }, body: JSON.stringify({ sessionId: 'session-1', message: 'refund order 12' }) });
  assert.equal(good.status, 200); const body = await good.text(); assert.match(body, /committed/); assert.match(body, /ticketId/);
  const requestId = '40000000-0000-4000-8000-000000000042';
  const own = await fetch(`${base}/agents/customer/refund/chat`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-dvaia-secureshop-launch': goodLaunch }, body: JSON.stringify({ sessionId: 'session-1', message: 'refund order 12', requestId: requestId.toUpperCase() }) });
  assert.equal(own.status, 200); await own.text(); assert.equal(runInput.requestId, requestId);
  const recovery = await fetch(`${base}/agents/customer/refund/operations/${requestId}/${requestId}`, { headers: { 'x-dvaia-secureshop-launch': goodLaunch } });
  assert.equal(recovery.status, 200); assert.deepEqual(await recovery.json(), { requestId, status: 'unconfirmed' });
  assert.equal(readInput[2], personaSession);
  const malformed = await fetch(`${base}/agents/customer/refund/operations/not-uuid/${requestId}`, { headers: { 'x-dvaia-secureshop-launch': goodLaunch } });
  assert.equal(malformed.status, 400);
  const bad = await fetch(`${base}/agents/customer/refund/chat`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-dvaia-secureshop-launch': 'bad' }, body: JSON.stringify({ sessionId: 'session-1', message: 'refund order 12' }) });
  assert.equal(bad.status, 401);
});

test('refund request readback requires the same live customer conversation and a durable effect receipt', async () => {
  const sessionId = '91000000-0000-4000-8000-000000000011';
  const requestId = '92000000-0000-4000-8000-000000000011';
  const credential = Object.freeze({ sessionId: '93000000-0000-4000-8000-000000000011', authorityVersion: '3' });
  const persona = Object.freeze({ id: 41, role: 'customer' });
  const binding = Object.freeze({ ...scope, shopUserId: 41, role: 'customer' });
  let stale = false, turn = { status: 'completed' }, receipt = { ticketId: '77', orderId: 12 }, reads = 0;
  let collisionAttempt = false, collisionObserved = false;
  const runtime = createSecureShopBoundRefundRuntime({
    launches: { async assertCurrent() { if (stale) throw Object.assign(new Error('stale'), { code: 'STALE_LAUNCH' }); } },
    conversationRepository: {
      async getBoundSession() { return { id: sessionId, state: 'active', binding, purpose: 'secureshop_refund_request' }; },
      async appendMessage() {}, async getMessages() { return []; }, async getTokens() { return 0; },
      async addTokens() {}, async appendTraces() {},
    },
    journal: { async claim() {}, async complete() {}, async markUncertain() {},
      async readBoundRequest(input) { assert.equal(input.sessionId, sessionId); assert.equal(input.requestId, requestId);
        if (collisionObserved) throw Object.assign(new Error('duplicate request UUID'), { code: 'TURN_REQUEST_CONFLICT' });
        return turn; } },
    coordinator: { async run() {} }, provider: { async chat() {} }, authenticatePersona() {},
    personaAuthority: { capture(input) { return { binding: { ...input.scope, personaId: input.personaId,
      role: input.role, sessionId: input.sessionId, authorityVersion: input.authorityVersion },
      async assertRemoteAdmission() {} }; } },
    refundRepository: { async create() {}, async readRequest(target, input) {
      reads++; assert.equal(target.targetId, scope.targetId); assert.equal(input.personaSessionId, credential.sessionId);
      if (collisionAttempt) collisionObserved = true;
      return receipt;
    } },
    commerce: { async order() {} }, resolveTarget: async () => scope,
    resolveExistingTarget: async () => scope,
    buildBasePrompt: () => '', buildPolicyBlock: async () => '', checkToolAcl: async () => ({ allowed: true }),
  });
  assert.deepEqual(await runtime.readRequest(scope, persona, credential, sessionId, requestId),
    { requestId, status: 'saved', ticketId: '77', orderId: 12 });
  receipt = null;
  assert.deepEqual(await runtime.readRequest(scope, persona, credential, sessionId, requestId),
    { requestId, status: 'unconfirmed' });
  turn = { status: 'uncertain' };
  assert.deepEqual(await runtime.readRequest(scope, persona, credential, sessionId, requestId),
    { requestId, status: 'unconfirmed' });
  turn = { status: 'completed' }; receipt = { ticketId: '77', orderId: 12 }; collisionAttempt = true;
  await assert.rejects(runtime.readRequest(scope, persona, credential, sessionId, requestId),
    { code: 'TURN_REQUEST_CONFLICT' });
  collisionAttempt = false; collisionObserved = false;
  await assert.rejects(runtime.readRequest(scope, { id: 42, role: 'customer' }, credential, sessionId, requestId),
    { code: 'CONVERSATION_UNAVAILABLE' });
  stale = true;
  await assert.rejects(runtime.readRequest(scope, persona, credential, sessionId, requestId), { code: 'STALE_LAUNCH' });
  assert.equal(reads, 4);
});

test('refund repository readback verifies exact audit digest and ticket without writing', async () => {
  const receipts = require('../server/database/postgres/secureshopRefundOperationReceipt');
  const operationId = '94000000-0000-4000-8000-000000000011';
  const requestId = '95000000-0000-4000-8000-000000000011';
  const runId = '96000000-0000-4000-8000-000000000011';
  const personaSessionId = '97000000-0000-4000-8000-000000000011';
  const original = receipts.request(scope, { shopUserId: 41, orderId: 12, requestId, runId,
    reason: 'duplicate charge' }, { operationId, personaSessionId, authorityVersion: '3', toolInvocationId: '2:refund' });
  const receipt = { operationId, ...original.exact, applied: true, ticketId: '77' };
  const result = { ticket_id: '77', order_id: '12', ok: true, replayed: false, applied: true };
  let digest = original.digest, writes = 0, stale = false;
  const client = { release() {}, async query(sql, args = []) {
    if (/^(BEGIN|COMMIT|ROLLBACK)/.test(sql)) return { rows: [], rowCount: 0 };
    if (sql.startsWith('SELECT set_config')) return { rows: [], rowCount: 1 };
    if (sql.includes('FROM secureshop_review.product_targets')) return { rows: [{ lifecycle: 'active' }], rowCount: 1 };
    if (sql.includes('SELECT event_id FROM secureshop_review.bound_audit_events')) {
      assert.equal(args.at(-1), requestId); return { rows: [{ event_id: operationId }], rowCount: 1 };
    }
    if (sql.includes('SELECT * FROM secureshop_review.bound_audit_events')) return { rows: [{
      source_kind: 'refund_operation', launch_id: scope.launchId, scenario_id: scope.scenarioId,
      generation: scope.generation, original_platform_owner_id: scope.platformOwnerId,
      original_platform_session_id: scope.platformSessionId, shop_user_id: 41, shop_role: 'customer',
      params_json: JSON.stringify({ digest, receipt, result }),
    }], rowCount: 1 };
    if (sql.includes('FROM secureshop_review.product_target_refund_requests')) return { rows: [{ ticket_id: '77', order_id: '12' }], rowCount: 1 };
    writes++; throw new Error(`unexpected readback SQL: ${sql.slice(0, 80)}`);
  } };
  const repo = createSecureShopBoundRefundRepository({ query: (...args) => client.query(...args),
    async connect() { return client; } }, { checkCurrent: async () => { if (stale) throw Object.assign(new Error('stale'), { code: 'STALE_LAUNCH' }); } });
  const input = { requestId, shopUserId: 41, personaSessionId, authorityVersion: '3' };
  assert.deepEqual(await repo.readRequest(scope, input), { ticketId: '77', orderId: 12 });
  digest = '0'.repeat(64);
  await assert.rejects(repo.readRequest(scope, input), { code: 'REFUND_OPERATION_CONFLICT' });
  digest = original.digest;
  await assert.rejects(repo.readRequest(scope, { ...input, shopUserId: 42 }), { code: 'REFUND_OPERATION_CONFLICT' });
  stale = true;
  await assert.rejects(repo.readRequest(scope, input), { code: 'STALE_LAUNCH' });
  assert.equal(writes, 0);
});

test('refund turn lookup binds purpose, current execution and customer without a write', async () => {
  const { createTurnRequestsRepository } = require('../server/database/postgres/secureshopTurnRequestsRepository');
  const sessionId = '91000000-0000-4000-8000-000000000021';
  const requestId = '92000000-0000-4000-8000-000000000021';
  const expected = [requestId, 'secureshop_refund_request', scope.launchId,
    scope.scenarioId, scope.generation, scope.platformOwnerId, scope.platformSessionId, 41, 'customer'];
  let calls = 0, duplicated = false;
  const client = { release() {}, async query(sql, args) {
    calls++;
    assert.match(sql, /s\.conversation_purpose=\$2/);
    assert.match(sql, /s\.original_platform_session_id=\$7/);
    assert.match(sql, /s\.user_id=\$8 AND s\.role=\$9/);
    assert.match(sql, /LIMIT 2/);
    assert.deepEqual(args, expected);
    const row = { session_id: sessionId, status: 'completed', request_hash: 'hash', request_version: 1, result_json: {} };
    return { rows: duplicated ? [row, { ...row, session_id: 'other-conversation' }] : [row] };
  } };
  const repo = createTurnRequestsRepository({ pool: { async connect() { return client; } } });
  assert.equal((await repo.readBoundRequest({ sessionId, requestId,
    binding: { ...scope, shopUserId: 41, role: 'customer' }, purpose: 'secureshop_refund_request' })).status, 'completed');
  duplicated = true;
  await assert.rejects(repo.readBoundRequest({ sessionId, requestId,
    binding: { ...scope, shopUserId: 41, role: 'customer' }, purpose: 'secureshop_refund_request' }),
  { code: 'TURN_REQUEST_CONFLICT' });
  assert.equal(calls, 2);
});

 test('repository preserves bigint ticket IDs and rejects cancelled or malformed orders', async () => {
  const repo = createSecureShopBoundRefundRepository(fakePool({ ticketId: '9007199254740993' }), { checkCurrent: async () => {} });
  const result = await repo.create(scope, { shopUserId: 41, orderId: 12, ...ids(), reason: 'x' });
  assert.equal(result.ticket_id, '9007199254740993');
  await assert.rejects(() => createSecureShopBoundRefundRepository(fakePool({ orderStatus: 'cancelled' }), { checkCurrent: async () => {} }).create(scope, { shopUserId: 41, orderId: 12, ...ids(), reason: 'x' }), { code: 'REFUND_NOT_ELIGIBLE' });
  await assert.rejects(() => repo.create(scope, { shopUserId: 41, orderId: '12', ...ids(), reason: 'x' }), { code: 'INVALID_ARGUMENT' });
 });

test('production refund runtime creates purpose-bound session and executes the local refund effect', async () => {
  const sessions = new Map(); const messages = new Map(); const traces = []; let effectRequestId;
  const conversationRepository = {
    async getBoundSession(id) { return sessions.get(id) || null; },
    async acquireBoundSession({ id, binding, purpose }) { const row = { id, binding, purpose, state: 'pending' }; sessions.set(id, row); return row; },
    async activateBoundSession(id) { sessions.get(id).state = 'active'; return true; },
    async getMessages(id) { return messages.get(id) || []; }, async runExclusive(id, operation) { return operation(); },
    async appendMessage(id, _binding, message) { messages.set(id, [...(messages.get(id) || []), message]); },
    async getTokens() { return 0; }, async addTokens() {}, async appendTraces(_id, _binding, rows) { traces.push(...rows); },
  };
  const launches = { async assertCurrent() {} };
  const coordinator = { async run(_id, _opts, operation) { return operation({ runId: '90000000-0000-4000-8000-000000000001', ownerKey: 'refund-owner', generation: 1, durableGeneration: 1, signal: undefined, async check() {}, async effectWithReceipt(_key, fn) { return { value: await fn(), receipt: { status: 'completed', runId: '90000000-0000-4000-8000-000000000001' } }; }, async trace() {} }); } };
  const responses = [
    { stop_reason: 'tool_use', tool_uses: [{ id: 'refund-status-1', name: 'support.order_status', args: { order_id: 12 } }] },
    { stop_reason: 'tool_use', tool_uses: [{ id: 'refund-tool-1', name: 'support.refund_request', args: { order_id: 12, reason: 'duplicate charge' } }] },
    { stop_reason: 'end_turn', text: 'Refund ticket submitted.' },
  ];
  const runtime = createSecureShopBoundRefundRuntime({ launches, conversationRepository,
    journal: { async claim() { return { status: 'claimed', claimId: 'c' }; }, async complete() {}, async markUncertain() {} }, coordinator,
    provider: { async chat() { return responses.shift(); }, async finalResponse() { return responses.shift(); } }, authenticatePersona() {},
    refundRepository: { async create(_target, input) { effectRequestId = input.requestId; return { ticket_id: '9223372036854775807', order_id: '12', ok: true, replayed: false }; } },
    commerce: { async order() { return { order: { id: 12, payment_status: 'approved' } }; } }, resolveTarget: async value => value,
    buildBasePrompt: role => role === 'customer' ? 'support' : '', buildPolicyBlock: async () => '', checkToolAcl: async () => ({ allowed: true, action: 'dispatch' }) });
  const session = await runtime.createSession(scope, { id: 41, role: 'customer' }); const events = [];
  const result = await runtime.runner.run({ sessionId: session.id, requestId: '91000000-0000-4000-8000-000000000001', scope, persona: { id: 41, role: 'customer' }, message: 'Please refund order 12. Reason: duplicate charge', stream: { send(name, data) { events.push([name, data]); } }, localToolAuthority: { requestId: '91000000-0000-4000-8000-000000000002' } });
  assert.equal(result.stopReason, 'end_turn'); assert.match(result.text, /ticket submitted/); assert.ok(events.some(([name]) => name === 'tool_result')); assert.ok(traces.length > 0);
  assert.equal(effectRequestId, '91000000-0000-4000-8000-000000000001');
});

test('refund provider input contains the exact admitted customer policy snapshot', async () => {
  const sessions = new Map(); const messages = new Map(); const traces = []; const admissions = [];
  const conversationRepository = {
    async getBoundSession(id) { return sessions.get(id) || null; },
    async acquireBoundSession({ id, binding, purpose }) { const row = { id, binding, purpose, state: 'pending' }; sessions.set(id, row); return row; },
    async activateBoundSession(id) { sessions.get(id).state = 'active'; return true; },
    async getMessages(id) { return messages.get(id) || []; }, async runExclusive(_id, operation) { return operation(); },
    async appendMessage(id, _binding, message) { messages.set(id, [...(messages.get(id) || []), message]); },
    async getTokens() { return 0; }, async addTokens() {}, async appendTraces(_id, _binding, rows) { traces.push(...rows); },
  };
  const { buildPolicySnapshot } = require('../server/services/secureshopPromptPolicySnapshot');
  const { createHash } = require('node:crypto');
  const rendered = 'REFUND_CUSTOMER_BOUND_POLICY';
  const snapshot = buildPolicySnapshot({ policyVersion: '4', role: 'customer', policies: [{ name: 'owned', rendered, renderedSha256: createHash('sha256').update(rendered).digest('hex'), targets: ['customer'] }] });
  const credential = { sessionId: '93000000-0000-4000-8000-000000000031', authorityVersion: '7' };
  const personaAuthority = { capture(input) { return { binding: { ...input.scope, personaId: input.personaId, role: input.role, sessionId: input.sessionId, authorityVersion: input.authorityVersion }, async assertRemoteAdmission() {}, async withPersonaEffect(work) { return work({}); }, async withCrossStoreEffect(work) { return work(); } }; } };
  const launches = { async assertCurrent() {} };
  const coordinator = { async run(_id, _opts, operation) { return operation({ runId: '90000000-0000-4000-8000-000000000031', ownerKey: 'refund-owner', generation: 1, durableGeneration: 1, signal: undefined, async check() {}, async effectWithReceipt(_key, fn) { return { value: await fn(), receipt: { status: 'completed' } }; }, async trace() {} }); } };
  const responses = [
    { stop_reason: 'tool_use', tool_uses: [{ id: 'refund-status-1', name: 'support.order_status', args: { order_id: 12 } }] },
    { stop_reason: 'tool_use', tool_uses: [{ id: 'refund-tool-1', name: 'support.refund_request', args: { order_id: 12, reason: 'duplicate charge' } }] },
    { stop_reason: 'end_turn', text: 'Refund ticket submitted.' },
  ];
  const runtime = createSecureShopBoundRefundRuntime({ personaAuthority, launches, conversationRepository,
    promptPolicyRepository: { async admitRunSnapshot(input) { admissions.push(input); assert.equal(input.persona.role, 'customer'); assert.deepEqual(input.personaSession, credential); return snapshot; } },
    journal: { async claim() { return { status: 'claimed', claimId: 'c' }; }, async complete() {}, async markUncertain() {} }, coordinator,
    provider: { async chat(input) { assert.ok(input.system.includes(rendered)); return responses.shift(); }, async finalResponse(input) { assert.ok(input.system.includes(rendered)); return responses.shift(); } }, authenticatePersona() {},
    refundRepository: { async create() { return { ticket_id: '9223372036854775807', order_id: '12', ok: true, replayed: false }; } },
    commerce: { async order() { return { order: { id: 12, payment_status: 'approved' } }; } }, resolveTarget: async value => value,
    buildBasePrompt: role => role === 'customer' ? 'support' : '', buildPolicyBlock: async () => '', checkToolAcl: async () => ({ allowed: true, action: 'dispatch' }) });
  const session = await runtime.createSession(scope, { id: 41, role: 'customer' }, credential); const events = [];
  const result = await runtime.runner.run({ sessionId: session.id, personaSession: credential, requestId: '91000000-0000-4000-8000-000000000031', scope, persona: { id: 41, role: 'customer' }, message: 'Please refund order 12. Reason: duplicate charge', stream: { send(name, data) { events.push([name, data]); } }, localToolAuthority: { requestId: '91000000-0000-4000-8000-000000000032' } });
  assert.equal(result.stopReason, 'end_turn'); assert.equal(admissions.length, 1); assert.ok(events.some(([name]) => name === 'tool_result'));
  assert.ok(traces.some(row => row.kind === 'prompt_policy_snapshot' && row.result_json.includes('\"policyVersion\":\"4\"')));
});

test('candidate refund session admission and held execution recheck captured authority', async () => {
  let revoked=false,revokeDuringCreate=false,effects=0,malformedCapture=false,capturePatch=null,orderReads=0;
  const personaSession={sessionId:'70000000-0000-4000-8000-000000000001',authorityVersion:'1'};
  const check=async()=>{if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID',executionBoundary:true});};
  const sessions = new Map(); const messages = new Map(); const traces = [];
  const conversationRepository = {
    async getBoundSession(id) { return sessions.get(id) || null; },
    async acquireBoundSession({ id, binding, purpose }) { const row = { id, binding, purpose, state: 'pending' }; sessions.set(id, row); return row; },
    async activateBoundSession(id) { sessions.get(id).state = 'active'; if(revokeDuringCreate)revoked=true; return true; },
    async getMessages(id) { return messages.get(id) || []; }, async runExclusive(id, operation) { return operation(); },
    async appendMessage(id, _binding, message) { messages.set(id, [...(messages.get(id) || []), message]); },
    async getTokens() { return 0; }, async addTokens() {}, async appendTraces(_id, _binding, rows) { traces.push(...rows); },
  };
  const launches = { async assertCurrent() {} };
  const coordinator = { async run(_id, _opts, operation) { return operation({ runId: '90000000-0000-4000-8000-000000000001', ownerKey: 'refund-owner', generation: 1, durableGeneration: 1, signal: undefined, async check() {}, async effectWithReceipt(_key, fn) { return { value: await fn(), receipt: { status: 'completed', runId: '90000000-0000-4000-8000-000000000001' } }; }, async trace() {} }); } };
  const responses = [
    { stop_reason: 'tool_use', tool_uses: [{ id: 'refund-status-1', name: 'support.order_status', args: { order_id: 12 } }] },
    { stop_reason: 'tool_use', tool_uses: [{ id: 'refund-tool-1', name: 'support.refund_request', args: { order_id: 12, reason: 'duplicate charge' } }] },
    { stop_reason: 'end_turn', text: 'Refund ticket submitted.' },
  ];
  const runtime = createSecureShopBoundRefundRuntime({ personaAuthority:{capture:async({scope:s,personaId,role,sessionId,authorityVersion})=>{await Promise.resolve();if(malformedCapture)return null;return{binding:{...s,personaId,role,sessionId,authorityVersion,...capturePatch},assertRemoteAdmission:check,withPersonaEffect:async()=>{throw Error("No same-store tool expected");},withCrossStoreEffect:async work=>{await check();return work();}};}}, launches, conversationRepository,
    journal: { async claim() { return { status: 'claimed', claimId: 'c' }; }, async complete() {}, async markUncertain() {} }, coordinator,
    provider: { async chat() { if(responses.length===2)revoked=true;return responses.shift(); }, async finalResponse() { return responses.shift(); } }, authenticatePersona() {},
    refundRepository: { async create() { effects++;return { ticket_id: '9223372036854775807', order_id: '12', ok: true, replayed: false }; } },
    commerce: { async order(input) { orderReads++;assert.deepEqual(input.personaSession,personaSession);return { order: { id: 12, payment_status: 'approved' } }; } }, resolveTarget: async value => value,
    buildBasePrompt: role => role === 'customer' ? 'support' : '', buildPolicyBlock: async () => '', checkToolAcl: async () => ({ allowed: true, action: 'dispatch' }) });
  await assert.rejects(runtime.createSession(scope,{id:41,role:'customer'}),{code:'SHOP_AUTH_INVALID'});
  assert.equal(sessions.size,0);
  malformedCapture=true;
  await assert.rejects(runtime.createSession(scope,{id:41,role:'customer'},personaSession),{code:'SHOP_AUTH_INVALID'});
  malformedCapture=false;capturePatch={personaId:99};
  await assert.rejects(runtime.createSession(scope,{id:41,role:'customer'},personaSession),{code:'SHOP_AUTH_INVALID'});
  capturePatch=null;assert.equal(sessions.size,0);
  revoked=true;
  await assert.rejects(runtime.createSession(scope,{id:41,role:'customer'},personaSession),{code:'SHOP_AUTH_INVALID'});
  assert.equal(sessions.size,0);
  revoked=false;revokeDuringCreate=true;
  await assert.rejects(runtime.createSession(scope,{id:41,role:'customer'},personaSession),{code:'SHOP_AUTH_INVALID'});
  assert.equal(sessions.size,1); // durable but inert orphan; it was never returned as admitted
  sessions.clear();revoked=false;revokeDuringCreate=false;
  const mutableScope={...scope},mutablePersona={id:41,role:'customer'},mutable={...personaSession};
  const creating=runtime.createSession(mutableScope,mutablePersona,mutable);
  mutableScope.platformOwnerId=999;mutablePersona.id=99;mutablePersona.role='admin';mutable.authorityVersion='999';
  const session=await creating;const events=[];
  assert.equal(sessions.get(session.id).binding.platformOwnerId,scope.platformOwnerId);
  assert.equal(sessions.get(session.id).binding.shopUserId,41);
  assert.equal(sessions.get(session.id).binding.role,'customer');
  await assert.rejects(runtime.runner.run({ personaSession, sessionId: session.id, requestId: '91000000-0000-4000-8000-000000000001', scope, persona: { id: 41, role: 'customer' }, message: 'Please refund order 12. Reason: duplicate charge', stream: { send(name, data) { events.push([name, data]); } }, localToolAuthority: { requestId: '91000000-0000-4000-8000-000000000002' } }),{code:'SHOP_AUTH_INVALID'});
  assert.equal(effects,0);assert.equal(orderReads,1);
});

test('candidate refund factory rechecks captured authority after a held provider decision', { timeout: 5000 }, async () => {
  let revoked=false,effects=0,orderReads=0,reached,release;
  const held = new Promise(resolve => { reached=resolve; });
  const gate = new Promise(resolve => { release=resolve; });
  const personaSession={sessionId:'70000000-0000-4000-8000-000000000001',authorityVersion:'1'};
  const check=async()=>{if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID',executionBoundary:true});};
  const sessions = new Map(); const messages = new Map(); const traces = [];
  const conversationRepository = {
    async getBoundSession(id) { return sessions.get(id) || null; },
    async acquireBoundSession({ id, binding, purpose }) { const row = { id, binding, purpose, state: 'pending' }; sessions.set(id, row); return row; },
    async activateBoundSession(id) { sessions.get(id).state = 'active'; return true; },
    async getMessages(id) { return messages.get(id) || []; }, async runExclusive(id, operation) { return operation(); },
    async appendMessage(id, _binding, message) { messages.set(id, [...(messages.get(id) || []), message]); },
    async getTokens() { return 0; }, async addTokens() {}, async appendTraces(_id, _binding, rows) { traces.push(...rows); },
  };
  const launches = { async assertCurrent() {} };
  const coordinator = { async run(_id, _opts, operation) { return operation({ runId: '90000000-0000-4000-8000-000000000001', ownerKey: 'refund-owner', generation: 1, durableGeneration: 1, signal: undefined, async check() {}, async effectWithReceipt(_key, fn) { return { value: await fn(), receipt: { status: 'completed', runId: '90000000-0000-4000-8000-000000000001' } }; }, async trace() {} }); } };
  const responses = [
    { stop_reason: 'tool_use', tool_uses: [{ id: 'refund-status-1', name: 'support.order_status', args: { order_id: 12 } }] },
    { stop_reason: 'tool_use', tool_uses: [{ id: 'refund-tool-1', name: 'support.refund_request', args: { order_id: 12, reason: 'duplicate charge' } }] },
    { stop_reason: 'end_turn', text: 'Refund ticket submitted.' },
  ];
  const runtime = createSecureShopBoundRefundRuntime({ personaAuthority:{capture:({scope:s,personaId,role,sessionId,authorityVersion})=>({binding:{...s,personaId,role,sessionId,authorityVersion},assertRemoteAdmission:check,withPersonaEffect:async work=>{await check();return work();},withCrossStoreEffect:async work=>{await check();return work();}})}, launches, conversationRepository,
    journal: { async claim() { return { status: 'claimed', claimId: 'c' }; }, async complete() {}, async markUncertain() {} }, coordinator,
    provider: { async chat() { if(responses.length===2){reached();await gate;}return responses.shift(); }, async finalResponse() { return responses.shift(); } }, authenticatePersona() {},
    refundRepository: { async create() { effects++;return { ticket_id: '9223372036854775807', order_id: '12', ok: true, replayed: false }; } },
    commerce: { async order() { orderReads++;return { order: { id: 12, payment_status: 'approved' } }; } }, resolveTarget: async value => value,
    buildBasePrompt: role => role === 'customer' ? 'support' : '', buildPolicyBlock: async () => '', checkToolAcl: async () => ({ allowed: true, action: 'dispatch' }) });
  const session = await runtime.createSession(scope, { id: 41, role: 'customer' },personaSession); const events = [];
  const pending=runtime.runner.run({ personaSession, sessionId: session.id, requestId: '91000000-0000-4000-8000-000000000001', scope, persona: { id: 41, role: 'customer' }, message: 'Please refund order 12. Reason: duplicate charge', stream: { send(name, data) { events.push([name, data]); } }, localToolAuthority: { requestId: '91000000-0000-4000-8000-000000000002' } });
  const denied=assert.rejects(pending,{code:'SHOP_AUTH_INVALID'});
  await held;
  assert.equal(orderReads,1);assert.equal(effects,0);
  revoked=true;release();
  await denied;
  assert.equal(effects,0);
});
