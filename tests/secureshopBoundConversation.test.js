'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { createBoundConversationService } = require('../server/services/secureshopBoundConversation');
const scope = { launchId: '60000000-0000-4000-8000-000000000001', scenarioId: '60000000-0000-4000-8000-000000000002', generation: 1, platformOwnerId: 5, platformSessionId: 6 };
function fixture(failCheck = 0, activate = true, abandonFails = false) {
  const events = []; let checks = 0;
  const service = createBoundConversationService({ makeId: () => 'owned-conversation', launches: {
    async assertCurrent(binding) { events.push(['check', binding]); if (++checks === failCheck) throw Object.assign(new Error('revoked'), { code: 'STALE_LAUNCH' }); },
  }, conversations: {
    async acquireBoundSession(value) { events.push(['pending', value]); return { id: value.id, state: 'pending', created: true }; },
    async getBoundSession() { return null; },
    async activateBoundSession(id, binding) { events.push(['activate', id, binding]); return activate; },
    async abandonBoundSession(id, binding) { events.push(['abandon', id, binding]); if (abandonFails) throw new Error('cleanup unavailable'); },
  } });
  return { service, events };
}
test('bound creation returns only an ID after all three current-authority checks', async () => {
  const { service, events } = fixture();
  assert.deepEqual(await service.create(scope, { id: 1, role: 'customer' }), { id: 'owned-conversation' });
  assert.deepEqual(events.map(e => e[0]), ['check', 'pending', 'check', 'activate', 'check']);
  assert.equal(events[1][1].binding.shopUserId, 1);
  assert.equal(events[1][1].binding.platformOwnerId, 5);
  assert.ok(!Object.hasOwn(events[0][1], 'shopUserId'));
});

test('server-owned purpose participates in acquisition, activation, and ownership',async()=>{
  const purpose='mcp_rogue_registration',events=[];
  const {createConversationBinding}=require('../server/services/secureshopConversationBinding');
  const binding=createConversationBinding(scope,{id:1,role:'admin'});
  let stored;
  const service=createBoundConversationService({makeId:()=> 'purpose-session',launches:{async assertCurrent(){}},conversations:{
    async acquireBoundSession(value){events.push(['acquire',value.purpose]);stored={id:value.id,state:'pending',binding:value.binding,purpose:value.purpose};return{id:value.id,state:'pending'};},
    async activateBoundSession(id,_binding,valuePurpose){events.push(['activate',valuePurpose]);stored={...stored,id,state:'active'};return true;},
    async getBoundSession(){return stored;},async getMessages(_id,_binding,valuePurpose){events.push(['messages',valuePurpose]);return[];},
  }});
  const created=await service.create(scope,{id:1,role:'admin'},purpose);
  assert.deepEqual(created,{id:'purpose-session'});
  assert.deepEqual(await service.getMessages(created.id,scope,{id:1,role:'admin'},purpose),[]);
  assert.deepEqual(events,[['acquire',purpose],['activate',purpose],['messages',purpose]]);
  await assert.rejects(service.assertOwned(created.id,scope,{id:1,role:'admin'},'mcp_rug_pull'),{code:'CONVERSATION_UNAVAILABLE'});
  await assert.rejects(service.create(scope,{id:1,role:'admin'},'caller_selected'),/Invalid conversation purpose/);
});
for (const stage of [1, 2, 3]) test(`revocation at creation check ${stage} never returns a usable ID`, async () => {
  const { service, events } = fixture(stage, true, true);
  await assert.rejects(service.create(scope, { id: 1, role: 'customer' }), /revoked/);
  assert.equal(events.some(e => e[0] === 'abandon'), false);
  assert.equal(events.some(e => e[0] === 'activate'), stage === 3);
});
test('failed exact activation remains recoverable but never returns success', async () => {
  const { service, events } = fixture(0, false);
  await assert.rejects(service.create(scope, { id: 1, role: 'customer' }), { code: 'CONVERSATION_UNAVAILABLE' });
  assert.equal(events.some(e => e[0] === 'abandon'), false);
});

test('queued turn rechecks current authority before invoking any operation', async () => {
  const { createConversationBinding } = require('../server/services/secureshopConversationBinding');
  const binding = createConversationBinding(scope, { id: 1, role: 'customer' });
  let release, queued, revoked = false, effects = 0;
  const entered = new Promise(resolve => { queued = resolve; });
  const service = createBoundConversationService({ launches: { async assertCurrent() { if (revoked) throw new Error('revoked'); } }, conversations: {
    async getBoundSession(id) { return { id, state: 'active', binding }; },
    async runExclusive(_id, operation) { queued(); await new Promise(resolve => { release = resolve; }); return operation(); },
  } });
  const running = service.runExclusive('session', scope, { id: 1, role: 'customer' }, () => { effects++; });
  await entered; revoked = true; release();
  await assert.rejects(running, /revoked/); assert.equal(effects, 0);
});

test('inactive or mismatched conversations cannot authorize a bound operation', async () => {
  const { createConversationBinding } = require('../server/services/secureshopConversationBinding');
  const binding = createConversationBinding(scope, { id: 1, role: 'customer' });
  for (const stored of [null, { id: 'session', state: 'pending', binding }, { id: 'session', state: 'abandoned', binding }, { id: 'session', state: 'active', binding: { ...binding, generation: 2 } }, { id: 'other', state: 'active', binding }]) {
    let checks = 0, effects = 0;
    const service = createBoundConversationService({ launches: { async assertCurrent() { checks++; } }, conversations: {
      async getBoundSession() { return stored; }, async runExclusive(_id, operation) { return operation(); },
    } });
    await assert.rejects(service.runExclusive('session', scope, { id: 1, role: 'customer' }, () => { effects++; }), { code: 'CONVERSATION_UNAVAILABLE' });
    assert.equal(checks, 0); assert.equal(effects, 0);
  }
});

for (const method of ['getMessages', 'getTrace']) test(`${method} suppresses results when revocation is observed during the read`, async () => {
  const { createConversationBinding } = require('../server/services/secureshopConversationBinding');
  const persona = { id: 1, role: 'customer' };
  const binding = createConversationBinding(scope, persona);
  let revoked = false, reads = 0;
  const service = createBoundConversationService({ launches: { async assertCurrent() { if (revoked) throw new Error('revoked'); } }, conversations: {
    async getBoundSession(id) { return { id, state: 'active', binding }; },
    async [method](_id, expected) { assert.deepEqual(expected, binding); reads++; revoked = true; return ['private observation']; },
  } });
  await assert.rejects(service[method]('session', scope, persona), /revoked/);
  assert.equal(reads, 1);
});

test('latest traces use trusted full scope and recheck after the query', async () => {
  let checks = 0;
  const service = createBoundConversationService({ launches: { async assertCurrent() { if (++checks === 2) throw new Error('expired'); } }, conversations: {
    async latestTrace(binding, limit) { assert.equal(binding.platformOwnerId, 5); assert.equal(binding.shopUserId, 1); assert.equal(limit, 2); return ['private trace']; },
  } });
  await assert.rejects(service.latestTrace(scope, { id: 1, role: 'customer' }, 2), /expired/);
});

for (const failureCheck of [2, 3]) test(`temporary authority failure at check ${failureCheck} retries the same retained conversation`, async () => {
  let stored, checks = 0, acquisitions = 0, activations = 0;
  const service = createBoundConversationService({ launches: { async assertCurrent() {
    if (++checks === failureCheck) throw Object.assign(new Error('temporarily locked'), { code: 'STALE_LAUNCH' });
  } }, conversations: {
    async acquireBoundSession({ id, binding }) {
      acquisitions++;
      if (!stored) stored = { id, state: 'pending', binding };
      return { id: stored.id, state: stored.state };
    },
    async activateBoundSession() { activations++; stored.state = 'active'; return true; },
    async abandonBoundSession() { assert.fail('temporary failure must not abandon'); },
  } });
  await assert.rejects(service.create(scope, { id: 1, role: 'customer' }), /temporarily locked/);
  const original = stored.id;
  assert.deepEqual(await service.create(scope, { id: 1, role: 'customer' }), { id: original });
  assert.equal(acquisitions, 2); assert.equal(activations, 1);
});

test('a concurrent activation is accepted only after exact active-binding reread', async () => {
  const { createConversationBinding } = require('../server/services/secureshopConversationBinding');
  const binding = createConversationBinding(scope, { id: 1, role: 'customer' });
  const service = createBoundConversationService({ launches: { async assertCurrent() {} }, conversations: {
    async acquireBoundSession() { return { id: 'existing', state: 'pending' }; },
    async activateBoundSession() { return false; },
    async getBoundSession() { return { id: 'existing', state: 'active', binding }; },
  } });
  assert.deepEqual(await service.create(scope, { id: 1, role: 'customer' }), { id: 'existing' });
});
