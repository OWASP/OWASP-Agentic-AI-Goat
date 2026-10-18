'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { prepareListingAdmission } = require('../server/services/secureshopListingJournalContract');
const { createListingExecutorBridge } = require('../server/services/secureshopListingExecutorBridge');
function fixture(state = 'running') {
  const admission = prepareListingAdmission({ scope: { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1, platformOwnerId: 1, platformSessionId: 2 },
    persona: { id: 12, role: 'merchant' }, personaSession: { sessionId: randomUUID(), authorityVersion: '1' }, targetId: randomUUID(), mode: 'vuln', catalogRevision: '0',
    request: { version: 1, action: 'import', operationId: randomUUID(), json_url: 'http://supplier.invalid/catalog', xml_url: null } });
  const calls = [], journal = { async get(raw) { calls.push('journal'); assert.deepEqual(raw.request, admission.request); return { state }; } };
  const client = { registerAdmission(value) { calls.push('register'); assert.equal(value.bindingSha256, admission.bindingSha256); return value.request.operationId; },
    async execute() { calls.push('POST'); return { status: 'completed' }; }, async get() { calls.push('GET'); return { status: 'completed' }; } };
  client.withAdmission=async(value,work)=>{const handle=client.registerAdmission(value);try{return await work(handle);}finally{calls.push('release');}};
  const input = { admission, checkCurrent: async () => { calls.push('authority'); } };
  return { admission, calls, journal, client, input, bridge: createListingExecutorBridge({ listingJournal: journal, client }) };
}
test('executor registration follows exact persisted admission validation', async () => {
  const f = fixture(); assert.equal(await f.bridge.execute(f.input), f.admission.request.operationId);
  assert.ok(f.calls.indexOf('journal') < f.calls.indexOf('register'));
  assert.equal(f.calls.filter(v => v === 'POST').length, 1);
});
test('unknown recovery performs GET only and never registers a rejected admission', async () => {
  const f = fixture('unknown');
  await assert.rejects(f.bridge.execute(f.input), { code: 'LISTING_EXECUTOR_RECOVERY_REQUIRED' });
  assert.ok(!f.calls.includes('register'));
  assert.deepEqual(await f.bridge.recover(f.input), { state: 'completed', receiptHandle: f.admission.request.operationId });
  assert.ok(!f.calls.includes('POST'));
  const denied = fixture(); denied.journal.get = async () => { throw Error('wrong original session'); };
  await assert.rejects(denied.bridge.execute(denied.input), /wrong original session/);
  assert.ok(!denied.calls.includes('register'));
});
test('late revocation prevents receipt release and lost response never becomes retry permission', async () => {
  const f = fixture(); let revoked = false;
  f.input.checkCurrent = async () => { if (revoked) throw Error('revoked'); };
  f.client.execute = async () => { revoked = true; return { status: 'completed' }; };
  await assert.rejects(f.bridge.execute(f.input), /revoked/);
  const lost = fixture(); lost.client.execute = async () => { throw Error('lost response'); };
  await assert.rejects(lost.bridge.execute(lost.input), error => error.code === 'LISTING_OUTCOME_UNCERTAIN' && error.automaticRetry === false);
});
test('terminal operation recovery does not contact executor', async () => {
  for (const state of ['declined', 'failed', 'completed']) {
    const f = fixture(state); assert.deepEqual(await f.bridge.recover(f.input), { state });
    assert.ok(!f.calls.includes('register'));
  }
});
