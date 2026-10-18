'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { createTurnAdmission } = require('../server/services/secureshopTurnAdmission');
const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const binding = { launchId: id, scenarioId: id, generation: 1, platformOwnerId: 7, platformSessionId: 8, shopUserId: 1, role: 'customer' };
function fixture() {
  let row, rejectPublication = false;
  const journal = {
    async claim() { if (row) return structuredClone(row); row = { status: 'started', claimId: id }; return { ...row, status: 'claimed' }; },
    async complete({ result }) { row = { ...row, status: 'completed', result: structuredClone(result) }; },
    async markUncertain() { if (row.status === 'started') row.status = 'uncertain'; },
  };
  const service = createTurnAdmission({ journal });
  const input = { sessionId: id, requestId: id, binding, message: 'raw message', boundary: {
    async check() { if (rejectPublication && row?.status === 'completed') throw new Error('authority lost'); },
  } };
  return { run: operation => service.run(input, operation), losePublication() { rejectPublication = true; }, restore() { rejectPublication = false; } };
}
test('lost publication recovers the completed DTO without another graph operation', async () => {
  const f = fixture(); let effects = 0; f.losePublication();
  await assert.rejects(f.run(async () => { effects++; return { text: '<script>raw result</script>' }; }), /authority lost/);
  f.restore();
  assert.deepEqual(await f.run(() => { effects++; }), { replayed: true, result: { text: '<script>raw result</script>' } });
  assert.equal(effects, 1);
});
test('failure after an effect is uncertain and cannot automatically execute again', async () => {
  const f = fixture(); let effects = 0;
  await assert.rejects(f.run(async () => { effects++; throw new Error('lost result'); }), /lost result/);
  await assert.rejects(f.run(() => { effects++; }), { code: 'TURN_RECOVERY_REQUIRED' });
  assert.equal(effects, 1);
});
test('a prior unfinished claim is marked uncertain and never invokes the graph', async () => {
  let marked = 0;
  const service = createTurnAdmission({ journal: { async claim() { return { status: 'started', claimId: id }; }, async complete() { assert.fail(); }, async markUncertain() { marked++; } } });
  await assert.rejects(service.run({ sessionId: id, requestId: id, binding, message: 'raw', boundary: { async check() {} } }, () => assert.fail()), { code: 'TURN_RECOVERY_REQUIRED' });
  assert.equal(marked, 1);
});
test('an admitted claim can be abandoned when durable run creation fails', async () => {
  let state = 'missing', marked = 0;
  const service = createTurnAdmission({ journal: {
    async claim() { if (state === 'missing') { state = 'started'; return { status: 'claimed', claimId: id }; } return { status: state, claimId: id }; },
    async complete() { assert.fail('no operation ran'); },
    async markUncertain() { state = 'uncertain'; marked++; },
  } });
  const prepared = await service.prepare({ sessionId: id, requestId: id, binding, message: 'raw' });
  await service.abandon(prepared);
  await service.abandon(prepared);
  assert.equal(marked, 1);
  await assert.rejects(service.run({ sessionId: id, requestId: id, binding, message: 'raw', boundary: { async check() {} } }, () => assert.fail()), { code: 'TURN_RECOVERY_REQUIRED' });
});
test('compatibility run abandons a claim when authority is lost after prepare', async () => {
  let checks = 0, state = 'missing', marked = 0;
  const service = createTurnAdmission({ journal: {
    async claim() { state = 'started'; return { status: 'claimed', claimId: id }; },
    async complete() { assert.fail('no operation ran'); },
    async markUncertain() { state = 'uncertain'; marked++; },
  } });
  await assert.rejects(service.run({ sessionId: id, requestId: id, binding, message: 'raw', boundary: {
    async check() { if (++checks === 2) throw new Error('authority lost after claim'); },
  } }, () => assert.fail('no operation ran')), /authority lost/);
  assert.equal(state, 'uncertain'); assert.equal(marked, 1);
});
