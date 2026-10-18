'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createPromptPolicyRunBinding } = require('../server/services/secureshopPromptPolicyRunBinding');
const sessionId = '81000000-0000-4000-8000-000000000001';
const input = { runId: '82000000-0000-4000-8000-000000000001', persona: { id: 91, role: 'customer' },
  scope: { launchId: '91000000-0000-4000-8000-000000000001', scenarioId: '91000000-0000-4000-8000-000000000002',
    generation: 3, platformOwnerId: 71, platformSessionId: 81 } };
const run = { owner_key: JSON.stringify(['SecureShopBoundConversation', sessionId]), generation: '9' };
function fixture({ before = [run], after = [run], conversations = [{ id: sessionId }] } = {}) {
  const observed = []; let reads = 0;
  const checker = createPromptPolicyRunBinding({ identityPool: { async query(sql, params) {
    assert.match(sql, /r.status='running'/); assert.match(sql, /r.generation=o.generation/);
    assert.deepEqual(params, [input.runId]); return { rows: reads++ ? after : before };
  } } });
  const client = { async query(sql, params) { observed.push(params); assert.match(sql, /binding_state='active'/); return { rows: conversations }; } };
  return { checker, client, observed };
}
test('binds live canonical run to all conversation ownership coordinates using supplied client', async () => {
  const f = fixture(); assert.equal(await f.checker(f.client, input), true);
  assert.deepEqual(f.observed, [[sessionId, input.scope.launchId, input.scope.scenarioId, 3, 71, 81, 91, 'customer']]);
});
for (const [name, options] of Object.entries({ missing: { before: [] }, foreignFamily: { before: [{ ...run, owner_key: JSON.stringify(['Other', sessionId]) }] },
  foreignConversation: { conversations: [] }, changedGeneration: { after: [{ ...run, generation: '10' }] },
  terminalDuringRead: { after: [] }, malformedOwner: { before: [{ ...run, owner_key: 'null' }] } })) {
  test(`rejects ${name} run admission`, async () => { const f = fixture(options);
    await assert.rejects(f.checker(f.client, input), { code: 'POLICY_RUN_AUTHORITY_UNAVAILABLE' });
  });
}
