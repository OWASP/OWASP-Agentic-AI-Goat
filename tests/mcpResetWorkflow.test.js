'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { resetMcpWorkshop } = require('../server/services/mcp/resetWorkflow');
test('reset attempts remaining stores after failure and never exposes backend errors', async () => {
  const calls = [];
  const result = await resetMcpWorkshop({
    progress: async () => { calls.push('progress'); throw Error('private connection'); },
    sandbox: async () => { calls.push('sandbox'); return { ok: false }; },
    canonical: async () => { calls.push('canonical'); },
  });
  assert.deepEqual(calls, ['progress', 'sandbox', 'canonical']);
  assert.equal(result.success, false);
  assert.deepEqual(result.failedSteps, ['progress', 'sandbox']);
  assert.ok(!JSON.stringify(result).includes('private'));
});
test('reset reports success only after every cleanup settles', async () => {
  let complete;
  const pending = new Promise(resolve => { complete = resolve; });
  let settled = false;
  const operation = resetMcpWorkshop({ progress: async () => {}, sandbox: () => pending, canonical: async () => {} });
  operation.then(() => { settled = true; });
  await Promise.resolve();
  assert.equal(settled, false);
  complete({ ok: true });
  assert.deepEqual(await operation, { success: true });
});
