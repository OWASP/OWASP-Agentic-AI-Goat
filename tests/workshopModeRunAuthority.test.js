'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createWorkshopModeRunAuthority } = require('../server/services/workshopModeRunAuthority');

test('a run captures its canonical owner mode and rejects a changed stamp or generation', async () => {
  let scope = { generation: 4, mode: null, modeStamp: 'default' };
  const authority = createWorkshopModeRunAuthority({ workshopKey: 'mcp_workshop',
    readScope: async (owner, key) => {
      assert.equal(owner, 7); assert.equal(key, 'mcp_workshop'); return { ...scope };
    } });
  const execution = { check: async () => {} };
  const captured = await authority.capture(7, execution);
  assert.equal(captured.mode, 'vuln');
  await captured.check();
  scope = { ...scope, mode: 'fixed', modeStamp: 'next' };
  await assert.rejects(captured.check(), { code: 'WORKSHOP_MODE_CHANGED' });
  const fixed = await authority.capture(7, execution);
  assert.equal(fixed.mode, 'fixed');
  scope = { ...scope, generation: 5 };
  await assert.rejects(fixed.check(), { code: 'WORKSHOP_MODE_CHANGED' });
});

test('invalid canonical mode never becomes vulnerable fallback', async () => {
  const authority = createWorkshopModeRunAuthority({ workshopKey: 'mcp_workshop',
    readScope: async () => ({ generation: 0, mode: 'unexpected', modeStamp: 'x' }) });
  await assert.rejects(authority.capture(1, { check: async () => {} }),
    { code: 'WORKSHOP_MODE_SCOPE_UNAVAILABLE' });
});
