'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { main, revokePlatformSessions } = require('../scripts/admin/revoke-platform-sessions');

test('signing-key rotation cleanup revokes every active platform session with a fixed audit reason', async () => {
  const calls = [];
  let text = '';
  const count = await revokePlatformSessions({
    repository: { async revokeAllActiveSessions(reason) { calls.push(reason); return 7; } },
    output: { write(value) { text += value; } },
  });
  assert.equal(count, 7);
  assert.deepEqual(calls, ['signing_key_rotation']);
  assert.equal(text, 'Revoked 7 active platform session(s).\n');
});

test('session revocation command has a side-effect-free help path and rejects extra arguments', async () => {
  let text = '';
  assert.equal(await main({ args: ['--help'], output: { write(value) { text += value; } } }), 0);
  assert.match(text, /does not print, generate, or edit the key/);
  await assert.rejects(() => main({ args: ['unexpected'] }), { code: 'INVALID_ARGUMENT' });
});

test('session revocation fails closed when no repository contract is supplied', async () => {
  await assert.rejects(() => revokePlatformSessions({ repository: {} }), { code: 'INVALID_CONFIGURATION' });
});
