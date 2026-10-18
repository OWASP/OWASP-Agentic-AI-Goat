'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { createTurnRequest } = require('../server/services/secureshopTurnRequest');
const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const binding = { launchId: id, scenarioId: id, generation: 1, platformOwnerId: 7, platformSessionId: 8, shopUserId: 1, role: 'customer' };
const request = overrides => createTurnRequest({ sessionId: id, requestId: id, binding, message: 'raw\n<script>payload</script>', ...overrides });
test('request digest binds exact payload and all ownership coordinates without storing either', () => {
  const base = request();
  for (const message of ['raw <script>payload</script>', 'raw\n<script>payload</script> ', 'raw\u0000<script>payload</script>']) assert.notEqual(request({ message }).hash, base.hash);
  for (const [key, value] of Object.entries({ platformOwnerId: 9, platformSessionId: 9, shopUserId: 9, generation: 2, role: 'admin', launchId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', scenarioId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' })) assert.notEqual(request({ binding: { ...binding, [key]: value } }).hash, base.hash);
  assert.deepEqual(Object.keys(base), ['sessionId', 'requestId', 'version', 'hash']);
  assert.equal(request({ sessionId: id.toUpperCase() }).hash, base.hash);
});
test('retry encoding retains version one and rejects unsupported historical versions', () => {
  assert.equal(request({ version: 1 }).hash, request().hash);
  assert.throws(() => request({ version: 2 }), { code: 'TURN_VERSION_UNAVAILABLE' });
  assert.throws(() => request({ requestId: 'not-a-uuid' }), { code: 'INVALID_TURN_REQUEST' });
});
