'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createConfigSnapshotHandler } = require('../index');

test('config snapshot endpoint cannot accept caller-selected files, commands or extra authority', async () => {
  let reads = 0;
  const handler = createConfigSnapshotHandler(async () => { reads++; return {}; });
  const valid = { sessionId: 'mcp_7', invocationId: randomUUID() };
  for (const body of [null, [], {}, { ...valid, path: '/host/private' },
    { ...valid, command: 'cat /host/private' }, { ...valid, owner: 8 },
    { ...valid, sessionId: 'mcp_07' }, { ...valid, sessionId: 'mcp_2147483648' },
    { ...valid, invocationId: 'not-a-uuid' }]) {
    assert.equal((await handler(body)).status, 400);
  }
  assert.equal(reads, 0);
});

test('snapshot endpoint echoes invocation identity and redacts read failures', async () => {
  const request = { sessionId: 'mcp_7', invocationId: randomUUID() };
  const payload = { output: 'owned fixture', observation: { version: 'fixture' } };
  const response = await createConfigSnapshotHandler(async () => payload)(request);
  assert.equal(response.status, 200);
  assert.deepEqual(response.body, { ok: true, invocationId: request.invocationId, ...payload });
  const failed = await createConfigSnapshotHandler(async () => { throw Error('/private/path confidential'); })(request);
  assert.equal(failed.status, 503);
  assert.deepEqual(failed.body, { ok: false, error: 'CONFIG_SNAPSHOT_UNAVAILABLE' });
});
