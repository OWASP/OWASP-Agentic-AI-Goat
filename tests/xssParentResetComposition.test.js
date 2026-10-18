'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createXssParentResetComposition } = require('../server/services/xssParentResetComposition');

function fixture({ returnedOperationId } = {}) {
  const operations = [];
  const identityPool = { query:async (sql, params) => {
    assert.match(sql, /identity.begin_xss_parent_reset/);
    operations.push(params[0]);
    return { rowCount:1, rows:[{ operationId:returnedOperationId || params[0], ownerId:params[1], ownerKey:'["XSS","17"]',
      workshopGenerationFrom:'1', workshopGenerationTo:'2', graphGeneration:'2', status:'completed' }] };
  } };
  const unexpected = () => { throw new Error('Completed replay must not perform another effect'); };
  const composition = createXssParentResetComposition({ identityPool,
    store:{ assertReady:async () => true, retireOrRead:unexpected, clearParent:unexpected },
    runs:{ reset:unexpected },
  });
  return { composition, operations, lifecycle:{ ownerId:17, check:async () => {} } };
}

test('administrative composition generates operation IDs and normalizes supplied UUID replay', async () => {
  const { composition, operations, lifecycle } = fixture();
  const supplied = 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA';
  const replay = await composition.reset({ ownerId:17, operationId:supplied, lifecycle });
  assert.equal(replay.operationId, supplied.toLowerCase());
  const first = await composition.reset({ ownerId:17, lifecycle });
  const second = await composition.reset({ ownerId:17, lifecycle });
  assert.match(first.operationId, /^[0-9a-f-]{36}$/);
  assert.notEqual(first.operationId, second.operationId);
  assert.equal(operations.length, 5);
});

test('headerless retry adopts the server-owned existing operation', async () => {
  const operationId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const { composition, operations, lifecycle } = fixture({ returnedOperationId:operationId });
  const result = await composition.reset({ ownerId:17, lifecycle });
  assert.equal(result.operationId, operationId);
  assert.notEqual(operations[0], operationId);
  assert.equal(operations[1], operationId);
});

test('malformed operation IDs fail before journal or graph admission', async () => {
  const { composition, operations, lifecycle } = fixture();
  for (const operationId of ['', null, 1, 'not-a-uuid']) {
    await assert.rejects(composition.reset({ ownerId:17, operationId, lifecycle }), { code:'BAD_REQUEST', statusCode:400 });
  }
  assert.deepEqual(operations, []);
});

test('unavailable schema is reported as retryable storage failure', async () => {
  const composition = createXssParentResetComposition({
    identityPool:{ query:async () => { throw Object.assign(new Error('missing function'), { code:'42883' }); } },
    store:{ assertReady:async () => true, retireOrRead:async () => {}, clearParent:async () => {} },
    runs:{ reset:async () => {} },
  });
  await assert.rejects(composition.assertReady(), { code:'XSS_PARENT_RESET_STORAGE_NOT_READY', statusCode:503 });
});
