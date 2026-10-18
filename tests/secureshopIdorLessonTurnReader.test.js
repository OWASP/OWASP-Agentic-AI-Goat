'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopIdorLessonTurnReader } =
  require('../server/database/postgres/secureshopIdorLessonTurnReader');

const id = n => `${String(n).padStart(8, '0')}-1111-4111-8111-111111111111`;
const binding = { launchId: id(1), scenarioId: id(2), generation: 3,
  platformOwnerId: 4, platformSessionId: 5, shopUserId: 1000000001,
  role: 'customer' };
const sessionId = id(6), requestId = id(7), hash = 'a'.repeat(64);
const row = { session_id: sessionId, request_id: requestId,
  status: 'completed', request_hash: hash, request_version: 1,
  result_json: { stopReason: 'end_turn', text: 'Saved answer' } };

function fixture(initial = []) {
  const queries = []; let rows = initial, released = 0;
  const pool = { async connect() { return { async query(sql, args) {
    queries.push({ sql, args }); return { rows };
  }, release() { released++; } }; } };
  return { reader: createSecureShopIdorLessonTurnReader({ pool }), queries,
    setRows(value) { rows = value; }, get released() { return released; } };
}

test('original lesson read is SELECT-only and exact-purpose active full binding', async () => {
  const f = fixture([row]);
  const found = await f.reader.readIdorLessonRequest({ sessionId, requestId,
    binding, purpose: 'secureshop_idor_lesson' });
  assert.deepEqual(found, row);
  assert.equal(f.released, 1);
  const { sql, args } = f.queries[0];
  assert.deepEqual(args, [requestId, 'secureshop_idor_lesson', binding.launchId,
    binding.scenarioId, binding.generation, binding.platformOwnerId,
    binding.platformSessionId, binding.shopUserId, 'customer']);
  for (const term of ["s.authority_mode='launch_bound'",
    "s.binding_state='active'", 's.platform_launch_id=$3',
    's.platform_scenario_id=$4', 's.platform_launch_generation=$5',
    's.original_platform_owner_id=$6', 's.original_platform_session_id=$7',
    's.user_id=$8', 's.role=$9', 's.conversation_purpose=$2'])
    assert.ok(sql.includes(term), term);
  assert.doesNotMatch(sql, /INSERT|UPDATE|DELETE|FOR UPDATE|FOR SHARE/i);
});

test('foreign conversation, ambiguous ID, stale version and malformed result fail closed', async () => {
  const f = fixture([]);
  const original = () => f.reader.readIdorLessonRequest({ sessionId, requestId,
    binding, purpose: 'secureshop_idor_lesson' });
  assert.equal(await original(), null);
  f.setRows([{ ...row, session_id: id(8) }]);
  await assert.rejects(original(), { code: 'TURN_REQUEST_CONFLICT' });
  f.setRows([row, { ...row, session_id: id(8) }]);
  await assert.rejects(original(), { code: 'TURN_REQUEST_CONFLICT' });
  f.setRows([{ ...row, request_version: 2 }]);
  await assert.rejects(original(), { code: 'TURN_REQUEST_CONFLICT' });
  f.setRows([{ ...row, result_json: 'private text' }]);
  await assert.rejects(original(), { code: 'TURN_REQUEST_CONFLICT' });
  f.setRows([{ ...row, status: 'uncertain', result_json: null }]);
  assert.equal((await original()).status, 'uncertain');
  assert.equal(f.released, 6);
});

test('assessment lookup is separate persona_inbox purpose and rejects caller-selected purpose', async () => {
  const f = fixture([row]);
  assert.equal((await f.reader.readIdorLessonAssessment({ requestId, binding })).status,
    'completed');
  assert.equal(f.queries[0].args[1], 'persona_inbox');
  assert.throws(() => f.reader.readIdorLessonRequest({ sessionId, requestId,
    binding, purpose: 'secureshop_customer_chat' }), { code: 'INVALID_ARGUMENT' });
  await assert.rejects(f.reader.readIdorLessonRequest({ sessionId, requestId,
    binding: { ...binding, role: 'merchant' }, purpose: 'secureshop_idor_lesson' }),
  { code: 'INVALID_ARGUMENT' });
  assert.equal(f.queries.length, 1);
});
