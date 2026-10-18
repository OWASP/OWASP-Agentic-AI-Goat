'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createCouponAgentAssessmentReader } =
  require('../server/database/postgres/secureshopCouponAgentAssessmentReader');

function fixture() {
  const binding = { launchId: randomUUID(), scenarioId: randomUUID(),
    generation: 2, platformOwnerId: 5, platformSessionId: 7,
    shopUserId: 1000000001, role: 'customer' };
  const requestId = randomUUID(), sessionId = randomUUID(), queries = [];
  let rows = [];
  const pool = { async connect() { return { async query(sql, values) {
    queries.push({ sql, values });
    return { rows };
  }, release() {} }; } };
  const reader = createCouponAgentAssessmentReader({ pool });
  return { binding, requestId, sessionId, queries, reader,
    setRows(value) { rows = value; } };
}

test('assessment reader selects only the active original customer persona inbox turn', async () => {
  const f = fixture();
  const row = { session_id: f.sessionId, request_id: f.requestId,
    status: 'completed', request_hash: 'a'.repeat(64), request_version: 1,
    result_json: { completed: false, judgment: { verdict: 'unavailable' } } };
  f.setRows([row]);
  assert.deepEqual(await f.reader.readCouponAgentAssessment({
    requestId: f.requestId, binding: f.binding }), row);
  assert.equal(f.queries.length, 1);
  const { sql, values } = f.queries[0];
  assert.match(sql, /^SELECT /);
  assert.match(sql, /conversation_purpose='persona_inbox'/);
  assert.match(sql, /authority_mode='launch_bound'/);
  assert.match(sql, /binding_state='active'/);
  assert.match(sql, /platform_launch_generation=\$4/);
  assert.match(sql, /original_platform_owner_id=\$5/);
  assert.match(sql, /original_platform_session_id=\$6/);
  assert.match(sql, /s\.user_id=\$7/);
  assert.match(sql, /s\.role='customer'/);
  assert.deepEqual(values, [f.requestId, f.binding.launchId,
    f.binding.scenarioId, f.binding.generation,
    f.binding.platformOwnerId, f.binding.platformSessionId,
    f.binding.shopUserId]);
});

test('assessment reader rejects ambiguous or malformed saved rows and never mutates', async () => {
  const f = fixture();
  assert.equal(await f.reader.readCouponAgentAssessment({
    requestId: f.requestId, binding: f.binding }), null);
  const row = { session_id: f.sessionId, request_id: f.requestId,
    status: 'completed', request_hash: 'a'.repeat(64), request_version: 1,
    result_json: { completed: false } };
  f.setRows([row, row]);
  await assert.rejects(f.reader.readCouponAgentAssessment({
    requestId: f.requestId, binding: f.binding }),
  { code: 'COUPON_AGENT_ASSESSMENT_UNAVAILABLE' });
  f.setRows([{ ...row, request_hash: 'bad' }]);
  await assert.rejects(f.reader.readCouponAgentAssessment({
    requestId: f.requestId, binding: f.binding }),
  { code: 'COUPON_AGENT_ASSESSMENT_UNAVAILABLE' });
  assert.ok(f.queries.every(entry => entry.sql.startsWith('SELECT ')));
});
