'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createTicketBrowserAssessmentReader } = require('../server/database/postgres/secureshopTicketBrowserAssessmentReader');

const E = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const requestId = E(1), sessionId = E(2);
const binding = { launchId: E(3), scenarioId: E(4), generation: 2,
  platformOwnerId: 8, platformSessionId: 9, shopUserId: 10, role: 'admin' };
function fixture(rows) {
  const calls = [];
  const reader = createTicketBrowserAssessmentReader({ pool: {
    connect: async () => ({ query: async (sql, values) => {
      calls.push({ sql, values }); return { rows };
    }, release() {} }),
  } });
  return { reader, calls };
}
const row = { session_id: sessionId, request_id: requestId,
  status: 'completed', request_hash: 'a'.repeat(64), request_version: 1,
  result_json: { completed: false, judgment: { verdict: 'fail' } } };

test('ticket assessment reader is exact admin persona_inbox SELECT-only', async () => {
  const f = fixture([row]);
  assert.deepEqual(await f.reader.readTicketBrowserAssessment({ requestId, binding }), row);
  assert.equal(f.calls.length, 1);
  assert.match(f.calls[0].sql, /s\.conversation_purpose='persona_inbox'/);
  assert.match(f.calls[0].sql, /s\.role='admin'/);
  assert.match(f.calls[0].sql, /s\.binding_state='active'/);
  assert.doesNotMatch(f.calls[0].sql, /\b(?:INSERT|UPDATE|DELETE)\b/i);
  assert.deepEqual(f.calls[0].values, [requestId, binding.launchId,
    binding.scenarioId, binding.generation, binding.platformOwnerId,
    binding.platformSessionId, binding.shopUserId]);
});

test('reader rejects foreign role, duplicate owner, stale or malformed rows', async () => {
  await assert.rejects(fixture([row]).reader.readTicketBrowserAssessment({ requestId,
    binding: { ...binding, role: 'customer' } }),
  { code: 'TICKET_BROWSER_ASSESSMENT_UNAVAILABLE' });
  for (const rows of [[row,row], [{ ...row, request_hash: 'bad' }],
    [{ ...row, request_version: 2 }],
    [{ ...row, status: 'completed', result_json: null }],
    [{ ...row, session_id: E(5), request_id: E(9) }]]) {
    await assert.rejects(fixture(rows).reader.readTicketBrowserAssessment({
      requestId, binding }), { code: 'TICKET_BROWSER_ASSESSMENT_UNAVAILABLE' });
  }
  assert.equal(await fixture([]).reader.readTicketBrowserAssessment({ requestId,
    binding }), null);
});
