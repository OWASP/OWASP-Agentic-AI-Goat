'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createCodeBotRequestJournal, requestFingerprint } = require('../server/agent-runtime/codeBotRequestJournal');

const key = 'a'.repeat(64), fingerprint = requestFingerprint({ userMessage: 'hello', conversationHistory: [] });
const claim = (overrides = {}) => ({ ownerKey: '["CodeBot","7"]', requestKey: key, fingerprint,
  userId: 7, platformSessionId: 11, generation: '4', runId: '10000000-0000-4000-8000-000000000001', ...overrides });

function poolFixture() {
  const rows = new Map();let admission = true;
  return { rows, setAdmission(value) { admission = value; }, async query(sql, args = []) {
    if (/SELECT relation_ready/.test(sql)) return { rows: [{ relation_ready: true, can_select: true,
      can_insert: true, can_update_status: true, can_update_response: true }] };
    const id = `${args[0]}:${args[1]}`;
    if (/INSERT INTO graph_runtime\.codebot_requests/.test(sql)) {
      if (!admission || rows.has(id)) return { rowCount: 0, rows: [] };
      rows.set(id, { fingerprint: args[2], userId: args[3], platformSessionId: args[4], generation: String(args[5]),
        runId: args[6], status: 'started', response: null });
      return { rowCount: 1, rows: [{ run_id: args[6] }] };
    }
    if (/SELECT request_fingerprint_sha256/.test(sql)) return { rows: rows.has(id) ? [{ ...rows.get(id) }] : [] };
    if (/SET status='completed'/.test(sql)) {
      const row = rows.get(id);if (!row || row.status !== 'started') return { rowCount: 0 };
      row.status = 'completed';row.response = JSON.parse(args[7]);return { rowCount: 1 };
    }
    if (/SET status='uncertain'/.test(sql)) { const row = rows.get(id);if (row?.status === 'started') row.status = 'uncertain';return { rowCount: row ? 1 : 0 }; }
    throw new Error(`Unexpected SQL: ${sql}`);
  } };
}

test('CodeBot request fingerprint is typed, deterministic and bounded', () => {
  assert.equal(requestFingerprint({ b: 2, a: [1, null] }), requestFingerprint({ a: [1, null], b: 2 }));
  assert.notEqual(requestFingerprint({ value: null }), requestFingerprint({}));
  assert.notEqual(requestFingerprint({ value: '1' }), requestFingerprint({ value: 1 }));
  assert.throws(() => requestFingerprint({ value: 'x'.repeat(140000) }), { code: 'CODEBOT_REQUEST_TOO_LARGE' });
});

test('same request replays only its committed bounded response', async () => {
  const pool = poolFixture(), journal = createCodeBotRequestJournal(pool), value = claim();
  assert.equal(await journal.replay(value), null, 'lookup does not create a request');
  assert.equal(pool.rows.size, 0);
  await journal.assertReady();assert.deepEqual(await journal.claim(value), { replayed: false });
  const response = { success: true, newlyCompletedObjectives: ['rce_cmd'] };
  await journal.complete(value, response);
  assert.deepEqual(await journal.replay(value), { replayed: true, response });
  assert.deepEqual(await journal.claim(value), { replayed: true, response });
  response.success = false;
  assert.equal((await journal.replay(value)).response.success, true,'stored replay is isolated from caller mutation');
});

test('changed body, session, generation and incomplete attempts never replay', async () => {
  const pool = poolFixture(), journal = createCodeBotRequestJournal(pool), value = claim();await journal.claim(value);
  await assert.rejects(journal.replay(claim({ fingerprint: 'b'.repeat(64) })), { code: 'CODEBOT_REQUEST_FINGERPRINT_CONFLICT' });
  await assert.rejects(journal.claim(claim({ fingerprint: 'b'.repeat(64) })), { code: 'CODEBOT_REQUEST_FINGERPRINT_CONFLICT' });
  await assert.rejects(journal.claim(claim({ platformSessionId: 12 })), { code: 'CODEBOT_REQUEST_SESSION_CONFLICT' });
  await assert.rejects(journal.claim(claim({ generation: '5' })), { code: 'CODEBOT_REQUEST_GENERATION_CONFLICT' });
  await assert.rejects(journal.claim(value), { code: 'CODEBOT_REQUEST_INCOMPLETE' });
  await journal.markUncertain(value);await assert.rejects(journal.claim(value), { code: 'CODEBOT_REQUEST_INCOMPLETE' });
});

test('failed admission and unavailable readiness remain explicit', async () => {
  const pool = poolFixture();pool.setAdmission(false);const journal = createCodeBotRequestJournal(pool);
  await assert.rejects(journal.claim(claim()), { code: 'CODEBOT_REQUEST_ADMISSION_REJECTED' });
  const unavailable = createCodeBotRequestJournal({ query: async () => ({ rows: [{ relation_ready: false }] }) });
  await assert.rejects(unavailable.assertReady(), { code: 'CODEBOT_REQUEST_JOURNAL_UNAVAILABLE' });
  await assert.rejects(journal.complete(claim(), { output: 'x'.repeat(300000) }), { code: 'CODEBOT_RESPONSE_INVALID' });
});
