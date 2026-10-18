'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  projectRecentWorkshopHistory,
  TRUNCATION_MARKER,
  MIN_HISTORY_CHARS,
} = require('../server/agent-runtime/workshopHistoryProjection');

test('recent history projection keeps newest roles and text without mutating stored rows', () => {
  const history = [
    { message_type: 'user', message: `old:${'x'.repeat(700)}` },
    { message_type: 'assistant', message: `middle:${'y'.repeat(700)}` },
    { message_type: 'user', message: 'newest fact is ORCHID-73' },
    { message_type: 'assistant', message: 'I will remember ORCHID-73' },
  ];
  const before = structuredClone(history);
  const projected = projectRecentWorkshopHistory(history, { maxChars: 320 });

  assert.ok(JSON.stringify(projected).length <= 320);
  assert.deepEqual(projected.map(row => row.message_type), ['user', 'assistant']);
  assert.match(projected[0].message, new RegExp(`^${TRUNCATION_MARKER.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
  assert.match(projected[0].message, /newest fact is ORCHID-73/);
  assert.equal(projected[1].message, 'I will remember ORCHID-73');
  assert.deepEqual(history, before);
  assert.notEqual(projected[0], history[2]);
});

test('an oversized newest message retains its recent suffix within the encoded character ceiling', () => {
  const latest = { message_type: 'user', message: `${'older detail 😀 '.repeat(200)}LATEST_FACT_END` };
  const history = [{ message_type: 'assistant', message: 'older turn' }, latest];
  const before = structuredClone(history);
  const projected = projectRecentWorkshopHistory(history, { maxChars: 180 });

  assert.equal(projected.length, 1);
  assert.equal(projected[0].message_type, 'user');
  assert.ok(projected[0].message.startsWith(`${TRUNCATION_MARKER}\n`));
  assert.ok(projected[0].message.endsWith('LATEST_FACT_END'));
  assert.ok(JSON.stringify(projected).length <= 180);
  assert.equal(/(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]|[\uD800-\uDBFF](?:$|[^\uDC00-\uDFFF])/.test(projected[0].message), false);
  assert.deepEqual(history, before);
});

test('the smallest supported budget is bounded and invalid roles fail closed', () => {
  const projected = projectRecentWorkshopHistory([
    { message_type: 'assistant', message: '😀'.repeat(200) },
  ], { maxChars: MIN_HISTORY_CHARS });
  assert.deepEqual(projected, [{ message_type: 'assistant', message: `${TRUNCATION_MARKER}\n` }]);
  assert.equal(JSON.stringify(projected).length, MIN_HISTORY_CHARS);
  assert.throws(() => projectRecentWorkshopHistory([
    { message_type: 'not-a-role'.repeat(1000), message: 'unsafe' },
  ]), /role must be user or assistant/);
});

test('message-count omissions are explicit even when the retained rows fit', () => {
  const history = Array.from({ length: 5 }, (_, index) => ({
    message_type: index % 2 ? 'assistant' : 'user',
    message: `turn-${index}`,
  }));
  const projected = projectRecentWorkshopHistory(history, { maxChars: 500, maxMessages: 2 });
  assert.deepEqual(projected.map(row => row.message_type), ['assistant', 'user']);
  assert.ok(projected[0].message.startsWith(`${TRUNCATION_MARKER}\nturn-3`));
  assert.equal(projected[1].message, 'turn-4');
});
