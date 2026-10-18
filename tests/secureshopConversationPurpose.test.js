'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { SECURESHOP_CONVERSATION_PURPOSES: PURPOSES, normalizeConversationPurpose } =
  require('../server/services/secureshopConversationPurpose');

test('mail summary is a distinct server-owned purpose and normalizes exactly', () => {
  assert.equal(PURPOSES.mailSummary, 'secureshop_mail_summary');
  assert.equal(normalizeConversationPurpose(PURPOSES.mailSummary), 'secureshop_mail_summary');
  assert.notEqual(PURPOSES.mailSummary, PURPOSES.mailReply);
});

test('purpose normalization rejects malformed or unsupported values', () => {
  for (const value of ['mail_summary', 'secureshop_mail_summary ', 'caller_selected',
    'secureshop_mail_reply\0', null, 42]) {
    assert.throws(() => normalizeConversationPurpose(value), /Invalid conversation purpose/);
  }
});

test('forward migration admits summary without broadening authority or changing reply lifecycle', () => {
  const sql = fs.readFileSync(require('node:path').join(__dirname,
    '../db/postgres/workshop-migrations/secureshop_agents/0091_mail_summary_conversation_purpose.sql'), 'utf8');
  assert.match(sql, /'secureshop_mail_reply',\s*'secureshop_mail_summary',\s*'secureshop_inventory'/);
  assert.match(sql, /authority_mode='launch_bound' OR conversation_purpose='general'/);
  assert.doesNotMatch(sql, /bound_lab_mail|mail_scene_target_current|mail_uncertain/);
});

test('coupon probe is a distinct customer-only server-owned purpose', () => {
  assert.equal(PURPOSES.couponProbe, 'secureshop_coupon_probe');
  assert.equal(normalizeConversationPurpose(PURPOSES.couponProbe), PURPOSES.couponProbe);
  assert.notEqual(PURPOSES.couponProbe, PURPOSES.customerChat);
});

test('coupon probe migration preserves launch-bound authority semantics', () => {
  const sql = fs.readFileSync(require('node:path').join(__dirname,
    '../db/postgres/workshop-migrations/secureshop_agents/0095_coupon_probe_conversation_purpose.sql'), 'utf8');
  assert.match(sql, /'secureshop_idor_lesson','secureshop_coupon_probe'/);
  assert.match(sql, /authority_mode='launch_bound' OR conversation_purpose='general'/);
  assert.doesNotMatch(sql, /DROP DATABASE|TRUNCATE|DELETE FROM/);
});

test('V44 adds only its distinct launch-bound path-read purpose and preserves all prior purposes', () => {
 const dir = require('node:path').join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents');
 const previous = fs.readFileSync(require('node:path').join(dir,'0107_file_summary_conversation_purpose.sql'),'utf8');
 const next = fs.readFileSync(require('node:path').join(dir,'0109_file_path_summary_conversation_purpose.sql'),'utf8');
 const values = sql => [...sql.match(/conversation_purpose IN \(([\s\S]*?)\)/)[1].matchAll(/'([^']+)'/g)].map(x=>x[1]);
 assert.deepEqual(values(next), [...values(previous),'secureshop_file_path_summary']);
 assert.deepEqual([...new Set(values(next))].sort(), Object.values(PURPOSES).sort());
 assert.equal(normalizeConversationPurpose(PURPOSES.filePathSummary),'secureshop_file_path_summary');
 assert.notEqual(PURPOSES.filePathSummary,PURPOSES.fileSummary);
 assert.match(next,/authority_mode='launch_bound' OR conversation_purpose='general'/);
 assert.doesNotMatch(next,/DELETE FROM|TRUNCATE|DROP DATABASE|UPDATE /i);
});
