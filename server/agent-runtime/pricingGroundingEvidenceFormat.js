'use strict';

// Evidence representation only: no semantic labels, provider or grading behavior.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const VERSION = 'pricing-lossless-blocks-v1';
const MAX_BYTES = 65536;
const PREFIX = '<<<OWASP_AI_GOAT_PRICING_EVIDENCE_V1';
const HEADER = `${PREFIX}:BEGIN>>>\n`;
const FOOTER = `${PREFIX}:END>>>`;
const FIELDS = Object.freeze({
  effect: Object.freeze(['tool_observation', 'answer', 'answer_passages']),
  support: Object.freeze(['tool_observation', 'answer', 'selected_claim_quote', 'server_bound_source_sha256']),
});
const sha = value => createHash('sha256').update(value).digest('hex');
function text(value) {
  assert.equal(typeof value, 'string');
  assert(value.isWellFormed(), 'Ill-formed UTF-16 is not losslessly transportable');
  assert(Buffer.byteLength(value) <= MAX_BYTES, 'Evidence cap exceeded');
  return value;
}
function validateUser(raw, stage) {
  text(raw); assert(Object.hasOwn(FIELDS, stage), 'Closed comparison stage required');
  const value = JSON.parse(raw);
  assert(value && Object.getPrototypeOf(value) === Object.prototype);
  assert.deepEqual(Object.keys(value), FIELDS[stage], 'Exact canonical evidence keys/order required');
  assert.equal(JSON.stringify(value), raw, 'Canonical evidence JSON required');
  assert(value.tool_observation && Object.getPrototypeOf(value.tool_observation) === Object.prototype);
  assert.equal(value.tool_observation.grounded, false);
  text(value.answer);
  if (stage === 'effect') {
    assert(Array.isArray(value.answer_passages) && value.answer_passages.length > 0);
  } else {
    text(value.selected_claim_quote);
    assert(value.answer.includes(value.selected_claim_quote));
    assert.equal(value.server_bound_source_sha256, sha(JSON.stringify(value.tool_observation)));
  }
  return value;
}
function rawField(key, value) { return key === 'answer' || key === 'selected_claim_quote' ? value : JSON.stringify(value); }
function encode(raw, stage = 'effect') {
  const value = validateUser(raw, stage);
  let encoded = HEADER + stage + '\n';
  for (const key of FIELDS[stage]) {
    const body = text(rawField(key, value[key]));
    assert(!body.includes(PREFIX), 'Evidence delimiter collision');
    // Length is in UTF-16 code units; well-formed strings survive UTF-8 transport.
    encoded += `${PREFIX}:${key}:${body.length}>>>\n${body}\n`;
  }
  return text(encoded + FOOTER);
}
function decode(encoded, stage = 'effect') {
  text(encoded); assert(Object.hasOwn(FIELDS, stage));
  const begin = HEADER + stage + '\n'; assert(encoded.startsWith(begin));
  let cursor = begin.length;
  const value = {};
  for (const key of FIELDS[stage]) {
    const start = `${PREFIX}:${key}:`; assert(encoded.startsWith(start, cursor)); cursor += start.length;
    const end = encoded.indexOf('>>>\n', cursor); assert(end >= cursor);
    const count = encoded.slice(cursor, end); assert(/^(0|[1-9]\d*)$/.test(count));
    const length = Number(count); assert(Number.isSafeInteger(length) && length <= MAX_BYTES);
    cursor = end + 4;
    const body = encoded.slice(cursor, cursor + length); assert.equal(body.length, length);
    text(body); assert(!body.includes(PREFIX), 'Evidence delimiter collision');
    cursor += length; assert.equal(encoded[cursor++], '\n');
    value[key] = key === 'answer' || key === 'selected_claim_quote' ? body : JSON.parse(body);
  }
  assert.equal(encoded.slice(cursor), FOOTER, 'Trailing/truncated/duplicated evidence rejected');
  const raw = JSON.stringify(value); validateUser(raw, stage);
  assert.equal(encode(raw, stage), encoded, 'Noncanonical block encoding');
  return raw;
}

module.exports = { VERSION, MAX_BYTES, PREFIX, encode, decode };
