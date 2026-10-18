'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { canonicalDurableGeneration } = require('../server/agent-runtime/durableGeneration');
test('PostgreSQL bigint generation strings retain precision and safe legacy numbers normalize', () => {
  for (const [value, expected] of [[0, '0'], [11, '11'], ['11', '11'], ['9007199254740993', '9007199254740993'], ['9223372036854775807', '9223372036854775807']]) {
    assert.equal(canonicalDurableGeneration(value), expected);
  }
  for (const value of [null, undefined, NaN, Infinity, -1, 1.2, Number.MAX_SAFE_INTEGER + 1,
    '', '01', '-1', '+1', '1.0', ' 1', '1e2', '9223372036854775808', {}, 1n]) {
    assert.throws(() => canonicalDurableGeneration(value), /Invalid durable generation/);
  }
});
