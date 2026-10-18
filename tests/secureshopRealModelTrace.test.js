'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { isQualifiedSecureShopModelTrace: qualifies } = require('../server/services/secureshopRealModelTrace');
const trace = (meta = {}, provider = 'ollama') => ({ provider, kind: 'model_decision', step: 1,
  result_json: JSON.stringify({ model: 'llama3.1:8b', mocked: false, ...meta }) });
test('all shared evidence consumers reject simulation before invoking the adapter qualifier', () => {
  let calls = 0;
  const qualify = () => { calls++; return true; };
  for (const marker of ['mock', 'fixture', 'scripted', 'fallback', 'unavailable']) {
    assert.equal(qualifies(trace({}, ` ${marker.toUpperCase()} `), qualify), false);
    assert.equal(qualifies(trace({ model: marker }), qualify), false);
  }
  for (const meta of [{ mocked: true }, { mocked: null }, { fallback: true }, { model: '' }]) {
    assert.equal(qualifies(trace(meta), qualify), false);
  }
  assert.equal(calls, 0);
});
test('real-looking identity still requires successful server qualification', () => {
  assert.equal(qualifies(trace()), false);
  assert.equal(qualifies(trace(), () => false), false);
  assert.equal(qualifies(trace(), () => { throw new Error('unavailable'); }), false);
  assert.equal(qualifies(trace(), value => Object.isFrozen(value) && value.provider === 'ollama'), true);
  assert.equal(qualifies({ result_json: '{bad' }, () => true), false);
});
