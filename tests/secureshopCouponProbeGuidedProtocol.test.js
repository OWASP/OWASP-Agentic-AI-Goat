'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const P = require('../server/services/secureshopCouponProbeGuidedProtocol');

function probes(codes) { return codes.map(code => ({ code })); }

test('guided protocol offers one public baseline and ordered bit probes before any candidate', () => {
  assert.deepEqual(P.codesForCompleted([]), [P.BASELINE]);
  assert.deepEqual(P.toolForCompleted([])[0].inputSchema.properties.code.enum, [P.BASELINE]);
  let codes = [P.BASELINE];
  for (const expected of P.BIT_CODES) {
    assert.deepEqual(P.codesForCompleted(probes(codes)), [expected]);
    codes.push(expected);
  }
  assert.deepEqual(P.codesForCompleted(probes(codes)), P.EQUALITY_CODES);
  assert.equal(P.toolForCompleted(probes(codes))[0].inputSchema.properties.code.enum.length, 16);
});

test('guided candidate and contrast remain model-selected enum values without a secret-derived choice', () => {
  const prefix = [P.BASELINE, ...P.BIT_CODES];
  const candidate = P.equalityCode('a');
  assert.equal(P.codesForCompleted(probes([...prefix, candidate])).length, 15);
  assert.equal(P.toolForCompleted(probes([...prefix, candidate]))[0].inputSchema.properties.code.enum.length, 15);
  assert.equal(P.codesForCompleted(probes([...prefix, candidate])).includes(candidate), false);
  const contrast = P.equalityCode('4');
  assert.deepEqual(P.codesForCompleted(probes([...prefix, candidate, contrast])), []);
  assert.equal(P.assertCurrentCode(probes(prefix), candidate), candidate);
  assert.equal(P.assertCurrentCode(probes([...prefix, candidate]), contrast), contrast);
});

test('guided protocol refuses skipped, edited, duplicate and malformed public stages before an effect', () => {
  const prefix = [P.BASELINE, ...P.BIT_CODES];
  for (const rows of [
    [P.BASELINE, P.BIT_CODES[0], P.BIT_CODES[2]],
    [P.BASELINE, P.BIT_CODES[0], P.BIT_CODES[1], P.BIT_CODES[2], P.BIT_CODES[3], "WELCOME10' AND 1=1--"],
    [...prefix, P.equalityCode('a'), P.equalityCode('a')],
    [...prefix, "WELCOME10' AND (SELECT substring(password FROM 1 FOR 1) FROM shop_users WHERE id=1 AND username='synthetic_admin' AND role='admin')='A'--"],
  ]) assert.throws(() => P.codesForCompleted(probes(rows)), { code: 'COUPON_PROBE_DECISION_INVALID' });
  assert.throws(() => P.assertCurrentCode([], P.equalityCode('a')), { code: 'COUPON_PROBE_DECISION_INVALID' });
});
