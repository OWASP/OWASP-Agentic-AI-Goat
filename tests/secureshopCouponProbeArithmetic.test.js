'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const Arithmetic = require('../server/services/secureshopCouponProbeArithmetic');
const probes = [true, false, false, false, true].map((valid, index) => ({
  observation: { result: { content: [{ type: 'text', text: JSON.stringify({
    valid, code: `public-${index}`, discount_percent: valid ? 10 : 0,
  }) }] } },
}));
const terms = [false, false, false, true].map((valid, index) => ({ probeNumber: index + 2,
  valid, weight: 2 ** index }));
test('public arithmetic computes model-supplied weights without deriving a character or query', () => {
  assert.deepEqual(Arithmetic.calculate(probes, { terms }), { version: 2, sum: 8, hex: '8' });
  assert.deepEqual(Arithmetic.calculate(probes, { terms: terms.map(term => ({ ...term, weight: 0 })) }),
    { version: 2, sum: 0, hex: '0' });
  assert.deepEqual(Object.keys(Arithmetic.calculate(probes, { terms })), ['version', 'sum', 'hex']);
});
test('all sixteen public bit patterns and bounded noncanonical weights convert without choosing a character', () => {
  for (let value = 0; value < 16; value += 1) {
    const bits = [0, 1, 2, 3].map(bit => Boolean(value & (2 ** bit)));
    const source = [true, ...bits].map((valid, index) => ({ observation: { result: {
      content: [{ type: 'text', text: JSON.stringify({ valid, code: `public-${index}`,
        discount_percent: valid ? 10 : 0 }) }],
    } } }));
    const chosen = bits.map((valid, index) => ({ probeNumber: index + 2, valid, weight: 2 ** index }));
    assert.deepEqual(Arithmetic.calculate(source, { terms: chosen }),
      { version: 2, sum: value, hex: value.toString(16) });
  }
  const allTrue = [true, true, true, true, true].map((valid, index) => ({ observation: { result: {
    content: [{ type: 'text', text: JSON.stringify({ valid, code: `public-${index}`,
      discount_percent: 10 }) }],
  } } }));
  const heavy = [2, 3, 4, 5].map(probeNumber => ({ probeNumber, valid: true, weight: 15 }));
  assert.deepEqual(Arithmetic.calculate(allTrue, { terms: heavy }), { version: 2, sum: 60, hex: '3c' });
});
test('recorded arithmetic accepts only exact current or historical observed result', () => {
  assert.deepEqual(Arithmetic.validateRecordedResult(probes, { terms },
    { version: 2, sum: 8, hex: '8' }), { version: 2, sum: 8, hex: '8' });
  assert.deepEqual(Arithmetic.validateRecordedResult(probes, { terms }, { sum: 8 }), { sum: 8 });
  const jsonbOrdered = { hex: '8', sum: 8, version: 2 };
  const restored = Arithmetic.validateRecordedResult(probes, { terms }, jsonbOrdered);
  assert.deepEqual(Object.keys(restored), ['version', 'sum', 'hex']);
  assert.equal(JSON.stringify(restored), '{"version":2,"sum":8,"hex":"8"}');
  assert.deepEqual(Object.keys(Arithmetic.validateRecordedResult(probes, { terms }, { sum: 8 })), ['sum']);
  for (const invalid of [{ version: 1, sum: 8, hex: '8' }, { version: 2, sum: 8, hex: '08' },
    { version: 2, sum: 8, hex: 'A' }, { version: 2, sum: 9, hex: '9' },
    { sum: 8, hex: '8' }, { sum: 8, version: 2 }, { sum: 9 }]) {
    assert.throws(() => Arithmetic.validateRecordedResult(probes, { terms }, invalid),
      { code: 'COUPON_PROBE_DECISION_INVALID' });
  }
});
test('public arithmetic rejects copied-booleans drift, extraneous inputs and unbounded arithmetic', () => {
  for (const invalid of [
    { terms: terms.map((term, index) => index === 1 ? { ...term, valid: true } : term) },
    { terms: terms.map((term, index) => index === 1 ? { ...term, probeNumber: 5 } : term) },
    { terms: terms.map((term, index) => index === 1 ? { ...term, weight: 16 } : term) },
    { terms, character: '8' },
    { terms: terms.slice(0, 3) },
  ]) assert.throws(() => Arithmetic.calculate(probes, invalid), { code: 'COUPON_PROBE_DECISION_INVALID' });
});
