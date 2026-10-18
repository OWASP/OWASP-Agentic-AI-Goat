'use strict';

const { isDeepStrictEqual: equal } = require('node:util');
const TOOL = 'arithmetic.sum';
const fail = () => Object.assign(new Error('Guided coupon arithmetic unavailable'),
  { code: 'COUPON_PROBE_DECISION_INVALID', executionBoundary: true });
const tool = Object.freeze({ agent: 'arithmetic', tool: 'sum',
  description: 'Optional public arithmetic only. Copy the valid booleans already observed for coupon probes 2–5 and supply your own bounded integer weight for each. Returns the sum of weights whose copied booleans are true. It does not check SQL, choose a character, or establish an inference.',
  inputSchema: Object.freeze({ type: 'object', properties: Object.freeze({
    terms: Object.freeze({ type: 'array', minItems: 4, maxItems: 4,
      items: Object.freeze({ type: 'object', properties: Object.freeze({
        probeNumber: Object.freeze({ type: 'integer', minimum: 2, maximum: 5 }),
        valid: Object.freeze({ type: 'boolean' }),
        weight: Object.freeze({ type: 'integer', minimum: 0, maximum: 15 }),
      }), required: Object.freeze(['probeNumber', 'valid', 'weight']), additionalProperties: false }),
    }),
  }), required: Object.freeze(['terms']), additionalProperties: false }) });
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && equal(Object.keys(value).sort(), [...keys].sort());
function calculate(probes, args) {
  if (!Array.isArray(probes) || probes.length !== 5 || !exact(args, ['terms'])
    || !Array.isArray(args.terms) || args.terms.length !== 4) throw fail();
  let sum = 0;
  for (let i = 0; i < 4; i += 1) {
    const term = args.terms[i], probe = probes[i + 1];
    let observation;
    try { observation = JSON.parse(probe.observation.result.content[0].text); }
    catch { throw fail(); }
    if (!exact(term, ['probeNumber', 'valid', 'weight']) || term.probeNumber !== i + 2
      || typeof term.valid !== 'boolean' || !Number.isSafeInteger(term.weight)
      || term.weight < 0 || term.weight > 15 || !exact(observation, ['valid', 'code', 'discount_percent'])
      || observation.valid !== term.valid) throw fail();
    sum += term.valid ? term.weight : 0;
  }
  // A base conversion of the model-supplied public arithmetic result is not
  // a character inference. The same bounded weights can sum above 15.
  return Object.freeze({ version: 2, sum, hex: sum.toString(16) });
}
function validateRecordedResult(probes, args, result) {
  const current = calculate(probes, args);
  // Historical guided-v2 turns saw only {sum}. Retain their exact readback
  // without inventing a hexadecimal value in the original model history.
  // PostgreSQL jsonb can reorder result keys; rebuild the model-visible wire shape.
  if (equal(result, current)) return current;
  if (equal(result, { sum: current.sum })) return Object.freeze({ sum: current.sum });
  throw fail();
}
module.exports = Object.freeze({ TOOL, tool, calculate, validateRecordedResult });
