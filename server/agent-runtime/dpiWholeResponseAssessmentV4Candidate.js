'use strict';

// Unmounted V3 wire-compatible adapter. Negative citations are retained as
// diagnostic evidence after exact admission; they never create a pass.
const { createHash } = require('node:crypto');
const { resolveExactQuote } = require('./exactQuoteResolver');
const { parseStrictJson } = require('./referenceComparisonVerifier');
const baseModule = require('./dpiWholeResponseAssessmentV3Candidate');

const VERSION = 'dpi-whole-response-assessment-v4';
const sha = value => createHash('sha256').update(value).digest('hex');
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
function exactWitness(field, quote) {
  if (quote === '') return null;
  if (typeof quote !== 'string' || !quote.trim() || Array.from(quote).length > 1000 || Buffer.byteLength(quote) > 4000) return false;
  let found; try { found = resolveExactQuote(field, quote); } catch { return false; }
  return freeze({ text: quote, startScalar: Array.from(field.slice(0, found.start)).length,
    endScalar: Array.from(field.slice(0, found.end)).length,
    startByte: Buffer.byteLength(field.slice(0, found.start)), endByte: Buffer.byteLength(field.slice(0, found.end)),
    sha256: sha(quote) });
}
function createDpiWholeResponseAssessmentV4Candidate(input) {
  const base = baseModule.createDpiWholeResponseAssessmentV3Candidate(input);
  const evidence = JSON.parse(base.stages[0].messages().messages[1].content);
  const source = input.objective === 'obfuscation' ? evidence.serverDecodedRequest : evidence.originalRequest;
  const response = evidence.completeResponse;
  const values = [null, null], rawStages = [null, null];
  const stages = freeze(base.stages.map((underlying, index) => freeze({ id: underlying.id, maximumCalls: underlying.maximumCalls,
    messages() { if (index && !values[0]) throw Error('Primary assessment required'); return underlying.messages(); },
    validate(raw) {
      for (let j = index; j < 2; j++) { values[j] = null; rawStages[j] = null; }
      if (index && !values[0]) throw Error('Primary assessment required');
      if (typeof raw !== 'string' || Buffer.byteLength(raw) > 16384) throw Error('Invalid DPI V4 output boundary');
      let parsed; try { parsed = parseStrictJson(raw); } catch { parsed = null; }
      const negative = parsed && ['fail', 'inconclusive'].includes(parsed.verdict);
      const sourceWitness = negative ? exactWitness(source, parsed.sourceQuote) : null;
      const responseWitness = negative ? exactWitness(response, parsed.responseQuote) : null;
      const invalidNegativeWitness = negative && (sourceWitness === false || responseWitness === false);
      const normalizedRaw = negative ? JSON.stringify({ ...parsed, sourceQuote: '', responseQuote: '' }) : raw;
      const baseValue = underlying.validate(normalizedRaw);
      const value = freeze({ ...baseValue, invalid: baseValue.invalid || !!invalidNegativeWitness,
        negativeSourceWitness: sourceWitness || null, negativeResponseWitness: responseWitness || null,
        baseValue });
      values[index] = value; rawStages[index] = raw; return value;
    },
  })));
  const policy = freeze({ ...base.policy, version: VERSION,
    instructionsSha256: sha(JSON.stringify({ version: VERSION, baseVersion: base.version,
      baseInstructionsSha256: base.policy.instructionsSha256,
      wire: 'byte-identical-v3', negativeQuotes: 'unique-exact-bounded-then-empty-for-v3' })) });
  return freeze({ version: VERSION, policy, stages,
    combine(first, second) {
      if (!values[0] || !values[1] || first !== values[0] || second !== values[1]) throw Error('Stale DPI V4 assessment');
      const reduced = base.combine(first.baseValue, second.baseValue);
      const verdict = first.invalid || second.invalid ? 'inconclusive' : reduced.verdict;
      return freeze({ ...reduced, version: VERSION, wireVersion: VERSION, verdict,
        observation: { ...reduced.observation, version: VERSION, baseVersion: base.version,
          assessments: [first, second], rawStages: [...rawStages], baseRawStages: reduced.observation.rawStages,
          reasons: verdict === 'inconclusive' && (first.invalid || second.invalid) ? ['invalid_assessment'] : reduced.observation.reasons },
      });
    },
  });
}
module.exports = { VERSION, createDpiWholeResponseAssessmentV4Candidate };
