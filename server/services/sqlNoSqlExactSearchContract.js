'use strict';

const CONTRACTS = Object.freeze({
  ARIA: Object.freeze({
    prefix: /^\s*(?:please\s+)?search\s+products\s+using\s+this\s+exact\s+searchterm\s*:[ \t]?/i,
    tool: 'search_products',
    parameter: 'searchTerm',
  }),
  NOVA: Object.freeze({
    prefix: /^\s*(?:please\s+)?search\s+papers\s+using\s+this\s+exact\s+query\s*:[ \t]?/i,
    tool: 'search_papers',
    parameter: 'query',
  }),
});

function extractExactSearchObligation(family, message) {
  const contract = CONTRACTS[family];
  if (!contract || typeof message !== 'string') return null;
  const match = message.match(contract.prefix);
  if (!match) return null;
  const value = message.slice(match[0].length);
  if (!value.length) return null;
  return Object.freeze({ tool: contract.tool, parameter: contract.parameter, value });
}

function validateExactSearchDecision(family, message, decision) {
  const obligation = extractExactSearchObligation(family, message);
  if (!obligation) return decision;
  if (decision?.tool === 'general_chat') return decision;
  if (decision?.tool === obligation.tool
      && decision.params?.[obligation.parameter] === obligation.value) return decision;
  const selected = typeof decision?.params?.[obligation.parameter] === 'string'
    ? decision.params[obligation.parameter] : '';
  const expectedBytes = Buffer.from(obligation.value, 'utf8');
  const selectedBytes = Buffer.from(selected, 'utf8');
  let mismatchByte = 0;
  while (mismatchByte < expectedBytes.length && mismatchByte < selectedBytes.length
      && expectedBytes[mismatchByte] === selectedBytes[mismatchByte]) mismatchByte += 1;
  const error = new Error(`The explicit exact ${obligation.parameter} was not preserved byte-for-byte. The selected value has ${selectedBytes.length} UTF-8 bytes; the requested exact value has ${expectedBytes.length}; the first mismatch is at byte ${mismatchByte}. Re-read the original request and copy every character after the exact-field colon without repairing, normalizing, or truncating it.`);
  error.code = 'WORKSHOP_EXACT_SEARCH_MISMATCH';
  throw error;
}

function buildExactSearchDecisionFormat(family, message) {
  const obligation = extractExactSearchObligation(family, message);
  if (!obligation) return null;
  const searchProperties = obligation.parameter === 'searchTerm'
    ? { searchTerm: { type: 'string', const: obligation.value }, maxPrice: { type: ['number', 'null'] } }
    : { query: { type: 'string', const: obligation.value }, topic: { type: ['string', 'null'] }, year: { type: ['integer', 'null'] } };
  return Object.freeze({
    type: 'object', additionalProperties: false, required: ['tool', 'params'],
    properties: {
      tool: { type: 'string', enum: [obligation.tool, 'general_chat'] },
      params: { type: 'object', additionalProperties: false, properties: searchProperties },
    },
  });
}

module.exports = { extractExactSearchObligation, validateExactSearchDecision, buildExactSearchDecisionFormat };
