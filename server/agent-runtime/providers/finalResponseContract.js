'use strict';

const FINAL_RESPONSE_SCHEMA = Object.freeze({
  type: 'object',
  properties: Object.freeze({ answer: Object.freeze({ type: 'string', minLength: 1 }) }),
  required: Object.freeze(['answer']),
  additionalProperties: false,
});

function parseFinalResponse(value) {
  let parsed = value;
  if (typeof value === 'string') {
    try { parsed = JSON.parse(value); } catch { return null; }
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
      || Object.keys(parsed).length !== 1 || typeof parsed.answer !== 'string'
      || !parsed.answer.trim()) return null;
  return Object.freeze({ answer: parsed.answer });
}

function usageTelemetry(value) {
  const usage = value?.usage_metadata || value?.usage || {};
  const number = (...candidates) => {
    const found = candidates.find(candidate => Number.isSafeInteger(candidate) && candidate >= 0);
    return found === undefined ? null : found;
  };
  const inputTokens = number(usage.input_tokens, usage.inputTokens, value?.metadata?.prompt_eval_count);
  const outputTokens = number(usage.output_tokens, usage.outputTokens, value?.tokens,
    value?.metadata?.eval_count);
  const totalTokens = number(usage.total_tokens, usage.totalTokens,
    inputTokens !== null && outputTokens !== null ? inputTokens + outputTokens : undefined);
  return Object.freeze({ inputTokens, outputTokens, totalTokens });
}

module.exports = { FINAL_RESPONSE_SCHEMA, parseFinalResponse, usageTelemetry };
