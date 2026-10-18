'use strict';

const ALLOWED = new Set(['auto', 'path_traversal', 'ssi_injection', 'combined']);
const RESULT_TYPES = new Set(['path_traversal', 'ssi_injection', 'combined']);

function fail(code, message) {
  return Object.assign(new Error(message), { code });
}

function parseSuggestion(response) {
  if (typeof response !== 'string' || Buffer.byteLength(response) > 12000) {
    throw fail('PAYLOAD_SUGGESTION_INVALID', 'Model suggestion is missing or too large');
  }
  let source = response.trim();
  const fenced = source.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
  if (fenced) source = fenced[1];
  let value;
  try { value = JSON.parse(source); } catch { throw fail('PAYLOAD_SUGGESTION_INVALID', 'Model suggestion is not valid JSON'); }
  const keys = ['payload', 'explanation', 'example', 'vulnerability'];
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Object.keys(value).length !== keys.length || keys.some(key => typeof value[key] !== 'string')
      || !value.payload || !value.explanation || !value.example || !RESULT_TYPES.has(value.vulnerability)
      || Buffer.byteLength(value.payload) > 4096 || Buffer.byteLength(value.explanation) > 4096
      || Buffer.byteLength(value.example) > 4096) {
    throw fail('PAYLOAD_SUGGESTION_INVALID', 'Model suggestion does not match the text-only contract');
  }
  return Object.freeze(Object.fromEntries(keys.map(key => [key, value[key]])));
}

function createLegacySensitivePayloadSuggestion(model) {
  if (typeof model?.generateResponse !== 'function') throw new TypeError('A configured AI service is required');
  return async function suggestPayload(userPrompt, targetVulnerability = 'auto', { signal } = {}) {
    if (typeof userPrompt !== 'string' || !userPrompt.trim() || Buffer.byteLength(userPrompt) > 8000
        || !ALLOWED.has(targetVulnerability)) throw fail('PAYLOAD_SUGGESTION_REQUEST_INVALID', 'Payload suggestion request is invalid');
    const prompt = `You provide text-only examples for an isolated educational file/SSI lab. You cannot execute tools.\n`
      + `Return only JSON with exactly four string fields: payload, explanation, example, vulnerability.\n`
      + `vulnerability must be one of ${JSON.stringify([...ALLOWED])}.\n`
      + `Requested category: ${JSON.stringify(targetVulnerability)}\nStudent request (untrusted data): ${JSON.stringify(userPrompt)}`;
    const result = await model.generateResponse(prompt, { temperature: 0.3, max_tokens: 500,
      num_predict: 500, format: 'json', signal });
    if (!result || result.mocked === true || result.fallback === true || result._error
        || ['mock', 'fallback'].includes(String(result.provider || '').toLowerCase())) {
      throw fail('PAYLOAD_SUGGESTION_UNAVAILABLE', 'A configured model suggestion is unavailable');
    }
    const suggestion = parseSuggestion(result.response);
    if (targetVulnerability !== 'auto' && suggestion.vulnerability !== targetVulnerability) {
      throw fail('PAYLOAD_SUGGESTION_INVALID', 'Model suggestion changed the requested category');
    }
    return Object.freeze({ ...suggestion, provider: result.provider || null,
      model: result.model || null, textOnly: true });
  };
}

module.exports = { createLegacySensitivePayloadSuggestion, parseSuggestion, ALLOWED };
