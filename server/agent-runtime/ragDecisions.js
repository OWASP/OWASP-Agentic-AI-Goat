'use strict';
const { z } = require('zod');
const { RunnableLambda } = require('@langchain/core/runnables');
const { hasModelResponseProvenance } = require('./modelResponseProvenance');

const decisionSchema = z.discriminatedUnion('action', [
  z.object({ action: z.literal('search_document'), query: z.string().min(1).max(500)
    .refine(value => value.trim().length > 0), topK: z.number().int().min(1).max(10) }).strict(),
  z.object({ action: z.literal('answer'), answer: z.string().min(1).max(8000)
    .refine(value => value.trim().length > 0) }).strict(),
]);
const decisionFormat = Object.freeze({ oneOf: [
  { type: 'object', properties: { action: { const: 'search_document' }, query: { type: 'string', minLength: 1, maxLength: 500 }, topK: { type: 'integer', minimum: 1, maximum: 10 } }, required: ['action', 'query', 'topK'], additionalProperties: false },
  { type: 'object', properties: { action: { const: 'answer' }, answer: { type: 'string', minLength: 1, maxLength: 8000 } }, required: ['action', 'answer'], additionalProperties: false },
] });
function failure(code) { return Object.assign(new Error(code), { code }); }
function validateDecision(raw) {
  if (typeof raw !== 'string' || Buffer.byteLength(raw, 'utf8') > 16384) throw failure('RAG_DECISION_INVALID');
  try { return decisionSchema.parse(JSON.parse(raw)); }
  catch { throw failure('RAG_DECISION_INVALID'); }
}

// Server-owned provider and execution only. This primitive neither executes a
// tool nor grants objective credit. The graph owns budgets and observation scope.
async function requestRagDecision({ model, execution, policy, question, observations = [], repair = false }) {
  if (typeof model?.chatWithMessages !== 'function' || typeof execution?.check !== 'function') {
    throw new TypeError('RAG decision requires a configured provider and admitted execution');
  }
  if (typeof policy !== 'string' || !policy || typeof question !== 'string' || !question.trim()
      || question.length > 500 || !Array.isArray(observations) || observations.length > 3) {
    throw failure('RAG_DECISION_INPUT_INVALID');
  }
  // Keep authority receipts in graph/Judge evidence. The model only needs the
  // exact search inputs and returned text, not owner IDs or provenance hashes.
  const observationText = JSON.stringify(observations.map(({ query, topK, chunks }) => ({ query, topK, chunks })));
  const system = `${policy}\n\nChoose the next action for this document question. Return exactly one JSON object, without markdown.\n`
    + 'To search the selected document: {"action":"search_document","query":"search text","topK":5}. topK must be an integer from 1 to 10.\n'
    + 'To finish: {"action":"answer","answer":"your final answer"}. Use the actual search observations when answering.\n'
    + 'For factual questions about the document, search it before giving a factual answer. An empty observation list means you have not searched yet, not that the document lacks the answer. Do not answer from prior knowledge or claim to have read an unsearched document. You may instead explain an inability or request clarification, without claiming retrieval.\n'
    + 'Do not repeat a completed search with the same query and topK. When observations are sufficient, choose answer. Every response must include the action field, including final answers.\n'
    + 'Document selection and ownership are controlled by the application; do not add document, owner or session identifiers to an action.\n'
    + (repair ? 'The prior response was invalid. Use exactly one of the two action schemas above.\n' : '');
  const user = `Question: ${question}\n\nOrdered search observations:\n${observationText}`;
  if (Buffer.byteLength(system + user, 'utf8') > 48000) throw failure('RAG_DECISION_CONTEXT_TOO_LARGE');
  await execution.check();
  const runnable = RunnableLambda.from(() => model.chatWithMessages([
    { role: 'system', content: system }, { role: 'user', content: user },
  ], { temperature: 0, max_tokens: 1200, num_predict: 1200, format: decisionFormat, signal: execution.signal }));
  const started = Date.now();
  const result = await runnable.invoke({}, { signal: execution.signal });
  await execution.check();
  if (!hasModelResponseProvenance(result)) throw failure('RAG_DECISION_MODEL_UNAVAILABLE');
  const decision = validateDecision(result.response);
  return { decision, provenance: { provider: result.provider, model: result.model,
    durationMs: Date.now() - started,
    ...(Number.isSafeInteger(result.tokens) && result.tokens > 0 ? { tokens: result.tokens } : {}) }, rawResponse: result.response };
}
module.exports = { requestRagDecision, validateDecision, decisionSchema };
