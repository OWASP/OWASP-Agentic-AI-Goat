'use strict';
const { createHash } = require('node:crypto');
const { Annotation, StateGraph, START, END } = require('@langchain/langgraph');
const { DynamicStructuredTool } = require('@langchain/core/tools');
const { z } = require('zod');
const { requestRagDecision } = require('./ragDecisions');
const SEARCH_LIMIT = 3;
const searchSchema = z.object({ query: z.string().min(1).max(500), topK: z.number().int().min(1).max(10) }).strict();
const fail = code => Object.assign(new Error(code), { code });
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
function validateObservation(result, topK) {
  const indices = new Set();
  if (!result || !Array.isArray(result.chunks) || result.chunks.length > topK
      || result.chunks.some(chunk => {
        if (typeof chunk?.text !== 'string' || !Number.isInteger(chunk.chunkIndex) || chunk.chunkIndex < 0
            || !Number.isFinite(chunk.score) || Math.abs(chunk.score) > 1.000001 || indices.has(chunk.chunkIndex)) return true;
        indices.add(chunk.chunkIndex); return false;
      }) || !result.receipt || typeof result.receipt !== 'object' || Array.isArray(result.receipt)) {
    throw fail('RAG_SEARCH_EVIDENCE_INVALID');
  }
  if (Buffer.byteLength(JSON.stringify(result), 'utf8') > 40000) throw fail('RAG_SEARCH_CONTEXT_TOO_LARGE');
}

// searchDocument is bound by server composition to one admitted owner/resource.
// No identity or source selector is accepted from model arguments. This loop
// produces evidence; canonical Judge/credit publication remains a separate step.
async function runRagDecisionLoop({ model, execution, policy, question, searchDocument }) {
  if (typeof searchDocument !== 'function' || typeof execution?.check !== 'function'
      || typeof execution?.effect !== 'function') throw new TypeError('Admitted RAG execution and bound search required');
  const observations = [], seen = new Set();
  let decisionResult, finalResult;
  const trace = async (node, data, type = 'decision') => execution.trace?.({ node, type, data });
  const graph = new StateGraph(Annotation.Root({ action: Annotation() }))
    .addNode('decide', async () => {
      await execution.check();
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          decisionResult = await requestRagDecision({ model, execution, policy, question,
            observations, repair: attempt === 1 });
          await trace('rag_decide', { tool: decisionResult.decision.action, decisionSource: 'model', attempt: attempt + 1,
            ...decisionResult.provenance, toolSteps: observations.length });
          return { action: decisionResult.decision.action };
        } catch (error) {
          if (error.code !== 'RAG_DECISION_INVALID' || attempt === 1) throw error;
          await trace('rag_decide', { errorCode: error.code, attempt: attempt + 1 });
        }
      }
    })
    .addNode('search', async () => {
      await execution.check();
      if (observations.length >= SEARCH_LIMIT) throw fail('RAG_SEARCH_BUDGET_EXHAUSTED');
      const { query, topK } = decisionResult.decision;
      const args = { query, topK }, key = digest(args);
      if (seen.has(key)) throw fail('RAG_DUPLICATE_SEARCH');
      seen.add(key);
      let observation;
      const tool = new DynamicStructuredTool({ name: 'search_document',
        description: 'Search the currently selected document and return matching source chunks.', schema: searchSchema,
        func: async selected => {
          observation = await execution.effect(`rag_search:${observations.length}:${key}`, async () => {
            await execution.check();
            const result = await searchDocument(selected, { effectKey: `rag_search:${observations.length}:${key}` });
            await execution.check();
            return result;
          });
          // Validate both fresh callback results and any ledger replay projection.
          // Never silently clip source text: missing context must be explicit.
          validateObservation(observation, topK);
          return JSON.stringify(observation);
        } });
      await tool.invoke(args, { signal: execution.signal });
      await execution.check();
      observations.push({ query, topK, chunks: observation.chunks, receipt: observation.receipt });
      await trace('rag_search', { tool: 'search_document', decisionSource: 'model', toolSteps: observations.length }, 'tool');
      return {};
    })
    .addNode('answer', async () => {
      await execution.check();
      finalResult = { answer: decisionResult.decision.answer, observations,
        modelResult: { ...decisionResult.provenance, response: decisionResult.decision.answer,
          mocked: false, fallback: false }, rawDecisionResponse: decisionResult.rawResponse };
      await trace('rag_answer', { decisionSource: 'model', toolSteps: observations.length, terminationReason: 'model_finished' });
      return {};
    })
    .addEdge(START, 'decide')
    .addConditionalEdges('decide', state => state.action, { search_document: 'search', answer: 'answer' })
    .addEdge('search', 'decide').addEdge('answer', END).compile();
  await graph.invoke({}, { recursionLimit: 12, signal: execution.signal });
  await execution.check();
  return finalResult;
}
module.exports = { runRagDecisionLoop, SEARCH_LIMIT };
