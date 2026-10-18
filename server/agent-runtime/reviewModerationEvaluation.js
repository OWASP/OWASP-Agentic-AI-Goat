'use strict';

const { createHash } = require('node:crypto');
const { Annotation, StateGraph, START, END } = require('@langchain/langgraph');

// Transport, cancellation and evidence admission remain the canonical Judge's
// responsibility. This graph controls the two semantic stages and bounded repair.
function createReviewModerationEvaluation({ comparison, invoke, admit, check, emit, disposition, parsed, invalid }) {
  const stages = [];
  const responses = new Map();
  const values = new Map();
  let result, outputTokens = 0, usageKnown = true;
  const definitions = {
    instruction: [comparison.instructionMessages, comparison.validateInstruction,
      comparison.policy.maximumInstructionCalls],
    content: [comparison.contentMessages, comparison.validateContent,
      comparison.policy.maximumContentCalls],
  };
  const snapshot = () => {
    const latest = stages.at(-1);
    return {
      attempts: stages.reduce((sum, item) => sum + item.attempts, 0),
      provider: latest?.provider || null, model: latest?.model || null,
      usage: usageKnown ? { outputTokens } : null,
      ...(stages.length ? { reviewModeration: { version: comparison.policy.version,
        stages: stages.map(({ error, ...item }) => ({ ...item,
          responseSha256: [...item.responseSha256] })),
        ...(result ? { observation: result.observation } : {}) } } : {}),
    };
  };
  const modelNode = stage => async () => {
    await check();
    let audit = stages.find(item => item.stage === stage);
    if (!audit) {
      audit = { stage, attempts: 0, provider: null, model: null,
        completed: false, responseSha256: [], error: undefined };
      stages.push(audit);
    }
    const prepared = definitions[stage][0](audit.error);
    admit(prepared);
    audit.attempts += 1;
    await emit(`judge_review_${stage}_model`, 'start', { attempt: audit.attempts });
    const response = await invoke(prepared, stage, audit.attempts);
    responses.set(stage, response);
    audit.provider = response?.provider || null;
    audit.model = response?.model || null;
    audit.responseSha256.push(typeof response?.response === 'string'
      ? createHash('sha256').update(response.response).digest('hex') : null);
    await check();
    if (response?.mocked || response?.fallback || response?.provider === 'mock'
        || typeof response?.provider !== 'string' || !response.provider.trim()
        || typeof response?.model !== 'string' || !response.model.trim()) {
      throw new Error('JUDGE_MODEL_UNAVAILABLE');
    }
    const tokens = response?.metadata?.eval_count ?? (response?.tokens > 0 ? response.tokens : null);
    if (Number.isFinite(tokens) && tokens >= 0) outputTokens += tokens;
    else usageKnown = false;
    await emit(`judge_review_${stage}_model`, 'end', { attempt: audit.attempts,
      provider: audit.provider, model: audit.model });
    return {};
  };
  const validationNode = stage => async () => {
    await check();
    const audit = stages.find(item => item.stage === stage);
    try {
      const validationText=responses.get(stage).response;try{parsed?.(stage,audit.attempts,validationText);}catch{}
      values.set(stage, definitions[stage][1](validationText));
      audit.completed = true;
      try{disposition?.(stage,audit.attempts,'accepted');}catch{}
    } catch (error) {
      try{disposition?.(stage,audit.attempts,'rejected');}catch{}
      audit.error = 'Return a valid, complete classification with only supplied passage IDs.';
      await invalid?.(stage, audit.attempts, responses.get(stage), error);
      await emit(`judge_review_${stage}_validate`, 'invalid', {
        attempt: audit.attempts, errorCode: 'INVALID_JUDGE_OUTPUT' });
    }
    return { retry: !audit.completed && audit.attempts < definitions[stage][2] };
  };
  const state = Annotation.Root({ retry: Annotation({ reducer: (_, value) => value, default: () => false }) });
  const graph = new StateGraph(state)
    .addNode('instruction_model', modelNode('instruction'))
    .addNode('instruction_validate', validationNode('instruction'))
    .addNode('content_model', modelNode('content'))
    .addNode('content_validate', validationNode('content'))
    .addNode('compare', async () => {
      await check();
      result = comparison.combine(values.get('instruction'), values.get('content'));
      await emit('judge_review_compare', 'verdict', { verdict: result.verdict });
      return {};
    })
    .addEdge(START, 'instruction_model')
    .addEdge('instruction_model', 'instruction_validate')
    .addConditionalEdges('instruction_validate', value => value.retry ? 'instruction_model'
      : values.has('instruction') ? comparison.policy.sourceOnly ? 'compare' : 'content_model' : END, ['instruction_model', 'content_model', 'compare', END])
    .addEdge('content_model', 'content_validate')
    .addConditionalEdges('content_validate', value => value.retry ? 'content_model'
      : values.has('content') ? 'compare' : END, ['content_model', 'compare', END])
    .addEdge('compare', END).compile();
  return Object.freeze({ snapshot, async run(signal) {
    await graph.invoke({}, { signal, recursionLimit: 16 });
    await check();
    return result ? { ...result, ...snapshot() } : {
      verdict: 'unavailable', explanation: 'A review classification remained invalid; no completion was awarded.',
      criteria: [], errorCode: 'INVALID_JUDGE_OUTPUT', ...snapshot(),
    };
  } });
}

module.exports = { createReviewModerationEvaluation };
