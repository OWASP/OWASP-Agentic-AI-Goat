'use strict';

const { createHash } = require('node:crypto');
const { Annotation, StateGraph, START, END } = require('@langchain/langgraph');

// Transport, cancellation and evidence admission remain the canonical Judge's
// responsibility. This graph controls the source semantic stage and bounded repair.
function createBoundedSourceClassificationEvaluation({ comparison, invoke, admit, check, emit, disposition, parsed, invalid, auditField, eventPrefix, label }) {
  if(!['mailReplyComparison','inventoryStockComparison','dpiAnswerComparison'].includes(auditField)||!['judge_mail','judge_inventory','judge_dpi_answer'].includes(eventPrefix)||typeof label!=='string')throw TypeError('Closed source classification audit configuration required');
  const stages = [];
  const responses = new Map();
  const values = new Map();
  let result, outputTokens = 0, usageKnown = true;
  const stageDefinitions=comparison.stages||[{id:'instruction',messages:comparison.messages,validate:comparison.validate,maximumCalls:comparison.policy.maximumCalls}];
  if(comparison.stages && (!(auditField==='mailReplyComparison'&&['mail-grounded-action-comparison-v3','mail-keyed-action-comparison-v4','mail-source-only-action-comparison-v5','mail-sparse-source-comparison-v6','mail-compact-entailment-comparison-v7','mail-conditional-entailment-comparison-v8','mail-whole-source-comparison-v9'].includes(comparison.policy.version)&&stageDefinitions.map(s=>s.id).join(',')==='extract,verify'||auditField==='dpiAnswerComparison'&&['dpi-answer-comparison-v1','dpi-answer-comparison-v2','dpi-answer-comparison-v3','dpi-answer-comparison-v4','dpi-answer-comparison-v5','dpi-answer-comparison-v6','dpi-answer-comparison-v7','dpi-answer-comparison-v8','dpi-answer-comparison-v9'].includes(comparison.policy.version)&&stageDefinitions.map(s=>s.id).join(',')==='source,answer'||auditField==='dpiAnswerComparison'&&['dpi-answer-comparison-v8','dpi-answer-comparison-v9'].includes(comparison.policy.version)&&stageDefinitions.map(s=>s.id).join(',')==='witness,source,answer')||stageDefinitions.some(s=>s.maximumCalls!==2)))throw TypeError('Closed independent mail stages required');
  const definitions=Object.fromEntries(stageDefinitions.map(s=>[s.id,[s.messages,s.validate,s.maximumCalls]]));
  const stageIds=stageDefinitions.map(s=>s.id);
  const snapshot = () => {
    const latest = stages.at(-1);
    return {
      attempts: stages.reduce((sum, item) => sum + item.attempts, 0),
      provider: latest?.provider || null, model: latest?.model || null,
      usage: usageKnown ? { outputTokens } : null,
      ...(stages.length ? { [auditField]: { version: comparison.policy.version,
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
    await emit(`${eventPrefix}_${stage}_model`, 'start', { attempt: audit.attempts });
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
    await emit(`${eventPrefix}_${stage}_model`, 'end', { attempt: audit.attempts,
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
      if(comparison.stages && error.code==='JUDGE_CONTEXT_LIMIT')throw error;
      audit.error = ['mail-conditional-entailment-comparison-v8','mail-keyed-action-comparison-v4','mail-source-only-action-comparison-v5','dpi-answer-comparison-v2','dpi-answer-comparison-v3','dpi-answer-comparison-v4','dpi-answer-comparison-v5','dpi-answer-comparison-v6','dpi-answer-comparison-v7','dpi-answer-comparison-v8','dpi-answer-comparison-v9'].includes(comparison.policy.version) ? stageDefinitions.find(s=>s.id===stage).repairMessage(error) : 'Return a valid, complete classification using the supplied schema and source values.';
      await invalid?.(stage, audit.attempts, responses.get(stage), error);
      await emit(`${eventPrefix}_${stage}_validate`, 'invalid', {
        attempt: audit.attempts, errorCode: 'INVALID_JUDGE_OUTPUT' });
    }
    return { retry: !audit.completed && audit.attempts < definitions[stage][2] };
  };
  const state = Annotation.Root({ retry: Annotation({ reducer: (_, value) => value, default: () => false }) });
  const builder=new StateGraph(state);
  for(const stage of stageIds)builder.addNode(`${stage}_model`,modelNode(stage)).addNode(`${stage}_validate`,validationNode(stage));
  builder.addNode('compare',async()=>{
    await check();
    result=comparison.combine(...stageIds.map(stage=>values.get(stage)));
    await emit(`${eventPrefix}_compare`,'verdict',{verdict:result.verdict});
    return {};
  }).addEdge(START,`${stageIds[0]}_model`);
  stageIds.forEach((stage,index)=>{
    const next=index+1<stageIds.length?`${stageIds[index+1]}_model`:'compare';
    builder.addEdge(`${stage}_model`,`${stage}_validate`).addConditionalEdges(`${stage}_validate`,value=>value.retry?`${stage}_model`:values.has(stage)?next:END,[`${stage}_model`,next,END]);
  });
  const graph=builder.addEdge('compare',END).compile();
  return Object.freeze({ snapshot, async run(signal) {
    await graph.invoke({}, { signal, recursionLimit: stageIds.length===1?16:stageIds.length===3?32:24 });
    await check();
    return result ? { ...result, ...snapshot() } : {
      verdict: 'unavailable', explanation: `A ${label} classification remained invalid; no completion was awarded.`,
      criteria: [], errorCode: 'INVALID_JUDGE_OUTPUT', ...snapshot(),
    };
  } });
}

module.exports = { createBoundedSourceClassificationEvaluation };
