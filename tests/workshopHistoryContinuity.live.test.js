'use strict';

const Module = require('node:module');
const load = Module._load;
Module._load = function forbidApplicationStores(request, parent, isMain) {
  if (/(?:^|\/)(?:authDb|sqlWorkshopDb|nosqlWorkshopDb)(?:\.js)?$/.test(request)) {
    throw new Error(`Application database import forbidden in model-only continuity gate: ${request}`);
  }
  return load.call(this, request, parent, isMain);
};

const test = require('node:test');
const assert = require('node:assert/strict');

const cohort = process.env.LIVE_WORKSHOP_HISTORY_COHORT ?? 'retry';
assert.ok(['retry', 'historical-two-call'].includes(cohort), 'Closed history continuity cohort required');
const historical = cohort === 'historical-two-call';
const callLimit = historical ? 2 : 3;

test('local llama3.1:8b preserves newest bounded server history for ARIA and NOVA', {
  skip: process.env.LIVE_WORKSHOP_HISTORY !== '1', timeout: historical ? 230000 : 350000,
}, async t => {
  const provider = require('../server/agent-runtime/providers/langchainProvider').createLangChainProvider({
    provider: 'ollama', model: 'llama3.1:8b', baseURL: process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434',
  });
  const cases = [
    { family: 'aria', fact: 'ARIA-MINTLEAF' },
    { family: 'nova', fact: 'NOVA-CEDARLEAF' },
  ];
  const allCalls = [];
  let repairedDecisions = 0;

  for (const item of cases) {
    const excludedOldPrefix = `OLDEST_PREFIX_${item.family.toUpperCase()}`;
    const history = Array.from({ length: 10 }, (_, index) => ({
      message_type: index % 2 ? 'assistant' : 'user',
      message: `${index === 0 ? excludedOldPrefix : `older-${index}`}:${'neutral prior context '.repeat(90)}`,
    }));
    history.push(
      { message_type: 'user', message: `The nickname I want you to remember is ${item.fact}.` },
      { message_type: 'assistant', message: `I will remember ${item.fact}.` },
    );
    const attempts = [];
    let providerCalls = 0;
    const model = { provider: 'ollama', async generateResponse(prompt, options = {}) {
      const phase = prompt.includes('Select exactly one tool') ? 'decision' : 'response';
      const attempt = { phase, promptChars: prompt.length, retainedFact: prompt.includes(item.fact),
        oldPrefixOmitted: !prompt.includes(excludedOldPrefix), marked: prompt.includes('[TRUNCATED FOR MODEL CONTEXT]') };
      attempts.push(attempt);
      if (providerCalls >= callLimit) {
        attempt.error = { code: 'LIVE_PROVIDER_CALL_BUDGET', name: 'Error' };
        const error = new Error(`${item.family} exceeded its ${callLimit}-call provider budget`);error.code='LIVE_PROVIDER_CALL_BUDGET';throw error;
      }
      providerCalls += 1;
      const signal = AbortSignal.any([AbortSignal.timeout(60000), ...(options.signal ? [options.signal] : [])]);
      try {
        const result = await provider.generate(prompt, {
          ...options, signal, timeout: 60000, temperature: 0, num_predict: phase === 'decision' ? 180 : 80,
        });
        attempt.result = { provider: result.provider, model: result.model, fallback: result.fallback === true,
          responseChars: typeof result.response === 'string' ? result.response.length : null };
        allCalls.push(attempt);return result;
      } catch (error) {
        attempt.error = { code: error?.code || null, name: error?.name || 'Error' };throw error;
      }
    } };
    const store = {
      async getHistory() { return history.slice(-12).map(row => ({ ...row })); },
      async saveMessage(_owner, message_type, message) { history.push({ message_type, message }); },
    };
    const { createAgent } = require(`../server/services/${item.family}AgentService`);
    const ownerId=`${item.family}-history-live`;
    const agent = createAgent({ model, store, defaultTimeoutMs: historical ? 125000 : 190000 });
    const result = await agent.invoke(ownerId,
      'What exact nickname did I ask you to remember? Reply with only the nickname; do not use a shopping or research tool.', 'fixed',
      { includeRunMetadata: true });

    t.diagnostic(JSON.stringify({ cohort, family: item.family.toUpperCase(), attempts, providerCalls,
      graph: { decisionSource: result.run.decisionSource, toolUsed: result.toolUsed, response: result.response } }));
    const phases=attempts.map(call=>call.phase),decisionCalls=phases.filter(phase=>phase==='decision').length;
    assert.ok(decisionCalls===1||decisionCalls===2);assert.equal(phases.at(-1),'response');assert.equal(providerCalls,attempts.length);assert.ok(providerCalls<=callLimit);
    if (historical) { assert.equal(providerCalls, 2); assert.deepEqual(phases, ['decision', 'response']); }
    assert.ok(attempts.every(call => call.retainedFact && call.oldPrefixOmitted && call.marked && call.promptChars <= 24000));
    assert.ok(attempts.filter(call=>call.result).every(call=>call.result.provider==='ollama'&&call.result.model==='llama3.1:8b'&&!call.result.fallback));
    assert.equal(result.run.decisionSource, 'model');
    assert.equal(result.run.responseSource,'model');assert.equal(result.run.responseErrorCode,undefined);
    assert.equal(result.toolUsed, null);
    assert.deepEqual(result.toolObservations, []);
    assert.match(result.response, new RegExp(item.fact));
    const run=require('../server/agent-runtime/runTraceStore').getRun(result.run.runId,JSON.stringify([item.family.toUpperCase(),ownerId]));
    assert.ok(run);const tracedDecisionAttempts=run.events.filter(event=>event.node==='decide'&&['decision','error'].includes(event.type)&&Number.isInteger(event.data.attempt));
    assert.deepEqual(tracedDecisionAttempts.map(event=>event.data.attempt),Array.from({length:decisionCalls},(_,index)=>index+1));
    // JSON/provider failures emit decide errors; valid JSON rejected by the
    // validate node can also retry, without a decide error.
    for (const event of run.events.filter(event => event.node === 'decide' && event.type === 'error')) {
      assert.equal(event.data.errorCode, 'DECISION_UNAVAILABLE');
      assert.equal(event.data.decisionSource, 'unavailable');
    }
    if(decisionCalls===2)repairedDecisions+=1;
    t.diagnostic(JSON.stringify({ cohort, family: item.family.toUpperCase(), factRecalled: true, attempts,
      boundary: 'actual llama3.1:8b and real workshop graph/service; trusted in-memory history, no native database, Judge, credit, or installed-runtime claim' }));
  }
  if (historical) { assert.equal(repairedDecisions, 0); assert.equal(allCalls.length, 4); }
  else { assert.ok(repairedDecisions>=1);assert.ok(allCalls.length>=4&&allCalls.length<=6); }
});
