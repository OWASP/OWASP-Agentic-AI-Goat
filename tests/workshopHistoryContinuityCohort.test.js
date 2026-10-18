'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require.resolve('./workshopHistoryContinuity.live.test'), 'utf8');
// Execute the real qualification callback against controlled seams only. Unknown
// imports fail, so neither the real provider nor an application store can load.
function controlled(cohort, decisions = 1) {
  let callback, options, dispatches = 0;
  const traces = new Map(), agentTimeouts = [];
  const fakeModule = { _load() { throw Error('Unexpected module loader use'); } };
  const context = { process: { env: { LIVE_WORKSHOP_HISTORY: '1', ...(cohort === undefined ? {} : { LIVE_WORKSHOP_HISTORY_COHORT: cohort }) } }, AbortSignal,
    require(name) {
      if (name === 'node:module') return fakeModule;
      if (name === 'node:assert/strict') return assert;
      if (name === 'node:test') return (_name, opts, fn) => { options = opts; callback = fn; };
      if (name.endsWith('/providers/langchainProvider')) return { createLangChainProvider() { return { async generate() { dispatches++; return { provider: 'ollama', model: 'llama3.1:8b', fallback: false, response: 'controlled' }; } }; } };
      if (name.endsWith('/runTraceStore')) return { getRun(id) { return traces.get(id); } };
      if (/services\/(aria|nova)AgentService$/.test(name)) {
        const family = /services\/(aria|nova)/.exec(name)[1];
        return { createAgent({ model, store, defaultTimeoutMs }) {
          agentTimeouts.push(defaultTimeoutMs);
          return { async invoke(owner) {
            const history = await store.getHistory(owner);
            const fact = history.at(-2).message.match(/is (.+)\./)[1];
            const events = [];
            for (let i = 1; i <= decisions; i++) {
              await model.generateResponse(`Select exactly one tool [TRUNCATED FOR MODEL CONTEXT] ${fact}`);
              events.push({ node: 'decide', type: 'decision', data: { attempt: i } });
            }
            await model.generateResponse(`[TRUNCATED FOR MODEL CONTEXT] ${fact}`);
            traces.set(family, { events });
            return { run: { runId: family, decisionSource: 'model', responseSource: 'model' }, toolUsed: null, toolObservations: [], response: fact };
          } };
        } };
      }
      throw Error('Unapproved controlled import: ' + name);
    } };
  vm.compileFunction(source, ['require', 'process', 'AbortSignal'], { filename: 'history-continuity-controlled.js' })(context.require, context.process, context.AbortSignal);
  return { options, agentTimeouts, calls: () => dispatches, run: () => callback({ diagnostic() {} }) };
}
test('historical cohort preserves two calls per family and original deadlines', async () => {
  const c = controlled('historical-two-call');
  assert.equal(c.options.timeout, 230000); assert.equal(c.options.skip, false);
  await c.run(); assert.equal(c.calls(), 4); assert.deepEqual(c.agentTimeouts, [125000, 125000]);
});
test('default retry cohort still requires repair and retains three-call ceiling', async () => {
  const c = controlled(undefined, 2); await c.run();
  assert.equal(c.options.timeout, 350000); assert.equal(c.calls(), 6); assert.deepEqual(c.agentTimeouts, [190000, 190000]);
  await assert.rejects(controlled('retry', 1).run(), /repairedDecisions/);
});
test('historical cohort denies a retry before a third provider dispatch; selector is closed', async () => {
  const c = controlled('historical-two-call', 2);
  await assert.rejects(c.run(), { code: 'LIVE_PROVIDER_CALL_BUDGET' }); assert.equal(c.calls(), 2);
  for (const value of ['both', '']) assert.throws(() => controlled(value), /Closed history continuity cohort/);
});
