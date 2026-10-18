'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const judgeModule = require('../server/agent-runtime/objectiveJudge');
const { createObjectiveCompletionService } = require('../server/services/objectiveCompletionService');
const { createObjectiveRegradeService } = require('../server/services/objectiveRegradeService');
const { createMcpTiming, createMcpReconTiming } = require('../server/services/mcp/timing');
const keys = ['MCP_DECISION_TIMEOUT_MS', 'MCP_RESPONSE_TIMEOUT_MS', 'MCP_RUN_TIMEOUT_MS', 'MCP_RECON_JUDGE_TIMEOUT_MS'];
async function configured(values, work) {
  const prior = Object.fromEntries(keys.map(key => [key, process.env[key]]));
  try {
    for (const key of keys) values[key] === undefined ? delete process.env[key] : process.env[key] = values[key];
    return await work();
  } finally {
    for (const key of keys) prior[key] === undefined ? delete process.env[key] : process.env[key] = prior[key];
  }
}
const rubric = { family: 'MCP', scenario: 'assistant_tools', objectiveId: 'mcp_recon',
  version: 'mcp_owned_recon.v2', mode: 'vuln', requiredFacts: [],
  criteria: [{ id: 'proof', description: 'Controlled observed outcome.', allowedSources: ['assistant_response'] }] };
const evidence = [{ id: 'answer', source: 'assistant_response', content: 'Controlled retained answer.' }];
function fixture({ inputRubric = rubric, workshopKey = 'mcp_workshop', judge, terminal = false } = {}) {
  const packet = judgeModule.prepareJudgeInput({ rubric: inputRubric, evidence });
  const execution = { runId: randomUUID(), ownerKey: '["MCP","7"]', durableGeneration: '0',
    signal: new AbortController().signal, check: async () => {} };
  let savedScope, commits = 0;
  const receipt = { evaluationId: randomUUID(), runId: execution.runId, workshopKey,
    family: inputRubric.family, scenario: inputRubric.scenario, objectiveId: inputRubric.objectiveId,
    rubricVersion: inputRubric.version, evidenceDigest: packet.evidenceDigest, generation: 0,
    ...(terminal ? { verdict: 'unavailable', disposition: 'not_pass', result: { verdict: 'unavailable' } } : {}) };
  const service = createObjectiveCompletionService({ ...(judge === undefined ? {} : { judge }),
    progress: { getGeneration: async () => 0 }, receipts: {
      beginEvaluation: async scope => { savedScope = scope; return { ...scope, generation: 0 }; },
      beginRetry: async () => ({ receipt, packet: packet.packet }),
      recordVerdict: async ({ result }) => { commits++; return { ...(savedScope || receipt), result,
        verdict: result.verdict, disposition: 'not_pass' }; },
    } });
  return { service, execution, packet, receipt, commits: () => commits,
    async evaluate() {
      const attempt = await service.beginAttempt({ userId: 7, workshopKey, execution });
      return service.evaluate({ userId: 7, workshopKey, rubric: inputRubric, evidence, execution, attempt,
        judgeTimeoutMs: 999999 }); // Unknown caller options cannot select the budget.
    },
    retry: extra => service.retry({ userId: 7, evaluationId: randomUUID(), execution, ...extra }),
  };
}
async function captureJudges(work) {
  const original = judgeModule.createObjectiveJudge, calls = [];
  judgeModule.createObjectiveJudge = (options = {}) => async input => {
    calls.push({ options, input });
    return { verdict: 'fail', criteria: [], explanation: 'Controlled result.' };
  };
  try { await work(calls); } finally { judgeModule.createObjectiveJudge = original; }
}

test('recon Judge configuration is bounded, enclosed, and isolated from ordinary MCP timing', () => {
  assert.equal(createMcpReconTiming({ env: {} }).judgeTimeoutMs, 90000);
  assert.equal(createMcpReconTiming({ env: { MCP_RECON_JUDGE_TIMEOUT_MS: '120000' } }).judgeTimeoutMs, 120000);
  for (const value of ['', '0', '99', '120001', '1e5', ' 90000', '090000', 90000, null]) {
    assert.throws(() => createMcpReconTiming({ env: { MCP_RECON_JUDGE_TIMEOUT_MS: value } }), RangeError);
  }
  assert.throws(() => createMcpReconTiming({ env: { MCP_RUN_TIMEOUT_MS: '89999' } }), /exceeds/);
  assert.equal(createMcpTiming({ env: { MCP_RECON_JUDGE_TIMEOUT_MS: 'invalid' } }).runTimeoutMs, 120000);
});

test('canonical initial and retry grading select the same recon budget without rewriting historical packets', async () => {
  for (const timeout of [90000, 120000]) await configured({ MCP_RECON_JUDGE_TIMEOUT_MS: String(timeout), MCP_RUN_TIMEOUT_MS: '290000' },
    () => captureJudges(async calls => {
      const f = fixture(), before = f.packet.packet;
      await f.evaluate(); await f.retry();
      assert.equal(calls.length, 2);
      for (const call of calls) {
        assert.equal(call.options.timeoutMs, timeout);
        const { execution, ...input } = call.input;
        assert.equal(judgeModule.prepareJudgeInput(input).packet, before);
        assert.equal(input.rubric.version, 'mcp_owned_recon.v2');
        assert.equal(execution.signal, f.execution.signal);
        assert.equal(execution.runId, f.execution.runId);
      }
      assert.equal(f.packet.packet, before); assert.equal(f.commits(), 2);
    }));
});

test('each scope coordinate must match; injected Judges and terminal retry replay remain unchanged', async () => configured(
  { MCP_RECON_JUDGE_TIMEOUT_MS: 'invalid' }, () => captureJudges(async calls => {
    for (const change of [{ workshopKey: 'other_workshop' },
      ...['family', 'scenario', 'objectiveId'].map(key => ({ inputRubric: { ...rubric, [key]: 'other' } }))]) {
      const f = fixture(change); await f.evaluate(); await f.retry();
    }
    assert.equal(calls.length, 8); assert(calls.every(call => call.options.timeoutMs === undefined));
    let injected = 0;
    const custom = fixture({ judge: async () => { injected++; return { verdict: 'fail', criteria: [] }; } });
    await custom.evaluate(); await custom.retry(); assert.equal(injected, 2); assert.equal(calls.length, 8);
    const terminal = fixture({ terminal: true }); assert.equal((await terminal.retry()).replayed, true);
    assert.equal(terminal.commits(), 0); assert.equal(calls.length, 8);
    await assert.rejects(custom.retry({ retryJudge: async () => ({ verdict: 'pass' }) }), { code: 'RETRY_NOT_ALLOWED' });
  })));

test('the configured recon Judge cannot outlive owner cancellation or commit its result', async () => configured(
  { MCP_RECON_JUDGE_TIMEOUT_MS: '120000' }, async () => {
    const original = judgeModule.createObjectiveJudge, owner = new AbortController();
    let transports = 0;
    judgeModule.createObjectiveJudge = options => original({ ...options, model: { chat: async () => {
      transports++; owner.abort(new DOMException('Owner reset', 'AbortError'));
      return { response: JSON.stringify({ verdict: 'fail', explanation: 'Controlled result.',
        criteria: [{ id: 'proof', satisfied: false, evidenceRefs: ['answer'] }] }) };
    } } });
    try {
      const f = fixture(); f.execution.signal = owner.signal;
      await assert.rejects(f.evaluate(), { name: 'AbortError' });
      assert.equal(transports, 1); assert.equal(f.commits(), 0);
      await assert.rejects(f.retry(), { name: 'AbortError' }); assert.equal(transports, 1);
    } finally { judgeModule.createObjectiveJudge = original; }
  }));

test('only an exact persisted recon recovery gets the shared MCP owner budget and no Judge override', async () => configured(
  { MCP_RECON_JUDGE_TIMEOUT_MS: '120000', MCP_RUN_TIMEOUT_MS: '290000' }, async () => {
    const base = { owner_key: '["MCP","7"]', workshop_key: 'mcp_workshop', family: 'MCP',
      scenario: 'assistant_tools', objective_id: 'mcp_recon' };
    for (const change of [{}, ...['workshop_key', 'family', 'scenario', 'objective_id'].map(key => ({ [key]: 'other' })),
      { owner_key: '["other","7"]' }]) {
      let runOptions, seen;
      const execution = { check: async () => {}, signal: new AbortController().signal };
      const retry = createObjectiveRegradeService({ receipts: { getRecovery: async () => ({ ...base, ...change }) },
        completion: { retry: async args => { seen = args; return { controlled: true }; } },
        coordinatorFactory: () => ({ run: async (_owner, options, work) => { runOptions = options; return work(execution); } }),
      });
      await retry({ userId: 7, evaluationId: randomUUID() });
      assert.equal(runOptions.timeoutMs, Object.keys(change).length ? undefined : 290000);
      assert.equal(seen.execution, execution); assert.equal(seen.retryJudge, undefined);
    }
  }));
